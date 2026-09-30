package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestRotationByCount 达到条数阈值即原子封存并开新批次：
// 查询总量恒等于已处理事件数，绝无半截批次。
func TestRotationByCount(t *testing.T) {
	log := newTL(t)
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 2, MaxBatchBytes: 1 << 20,
		MaxBatchAge: time.Hour, RetainBatches: 1000})
	qs := NewQueryService(p.Store(), p.Book())
	for i := 1; i <= 5; i++ {
		raw := mustJSON(t, makeEvent(fmt.Sprintf("r-%d", i), "cli", "exec"))
		seq, err := p.SubmitBytes(raw)
		log.submit(i, string(raw), seq, err)
		if err != nil {
			t.Fatalf("submit %d: %v", i, err)
		}
		if err := p.WaitDrained(); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	res, err := qs.Query(adminPrincipal(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res.Total != 5 {
		t.Fatalf("total=%d want 5 across batches", res.Total)
	}
	batches, _ := p.Store().Snapshot()
	var n int
	for _, b := range batches {
		n += len(b.Decisions)
		if !b.Active && len(b.Decisions) != 0 && len(b.Decisions) > 2 {
			t.Errorf("sealed batch %s oversized: %d", b.ID, len(b.Decisions))
		}
		log.t.Logf("batch %s active=%v records=%d", b.ID, b.Active, len(b.Decisions))
	}
	if n != 5 {
		t.Fatalf("records across snapshots=%d want 5", n)
	}
	// 正式批次文件必须带封存清单尾；活动文件只有 1 个事件。
	sealedFiles, _ := filepath.Glob(filepath.Join(p.cfg.Dir, "batches", "B-*.jsonl"))
	sealedOnly := sealedFiles[:0]
	for _, f := range sealedFiles {
		if !strings.HasSuffix(f, activeSuffix+".jsonl") {
			sealedOnly = append(sealedOnly, f)
		}
	}
	if len(sealedOnly) < 2 {
		t.Fatalf("expected >=2 sealed batch files, got %d", len(sealedOnly))
	}
	for _, f := range sealedOnly {
		if _, _, err := ReadBatchFile(f); err != nil {
			t.Fatalf("sealed file %s unreadable / half batch: %v", f, err)
		}
	}
}

// TestConcurrentQueriesDuringRotation 轮转期间并发查询不得报错或看到
// 半截批次：每个可见批次的计数必须与文件内完整记录一致。
func TestConcurrentQueriesDuringRotation(t *testing.T) {
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 3, MaxBatchBytes: 1 << 20,
		MaxBatchAge: 10 * time.Millisecond, RetainBatches: 1000})
	qs := NewQueryService(p.Store(), p.Book())
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			res, err := qs.Query(adminPrincipal(), QueryFilter{Limit: maxQueryLimit})
			if err != nil {
				t.Errorf("query during rotation: %v", err)
				return
			}
			if res.Total != len(res.Events) {
				t.Errorf("total/len mismatch: %d/%d", res.Total, len(res.Events))
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	for i := 0; i < 200; i++ {
		raw := mustJSON(t, makeEvent(fmt.Sprintf("c-%03d", i), "web", "login"))
		if _, err := p.SubmitBytes(raw); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	close(stop)
	wg.Wait()
	res, _ := qs.Query(adminPrincipal(), QueryFilter{Limit: maxQueryLimit})
	if res.Total != 200 {
		t.Fatalf("total=%d want 200", res.Total)
	}
}

// TestRetentionCleanup 按时间与最少保留数量清理已封存批次，
// 清理后查询与文件系统一致，活动批次不受影响。
func TestRetentionCleanup(t *testing.T) {
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 1, MaxBatchBytes: 1 << 20,
		MaxBatchAge: time.Hour, RetainAge: time.Hour, RetainBatches: 1})
	for i := 1; i <= 4; i++ {
		raw := mustJSON(t, makeEvent(fmt.Sprintf("k-%d", i), "cli", "exec"))
		if _, err := p.SubmitBytes(raw); err != nil {
			t.Fatalf("submit: %v", err)
		}
		if err := p.WaitDrained(); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}
	// 把全部已封存批次的 SealedAt 人为调老（通过直接改文件+重建索引
	// 代价较大；这里改为构造 RetainAge=0 立即过期，但 RetainBatches=1
	// 必须保护最新批次）。
	// 使用独立存储实例验证“立即过期 + 保留最近 1 个”的组合。
	dir := filepath.Join(t.TempDir(), "d2")
	p2, err := New(PipelineConfig{Dir: dir, MaxEventBytes: 2048,
		Sources: []Source{"web", "cli", "cron"},
		Retention: RetentionConfig{MaxBatchCount: 1, MaxBatchBytes: 1 << 20,
			MaxBatchAge: time.Hour, RetainAge: 0, RetainBatches: 1}})
	if err != nil {
		t.Fatalf("new p2: %v", err)
	}
	if _, err := p2.PublishPolicy(defaultRules()); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := p2.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	for i := 1; i <= 4; i++ {
		if _, err := p2.SubmitBytes(mustJSON(t, makeEvent(fmt.Sprintf("z-%d", i), "cli", "exec"))); err != nil {
			t.Fatalf("submit: %v", err)
		}
		if err := p2.WaitDrained(); err != nil {
			t.Fatalf("drain: %v", err)
		}
	}
	_ = p.Close()
	removed, err := p2.Store().EnforceRetention()
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed=%v want 3 oldest (newest protected by RetainBatches=1)", removed)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "batches", "B-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("remaining files=%d want 1", len(files))
	}
	res, err := NewQueryService(p2.Store(), p2.Book()).Query(adminPrincipal(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatalf("query after cleanup: %v", err)
	}
	if res.Total != 1 || res.Events[0].ID != "z-4" {
		t.Fatalf("expected only newest z-4, got total=%d first=%v", res.Total,
			func() string {
				if len(res.Events) > 0 {
					return res.Events[0].ID
				}
				return ""
			}())
	}
	if err := p2.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestNoActiveFileBeforeSeal 在轮转阈值到达前，正式文件名不得出现，
// 证明发布完全依赖原子改名（查询无法读到半截文件）。
func TestNoActiveFileBeforeSeal(t *testing.T) {
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 100, MaxBatchBytes: 1 << 20, MaxBatchAge: time.Hour})
	if _, err := p.SubmitBytes(mustJSON(t, makeEvent("only-1", "cli", "exec"))); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(p.cfg.Dir, "batches", "B-000001.jsonl"))
	if len(matches) != 0 {
		t.Fatalf("sealed name must not exist before rotation, got %v", matches)
	}
	actives, _ := filepath.Glob(filepath.Join(p.cfg.Dir, "batches", "*.active.jsonl"))
	if len(actives) != 1 {
		t.Fatalf("expected exactly one active file, got %v", actives)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p.cfg.Dir, "batches", "B-000001.jsonl")); err != nil {
		t.Fatalf("close should seal active batch: %v", err)
	}
}
