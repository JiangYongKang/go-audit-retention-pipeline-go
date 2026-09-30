package audit

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// 以底层组件在独立目录构造流水线（绕过 Close），用于模拟崩溃：
// 已写 WAL 与活动批次文件保留，但 consumer.state 停在旧位点。
func openInDir(t *testing.T, dir string, ret RetentionConfig) *Pipeline {
	t.Helper()
	p, err := New(PipelineConfig{
		Dir: dir, MaxEventBytes: 4096,
		Sources:   []Source{"web", "cli", "cron"},
		Retention: ret,
	})
	if err != nil {
		t.Fatalf("open %s: %v", dir, err)
	}
	return p
}

// TestRestartRecovery 干净重启：状态、结论与计数一致。
func TestRestartRecovery(t *testing.T) {
	log := newTL(t)
	dir := filepath.Join(t.TempDir(), "data")
	ret := RetentionConfig{MaxBatchCount: 100, MaxBatchBytes: 1 << 20,
		MaxBatchAge: time.Hour, RetainBatches: 100}

	p := openInDir(t, dir, ret)
	if _, err := p.PublishPolicy(defaultRules()); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		raw := mustJSON(t, makeEvent(fmt.Sprintf("rec-%d", i), "cli", "exec"))
		seq, err := p.SubmitBytes(raw)
		log.submit(i, string(raw), seq, err)
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 重启：同样事件必须全部被识别为重复，不产生新处理计数。
	p2 := openInDir(t, dir, ret)
	if _, err := p2.PublishPolicy(defaultRules()); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 6; i++ {
		raw := mustJSON(t, makeEvent(fmt.Sprintf("rec-%d", i), "cli", "exec"))
		if _, err := p2.SubmitBytes(raw); !IsCode(err, CodeDuplicate) {
			t.Fatalf("event %d after restart: want duplicate got %v", i, err)
		}
	}
	// 新事件继续分配的序号必须接在旧序号之后。
	raw := mustJSON(t, makeEvent("rec-7", "cli", "exec"))
	seq, err := p2.SubmitBytes(raw)
	if err != nil {
		t.Fatalf("submit rec-7: %v", err)
	}
	if seq != 7 {
		t.Fatalf("seq after restart=%d want 7 (WAL must continue numbering)", seq)
	}
	if err := p2.Start(); err != nil {
		t.Fatal(err)
	}
	if err := p2.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	res, err := NewQueryService(p2.Store(), p2.Book()).Query(adminPrincipal(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 7 {
		t.Fatalf("total after restart=%d want 7", res.Total)
	}
	for _, v := range res.Events {
		if v.Batch == "" {
			t.Errorf("event %s has empty batch id after recovery", v.ID)
		}
	}
	log.decisions("RECOVERED", res.Events)
	if err := p2.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestCrashBeforeCommit 模拟崩溃：WAL 有全部事件、批次文件已写入，
// 但消费进度位点被人为回退。重启后未提交部分必须继续处理，
// 且每条只计数一次（结论与批次不变）。
func TestCrashBeforeCommit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ret := RetentionConfig{MaxBatchCount: 100, MaxBatchBytes: 1 << 20,
		MaxBatchAge: time.Hour, RetainBatches: 100}

	p := openInDir(t, dir, ret)
	if _, err := p.PublishPolicy(defaultRules()); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if _, err := p.SubmitBytes(mustJSON(t,
			makeEvent(fmt.Sprintf("cr-%d", i), "cli", "exec"))); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	// 不调用 Close，直接丢弃流水线（模拟进程被杀）。底层文件保留。
	// 活动批次未补清单、进度位点停在 5；把它回退到 2 模拟
	// “批次已含 seq3..5 但位点未推进”的崩溃窗口。
	stateFile := filepath.Join(dir, stateFileName)
	if err := writeRawStateForTest(stateFile, 2); err != nil {
		t.Fatal(err)
	}

	p2 := openInDir(t, dir, ret)
	if _, err := p2.PublishPolicy(defaultRules()); err != nil {
		t.Fatal(err)
	}
	committed, err := p2.Store().CommittedSeq()
	if err != nil {
		t.Fatal(err)
	}
	if committed != 2 {
		t.Fatalf("seed committed=%d want 2", committed)
	}
	if err := p2.Start(); err != nil {
		t.Fatal(err)
	}
	if err := p2.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	// seq 3..5 在恢复时已在批次中：必须幂等补齐位点，不能重复处理。
	if got := p2.Stats().Processed; got != 0 {
		t.Fatalf("replayed events must not be reprocessed, processed=%d", got)
	}
	if c, _ := p2.Store().CommittedSeq(); c != 5 {
		t.Fatalf("committed after recovery=%d want 5", c)
	}
	res, err := NewQueryService(p2.Store(), p2.Book()).Query(adminPrincipal(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != 5 {
		t.Fatalf("total=%d want 5 (no loss, no dup)", res.Total)
	}
	// 新事件序号继续接 6，不会与恢复记录冲突。
	if _, err := p2.SubmitBytes(mustJSON(t, makeEvent("cr-6", "cli", "exec"))); err != nil {
		t.Fatalf("submit cr-6: %v", err)
	}
	if err := p2.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	res, _ = NewQueryService(p2.Store(), p2.Book()).Query(adminPrincipal(), QueryFilter{Limit: 100})
	if res.Total != 6 {
		t.Fatalf("total=%d want 6", res.Total)
	}
	if err := p2.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyVersionReproducibility 策略升级不改变历史结论；
// 历史决策始终带判定时的版本号与规则依据，且可用旧快照重新复现。
func TestPolicyVersionReproducibility(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	ret := RetentionConfig{MaxBatchCount: 100, MaxBatchBytes: 1 << 20,
		MaxBatchAge: time.Hour, RetainBatches: 100}
	p := openInDir(t, dir, ret)
	v1, _ := p.PublishPolicy([]Rule{
		{ID: "v1-flag-web-login", Sources: []Source{"web"}, Types: []string{"login"},
			Action: ActionFlag, Reason: "old policy"},
	})
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.SubmitBytes(mustJSON(t, makeEvent("hist-1", "web", "login"))); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	// 发布 v2：web login 变为 allow。新事件用 v2，历史事件仍停留在 v1。
	v2, err := p.PublishPolicy([]Rule{
		{ID: "v2-allow-all", Action: ActionAllow, Reason: "new policy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.SubmitBytes(mustJSON(t, makeEvent("hist-2", "web", "login"))); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatal(err)
	}
	res, err := NewQueryService(p.Store(), p.Book()).Query(adminPrincipal(), QueryFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]EventView{}
	for _, e := range res.Events {
		byID[e.ID] = e
	}
	h1, h2 := byID["hist-1"], byID["hist-2"]
	if h1.Decision.PolicyVersion != v1 || h1.Decision.Verdict != VerdictFlag ||
		h1.Decision.RuleID != "v1-flag-web-login" {
		t.Fatalf("hist-1 not preserved on v1: %+v", h1.Decision)
	}
	if h2.Decision.PolicyVersion != v2 || h2.Decision.Verdict != VerdictAllow {
		t.Fatalf("hist-2 not evaluated on v2: %+v", h2.Decision)
	}
	// 用 v1 快照重新评估 hist-1 的事件，必须复现相同结论。
	ev := h1
	original := Event{ID: ev.ID, Source: ev.Source, Type: ev.Type, OccurredAt: ev.OccurredAt}
	re := NewRouter(p.Book()).Evaluate(&original, v1)
	if re.Verdict != VerdictFlag || re.RuleID != "v1-flag-web-login" || !re.Matched {
		t.Fatalf("historical decision not reproducible: %+v", re)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}
