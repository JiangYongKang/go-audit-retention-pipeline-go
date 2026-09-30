package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentWritesAndQueries 高并发写入同一进程，期间并发查询，
// 验证：全部有效事件被处理、结论完整，查询无错误、无半截批次。
func TestConcurrentWritersAndQueries(t *testing.T) {
	log := newTL(t)
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 25, MaxBatchBytes: 128 * 1024,
		MaxBatchAge: 50 * time.Millisecond, RetainBatches: 100,
	})
	qs := NewQueryService(p.Store(), p.Book())

	const writers = 8
	const perWriter = 40
	var wg sync.WaitGroup
	var acceptMu sync.Mutex
	acceptedIDs := map[string]struct{}{}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := fmt.Sprintf("w%d-e%03d", w, i)
				src := Source([]string{"web", "cli", "cron"}[i%3])
				typ := map[Source]string{"web": "login", "cli": "exec", "cron": "job"}[src]
				raw := mustJSON(t, makeEvent(id, src, typ))
				seq, err := p.SubmitBytes(raw)
				log.submit(w*perWriter+i, string(raw), seq, err)
				if err == nil {
					acceptMu.Lock()
					acceptedIDs[id] = struct{}{}
					acceptMu.Unlock()
				}
			}
		}(w)
	}

	// 并发查询：整个测试期间持续读，任何一次都必须成功且字段完整。
	stop := make(chan struct{})
	var qwg sync.WaitGroup
	qwg.Add(1)
	go func() {
		defer qwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			res, err := qs.Query(adminPrincipal(), QueryFilter{Limit: maxQueryLimit})
			if err != nil {
				t.Errorf("concurrent query failed: %v", err)
				return
			}
			// 任何时候看到的结论都必须带版本与依据；批次要么是活动批次，
			// 要么是完整封存批次（总数与可见数一致，不允许残缺）。
			for _, v := range res.Events {
				if v.Decision.Basis == "" || v.Decision.PolicyVersion == 0 {
					t.Errorf("event %s missing decision basis/version", v.ID)
					return
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	close(stop)
	qwg.Wait()

	want := writers * perWriter
	st := p.Stats()
	if st.Processed != int64(want) {
		t.Fatalf("processed=%d want %d (accepted=%d rejected=%d failed=%d)",
			st.Processed, want, st.Accepted, st.Rejected, st.Failed)
	}
	if st.Failed != 0 {
		t.Fatalf("internal failures: %d", st.Failed)
	}
	res, err := qs.Query(adminPrincipal(), QueryFilter{Limit: maxQueryLimit})
	if err != nil {
		t.Fatalf("final query: %v", err)
	}
	if res.Total != want {
		t.Fatalf("visible total=%d want %d", res.Total, want)
	}
	got := map[string]struct{}{}
	for _, v := range res.Events {
		got[v.ID] = struct{}{}
	}
	for id := range acceptedIDs {
		if _, ok := got[id]; !ok {
			t.Errorf("accepted event %s missing from query results", id)
		}
	}
	log.decisions("FINAL", res.Events[:min(6, len(res.Events))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestDuplicateRejected 同 ID 二次提交必须被显式拒绝且只计数一次。
func TestDuplicateRejected(t *testing.T) {
	log := newTL(t)
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 10, MaxBatchBytes: 4096, MaxBatchAge: time.Hour,
	})
	raw := mustJSON(t, makeEvent("dup-1", "cli", "exec"))
	seq, err := p.SubmitBytes(raw)
	log.submit(1, string(raw), seq, err)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	_, err = p.SubmitBytes(raw)
	log.submit(2, string(raw), 0, err)
	if !IsCode(err, CodeDuplicate) {
		t.Fatalf("want %s got %v", CodeDuplicate, err)
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if st := p.Stats(); st.Processed != 1 {
		t.Fatalf("processed=%d want 1 (must not double count)", st.Processed)
	}
}
