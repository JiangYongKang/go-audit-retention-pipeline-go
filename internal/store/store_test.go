package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return st, dir
}

func mkRec(seq int64, batch string) model.Record {
	return model.Record{
		Seq: seq, BatchID: batch, Source: "payments", Type: "transfer",
		Timestamp: time.Now(),
		Payload:   map[string]string{"risk": "high", "amount": "100"},
		Matched:   seq%2 == 0, HitRuleID: "pay-fraud", PolicyVer: 1,
		Reason: "test decision", Accepted: true,
	}
}

// TestAppendSealAndRecover verifies durable appends, atomic sealing and
// exact index rebuild after a simulated restart.
func TestAppendSealAndRecover(t *testing.T) {
	ctx := context.Background()
	st, dir := newTestStore(t)

	b1, err := st.CurrentBatchID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i <= 3; i++ {
		if err := st.Append(ctx, mkRec(i, b1)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		t.Logf("input seq=%d -> batch=%s decision=matched:%v rule=pay-fraud", i, b1, i%2 == 0)
	}
	meta, err := st.SealBatch(ctx, "")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	t.Logf("sealed batch=%s count=%d seq=[%d..%d]", meta.ID, meta.Count, meta.MinSeq, meta.MaxSeq)
	if meta.Count != 3 {
		t.Fatalf("sealed count = %d, want 3", meta.Count)
	}

	b2, err := st.CurrentBatchID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b2 == b1 {
		t.Fatal("new open batch expected after seal")
	}
	if err := st.Append(ctx, mkRec(4, b2)); err != nil {
		t.Fatalf("append 4: %v", err)
	}

	// Reopen from disk: simulates a process restart.
	st2, err := New(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	maxSeq, err := st2.AppendedSeq(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if maxSeq != 4 {
		t.Fatalf("maxSeq after reopen = %d, want 4", maxSeq)
	}
	batches, err := st2.Batches(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 || batches[0].ID != b1 {
		t.Fatalf("sealed batches after reopen = %+v, want only %s", batches, b1)
	}
	cur, err := st2.CurrentBatchID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cur != b2 {
		t.Fatalf("open batch after reopen = %s, want %s", cur, b2)
	}
}

// TestQuerySealedOnly guarantees readers never see the open batch, which
// is what prevents half-batch reads during rotation.
func TestQuerySealedOnly(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	b, _ := st.CurrentBatchID(ctx)
	if err := st.Append(ctx, mkRec(1, b)); err != nil {
		t.Fatal(err)
	}
	recs, err := st.Query(ctx, "", "payments", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("open batch visible to query: %d rows", len(recs))
	}
	if _, err := st.SealBatch(ctx, ""); err != nil {
		t.Fatal(err)
	}
	recs, err = st.Query(ctx, "", "payments", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("sealed batch not visible: %d rows", len(recs))
	}
	t.Logf("input seq=1 batch=%s visible only after seal, decision=%q", recs[0].BatchID, recs[0].Reason)
}

// TestDuplicateSeqRejected verifies the storage-level duplicate guard.
func TestDuplicateSeqRejected(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	b, _ := st.CurrentBatchID(ctx)
	if err := st.Append(ctx, mkRec(1, b)); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, mkRec(1, b)); err == nil {
		t.Fatal("duplicate seq was accepted")
	} else {
		t.Logf("duplicate seq=1 correctly rejected: %v", err)
	}
}

// TestConcurrentAppendsAndQueryDuringSeal stresses concurrent writers
// and concurrent sealed-batch reads during repeated rotation.
func TestConcurrentAppendsAndQueryDuringSeal(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)

	const writers, per = 8, 40
	var wg sync.WaitGroup
	errCh := make(chan error, writers+1)
	var seqMu sync.Mutex
	next := int64(1)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				seqMu.Lock()
				seq := next
				next++
				seqMu.Unlock()
				b, err := st.CurrentBatchID(ctx)
				if err != nil {
					errCh <- err
					return
				}
				if err := st.Append(ctx, mkRec(seq, b)); err != nil {
					errCh <- err
					return
				}
				count, err := st.OpenBatchCount(ctx)
				if err != nil {
					errCh <- err
					return
				}
				if count >= 10 {
					if _, err := st.SealBatch(ctx, b); err != nil {
						errCh <- err
						return
					}
					t.Logf("writer=%d sealed batch=%s at count=%d", w, b, count)
				}
			}
		}(w)
	}
	// Concurrent reader: must only ever see complete sealed batches.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			batches, recs, err := st.Snapshot(ctx, "payments", "")
			if err != nil {
				errCh <- err
				return
			}
			sealedCount := 0
			for _, bm := range batches {
				sealedCount += bm.Count
			}
			if sealedCount != len(recs) {
				errCh <- errMismatch(sealedCount, len(recs))
				return
			}
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	maxSeq, _ := st.AppendedSeq(ctx)
	if maxSeq != writers*per {
		t.Fatalf("maxSeq=%d want %d", maxSeq, writers*per)
	}
}

// TestDeleteBatchAtomic verifies deleted batches disappear completely and
// open batches cannot be deleted.
func TestDeleteBatchAtomic(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	b, _ := st.CurrentBatchID(ctx)
	if err := st.Append(ctx, mkRec(1, b)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteBatch(ctx, b); err == nil {
		t.Fatal("deleting open batch should fail")
	}
	meta, err := st.SealBatch(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteBatch(ctx, meta.ID); err != nil {
		t.Fatalf("delete sealed: %v", err)
	}
	if _, err := st.Query(ctx, meta.ID, "", "", 0); err == nil {
		t.Fatal("query on deleted batch should fail with NOT_FOUND")
	}
	batches, _ := st.Batches(ctx)
	if len(batches) != 0 {
		t.Fatalf("deleted batch still listed: %+v", batches)
	}
	t.Logf("batch=%s deleted atomically; query and listing no longer expose it", meta.ID)
}

// TestCursorRoundTrip verifies persisted consumer progress survives restart.
func TestCursorRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, dir := newTestStore(t)
	want := model.Cursor{LastConsumedSeq: 41, AcceptedCount: 7}
	if err := st.SaveCursor(ctx, want); err != nil {
		t.Fatal(err)
	}
	st2, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st2.LoadCursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("cursor after restart = %+v, want %+v", got, want)
	}
}

func errMismatch(a, b int) error {
	return &mismatchErr{a: a, b: b}
}

type mismatchErr struct{ a, b int }

func (e *mismatchErr) Error() string {
	return "half-batch read: sealed record count != query rows"
}
