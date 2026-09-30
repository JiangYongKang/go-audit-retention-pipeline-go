package pipeline

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/retention"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/router"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/store"
)

type rig struct {
	dir string
	st  *store.Store
	rt  *retention.Manager
	rr  *router.Router
	pl  *Pipeline
}

func newRig(t *testing.T, batchSize int) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := retention.NewManager(retention.Policy{
		MaxBatchRecords: batchSize, MaxBatchAge: time.Hour, Retention: time.Hour,
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	rr := router.NewRouter()
	pl, err := New(st, rt, rr, Config{
		MaxPayloadBytes: 2048, MaxFieldValueLen: 128,
		KnownSources: map[string]bool{"payments": true, "auth": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := pl.InstallPolicy(ctx, model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "pay-fraud", Source: "payments", EventType: "transfer", Field: "risk", Equals: "high"},
	}}); err != nil {
		t.Fatal(err)
	}
	return &rig{dir: dir, st: st, rt: rt, rr: rr, pl: pl}
}

func good(risk string) model.RawEvent {
	return model.RawEvent{
		Source: "payments", Type: "transfer", Timestamp: time.Now(),
		Payload: map[string]string{"risk": risk, "amount": "100"},
	}
}

func TestRejectionCodesDistinguishable(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, 1000)

	cases := []struct {
		name string
		json []byte
		raw  model.RawEvent
		use  bool
		code apperr.Code
	}{
		{"malformed json", []byte("{bad-json"), model.RawEvent{}, false, apperr.CodeMalformedJSON},
		{"missing timestamp", nil, model.RawEvent{Source: "payments", Type: "transfer", Payload: map[string]string{}}, true, apperr.CodeMissingField},
		{"unknown source", nil, model.RawEvent{Source: "mystery", Type: "x", Timestamp: time.Now(), Payload: map[string]string{}}, true, apperr.CodeUnknownSource},
		{"value too large", nil, model.RawEvent{Source: "payments", Type: "transfer", Timestamp: time.Now(),
			Payload: map[string]string{"k": strings.Repeat("x", 200)}}, true, apperr.CodeValueTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var res model.SubmissionResult
			var err error
			if tc.use {
				res, err = r.pl.Submit(ctx, tc.raw)
			} else {
				res, err = r.pl.SubmitJSON(ctx, tc.json)
			}
			ae, ok := err.(*apperr.Error)
			if !ok {
				t.Fatalf("expected *apperr.Error, got %T", err)
			}
			t.Logf("input=%s -> accepted=%v code=%s msg=%v", tc.name, res.Accepted, ae.Code, err)
			if ae.Code != tc.code {
				t.Fatalf("code=%s want %s", ae.Code, tc.code)
			}
			if res.Accepted {
				t.Fatal("rejected event must not be accepted")
			}
		})
	}

	// Rejected events must not consume sequence numbers.
	before, _ := r.st.AppendedSeq(ctx)
	if before != 0 {
		t.Fatalf("rejected events were persisted, maxSeq=%d", before)
	}
	ok1, err := r.pl.Submit(ctx, good("high"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input risk=high -> seq=%d batch=%s matched=%v reason=%q", ok1.Seq, ok1.BatchID, ok1.Matched, ok1.Reason)
	if ok1.Seq != 1 || !ok1.Matched || ok1.HitRuleID != "pay-fraud" {
		t.Fatalf("first accepted event wrong: %+v", ok1)
	}
	ok2, err := r.pl.Submit(ctx, good("low"))
	if err != nil {
		t.Fatal(err)
	}
	if ok2.Seq != 2 || ok2.Matched {
		t.Fatalf("second event wrong: %+v", ok2)
	}
}

func TestConcurrentWritesUniqueAndComplete(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, 13) // forces rotations mid-flight

	const goroutines, per = 16, 50
	var wg sync.WaitGroup
	var mu sync.Mutex
	seqs := map[int64]bool{}
	errs := 0
	var batchesSeen sync.Map
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				res, err := r.pl.Submit(ctx, good(map[bool]string{true: "high", false: "low"}[(g+i)%3 == 0]))
				if err != nil {
					mu.Lock()
					errs++
					mu.Unlock()
					return
				}
				mu.Lock()
				if seqs[res.Seq] {
					t.Errorf("duplicate seq %d", res.Seq)
				}
				seqs[res.Seq] = true
				mu.Unlock()
				batchesSeen.Store(res.BatchID, true)
			}
		}(g)
	}
	wg.Wait()
	if errs != 0 {
		t.Fatalf("%d submissions errored", errs)
	}
	total := goroutines * per
	if len(seqs) != total {
		t.Fatalf("unique accepted = %d, want %d", len(seqs), total)
	}
	maxSeq, _ := r.st.AppendedSeq(ctx)
	if maxSeq != int64(total) {
		t.Fatalf("durable maxSeq=%d want %d (no gaps, no loss)", maxSeq, total)
	}
	sealed, _ := r.st.Batches(ctx)
	t.Logf("input %d concurrent events -> %d sealed batches, %d unique seq", total, len(sealed), len(seqs))
	count := 0
	for _, b := range sealed {
		count += b.Count
	}
	open, _ := r.st.OpenBatchCount(ctx)
	if count+open != total {
		t.Fatalf("records across sealed(%d)+open(%d) != %d", count, open, total)
	}
}

func TestRestartRecoveryNoDoubleCount(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, 1000)
	dir := r.dir

	// Submit 6 events, 3 of which match (risk=high).
	for i := 0; i < 6; i++ {
		risk := "low"
		if i%2 == 0 {
			risk = "high"
		}
		res, err := r.pl.Submit(ctx, good(risk))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("input risk=%s -> seq=%d batch=%s decision=%q", risk, res.Seq, res.BatchID, res.Reason)
	}
	// First consumer run consumes through seq 4 (2 matched).
	if err := r.pl.Consume(ctx, 4, 2); err != nil {
		t.Fatal(err)
	}
	if err := r.st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reboot: fresh store/router/pipeline over the same directory.
	replayed, accepted := rebootAndRecover(t, ctx, dir)
	if replayed != 2 || accepted != 1 {
		t.Fatalf("first recovery replayed=%d accepted=%d, want 2/1", replayed, accepted)
	}
	t.Logf("restart #1: input unconsumed seq 5,6 -> replayed=%d accepted=%d", replayed, accepted)

	// Second reboot: nothing left; counts must not move.
	replayed2, accepted2 := rebootAndRecover(t, ctx, dir)
	if replayed2 != 0 || accepted2 != 0 {
		t.Fatalf("second recovery replayed=%d accepted=%d, want 0/0 (double counting)", replayed2, accepted2)
	}
	cursor, _ := func() (model.Cursor, error) {
		st2, _ := store.New(dir)
		defer st2.Close()
		return st2.LoadCursor(ctx)
	}()
	if cursor.LastConsumedSeq != 6 || cursor.AcceptedCount != 3 {
		t.Fatalf("cursor=%+v want {6 3}", cursor)
	}
}

func rebootAndRecover(t *testing.T, ctx context.Context, dir string) (int, int) {
	t.Helper()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := retention.NewManager(retention.Policy{MaxBatchRecords: 1000, MaxBatchAge: time.Hour, Retention: time.Hour}, st)
	if err != nil {
		t.Fatal(err)
	}
	rr := router.NewRouter()
	pl, err := New(st, rt, rr, Config{
		MaxPayloadBytes: 2048, MaxFieldValueLen: 128,
		KnownSources: map[string]bool{"payments": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.LoadPoliciesFromStore(ctx); err != nil {
		t.Fatal(err)
	}
	replayed, accepted, err := pl.Recover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return replayed, accepted
}

// TestInternalRoutingFailure tests that an internal processing failure
// (no policy installed) is reported as POLICY_FAILURE, consumes no
// sequence number, and the pipeline keeps working once fixed.
func TestInternalRoutingFailure(t *testing.T) {
	ctx := context.Background()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rt, err := retention.NewManager(retention.Policy{MaxBatchRecords: 1000}, st)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := New(st, rt, router.NewRouter(), Config{KnownSources: map[string]bool{"payments": true}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pl.Submit(ctx, good("high"))
	ae, ok := err.(*apperr.Error)
	if !ok || ae.Code != apperr.CodePolicyFailure {
		t.Fatalf("want POLICY_FAILURE, got %v", err)
	}
	t.Logf("input risk=high with no policy -> %v (distinguishable internal failure)", err)
	maxSeq, _ := st.AppendedSeq(ctx)
	if maxSeq != 0 {
		t.Fatalf("failed routing must not consume a seq, maxSeq=%d", maxSeq)
	}
	if err := pl.InstallPolicy(ctx, model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "pay-fraud", Source: "payments", EventType: "transfer", Field: "risk", Equals: "high"},
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := pl.Submit(ctx, good("high"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Seq != 1 {
		t.Fatalf("seq after recovered failure = %d, want 1", res.Seq)
	}
	t.Logf("after policy install input risk=high -> seq=%d (no gap from earlier failure)", res.Seq)
}
