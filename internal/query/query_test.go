package query

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/security"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/store"
)

func setup(t *testing.T) (*store.Store, *security.Enforcer, *Service) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	en := security.NewEnforcer()
	en.Grant(security.Role{Name: "auditor",
		AllowedSources: map[string]bool{"payments": true},
		AllowedFields:  map[string]bool{"risk": true},
	})
	en.Grant(security.Role{Name: "admin",
		AllowedSources: map[string]bool{"*": true},
		AllowedFields:  map[string]bool{"*": true},
	})
	return st, en, NewService(st, en)
}

func seed(t *testing.T, st *store.Store, batch string, seq int64, source string) {
	t.Helper()
	if err := st.Append(context.Background(), model.Record{
		Seq: seq, BatchID: batch, Source: source, Type: "transfer",
		Timestamp: time.Now(), Payload: map[string]string{"risk": "high", "secret": "s"},
		Matched: true, HitRuleID: "r", PolicyVer: 1, Accepted: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestQueryDeniedAndHidden(t *testing.T) {
	ctx := context.Background()
	st, _, svc := setup(t)
	b, _ := st.CurrentBatchID(ctx)
	seed(t, st, b, 1, "payments")
	if _, err := st.SealBatch(ctx, ""); err != nil {
		t.Fatal(err)
	}

	// Unknown principal: same denial regardless of batch existence.
	if _, err := svc.Query(ctx, "ghost", "", "payments", "", 10); !isDenied(err) {
		t.Fatalf("ghost: want ACCESS_DENIED, got %v", err)
	}
	// Known principal probing a source it lacks: denial, never NOT_FOUND.
	if _, err := svc.Query(ctx, "auditor", "does-not-exist-batch", "auth", "", 10); !isDenied(err) {
		t.Fatalf("source probe leaked: %v", err)
	}
	t.Logf("input principal=auditor source=auth batch=unknown -> %v (denial precedes existence check)", errDeniedText)

	views, err := svc.Query(ctx, "auditor", "", "payments", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("views=%d want 1", len(views))
	}
	if _, leak := views[0].Payload["secret"]; leak {
		t.Fatal("hidden field leaked through query")
	}
	t.Logf("input auditor query payments -> batch=%s payload=%v (secret omitted, not nulled)",
		views[0].BatchID, views[0].Payload)
}

func TestConcurrentQueryWhileRotating(t *testing.T) {
	ctx := context.Background()
	st, _, svc := setup(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for seq := int64(1); seq <= 400; seq++ {
			b, _ := st.CurrentBatchID(ctx)
			seed(t, st, b, seq, "payments")
			c, _ := st.OpenBatchCount(ctx)
			if c >= 20 {
				if _, err := st.SealBatch(ctx, b); err != nil {
					t.Error(err)
					return
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			batches, views, err := svc.Snapshot(ctx, "admin", "payments", "")
			if err != nil {
				t.Error(err)
				return
			}
			sealed := 0
			for _, b := range batches {
				sealed += b.Count
			}
			if sealed != len(views) {
				t.Errorf("half-batch read during rotation: batch count=%d query rows=%d", sealed, len(views))
				return
			}
		}
	}()
	wg.Wait()
}

var errDeniedText = "ACCESS_DENIED"

func isDenied(err error) bool {
	var ae *apperr.Error
	return errors.As(err, &ae) && ae.Code == apperr.CodeAccessDenied
}

// TestConcurrentQueryWhileCleaning seals and deletes batches while
// readers run; a reader must see a whole batch or none, never an error
// caused by a half-deleted file, and no partial row counts.
func TestConcurrentQueryWhileCleaning(t *testing.T) {
	ctx := context.Background()
	st, _, svc := setup(t)

	// Build 30 sealed batches of 10 records each = 300 sealed records.
	for seq := int64(1); seq <= 300; seq++ {
		b, _ := st.CurrentBatchID(ctx)
		seed(t, st, b, seq, "payments")
		if c, _ := st.OpenBatchCount(ctx); c >= 10 {
			if _, err := st.SealBatch(ctx, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	batches, _ := svc.Batches(ctx, "admin")
	if len(batches) != 30 {
		t.Fatalf("expected 30 sealed batches, got %d", len(batches))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, b := range batches {
			if err := st.DeleteBatch(ctx, b.ID); err != nil {
				t.Error(err)
				return
			}
			t.Logf("input cleanup -> deleted batch=%s", b.ID)
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			listed, views, err := svc.Snapshot(ctx, "admin", "payments", "")
			if err != nil {
				t.Errorf("reader saw inconsistent state during delete: %v", err)
				return
			}
			sealed := 0
			for _, b := range listed {
				sealed += b.Count
			}
			if sealed != len(views) {
				t.Errorf("half-deleted batch visible: listed rows=%d query rows=%d", sealed, len(views))
				return
			}
		}
	}()
	wg.Wait()
	left, _ := svc.Query(ctx, "admin", "", "payments", "", 0)
	if len(left) != 0 {
		t.Fatalf("after cleanup %d records still visible", len(left))
	}
}
