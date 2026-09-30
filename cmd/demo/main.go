// Command demo runs an end-to-end local demonstration of the audit
// retention pipeline: concurrent ingestion, rotation, least-privilege
// masked queries, distinguishable rejections and restart recovery.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/pipeline"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/query"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/retention"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/router"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/security"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/store"
)

func main() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "audit-demo-")
	must(err)
	defer os.RemoveAll(dir)
	fmt.Println("data dir:", dir)

	// ---- boot: policy v1 + roles -----------------------------------
	st, err := store.New(dir)
	must(err)
	rt, err := retention.NewManager(retention.Policy{
		MaxBatchRecords: 5, MaxBatchAge: time.Hour, Retention: time.Hour,
	}, st)
	must(err)
	rr := router.NewRouter()
	pl, err := pipeline.New(st, rt, rr, pipeline.Config{
		MaxPayloadBytes: 4096, MaxFieldValueLen: 512,
		KnownSources: map[string]bool{"payments": true, "auth": true},
	})
	must(err)
	must(pl.InstallPolicy(ctx, model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "pay-fraud", Source: "payments", EventType: "transfer", Field: "risk", Equals: "high"},
		{ID: "auth-admin", Source: "auth", EventType: "login", Field: "target", Equals: "admin"},
	}}))

	en := security.NewEnforcer()
	en.Grant(security.Role{
		Name:           "auditor",
		AllowedSources: map[string]bool{"payments": true},
		AllowedFields:  map[string]bool{"risk": true, "amount": true},
	})
	en.Grant(security.Role{
		Name:           "security",
		AllowedSources: map[string]bool{"auth": true, "payments": true},
		AllowedFields:  map[string]bool{"*": true},
		RedactedFields: map[string]bool{"ssn": true},
	})
	qs := query.NewService(st, en)

	// ---- concurrent writers ----------------------------------------
	fmt.Println("\n== concurrent ingestion ==")
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			src, typ, risk := "payments", "transfer", "low"
			if i%3 == 0 {
				risk = "high"
			}
			if i >= 10 {
				src, typ, risk = "auth", "login", ""
			}
			raw := model.RawEvent{
				Source: src, Type: typ, Timestamp: time.Now(),
				Payload: map[string]string{"risk": risk, "amount": fmt.Sprintf("%d", 100+i), "ssn": "123-45-6789"},
			}
			res, err := pl.Submit(ctx, raw)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Printf("input=%+v -> ERROR %v\n", raw.Source, err)
				return
			}
			fmt.Printf("input=%s/%s risk=%s -> seq=%d batch=%s matched=%v rule=%s reason=%q\n",
				raw.Source, raw.Type, raw.Payload["risk"], res.Seq, res.BatchID, res.Matched, res.HitRuleID, res.Reason)
		}(i)
	}
	wg.Wait()

	batches, err := qs.Batches(ctx, "auditor")
	must(err)
	fmt.Printf("\nsealed batches after rotation (size=5): %d\n", len(batches))
	for _, b := range batches {
		fmt.Printf("  batch=%s count=%d seq=[%d..%d] sealed=%s\n", b.ID, b.Count, b.MinSeq, b.MaxSeq, b.SealedAt)
	}

	// ---- queries: masking and denial --------------------------------
	fmt.Println("\n== least-privilege queries ==")
	views, err := qs.Query(ctx, "auditor", "", "payments", "", 100)
	must(err)
	for _, v := range views {
		fmt.Printf("auditor sees seq=%d batch=%s payload=%v matched=%v\n", v.Seq, v.BatchID, v.Payload, v.Matched)
	}
	_, err = qs.Query(ctx, "auditor", "", "auth", "", 10)
	fmt.Printf("auditor query auth -> %v (expect ACCESS_DENIED)\n", err)
	views, err = qs.Query(ctx, "security", "", "payments", "", 2)
	must(err)
	for _, v := range views {
		fmt.Printf("security sees seq=%d payload=%v (ssn redacted)\n", v.Seq, v.Payload)
	}

	// ---- distinguishable rejections --------------------------------
	fmt.Println("\n== bad inputs ==")
	_, err = pl.SubmitJSON(ctx, []byte("{not json"))
	fmt.Printf("malformed json -> %v\n", err)
	_, err = pl.Submit(ctx, model.RawEvent{Source: "payments", Type: "transfer", Payload: map[string]string{"a": "b"}})
	fmt.Printf("missing timestamp -> %v\n", err)
	_, err = pl.Submit(ctx, model.RawEvent{Source: "unknown", Type: "x", Timestamp: time.Now(), Payload: map[string]string{}})
	fmt.Printf("unknown source -> %v\n", err)
	_, err = pl.Submit(ctx, model.RawEvent{Source: "payments", Type: "transfer", Timestamp: time.Now(),
		Payload: map[string]string{"k": string(make([]byte, 600))}})
	fmt.Printf("value too large -> %v\n", err)

	// ---- partial consumption then restart ---------------------------
	fmt.Println("\n== restart recovery ==")
	maxSeq, err := st.AppendedSeq(ctx)
	must(err)
	must(pl.Consume(ctx, maxSeq-2, 0)) // leave 2 events unconsumed
	cur, err := pl.Cursor(ctx)
	must(err)
	fmt.Printf("before restart: maxSeq=%d cursor=%+v\n", maxSeq, cur)
	must(st.Close())

	// reopen everything from disk, exactly like a fresh process
	st2, err := store.New(dir)
	must(err)
	rt2, err := retention.NewManager(retention.Policy{
		MaxBatchRecords: 5, MaxBatchAge: time.Hour, Retention: time.Hour,
	}, st2)
	must(err)
	rr2 := router.NewRouter()
	pl2, err := pipeline.New(st2, rt2, rr2, pipeline.Config{
		MaxPayloadBytes: 4096, MaxFieldValueLen: 512,
		KnownSources: map[string]bool{"payments": true, "auth": true},
	})
	must(err)
	must(pl2.LoadPoliciesFromStore(ctx))
	replayed, accepted, err := pl2.Recover(ctx)
	must(err)
	fmt.Printf("after restart: replayed=%d accepted(matched)=%d\n", replayed, accepted)
	replayed2, _, err := pl2.Recover(ctx)
	must(err)
	fmt.Printf("second recover: replayed=%d (expect 0; no double counting)\n", replayed2)
	cur2, err := pl2.Cursor(ctx)
	must(err)
	fmt.Printf("cursor after recovery=%+v\n", cur2)

	// ---- policy update reproducibility ------------------------------
	must(pl2.InstallPolicy(ctx, model.Policy{Version: 2, Rules: []model.Rule{
		{ID: "pay-all", Source: "payments", EventType: "transfer", Field: "risk", Equals: "low"},
	}}))
	m1, err := rr2.RouteWith(model.Event{Source: "payments", Type: "transfer", Payload: map[string]string{"risk": "high"}}, 1)
	must(err)
	m2, err := rr2.RouteWith(model.Event{Source: "payments", Type: "transfer", Payload: map[string]string{"risk": "high"}}, 2)
	must(err)
	fmt.Printf("\nreproducibility: same event under v1 matched=%v (%s); under v2 matched=%v (%s)\n",
		m1.Matched, m1.RuleID, m2.Matched, m2.RuleID)

	// ---- cleanup: future clock deletes all sealed batches ------------
	removed, err := rt2.Cleanup(ctx, time.Now().Add(2*time.Hour))
	must(err)
	fmt.Printf("\ncleanup removed %d sealed batches: %v\n", len(removed), removed)
	dir2 := filepath.Join(dir, "batches")
	entries, _ := os.ReadDir(dir2)
	fmt.Print("remaining batch files (only the open .jsonl): ")
	for _, e := range entries {
		fmt.Print(e.Name(), " ")
	}
	fmt.Println()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL:", err)
		os.Exit(1)
	}
}
