package security

import (
	"context"
	"testing"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

func mkRecord() model.Record {
	return model.Record{
		Seq: 1, BatchID: "b1", Source: "payments", Type: "transfer",
		Timestamp: time.Now(),
		Payload: map[string]string{
			"risk": "high", "amount": "100", "ssn": "123-45-6789",
		},
		Matched: true, HitRuleID: "pay-fraud", PolicyVer: 1, Reason: "r",
	}
}

func TestDenyUnknownPrincipalAndSource(t *testing.T) {
	ctx := context.Background()
	e := NewEnforcer()
	e.Grant(Role{
		Name: "auditor", AllowedSources: map[string]bool{"payments": true},
		AllowedFields: map[string]bool{"risk": true},
	})
	if err := e.CheckSource(ctx, "ghost", "payments"); err == nil {
		t.Fatal("unknown principal was allowed")
	}
	if err := e.CheckSource(ctx, "auditor", "auth"); err == nil {
		t.Fatal("missing source grant was allowed")
	} else {
		t.Logf("input principal=auditor source=auth -> %v", err)
	}
	if _, err := e.Mask(ctx, "ghost", mkRecord()); err == nil {
		t.Fatal("masking for unknown principal must fail with ACCESS_DENIED")
	}
}

func TestMaskingHidesFieldsCompletely(t *testing.T) {
	ctx := context.Background()
	e := NewEnforcer()
	e.Grant(Role{
		Name: "auditor", AllowedSources: map[string]bool{"payments": true},
		AllowedFields: map[string]bool{"risk": true}, // amount and ssn hidden
	})
	v, err := e.Mask(ctx, "auditor", mkRecord())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input payload={risk,amount,ssn} -> auditor view=%v", v.Payload)
	if _, present := v.Payload["ssn"]; present {
		t.Fatal("hidden field ssn leaked into view")
	}
	if _, present := v.Payload["amount"]; present {
		t.Fatal("hidden field amount leaked into view")
	}
	if v.Payload["risk"] != "high" {
		t.Fatalf("allowed field wrong: %v", v.Payload)
	}
	if len(v.Payload) != 1 {
		t.Fatal("hidden fields must leave no structural trace in response")
	}
}

func TestRedactionIsStable(t *testing.T) {
	ctx := context.Background()
	e := NewEnforcer()
	e.Grant(Role{
		Name: "sec", AllowedSources: map[string]bool{"payments": true},
		AllowedFields:  map[string]bool{"*": true},
		RedactedFields: map[string]bool{"ssn": true},
	})
	v1, err := e.Mask(ctx, "sec", mkRecord())
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := e.Mask(ctx, "sec", mkRecord())
	t.Logf("input ssn=123-45-6789 -> redacted=%s stable=%v", v1.Payload["ssn"], v1.Payload["ssn"] == v2.Payload["ssn"])
	if v1.Payload["ssn"] == "123-45-6789" {
		t.Fatal("raw sensitive value leaked")
	}
	if v1.Payload["ssn"] != v2.Payload["ssn"] {
		t.Fatal("redaction must be deterministic for equality correlation")
	}
}
