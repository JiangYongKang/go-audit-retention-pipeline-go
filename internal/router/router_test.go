package router

import (
	"context"
	"testing"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

func event(source, typ string, payload map[string]string) model.Event {
	return model.Event{Source: source, Type: typ, Payload: payload}
}

func TestRoutingBasis(t *testing.T) {
	r := NewRouter()
	pol := model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "pay-fraud", Source: "payments", EventType: "transfer", Field: "risk", Equals: "high"},
	}}
	if err := r.PutPolicy(pol); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		ev     model.Event
		match  bool
		rule   string
		reason string // substring expected in match trace fields
		got    string
	}{
		{"hit", event("payments", "transfer", map[string]string{"risk": "high"}), true, "pay-fraud", "", "high"},
		{"wrong value", event("payments", "transfer", map[string]string{"risk": "low"}), false, "pay-fraud", "expected", "low"},
		{"missing field", event("payments", "transfer", map[string]string{}), false, "pay-fraud", "missing", "<missing>"},
		{"no applicable rule", event("auth", "login", map[string]string{}), false, "", "noapplicable", "<no applicable rule>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := r.Route(context.Background(), tc.ev)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("input=%s/%s payload=%v -> batch decision: rule=%s matched=%v field=%s expect=%s got=%s",
				tc.ev.Source, tc.ev.Type, tc.ev.Payload, m.RuleID, m.Matched, m.MatchedField, m.ExpectValue, m.GotValue)
			if m.Matched != tc.match || m.RuleID != tc.rule {
				t.Fatalf("match=%v rule=%s, want %v %s", m.Matched, m.RuleID, tc.match, tc.rule)
			}
			if m.GotValue != tc.got {
				t.Fatalf("got=%q want %q", m.GotValue, tc.got)
			}
			if tc.reason == "expected" && (m.ExpectValue != "high" || m.MatchedField != "risk") {
				t.Fatalf("decision basis missing expected field/value: %+v", m)
			}
		})
	}
}

func TestPolicyImmutabilityAndReproducibility(t *testing.T) {
	r := NewRouter()
	if err := r.PutPolicy(model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "a", Source: "s", EventType: "e", Field: "f", Equals: "1"},
	}}); err != nil {
		t.Fatal(err)
	}
	// Same content is idempotent.
	if err := r.PutPolicy(model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "a", Source: "s", EventType: "e", Field: "f", Equals: "1"},
	}}); err != nil {
		t.Fatalf("identical reinstall: %v", err)
	}
	// Different content under same version is rejected.
	if err := r.PutPolicy(model.Policy{Version: 1, Rules: []model.Rule{
		{ID: "a", Source: "s", EventType: "e", Field: "f", Equals: "2"},
	}}); err == nil {
		t.Fatal("conflicting immutable policy was accepted")
	}
	if err := r.PutPolicy(model.Policy{Version: 2, Rules: []model.Rule{
		{ID: "b", Source: "s", EventType: "e", Field: "f", Equals: "1"},
	}}); err != nil {
		t.Fatal(err)
	}
	ev := event("s", "e", map[string]string{"f": "1"})
	m1, _ := r.RouteWith(ev, 1)
	m2, _ := r.RouteWith(ev, 2)
	t.Logf("input payload f=1 -> v1 rule=%s matched=%v; v2 rule=%s matched=%v", m1.RuleID, m1.Matched, m2.RuleID, m2.Matched)
	if m1.RuleID != "a" || m2.RuleID != "b" || !m1.Matched || !m2.Matched {
		t.Fatal("historical policy versions not reproducible")
	}
	if _, err := r.RouteWith(ev, 99); err == nil {
		t.Fatal("routing with missing version should fail")
	}
}
