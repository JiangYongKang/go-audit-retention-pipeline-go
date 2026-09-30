package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// testLogger 在单测中统一打印：输入（原始 JSON）、批次标识与判定依据，
// 满足“结论可解释、可追溯”的验证要求。
type testLogger struct{ t *testing.T }

func newTL(t *testing.T) *testLogger {
	t.Helper()
	return &testLogger{t: t}
}

func (l *testLogger) submit(n int, raw string, seq int64, err error) {
	t := l.t
	if err != nil {
		code := Code("?")
		if ae, ok := AsError(err); ok {
			code = ae.Code
		}
		t.Logf("[CASE %03d] INPUT=%s => REJECTED code=%s detail=%v", n, raw, code, err)
		return
	}
	t.Logf("[CASE %03d] INPUT=%s => ACCEPTED seq=%d", n, raw, seq)
}

func (l *testLogger) decisions(tag string, views []EventView) {
	for i, v := range views {
		t := l.t
		t.Logf("[%s #%02d] BATCH=%s EVENT_ID=%s VERDICT=%s RULE=%s POLICY=v%d BASIS=%s",
			tag, i+1, v.Batch, v.ID, v.Decision.Verdict, v.Decision.RuleID,
			v.Decision.PolicyVersion, v.Decision.Basis)
	}
}

type eventInput struct {
	ID         string            `json:"id"`
	Source     Source            `json:"source"`
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	Actor      string            `json:"actor,omitempty"`
	Action     string            `json:"action,omitempty"`
	Resource   string            `json:"resource,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	Email      string            `json:"email,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func newTestPipeline(t *testing.T, retention RetentionConfig) *Pipeline {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	p, err := New(PipelineConfig{
		Dir:           dir,
		MaxEventBytes: 2048,
		Sources:       []Source{"web", "cli", "cron"},
		Retention:     retention,
	})
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	v, err := p.PublishPolicy(defaultRules())
	if err != nil || v != 1 {
		t.Fatalf("publish: v=%d err=%v", v, err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func defaultRules() []Rule {
	return []Rule{
		{ID: "web-login", Sources: []Source{"web"}, Types: []string{"login"},
			Action: ActionFlag, Reason: "review web logins"},
		{ID: "cli-allow", Sources: []Source{"cli"}, Action: ActionAllow},
		{ID: "cron-deny", Sources: []Source{"cron"}, Types: []string{"job"},
			Action: ActionDeny, Reason: "deny cron jobs"},
	}
}

func adminPrincipal() Principal {
	return Principal{Name: "admin", Scopes: map[Scope]bool{
		ScopeQuery: true, ScopeEventActor: true, ScopeEventIP: true,
		ScopeEventEmail: true, ScopeEventAttrAll: true,
		Scope("event.attributes.department"): true,
	}}
}

func viewerPrincipal() Principal {
	return Principal{Name: "viewer", Scopes: map[Scope]bool{ScopeQuery: true}}
}

func makeEvent(id string, src Source, typ string) eventInput {
	return eventInput{
		ID: id, Source: src, Type: typ,
		OccurredAt: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
		Actor:      "actor-" + id, SourceIP: "10.1.2.3",
		Email:      id + "@example.com",
		Attributes: map[string]string{"department": "sec", "k": "v"},
	}
}

func timeNow() time.Time { return time.Now().UTC() }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
