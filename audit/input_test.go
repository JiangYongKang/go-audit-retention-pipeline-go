package audit

import (
	"strings"
	"testing"
	"time"
)

// TestRejectionCodes 各类坏输入必须返回互相可区分的原因码，
// 绝不静默丢弃、绝不混成同一种错误。
func TestRejectionCodes(t *testing.T) {
	log := newTL(t)
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 10, MaxBatchBytes: 4096, MaxBatchAge: time.Hour,
	})
	now := timeNow()

	cases := []struct {
		name string
		raw  []byte
		want Code
	}{
		{"oversized", make([]byte, p.cfg.MaxEventBytes+1), CodeOversized},
		{"empty", nil, CodeFormat},
		{"malformed_json", []byte("{not-json"), CodeFormat},
		{"trailing_values", []byte(`{"a":1}{"b":2}`), CodeFormat},
		{"missing_id", mustJSON(t, eventInput{
			Source: "web", Type: "login", OccurredAt: now}), CodeMissingField},
		{"missing_source", mustJSON(t, eventInput{
			ID: "x", Type: "login", OccurredAt: now}), CodeMissingField},
		{"missing_type", mustJSON(t, eventInput{
			ID: "x", Source: "web", OccurredAt: now}), CodeMissingField},
		{"missing_occurred_at", mustJSON(t, eventInput{
			ID: "x", Source: "web", Type: "login"}), CodeMissingField},
		{"unknown_source", mustJSON(t, eventInput{
			ID: "x", Source: "iot", Type: "login", OccurredAt: now}), CodeUnknownSource},
		{"oversized_id", mustJSON(t, eventInput{
			ID: strings.Repeat("a", MaxEventIDLen+1), Source: "web",
			Type: "login", OccurredAt: now}), CodeOversized},
		{"oversized_attrs", mustJSON(t, func() eventInput {
			e := makeEvent("big", "web", "login")
			e.Attributes = map[string]string{}
			for i := 0; i < MaxAttrEntries+1; i++ {
				e.Attributes["k"+itoa(i)] = "v"
			}
			return e
		}()), CodeOversized},
	}
	for i, tc := range cases {
		_, err := p.SubmitBytes(tc.raw)
		log.submit(i+1, truncate(string(tc.raw)), 0, err)
		if !IsCode(err, tc.want) {
			t.Errorf("%s: want code %s got %v", tc.name, tc.want, err)
		}
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// 所有坏输入必须只计拒绝、不产生已处理事件。
	st := p.Stats()
	if st.Processed != 0 || st.Rejected != int64(len(cases)) {
		t.Fatalf("processed=%d rejected=%d want 0/%d", st.Processed, st.Rejected, len(cases))
	}
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "...(truncated)"
	}
	return s
}
