// Package model defines the core audit event domain types.
package model

import "time"

// RawEvent is an event submitted by a producer.
type RawEvent struct {
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Payload   map[string]string `json:"payload"`
}

// Event is a validated event carrying a global sequence number.
type Event struct {
	Seq       int64
	Source    string
	Type      string
	Timestamp time.Time
	Payload   map[string]string
}

// Match records why a rule did or did not match.
type Match struct {
	RuleID       string `json:"rule_id"`
	Matched      bool   `json:"matched"`
	PolicyVer    int64  `json:"policy_ver"`
	MatchedField string `json:"matched_field"`
	ExpectValue  string `json:"expect_value"`
	GotValue     string `json:"got_value"`
}

// Record is a routed, persisted processing result.
type Record struct {
	Seq        int64             `json:"seq"`
	BatchID    string            `json:"batch_id"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Timestamp  time.Time         `json:"timestamp"`
	Payload    map[string]string `json:"payload"`
	Matched    bool              `json:"matched"`
	HitRuleID  string            `json:"hit_rule_id"`
	PolicyVer  int64             `json:"policy_ver"`
	Reason     string            `json:"reason"`
	Accepted   bool              `json:"accepted"`
	RejectCode string            `json:"reject_code,omitempty"`
}

// Rule is a single routing rule within a policy.
type Rule struct {
	ID        string `json:"id"`
	Source    string `json:"source"`
	EventType string `json:"event_type"`
	Field     string `json:"field"`
	Equals    string `json:"equals"`
}

// Policy is an immutable, versioned routing configuration.
type Policy struct {
	Version int64  `json:"version"`
	Rules   []Rule `json:"rules"`
}

// BatchMeta describes a sealed retention batch.
type BatchMeta struct {
	ID       string    `json:"id"`
	OpenedAt time.Time `json:"opened_at"`
	SealedAt time.Time `json:"sealed_at"`
	MinSeq   int64     `json:"min_seq"`
	MaxSeq   int64     `json:"max_seq"`
	Count    int       `json:"count"`
}

// Cursor tracks consumer progress for restart recovery.
type Cursor struct {
	LastConsumedSeq int64 `json:"last_consumed_seq"`
	AcceptedCount   int64 `json:"accepted_count"`
}

// SubmissionResult is the per-event result returned to producers.
type SubmissionResult struct {
	Accepted   bool
	Seq        int64
	BatchID    string
	Matched    bool
	HitRuleID  string
	PolicyVer  int64
	Reason     string
	RejectCode string
}
