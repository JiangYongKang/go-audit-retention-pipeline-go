// Package pipeline wires validation, routing, storage, retention and
// consumer cursors into one consistent ingestion flow.
package pipeline

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/retention"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/router"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/store"
)

// Config are pipeline limits and dependencies.
type Config struct {
	// MaxPayloadBytes limits the total UTF-8 byte size of payload values.
	MaxPayloadBytes int
	// MaxFieldValueLen limits a single payload value.
	MaxFieldValueLen int
	// KnownSources, when non-nil, restricts accepted event sources.
	KnownSources map[string]bool
}

// Pipeline ingests and consumes events.
type Pipeline struct {
	store  *store.Store
	rt     *retention.Manager
	router *router.Router
	cfg    Config

	mu   sync.Mutex
	next int64 // next global sequence; rebuilt from storage on startup
}

// New constructs a Pipeline and seeds the sequence counter from durable
// storage, which is what makes restarted processes continue without
// reusing or repeating sequence numbers.
func New(st *store.Store, rt *retention.Manager, rr *router.Router, cfg Config) (*Pipeline, error) {
	maxSeq, err := st.AppendedSeq(context.Background())
	if err != nil {
		return nil, err
	}
	return &Pipeline{store: st, rt: rt, router: rr, cfg: cfg, next: maxSeq + 1}, nil
}

// Submit validates, routes and persists one event. Validation rejections
// are returned as *apperr.Error with distinct codes and are never
// persisted; accepted events return the decision and batch placement.
func (p *Pipeline) Submit(ctx context.Context, raw model.RawEvent) (model.SubmissionResult, error) {
	if err := p.validate(raw); err != nil {
		return model.SubmissionResult{Accepted: false}, err
	}

	p.mu.Lock()
	seq := p.next
	p.next++
	p.mu.Unlock()

	ev := model.Event{
		Seq:       seq,
		Source:    raw.Source,
		Type:      raw.Type,
		Timestamp: raw.Timestamp,
		Payload:   raw.Payload,
	}
	match, err := p.router.Route(ctx, ev)
	if err != nil {
		// Internal routing failure: release the reserved sequence so the
		// durable stream stays gap-free and the failure is distinguishable
		// from a producer-caused rejection.
		p.rollbackSeq(seq)
		return model.SubmissionResult{Accepted: false}, apperr.Wrap(apperr.CodePolicyFailure, "routing failed", err)
	}

	// BatchID is left empty: the store assigns ownership under its write
	// lock, guaranteeing the record never lands in a batch sealed by a
	// concurrent writer.
	rec := model.Record{
		Seq:       seq,
		Source:    ev.Source,
		Type:      ev.Type,
		Timestamp: ev.Timestamp,
		Payload:   ev.Payload,
		Matched:   match.Matched,
		HitRuleID: match.RuleID,
		PolicyVer: match.PolicyVer,
		Reason:    explain(match),
		Accepted:  true,
	}
	if err := p.store.Append(ctx, rec); err != nil {
		p.rollbackSeq(seq)
		return model.SubmissionResult{}, err
	}
	count, err := p.store.OpenBatchCount(ctx)
	if err != nil {
		return model.SubmissionResult{}, apperr.Wrap(apperr.CodeInternal, "read batch count failed", err)
	}
	if err := p.rt.OnWrite(ctx, count); err != nil {
		// The event is already durable; rotation failure must not lose it
		// or report rejection. Surface as internal error but keep result.
		return model.SubmissionResult{
			Accepted: true, Seq: seq, BatchID: rec.BatchID,
			Matched: rec.Matched, HitRuleID: rec.HitRuleID,
			PolicyVer: rec.PolicyVer, Reason: rec.Reason,
		}, apperr.Wrap(apperr.CodeInternal, "rotation failed", err)
	}
	return model.SubmissionResult{
		Accepted:  true,
		Seq:       seq,
		BatchID:   rec.BatchID,
		Matched:   rec.Matched,
		HitRuleID: rec.HitRuleID,
		PolicyVer: rec.PolicyVer,
		Reason:    rec.Reason,
	}, nil
}

// rollbackSeq returns a reserved-but-unused sequence to the counter. Only
// the currently highest reservation can be rolled back, so concurrent
// appends cannot collide.
func (p *Pipeline) rollbackSeq(seq int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.next == seq+1 {
		p.next = seq
	}
}

func (p *Pipeline) validate(raw model.RawEvent) error {
	if raw.Source == "" {
		return apperr.New(apperr.CodeMissingField, "missing field: source")
	}
	if raw.Type == "" {
		return apperr.New(apperr.CodeMissingField, "missing field: type")
	}
	if raw.Timestamp.IsZero() {
		return apperr.New(apperr.CodeMissingField, "missing field: timestamp")
	}
	if raw.Timestamp.After(time.Now().Add(time.Hour)) {
		return apperr.New(apperr.CodeMissingField, "timestamp in the future beyond tolerance")
	}
	if raw.Payload == nil {
		return apperr.New(apperr.CodeMissingField, "missing field: payload")
	}
	if p.cfg.KnownSources != nil && !p.cfg.KnownSources[raw.Source] {
		return apperr.New(apperr.CodeUnknownSource, "unknown source: "+raw.Source)
	}
	var total int
	for k, v := range raw.Payload {
		if k == "" {
			return apperr.New(apperr.CodeMissingField, "payload contains empty key")
		}
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			return apperr.New(apperr.CodeMalformedJSON, "payload key/value must be valid UTF-8")
		}
		total += len(k) + len(v)
		if p.cfg.MaxFieldValueLen > 0 && len(v) > p.cfg.MaxFieldValueLen {
			return apperr.New(apperr.CodeValueTooLarge, "payload value exceeds length limit")
		}
	}
	if p.cfg.MaxPayloadBytes > 0 && total > p.cfg.MaxPayloadBytes {
		return apperr.New(apperr.CodeValueTooLarge, "payload exceeds total byte limit")
	}
	return nil
}

func explain(m model.Match) string {
	switch {
	case m.Matched:
		return "rule " + m.RuleID + " matched: " + m.MatchedField + "==" + m.ExpectValue
	case m.RuleID != "" && m.GotValue == "<missing>":
		return "rule " + m.RuleID + " not matched: field " + m.MatchedField + " missing"
	case m.RuleID != "":
		return "rule " + m.RuleID + " not matched: " + m.MatchedField + " expected=" + m.ExpectValue + " got=" + m.GotValue
	default:
		return "no applicable rule under policy v" + strconv.FormatInt(m.PolicyVer, 10)
	}
}

// Recover reprocesses persisted events beyond the consumer cursor after a
// restart. It never re-counts events at or before the cursor and persists
// an updated cursor, so repeated restarts are idempotent.
func (p *Pipeline) Recover(ctx context.Context) (replayed int, accepted int, err error) {
	cursor, err := p.store.LoadCursor(ctx)
	if err != nil {
		return 0, 0, err
	}
	recs, err := p.store.ListAll(ctx)
	if err != nil {
		return 0, 0, err
	}
	var newAccepted int64
	var lastSeq int64 = cursor.LastConsumedSeq
	for _, rec := range recs {
		if rec.Seq <= cursor.LastConsumedSeq {
			continue
		}
		replayed++
		if rec.Matched {
			newAccepted++
		}
		lastSeq = rec.Seq
	}
	if replayed > 0 {
		if err := p.store.SaveCursor(ctx, model.Cursor{
			LastConsumedSeq: lastSeq,
			AcceptedCount:   cursor.AcceptedCount + newAccepted,
		}); err != nil {
			return 0, 0, err
		}
	}
	return replayed, int(newAccepted), nil
}

// Consume advances the consumer cursor through throughSeq and records how
// many of the newly consumed events were accepted. Advancing over the same
// range again changes nothing.
func (p *Pipeline) Consume(ctx context.Context, throughSeq int64, acceptedDelta int64) error {
	cursor, err := p.store.LoadCursor(ctx)
	if err != nil {
		return err
	}
	if throughSeq <= cursor.LastConsumedSeq {
		return nil // idempotent: range already consumed
	}
	return p.store.SaveCursor(ctx, model.Cursor{
		LastConsumedSeq: throughSeq,
		AcceptedCount:   cursor.AcceptedCount + acceptedDelta,
	})
}

// Cursor returns the current consumer cursor.
func (p *Pipeline) Cursor(ctx context.Context) (model.Cursor, error) {
	return p.store.LoadCursor(ctx)
}

// SubmitJSON parses one JSON-encoded event and submits it. JSON syntax or
// type errors are reported as MALFORMED_JSON so producers can distinguish
// bad framing from semantic validation rejections.
func (p *Pipeline) SubmitJSON(ctx context.Context, data []byte) (model.SubmissionResult, error) {
	var raw model.RawEvent
	if err := json.Unmarshal(data, &raw); err != nil {
		return model.SubmissionResult{Accepted: false},
			apperr.Wrap(apperr.CodeMalformedJSON, "event is not valid JSON", err)
	}
	return p.Submit(ctx, raw)
}

// InstallPolicy durably stores a policy and activates it in the router.
// Stored versions are immutable, so historical decisions stay reproducible.
func (p *Pipeline) InstallPolicy(ctx context.Context, pol model.Policy) error {
	if err := p.store.PutPolicy(ctx, pol); err != nil {
		return err
	}
	return p.router.PutPolicy(pol)
}

// LoadPoliciesFromStore activates all durable policy versions in the
// router after a restart. Routing then behaves exactly as before the
// restart, including for historical version lookups.
func (p *Pipeline) LoadPoliciesFromStore(ctx context.Context) error {
	latest, err := p.store.LatestPolicyVersion(ctx)
	if err != nil {
		return err
	}
	for v := int64(1); v <= latest; v++ {
		pol, err := p.store.GetPolicy(ctx, v)
		if err != nil {
			return err
		}
		if err := p.router.PutPolicy(pol); err != nil {
			return err
		}
	}
	return nil
}
