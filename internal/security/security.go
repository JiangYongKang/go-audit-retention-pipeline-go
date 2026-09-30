// Package security enforces least-privilege field access and masking.
//
// Access control has two layers:
//
//  1. A principal without a grant for an event source is denied outright.
//  2. A principal may only see payload fields its role lists. Fields that
//     are not permitted are omitted from the response completely: the
//     response shape, error text and counts never reveal that a hidden
//     field exists or what it contained.
//
// Fields explicitly listed as redacted are visible as keys but their value
// is replaced by a stable SHA-256 prefix, which is enough to correlate
// equality across events without exposing the value itself.
package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

// Role describes a principal's source and field grants.
type Role struct {
	Name           string
	AllowedSources map[string]bool
	AllowedFields  map[string]bool
	RedactedFields map[string]bool
}

// Enforcer authorizes access and masks records.
type Enforcer struct {
	mu    sync.RWMutex
	roles map[string]Role
}

// NewEnforcer constructs an Enforcer with no roles.
func NewEnforcer() *Enforcer {
	return &Enforcer{roles: map[string]Role{}}
}

// Grant installs or replaces a role.
func (e *Enforcer) Grant(r Role) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roles[r.Name] = r
}

func (e *Enforcer) role(principal string) (Role, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r, ok := e.roles[principal]
	return r, ok
}

// CheckSource denies principals without a grant for the source. The error
// is identical for an unknown principal and a known one missing the grant,
// so it cannot be used to probe role existence.
func (e *Enforcer) CheckSource(ctx context.Context, principal, source string) error {
	r, ok := e.role(principal)
	if !ok || !r.AllowedSources["*"] && !r.AllowedSources[source] {
		return apperr.New(apperr.CodeAccessDenied, "access denied")
	}
	return nil
}

// View is a masked projection of a record. Hidden fields are absent rather
// than null, leaving no structural trace of their existence.
type View struct {
	Seq       int64             `json:"seq"`
	BatchID   string            `json:"batch_id"`
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Matched   bool              `json:"matched"`
	HitRuleID string            `json:"hit_rule_id"`
	PolicyVer int64             `json:"policy_ver"`
	Reason    string            `json:"reason"`
	Payload   map[string]string `json:"payload"`
}

// Mask projects the fields the principal is allowed to see.
func (e *Enforcer) Mask(ctx context.Context, principal string, rec model.Record) (View, error) {
	r, ok := e.role(principal)
	if !ok || !r.AllowedSources["*"] && !r.AllowedSources[rec.Source] {
		return View{}, apperr.New(apperr.CodeAccessDenied, "access denied")
	}
	v := View{
		Seq:       rec.Seq,
		BatchID:   rec.BatchID,
		Source:    rec.Source,
		Type:      rec.Type,
		Timestamp: rec.Timestamp,
		Matched:   rec.Matched,
		HitRuleID: rec.HitRuleID,
		PolicyVer: rec.PolicyVer,
		Reason:    rec.Reason,
		Payload:   map[string]string{},
	}
	for k, val := range rec.Payload {
		if !r.AllowedFields["*"] && !r.AllowedFields[k] {
			continue // hidden: key and value vanish entirely
		}
		if r.RedactedFields[k] {
			sum := sha256.Sum256([]byte(val))
			val = "sha256:" + hex.EncodeToString(sum[:])[:12]
		}
		v.Payload[k] = val
	}
	return v, nil
}
