// Package router performs versioned rule routing.
//
// Every decision carries the policy version and, for each evaluated rule,
// the field, expected and observed value, so a hit or miss is fully
// explainable. Policy versions are immutable once installed; evaluating an
// event against an explicit version keeps historical results reproducible
// after a policy update.
package router

import (
	"context"
	"sync"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

// Router routes events against versioned policies.
type Router struct {
	mu       sync.RWMutex
	policies map[int64]model.Policy
	current  int64
}

// NewRouter constructs an empty Router.
func NewRouter() *Router {
	return &Router{policies: map[int64]model.Policy{}}
}

// PutPolicy installs an immutable policy version. Re-installing the same
// version with identical content is idempotent; conflicting content fails.
// Versions must be positive and move forward monotonically.
func (r *Router) PutPolicy(p model.Policy) error {
	if p.Version <= 0 {
		return apperr.New(apperr.CodePolicyFailure, "policy version must be positive")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.policies[p.Version]; ok {
		if !equalPolicy(existing, p) {
			return apperr.New(apperr.CodePolicyFailure, "immutable policy version conflict")
		}
		return nil
	}
	if p.Version <= r.current {
		return apperr.New(apperr.CodePolicyFailure, "policy version must be greater than current")
	}
	r.policies[p.Version] = p
	r.current = p.Version
	return nil
}

// Route evaluates an event against the policy currently active.
func (r *Router) Route(ctx context.Context, e model.Event) (model.Match, error) {
	r.mu.RLock()
	ver := r.current
	r.mu.RUnlock()
	return r.RouteWith(e, ver)
}

// RouteWith evaluates an event against a specific policy version. The
// resulting Match is deterministic for a given (event, version) pair.
func (r *Router) RouteWith(e model.Event, version int64) (model.Match, error) {
	r.mu.RLock()
	p, ok := r.policies[version]
	r.mu.RUnlock()
	if !ok {
		return model.Match{}, apperr.New(apperr.CodePolicyFailure, "policy version not installed")
	}
	m := model.Match{PolicyVer: version}
	for _, rule := range p.Rules {
		if rule.Source != "" && rule.Source != e.Source {
			continue
		}
		if rule.EventType != "" && rule.EventType != e.Type {
			continue
		}
		got, present := e.Payload[rule.Field]
		m = model.Match{
			RuleID:       rule.ID,
			PolicyVer:    version,
			MatchedField: rule.Field,
			ExpectValue:  rule.Equals,
			GotValue:     got,
		}
		if present && got == rule.Equals {
			m.Matched = true
			return m, nil
		}
		// First applicable rule (source/type match) determines the
		// miss reason, including a missing field.
		if !present {
			m.GotValue = "<missing>"
		}
		return m, nil
	}
	// No rule applied to this source/type at all: a documented non-hit.
	return model.Match{PolicyVer: version, GotValue: "<no applicable rule>"}, nil
}

// CurrentVersion returns the latest installed policy version.
func (r *Router) CurrentVersion() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

func equalPolicy(a, b model.Policy) bool {
	if a.Version != b.Version || len(a.Rules) != len(b.Rules) {
		return false
	}
	for i := range a.Rules {
		if a.Rules[i] != b.Rules[i] {
			return false
		}
	}
	return true
}
