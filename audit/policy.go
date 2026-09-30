package audit

import (
	"fmt"
	"strings"
	"time"
)

type (
	// RuleID 规则标识。
	RuleID string
	// PolicyVersion 策略版本，单调递增、不可变。
	PolicyVersion int64
	// DecisionAction 规则命中后的动作。
	DecisionAction string
)

const (
	ActionAllow DecisionAction = "allow"
	ActionDeny  DecisionAction = "deny"
	ActionFlag  DecisionAction = "flag"
)

// Rule 按顺序匹配，空切片代表该维度通配；首个命中的规则生效。
type Rule struct {
	ID      RuleID         `json:"id"`
	Sources []Source       `json:"sources,omitempty"`
	Types   []string       `json:"types,omitempty"`
	Actions []string       `json:"actions,omitempty"`
	Action  DecisionAction `json:"action"`
	Reason  string         `json:"reason,omitempty"`
}

// Policy 是某一版本的不可变规则快照。
type Policy struct {
	Version   PolicyVersion `json:"version"`
	CreatedAt time.Time     `json:"created_at"`
	Rules     []Rule        `json:"rules"`
}

func (r Rule) matches(e *Event) (bool, string) {
	var missed []string
	if len(r.Sources) > 0 {
		if !sourceIn(e.Source, r.Sources) {
			missed = append(missed, fmt.Sprintf("source=%q not in %v", e.Source, r.Sources))
		}
	}
	if len(r.Types) > 0 {
		if !stringIn(e.Type, r.Types) {
			missed = append(missed, fmt.Sprintf("type=%q not in %v", e.Type, r.Types))
		}
	}
	if len(r.Actions) > 0 {
		if !stringIn(e.Action, r.Actions) {
			missed = append(missed, fmt.Sprintf("action=%q not in %v", e.Action, r.Actions))
		}
	}
	if len(missed) > 0 {
		return false, strings.Join(missed, "; ")
	}
	return true, ""
}

// Evaluation 记录判定结论与可追溯依据。
type Evaluation struct {
	Matched bool          `json:"matched"`
	RuleID  RuleID        `json:"rule_id,omitempty"`
	Version PolicyVersion `json:"version"`
	Verdict Verdict       `json:"verdict"`
	Basis   string        `json:"basis"`
}

// PolicyBook 保存全部历史版本快照（发布后不可变），
// 保证策略更新后仍可按旧版本复现历史结论。
type PolicyBook struct {
	versions map[PolicyVersion]*Policy
	latest   PolicyVersion
}

func NewPolicyBook() *PolicyBook {
	return &PolicyBook{versions: map[PolicyVersion]*Policy{}}
}

// Publish 发布一个新版本：校验规则合法性、做防御性深拷贝，
// 返回分配的版本号（从 1 起单调递增）。
func (b *PolicyBook) Publish(rules []Rule) (PolicyVersion, error) {
	for i, r := range rules {
		if r.ID == "" {
			return 0, newError(CodeInternal, fmt.Sprintf("rules[%d].id", i),
				"rule id is required", nil)
		}
		switch r.Action {
		case ActionAllow, ActionDeny, ActionFlag:
		default:
			return 0, newError(CodeInternal, fmt.Sprintf("rules[%d].action", i),
				"rule action must be allow/deny/flag", nil)
		}
	}
	v := b.latest + 1
	cp := make([]Rule, len(rules))
	for i, r := range rules {
		cp[i] = Rule{
			ID:      r.ID,
			Sources: append([]Source(nil), r.Sources...),
			Types:   append([]string(nil), r.Types...),
			Actions: append([]string(nil), r.Actions...),
			Action:  r.Action,
			Reason:  r.Reason,
		}
	}
	b.versions[v] = &Policy{Version: v, CreatedAt: time.Now().UTC(), Rules: cp}
	b.latest = v
	return v, nil
}

func (b *PolicyBook) Latest() PolicyVersion { return b.latest }

// Snapshot 返回指定版本的不可变策略。
func (b *PolicyBook) Snapshot(v PolicyVersion) (*Policy, bool) {
	p, ok := b.versions[v]
	return p, ok
}

// Router 基于 PolicyBook 对事件做顺序匹配。
type Router struct{ book *PolicyBook }

func NewRouter(book *PolicyBook) *Router { return &Router{book: book} }

// Evaluate 按策略版本取不可变快照并顺序匹配；无论命中与否，
// 都显式记录依据（命中规则 / 每条规则未命中的维度）。
func (r *Router) Evaluate(e *Event, version PolicyVersion) Evaluation {
	p, ok := r.book.Snapshot(version)
	if !ok {
		return Evaluation{
			Version: version,
			Verdict: VerdictNoMatch,
			Basis:   fmt.Sprintf("policy version %d not found; no rule evaluated", version),
		}
	}
	var skipReasons []string
	for _, rule := range p.Rules {
		ok, why := rule.matches(e)
		if ok {
			verdict := actionToVerdict(rule.Action)
			basis := fmt.Sprintf(
				"policy v%d rule %q matched first: sources=%v types=%v actions=%v; action=%s",
				version, rule.ID, dimOrWild(rule.Sources), dimOrWild(rule.Types),
				dimOrWild(rule.Actions), rule.Action)
			if rule.Reason != "" {
				basis += "; reason=" + rule.Reason
			}
			return Evaluation{
				Matched: true,
				RuleID:  rule.ID,
				Version: version,
				Verdict: verdict,
				Basis:   basis,
			}
		}
		skipReasons = append(skipReasons,
			fmt.Sprintf("rule %q skipped (%s)", rule.ID, why))
	}
	return Evaluation{
		Matched: false,
		Version: version,
		Verdict: VerdictNoMatch,
		Basis: fmt.Sprintf("policy v%d no match among %d rules: %s",
			version, len(p.Rules), strings.Join(skipReasons, " | ")),
	}
}

func actionToVerdict(a DecisionAction) Verdict {
	switch a {
	case ActionAllow:
		return VerdictAllow
	case ActionDeny:
		return VerdictDeny
	case ActionFlag:
		return VerdictFlag
	default:
		return VerdictNoMatch
	}
}

func sourceIn(v Source, list []Source) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func stringIn(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// dimOrWild 仅用于生成可读依据，空维度显示为 *。
func dimOrWild[T ~string](in []T) []string {
	if len(in) == 0 {
		return []string{"*"}
	}
	out := make([]string, len(in))
	for i, x := range in {
		out[i] = string(x)
	}
	return out
}
