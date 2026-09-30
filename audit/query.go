package audit

import (
	"sort"
	"time"
)

// Scope 是查询侧的最小权限粒度。
type Scope string

const (
	ScopeQuery        Scope = "audit.query"
	ScopeEventActor   Scope = "event.actor"
	ScopeEventIP      Scope = "event.source_ip"
	ScopeEventEmail   Scope = "event.email"
	ScopeEventAttrAll Scope = "event.attributes.all"
)

// 受保护属性键的专用范围；未列出的属性键随 ScopeEventAttrAll 开放。
// 键集合本身也是敏感信息：调用方只能看到被授权范围内的属性键。
const (
	AttrKeyDepartment = "department"
)

// Principal 是查询调用方及其持有的权限范围。
type Principal struct {
	Name   string
	Scopes map[Scope]bool
}

func (p Principal) Has(s Scope) bool { return p.Scopes != nil && p.Scopes[s] }

// QueryFilter 描述查询条件。不允许按无权查看的字段过滤：
// 对无权字段的过滤与“未知字段过滤”返回完全相同的 CodeInvalidFilter，
// 错误文案也不回显字段名，从而无法借此探测被隐藏字段是否存在。
type QueryFilter struct {
	Sources  []Source          // 可选：来源白名单
	Types    []string          // 可选：类型白名单
	Verdicts []Verdict         // 可选：结论白名单
	Since    *time.Time        // 可选：发生时间下界（含）
	Until    *time.Time        // 可选：发生时间上界（不含）
	Attrs    map[string]string // 可选：属性等值条件（仅可见属性键）
	Limit    int               // <=0 表示使用默认上限
}

const defaultQueryLimit = 1000
const maxQueryLimit = 10000

// DecisionView 是结论的对外投影。
type DecisionView struct {
	Verdict       Verdict       `json:"verdict"`
	RuleID        RuleID        `json:"rule_id,omitempty"`
	PolicyVersion PolicyVersion `json:"policy_version"`
	Basis         string        `json:"basis"`
}

// EventView 是事件的对外投影。无权字段直接缺省：
//
//	空值省略与“无权访问”在序列化字节上不可区分，
//	因此无法通过响应结构判断被隐藏字段是否存在或是否有值。
type EventView struct {
	ID         string            `json:"id"`
	Source     Source            `json:"source"`
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	Action     string            `json:"action,omitempty"`
	Resource   string            `json:"resource,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	SourceIP   string            `json:"source_ip,omitempty"`
	Email      string            `json:"email,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Batch      BatchID           `json:"batch"`
	Decision   DecisionView      `json:"decision"`
}

// QueryResult 只包含调用方有权看到的字段。
type QueryResult struct {
	Events []EventView `json:"events"`
	Total  int         `json:"total"`
}

// QueryService 做鉴权、字段脱敏与批次只读快照查询。
type QueryService struct {
	store *Store
	book  *PolicyBook
}

func NewQueryService(store *Store, book *PolicyBook) *QueryService {
	return &QueryService{store: store, book: book}
}

// attrScope 把受保护属性键映射到专用范围；
// 其它键统一归到 ScopeEventAttrAll。
func attrScope(key string) Scope {
	switch key {
	case AttrKeyDepartment:
		return Scope("event.attributes.department")
	default:
		return ScopeEventAttrAll
	}
}

// Query 执行受控查询：
//  1. 未认证 → CodeUnauthenticated；
//  2. 缺少 audit.query → CodePermissionDenied（不透露任何数据细节）；
//  3. 按无权字段过滤与按不存在字段过滤同样报 CodeInvalidFilter，
//     且不回显字段名；
//  4. 结果逐条按字段授权投影，隐藏字段直接缺省，总数仅统计可见命中。
func (s *QueryService) Query(pr Principal, f QueryFilter) (*QueryResult, error) {
	if pr.Name == "" {
		return nil, newError(CodeUnauthenticated, "", "authentication required", nil)
	}
	if !pr.Has(ScopeQuery) {
		return nil, newError(CodePermissionDenied, "", "not permitted to query audit events", nil)
	}
	// 过滤条件中不得引用无权可见的字段。
	for key := range f.Attrs {
		if !pr.Has(attrScope(key)) {
			// 与“过滤器字段不存在”同一错误，且不回显 key。
			return nil, newError(CodeInvalidFilter, "", "filter references a field that is not available", nil)
		}
	}
	for _, v := range f.Verdicts {
		switch v {
		case VerdictAllow, VerdictDeny, VerdictFlag, VerdictNoMatch:
		default:
			return nil, newError(CodeInvalidFilter, "", "unsupported verdict in filter", nil)
		}
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	if limit > maxQueryLimit {
		return nil, newError(CodeInvalidFilter, "", "limit exceeds maximum", nil)
	}

	batches, err := s.store.Snapshot()
	if err != nil {
		return nil, err
	}
	var views []EventView
	for _, b := range batches {
		// 每个批次快照在其生成时即完整，遍历时不与写者共享切片。
		for _, d := range b.Decisions {
			if !matchFilter(d, f) {
				continue
			}
			views = append(views, project(pr, d))
		}
	}
	sort.SliceStable(views, func(i, j int) bool { return views[i].OccurredAt.Before(views[j].OccurredAt) })
	total := len(views)
	if len(views) > limit {
		views = views[:limit]
	}
	return &QueryResult{Events: views, Total: total}, nil
}

func matchFilter(d Decision, f QueryFilter) bool {
	if len(f.Sources) > 0 && !sourceIn(d.Source, f.Sources) {
		return false
	}
	if len(f.Types) > 0 && !stringIn(d.Type, f.Types) {
		return false
	}
	if len(f.Verdicts) > 0 {
		ok := false
		for _, v := range f.Verdicts {
			if v == d.Verdict {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.Since != nil && d.OccurredAt.Before(*f.Since) {
		return false
	}
	if f.Until != nil && !d.OccurredAt.Before(*f.Until) {
		return false
	}
	if len(f.Attrs) > 0 {
		if d.Event.Attributes == nil {
			return false
		}
		for k, v := range f.Attrs {
			if got, ok := d.Event.Attributes[k]; !ok || got != v {
				return false
			}
		}
	}
	return true
}

// project 按调用方范围逐条投影。未授权字段保持零值，
// 配合 omitempty 与“本就为空”的输出完全一致。
func project(pr Principal, d Decision) EventView {
	v := EventView{
		ID:         d.Event.ID,
		Source:     d.Source,
		Type:       d.Type,
		OccurredAt: d.OccurredAt,
		Action:     d.Event.Action,
		Resource:   d.Event.Resource,
		Batch:      d.Batch,
		Decision: DecisionView{
			Verdict:       d.Verdict,
			RuleID:        d.RuleID,
			PolicyVersion: d.PolicyVersion,
			Basis:         d.Basis,
		},
	}
	if pr.Has(ScopeEventActor) {
		v.Actor = d.Event.Actor
	}
	if pr.Has(ScopeEventIP) {
		v.SourceIP = d.Event.SourceIP
	}
	if pr.Has(ScopeEventEmail) {
		v.Email = d.Event.Email
	}
	if len(d.Event.Attributes) > 0 {
		attrs := make(map[string]string)
		for k, val := range d.Event.Attributes {
			if pr.Has(attrScope(k)) {
				attrs[k] = val
			}
		}
		if len(attrs) > 0 {
			v.Attributes = attrs
		}
	}
	return v
}
