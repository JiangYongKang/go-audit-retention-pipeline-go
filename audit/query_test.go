package audit

import (
	"encoding/json"
	"testing"
	"time"
)

func seedOne(t *testing.T, p *Pipeline, src Source, typ string) {
	t.Helper()
	raw := mustJSON(t, makeEvent("secret-1", src, typ))
	if _, err := p.SubmitBytes(raw); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := p.WaitDrained(); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

// TestAuthAndMasking 未认证 / 无查询权 / 字段脱敏 / 隐藏字段侧信道。
func TestAuthAndMasking(t *testing.T) {
	log := newTL(t)
	p := newTestPipeline(t, RetentionConfig{
		MaxBatchCount: 10, MaxBatchBytes: 4096, MaxBatchAge: time.Hour})
	seedOne(t, p, "web", "login")
	qs := NewQueryService(p.Store(), p.Book())
	all := QueryFilter{Limit: 10}

	// 1) 未认证：拒绝且不含任何数据细节。
	if _, err := qs.Query(Principal{}, all); !IsCode(err, CodeUnauthenticated) {
		t.Fatalf("unauthenticated: want %s got %v", CodeUnauthenticated, err)
	}
	// 2) 已认证但无 audit.query：拒绝；错误结构中不包含字段名 / 事件 ID。
	noQuery := Principal{Name: "noq", Scopes: map[Scope]bool{ScopeEventIP: true}}
	if _, err := qs.Query(noQuery, all); !IsCode(err, CodePermissionDenied) {
		t.Fatalf("no-scope: want %s got %v", CodePermissionDenied, err)
	}
	if err, _ := AsError(errOf(qs, noQuery, all)); err != nil && err.Field != "" {
		t.Fatalf("permission error must not name a field, got field=%q", err.Field)
	}

	// 3) 管理员可见全部敏感字段；viewer 不可见 IP / email / 属性。
	adminRes, err := qs.Query(adminPrincipal(), all)
	if err != nil {
		t.Fatalf("admin query: %v", err)
	}
	viewRes, err := qs.Query(viewerPrincipal(), all)
	if err != nil {
		t.Fatalf("viewer query: %v", err)
	}
	if len(adminRes.Events) != 1 || len(viewRes.Events) != 1 {
		t.Fatalf("expected one event each")
	}
	a, v := adminRes.Events[0], viewRes.Events[0]
	if a.SourceIP == "" || a.Email == "" || len(a.Attributes) == 0 || a.Actor == "" {
		t.Fatalf("admin should see sensitive fields: %+v", a)
	}
	if v.SourceIP != "" || v.Email != "" || v.Actor != "" || len(v.Attributes) != 0 {
		t.Fatalf("viewer leaked hidden fields: %+v", v)
	}
	log.decisions("ADMIN-VISIBLE", adminRes.Events)
	log.decisions("VIEWER-VISIBLE", viewRes.Events)

	// 4) 字节级证明：viewer 看到的 JSON 与“该事件本就没有这些字段”
	//    的手工构造结果一致（不出现任何被隐藏字段的键）。
	hiddenKeys := []string{"source_ip", "email", "actor", "attributes"}
	b, _ := json.Marshal(v)
	for _, k := range hiddenKeys {
		if containsJSONKey(b, k) {
			t.Fatalf("hidden key %q present in viewer JSON: %s", k, b)
		}
	}

	// 5) 用无权字段过滤与用“根本不存在的字段”过滤必须同码同文案，
	//    且不回显字段名，避免借此探测隐藏字段是否存在。
	errHidden := qerr(qs, viewerPrincipal(),
		QueryFilter{Attrs: map[string]string{"department": "sec"}})
	errBogus := qerr(qs, viewerPrincipal(),
		QueryFilter{Attrs: map[string]string{"nope-key": "x"}})
	if !IsCode(errHidden, CodeInvalidFilter) || !IsCode(errBogus, CodeInvalidFilter) {
		t.Fatalf("want invalid_filter for both: %v / %v", errHidden, errBogus)
	}
	if errHidden.Error() != errBogus.Error() {
		t.Fatalf("error messages must not differ by field:\n%v\n%v", errHidden, errBogus)
	}
	// 持相关范围的主体则可以按该属性过滤。
	deptViewer := Principal{Name: "dep", Scopes: map[Scope]bool{
		ScopeQuery: true, Scope("event.attributes.department"): true}}
	res, err := qs.Query(deptViewer, QueryFilter{
		Attrs: map[string]string{"department": "sec"}})
	if err != nil || res.Total != 1 {
		t.Fatalf("authorized attr filter: res=%+v err=%v", res, err)
	}
}

func errOf(qs *QueryService, pr Principal, f QueryFilter) error {
	_, err := qs.Query(pr, f)
	return err
}

func qerr(qs *QueryService, pr Principal, f QueryFilter) error {
	_, err := qs.Query(pr, f)
	return err
}

func containsJSONKey(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
