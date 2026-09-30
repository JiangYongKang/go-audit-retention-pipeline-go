// Command auditdemo 在本地数据目录上端到端演示审计事件的
// 接入、规则路由、批次轮转、留存清理与最小权限受控查询。
//
// 用法：
//
//	go run ./cmd/auditdemo -dir ./.auditdata -clean
//
// 程序会：发布两版策略 -> 接入正常/异常/重复事件 -> 等待处理完成
// -> 用两个权限不同的身份查询 -> 执行留存清理 -> 打印结论。
// 数据目录可重复运行：WAL 与消费进度保证重启后续跑不重复。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/audit"
)

func main() {
	dir := flag.String("dir", "./.auditdata", "data directory for WAL/batches/state")
	clean := flag.Bool("clean", false, "remove data directory before running")
	flag.Parse()

	if *clean {
		if err := os.RemoveAll(*dir); err != nil {
			fail("clean: %v", err)
		}
	}

	p, err := audit.New(audit.PipelineConfig{
		Dir:           *dir,
		MaxEventBytes: 4096,
		Sources:       []audit.Source{"web", "cli", "cron"},
		Retention: audit.RetentionConfig{
			MaxBatchCount: 3,
			MaxBatchBytes: 64 * 1024,
			MaxBatchAge:   500 * time.Millisecond,
			RetainAge:     0, // 演示中不按时间删除，只演示手动删除
			RetainBatches: 1,
		},
	})
	if err != nil {
		fail("new pipeline: %v", err)
	}

	// 策略 v1：先具体后兜底，顺序匹配。
	v1, err := p.PublishPolicy([]audit.Rule{
		{ID: "web-login-flag", Sources: []audit.Source{"web"}, Types: []string{"login"},
			Action: audit.ActionFlag, Reason: "web logins are reviewed"},
		{ID: "cli-allow", Sources: []audit.Source{"cli"}, Action: audit.ActionAllow},
		{ID: "cron-deny", Sources: []audit.Source{"cron"}, Types: []string{"job"},
			Action: audit.ActionDeny, Reason: "cron jobs denied by policy"},
	})
	if err != nil {
		fail("publish v1: %v", err)
	}
	fmt.Printf("[policy] published version v%d\n", v1)

	if err := p.Start(); err != nil {
		fail("start: %v", err)
	}
	defer p.Close()

	now := time.Now().UTC()
	events := []map[string]any{
		{"id": "e-1", "source": "web", "type": "login", "occurred_at": now,
			"actor": "alice", "action": "sign-in", "source_ip": "10.0.0.3",
			"email":      "alice@example.com",
			"attributes": map[string]string{"department": "security"}},
		{"id": "e-2", "source": "cli", "type": "exec", "occurred_at": now.Add(time.Second),
			"actor": "bob", "action": "deploy", "resource": "svc-a"},
		{"id": "e-3", "source": "cron", "type": "job", "occurred_at": now.Add(2 * time.Second),
			"action": "nightly"},
		{"id": "e-1", "source": "web", "type": "login", "occurred_at": now, "actor": "alice"}, // 重复
		{"id": "e-4", "source": "iot", "type": "x", "occurred_at": now},                       // 未知来源
		{"id": "e-5", "source": "web"},                                                        // 缺字段
	}
	for i, ev := range events {
		raw, _ := json.Marshal(ev)
		seq, err := p.SubmitBytes(raw)
		if err != nil {
			code := audit.Code("?")
			if ae, ok := audit.AsError(err); ok {
				code = ae.Code
			}
			fmt.Printf("[ingest] #%d REJECTED code=%s reason=%v\n", i+1, code, err)
			continue
		}
		fmt.Printf("[ingest] #%d ACCEPTED seq=%d id=%v\n", i+1, seq, ev["id"])
	}
	// 畸形 JSON 与超限也显式演示。
	if _, err := p.SubmitBytes([]byte("{not-json")); err != nil {
		fmt.Printf("[ingest] malformed REJECTED code=%s\n", codeOf(err))
	}
	if _, err := p.SubmitBytes(make([]byte, 5000)); err != nil {
		fmt.Printf("[ingest] oversized REJECTED code=%s\n", codeOf(err))
	}

	if err := p.WaitDrained(); err != nil {
		fail("drain: %v", err)
	}
	// 等活动批次越过年龄阈值后触发一次轮转。
	time.Sleep(600 * time.Millisecond)
	if err := p.WaitDrained(); err != nil {
		fail("drain2: %v", err)
	}

	// 发布 v2：仅影响之后的新事件；历史结论仍可按 v1 复现。
	v2, err := p.PublishPolicy([]audit.Rule{
		{ID: "everything-allow", Action: audit.ActionAllow},
	})
	if err != nil {
		fail("publish v2: %v", err)
	}
	fmt.Printf("[policy] published version v%d (history stays on v%d)\n", v2, v1)

	qs := audit.NewQueryService(p.Store(), p.Book())

	admin := audit.Principal{Name: "admin", Scopes: map[audit.Scope]bool{
		audit.ScopeQuery: true, audit.ScopeEventActor: true, audit.ScopeEventIP: true,
		audit.ScopeEventEmail: true, audit.ScopeEventAttrAll: true,
		audit.Scope("event.attributes.department"): true,
	}}
	viewer := audit.Principal{Name: "viewer", Scopes: map[audit.Scope]bool{
		audit.ScopeQuery: true, audit.ScopeEventActor: true,
	}}
	anon := audit.Principal{Name: "anon", Scopes: map[audit.Scope]bool{}}

	printQuery := func(tag string, who audit.Principal, f audit.QueryFilter) {
		res, err := qs.Query(who, f)
		if err != nil {
			fmt.Printf("[query:%s] DENIED code=%s reason=%v\n", tag, codeOf(err), err)
			return
		}
		fmt.Printf("[query:%s] visible=%d total=%d\n", tag, len(res.Events), res.Total)
		for _, ev := range res.Events {
			b, _ := json.Marshal(ev)
			fmt.Printf("    %s\n", b)
		}
	}
	printQuery("admin", admin, audit.QueryFilter{Limit: 10})
	printQuery("viewer", viewer, audit.QueryFilter{Limit: 10})
	printQuery("anon", anon, audit.QueryFilter{})
	// viewer 按无权字段过滤：错误不回显字段名，与不存在字段同码。
	_, err = qs.Query(viewer, audit.QueryFilter{Attrs: map[string]string{"department": "security"}})
	fmt.Printf("[query:viewer-hidden-filter] code=%s reason=%v\n", codeOf(err), err)

	removed, err := p.Store().EnforceRetention()
	if err != nil {
		fail("retention: %v", err)
	}
	fmt.Printf("[retention] removed %d old batch(es): %v\n", len(removed), removed)

	st := p.Stats()
	fmt.Printf("[stats] accepted=%d rejected=%d processed=%d committed=%d\n",
		st.Accepted, st.Rejected, st.Processed, st.CommittedSeq)
	fmt.Println("[done] rerun without -clean to observe restart recovery")
}

func codeOf(err error) audit.Code {
	if ae, ok := audit.AsError(err); ok {
		return ae.Code
	}
	return audit.Code("?")
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
