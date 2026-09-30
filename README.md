# 审计事件收集、留存与受控查询流水线（本地可运行）

一个零外部依赖（仅 Go 标准库）的本地审计流水线，覆盖：

- 多来源事件接入与**版本化规则顺序路由**，每条结论都带策略版本、命中规则（或逐条未命中维度）等可追溯依据；
- 接入侧对**格式错误 / 字段缺失 / 超限 / 未知来源 / 重复事件 / 内部失败**给出互相可区分的错误码，不静默丢弃；
- 预写日志（WAL）+ 单消费者 + 批次存储：**fsync 持久化、原子轮转、留存清理、重启续跑不丢不重**；
- 轮转 / 清理期间并发查询只能看到完整批次；
- 查询侧**最小权限 + 敏感字段脱敏**，无权限访问被拒绝，且无法通过错误、计数或响应结构探测隐藏字段；
- 完整单元测试（并发写入/查询、轮转/清理、异常输入、权限不足、重启恢复、策略复现），日志打印输入、批次标识与判定依据。

## 1. 事件模型

接入原始字节为单个 JSON 对象，解析为 `audit.Event`：

| 字段 | 说明 | 是否敏感 |
| --- | --- | --- |
| `id` | 事件全局唯一 ID（≤256 字节），重复 ID 显式拒绝 | 否 |
| `source` | 来源标识，必须在启动时登记（如 `web`/`cli`/`cron`） | 否 |
| `type` | 事件类型（如 `login`/`exec`/`job`） | 否 |
| `occurred_at` | RFC3339 事件发生时间（必填） | 否 |
| `actor` / `action` / `resource` | 主体、动作、资源 | `actor` 敏感 |
| `source_ip` | 来源 IP | 敏感 |
| `email` | 邮箱 | 敏感 |
| `attributes` | 字符串属性表（≤100 项，键≤256B、值≤4KB） | 按键级授权（见第 4 节） |

整体载荷受 `MaxEventBytes` 限制。拒绝原因码（`audit.Code`，互不混用）：

| 错误码 | 触发条件 |
| --- | --- |
| `malformed_format` | 空载荷、非法 JSON、单条载荷含多个 JSON 值 |
| `missing_field` | `id`/`source`/`type`/`occurred_at` 缺失或为空 |
| `oversized` | 整体超长、ID 过长、属性项/键/值超限 |
| `unknown_source` | 来源未登记 |
| `duplicate_event` | 事件 ID 已在 WAL 中（含重启后的历史 ID） |
| `internal_error` | 落盘 / 恢复 / 序列化等内部失败（显式暴露，不吞掉） |
| `pipeline_closed` | 关闭后提交 |

### 规则路由与可追溯依据

- 策略通过 `PublishPolicy` 发布，得到单调递增、**发布后不可变**的版本号；`PolicyBook` 保留全部历史快照。
- 规则按顺序匹配，**首个命中生效**；空维度切片表示该维度通配。动作：`allow` / `deny` / `flag`；无任何规则命中时结论为 `no_match`。
- 每条 `Decision` 持久化：`seq`、`event_id`、`source/type`、`occurred_at/evaluated_at`、`policy_version`、`matched`、`rule_id`、`verdict`、人类可读的 `basis`。
  - 命中：`policy v1 rule "web-login" matched first: sources=[web] types=[login] actions=[*]; action=flag; reason=...`
  - 未命中：逐条列出被跳过规则及未命中的维度，如 `rule "x" skipped (source="a" not in [...])`。
- **策略更新后历史可复现**：历史决策记录的是判定时的版本与依据；可用 `Router.Evaluate(&event, oldVersion)` 对同一旧版本快照重新评估，得到相同结论。新版本只影响发布后到达的新事件。

## 2. 持久化、轮转与留存规则

数据目录（`PipelineConfig.Dir`）布局：

```
<dir>/
├── wal.log                 # 仅追加预写日志：每行一条 {seq,event}，Append 内 fsync
├── consumer.state          # 消费进度 {"committed_seq":N}，临时文件+原子改名
└── batches/
    ├── B-000001.active.jsonl   # 活动批次（临时名，查询不读取）
    └── B-000001.jsonl          # 已封存批次（原子改名后才出现）
```

### 处理流水线

1. `SubmitBytes`：校验 → 查重 → 追加 WAL（写入+fsync 后才返回序号）；校验失败不产生任何状态变化。
2. 唯一的后台消费 goroutine 从 `committed_seq+1` 跟随 WAL：路由判定 → 写入活动批次（每行 fsync）→ `CommitSeq` 原子推进进度。
3. **先批次落盘、后提交进度**：崩溃后至多重放，绝不丢事件；重放到“已在批次但进度未推进”的序号时幂等补齐位点，**不重复计数**。
4. 单消费者 + 存储写锁保证序号严格连续；查询多读靠 `RWMutex` 读已发布快照。

### 轮转（任一阈值满足即封存）

`RetentionConfig`：

- `MaxBatchCount`（默认 1000）：活动批次条数达到阈值；
- `MaxBatchBytes`（默认 4 MiB）：活动批次累计字节达到阈值；
- `MaxBatchAge`（默认 1h）：活动批次存活超过时长；
- 优雅关闭时也会封存活动批次。

封存流程：向 `B-xxxxxx.active.jsonl` 追加“清单尾”（计数、序号区间、字节数、覆盖的策略版本）→ fsync → 关闭 → **原子 rename 为 `B-xxxxxx.jsonl`** → 目录 fsync → 同一临界区内发布内存只读视图。

因此查询在任何时刻只可能看到：**该批次不存在**，或**完整批次**，不会看到半截批次。

### 留存清理

`EnforceRetention` 在写锁内执行：

- 删除 `SealedAt` 早于 `now - RetainAge` 的已封存批次；
- 但始终保留最近 `RetainBatches` 个已封存批次（数量保护优先于年龄）；
- 先摘除内存发布项再 unlink + 目录 fsync；删除失败显式报错并恢复发布项。

### 重启恢复

- WAL：启动时全量扫描校验序号严格连续、记录无损坏（发现半截/损坏行按 `internal_error` 显式失败，不静默截断），下一条序号取尾部 +1。
- 批次：加载全部已封存批次并校验序号连续；把崩溃遗留的 `*.active.jsonl` 补写清单尾后原子改名封存（空活动文件直接删除）；记录的批次归属以所在文件为准回填。
- 进度：读取 `consumer.state`，消费者从其后继续；历史事件 ID 全部建立索引，重启后重发同一 ID 仍返回 `duplicate_event`。

## 3. 并发一致性小结

| 场景 | 保证 |
| --- | --- |
| 多 goroutine 并发写入 | WAL 内锁串行化，序号全局单调；重复 ID 拒绝 |
| 写入期间并发查询 | 读快照（活动批次为内存镜像 + 已封存批次只读切片），全程不与写者共享底层切片 |
| 轮转 / 清理期间查询 | 发布与摘除都在锁内整体完成，配合原子改名，无半截 / 空窗批次可见 |
| 崩溃 / kill -9 | WAL + 进度位点恢复；不丢、不重计数；新事件序号续接 |

## 4. 权限边界与脱敏

查询由 `QueryService.Query(principal, filter)` 执行，权限模型为**能力范围（scope）集合**：

| Scope | 可见能力 |
| --- | --- |
| `audit.query` | 基础查询资格；**缺失即整体拒绝** |
| `event.actor` | 可见 `actor` 字段 |
| `event.source_ip` | 可见来源 IP |
| `event.email` | 可见邮箱 |
| `event.attributes.all` | 可见普通属性键 |
| `event.attributes.department` | 可见受保护属性键 `department`（其他受保护键可同模式扩展） |

边界规则：

1. `Principal.Name` 为空 → `unauthenticated`；缺 `audit.query` → `permission_denied`。拒绝错误不带任何字段名 / 事件信息。
2. 结论中的 `verdict`、`rule_id`、`policy_version`、`basis` 对任何持 `audit.query` 者可见（这是审计可解释性本身的一部分）。
3. 未授权字段在投影中保持零值，配合 `omitempty` 序列化后**与“该字段本来就不存在/为空”的字节完全一致**；响应结构固定，不因权限不同而多/少键位。
4. `Total` 只统计当前权限下可见的命中数；无权字段不会通过计数差异暴露存在性。
5. 不允许按无权字段过滤：对隐藏属性键的过滤与对“根本不存在的字段”的过滤返回**相同的 `invalid_filter` 与相同文案，且不回显字段名**，杜绝侧信道探测。

## 5. 兼容范围

- 语言：Go 1.25+（`go.mod` 声明 `go 1.25.0`；使用 `context.AfterFunc` 等标准库能力）。
- 依赖：仅 Go 标准库，无外部服务、无网络、无 cgo。
- 平台：本地文件系统（依赖 `fsync`、目录 fsync 与原子 `rename`；POSIX / Linux、macOS 行为符合预期；Windows 上目录 fsync 语义未做专门适配）。
- 存储格式：WAL 与批次均为 JSONL（每行一个 JSON 对象），批次末行为 `_manifest` 清单标记；版本字段内置于记录中，便于离线检查。
- 适用边界：单进程本地流水线；未实现多进程对同一目录的共享写入（多写者需外加锁/网络协调，不在当前范围）。

## 6. 本地验证

```bash
# 构建与静态检查
go build ./...
go vet ./...

# 全部单元测试（含 -race；反复运行可验证稳定性）
go test ./... -race -count=1
go test ./... -race -count=5

# 查看带输入 / 批次标识 / 判定依据的单测日志
go test ./audit/ -run TestRestartRecovery -v
go test ./audit/ -run TestRejectionCodes -v

# 端到端演示（接入正常/异常/重复事件、不同权限查询、留存清理）
go run ./cmd/auditdemo -dir ./.auditdata -clean
# 再次运行（不加 -clean）：相同事件被判重，序号续接，验证重启恢复
go run ./cmd/auditdemo -dir ./.auditdata
```

测试覆盖一览（`audit/*_test.go`）：

| 测试 | 覆盖点 |
| --- | --- |
| `TestConcurrentWritersAndQueries` | 8×40 并发写入 + 持续并发查询，结论完整、计数一致 |
| `TestDuplicateRejected` | 重复 ID 显式拒绝且只计数一次 |
| `TestRejectionCodes` | 11 类坏输入各自返回可区分错误码 |
| `TestAuthAndMasking` | 未认证、无查询权、字段脱敏、JSON 字节级无隐藏键、隐藏字段过滤与不存在字段同码 |
| `TestRotationByCount` | 计数轮转、多批次总量一致、封存文件可完整读取 |
| `TestConcurrentQueriesDuringRotation` | 快速轮转期间查询不报错、`total==len` 无半截 |
| `TestRetentionCleanup` | 年龄 + 最近 N 批保护；文件系统与查询结果一致 |
| `TestNoActiveFileBeforeSeal` | 封存前正式文件名不存在（原子改名发布） |
| `TestWALAppendReplayAndFollow` / `TestWALCorruptionRejected` | 序号单调、回放/跟随、损坏显式失败 |
| `TestRestartRecovery` | 干净重启：判重、序号续接、批次归属完整 |
| `TestCrashBeforeCommit` | 位点回退模拟崩溃窗口：不丢、不重计数、位点补齐 |
| `TestPolicyVersionReproducibility` | 升级策略不改历史；旧版本快照可复现原结论 |

## 7. 主要 API

```go
p, _ := audit.New(audit.PipelineConfig{
    Dir: dir, MaxEventBytes: 4096, Sources: []audit.Source{"web", "cli"},
    Retention: audit.RetentionConfig{MaxBatchCount: 1000, /* ... */},
})
v, _ := p.PublishPolicy([]audit.Rule{ /* 顺序规则 */ })
_ = p.Start()
seq, err := p.SubmitBytes(rawJSON)   // 校验+WAL 持久化；err 携带 *audit.Error 错误码
_ = p.WaitDrained()
res, err := audit.NewQueryService(p.Store(), p.Book()).
    Query(principal, audit.QueryFilter{Sources: ..., Verdicts: ..., Limit: 50})
removed, _ := p.Store().EnforceRetention()
_ = p.Close()
```
