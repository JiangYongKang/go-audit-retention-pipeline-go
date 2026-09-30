# 审计事件收集、留存与受控查询（Go）

一个可在本地直接运行的审计事件管道：多来源事件接入 → 校验与版本化规则路由 →
仅追加持久化 → 按策略轮转/清理 → 最小权限脱敏查询，并支持进程重启后的
**去重续跑**与**历史判定复现**。

- 仅依赖 Go 标准库，无外部服务；
- 所有并发路径在 `-race` 下测试；
- 拒绝/失败原因使用独立错误码，不静默丢弃、不混成同一种错误；
- 查询永远只能读到“已密封的完整批次”，轮转/清理期间不出现半截数据。

## 1. 目录结构

| 包 | 职责 |
|---|---|
| `internal/model` | 事件、规则、策略、批次、游标等领域类型 |
| `internal/apperr` | 可区分的错误码与包装 |
| `internal/router` | 版本化规则路由，产出可解释的命中/未命中依据 |
| `internal/store` | JSONL 追加存储、原子密封/删除、重启索引重建、游标与策略持久化 |
| `internal/retention` | 按条数/时长轮转、按留存期清理 |
| `internal/pipeline` | 校验、路由、落盘、轮转回调、消费游标、重启重放、JSON 入口 |
| `internal/security` | 角色授权、来源级拒绝、字段级投影与脱敏 |
| `internal/query` | 授权查询与一致性快照 |
| `cmd/demo` | 端到端本地演示（并发写、轮转、脱敏、异常输入、重启恢复、清理） |

## 2. 事件模型

输入事件 `model.RawEvent`：

```json
{
  "source": "payments",
  "type": "transfer",
  "timestamp": "2026-09-30T08:00:00Z",
  "payload": { "risk": "high", "amount": "100", "ssn": "..." }
}
```

- `source` / `type` / `timestamp` / `payload` 均必填，`timestamp` 不允许超出
  容忍窗口的未来时间；payload 的 key/value 必须是合法 UTF-8。
- 校验通过后分配**全局单调递增 seq**，随后进入规则路由。
- 每条处理结果（`model.Record`）记录：`seq`、所属 `batch_id`、来源/类型/时间、
  原始 payload、`matched`、`hit_rule_id`、`policy_ver` 与人类可读的 `reason`。
  因此“顺序、来源、命中与否、依据”都可逐条追溯。

### 2.1 可区分的拒绝 / 失败原因

| 错误码 | 触发条件 |
|---|---|
| `MALFORMED_JSON` | 输入不是合法 JSON，或 payload 非 UTF-8 |
| `MISSING_FIELD` | 缺少 source/type/timestamp/payload、空 key、未来时间等 |
| `VALUE_TOO_LARGE` | 单值长度或 payload 总字节超限 |
| `UNKNOWN_SOURCE` | 来源不在已知来源集合 |
| `POLICY_FAILURE` | 策略版本问题 / 路由内部失败（与生产者输入错误区分） |
| `INTERNAL_ERROR` | 存储、轮转等内部故障 |
| `NOT_FOUND` | 查询的批次不存在或尚未密封 |
| `ACCESS_DENIED` | 无权访问该来源 |

被拒绝的事件**不落盘、不占 seq**；内部路由失败会回滚已预留的 seq，保证
持久化流无空洞，且失败可与非法输入区分。

### 2.2 规则与判定依据

- 规则按来源、事件类型筛选，再比较指定 payload 字段与期望值。
- 判定结果区分四种情况：**命中**、**值不符**（记录 expect/got）、
  **字段缺失**（got=`<missing>`）、**无适用规则**（got=`<no applicable rule>`）。
- `reason` 形如：
  - `rule pay-fraud matched: risk==high`
  - `rule pay-fraud not matched: risk expected=high got=low`
  - `rule auth-admin not matched: field target missing`
  - `no applicable rule under policy v1`

## 3. 留存、轮转与清理

数据目录（默认由调用方指定，例如临时目录）：

```
<dir>/
├── batches/<batchID>.jsonl   # 一个批次的追加记录
├── batches/<batchID>.meta    # 仅密封后出现（密封标记，原子 rename）
├── cursor.json               # 消费进度
└── policies/v<N>.json         # 不可变策略版本
```

### 3.1 轮转

`retention.Policy`：

- `MaxBatchRecords`：当前打开批次达到条数即密封并打开新批次；
- `MaxBatchAge`：打开时长达到阈值即密封（可由定时器调用 `MaybeRotateByAge`）；
- 轮转决策由管理器互斥串行，多个并发写入者只会触发一次密封。

**密封的原子性**：在 store 的同一把写锁内完成“写 meta 标记 + 切换当前批次”，
且记录的批次归属在追加锁内确定，因此记录不可能落入一个已被并发密封的批次。

### 3.2 半截批次隔离

- 查询（`Query` / `Snapshot`）**只读已密封批次**，正在写入的打开批次对读者不可见。
- 删除批次与追加/查询共用串行化锁；读者要么看到整批，要么完全看不到。
- `Snapshot` 在**同一次读锁**内返回批次清单与记录，保证“清单计数 == 行数”，
  适用于清理与读取并发时的 count-then-read 一致性校验。

### 3.3 清理

- `Manager.Cleanup(now)` 删除 `SealedAt < now - Retention` 的已密封批次
  （打开批次永不删除）。数据文件与 meta 一并移除，内存索引同步删除。

## 4. 重启恢复与不重复计数

- 启动时 `store.New` 扫描磁盘重建批次索引、已用 seq 集合和 `maxSeq`；
  崩溃在轮转中途（多个无 meta 的 jsonl）时，按修改时间把最新者视为打开批次，
  其余补写 meta 视为已密封。
- seq 计数器由持久化的 `maxSeq+1` 续号；存储层用已用 seq 集合拒绝真正的重复。
- 消费进度持久化在 `cursor.json`：`{last_consumed_seq, accepted_count}`。
  `Pipeline.Recover` 只重放 `seq > last_consumed_seq` 的记录，更新游标后落盘；
  再次重启/再次恢复结果为空——**未消费事件继续处理且不重复计数**。
- 策略随 `policies/v<N>.json` 持久化，重启后 `LoadPoliciesFromStore` 逐个装载。

### 4.1 策略更新后历史可复现

- 策略版本**只增不改**：同版本不同内容被拒绝（`POLICY_FAILURE`），相同内容重复安装幂等。
- 每条记录保存 `policy_ver`；`Router.RouteWith(event, version)` 可对任意已安装
  版本重新评估，同一 (事件, 版本) 的结论确定不变。因此更新到 v2 后，仍可用 v1
  复现历史判定。

## 5. 权限边界与脱敏

角色 `security.Role`：

- `AllowedSources`：允许的来源（`*` 为全部）；
- `AllowedFields`：可见 payload 字段（`*` 为全部）；
- `RedactedFields`：可见 key 但值替换为稳定的 `sha256:<12 位前缀>`，
  可用于跨事件判断“是否相等”而不泄露原值。

规则：

1. 无来源授权（含未知身份）一律返回同一个 `ACCESS_DENIED: access denied`，
   错误文案不因“身份不存在 / 来源未授权 / 批次是否存在”而变化。
2. **授权检查先于任何存储访问**：无权来源时，即使批次 ID 不存在也只得到拒绝，
   无法借 `NOT_FOUND`、行数或响应结构探测隐藏数据。
3. 未授权字段从 payload 中**整体省略**（不是置 null、不是空串），响应里不留
   任何“该字段存在”的痕迹；隐藏字段也不影响行数与批次计数。
4. 若投影阶段出现授权问题，整请求拒绝而非静默丢行，避免通过行数差异推断部分可见性。

## 6. 兼容范围

- Go 版本：`go 1.25`（在 Go 1.26 工具链下验证）。
- 仅使用标准库；存储格式为 JSONL + JSON，人工可读、可离线检查。
- 面向**单进程本地运行**：通过进程内互斥与文件 fsync 保证一致性；
  不是多节点共享存储方案，多进程并发写同一目录不在兼容范围内。
- 时间以 RFC3339 / Go `time.Time` 序列化；批次 ID 使用 UTC 纳秒时间戳。

## 7. 本地验证

```bash
# 端到端演示（打印输入、seq、批次标识、命中依据、脱敏视图、拒绝码、恢复与清理）
go run ./cmd/demo

# 全量单元测试（建议带竞态检测）
go test ./... -race -count=1

# 反复执行以验证并发稳定性
go test ./... -race -count=3

go vet ./...
```

### 7.1 测试覆盖与日志

- 并发写入与查询：`TestConcurrentWritesUniqueAndComplete`、
  `TestConcurrentAppendsAndQueryDuringSeal`、`TestConcurrentQueryWhileRotating`；
- 轮转与清理：`TestRotationByCount`、`TestRotationByAge`、
  `TestCleanupCutoff`、`TestDeleteBatchAtomic`、`TestConcurrentQueryWhileCleaning`；
- 异常输入：`TestRejectionCodesDistinguishable`（四类错误码）、
  `TestInternalRoutingFailure`（内部失败）；
- 权限不足/脱敏：`TestDenyUnknownPrincipalAndSource`、
  `TestMaskingHidesFieldsCompletely`、`TestRedactionIsStable`、
  `TestQueryDeniedAndHidden`；
- 重启恢复：`TestRestartRecoveryNoDoubleCount`、`TestAppendSealAndRecover`、
  `TestCursorRoundTrip`；
- 判定可复现：`TestPolicyImmutabilityAndReproducibility`。

测试日志按要求打印**输入、批次标识、判定依据**，例如：

```
input risk=high -> seq=1 batch=20260930T...Z matched=true reason="rule pay-fraud matched: risk==high"
input count=5 -> sealed batch=20260930T...Z new open=20260930T...Z
input payload={risk,amount,ssn} -> auditor view=map[risk:high]
restart #1: input unconsumed seq 5,6 -> replayed=2 accepted=1
input cleanup -> deleted batch=20260930T...Z
```
