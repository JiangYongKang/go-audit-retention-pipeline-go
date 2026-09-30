package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	batchesDirName = "batches"
	stateFileName  = "consumer.state"
	activeSuffix   = ".active"
)

// RetentionConfig 定义轮转阈值与留存清理规则。
type RetentionConfig struct {
	MaxBatchCount int           // 活动批次达到该条数则轮转
	MaxBatchBytes int64         // 活动批次达到该字节数则轮转
	MaxBatchAge   time.Duration // 活动批次存活超过该时长则轮转
	RetainAge     time.Duration // 清理：SealedAt 早于 now-RetainAge 的批次
	RetainBatches int           // 清理：始终保留最近 N 个已封存批次
}

func (c RetentionConfig) normalized() RetentionConfig {
	if c.MaxBatchCount <= 0 {
		c.MaxBatchCount = 1000
	}
	if c.MaxBatchBytes <= 0 {
		c.MaxBatchBytes = 4 * 1024 * 1024
	}
	if c.MaxBatchAge <= 0 {
		c.MaxBatchAge = time.Hour
	}
	if c.RetainBatches < 0 {
		c.RetainBatches = 0
	}
	return c
}

// StoreConfig 是持久化存储配置。
type StoreConfig struct {
	Dir       string
	Retention RetentionConfig
}

// activeBatch 是当前正在追加的批次；它只通过内存镜像对外可见，
// 文件在封存改名前不会被任何查询读取。
type activeBatch struct {
	id        BatchID
	createdAt time.Time
	path      string
	f         *os.File
	decisions []Decision
	size      int64
	policyVer map[PolicyVersion]struct{}
}

// sealedBatch 是已封存批次的内存只读视图（改名完成后发布）。
type sealedBatch struct {
	manifest  Manifest
	decisions []Decision
}

// Store 管理活动批次、已封存批次、消费进度与留存清理。
// 单一消费 goroutine 负责 Append；查询 goroutine 通过 RLock
// 读取已发布快照，封存 / 清理的发布动作整体持锁，
// 因此并发查询只可能看到完整批次，绝无半截批次。
type Store struct {
	mu      sync.RWMutex
	cfg     StoreConfig
	dir     string
	book    *PolicyBook
	active  *activeBatch
	sealed  map[BatchID]*sealedBatch // 按批次 ID 索引
	order   []BatchID                // 封存顺序（旧→新）
	lastSeq int64                    // 已进入批次的最大 WAL 序号
	nextNum int64                    // 下一个批次序号
	closed  bool
	now     func() time.Time
}

func OpenStore(cfg StoreConfig, book *PolicyBook) (*Store, error) {
	cfg.Retention = cfg.Retention.normalized()
	dir := filepath.Join(cfg.Dir, batchesDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, newError(CodeInternal, "store.dir", "mkdir failed", err)
	}
	s := &Store{
		cfg:    cfg,
		dir:    dir,
		book:   book,
		sealed: map[BatchID]*sealedBatch{},
		now:    func() time.Time { return time.Now().UTC() },
	}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

// recover 启动恢复：
//  1. 加载全部已封存批次并校验序号连续；
//  2. 将上次崩溃遗留的活动批次补写清单并原子改名封存；
//  3. 读取消费进度。
func (s *Store) recover() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return newError(CodeInternal, "store.dir", "read batches dir failed", err)
	}
	var sealedFiles, activeFiles []string
	var maxNum int64
	for _, en := range entries {
		if en.IsDir() {
			continue
		}
		name := en.Name()
		if strings.HasSuffix(name, activeSuffix+".jsonl") {
			activeFiles = append(activeFiles, filepath.Join(s.dir, name))
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") {
			// 非批次文件（未来扩展）显式忽略目录以外的未知项。
			continue
		}
		id := BatchID(strings.TrimSuffix(name, ".jsonl"))
		n, ok := ParseBatchSeq(id)
		if !ok {
			return newError(CodeInternal, "store", "unrecognized batch file: "+name, nil)
		}
		if n > maxNum {
			maxNum = n
		}
		sealedFiles = append(sealedFiles, filepath.Join(s.dir, name))
	}
	sort.Strings(sealedFiles)
	var prevMax int64
	for _, p := range sealedFiles {
		decs, m, err := ReadBatchFile(p)
		if err != nil {
			return newError(CodeInternal, "store", "recover batch failed: "+filepath.Base(p), err)
		}
		if !m.Sealed {
			return newError(CodeInternal, "store", "unsealed manifest in named batch file", nil)
		}
		if len(decs) > 0 && decs[0].Seq != prevMax+1 {
			return newError(CodeInternal, "store", "sequence gap between sealed batches", nil)
		}
		// 批次归属以所在文件为准回填，不依赖记录序列化时是否已赋值。
		for i := range decs {
			decs[i].Batch = m.ID
		}
		prevMax = m.MaxSeq
		s.sealed[m.ID] = &sealedBatch{manifest: m, decisions: decs}
		s.order = append(s.order, m.ID)
	}
	// 崩溃遗留的活动批次：补全清单并改名，视为已完成批次。
	for _, p := range activeFiles {
		sb, err := s.sealLeftoverActive(p)
		if err != nil {
			return err
		}
		if sb != nil {
			if len(sb.decisions) > 0 && sb.decisions[0].Seq != prevMax+1 {
				return newError(CodeInternal, "store", "sequence gap in leftover active batch", nil)
			}
			prevMax = sb.manifest.MaxSeq
			s.sealed[sb.manifest.ID] = sb
			s.order = append(s.order, sb.manifest.ID)
			n, _ := ParseBatchSeq(sb.manifest.ID)
			if n > maxNum {
				maxNum = n
			}
		}
	}
	sort.Slice(s.order, func(i, j int) bool { return s.order[i] < s.order[j] })
	s.lastSeq = prevMax
	s.nextNum = maxNum + 1
	return nil
}

// sealLeftoverActive 把遗留活动文件中的决策读出、补写清单尾并改名。
func (s *Store) sealLeftoverActive(path string) (*sealedBatch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newError(CodeInternal, "store", "read leftover active failed", err)
	}
	id := BatchID(strings.TrimSuffix(filepath.Base(path), activeSuffix+".jsonl"))
	if _, ok := ParseBatchSeq(id); !ok {
		return nil, newError(CodeInternal, "store", "bad leftover active name", nil)
	}
	var decs []Decision
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d Decision
		if err := json.Unmarshal([]byte(line), &d); err != nil {
			return nil, newError(CodeInternal, "store", "corrupt leftover active record", err)
		}
		d.Batch = id
		decs = append(decs, d)
	}
	if len(decs) == 0 {
		// 空活动文件直接删除，不产生空批次。
		if err := os.Remove(path); err != nil {
			return nil, newError(CodeInternal, "store", "remove empty active failed", err)
		}
		_ = syncDir(s.dir)
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, newError(CodeInternal, "store", "reopen leftover active failed", err)
	}
	now := s.now()
	m := buildManifest(id, id.FileName(), decs, decs[0], now)
	if err := WriteManifestFooter(f, m); err != nil {
		_ = f.Close()
		return nil, newError(CodeInternal, "store", "write leftover manifest failed", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, newError(CodeInternal, "store", "fsync leftover failed", err)
	}
	if err := f.Close(); err != nil {
		return nil, newError(CodeInternal, "store", "close leftover failed", err)
	}
	final := filepath.Join(s.dir, id.FileName())
	if err := os.Rename(path, final); err != nil {
		return nil, newError(CodeInternal, "store", "rename leftover failed", err)
	}
	if err := syncDir(s.dir); err != nil {
		return nil, newError(CodeInternal, "store", "fsync dir after leftover rename failed", err)
	}
	// 以所在文件名回填批次归属（崩溃前写入时该字段可能尚未赋值）。
	for i := range decs {
		decs[i].Batch = id
	}
	return &sealedBatch{manifest: m, decisions: decs}, nil
}

// FileName 返回批次的正式文件名。
func (b BatchID) FileName() string { return string(b) + ".jsonl" }

// ActiveFileName 返回活动批次临时文件名。
func (b BatchID) ActiveFileName() string { return string(b) + activeSuffix + ".jsonl" }

func buildManifest(id BatchID, file string, decs []Decision, first Decision, now time.Time) Manifest {
	verSet := map[PolicyVersion]struct{}{}
	var size int64
	var minSeq, maxSeq int64 = first.Seq, first.Seq
	for _, d := range decs {
		verSet[d.PolicyVersion] = struct{}{}
		if d.Seq < minSeq {
			minSeq = d.Seq
		}
		if d.Seq > maxSeq {
			maxSeq = d.Seq
		}
		// 估算字节规模与文件写入规模一致（JSONL 单行 + 换行）。
		b, _ := MarshalDecision(d)
		size += int64(len(b)) + 1
	}
	vers := make([]PolicyVersion, 0, len(verSet))
	for v := range verSet {
		vers = append(vers, v)
	}
	sort.Slice(vers, func(i, j int) bool { return vers[i] < vers[j] })
	return Manifest{
		ID:             id,
		File:           file,
		CreatedAt:      first.EvaluatedAt,
		SealedAt:       now,
		Sealed:         true,
		Count:          len(decs),
		MinSeq:         minSeq,
		MaxSeq:         maxSeq,
		SizeBytes:      size,
		PolicyVersions: vers,
	}
}

// ---- 消费进度：单文件原子替换 ----

type consumerState struct {
	CommittedSeq int64 `json:"committed_seq"`
}

func (s *Store) statePath() string { return filepath.Join(s.cfg.Dir, stateFileName) }

// CommittedSeq 返回已确认处理完成并持久化的 WAL 序号。
func (s *Store) CommittedSeq() (int64, error) {
	b, err := os.ReadFile(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, newError(CodeInternal, "store.state", "read state failed", err)
	}
	var st consumerState
	if err := json.Unmarshal(b, &st); err != nil {
		return 0, newError(CodeInternal, "store.state", "corrupt state file", err)
	}
	return st.CommittedSeq, nil
}

// CommitSeq 原子持久化消费进度（临时文件 + fsync + 改名 + 目录 fsync）。
func (s *Store) CommitSeq(seq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeStateLocked(seq)
}

func (s *Store) writeStateLocked(seq int64) error {
	tmp := s.statePath() + ".tmp"
	st := consumerState{CommittedSeq: seq}
	b, err := json.Marshal(&st)
	if err != nil {
		return newError(CodeInternal, "store.state", "marshal state failed", err)
	}
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return newError(CodeInternal, "store.state", "write temp state failed", err)
	}
	d, err := os.Open(s.cfg.Dir)
	if err != nil {
		return newError(CodeInternal, "store.dir", "open dir for state rename failed", err)
	}
	if err := syncAndClose(tmp, d); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.statePath()); err != nil {
		return newError(CodeInternal, "store.state", "rename state failed", err)
	}
	if err := syncDir(s.cfg.Dir); err != nil {
		return newError(CodeInternal, "store.dir", "fsync dir after state rename failed", err)
	}
	return nil
}

func syncAndClose(tmp string, d *os.File) error {
	f, err := os.Open(tmp)
	if err != nil {
		_ = d.Close()
		return newError(CodeInternal, "store.state", "reopen temp state failed", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = d.Close()
		return newError(CodeInternal, "store.state", "fsync temp state failed", err)
	}
	if err := f.Close(); err != nil {
		_ = d.Close()
		return newError(CodeInternal, "store.state", "close temp state failed", err)
	}
	return d.Close()
}

var _ = fmt.Sprintf

// ---- 写入（单消费 goroutine）、原子轮转、留存清理、只读快照 ----

// Append 把一条判定写入活动批次，必要时先原子封存并开启新批次，
// 返回所在批次。seq 必须严格递增：重复 seq 幂等返回原批次且不重复计数。
func (s *Store) Append(d Decision) (BatchID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", newError(CodeClosed, "store", "store is closed", nil)
	}
	if d.Seq <= s.lastSeq && d.Seq > 0 {
		// 重启恢复后消费者可能对已入批次的序号再次投递：幂等跳过。
		if id, ok := s.batchOfSeqLocked(d.Seq); ok {
			return id, nil
		}
		return "", newError(CodeInternal, "store",
			fmt.Sprintf("seq %d below watermark without owning batch", d.Seq), nil)
	}
	if s.active != nil && d.Seq != s.lastSeq+1 {
		return "", newError(CodeInternal, "store",
			fmt.Sprintf("non-contiguous append: got %d want %d", d.Seq, s.lastSeq+1), nil)
	}
	if s.active == nil {
		if err := s.startActiveLocked(d); err != nil {
			return "", err
		}
	}
	line, err := MarshalDecision(d)
	if err != nil {
		return "", newError(CodeInternal, "store", "marshal decision failed", err)
	}
	if _, err := s.active.f.Write(append(line, '\n')); err != nil {
		return "", newError(CodeInternal, "store", "write active batch failed", err)
	}
	if err := s.active.f.Sync(); err != nil {
		return "", newError(CodeInternal, "store", "fsync active batch failed", err)
	}
	d.Batch = s.active.id
	s.active.decisions = append(s.active.decisions, d)
	s.active.size += int64(len(line)) + 1
	s.active.policyVer[d.PolicyVersion] = struct{}{}
	s.lastSeq = d.Seq
	id := s.active.id
	if s.shouldSealLocked() {
		if err := s.sealActiveLocked(); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (s *Store) startActiveLocked(first Decision) error {
	id := BatchID(fmt.Sprintf("B-%06d", s.nextNum))
	path := filepath.Join(s.dir, id.ActiveFileName())
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return newError(CodeInternal, "store", "create active batch failed", err)
	}
	if err := syncDir(s.dir); err != nil {
		_ = f.Close()
		return newError(CodeInternal, "store", "fsync dir after active create failed", err)
	}
	s.active = &activeBatch{
		id:        id,
		createdAt: first.EvaluatedAt,
		path:      path,
		f:         f,
		policyVer: map[PolicyVersion]struct{}{},
	}
	return nil
}

func (s *Store) shouldSealLocked() bool {
	a := s.active
	r := s.cfg.Retention
	if len(a.decisions) >= r.MaxBatchCount {
		return true
	}
	if a.size >= r.MaxBatchBytes {
		return true
	}
	if s.now().Sub(a.createdAt) >= r.MaxBatchAge {
		return true
	}
	return false
}

// sealActiveLocked 完成封存：补写清单尾、fsync、关闭、原子改名、
// 目录 fsync，然后一次性发布内存只读快照。整个过程持锁，
// 查询只能看到“不存在”或“完整批次”两种状态。
func (s *Store) sealActiveLocked() error {
	a := s.active
	if a == nil || len(a.decisions) == 0 {
		return nil
	}
	now := s.now()
	m := buildManifest(a.id, a.id.FileName(), a.decisions, a.decisions[0], now)
	if err := WriteManifestFooter(a.f, m); err != nil {
		return newError(CodeInternal, "store", "write manifest footer failed", err)
	}
	if err := a.f.Sync(); err != nil {
		return newError(CodeInternal, "store", "fsync before seal failed", err)
	}
	if err := a.f.Close(); err != nil {
		return newError(CodeInternal, "store", "close active before rename failed", err)
	}
	final := filepath.Join(s.dir, a.id.FileName())
	if err := os.Rename(a.path, final); err != nil {
		return newError(CodeInternal, "store", "atomic rename on seal failed", err)
	}
	if err := syncDir(s.dir); err != nil {
		return newError(CodeInternal, "store", "fsync dir after seal failed", err)
	}
	// 发布点：文件已以正式名原子就位，内存视图同临界区内更新。
	decsCopy := make([]Decision, len(a.decisions))
	copy(decsCopy, a.decisions)
	s.sealed[a.id] = &sealedBatch{manifest: m, decisions: decsCopy}
	s.order = append(s.order, a.id)
	s.nextNum++
	s.active = nil
	return nil
}

// EnforceRetention 清理过期且超出最少保留数量的已封存批次，
// 返回被删除的批次标识。删除在写锁内进行；删除本身先移除内存
// 发布项，再 unlink + 目录 fsync，查询不会读到删除中的半截状态。
func (s *Store) EnforceRetention() ([]BatchID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.cfg.Retention
	cutoff := s.now().Add(-r.RetainAge)
	protected := map[BatchID]struct{}{}
	if r.RetainBatches > 0 && r.RetainBatches < len(s.order) {
		for _, id := range s.order[len(s.order)-r.RetainBatches:] {
			protected[id] = struct{}{}
		}
	}
	var removed []BatchID
	var newOrder []BatchID
	for _, id := range s.order {
		sb := s.sealed[id]
		drop := sb.manifest.SealedAt.Before(cutoff)
		if _, keep := protected[id]; keep {
			drop = false
		}
		if !drop {
			newOrder = append(newOrder, id)
			continue
		}
		// 先摘除发布项，后续查询立即看不到该批次。
		delete(s.sealed, id)
		path := filepath.Join(s.dir, sb.manifest.File)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			// 删除失败：把发布项恢复并显式失败，不静默。
			s.sealed[id] = sb
			return removed, newError(CodeInternal, "store", "remove batch file failed", err)
		}
		removed = append(removed, id)
	}
	if err := syncDir(s.dir); err != nil {
		return removed, newError(CodeInternal, "store", "fsync dir after retention failed", err)
	}
	s.order = newOrder
	return removed, nil
}

// AlreadyBatched 判断序号是否已进入某个批次（恢复去重用）。
func (s *Store) alreadyBatched(seq int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.batchOfSeqLocked(seq)
	return ok
}

// batchOfSeqLocked 在已封存批次与活动批次中定位序号所属批次。
func (s *Store) batchOfSeqLocked(seq int64) (BatchID, bool) {
	if s.active != nil {
		for _, d := range s.active.decisions {
			if d.Seq == seq {
				return d.Batch, true
			}
		}
	}
	for _, sb := range s.sealed {
		if seq >= sb.manifest.MinSeq && seq <= sb.manifest.MaxSeq {
			return sb.manifest.ID, true
		}
	}
	return "", false
}

// Snapshot 返回当前全部已发布批次的深拷贝视图：按封存顺序排列，
// 外加尚未封存活动批次的已落盘记录（它们同样是完整记录）。
// 整个拷贝在读锁内完成，轮转 / 清理的发布动作无法插入，
// 因此查询永远不会看到批次的一半新、一半旧。
func (s *Store) Snapshot() ([]Batch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Batch, 0, len(s.order)+1)
	for _, id := range s.order {
		sb := s.sealed[id]
		if sb == nil {
			continue
		}
		out = append(out, sb.snapshot())
	}
	if s.active != nil {
		decs := make([]Decision, len(s.active.decisions))
		copy(decs, s.active.decisions)
		out = append(out, Batch{ID: s.active.id, Active: true, Decisions: decs})
	}
	return out, nil
}

// Batch 是批次的只读快照。
type Batch struct {
	ID        BatchID
	Active    bool
	Decisions []Decision
}

func (sb *sealedBatch) snapshot() Batch {
	decs := make([]Decision, len(sb.decisions))
	copy(decs, sb.decisions)
	return Batch{ID: sb.manifest.ID, Active: false, Decisions: decs}
}

// Stats 为上层提供存储侧内部计数。
func (s *Store) Stats() (sealedCount int, activeCount int, lastSeq int64, activeID BatchID) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active != nil {
		activeCount = len(s.active.decisions)
		activeID = s.active.id
	}
	return len(s.order), activeCount, s.lastSeq, activeID
}

// Close 封存活动批次并落盘当前进度。
func (s *Store) Close(committedSeq int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.active != nil {
		if err := s.sealActiveLocked(); err != nil {
			return err
		}
	}
	return s.writeStateLocked(committedSeq)
}
