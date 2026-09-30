package audit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// PipelineConfig 是流水线配置。
type PipelineConfig struct {
	Dir           string
	MaxEventBytes int
	Sources       []Source
	Retention     RetentionConfig
}

// Stats 暴露可观测计数。接受 / 拒绝在接入阶段计数；
// Processed 只在事件真正判定并写入批次后递增，因此
// 重启续跑不会重复计数。
type Stats struct {
	Accepted      int64
	Rejected      int64
	Processed     int64
	Failed        int64
	CommittedSeq  int64
	ActiveBatch   BatchID
	SealedBatches int64
}

// Pipeline 串起接入校验、WAL、单消费者、规则路由与批次存储。
type Pipeline struct {
	cfg    PipelineConfig
	known  map[Source]struct{}
	wal    *WAL
	store  *Store
	book   *PolicyBook
	router *Router

	mu      sync.Mutex
	seenIDs map[string]struct{} // 已接受（在 WAL 中）的事件 ID
	closed  bool
	started bool
	cancel  context.CancelFunc
	doneCh  chan struct{}

	accepted  atomic.Int64
	rejected  atomic.Int64
	processed atomic.Int64
	failed    atomic.Int64
	committed atomic.Int64

	// drain 条件：已接受全部处理（committed >= 已写 WAL 最大序号）。
	drainMu   sync.Mutex
	drainCond *sync.Cond
}

func New(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.Dir == "" {
		return nil, newError(CodeInternal, "cfg.dir", "data directory is required", nil)
	}
	if cfg.MaxEventBytes <= 0 {
		cfg.MaxEventBytes = 1 << 20
	}
	cfg.Retention = cfg.Retention.normalized()
	known := make(map[Source]struct{}, len(cfg.Sources))
	for _, s := range cfg.Sources {
		if s == "" {
			return nil, newError(CodeInternal, "cfg.sources", "empty source name", nil)
		}
		known[s] = struct{}{}
	}
	book := NewPolicyBook()
	wal, err := OpenWAL(cfg.Dir)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(StoreConfig{Dir: cfg.Dir, Retention: cfg.Retention}, book)
	if err != nil {
		_ = wal.Close()
		return nil, err
	}
	p := &Pipeline{
		cfg:     cfg,
		known:   known,
		wal:     wal,
		store:   store,
		book:    book,
		router:  NewRouter(book),
		seenIDs: map[string]struct{}{},
		doneCh:  make(chan struct{}),
	}
	p.drainCond = sync.NewCond(&p.drainMu)
	if err := p.indexAcceptedIDs(); err != nil {
		_ = wal.Close()
		_ = store.Close(0)
		return nil, err
	}
	return p, nil
}

func (p *Pipeline) Book() *PolicyBook { return p.book }
func (p *Pipeline) Store() *Store     { return p.store }
func (p *Pipeline) WAL() *WAL         { return p.wal }

// indexAcceptedIDs 把历史 WAL 中的事件 ID 全部建索引，
// 使“重启后重发同一事件”仍可被识别为重复。
func (p *Pipeline) indexAcceptedIDs() error {
	return p.wal.ReadFrom(1, func(r walRecord) error {
		p.seenIDs[r.Event.ID] = struct{}{}
		return nil
	})
}

// PublishPolicy 发布新版本策略，返回版本号。策略以发布时快照为准，
// 之后再发布新版本不影响已处理事件的历史结论。
func (p *Pipeline) PublishPolicy(rules []Rule) (PolicyVersion, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.book.Publish(rules)
}

// Start 启动唯一的后台消费者，从上次提交序号之后续跑。
// 恢复期间未消费的事件会继续处理，已提交的不会重复处理。
func (p *Pipeline) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started {
		return newError(CodeInternal, "pipeline", "already started", nil)
	}
	if p.book.Latest() == 0 {
		return newError(CodeInternal, "policy",
			"publish at least one policy version before start", nil)
	}
	committed, err := p.store.CommittedSeq()
	if err != nil {
		return err
	}
	p.committed.Store(committed)
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.started = true
	go p.consumeLoop(ctx, committed)
	return nil
}

func (p *Pipeline) consumeLoop(ctx context.Context, fromCommitted int64) {
	defer close(p.doneCh)
	err := p.wal.Follow(ctx, fromCommitted+1, func(rec walRecord) error {
		// 恢复边界：该序号在崩溃前已进入批次（进度位点未及时推进），
		// 幂等跳过且不重复计数，只把提交位点补齐。
		if rec.Seq <= p.committed.Load() {
			return nil
		}
		if p.store.alreadyBatched(rec.Seq) {
			if err := p.store.CommitSeq(rec.Seq); err != nil {
				p.failed.Add(1)
				return err
			}
			p.committed.Store(rec.Seq)
			p.signalDrained()
			return nil
		}
		version := p.book.Latest()
		ev := rec.Event
		evl := ev
		eval := p.router.Evaluate(&evl, version)
		d := Decision{
			Seq:           rec.Seq,
			EventID:       ev.ID,
			Source:        ev.Source,
			Type:          ev.Type,
			OccurredAt:    ev.OccurredAt,
			EvaluatedAt:   time.Now().UTC(),
			PolicyVersion: eval.Version,
			Matched:       eval.Matched,
			RuleID:        eval.RuleID,
			Verdict:       eval.Verdict,
			Basis:         eval.Basis,
			Event:         ev,
		}
		if _, err := p.store.Append(d); err != nil {
			p.failed.Add(1)
			return err
		}
		// 先批次落盘（Append 内 fsync + 可能已原子封存），再提交进度，
		// 崩溃后至多重处理、绝不丢事件。
		if err := p.store.CommitSeq(rec.Seq); err != nil {
			p.failed.Add(1)
			return err
		}
		p.processed.Add(1)
		p.committed.Store(rec.Seq)
		p.signalDrained()
		return nil
	})
	if err != nil {
		// 内部处理失败显式计数；不静默丢弃。
		p.failed.Add(1)
	}
}

func (p *Pipeline) signalDrained() {
	p.drainMu.Lock()
	p.drainCond.Broadcast()
	p.drainMu.Unlock()
}

// SubmitBytes 接收原始事件：校验通过即写入持久 WAL 并返回序号；
// 校验失败按原因码拒绝，不产生任何状态变化。重复 ID 显式拒绝。
func (p *Pipeline) SubmitBytes(raw []byte) (int64, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, newError(CodeClosed, "pipeline", "pipeline is closed", nil)
	}
	p.mu.Unlock()

	ev, verr := ParseEvent(raw, p.cfg.MaxEventBytes, p.known)
	if verr != nil {
		p.rejected.Add(1)
		return 0, verr
	}
	p.mu.Lock()
	if _, dup := p.seenIDs[ev.ID]; dup {
		p.mu.Unlock()
		p.rejected.Add(1)
		return 0, newError(CodeDuplicate, "id", "duplicate event id", nil)
	}
	p.seenIDs[ev.ID] = struct{}{}
	p.mu.Unlock()

	seq, err := p.wal.Append(*ev)
	if err != nil {
		p.mu.Lock()
		delete(p.seenIDs, ev.ID)
		p.mu.Unlock()
		p.failed.Add(1)
		return 0, err
	}
	p.accepted.Add(1)
	p.signalDrained()
	return seq, nil
}

// WaitDrained 阻塞直到所有已接受事件都完成判定与进度提交。
func (p *Pipeline) WaitDrained() error {
	p.drainMu.Lock()
	defer p.drainMu.Unlock()
	for {
		// 关闭期间仍允许等到底（关闭时不会再有新事件进入 WAL）；
		// 只有存储已彻底关闭时才作为错误返回。
		if p.committed.Load() >= p.wal.NextSeq()-1 {
			return nil
		}
		p.mu.Lock()
		storeClosed := false
		p.mu.Unlock()
		if storeClosed {
			return newError(CodeClosed, "pipeline", "closed while draining", nil)
		}
		p.drainCond.Wait()
	}
}

func (p *Pipeline) Stats() Stats {
	sealed, active, _, activeID := p.store.Stats()
	return Stats{
		Accepted:      p.accepted.Load(),
		Rejected:      p.rejected.Load(),
		Processed:     p.processed.Load(),
		Failed:        p.failed.Load(),
		CommittedSeq:  p.committed.Load(),
		ActiveBatch:   activeID,
		SealedBatches: int64(sealed) + boolToInt64(active > 0),
	}
}

// Close 停止接受新事件，等待消费者退出，封存活动批次并落盘进度。
func (p *Pipeline) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	started := p.started
	cancel := p.cancel
	p.mu.Unlock()
	p.signalDrained()
	// 关闭前先把所有已接受（已在 WAL）的事件处理完，避免取消
	// 与最后一批落盘记录竞争；未处理部分下次重启由进度位点续跑。
	if started {
		_ = p.WaitDrained()
		// 消费者随后阻塞在“等待新记录”上，必须靠 cancel 唤醒退出。
		cancel()
		<-p.doneCh
	}
	committed := p.committed.Load()
	if err := p.store.Close(committed); err != nil {
		_ = p.wal.Close()
		return err
	}
	return p.wal.Close()
}

func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
