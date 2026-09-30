package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

const walFileName = "wal.log"

// walRecord 是 WAL 中的一条记录：全局单调序号 + 事件内容。
type walRecord struct {
	Seq   int64 `json:"seq"`
	Event Event `json:"event"`
}

// WAL 为仅追加的预写日志：Append 在返回前完成 fsync。
// 消费者重启后从上次提交序号继续读，不丢、不重；
// Follow 在新记录落盘后立即被唤醒。
type WAL struct {
	mu      sync.Mutex
	cond    *sync.Cond
	dir     string
	f       *os.File
	nextSeq int64
	closed  bool
}

func OpenWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, newError(CodeInternal, "wal.dir", "mkdir failed", err)
	}
	path := filepath.Join(dir, walFileName)
	// O_CREATE 后对目录 fsync，确保目录项持久。
	newFile := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		newFile = true
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, newError(CodeInternal, "wal.file", "open failed", err)
	}
	if newFile {
		_ = syncDir(dir)
	}
	w := &WAL{dir: dir, f: f, nextSeq: 1}
	if err := w.recoverTail(); err != nil {
		_ = f.Close()
		return nil, err
	}
	w.cond = sync.NewCond(&w.mu)
	return w, nil
}

// recoverTail 从头扫描确定 nextSeq，同时检测半截尾记录。
// 写入是单次 Write，且 Append 才在 fsync 后返回，正常情况下
// 不会出现半截行；若发现则按内部损坏显式报错，绝不静默跳过。
func (w *WAL) recoverTail() error {
	f, err := os.Open(w.path())
	if err != nil {
		return newError(CodeInternal, "wal.file", "reopen for scan failed", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var maxSeq int64
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec walRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return newError(CodeInternal, "wal", "corrupt record encountered", err)
		}
		if rec.Seq <= 0 {
			return newError(CodeInternal, "wal", "record with non-positive seq", nil)
		}
		if rec.Seq != maxSeq+1 {
			return newError(CodeInternal, "wal", "non-contiguous sequence numbers", nil)
		}
		maxSeq = rec.Seq
	}
	if err := sc.Err(); err != nil {
		return newError(CodeInternal, "wal", "scan failed", err)
	}
	w.nextSeq = maxSeq + 1
	return nil
}

func (w *WAL) path() string { return filepath.Join(w.dir, walFileName) }

// Append 序列化、单行写入并 fsync，然后唤醒跟随者。返回全局序号。
func (w *WAL) Append(ev Event) (int64, error) {
	rec := walRecord{Seq: 0, Event: ev}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, newError(CodeClosed, "wal", "wal is closed", nil)
	}
	rec.Seq = w.nextSeq
	line, err := json.Marshal(rec)
	if err != nil {
		return 0, newError(CodeInternal, "wal", "marshal failed", err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		return 0, newError(CodeInternal, "wal", "write failed", err)
	}
	if err := w.f.Sync(); err != nil {
		return 0, newError(CodeInternal, "wal", "fsync failed", err)
	}
	w.nextSeq++
	w.cond.Broadcast()
	return rec.Seq, nil
}

// ReadFrom 回放 fromSeq（含）起的已有记录，不等待新记录。
func (w *WAL) ReadFrom(fromSeq int64, visit func(walRecord) error) error {
	f, err := os.Open(w.path())
	if err != nil {
		return newError(CodeInternal, "wal.file", "open for read failed", err)
	}
	defer f.Close()
	return scanFrom(f, fromSeq, visit)
}

// Follow 先回放 fromSeq（含）起的已有记录，然后等待并处理新落盘记录，
// 直到 ctx 取消。ctx 取消时返回 nil（正常停止）。
func (w *WAL) Follow(ctx context.Context, fromSeq int64, visit func(walRecord) error) error {
	// 每次唤醒重新打开并扫描：实现简单且无需维护跨写入的读偏移；
	// 扫描在 seq 达到当前尾后阻塞等待。
	var readTo int64 = fromSeq - 1
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		f, err := os.Open(w.path())
		if err != nil {
			return newError(CodeInternal, "wal.file", "open for follow failed", err)
		}
		var sawNew bool
		err = scanFromAfter(f, readTo, func(rec walRecord) error {
			sawNew = true
			readTo = rec.Seq
			return visit(rec)
		})
		_ = f.Close()
		if err != nil {
			return err
		}
		if sawNew {
			continue
		}
		// 已读到当前尾部，等待新记录或关闭。
		// cond.Wait 期间必须全程持锁，Wait 返回时锁被重新持有。
		stop := context.AfterFunc(ctx, func() {
			w.mu.Lock()
			w.cond.Broadcast()
			w.mu.Unlock()
		})
		w.mu.Lock()
		for w.nextSeq <= readTo+1 && !w.closed && ctx.Err() == nil {
			w.cond.Wait()
		}
		w.mu.Unlock()
		stop()
		if ctx.Err() != nil || w.closed {
			return nil
		}
	}
}

func scanFrom(f *os.File, fromSeq int64, visit func(walRecord) error) error {
	return scanFromAfter(f, fromSeq-1, visit)
}

// scanFromAfter 对 seq > afterSeq 的记录调用 visit。
func scanFromAfter(f *os.File, afterSeq int64, visit func(walRecord) error) error {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec walRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return newError(CodeInternal, "wal", "corrupt record encountered", err)
		}
		if rec.Seq <= afterSeq {
			continue
		}
		if err := visit(rec); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return newError(CodeInternal, "wal", "scan failed", err)
	}
	return nil
}

func (w *WAL) NextSeq() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.nextSeq
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.cond != nil {
		w.cond.Broadcast()
	}
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		return newError(CodeInternal, "wal", "final fsync failed", err)
	}
	if err := w.f.Close(); err != nil {
		return newError(CodeInternal, "wal", "close failed", err)
	}
	return nil
}

// syncDir 对目录执行 fsync，确保其中的新建 / 改名 / 删除条目持久。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
