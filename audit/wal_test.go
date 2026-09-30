package audit

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWALAppendReplayAndFollow(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wal")
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := int64(1); i <= 3; i++ {
		seq, err := w.Append(Event{ID: "w-" + itoa(int(i)), Source: "web",
			Type: "login", OccurredAt: time.Now().UTC()})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if seq != i {
			t.Fatalf("seq=%d want %d", seq, i)
		}
	}

	// ReadFrom 从指定位点回放。
	var got []int64
	if err := w.ReadFrom(2, func(r walRecord) error {
		got = append(got, r.Seq)
		return nil
	}); err != nil {
		t.Fatalf("readfrom: %v", err)
	}
	if len(got) != 2 || got[0] != 2 || got[1] != 3 {
		t.Fatalf("replay seqs=%v want [2 3]", got)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 重新打开：序号必须从尾部 +1 继续。
	w2, err := OpenWAL(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if w2.NextSeq() != 4 {
		t.Fatalf("next seq after reopen=%d want 4", w2.NextSeq())
	}

	// Follow 先回放旧记录再实时收到新记录。观察切片由互斥保护。
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var seenMu sync.Mutex
	var seen []int64
	seenLen := func() int {
		seenMu.Lock()
		defer seenMu.Unlock()
		return len(seen)
	}
	followDone := make(chan struct{})
	go func() {
		_ = w2.Follow(ctx, 1, func(r walRecord) error {
			seenMu.Lock()
			seen = append(seen, r.Seq)
			seenMu.Unlock()
			return nil
		})
		close(followDone)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && seenLen() < 3 {
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := w2.Append(Event{ID: "w-4", Source: "cli", Type: "exec",
		OccurredAt: time.Now().UTC()}); err != nil {
		t.Fatalf("append 4: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && seenLen() < 4 {
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-followDone
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) != 4 || seen[3] != 4 {
		t.Fatalf("follow seen=%v want [1 2 3 4]", seen)
	}
	if err := w2.Close(); err != nil {
		t.Fatalf("close2: %v", err)
	}
}

func TestWALCorruptionRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wal")
	w, err := OpenWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(Event{ID: "ok-1", Source: "web", Type: "login",
		OccurredAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// 追加一行损坏记录：重开必须显式失败，绝不静默截断。
	if err := appendRawForTest(filepath.Join(dir, walFileName), []byte("{bad\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWAL(dir); !IsCode(err, CodeInternal) {
		t.Fatalf("want internal error on corrupt WAL, got %v", err)
	}
}
