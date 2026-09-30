package retention

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

// fakeStore is an in-memory BatchStore recording seal/delete calls.
type fakeStore struct {
	mu        sync.Mutex
	current   string
	batches   map[string]model.BatchMeta
	sealed    []string
	deleted   []string
	sealCount int
}

func newFakeStore() *fakeStore {
	return &fakeStore{current: "b0", batches: map[string]model.BatchMeta{"b0": {ID: "b0", Count: 0}}}
}

func (f *fakeStore) CurrentBatchID(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current, nil
}

func (f *fakeStore) SealBatch(ctx context.Context, id string) (model.BatchMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.batches[id]
	if st.Count == 0 {
		return st, nil
	}
	st.SealedAt = time.Now()
	f.batches[id] = st
	f.sealed = append(f.sealed, id)
	f.sealCount++
	nid := "b" + itoa(len(f.batches))
	f.batches[nid] = model.BatchMeta{ID: nid}
	f.current = nid
	return st, nil
}

func (f *fakeStore) DeleteBatch(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.batches, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeStore) Batches(ctx context.Context) ([]model.BatchMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.BatchMeta
	for _, b := range f.batches {
		if !b.SealedAt.IsZero() {
			out = append(out, b)
		}
	}
	return out, nil
}

func (f *fakeStore) setCount(id string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := f.batches[id]
	b.Count = n
	f.batches[id] = b
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestRotationByCount(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	clock := time.Now()
	m, err := NewManager(Policy{MaxBatchRecords: 5}, f)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return clock }

	for i := 1; i <= 4; i++ {
		f.setCount(m.CurrentBatchID(), i)
		if err := m.OnWrite(ctx, i); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.sealed) != 0 {
		t.Fatalf("sealed early: %v", f.sealed)
	}
	f.setCount(m.CurrentBatchID(), 5)
	if err := m.OnWrite(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if len(f.sealed) != 1 {
		t.Fatalf("expected one seal at threshold, got %v", f.sealed)
	}
	t.Logf("input count=5 -> sealed batch=%s new open=%s", f.sealed[0], m.CurrentBatchID())
}

func TestRotationByAge(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	clock := time.Now()
	m, _ := NewManager(Policy{MaxBatchAge: time.Minute}, f)
	m.now = func() time.Time { return clock }
	f.setCount("b0", 2)

	if err := m.MaybeRotateByAge(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.sealed) != 0 {
		t.Fatal("sealed before age threshold")
	}
	clock = clock.Add(61 * time.Second)
	if err := m.MaybeRotateByAge(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.sealed) != 1 {
		t.Fatalf("age rotation did not seal: %v", f.sealed)
	}
	t.Logf("input age=61s -> sealed batch=%s", f.sealed[0])
}

func TestCleanupCutoff(t *testing.T) {
	ctx := context.Background()
	f := newFakeStore()
	now := time.Now()
	f.batches["old1"] = model.BatchMeta{ID: "old1", SealedAt: now.Add(-2 * time.Hour), Count: 1}
	f.batches["old2"] = model.BatchMeta{ID: "old2", SealedAt: now.Add(-90 * time.Minute), Count: 1}
	f.batches["fresh"] = model.BatchMeta{ID: "fresh", SealedAt: now.Add(-10 * time.Minute), Count: 1}
	m, _ := NewManager(Policy{Retention: time.Hour}, f)

	removed, err := m.Cleanup(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input batches old1(-2h) old2(-90m) fresh(-10m) retention=1h -> removed=%v", removed)
	if len(removed) != 2 {
		t.Fatalf("removed=%v, want old1,old2", removed)
	}
	if _, ok := f.batches["fresh"]; !ok {
		t.Fatal("fresh batch must survive cleanup")
	}
}
