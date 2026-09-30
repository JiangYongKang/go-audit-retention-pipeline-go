// Package retention enforces batch rotation and retention cleanup.
package retention

import (
	"context"
	"sync"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

// Policy configures rotation and cleanup behaviour.
type Policy struct {
	// MaxBatchRecords seals a batch once it holds this many records.
	MaxBatchRecords int
	// MaxBatchAge seals a batch once it has been open this long.
	MaxBatchAge time.Duration
	// Retention removes sealed batches older than this duration.
	Retention time.Duration
}

// BatchStore is the storage surface required by the manager. The concrete
// *store.Store satisfies it; the interface keeps packages decoupled.
type BatchStore interface {
	CurrentBatchID(ctx context.Context) (string, error)
	SealBatch(ctx context.Context, id string) (model.BatchMeta, error)
	DeleteBatch(ctx context.Context, id string) error
	Batches(ctx context.Context) ([]model.BatchMeta, error)
}

// Manager owns the open batch lifecycle. All rotation decisions are
// serialized so concurrent writers trigger at most one rotation per
// threshold crossing.
type Manager struct {
	store    BatchStore
	policy   Policy
	mu       sync.Mutex
	openedAt time.Time
	current  string
	now      func() time.Time
}

// NewManager constructs a Manager and attaches it to an existing open
// batch found in the store during recovery.
func NewManager(p Policy, st BatchStore) (*Manager, error) {
	m := &Manager{store: st, policy: p, now: time.Now}
	ctx := context.Background()
	id, err := st.CurrentBatchID(ctx)
	if err != nil {
		return nil, err
	}
	m.current = id
	m.openedAt = m.now()
	return m, nil
}

// CurrentBatchID returns the open batch id.
func (m *Manager) CurrentBatchID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// OnWrite is called after every durable append. It rotates when the
// record-count or age threshold is exceeded. count is the open batch size.
func (m *Manager) OnWrite(ctx context.Context, count int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	age := m.now().Sub(m.openedAt)
	byCount := m.policy.MaxBatchRecords > 0 && count >= m.policy.MaxBatchRecords
	byAge := m.policy.MaxBatchAge > 0 && age >= m.policy.MaxBatchAge
	if !byCount && !byAge {
		return nil
	}
	return m.rotateLocked(ctx)
}

// MaybeRotateByAge seals the open batch if its age threshold is reached.
// It is intended for periodic ticker-driven checks.
func (m *Manager) MaybeRotateByAge(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy.MaxBatchAge <= 0 || m.now().Sub(m.openedAt) < m.policy.MaxBatchAge {
		return nil
	}
	return m.rotateLocked(ctx)
}

func (m *Manager) rotateLocked(ctx context.Context) error {
	meta, err := m.store.SealBatch(ctx, m.current)
	if err != nil {
		return err
	}
	// Empty batch: the store keeps it open and returns its existing meta,
	// so there is no new batch to track.
	if meta.Count == 0 {
		return nil
	}
	id, err := m.store.CurrentBatchID(ctx)
	if err != nil {
		return err
	}
	m.current = id
	m.openedAt = m.now()
	return nil
}

// Seal explicitly seals the current batch and opens a new one.
func (m *Manager) Seal(ctx context.Context) (model.BatchMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.current
	meta, err := m.store.SealBatch(ctx, old)
	if err != nil {
		return model.BatchMeta{}, err
	}
	if meta.Count == 0 {
		return meta, nil
	}
	id, err := m.store.CurrentBatchID(ctx)
	if err != nil {
		return model.BatchMeta{}, err
	}
	m.current = id
	m.openedAt = m.now()
	return meta, nil
}

// Cleanup deletes sealed batches sealed before now-Retention. Deletion is
// delegated to the store, which serializes it against queries: a query
// observes either the full batch or its total absence.
func (m *Manager) Cleanup(ctx context.Context, now time.Time) ([]string, error) {
	if m.policy.Retention <= 0 {
		return nil, nil
	}
	batches, err := m.store.Batches(ctx)
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-m.policy.Retention)
	var removed []string
	for _, b := range batches {
		if b.SealedAt.Before(cutoff) {
			if err := m.store.DeleteBatch(ctx, b.ID); err != nil {
				return removed, err
			}
			removed = append(removed, b.ID)
		}
	}
	return removed, nil
}
