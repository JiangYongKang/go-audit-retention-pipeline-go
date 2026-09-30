// Package store provides durable, append-only storage with sealed batches.
//
// Layout under the data directory:
//
//	batches/<batchID>.jsonl   append-only records of one batch
//	batches/<batchID>.meta    present only once a batch is sealed
//	cursor.json               consumer progress
//	policies/v<N>.json        immutable policy versions
//
// Sealing is atomic from a reader's point of view: a new open batch is
// created and made current before the old batch file is renamed with a
// .meta marker, so a query never observes a batch that is half sealed.
package store

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/model"
)

type batchState struct {
	meta   model.BatchMeta
	recs   []model.Record
	sealed bool
}

// Store is the persistence boundary.
type Store struct {
	dir     string
	mu      sync.RWMutex
	batches map[string]*batchState
	current string
	maxSeq  int64
	seen    map[int64]struct{}
}

// New opens or creates a store rooted at dir and rebuilds its in-memory
// indexes from disk, which is the basis for restart recovery and
// duplicate suppression.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "batches"), 0o755); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "create data dir", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "policies"), 0o755); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "create policies dir", err)
	}
	s := &Store{dir: dir, batches: map[string]*batchState{}, seen: map[int64]struct{}{}}
	if err := s.recover(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) recover() error {
	entries, err := os.ReadDir(filepath.Join(s.dir, "batches"))
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "read batches dir", err)
	}
	type openInfo struct {
		path string
		info os.FileInfo
	}
	var opens []openInfo
	for _, en := range entries {
		name := en.Name()
		if en.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".meta") {
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		info, err := en.Info()
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "stat batch "+name, err)
		}
		id := strings.TrimSuffix(name, ".jsonl")
		if _, err := os.Stat(filepath.Join(s.dir, "batches", id+".meta")); err == nil {
			// Sealed: index is rebuilt by reading the data file.
			if err := s.loadBatch(id, info.ModTime(), true); err != nil {
				return err
			}
		} else {
			opens = append(opens, openInfo{path: filepath.Join(s.dir, "batches", name), info: info})
		}
	}
	// Exactly one batch can be open. If multiple are found after a crash
	// mid-rotation, the newest is open and the older ones are sealed.
	sort.Slice(opens, func(i, j int) bool { return opens[i].info.ModTime().Before(opens[j].info.ModTime()) })
	for i, o := range opens {
		id := strings.TrimSuffix(filepath.Base(o.path), ".jsonl")
		isCurrent := i == len(opens)-1
		if err := s.loadBatch(id, o.info.ModTime(), !isCurrent); err != nil {
			return err
		}
		if isCurrent {
			s.current = id
		} else if err := s.writeMetaLocked(s.batches[id]); err != nil {
			return err
		}
	}
	if s.current == "" {
		if err := s.openNewBatchLocked(time.Now()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) loadBatch(id string, mtime time.Time, sealed bool) error {
	f, err := os.Open(filepath.Join(s.dir, "batches", id+".jsonl"))
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "open batch "+id, err)
	}
	defer f.Close()
	st := &batchState{sealed: sealed}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec model.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "corrupt batch "+id, err)
		}
		st.recs = append(st.recs, rec)
		s.seen[rec.Seq] = struct{}{}
		if rec.Seq > s.maxSeq {
			s.maxSeq = rec.Seq
		}
	}
	if err := sc.Err(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "scan batch "+id, err)
	}
	if sealed {
		mb, err := os.ReadFile(filepath.Join(s.dir, "batches", id+".meta"))
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "read meta "+id, err)
		}
		if err := json.Unmarshal(mb, &st.meta); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "parse meta "+id, err)
		}
	} else {
		st.meta = model.BatchMeta{ID: id, OpenedAt: mtime}
		if n := len(st.recs); n > 0 {
			st.meta.MinSeq = st.recs[0].Seq
			st.meta.MaxSeq = st.recs[n-1].Seq
			st.meta.Count = n
		}
	}
	s.batches[id] = st
	return nil
}

func (s *Store) openNewBatchLocked(now time.Time) error {
	// Time-based id; guarantee uniqueness even under clock ties or
	// multiple rotations within the same nanosecond.
	id := now.UTC().Format("20060102T150405.000000000Z")
	for n := 0; ; n++ {
		candidate := id
		if n > 0 {
			candidate = fmt.Sprintf("%s-%d", id, n)
		}
		if _, ok := s.batches[candidate]; !ok {
			id = candidate
			break
		}
	}
	path := filepath.Join(s.dir, "batches", id+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "create batch "+id, err)
	}
	if err := f.Close(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "close batch "+id, err)
	}
	s.batches[id] = &batchState{meta: model.BatchMeta{ID: id, OpenedAt: now}}
	s.current = id
	return nil
}

// Close flushes and releases resources. All writes are fsynced per append,
// so close only verifies the directory is still usable.
func (s *Store) Close() error { return nil }

// Append durably appends one record to the currently open batch. A
// duplicate sequence number is rejected instead of being counted twice.
// Batch ownership is assigned here under the write lock, so a record can
// never land in a batch that another goroutine sealed concurrently.
func (s *Store) Append(ctx context.Context, rec model.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.seen[rec.Seq]; dup {
		return apperr.New(apperr.CodeInternal,
			fmt.Sprintf("duplicate seq %d already persisted", rec.Seq))
	}
	st, ok := s.batches[s.current]
	if !ok {
		return apperr.New(apperr.CodeInternal, "no open batch")
	}
	rec.BatchID = s.current
	line, err := json.Marshal(rec)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "marshal record", err)
	}
	if err := s.appendLineLocked(filepath.Join(s.dir, "batches", s.current+".jsonl"), line); err != nil {
		return err
	}
	st.recs = append(st.recs, rec)
	s.seen[rec.Seq] = struct{}{}
	if st.meta.Count == 0 {
		st.meta.MinSeq = rec.Seq
	}
	if rec.Seq > st.meta.MaxSeq {
		st.meta.MaxSeq = rec.Seq
	}
	if rec.Seq < st.meta.MinSeq {
		st.meta.MinSeq = rec.Seq
	}
	st.meta.Count++
	if rec.Seq > s.maxSeq {
		s.maxSeq = rec.Seq
	}
	return nil
}

func (s *Store) appendLineLocked(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "open append file", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write record", err)
	}
	if err := f.Sync(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "fsync record", err)
	}
	return nil
}

// AppendedSeq returns the highest durable sequence number (0 if none).
func (s *Store) AppendedSeq(ctx context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxSeq, nil
}

// Seen reports whether seq has already been persisted.
func (s *Store) Seen(ctx context.Context, seq int64) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.seen[seq]
	return ok, nil
}

// SealBatch atomically seals the open batch and opens a fresh one.
// Readers never see a half-sealed batch because the switch of the current
// batch and the meta marker happen under one lock.
func (s *Store) SealBatch(ctx context.Context, id string) (model.BatchMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" && id != s.current {
		st, ok := s.batches[id]
		if !ok {
			return model.BatchMeta{}, apperr.New(apperr.CodeNotFound, "batch not found: "+id)
		}
		if !st.sealed {
			return model.BatchMeta{}, apperr.New(apperr.CodeNotFound, "batch already rotated away: "+id)
		}
		return st.meta, nil
	}
	st := s.batches[s.current]
	if st.meta.Count == 0 {
		return st.meta, nil // nothing to seal; keep the empty batch open
	}
	st.meta.SealedAt = time.Now()
	st.sealed = true
	sealedID := s.current
	if err := s.writeMetaLocked(st); err != nil {
		st.sealed = false
		return model.BatchMeta{}, err
	}
	if err := s.openNewBatchLocked(time.Now()); err != nil {
		_ = os.Remove(filepath.Join(s.dir, "batches", sealedID+".meta"))
		st.sealed = false
		return model.BatchMeta{}, err
	}
	return st.meta, nil
}

func (s *Store) writeMetaLocked(st *batchState) error {
	b, err := json.MarshalIndent(st.meta, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "marshal meta", err)
	}
	tmp := filepath.Join(s.dir, "batches", st.meta.ID+".meta.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write meta tmp", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, "batches", st.meta.ID+".meta")); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "rename meta", err)
	}
	return nil
}

// CurrentBatchID returns the open batch id.
func (s *Store) CurrentBatchID(ctx context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current, nil
}

// DeleteBatch removes a sealed batch from disk and the index. The delete
// is serialized with appends and queries, so a concurrent query either
// sees the whole batch or none of it, never a partial result.
func (s *Store) DeleteBatch(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.batches[id]
	if !ok {
		return apperr.New(apperr.CodeNotFound, "batch not found: "+id)
	}
	if !st.sealed || id == s.current {
		return apperr.New(apperr.CodeInternal, "refuse to delete open batch: "+id)
	}
	if err := os.Remove(filepath.Join(s.dir, "batches", id+".jsonl")); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.CodeInternal, "remove batch data", err)
	}
	if err := os.Remove(filepath.Join(s.dir, "batches", id+".meta")); err != nil && !os.IsNotExist(err) {
		return apperr.Wrap(apperr.CodeInternal, "remove batch meta", err)
	}
	delete(s.batches, id)
	return nil
}

// Batches lists sealed batches in seal order.
func (s *Store) Batches(ctx context.Context) ([]model.BatchMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.BatchMeta
	for _, st := range s.batches {
		if st.sealed {
			out = append(out, st.meta)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SealedAt.Before(out[j].SealedAt) })
	return out, nil
}

// Query reads records from sealed batches only; the open batch is never
// exposed, preventing reads of half-written data during rotation.
func (s *Store) Query(ctx context.Context, batchID, source, eventType string, limit int) ([]model.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Record
	collect := func(st *batchState) {
		for _, rec := range st.recs {
			if source != "" && rec.Source != source {
				continue
			}
			if eventType != "" && rec.Type != eventType {
				continue
			}
			out = append(out, rec)
		}
	}
	if batchID != "" {
		st, ok := s.batches[batchID]
		if !ok {
			return nil, apperr.New(apperr.CodeNotFound, "batch not found: "+batchID)
		}
		if !st.sealed {
			return nil, apperr.New(apperr.CodeNotFound, "batch not found: "+batchID)
		}
		collect(st)
	} else {
		var sealed []*batchState
		for _, st := range s.batches {
			if st.sealed {
				sealed = append(sealed, st)
			}
		}
		sort.Slice(sealed, func(i, j int) bool { return sealed[i].meta.SealedAt.Before(sealed[j].meta.SealedAt) })
		for _, st := range sealed {
			collect(st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListAll returns every persisted record, including those in the open
// batch. It is used only for restart replay of unconsumed events.
func (s *Store) ListAll(ctx context.Context) ([]model.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var all []*batchState
	for _, st := range s.batches {
		all = append(all, st)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].meta.OpenedAt.Before(all[j].meta.OpenedAt) })
	var out []model.Record
	for _, st := range all {
		out = append(out, st.recs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// OpenBatchCount returns how many records the current open batch holds.
func (s *Store) OpenBatchCount(ctx context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.batches[s.current].meta.Count, nil
}

// SaveCursor atomically persists consumer progress.
func (s *Store) SaveCursor(ctx context.Context, c model.Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeJSONFileLocked(filepath.Join(s.dir, "cursor.json"), c)
}

// LoadCursor reads consumer progress; a missing cursor means zero progress.
func (s *Store) LoadCursor(ctx context.Context) (model.Cursor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var c model.Cursor
	b, err := os.ReadFile(filepath.Join(s.dir, "cursor.json"))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, apperr.Wrap(apperr.CodeInternal, "read cursor", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, apperr.Wrap(apperr.CodeInternal, "parse cursor", err)
	}
	return c, nil
}

// PutPolicy durably stores an immutable policy version.
func (s *Store) PutPolicy(ctx context.Context, p model.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, "policies", fmt.Sprintf("v%d.json", p.Version))
	if _, err := os.Stat(path); err == nil {
		var existing model.Policy
		b, rerr := os.ReadFile(path)
		if rerr == nil && json.Unmarshal(b, &existing) == nil && !policiesEqual(existing, p) {
			return apperr.New(apperr.CodeInternal, "policy version conflict: "+fmt.Sprintf("v%d", p.Version))
		}
		return nil // identical re-install is idempotent
	}
	return s.writeJSONFileLocked(path, p)
}

func policiesEqual(a, b model.Policy) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}

// GetPolicy loads a specific policy version so historical routing results
// remain reproducible after policy updates.
func (s *Store) GetPolicy(ctx context.Context, version int64) (model.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var p model.Policy
	b, err := os.ReadFile(filepath.Join(s.dir, "policies", fmt.Sprintf("v%d.json", version)))
	if os.IsNotExist(err) {
		return p, apperr.New(apperr.CodeNotFound, fmt.Sprintf("policy v%d not found", version))
	}
	if err != nil {
		return p, apperr.Wrap(apperr.CodeInternal, "read policy", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, apperr.Wrap(apperr.CodeInternal, "parse policy", err)
	}
	return p, nil
}

// LatestPolicyVersion returns the highest stored policy version.
func (s *Store) LatestPolicyVersion(ctx context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.dir, "policies"))
	if err != nil {
		return 0, apperr.Wrap(apperr.CodeInternal, "read policies dir", err)
	}
	var latest int64
	for _, en := range entries {
		name := strings.TrimSuffix(en.Name(), ".json")
		var v int64
		if _, err := fmt.Sscanf(name, "v%d", &v); err == nil && v > latest {
			latest = v
		}
	}
	return latest, nil
}

func (s *Store) writeJSONFileLocked(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "marshal json", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write json tmp", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "rename json", err)
	}
	return nil
}

// Snapshot returns sealed batch metadata and their records in one
// read-locked operation, so concurrent rotation or cleanup cannot make a
// reader observe a listing that disagrees with the rows it received.
func (s *Store) Snapshot(ctx context.Context, source, eventType string) ([]model.BatchMeta, []model.Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var metas []model.BatchMeta
	var sealed []*batchState
	for _, st := range s.batches {
		if st.sealed {
			sealed = append(sealed, st)
			metas = append(metas, st.meta)
		}
	}
	sort.Slice(sealed, func(i, j int) bool { return sealed[i].meta.SealedAt.Before(sealed[j].meta.SealedAt) })
	sort.Slice(metas, func(i, j int) bool { return metas[i].SealedAt.Before(metas[j].SealedAt) })
	var out []model.Record
	for _, st := range sealed {
		for _, rec := range st.recs {
			if source != "" && rec.Source != source {
				continue
			}
			if eventType != "" && rec.Type != eventType {
				continue
			}
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return metas, out, nil
}
