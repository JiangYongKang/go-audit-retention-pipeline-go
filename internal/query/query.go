// Package query provides authorized, least-privilege read access.
package query

import (
	"context"
	"time"

	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/apperr"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/security"
	"github.com/highcumontoa/go-audit-retention-pipeline-go/internal/store"
)

// Service is the read side of the system.
type Service struct {
	store    *store.Store
	enforcer *security.Enforcer
}

// NewService constructs a query Service.
func NewService(st *store.Store, en *security.Enforcer) *Service {
	return &Service{store: st, enforcer: en}
}

// Query returns masked views for an authorized principal.
//
// Authorization is evaluated before storage access, so a principal without
// the source grant always receives the same ACCESS_DENIED error: batch
// existence and record counts cannot be probed via NOT_FOUND or result
// sizes. Hidden payload fields are omitted entirely by the enforcer.
func (s *Service) Query(ctx context.Context, principal, batchID, source, eventType string, limit int) ([]security.View, error) {
	if source == "" {
		return nil, apperr.New(apperr.CodeMissingField, "missing filter: source")
	}
	if err := s.enforcer.CheckSource(ctx, principal, source); err != nil {
		return nil, err
	}
	recs, err := s.store.Query(ctx, batchID, source, eventType, limit)
	if err != nil {
		return nil, err
	}
	views := make([]security.View, 0, len(recs))
	for _, rec := range recs {
		v, err := s.enforcer.Mask(ctx, principal, rec)
		if err != nil {
			// Deny the whole request rather than silently dropping rows,
			// so partial visibility cannot be inferred from row counts.
			return nil, err
		}
		views = append(views, v)
	}
	return views, nil
}

// Batches lists sealed batch metadata for an authorized principal. Only
// ids and timing/count metadata are exposed; no payload is involved.
func (s *Service) Batches(ctx context.Context, principal string) ([]BatchInfo, error) {
	if principal == "" {
		return nil, apperr.New(apperr.CodeAccessDenied, "access denied")
	}
	metas, err := s.store.Batches(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BatchInfo, 0, len(metas))
	for _, m := range metas {
		out = append(out, BatchInfo{
			ID:       m.ID,
			OpenedAt: m.OpenedAt.Format(time.RFC3339Nano),
			SealedAt: m.SealedAt.Format(time.RFC3339Nano),
			MinSeq:   m.MinSeq,
			MaxSeq:   m.MaxSeq,
			Count:    m.Count,
		})
	}
	return out, nil
}

// BatchInfo is the externally visible batch metadata.
type BatchInfo struct {
	ID       string `json:"id"`
	OpenedAt string `json:"opened_at"`
	SealedAt string `json:"sealed_at"`
	MinSeq   int64  `json:"min_seq"`
	MaxSeq   int64  `json:"max_seq"`
	Count    int    `json:"count"`
}

// Snapshot returns masked records together with the batch listing observed
// under the same storage read lock. Concurrent cleanup can never produce a
// listing and a row set that disagree, which is what callers performing a
// count-then-read check need.
func (s *Service) Snapshot(ctx context.Context, principal, source, eventType string) ([]BatchInfo, []security.View, error) {
	if source == "" {
		return nil, nil, apperr.New(apperr.CodeMissingField, "missing filter: source")
	}
	if err := s.enforcer.CheckSource(ctx, principal, source); err != nil {
		return nil, nil, err
	}
	metas, recs, err := s.store.Snapshot(ctx, source, eventType)
	if err != nil {
		return nil, nil, err
	}
	infos := make([]BatchInfo, 0, len(metas))
	for _, m := range metas {
		infos = append(infos, BatchInfo{
			ID:       m.ID,
			OpenedAt: m.OpenedAt.Format(time.RFC3339Nano),
			SealedAt: m.SealedAt.Format(time.RFC3339Nano),
			MinSeq:   m.MinSeq,
			MaxSeq:   m.MaxSeq,
			Count:    m.Count,
		})
	}
	views := make([]security.View, 0, len(recs))
	for _, rec := range recs {
		v, err := s.enforcer.Mask(ctx, principal, rec)
		if err != nil {
			return nil, nil, err
		}
		views = append(views, v)
	}
	return infos, views, nil
}
