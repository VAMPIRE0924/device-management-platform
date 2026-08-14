package store

import (
	"context"
	"time"

	"i5cloud/internal/id"
)

func (s *Store) AppendAudit(ctx context.Context, input AuditInput) error {
	auditID, err := id.New()
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertAudit(ctx, tx, auditID, input, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}
