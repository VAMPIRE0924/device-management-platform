package store

import (
	"context"
	"database/sql"
	"time"
)

func insertAudit(ctx context.Context, tx *sql.Tx, auditID string, input AuditInput, now time.Time) error {
	metadata := input.MetadataJSON
	if metadata == "" {
		metadata = "{}"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,resource_type,resource_id,result,request_id,source_ip,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		auditID, input.Actor, input.Action, input.ResourceType, input.ResourceID, input.Result, input.RequestID, input.SourceIP, metadata, now.Format(time.RFC3339Nano))
	return err
}
