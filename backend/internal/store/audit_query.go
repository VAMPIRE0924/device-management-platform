package store

import (
	"context"
	"fmt"
	"time"
)

func (s *Store) ListAuditLogs(ctx context.Context, search, category string, limit, offset int) ([]AuditLog, error) {
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	pattern := "%" + search + "%"
	operationOnly := category == "operation"
	rows, err := s.db.QueryContext(ctx, `
SELECT id,actor,action,resource_type,resource_id,result,request_id,source_ip,metadata_json,created_at
FROM audit_logs
WHERE (? = 0 OR (resource_type <> 'access_session' AND action NOT LIKE 'access_session.%'))
  AND (?='' OR actor LIKE ? OR action LIKE ? OR resource_type LIKE ? OR resource_id LIKE ? OR request_id LIKE ?)
ORDER BY created_at DESC LIMIT ? OFFSET ?`, operationOnly, search, pattern, pattern, pattern, pattern, pattern, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AuditLog{}
	for rows.Next() {
		var item AuditLog
		var createdAt string
		if err := rows.Scan(&item.ID, &item.Actor, &item.Action, &item.ResourceType, &item.ResourceID, &item.Result, &item.RequestID, &item.SourceIP, &item.MetadataJSON, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("parse audit timestamp: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
