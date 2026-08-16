package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

func insertAudit(ctx context.Context, tx *sql.Tx, auditID string, input AuditInput, now time.Time) error {
	metadata := sanitizeAuditMetadata(input.MetadataJSON)
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(id,actor,action,resource_type,resource_id,result,request_id,source_ip,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		auditID, input.Actor, input.Action, input.ResourceType, input.ResourceID, input.Result, input.RequestID, input.SourceIP, metadata, now.Format(time.RFC3339Nano))
	return err
}

func sanitizeAuditMetadata(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "{}"
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		// Audit metadata is optional. Never persist malformed, potentially
		// secret-bearing text just because a caller forgot to encode JSON.
		return "{}"
	}
	value = redactAuditValue(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func redactAuditValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if auditKeyIsSensitive(key) {
				typed[key] = "[REDACTED]"
				continue
			}
			typed[key] = redactAuditValue(child)
		}
		return typed
	case []any:
		for index, child := range typed {
			typed[index] = redactAuditValue(child)
		}
		return typed
	default:
		return typed
	}
}

func auditKeyIsSensitive(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
	for _, fragment := range []string{
		"password", "passwd", "passphrase", "secret", "token", "credential",
		"privatekey", "verifykey", "authorization", "cookie",
	} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
