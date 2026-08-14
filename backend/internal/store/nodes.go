package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"i5cloud/internal/id"
)

func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,api_url,tls_server_name,credential_ref,port_start,port_end,enabled,health_status,last_checked_at,created_at,updated_at FROM nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Node{}
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

func (s *Store) CreateNode(ctx context.Context, input CreateNodeInput, audit AuditInput) (Node, error) {
	nodeID := input.ID
	if nodeID == "" {
		var err error
		nodeID, err = id.New()
		if err != nil {
			return Node{}, err
		}
	}
	auditID, err := id.New()
	if err != nil {
		return Node{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Node{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO nodes(id,name,api_url,tls_server_name,credential_ref,port_start,port_end,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		nodeID, input.Name, input.APIURL, input.TLSServerName, input.CredentialRef, input.PortStart, input.PortEnd, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Node{}, fmt.Errorf("insert node: %w", err)
	}
	audit.ResourceID = nodeID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(); err != nil {
		return Node{}, err
	}
	return Node{ID: nodeID, Name: input.Name, APIURL: input.APIURL, TLSServerName: input.TLSServerName, CredentialConfigured: input.CredentialRef != "", PortStart: input.PortStart, PortEnd: input.PortEnd, Enabled: true, HealthStatus: "unknown", CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) NodeCredentialReference(ctx context.Context, nodeID string) (string, error) {
	var reference string
	if err := s.db.QueryRowContext(ctx, `SELECT credential_ref FROM nodes WHERE id=?`, nodeID).Scan(&reference); err != nil {
		if err == sql.ErrNoRows {
			return "", ErrNotFound
		}
		return "", err
	}
	return reference, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(scanner rowScanner) (Node, error) {
	var node Node
	var credentialRef, lastChecked, createdAt, updatedAt string
	var enabled int
	var lastCheckedValue sql.NullString
	if err := scanner.Scan(&node.ID, &node.Name, &node.APIURL, &node.TLSServerName, &credentialRef, &node.PortStart, &node.PortEnd, &enabled, &node.HealthStatus, &lastCheckedValue, &createdAt, &updatedAt); err != nil {
		return Node{}, err
	}
	node.Enabled = enabled == 1
	node.CredentialConfigured = credentialRef != ""
	var err error
	node.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Node{}, err
	}
	node.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Node{}, err
	}
	if lastCheckedValue.Valid {
		lastChecked = lastCheckedValue.String
		parsed, parseErr := time.Parse(time.RFC3339Nano, lastChecked)
		if parseErr != nil {
			return Node{}, parseErr
		}
		node.LastCheckedAt = &parsed
	}
	return node, nil
}

func (s *Store) UpdateNode(ctx context.Context, nodeID string, input UpdateNodeInput, audit AuditInput) (Node, error) {
	auditID, err := id.New()
	if err != nil {
		return Node{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Node{}, err
	}
	defer tx.Rollback()
	var enabled any
	if input.Enabled != nil {
		if *input.Enabled {
			enabled = 1
		} else {
			enabled = 0
		}
	}
	result, err := tx.ExecContext(ctx, `
UPDATE nodes SET name=?,api_url=?,tls_server_name=?,credential_ref=CASE WHEN ?='' THEN credential_ref ELSE ? END,port_start=?,port_end=?,enabled=COALESCE(?,enabled),updated_at=?
WHERE id=?`, input.Name, input.APIURL, input.TLSServerName, input.CredentialRef, input.CredentialRef, input.PortStart, input.PortEnd, enabled, now.Format(time.RFC3339Nano), nodeID)
	if err != nil {
		return Node{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return Node{}, ErrNotFound
	}
	audit.ResourceID = nodeID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Node{}, err
	}
	if err := tx.Commit(); err != nil {
		return Node{}, err
	}
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return Node{}, err
	}
	for _, node := range nodes {
		if node.ID == nodeID {
			return node, nil
		}
	}
	return Node{}, ErrNotFound
}

func (s *Store) DeleteNode(ctx context.Context, nodeID string, audit AuditInput) error {
	auditID, err := id.New()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var projects int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE node_id = ?`, nodeID).Scan(&projects); err != nil {
		return err
	}
	if projects > 0 {
		return fmt.Errorf("node still has projects")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, nodeID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = nodeID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}
