package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

var (
	ErrNotFound           = errors.New("resource not found")
	ErrInUse              = errors.New("resource is in use")
	ErrLastAdmin          = errors.New("cannot remove the last enabled system administrator")
	ErrAlreadyInitialized = errors.New("platform is already initialized")
	ErrMFAChallenge       = errors.New("MFA challenge is invalid or expired")
	ErrMFAReplay          = errors.New("MFA code was already used")
	ErrMFACooldown        = errors.New("MFA email is in cooldown")
)

type NodeConnection struct {
	ID            string
	Name          string
	APIURL        string
	TLSServerName string
	CredentialRef string
	Enabled       bool
}

func (s *Store) GetNodeConnection(ctx context.Context, nodeID string) (NodeConnection, error) {
	var node NodeConnection
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT id,name,api_url,tls_server_name,credential_ref,enabled FROM nodes WHERE id = ?`, nodeID).Scan(&node.ID, &node.Name, &node.APIURL, &node.TLSServerName, &node.CredentialRef, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return NodeConnection{}, ErrNotFound
	}
	if err != nil {
		return NodeConnection{}, err
	}
	node.Enabled = enabled == 1
	return node, nil
}

func (s *Store) UpdateNodeHealth(ctx context.Context, nodeID, status string, checkedAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET health_status = ?, last_checked_at = ?, updated_at = ? WHERE id = ?`, status, checkedAt.UTC().Format(time.RFC3339Nano), checkedAt.UTC().Format(time.RFC3339Nano), nodeID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
