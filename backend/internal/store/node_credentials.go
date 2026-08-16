package store

import (
	"context"
	"database/sql"
)

func (s *Store) SaveNodeCredential(ctx context.Context, nodeID string, nonce, ciphertext []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_credentials(node_id,nonce,ciphertext,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP)
ON CONFLICT(node_id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,updated_at=CURRENT_TIMESTAMP`, nodeID, nonce, ciphertext)
	return err
}

func (s *Store) NodeCredential(ctx context.Context, nodeID string) ([]byte, []byte, error) {
	var nonce, ciphertext []byte
	err := s.db.QueryRowContext(ctx, `SELECT nonce,ciphertext FROM node_credentials WHERE node_id=?`, nodeID).Scan(&nonce, &ciphertext)
	if err == sql.ErrNoRows {
		return nil, nil, ErrNotFound
	}
	return nonce, ciphertext, err
}

func (s *Store) DeleteNodeCredential(ctx context.Context, nodeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM node_credentials WHERE node_id=?`, nodeID)
	return err
}
