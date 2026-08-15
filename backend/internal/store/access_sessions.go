package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) EndpointRoute(ctx context.Context, endpointID string) (EndpointRoute, error) {
	var route EndpointRoute
	var clientID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
	SELECT e.id,e.name,e.protocol,e.target_port,e.access_type,e.tls_server_name,e.allow_insecure_tls,e.ssh_credential_ref,e.ssh_auth_method,e.ssh_username,e.ssh_key_path,e.ssh_host_key_fingerprint,
       d.id,d.name,d.host,p.id,p.name,p.node_id,p.client_id
FROM endpoints e
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = d.project_id
WHERE e.id = ?`, endpointID).Scan(
		&route.EndpointID, &route.EndpointName, &route.Protocol, &route.TargetPort, &route.AccessType, &route.TLSServerName, &route.AllowInsecureTLS, &route.CredentialRef, &route.SSHAuthMethod, &route.SSHUsername, &route.SSHKeyPath, &route.SSHHostKeyFingerprint,
		&route.DeviceID, &route.DeviceName, &route.Host, &route.ProjectID, &route.ProjectName, &route.NodeID, &clientID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return EndpointRoute{}, ErrNotFound
	}
	if err != nil {
		return EndpointRoute{}, err
	}
	if clientID.Valid {
		route.ClientID = int(clientID.Int64)
	}
	return route, nil
}

func (s *Store) CreateAccessSession(ctx context.Context, input CreateAccessSessionInput, audit AuditInput) (AccessSession, error) {
	sessionID, err := id.New()
	if err != nil {
		return AccessSession{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return AccessSession{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessSession{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO access_sessions(id,user_id,project_id,endpoint_id,token_hash,mode,source_ip,status,expires_at,started_at) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		sessionID, input.UserID, input.ProjectID, input.EndpointID, input.TokenHash, input.Mode, input.SourceIP, "active", input.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return AccessSession{}, err
	}
	audit.ResourceID = sessionID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return AccessSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessSession{}, err
	}
	return AccessSession{ID: sessionID, UserID: input.UserID, ProjectID: input.ProjectID, EndpointID: input.EndpointID, Mode: input.Mode, SourceIP: input.SourceIP, Status: "active", ExpiresAt: input.ExpiresAt.UTC(), StartedAt: now}, nil
}

func (s *Store) ListActiveAccessSessions(ctx context.Context) ([]AccessSession, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id,s.user_id,s.project_id,s.endpoint_id,e.name,d.name,s.mode,s.source_ip,s.status,s.expires_at,s.started_at,s.ended_at
FROM access_sessions s
JOIN endpoints e ON e.id = s.endpoint_id
JOIN devices d ON d.id = e.device_id
WHERE s.status = 'active' AND s.expires_at > ?
ORDER BY s.started_at DESC`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AccessSession{}
	for rows.Next() {
		session, err := scanAccessSession(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, session)
	}
	return result, rows.Err()
}

func (s *Store) RevokeAccessSession(ctx context.Context, sessionID string, audit AuditInput) error {
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
	result, err := tx.ExecContext(ctx, `UPDATE access_sessions SET status = 'revoked', ended_at = ? WHERE id = ? AND status = 'active'`, now.Format(time.RFC3339Nano), sessionID)
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
	audit.ResourceID = sessionID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ExpireAccessSessions(ctx context.Context, now time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE access_sessions SET status = 'expired', ended_at = ? WHERE status = 'active' AND expires_at <= ?`,
		now.UTC().Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) ResolveAccessToken(ctx context.Context, tokenHash string) (AccessSession, EndpointRoute, error) {
	var session AccessSession
	var route EndpointRoute
	var userID, endedAt sql.NullString
	var clientID sql.NullInt64
	var expiresAt, startedAt string
	err := s.db.QueryRowContext(ctx, `
SELECT s.id,s.user_id,s.project_id,s.endpoint_id,e.name,d.name,s.mode,s.source_ip,s.status,s.expires_at,s.started_at,s.ended_at,
	       e.protocol,e.target_port,e.access_type,e.tls_server_name,e.allow_insecure_tls,e.ssh_credential_ref,e.ssh_auth_method,e.ssh_username,e.ssh_key_path,e.ssh_host_key_fingerprint,d.id,d.host,p.name,p.node_id,p.client_id
FROM access_sessions s
JOIN endpoints e ON e.id = s.endpoint_id
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = s.project_id
WHERE s.token_hash = ?`, tokenHash).Scan(
		&session.ID, &userID, &session.ProjectID, &session.EndpointID, &session.EndpointName, &session.DeviceName, &session.Mode, &session.SourceIP, &session.Status, &expiresAt, &startedAt, &endedAt,
		&route.Protocol, &route.TargetPort, &route.AccessType, &route.TLSServerName, &route.AllowInsecureTLS, &route.CredentialRef, &route.SSHAuthMethod, &route.SSHUsername, &route.SSHKeyPath, &route.SSHHostKeyFingerprint, &route.DeviceID, &route.Host, &route.ProjectName, &route.NodeID, &clientID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AccessSession{}, EndpointRoute{}, ErrNotFound
	}
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	session.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	if userID.Valid {
		session.UserID = &userID.String
	}
	if endedAt.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, endedAt.String)
		if parseErr != nil {
			return AccessSession{}, EndpointRoute{}, parseErr
		}
		session.EndedAt = &value
	}
	route.EndpointID = session.EndpointID
	route.EndpointName = session.EndpointName
	route.DeviceName = session.DeviceName
	route.ProjectID = session.ProjectID
	if clientID.Valid {
		route.ClientID = int(clientID.Int64)
	}
	if session.Status != "active" || !session.ExpiresAt.After(time.Now().UTC()) {
		return AccessSession{}, EndpointRoute{}, ErrNotFound
	}
	return session, route, nil
}

func scanAccessSession(scanner rowScanner) (AccessSession, error) {
	var session AccessSession
	var userID, endedAt sql.NullString
	var expiresAt, startedAt string
	if err := scanner.Scan(&session.ID, &userID, &session.ProjectID, &session.EndpointID, &session.EndpointName, &session.DeviceName, &session.Mode, &session.SourceIP, &session.Status, &expiresAt, &startedAt, &endedAt); err != nil {
		return AccessSession{}, err
	}
	var err error
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return AccessSession{}, err
	}
	session.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return AccessSession{}, err
	}
	if userID.Valid {
		session.UserID = &userID.String
	}
	if endedAt.Valid {
		value, parseErr := time.Parse(time.RFC3339Nano, endedAt.String)
		if parseErr != nil {
			return AccessSession{}, parseErr
		}
		session.EndedAt = &value
	}
	return session, nil
}
