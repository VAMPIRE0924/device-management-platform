package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

const accessActivityTouchInterval = 30 * time.Second

func (s *Store) EndpointRoute(ctx context.Context, endpointID string) (EndpointRoute, error) {
	var route EndpointRoute
	var clientID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
	SELECT e.id,e.name,e.protocol,e.target_port,e.access_type,e.tls_server_name,e.ssh_credential_ref,e.ssh_auth_method,e.ssh_username,e.ssh_key_path,e.ssh_host_key_fingerprint,
       d.id,d.name,d.host,p.id,p.name,p.node_id,p.client_id
FROM endpoints e
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = d.project_id
WHERE e.id = ?`, endpointID).Scan(
		&route.EndpointID, &route.EndpointName, &route.Protocol, &route.TargetPort, &route.AccessType, &route.TLSServerName, &route.CredentialRef, &route.SSHAuthMethod, &route.SSHUsername, &route.SSHKeyPath, &route.SSHHostKeyFingerprint,
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
	_, err = tx.ExecContext(ctx, `
INSERT INTO access_sessions(id,user_id,auth_session_id,project_id,endpoint_id,token_hash,route_label,grant_hash,grant_exchanged_at,mode,source_ip,status,expires_at,started_at,ended_at,last_seen_at)
VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,NULL,?)`,
		sessionID, input.UserID, input.AuthSessionID, input.ProjectID, input.EndpointID, input.TokenHash, input.RouteLabel, input.GrantHash, input.Mode, input.SourceIP, "active", input.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: access_sessions.token_hash") {
			return AccessSession{}, ErrInUse
		}
		return AccessSession{}, err
	}
	audit.ResourceID = sessionID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return AccessSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessSession{}, err
	}
	return AccessSession{ID: sessionID, TokenHash: input.TokenHash, DomainPrefix: input.RouteLabel, UserID: input.UserID, AuthSessionID: input.AuthSessionID, ProjectID: input.ProjectID, EndpointID: input.EndpointID, Mode: input.Mode, SourceIP: input.SourceIP, Status: "active", ExpiresAt: input.ExpiresAt.UTC(), StartedAt: now, LastSeenAt: now}, nil
}

// ExchangeAccessGrant consumes the one-time browser grant before issuing the
// host-scoped access cookie. A random access hostname is therefore routing
// information only and never sufficient authorization by itself.
func (s *Store) ExchangeAccessGrant(ctx context.Context, tokenHash, grantHash string, idleCutoff time.Time) (AccessSession, EndpointRoute, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE access_sessions
SET grant_exchanged_at = ?
WHERE token_hash = ? AND grant_hash = ? AND grant_exchanged_at IS NULL
  AND status = 'active' AND expires_at > ? AND last_seen_at > ?
  AND EXISTS (
    SELECT 1 FROM auth_sessions a JOIN users u ON u.id = a.user_id
    WHERE a.id = access_sessions.auth_session_id AND a.user_id = access_sessions.user_id
      AND a.status = 'active' AND a.expires_at > ? AND a.last_seen_at > ? AND u.enabled = 1
  )`, now, tokenHash, grantHash, now, idleCutoff.UTC().Format(time.RFC3339Nano), now, idleCutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return AccessSession{}, EndpointRoute{}, ErrNotFound
	}
	return s.ResolveAccessGrant(ctx, tokenHash, grantHash, idleCutoff)
}

func (s *Store) ResolveAccessGrant(ctx context.Context, tokenHash, grantHash string, idleCutoff time.Time) (AccessSession, EndpointRoute, error) {
	var session AccessSession
	var route EndpointRoute
	var userID, endedAt sql.NullString
	var clientID sql.NullInt64
	var expiresAt, startedAt, lastSeenAt string
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `
SELECT s.id,s.user_id,s.auth_session_id,s.project_id,s.endpoint_id,e.name,d.name,s.route_label,s.mode,s.source_ip,s.status,s.expires_at,s.started_at,s.last_seen_at,s.ended_at,
       e.protocol,e.target_port,e.access_type,e.tls_server_name,e.ssh_credential_ref,e.ssh_auth_method,e.ssh_username,e.ssh_key_path,e.ssh_host_key_fingerprint,d.id,d.host,p.name,p.node_id,p.client_id
FROM access_sessions s
JOIN auth_sessions a ON a.id = s.auth_session_id AND a.user_id = s.user_id
JOIN users u ON u.id = a.user_id AND u.enabled = 1
JOIN endpoints e ON e.id = s.endpoint_id
JOIN devices d ON d.id = e.device_id AND d.project_id = s.project_id
JOIN projects p ON p.id = s.project_id
WHERE s.token_hash = ? AND s.grant_hash = ? AND s.grant_exchanged_at IS NOT NULL
  AND s.status = 'active' AND s.expires_at > ? AND s.last_seen_at > ?
  AND a.status = 'active' AND a.expires_at > ? AND a.last_seen_at > ?`,
		tokenHash, grantHash, now.Format(time.RFC3339Nano), idleCutoff.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), idleCutoff.UTC().Format(time.RFC3339Nano)).Scan(
		&session.ID, &userID, &session.AuthSessionID, &session.ProjectID, &session.EndpointID, &session.EndpointName, &session.DeviceName, &session.DomainPrefix, &session.Mode, &session.SourceIP, &session.Status, &expiresAt, &startedAt, &lastSeenAt, &endedAt,
		&route.Protocol, &route.TargetPort, &route.AccessType, &route.TLSServerName, &route.CredentialRef, &route.SSHAuthMethod, &route.SSHUsername, &route.SSHKeyPath, &route.SSHHostKeyFingerprint, &route.DeviceID, &route.Host, &route.ProjectName, &route.NodeID, &clientID,
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
	previousLastSeen, err := time.Parse(time.RFC3339Nano, lastSeenAt)
	if err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	session.LastSeenAt = now
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
	route.EndpointID, route.EndpointName, route.DeviceName, route.ProjectID = session.EndpointID, session.EndpointName, session.DeviceName, session.ProjectID
	if clientID.Valid {
		route.ClientID = int(clientID.Int64)
	}
	// A single HTML page can load many assets concurrently. Persist activity at
	// a coarse interval so those requests do not create a SQLite write storm.
	if now.Sub(previousLastSeen) >= accessActivityTouchInterval {
		if _, err := tx.ExecContext(ctx, `UPDATE access_sessions SET last_seen_at = ? WHERE id = ?`, now.Format(time.RFC3339Nano), session.ID); err != nil {
			return AccessSession{}, EndpointRoute{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at = ? WHERE id = ? AND status = 'active'`, now.Format(time.RFC3339Nano), session.AuthSessionID); err != nil {
			return AccessSession{}, EndpointRoute{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return AccessSession{}, EndpointRoute{}, err
	}
	return session, route, nil
}

// TouchAccessSession records activity from a long-lived Web or WebSSH connection.
// The guarded update cannot revive an expired/revoked access or auth session.
func (s *Store) TouchAccessSession(ctx context.Context, sessionID string, now, idleCutoff time.Time) error {
	now = now.UTC()
	nowText := now.Format(time.RFC3339Nano)
	idleText := idleCutoff.UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
UPDATE access_sessions
SET last_seen_at = ?
WHERE id = ? AND status = 'active' AND expires_at > ? AND last_seen_at > ?
  AND EXISTS (
    SELECT 1 FROM auth_sessions a JOIN users u ON u.id = a.user_id
    WHERE a.id = access_sessions.auth_session_id AND a.user_id = access_sessions.user_id
		  AND a.status = 'active' AND a.expires_at > ? AND a.last_seen_at > ? AND u.enabled = 1
	  )`, nowText, sessionID, nowText, idleText, nowText, idleText)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	authResult, err := tx.ExecContext(ctx, `
UPDATE auth_sessions
SET last_seen_at = ?
WHERE id = (SELECT auth_session_id FROM access_sessions WHERE id = ?)
	  AND status = 'active' AND expires_at > ?`, nowText, sessionID, nowText)
	if err != nil {
		return err
	}
	authCount, err := authResult.RowsAffected()
	if err != nil {
		return err
	}
	if authCount != 1 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) ListActiveAccessSessions(ctx context.Context, idleCutoff time.Time) ([]AccessSession, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, `
SELECT s.id,s.token_hash,s.route_label,s.user_id,s.project_id,s.endpoint_id,e.name,d.name,s.mode,s.source_ip,s.status,s.expires_at,s.started_at,s.last_seen_at,s.ended_at
FROM access_sessions s
JOIN auth_sessions a ON a.id = s.auth_session_id AND a.user_id = s.user_id
JOIN users u ON u.id = a.user_id AND u.enabled = 1
JOIN endpoints e ON e.id = s.endpoint_id
JOIN devices d ON d.id = e.device_id
WHERE s.status = 'active' AND s.expires_at > ? AND s.last_seen_at > ?
  AND a.status = 'active' AND a.expires_at > ? AND a.last_seen_at > ?
ORDER BY s.last_seen_at DESC`, now, idleCutoff.UTC().Format(time.RFC3339Nano), now, idleCutoff.UTC().Format(time.RFC3339Nano))
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

func (s *Store) ExpireAccessSessions(ctx context.Context, now, idleCutoff time.Time) (int64, error) {
	nowText := now.UTC().Format(time.RFC3339Nano)
	idleText := idleCutoff.UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
UPDATE access_sessions
SET status = 'expired', ended_at = ?
WHERE status = 'active' AND (
  expires_at <= ? OR last_seen_at <= ? OR NOT EXISTS (
    SELECT 1 FROM auth_sessions a JOIN users u ON u.id = a.user_id
    WHERE a.id = access_sessions.auth_session_id AND a.user_id = access_sessions.user_id
      AND a.status = 'active' AND a.expires_at > ? AND a.last_seen_at > ? AND u.enabled = 1
  )
)`, nowText, nowText, idleText, nowText, idleText)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func scanAccessSession(scanner rowScanner) (AccessSession, error) {
	var session AccessSession
	var userID, endedAt sql.NullString
	var expiresAt, startedAt, lastSeenAt string
	if err := scanner.Scan(&session.ID, &session.TokenHash, &session.DomainPrefix, &userID, &session.ProjectID, &session.EndpointID, &session.EndpointName, &session.DeviceName, &session.Mode, &session.SourceIP, &session.Status, &expiresAt, &startedAt, &lastSeenAt, &endedAt); err != nil {
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
	session.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeenAt)
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
