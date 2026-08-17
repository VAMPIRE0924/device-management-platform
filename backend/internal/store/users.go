package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,username,display_name,email,role,enabled,EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=users.id),password_change_required,created_at,updated_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	result := []User{}
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range result {
		result[index].ProjectIDs, err = s.userProjects(ctx, result[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) HasUsers(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) CreateInitialAdmin(ctx context.Context, input CreateUserInput, audit AuditInput) (User, error) {
	userID, err := id.New()
	if err != nil {
		return User{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return User{}, err
	}
	if count != 0 {
		return User{}, ErrAlreadyInitialized
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		userID, input.Username, input.DisplayName, input.PasswordHash, "system_admin", 1, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return User{}, err
	}
	audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: userID, Username: input.Username, DisplayName: input.DisplayName, Role: "system_admin", Enabled: true, ProjectIDs: []string{}, PasswordChangeRequired: true, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) CreateUser(ctx context.Context, input CreateUserInput, audit AuditInput) (User, error) {
	userID, err := id.New()
	if err != nil {
		return User{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	enabled := 0
	if input.Enabled {
		enabled = 1
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		userID, input.Username, input.DisplayName, input.PasswordHash, input.Role, enabled, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return User{}, err
	}
	for _, projectID := range input.ProjectIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_memberships(user_id,project_id,created_at) VALUES(?,?,?)`, userID, projectID, now.Format(time.RFC3339Nano)); err != nil {
			return User{}, err
		}
	}
	audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return User{ID: userID, Username: input.Username, DisplayName: input.DisplayName, Role: input.Role, Enabled: input.Enabled, ProjectIDs: input.ProjectIDs, PasswordChangeRequired: true, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) UpdateUser(ctx context.Context, userID string, input UpdateUserInput, audit AuditInput) (User, error) {
	auditID, err := id.New()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()
	var username, previousRole, createdAtText string
	var previousEnabled int
	if err := tx.QueryRowContext(ctx, `SELECT username,role,enabled,created_at FROM users WHERE id = ?`, userID).Scan(&username, &previousRole, &previousEnabled, &createdAtText); errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	} else if err != nil {
		return User{}, err
	}
	if previousRole == "system_admin" && previousEnabled == 1 && (input.Role != "system_admin" || !input.Enabled) {
		var remaining int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = 'system_admin' AND enabled = 1 AND id <> ?`, userID).Scan(&remaining); err != nil {
			return User{}, err
		}
		if remaining == 0 {
			return User{}, ErrLastAdmin
		}
	}
	enabled := 0
	if input.Enabled {
		enabled = 1
	}
	if input.PasswordHash == "" {
		_, err = tx.ExecContext(ctx, `UPDATE users SET display_name=?,role=?,enabled=?,updated_at=? WHERE id=?`, input.DisplayName, input.Role, enabled, now.Format(time.RFC3339Nano), userID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE users SET display_name=?,password_hash=?,password_change_required=1,role=?,enabled=?,updated_at=? WHERE id=?`, input.DisplayName, input.PasswordHash, input.Role, enabled, now.Format(time.RFC3339Nano), userID)
	}
	if err != nil {
		return User{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM project_memberships WHERE user_id = ?`, userID); err != nil {
		return User{}, err
	}
	for _, projectID := range input.ProjectIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_memberships(user_id,project_id,created_at) VALUES(?,?,?)`, userID, projectID, now.Format(time.RFC3339Nano)); err != nil {
			return User{}, err
		}
	}
	// Permission, password, and enabled-state changes take effect immediately.
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return User{}, err
	}
	audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtText)
	if err != nil {
		return User{}, err
	}
	updated, err := s.userByID(ctx, userID)
	if err != nil {
		return User{}, err
	}
	updated.CreatedAt = createdAt
	return updated, nil
}

func (s *Store) DeleteUser(ctx context.Context, userID string, audit AuditInput) error {
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
	var role string
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT role,enabled FROM users WHERE id=?`, userID).Scan(&role, &enabled); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if role == "system_admin" && enabled == 1 {
		var remaining int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='system_admin' AND enabled=1 AND id<>?`, userID).Scan(&remaining); err != nil {
			return err
		}
		if remaining == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, userID); err != nil {
		return err
	}
	audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UserCredentialByUsername(ctx context.Context, username string) (UserCredential, error) {
	var credential UserCredential
	var enabled int
	var createdAt, updatedAt string
	var mfaEnabled, passwordChangeRequired int
	err := s.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.display_name,u.email,u.password_hash,u.role,u.enabled,EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=u.id),u.password_change_required,COALESCE((SELECT m.secret_ciphertext FROM user_mfa m WHERE m.user_id=u.id),''),COALESCE((SELECT m.preferred_method FROM user_mfa m WHERE m.user_id=u.id),''),u.created_at,u.updated_at FROM users u WHERE u.username = ?`, username).Scan(
		&credential.ID, &credential.Username, &credential.DisplayName, &credential.Email, &credential.PasswordHash, &credential.Role, &enabled, &mfaEnabled, &passwordChangeRequired, &credential.MFASecretCiphertext, &credential.MFAPreferredMethod, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return UserCredential{}, ErrNotFound
	}
	if err != nil {
		return UserCredential{}, err
	}
	credential.Enabled = enabled == 1
	credential.MFAEnabled = mfaEnabled == 1
	credential.PasswordChangeRequired = passwordChangeRequired == 1
	credential.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return UserCredential{}, err
	}
	credential.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return UserCredential{}, err
	}
	credential.ProjectIDs, err = s.userProjects(ctx, credential.ID)
	if err != nil {
		return UserCredential{}, err
	}
	return credential, nil
}

func (s *Store) CreateAuthSession(ctx context.Context, userID, tokenHash, csrfHash string, expiresAt time.Time) (AuthSession, error) {
	sessionID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	now := time.Now().UTC()
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,token_hash,csrf_hash,status,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?)`,
		sessionID, userID, tokenHash, csrfHash, "active", expiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return AuthSession{}, err
	}
	credential, err := s.userByID(ctx, userID)
	if err != nil {
		return AuthSession{}, err
	}
	return AuthSession{ID: sessionID, User: credential, ExpiresAt: expiresAt.UTC(), LastSeenAt: now, CSRFHash: csrfHash}, nil
}

func (s *Store) ResolveAuthSession(ctx context.Context, tokenHash string) (AuthSession, error) {
	var session AuthSession
	var enabled, mfaEnabled, passwordChangeRequired int
	var expiresAt, lastSeenAt, createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
SELECT s.id,s.expires_at,s.last_seen_at,s.csrf_hash,u.id,u.username,u.display_name,u.email,u.role,u.enabled,EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=u.id),u.password_change_required,u.created_at,u.updated_at
FROM auth_sessions s JOIN users u ON u.id=s.user_id
WHERE s.token_hash = ? AND s.status = 'active' AND s.expires_at > ?`, tokenHash, time.Now().UTC().Format(time.RFC3339Nano)).Scan(
		&session.ID, &expiresAt, &lastSeenAt, &session.CSRFHash, &session.User.ID, &session.User.Username, &session.User.DisplayName, &session.User.Email, &session.User.Role, &enabled, &mfaEnabled, &passwordChangeRequired, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrNotFound
	}
	if err != nil {
		return AuthSession{}, err
	}
	if enabled != 1 {
		return AuthSession{}, ErrNotFound
	}
	session.User.Enabled = true
	session.User.MFAEnabled = mfaEnabled == 1
	session.User.PasswordChangeRequired = passwordChangeRequired == 1
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return AuthSession{}, err
	}
	session.LastSeenAt, err = time.Parse(time.RFC3339Nano, lastSeenAt)
	if err != nil {
		return AuthSession{}, err
	}
	session.User.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	session.User.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	session.User.ProjectIDs, err = s.userProjects(ctx, session.User.ID)
	if err != nil {
		return AuthSession{}, err
	}
	return session, nil
}

func (s *Store) TouchAuthSession(ctx context.Context, sessionID string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at = ? WHERE id = ? AND status = 'active'`, now.UTC().Format(time.RFC3339Nano), sessionID)
	return err
}

func (s *Store) RevokeAuthSession(ctx context.Context, tokenHash string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET status = 'revoked' WHERE token_hash = ? AND status = 'active'`, tokenHash)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) ChangePassword(ctx context.Context, input ChangePasswordInput) (AuthSession, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthSession{}, err
	}
	defer tx.Rollback()
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT enabled FROM users WHERE id=?`, input.UserID).Scan(&enabled); errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrNotFound
	} else if err != nil {
		return AuthSession{}, err
	}
	if enabled != 1 || input.PasswordHash == "" {
		return AuthSession{}, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,password_change_required=0,updated_at=? WHERE id=?`, input.PasswordHash, now.Format(time.RFC3339Nano), input.UserID); err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked' WHERE user_id=? AND status='active'`, input.UserID); err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET status='revoked' WHERE user_id=? AND status='active'`, input.UserID); err != nil {
		return AuthSession{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,token_hash,csrf_hash,status,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,'active',?,?,?)`, sessionID, input.UserID, input.TokenHash, input.CSRFHash, input.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return AuthSession{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	input.Audit.ResourceID = input.UserID
	if err := insertAudit(ctx, tx, auditID, input.Audit, now); err != nil {
		return AuthSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthSession{}, err
	}
	user, err := s.userByID(ctx, input.UserID)
	if err != nil {
		return AuthSession{}, err
	}
	return AuthSession{ID: sessionID, User: user, ExpiresAt: input.ExpiresAt.UTC(), LastSeenAt: now, CSRFHash: input.CSRFHash}, nil
}

func (s *Store) CleanupAuthSessions(ctx context.Context, now time.Time) (int64, error) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE expires_at <= ? OR status <> 'active'`, now.UTC().Format(time.RFC3339Nano))
	result, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at <= ? OR (status = 'revoked' AND last_seen_at <= ?)`,
		now.UTC().Format(time.RFC3339Nano), now.Add(-24*time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) userByID(ctx context.Context, userID string) (User, error) {
	var user User
	var enabled, mfaEnabled, passwordChangeRequired int
	var createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `SELECT id,username,display_name,email,role,enabled,EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=users.id),password_change_required,created_at,updated_at FROM users WHERE id = ?`, userID).Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.Role, &enabled, &mfaEnabled, &passwordChangeRequired, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	user.Enabled = enabled == 1
	user.MFAEnabled = mfaEnabled == 1
	user.PasswordChangeRequired = passwordChangeRequired == 1
	user.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	user.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	user.ProjectIDs, err = s.userProjects(ctx, userID)
	return user, err
}

func (s *Store) userProjects(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT project_id FROM project_memberships WHERE user_id = ?
UNION
SELECT pp.project_id FROM policy_projects pp JOIN policy_users pu ON pu.policy_id=pp.policy_id JOIN access_policies p ON p.id=pp.policy_id WHERE pu.user_id = ? AND p.enabled=1
ORDER BY project_id`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var projectID string
		if err := rows.Scan(&projectID); err != nil {
			return nil, err
		}
		result = append(result, projectID)
	}
	return result, rows.Err()
}

func scanUser(scanner rowScanner) (User, error) {
	var user User
	var enabled, mfaEnabled, passwordChangeRequired int
	var createdAt, updatedAt string
	if err := scanner.Scan(&user.ID, &user.Username, &user.DisplayName, &user.Email, &user.Role, &enabled, &mfaEnabled, &passwordChangeRequired, &createdAt, &updatedAt); err != nil {
		return User{}, err
	}
	user.Enabled = enabled == 1
	user.MFAEnabled = mfaEnabled == 1
	user.PasswordChangeRequired = passwordChangeRequired == 1
	var err error
	user.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return User{}, err
	}
	user.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return user, err
}
