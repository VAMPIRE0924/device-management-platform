package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) CreateMFAChallenge(ctx context.Context, userID, tokenHash, purpose, encryptedSecret, sourceIP string, expiresAt time.Time) (MFAChallenge, error) {
	challengeID, err := id.New()
	if err != nil {
		return MFAChallenge{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MFAChallenge{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return MFAChallenge{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mfa_challenges(id,user_id,token_hash,purpose,secret_ciphertext,source_ip,status,attempts,expires_at,created_at) VALUES(?,?,?,?,?,?,'active',0,?,?)`, challengeID, userID, tokenHash, purpose, encryptedSecret, sourceIP, expiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return MFAChallenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return MFAChallenge{}, err
	}
	return s.MFAChallengeByToken(ctx, tokenHash)
}

func (s *Store) SetOnboardingPassword(ctx context.Context, challengeID, passwordHash string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET new_password_hash=? WHERE id=? AND purpose='onboard' AND status='active' AND expires_at>? AND attempts<5`, passwordHash, challengeID, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrMFAChallenge
	}
	return nil
}

func (s *Store) CompletePasswordChange(ctx context.Context, input CompleteMFAInput) (AuthSession, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthSession{}, err
	}
	defer tx.Rollback()
	var userID, purpose string
	var enabled int
	if err := tx.QueryRowContext(ctx, `SELECT c.user_id,c.purpose,u.enabled FROM mfa_challenges c JOIN users u ON u.id=c.user_id WHERE c.id=? AND c.status='active' AND c.expires_at>?`, input.ChallengeID, now.Format(time.RFC3339Nano)).Scan(&userID, &purpose, &enabled); errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrMFAChallenge
	} else if err != nil {
		return AuthSession{}, err
	}
	if purpose != "password" || input.PasswordHash == "" || enabled != 1 {
		return AuthSession{}, ErrMFAChallenge
	}
	if result, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET status='consumed' WHERE id=? AND status='active'`, input.ChallengeID); err != nil {
		return AuthSession{}, err
	} else if count, _ := result.RowsAffected(); count != 1 {
		return AuthSession{}, ErrMFAChallenge
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,password_change_required=0,updated_at=? WHERE id=?`, input.PasswordHash, now.Format(time.RFC3339Nano), userID); err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return AuthSession{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,token_hash,csrf_hash,status,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,'active',?,?,?)`, sessionID, userID, input.TokenHash, input.CSRFHash, input.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return AuthSession{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	input.Audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, input.Audit, now); err != nil {
		return AuthSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthSession{}, err
	}
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return AuthSession{}, err
	}
	return AuthSession{ID: sessionID, User: user, ExpiresAt: input.ExpiresAt.UTC(), CSRFHash: input.CSRFHash}, nil
}

func (s *Store) SetOnboardingEmailDelivery(ctx context.Context, challengeID, email, emailCodeHash string, expiresAt time.Time) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET email=?,email_code_hash=?,email_verified=0,email_sent_at=?,expires_at=? WHERE id=? AND purpose='onboard' AND status='active' AND new_password_hash<>'' AND attempts<5 AND (email_sent_at IS NULL OR email_sent_at<=?)`, email, emailCodeHash, now.Format(time.RFC3339Nano), expiresAt.UTC().Format(time.RFC3339Nano), challengeID, now.Add(-60*time.Second).Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrMFACooldown
	}
	return nil
}

func (s *Store) VerifyOnboardingEmail(ctx context.Context, challengeID, emailCodeHash string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET email_verified=1,email_code_hash='' WHERE id=? AND purpose='onboard' AND status='active' AND email_code_hash=? AND email<>''`, challengeID, emailCodeHash)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrMFAChallenge
	}
	return nil
}

func (s *Store) SetMFAChallengeMethod(ctx context.Context, challengeID, method, encryptedSecret, emailCodeHash string, expiresAt time.Time) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET method=?,secret_ciphertext=?,email_code_hash=?,email_sent_at=CASE WHEN ?<>'' THEN ? ELSE email_sent_at END,expires_at=? WHERE id=? AND status='active' AND attempts<5 AND (?='' OR email_code_hash='' OR email_sent_at IS NULL OR email_sent_at<=?)`, method, encryptedSecret, emailCodeHash, emailCodeHash, now.Format(time.RFC3339Nano), expiresAt.UTC().Format(time.RFC3339Nano), challengeID, emailCodeHash, now.Add(-60*time.Second).Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		if emailCodeHash != "" {
			return ErrMFACooldown
		}
		return ErrMFAChallenge
	}
	return nil
}

func (s *Store) ClearMFAEmailDelivery(ctx context.Context, challengeID, emailCodeHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET email_code_hash='',email_sent_at=NULL WHERE id=? AND status='active' AND email_code_hash=?`, challengeID, emailCodeHash)
	return err
}

func (s *Store) MFAChallengeByToken(ctx context.Context, tokenHash string) (MFAChallenge, error) {
	var challenge MFAChallenge
	var enabled, mfaEnabled, emailVerified, passwordChangeRequired int
	var expiresAt, createdAt, updatedAt string
	err := s.db.QueryRowContext(ctx, `
SELECT c.id,c.purpose,c.method,c.secret_ciphertext,c.email,c.email_code_hash,c.email_verified,c.new_password_hash,c.attempts,c.expires_at,
       u.id,u.username,u.display_name,u.email,u.role,u.enabled,u.password_change_required,
       EXISTS(SELECT 1 FROM user_mfa m WHERE m.user_id=u.id),
       COALESCE((SELECT m.secret_ciphertext FROM user_mfa m WHERE m.user_id=u.id),''),
       COALESCE((SELECT m.preferred_method FROM user_mfa m WHERE m.user_id=u.id),''),
       u.created_at,u.updated_at
FROM mfa_challenges c JOIN users u ON u.id=c.user_id
WHERE c.token_hash=? AND c.status='active' AND c.expires_at>?`, tokenHash, time.Now().UTC().Format(time.RFC3339Nano)).Scan(
		&challenge.ID, &challenge.Purpose, &challenge.Method, &challenge.SecretCiphertext, &challenge.Email, &challenge.EmailCodeHash, &emailVerified, &challenge.NewPasswordHash, &challenge.Attempts, &expiresAt,
		&challenge.User.ID, &challenge.User.Username, &challenge.User.DisplayName, &challenge.User.Email, &challenge.User.Role, &enabled, &passwordChangeRequired,
		&mfaEnabled, &challenge.MFASecretCiphertext, &challenge.MFAPreferredMethod, &createdAt, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return MFAChallenge{}, ErrMFAChallenge
	}
	if err != nil {
		return MFAChallenge{}, err
	}
	if enabled != 1 || challenge.Attempts >= 5 {
		return MFAChallenge{}, ErrMFAChallenge
	}
	challenge.User.Enabled = true
	challenge.User.MFAEnabled = mfaEnabled == 1
	challenge.User.PasswordChangeRequired = passwordChangeRequired == 1
	challenge.EmailVerified = emailVerified == 1
	challenge.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	challenge.User.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	challenge.User.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
	challenge.User.ProjectIDs, err = s.userProjects(ctx, challenge.User.ID)
	return challenge, err
}

func (s *Store) FailMFAChallenge(ctx context.Context, challengeID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET attempts=attempts+1,status=CASE WHEN attempts+1>=5 THEN 'revoked' ELSE status END WHERE id=? AND status='active'`, challengeID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return ErrMFAChallenge
	}
	return nil
}

func (s *Store) CompleteMFAEnrollment(ctx context.Context, input CompleteMFAInput) (AuthSession, error) {
	return s.completeMFA(ctx, input, true)
}

func (s *Store) CompleteMFAAuthentication(ctx context.Context, input CompleteMFAInput) (AuthSession, error) {
	return s.completeMFA(ctx, input, false)
}

func (s *Store) completeMFA(ctx context.Context, input CompleteMFAInput, onboarding bool) (AuthSession, error) {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthSession{}, err
	}
	defer tx.Rollback()
	var userID, purpose, encryptedSecret, pendingEmail, newPasswordHash string
	var enabled, emailVerified int
	if err := tx.QueryRowContext(ctx, `SELECT c.user_id,c.purpose,c.secret_ciphertext,c.email,c.email_verified,c.new_password_hash,u.enabled FROM mfa_challenges c JOIN users u ON u.id=c.user_id WHERE c.id=? AND c.status='active' AND c.expires_at>?`, input.ChallengeID, now.Format(time.RFC3339Nano)).Scan(&userID, &purpose, &encryptedSecret, &pendingEmail, &emailVerified, &newPasswordHash, &enabled); errors.Is(err, sql.ErrNoRows) {
		return AuthSession{}, ErrMFAChallenge
	} else if err != nil {
		return AuthSession{}, err
	}
	if enabled != 1 || onboarding != (purpose == "onboard") {
		return AuthSession{}, ErrMFAChallenge
	}
	if result, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET status='consumed' WHERE id=? AND status='active'`, input.ChallengeID); err != nil {
		return AuthSession{}, err
	} else if count, _ := result.RowsAffected(); count != 1 {
		return AuthSession{}, ErrMFAChallenge
	}
	if onboarding {
		if (input.MethodBound != "totp" && input.MethodBound != "email") || len(input.Recovery) < 8 || emailVerified != 1 || pendingEmail == "" || newPasswordHash == "" {
			return AuthSession{}, ErrMFAChallenge
		}
		if input.MethodBound == "totp" && encryptedSecret == "" {
			return AuthSession{}, ErrMFAChallenge
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=?,email=?,password_change_required=0,updated_at=? WHERE id=?`, newPasswordHash, pendingEmail, now.Format(time.RFC3339Nano), userID); err != nil {
			return AuthSession{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_mfa(user_id,secret_ciphertext,preferred_method,last_totp_counter,enabled_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET secret_ciphertext=excluded.secret_ciphertext,preferred_method=excluded.preferred_method,last_totp_counter=excluded.last_totp_counter,enabled_at=excluded.enabled_at,updated_at=excluded.updated_at`, userID, encryptedSecret, input.MethodBound, input.Counter, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			return AuthSession{}, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
			return AuthSession{}, err
		}
		for _, codeHash := range input.Recovery {
			codeID, err := id.New()
			if err != nil {
				return AuthSession{}, err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mfa_recovery_codes(id,user_id,code_hash,created_at) VALUES(?,?,?,?)`, codeID, userID, codeHash, now.Format(time.RFC3339Nano)); err != nil {
				return AuthSession{}, err
			}
		}
	} else if input.Method == "totp" {
		result, err := tx.ExecContext(ctx, `UPDATE user_mfa SET last_totp_counter=?,updated_at=? WHERE user_id=? AND last_totp_counter<?`, input.Counter, now.Format(time.RFC3339Nano), userID, input.Counter)
		if err != nil {
			return AuthSession{}, err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return AuthSession{}, ErrMFAReplay
		}
	} else if input.Method == "recovery" {
		result, err := tx.ExecContext(ctx, `UPDATE mfa_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`, now.Format(time.RFC3339Nano), userID, input.CodeHash)
		if err != nil {
			return AuthSession{}, err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return AuthSession{}, ErrMFAChallenge
		}
	} else if input.Method != "email" {
		return AuthSession{}, ErrMFAChallenge
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return AuthSession{}, err
	}
	sessionID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,token_hash,csrf_hash,status,expires_at,created_at,last_seen_at) VALUES(?,?,?,?,'active',?,?,?)`, sessionID, userID, input.TokenHash, input.CSRFHash, input.ExpiresAt.UTC().Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return AuthSession{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return AuthSession{}, err
	}
	input.Audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, input.Audit, now); err != nil {
		return AuthSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuthSession{}, err
	}
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return AuthSession{}, err
	}
	return AuthSession{ID: sessionID, User: user, ExpiresAt: input.ExpiresAt.UTC(), CSRFHash: input.CSRFHash}, nil
}

func (s *Store) RecoveryCodeCount(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=? AND used_at IS NULL`, userID).Scan(&count)
	return count, err
}

func (s *Store) ResetUserMFA(ctx context.Context, userID string, audit AuditInput) error {
	return s.resetUserMFA(ctx, `id=?`, userID, audit)
}

func (s *Store) ResetUserMFAByUsername(ctx context.Context, username string, audit AuditInput) error {
	return s.resetUserMFA(ctx, `username=?`, username, audit)
}

func (s *Store) resetUserMFA(ctx context.Context, predicate, value string, audit AuditInput) error {
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE `+predicate, value).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_mfa WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_change_required=1 WHERE id=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mfa_challenges SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET status='revoked' WHERE user_id=? AND status='active'`, userID); err != nil {
		return err
	}
	auditID, err := id.New()
	if err != nil {
		return err
	}
	audit.ResourceID = userID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}
