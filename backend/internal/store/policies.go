package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"i5cloud/internal/id"
)

type policySchedule struct {
	ValidFrom  *time.Time `json:"validFrom"`
	ValidUntil *time.Time `json:"validUntil"`
}

func (s *Store) ListAccessPolicies(ctx context.Context) ([]AccessPolicy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,capabilities_json,schedule_json,enabled,created_at,updated_at FROM access_policies ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	result := []AccessPolicy{}
	for rows.Next() {
		policy, err := scanAccessPolicy(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, policy)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range result {
		result[index].ProjectIDs, err = s.policyRelationIDs(ctx, "policy_projects", "project_id", result[index].ID)
		if err != nil {
			return nil, err
		}
		result[index].UserIDs, err = s.policyRelationIDs(ctx, "policy_users", "user_id", result[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Store) CreateAccessPolicy(ctx context.Context, input SaveAccessPolicyInput, audit AuditInput) (AccessPolicy, error) {
	policyID, err := id.New()
	if err != nil {
		return AccessPolicy{}, err
	}
	return s.saveAccessPolicy(ctx, policyID, input, audit, true)
}

func (s *Store) UpdateAccessPolicy(ctx context.Context, policyID string, input SaveAccessPolicyInput, audit AuditInput) (AccessPolicy, error) {
	return s.saveAccessPolicy(ctx, policyID, input, audit, false)
}

func (s *Store) saveAccessPolicy(ctx context.Context, policyID string, input SaveAccessPolicyInput, audit AuditInput, create bool) (AccessPolicy, error) {
	auditID, err := id.New()
	if err != nil {
		return AccessPolicy{}, err
	}
	capabilitiesJSON, _ := json.Marshal(input.Capabilities)
	scheduleJSON, _ := json.Marshal(policySchedule{ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil})
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccessPolicy{}, err
	}
	defer tx.Rollback()
	enabled := 0
	if input.Enabled {
		enabled = 1
	}
	if create {
		_, err = tx.ExecContext(ctx, `INSERT INTO access_policies(id,name,scope_json,capabilities_json,schedule_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, policyID, input.Name, `{}`, string(capabilitiesJSON), string(scheduleJSON), enabled, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	} else {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE access_policies SET name = ?,capabilities_json = ?,schedule_json = ?,enabled = ?,updated_at = ? WHERE id = ?`, input.Name, string(capabilitiesJSON), string(scheduleJSON), enabled, now.Format(time.RFC3339Nano), policyID)
		if err == nil {
			count, _ := result.RowsAffected()
			if count != 1 {
				return AccessPolicy{}, ErrNotFound
			}
		}
	}
	if err != nil {
		return AccessPolicy{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_projects WHERE policy_id = ?`, policyID); err != nil {
		return AccessPolicy{}, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM policy_users WHERE policy_id = ?`, policyID); err != nil {
		return AccessPolicy{}, err
	}
	for _, projectID := range input.ProjectIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_projects(policy_id,project_id) VALUES(?,?)`, policyID, projectID); err != nil {
			return AccessPolicy{}, err
		}
	}
	for _, userID := range input.UserIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_users(policy_id,user_id) VALUES(?,?)`, policyID, userID); err != nil {
			return AccessPolicy{}, err
		}
	}
	audit.ResourceID = policyID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return AccessPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return AccessPolicy{}, err
	}
	createdAt := now
	if !create {
		var value string
		if err := s.db.QueryRowContext(ctx, `SELECT created_at FROM access_policies WHERE id = ?`, policyID).Scan(&value); err == nil {
			createdAt, _ = time.Parse(time.RFC3339Nano, value)
		}
	}
	return AccessPolicy{ID: policyID, Name: input.Name, ProjectIDs: input.ProjectIDs, UserIDs: input.UserIDs, Capabilities: input.Capabilities, ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil, Enabled: input.Enabled, CreatedAt: createdAt, UpdatedAt: now}, nil
}

func (s *Store) DeleteAccessPolicy(ctx context.Context, policyID string, audit AuditInput) error {
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
	result, err := tx.ExecContext(ctx, `DELETE FROM access_policies WHERE id = ?`, policyID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = policyID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) HasPolicyCapability(ctx context.Context, userID, projectID, capability string, at time.Time) (bool, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT p.capabilities_json,p.schedule_json
FROM access_policies p
JOIN policy_users u ON u.policy_id=p.id
JOIN policy_projects pr ON pr.policy_id=p.id
WHERE p.enabled=1 AND u.user_id=? AND pr.project_id=?`, userID, projectID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var capabilitiesJSON, scheduleJSON string
		if err := rows.Scan(&capabilitiesJSON, &scheduleJSON); err != nil {
			return false, err
		}
		var capabilities []string
		var schedule policySchedule
		if json.Unmarshal([]byte(capabilitiesJSON), &capabilities) != nil || json.Unmarshal([]byte(scheduleJSON), &schedule) != nil {
			continue
		}
		if schedule.ValidFrom != nil && at.Before(*schedule.ValidFrom) || schedule.ValidUntil != nil && !at.Before(*schedule.ValidUntil) {
			continue
		}
		for _, allowed := range capabilities {
			if allowed == capability {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}

func scanAccessPolicy(scanner rowScanner) (AccessPolicy, error) {
	var policy AccessPolicy
	var capabilitiesJSON, scheduleJSON, createdAt, updatedAt string
	var enabled int
	if err := scanner.Scan(&policy.ID, &policy.Name, &capabilitiesJSON, &scheduleJSON, &enabled, &createdAt, &updatedAt); err != nil {
		return AccessPolicy{}, err
	}
	if err := json.Unmarshal([]byte(capabilitiesJSON), &policy.Capabilities); err != nil {
		return AccessPolicy{}, err
	}
	var schedule policySchedule
	if err := json.Unmarshal([]byte(scheduleJSON), &schedule); err != nil {
		return AccessPolicy{}, err
	}
	policy.ValidFrom, policy.ValidUntil = schedule.ValidFrom, schedule.ValidUntil
	policy.Enabled = enabled == 1
	var err error
	policy.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return AccessPolicy{}, err
	}
	policy.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	return policy, err
}

func (s *Store) policyRelationIDs(ctx context.Context, table, column, policyID string) ([]string, error) {
	if table != "policy_projects" && table != "policy_users" {
		return nil, errors.New("invalid policy relation")
	}
	query := `SELECT ` + column + ` FROM ` + table + ` WHERE policy_id = ? ORDER BY ` + column
	rows, err := s.db.QueryContext(ctx, query, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}
