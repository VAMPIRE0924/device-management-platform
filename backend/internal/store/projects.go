package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) ListProjects(ctx context.Context) ([]Project, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,code,name,node_id,owner_name,client_id,created_at,updated_at FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	projects := []Project{}
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		projects = append(projects, project)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	// The V1 SQLite store deliberately uses one connection. Finish consuming and
	// closing the project cursor before loading child rows to avoid pool deadlock.
	for index := range projects {
		projects[index].Networks, err = s.projectNetworks(ctx, projects[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return projects, nil
}

func (s *Store) ProjectByID(ctx context.Context, projectID string) (Project, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,code,name,node_id,owner_name,client_id,created_at,updated_at FROM projects WHERE id = ?`, projectID)
	project, err := scanProject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}
	project.Networks, err = s.projectNetworks(ctx, project.ID)
	return project, err
}

func (s *Store) CreateProject(ctx context.Context, code string, input CreateProjectInput, audit AuditInput) (Project, error) {
	projectID, err := id.New()
	if err != nil {
		return Project{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return Project{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO projects(id,code,name,node_id,owner_name,client_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		projectID, code, input.Name, input.NodeID, input.OwnerName, input.ClientID, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Project{}, fmt.Errorf("insert project: %w", err)
	}
	for _, cidr := range input.Networks {
		networkID, err := id.New()
		if err != nil {
			return Project{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_networks(id,project_id,cidr,created_at) VALUES(?,?,?,?)`, networkID, projectID, cidr, now.Format(time.RFC3339Nano)); err != nil {
			return Project{}, fmt.Errorf("insert project network: %w", err)
		}
	}
	for position, port := range DefaultProjectScanPorts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_scan_ports(project_id,position,name,protocol,port) VALUES(?,?,?,?,?)`, projectID, position, port.Name, port.Protocol, port.Port); err != nil {
			return Project{}, fmt.Errorf("insert default project scan port: %w", err)
		}
	}
	audit.ResourceID = projectID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Project{}, err
	}
	if err := tx.Commit(); err != nil {
		return Project{}, err
	}
	return Project{ID: projectID, Code: code, Name: input.Name, NodeID: input.NodeID, OwnerName: input.OwnerName, ClientID: input.ClientID, Networks: input.Networks, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) projectNetworks(ctx context.Context, projectID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cidr FROM project_networks WHERE project_id = ? ORDER BY cidr`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, err
		}
		result = append(result, cidr)
	}
	return result, rows.Err()
}

func (s *Store) UpdateProject(ctx context.Context, projectID string, input UpdateProjectInput, audit AuditInput) (Project, error) {
	auditID, err := id.New()
	if err != nil {
		return Project{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Project{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE projects SET name = ?,owner_name = ?,updated_at = ? WHERE id = ?`,
		input.Name, input.OwnerName, now.Format(time.RFC3339Nano), projectID)
	if err != nil {
		return Project{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return Project{}, ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM project_networks WHERE project_id = ?`, projectID); err != nil {
		return Project{}, err
	}
	for _, cidr := range input.Networks {
		networkID, err := id.New()
		if err != nil {
			return Project{}, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_networks(id,project_id,cidr,created_at) VALUES(?,?,?,?)`, networkID, projectID, cidr, now.Format(time.RFC3339Nano)); err != nil {
			return Project{}, err
		}
	}
	audit.ResourceID = projectID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Project{}, err
	}
	if err := tx.Commit(); err != nil {
		return Project{}, err
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		return Project{}, err
	}
	for _, project := range projects {
		if project.ID == projectID {
			return project, nil
		}
	}
	return Project{}, ErrNotFound
}

func (s *Store) DeleteProject(ctx context.Context, projectID string, audit AuditInput) error {
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
	var dependencies int
	if err := tx.QueryRowContext(ctx, `
SELECT
  (SELECT COUNT(*) FROM port_forwards pf JOIN endpoints e ON e.id=pf.endpoint_id JOIN devices d ON d.id=e.device_id WHERE d.project_id=?) +
  (SELECT COUNT(*) FROM access_sessions WHERE project_id=? AND status='active' AND expires_at>?) +
  (SELECT COUNT(*) FROM discovery_jobs WHERE project_id=? AND status IN ('queued','running'))`,
		projectID, projectID, now.Format(time.RFC3339Nano), projectID).Scan(&dependencies); err != nil {
		return err
	}
	if dependencies > 0 {
		return ErrInUse
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, projectID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = projectID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func scanProject(scanner rowScanner) (Project, error) {
	var project Project
	var clientID sql.NullInt64
	var createdAt, updatedAt string
	if err := scanner.Scan(&project.ID, &project.Code, &project.Name, &project.NodeID, &project.OwnerName, &clientID, &createdAt, &updatedAt); err != nil {
		return Project{}, err
	}
	if clientID.Valid {
		value := int(clientID.Int64)
		project.ClientID = &value
	}
	var err error
	project.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Project{}, err
	}
	project.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Project{}, err
	}
	return project, nil
}
