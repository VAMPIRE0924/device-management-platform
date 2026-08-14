package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"i5cloud/internal/id"
)

func (s *Store) ListPortForwards(ctx context.Context, projectID string) ([]PortForward, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT f.id,p.id,f.endpoint_id,e.name,d.name,p.node_id,p.client_id,d.host,e.target_port,f.server_port,f.node_task_id,f.status,f.expires_at,f.created_at,f.updated_at
FROM port_forwards f
JOIN endpoints e ON e.id = f.endpoint_id
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = d.project_id
WHERE p.id = ?
ORDER BY f.created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PortForward{}
	for rows.Next() {
		item, err := scanPortForward(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) ReservePortForward(ctx context.Context, input ReservePortForwardInput, audit AuditInput) (PortForward, error) {
	route, err := s.EndpointRoute(ctx, input.EndpointID)
	if err != nil {
		return PortForward{}, err
	}
	if route.ProjectID != input.ProjectID {
		return PortForward{}, ErrNotFound
	}
	if route.Protocol == "http" || route.Protocol == "https" {
		return PortForward{}, fmt.Errorf("web endpoints cannot create port forwards")
	}
	if route.ClientID < 1 {
		return PortForward{}, fmt.Errorf("project has no bound client")
	}
	var portStart, portEnd int
	if err := s.db.QueryRowContext(ctx, `SELECT port_start,port_end FROM nodes WHERE id = ? AND enabled = 1`, route.NodeID).Scan(&portStart, &portEnd); errors.Is(err, sql.ErrNoRows) {
		return PortForward{}, ErrNotFound
	} else if err != nil {
		return PortForward{}, err
	}
	forwardID, err := id.New()
	if err != nil {
		return PortForward{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return PortForward{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PortForward{}, err
	}
	defer tx.Rollback()
	serverPort := input.ServerPort
	if serverPort == 0 {
		serverPort, err = firstAvailablePort(ctx, tx, route.NodeID, portStart, portEnd)
		if err != nil {
			return PortForward{}, err
		}
	} else if serverPort < portStart || serverPort > portEnd {
		return PortForward{}, fmt.Errorf("server port is outside node port pool")
	}
	var expiresAt any
	if input.ExpiresAt != nil {
		expiresAt = input.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO port_forwards(id,endpoint_id,node_id,server_port,status,expires_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		forwardID, route.EndpointID, route.NodeID, serverPort, "provisioning", expiresAt, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return PortForward{}, fmt.Errorf("reserve port forward: %w", err)
	}
	audit.ResourceID = forwardID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return PortForward{}, err
	}
	if err := tx.Commit(); err != nil {
		return PortForward{}, err
	}
	return PortForward{ID: forwardID, ProjectID: route.ProjectID, EndpointID: route.EndpointID, EndpointName: route.EndpointName, DeviceName: route.DeviceName, NodeID: route.NodeID, ClientID: route.ClientID, Target: net.JoinHostPort(route.Host, strconv.Itoa(route.TargetPort)), ServerPort: serverPort, Status: "provisioning", ExpiresAt: input.ExpiresAt, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) ActivatePortForward(ctx context.Context, forwardID string, nodeTaskID int) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `UPDATE port_forwards SET node_task_id = ?, status = 'running', updated_at = ? WHERE id = ? AND status = 'provisioning'`, nodeTaskID, now, forwardID)
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
	return nil
}

func (s *Store) PortForwardByID(ctx context.Context, forwardID string) (PortForward, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT f.id,p.id,f.endpoint_id,e.name,d.name,p.node_id,p.client_id,d.host,e.target_port,f.server_port,f.node_task_id,f.status,f.expires_at,f.created_at,f.updated_at
FROM port_forwards f
JOIN endpoints e ON e.id = f.endpoint_id
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = d.project_id
WHERE f.id = ?`, forwardID)
	item, err := scanPortForward(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PortForward{}, ErrNotFound
	}
	return item, err
}

func (s *Store) ListExpiredPortForwards(ctx context.Context, now time.Time) ([]PortForward, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT f.id,p.id,f.endpoint_id,e.name,d.name,p.node_id,p.client_id,d.host,e.target_port,f.server_port,f.node_task_id,f.status,f.expires_at,f.created_at,f.updated_at
FROM port_forwards f
JOIN endpoints e ON e.id = f.endpoint_id
JOIN devices d ON d.id = e.device_id
JOIN projects p ON p.id = d.project_id
WHERE f.expires_at IS NOT NULL AND f.expires_at <= ? AND f.status IN ('provisioning','running','stopped','cleanup_failed')
ORDER BY f.expires_at ASC`, now.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PortForward{}
	for rows.Next() {
		item, scanErr := scanPortForward(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) SetPortForwardStatus(ctx context.Context, forwardID, status string, audit AuditInput) error {
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
	result, err := tx.ExecContext(ctx, `UPDATE port_forwards SET status = ?, updated_at = ? WHERE id = ?`, status, now.Format(time.RFC3339Nano), forwardID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = forwardID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeletePortForward(ctx context.Context, forwardID string, audit AuditInput) error {
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
	result, err := tx.ExecContext(ctx, `DELETE FROM port_forwards WHERE id = ?`, forwardID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = forwardID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func firstAvailablePort(ctx context.Context, tx *sql.Tx, nodeID string, start, end int) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT server_port FROM port_forwards WHERE node_id = ?`, nodeID)
	if err != nil {
		return 0, err
	}
	used := map[int]struct{}{}
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			rows.Close()
			return 0, err
		}
		used[port] = struct{}{}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	for port := start; port <= end; port++ {
		if _, exists := used[port]; !exists {
			return port, nil
		}
	}
	return 0, fmt.Errorf("node port pool is exhausted")
}

func scanPortForward(scanner rowScanner) (PortForward, error) {
	var item PortForward
	var clientID sql.NullInt64
	var nodeTaskID sql.NullInt64
	var expiresAt sql.NullString
	var host string
	var targetPort int
	var createdAt, updatedAt string
	if err := scanner.Scan(&item.ID, &item.ProjectID, &item.EndpointID, &item.EndpointName, &item.DeviceName, &item.NodeID, &clientID, &host, &targetPort, &item.ServerPort, &nodeTaskID, &item.Status, &expiresAt, &createdAt, &updatedAt); err != nil {
		return PortForward{}, err
	}
	if clientID.Valid {
		item.ClientID = int(clientID.Int64)
	}
	if nodeTaskID.Valid {
		value := int(nodeTaskID.Int64)
		item.NodeTaskID = &value
	}
	item.Target = net.JoinHostPort(host, strconv.Itoa(targetPort))
	var err error
	item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return PortForward{}, err
	}
	item.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return PortForward{}, err
	}
	if expiresAt.Valid {
		value, err := time.Parse(time.RFC3339Nano, expiresAt.String)
		if err != nil {
			return PortForward{}, err
		}
		item.ExpiresAt = &value
	}
	return item, nil
}
