package store

import (
	"context"
	"fmt"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

var DefaultProjectScanPorts = []DiscoveryPort{
	{Name: "Web 服务", Protocol: "http", Port: 80},
	{Name: "Web 服务（HTTPS）", Protocol: "https", Port: 443},
	{Name: "AdGuard Home", Protocol: "http", Port: 3000},
	{Name: "SmartDNS", Protocol: "http", Port: 3001},
	{Name: "SSH", Protocol: "ssh", Port: 22},
}

func (s *Store) ProjectScanPorts(ctx context.Context, projectID string) ([]DiscoveryPort, error) {
	if _, err := s.ProjectByID(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name,protocol,port FROM project_scan_ports WHERE project_id=? ORDER BY position`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ports := []DiscoveryPort{}
	for rows.Next() {
		var port DiscoveryPort
		if err := rows.Scan(&port.Name, &port.Protocol, &port.Port); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, rows.Err()
}

func (s *Store) ReplaceProjectScanPorts(ctx context.Context, projectID string, ports []DiscoveryPort, audit AuditInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM project_scan_ports WHERE project_id=?`, projectID)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id=?`, projectID).Scan(&exists); err != nil || exists != 1 {
			return ErrNotFound
		}
	}
	for position, port := range ports {
		if _, err := tx.ExecContext(ctx, `INSERT INTO project_scan_ports(project_id,position,name,protocol,port) VALUES(?,?,?,?,?)`, projectID, position, port.Name, port.Protocol, port.Port); err != nil {
			return fmt.Errorf("insert project scan port: %w", err)
		}
	}
	auditID, err := id.New()
	if err != nil {
		return err
	}
	audit.ResourceID = projectID
	if err := insertAudit(ctx, tx, auditID, audit, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}
