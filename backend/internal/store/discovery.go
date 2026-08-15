package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) DiscoveryRoute(ctx context.Context, projectID string) (DiscoveryRoute, error) {
	var route DiscoveryRoute
	var clientID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,node_id,client_id FROM projects WHERE id = ?`, projectID).Scan(&route.ProjectID, &route.NodeID, &clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return DiscoveryRoute{}, ErrNotFound
	}
	if err != nil {
		return DiscoveryRoute{}, err
	}
	if clientID.Valid {
		route.ClientID = int(clientID.Int64)
	}
	route.Networks, err = s.projectNetworks(ctx, projectID)
	if err != nil {
		return DiscoveryRoute{}, err
	}
	return route, nil
}

func (s *Store) ImportDiscoveryDevice(ctx context.Context, jobID string, input CreateDeviceInput, audit AuditInput) (Device, error) {
	job, err := s.DiscoveryJob(ctx, jobID)
	if err != nil {
		return Device{}, err
	}
	if job.Status != "completed" {
		return Device{}, fmt.Errorf("discovery job is not completed")
	}
	var resultCount int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_results WHERE job_id = ? AND host = ?`, jobID, input.Host).Scan(&resultCount); err != nil {
		return Device{}, err
	}
	if resultCount == 0 {
		return Device{}, ErrNotFound
	}
	auditID, err := id.New()
	if err != nil {
		return Device{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	var deviceID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM devices WHERE project_id = ? AND host = ?`, job.ProjectID, input.Host).Scan(&deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		deviceID, err = id.New()
		if err != nil {
			return Device{}, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO devices(id,project_id,host,name,device_type,vendor,source,status,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
			deviceID, job.ProjectID, input.Host, input.Name, input.DeviceType, input.Vendor, "discovery", "online", now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	} else if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE devices SET name = ?,device_type = ?,vendor = ?,status = 'online',last_seen_at = ?,updated_at = ? WHERE id = ?`,
			input.Name, input.DeviceType, input.Vendor, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), deviceID)
	}
	if err != nil {
		return Device{}, err
	}
	for _, endpoint := range input.Endpoints {
		var discovered int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM discovery_results WHERE job_id = ? AND host = ? AND protocol = ? AND port = ?`, jobID, input.Host, endpoint.Protocol, endpoint.TargetPort).Scan(&discovered); err != nil {
			return Device{}, err
		}
		verification := "unverified"
		var verifiedAt any
		if discovered > 0 {
			verification = "verified"
			verifiedAt = now.Format(time.RFC3339Nano)
		}
		endpointID, err := id.New()
		if err != nil {
			return Device{}, err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO endpoints(id,device_id,name,protocol,target_port,access_type,verification_status,last_verified_at,tls_server_name,allow_insecure_tls,ssh_credential_ref,ssh_host_key_fingerprint,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(device_id,protocol,target_port) DO UPDATE SET
  name=excluded.name,
  verification_status=CASE WHEN excluded.verification_status='verified' THEN 'verified' ELSE endpoints.verification_status END,
  last_verified_at=COALESCE(excluded.last_verified_at,endpoints.last_verified_at),
  tls_server_name=excluded.tls_server_name,
  allow_insecure_tls=excluded.allow_insecure_tls,
  ssh_credential_ref=CASE WHEN excluded.ssh_credential_ref='' THEN endpoints.ssh_credential_ref ELSE excluded.ssh_credential_ref END,
  ssh_host_key_fingerprint=excluded.ssh_host_key_fingerprint,
  updated_at=excluded.updated_at`,
			endpointID, deviceID, endpoint.Name, endpoint.Protocol, endpoint.TargetPort, endpointAccessType(endpoint.Protocol), verification, verifiedAt, endpoint.TLSServerName, endpoint.AllowInsecureTLS, endpoint.CredentialRef, endpoint.SSHHostKeyFingerprint, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		if err != nil {
			return Device{}, err
		}
		if discovered > 0 {
			_, err = tx.ExecContext(ctx, `UPDATE discovery_results SET import_status = 'imported' WHERE job_id = ? AND host = ? AND protocol = ? AND port = ?`, jobID, input.Host, endpoint.Protocol, endpoint.TargetPort)
			if err != nil {
				return Device{}, err
			}
		}
	}
	audit.ResourceID = deviceID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	devices, err := s.ListDevices(ctx, job.ProjectID)
	if err != nil {
		return Device{}, err
	}
	for _, device := range devices {
		if device.ID == deviceID {
			return device, nil
		}
	}
	return Device{}, ErrNotFound
}

func (s *Store) CreateDiscoveryJob(ctx context.Context, projectID string, networks []string, ports []DiscoveryPort, audit AuditInput) (DiscoveryJob, error) {
	jobID, err := id.New()
	if err != nil {
		return DiscoveryJob{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return DiscoveryJob{}, err
	}
	networksJSON, err := json.Marshal(networks)
	if err != nil {
		return DiscoveryJob{}, err
	}
	portsJSON, err := json.Marshal(ports)
	if err != nil {
		return DiscoveryJob{}, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DiscoveryJob{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO discovery_jobs(id,project_id,networks_json,ports_json,status,progress,created_at) VALUES(?,?,?,?,?,?,?)`, jobID, projectID, string(networksJSON), string(portsJSON), "queued", 0, now.Format(time.RFC3339Nano))
	if err != nil {
		return DiscoveryJob{}, err
	}
	audit.ResourceID = jobID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return DiscoveryJob{}, err
	}
	if err := tx.Commit(); err != nil {
		return DiscoveryJob{}, err
	}
	return DiscoveryJob{ID: jobID, ProjectID: projectID, Networks: networks, Ports: ports, Status: "queued", CreatedAt: now}, nil
}

func (s *Store) SetDiscoveryJobState(ctx context.Context, jobID, status string, progress int) error {
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := `UPDATE discovery_jobs SET status = ?, progress = ? WHERE id = ?`
	args := []any{status, progress, jobID}
	switch status {
	case "running":
		query = `UPDATE discovery_jobs SET status = ?, progress = ?, started_at = COALESCE(started_at, ?) WHERE id = ? AND status IN ('queued','running')`
		args = []any{status, progress, now, jobID}
	case "completed", "failed", "canceled":
		query = `UPDATE discovery_jobs SET status = ?, progress = ?, finished_at = ? WHERE id = ? AND status IN ('queued','running')`
		args = []any{status, progress, now, jobID}
	}
	result, err := s.db.ExecContext(ctx, query, args...)
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

func (s *Store) SaveDiscoveryResult(ctx context.Context, jobID string, result DiscoveryProbeResult) error {
	resultID, err := id.New()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO discovery_results(id,job_id,host,port,protocol,service_name,fingerprint,response_summary,confidence,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(job_id,host,protocol,port) DO UPDATE SET
  service_name=excluded.service_name,
  fingerprint=excluded.fingerprint,
  response_summary=excluded.response_summary,
  confidence=excluded.confidence`,
		resultID, jobID, result.Host, result.Port, result.Protocol, result.ServiceName, result.Fingerprint, result.ResponseSummary, result.Confidence, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) DiscoveryJob(ctx context.Context, jobID string) (DiscoveryJob, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,project_id,networks_json,ports_json,status,progress,created_at,started_at,finished_at FROM discovery_jobs WHERE id = ?`, jobID)
	job, err := scanDiscoveryJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return DiscoveryJob{}, ErrNotFound
	}
	return job, err
}

func (s *Store) ListDiscoveryJobs(ctx context.Context, projectID string) ([]DiscoveryJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,project_id,networks_json,ports_json,status,progress,created_at,started_at,finished_at FROM discovery_jobs WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DiscoveryJob{}
	for rows.Next() {
		job, err := scanDiscoveryJob(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, job)
	}
	return result, rows.Err()
}

func (s *Store) ListDiscoveryResults(ctx context.Context, jobID string) ([]DiscoveryResult, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,job_id,host,port,protocol,service_name,fingerprint,response_summary,confidence,import_status,created_at FROM discovery_results WHERE job_id = ? ORDER BY host,port`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DiscoveryResult{}
	for rows.Next() {
		var item DiscoveryResult
		var createdAt string
		if err := rows.Scan(&item.ID, &item.JobID, &item.Host, &item.Port, &item.Protocol, &item.ServiceName, &item.Fingerprint, &item.ResponseSummary, &item.Confidence, &item.ImportStatus, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func scanDiscoveryJob(scanner rowScanner) (DiscoveryJob, error) {
	var job DiscoveryJob
	var networksJSON, portsJSON, createdAt string
	var startedAt, finishedAt sql.NullString
	if err := scanner.Scan(&job.ID, &job.ProjectID, &networksJSON, &portsJSON, &job.Status, &job.Progress, &createdAt, &startedAt, &finishedAt); err != nil {
		return DiscoveryJob{}, err
	}
	if err := json.Unmarshal([]byte(networksJSON), &job.Networks); err != nil {
		return DiscoveryJob{}, err
	}
	if err := json.Unmarshal([]byte(portsJSON), &job.Ports); err != nil {
		return DiscoveryJob{}, err
	}
	var err error
	job.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return DiscoveryJob{}, err
	}
	if startedAt.Valid {
		value, err := time.Parse(time.RFC3339Nano, startedAt.String)
		if err != nil {
			return DiscoveryJob{}, err
		}
		job.StartedAt = &value
	}
	if finishedAt.Valid {
		value, err := time.Parse(time.RFC3339Nano, finishedAt.String)
		if err != nil {
			return DiscoveryJob{}, err
		}
		job.FinishedAt = &value
	}
	return job, nil
}
