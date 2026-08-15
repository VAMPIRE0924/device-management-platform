package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
)

func (s *Store) ProjectNetworks(ctx context.Context, projectID string) ([]string, error) {
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM projects WHERE id = ?`, projectID).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	return s.projectNetworks(ctx, projectID)
}

func (s *Store) ListDevices(ctx context.Context, projectID string) ([]Device, error) {
	if _, err := s.ProjectNetworks(ctx, projectID); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,project_id,host,name,device_type,vendor,source,status,last_seen_at,created_at,updated_at FROM devices WHERE project_id = ? ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	devices := []Device{}
	for rows.Next() {
		var device Device
		var lastSeenAt sql.NullString
		var createdAt, updatedAt string
		if err := rows.Scan(&device.ID, &device.ProjectID, &device.Host, &device.Name, &device.DeviceType, &device.Vendor, &device.Source, &device.Status, &lastSeenAt, &createdAt, &updatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		device.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			rows.Close()
			return nil, err
		}
		device.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if lastSeenAt.Valid {
			seen, parseErr := time.Parse(time.RFC3339Nano, lastSeenAt.String)
			if parseErr != nil {
				rows.Close()
				return nil, parseErr
			}
			device.LastSeenAt = &seen
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range devices {
		devices[index].Endpoints, err = s.deviceEndpoints(ctx, devices[index].ID)
		if err != nil {
			return nil, err
		}
	}
	return devices, nil
}

// VerifyDeviceEndpoints persists the result of an active probe for every
// registered endpoint on a device. The caller must provide a status for every
// endpoint; this prevents a partial probe from leaving stale "verified" rows.
func (s *Store) VerifyDeviceEndpoints(ctx context.Context, projectID, deviceID string, statuses map[string]bool, audit AuditInput) (Device, error) {
	if len(statuses) == 0 {
		return Device{}, errors.New("verification status is empty")
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
	var endpointCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM endpoints e JOIN devices d ON d.id=e.device_id WHERE d.id=? AND d.project_id=?`, deviceID, projectID).Scan(&endpointCount); err != nil {
		return Device{}, err
	}
	if endpointCount == 0 {
		return Device{}, ErrNotFound
	}
	if len(statuses) != endpointCount {
		return Device{}, errors.New("verification status does not cover every endpoint")
	}
	verifiedCount := 0
	for endpointID, verified := range statuses {
		status := "failed"
		var verifiedAt any
		if verified {
			status = "verified"
			verifiedAt = now.Format(time.RFC3339Nano)
			verifiedCount++
		}
		result, err := tx.ExecContext(ctx, `UPDATE endpoints SET verification_status=?,last_verified_at=CASE WHEN ? IS NULL THEN last_verified_at ELSE ? END,updated_at=? WHERE id=? AND device_id=?`, status, verifiedAt, verifiedAt, now.Format(time.RFC3339Nano), endpointID, deviceID)
		if err != nil {
			return Device{}, err
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return Device{}, errors.New("verification contains an unknown endpoint")
		}
	}
	deviceStatus := "offline"
	if verifiedCount > 0 {
		deviceStatus = "online"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET status=?,last_seen_at=CASE WHEN ? > 0 THEN ? ELSE last_seen_at END,updated_at=? WHERE id=? AND project_id=?`, deviceStatus, verifiedCount, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), deviceID, projectID); err != nil {
		return Device{}, err
	}
	audit.ResourceID = deviceID
	audit.MetadataJSON = fmt.Sprintf(`{"verified":%d,"failed":%d}`, verifiedCount, endpointCount-verifiedCount)
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	devices, err := s.ListDevices(ctx, projectID)
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

func (s *Store) CreateDevice(ctx context.Context, projectID string, input CreateDeviceInput, audit AuditInput) (Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	device, err := insertDeviceTx(ctx, tx, projectID, input, audit, time.Now().UTC())
	if err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return device, nil
}

// CreateDevices writes an entire CSV/import batch in one transaction. A
// duplicate host, duplicate endpoint or audit failure rolls back every row.
func (s *Store) CreateDevices(ctx context.Context, projectID string, inputs []CreateDeviceInput, audit AuditInput) ([]Device, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	devices := make([]Device, 0, len(inputs))
	for _, input := range inputs {
		device, err := insertDeviceTx(ctx, tx, projectID, input, audit, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return devices, nil
}

func insertDeviceTx(ctx context.Context, tx *sql.Tx, projectID string, input CreateDeviceInput, audit AuditInput, now time.Time) (Device, error) {
	deviceID, err := id.New()
	if err != nil {
		return Device{}, err
	}
	auditID, err := id.New()
	if err != nil {
		return Device{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO devices(id,project_id,host,name,device_type,vendor,source,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
		deviceID, projectID, input.Host, input.Name, input.DeviceType, input.Vendor, input.Source, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return Device{}, fmt.Errorf("insert device: %w", err)
	}
	endpoints := make([]DeviceEndpoint, 0, len(input.Endpoints))
	for _, endpointInput := range input.Endpoints {
		endpointID := endpointInput.ID
		if endpointID == "" {
			endpointID, err = id.New()
			if err != nil {
				return Device{}, err
			}
		}
		accessType := endpointAccessType(endpointInput.Protocol)
		_, err = tx.ExecContext(ctx, `INSERT INTO endpoints(id,device_id,name,protocol,target_port,access_type,tls_server_name,ssh_credential_ref,ssh_auth_method,ssh_username,ssh_key_path,ssh_host_key_fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			endpointID, deviceID, endpointInput.Name, endpointInput.Protocol, endpointInput.TargetPort, accessType, endpointInput.TLSServerName, endpointInput.CredentialRef, endpointInput.SSHAuthMethod, endpointInput.SSHUsername, endpointInput.SSHKeyPath, endpointInput.SSHHostKeyFingerprint, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		if err != nil {
			return Device{}, fmt.Errorf("insert endpoint: %w", err)
		}
		endpoints = append(endpoints, DeviceEndpoint{ID: endpointID, Name: endpointInput.Name, Protocol: endpointInput.Protocol, TargetPort: endpointInput.TargetPort, AccessType: accessType, VerificationStatus: "unverified", TLSServerName: endpointInput.TLSServerName, CredentialConfigured: endpointInput.CredentialRef != "", SSHAuthMethod: endpointInput.SSHAuthMethod, SSHUsername: endpointInput.SSHUsername, SSHKeyPath: endpointInput.SSHKeyPath, SSHHostKeyFingerprint: endpointInput.SSHHostKeyFingerprint})
	}
	audit.ResourceID = deviceID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Device{}, err
	}
	return Device{ID: deviceID, ProjectID: projectID, Host: input.Host, Name: input.Name, DeviceType: input.DeviceType, Vendor: input.Vendor, Source: input.Source, Status: "unknown", Endpoints: endpoints, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Store) deviceEndpoints(ctx context.Context, deviceID string) ([]DeviceEndpoint, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,protocol,target_port,access_type,verification_status,last_verified_at,tls_server_name,ssh_credential_ref,ssh_auth_method,ssh_username,ssh_key_path,ssh_host_key_fingerprint FROM endpoints WHERE device_id = ? ORDER BY created_at`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []DeviceEndpoint{}
	for rows.Next() {
		endpoint, err := scanDeviceEndpoint(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, endpoint)
	}
	return result, rows.Err()
}

func scanDeviceEndpoint(scanner rowScanner) (DeviceEndpoint, error) {
	var endpoint DeviceEndpoint
	var lastVerified sql.NullString
	var credentialRef string
	if err := scanner.Scan(&endpoint.ID, &endpoint.Name, &endpoint.Protocol, &endpoint.TargetPort, &endpoint.AccessType, &endpoint.VerificationStatus, &lastVerified, &endpoint.TLSServerName, &credentialRef, &endpoint.SSHAuthMethod, &endpoint.SSHUsername, &endpoint.SSHKeyPath, &endpoint.SSHHostKeyFingerprint); err != nil {
		return DeviceEndpoint{}, err
	}
	endpoint.CredentialConfigured = credentialRef != ""
	if lastVerified.Valid {
		value, err := time.Parse(time.RFC3339Nano, lastVerified.String)
		if err != nil {
			return DeviceEndpoint{}, err
		}
		endpoint.LastVerifiedAt = &value
	}
	return endpoint, nil
}

func endpointAccessType(protocol string) string {
	switch protocol {
	case "http", "https":
		return "web_proxy"
	case "ssh":
		return "web_ssh"
	default:
		return "port_forward"
	}
}

func (s *Store) UpdateDevice(ctx context.Context, projectID, deviceID string, input UpdateDeviceInput, audit AuditInput) (Device, error) {
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
	result, err := tx.ExecContext(ctx, `UPDATE devices SET host = CASE WHEN ? = '' THEN host ELSE ? END,name = ?,device_type = ?,vendor = ?,updated_at = ? WHERE id = ? AND project_id = ?`, input.Host, input.Host, input.Name, input.DeviceType, input.Vendor, now.Format(time.RFC3339Nano), deviceID, projectID)
	if err != nil {
		return Device{}, err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return Device{}, ErrNotFound
	}
	if input.Endpoints != nil {
		if err := replaceDeviceEndpointsTx(ctx, tx, deviceID, *input.Endpoints, now); err != nil {
			return Device{}, err
		}
	}
	audit.ResourceID = deviceID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return Device{}, err
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return s.deviceByID(ctx, projectID, deviceID)
}

func replaceDeviceEndpointsTx(ctx context.Context, tx *sql.Tx, deviceID string, desired []CreateEndpointInput, now time.Time) error {
	type existingEndpoint struct {
		protocol string
		port     int
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,protocol,target_port FROM endpoints WHERE device_id = ?`, deviceID)
	if err != nil {
		return err
	}
	existing := map[string]existingEndpoint{}
	for rows.Next() {
		var endpointID string
		var endpoint existingEndpoint
		if err := rows.Scan(&endpointID, &endpoint.protocol, &endpoint.port); err != nil {
			rows.Close()
			return err
		}
		existing[endpointID] = endpoint
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, endpoint := range desired {
		if endpoint.ID != "" {
			if _, ok := existing[endpoint.ID]; !ok && !endpoint.IsNew {
				return ErrNotFound
			}
		}
	}
	inUseRows, err := tx.QueryContext(ctx, `SELECT e.id FROM endpoints e WHERE e.device_id = ? AND (EXISTS (SELECT 1 FROM port_forwards pf WHERE pf.endpoint_id = e.id) OR EXISTS (SELECT 1 FROM access_sessions s WHERE s.endpoint_id = e.id AND s.status = 'active' AND s.expires_at > ?))`, deviceID, now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	inUse := map[string]struct{}{}
	for inUseRows.Next() {
		var endpointID string
		if err := inUseRows.Scan(&endpointID); err != nil {
			inUseRows.Close()
			return err
		}
		inUse[endpointID] = struct{}{}
	}
	if err := inUseRows.Close(); err != nil {
		return err
	}
	desiredIDs := map[string]struct{}{}
	for _, endpoint := range desired {
		if current, exists := existing[endpoint.ID]; endpoint.ID != "" && exists && !endpoint.IsNew {
			if _, busy := inUse[endpoint.ID]; busy && (current.protocol != endpoint.Protocol || current.port != endpoint.TargetPort) {
				return fmt.Errorf("endpoint %s is in use", endpoint.ID)
			}
			desiredIDs[endpoint.ID] = struct{}{}
		}
	}
	for endpointID := range existing {
		if _, keep := desiredIDs[endpointID]; !keep {
			if _, busy := inUse[endpointID]; busy {
				return fmt.Errorf("endpoint %s is in use", endpointID)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM endpoints WHERE id = ?`, endpointID); err != nil {
				return err
			}
		}
	}
	for _, endpoint := range desired {
		accessType := endpointAccessType(endpoint.Protocol)
		if endpoint.ID != "" {
			_, err = tx.ExecContext(ctx, `UPDATE endpoints SET name = ?,protocol = ?,target_port = ?,access_type = ?,verification_status = CASE WHEN protocol = ? AND target_port = ? THEN verification_status ELSE 'unverified' END,last_verified_at = CASE WHEN protocol = ? AND target_port = ? THEN last_verified_at ELSE NULL END,tls_server_name = ?,ssh_credential_ref = CASE WHEN ? = '' THEN ssh_credential_ref ELSE ? END,ssh_auth_method=CASE WHEN ?='' THEN ssh_auth_method ELSE ? END,ssh_username=CASE WHEN ?='' THEN ssh_username ELSE ? END,ssh_key_path=CASE WHEN ?='' AND ?='' THEN ssh_key_path ELSE ? END,ssh_host_key_fingerprint = ?,updated_at = ? WHERE id = ? AND device_id = ?`, endpoint.Name, endpoint.Protocol, endpoint.TargetPort, accessType, endpoint.Protocol, endpoint.TargetPort, endpoint.Protocol, endpoint.TargetPort, endpoint.TLSServerName, endpoint.CredentialRef, endpoint.CredentialRef, endpoint.SSHAuthMethod, endpoint.SSHAuthMethod, endpoint.SSHUsername, endpoint.SSHUsername, endpoint.SSHAuthMethod, endpoint.SSHKeyPath, endpoint.SSHKeyPath, endpoint.SSHHostKeyFingerprint, now.Format(time.RFC3339Nano), endpoint.ID, deviceID)
		} else {
			endpointID, idErr := id.New()
			if idErr != nil {
				return idErr
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO endpoints(id,device_id,name,protocol,target_port,access_type,tls_server_name,ssh_credential_ref,ssh_auth_method,ssh_username,ssh_key_path,ssh_host_key_fingerprint,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, endpointID, deviceID, endpoint.Name, endpoint.Protocol, endpoint.TargetPort, accessType, endpoint.TLSServerName, endpoint.CredentialRef, endpoint.SSHAuthMethod, endpoint.SSHUsername, endpoint.SSHKeyPath, endpoint.SSHHostKeyFingerprint, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteDevice(ctx context.Context, projectID, deviceID string, audit AuditInput) error {
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
	var references int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM port_forwards f JOIN endpoints e ON e.id=f.endpoint_id WHERE e.device_id = ?) + (SELECT COUNT(*) FROM access_sessions s JOIN endpoints e ON e.id=s.endpoint_id WHERE e.device_id = ? AND s.status = 'active' AND s.expires_at > ?)`, deviceID, deviceID, now.Format(time.RFC3339Nano)).Scan(&references)
	if err != nil {
		return err
	}
	if references > 0 {
		return fmt.Errorf("resource has active sessions or port forwards")
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id = ? AND project_id = ?`, deviceID, projectID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return ErrNotFound
	}
	audit.ResourceID = deviceID
	if err := insertAudit(ctx, tx, auditID, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) deviceByID(ctx context.Context, projectID, deviceID string) (Device, error) {
	devices, err := s.ListDevices(ctx, projectID)
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
