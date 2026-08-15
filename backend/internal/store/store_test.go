package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateAndCreateControlPlaneObjects(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "platform.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("second migration must be idempotent: %v", err)
	}
	version, err := db.SchemaVersion(ctx)
	if err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, err = %v", version, err)
	}
	var legacyNodeAccessTypeColumns int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='access_type'`).Scan(&legacyNodeAccessTypeColumns); err != nil {
		t.Fatal(err)
	}
	if legacyNodeAccessTypeColumns != 0 {
		t.Fatalf("nodes.access_type must be physically removed, found %d column", legacyNodeAccessTypeColumns)
	}
	var legacyTunnelPolicyColumns int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('projects') WHERE name='tunnel_on_demand'`).Scan(&legacyTunnelPolicyColumns); err != nil {
		t.Fatal(err)
	}
	if legacyTunnelPolicyColumns != 0 {
		t.Fatalf("projects.tunnel_on_demand must be physically removed, found %d column", legacyTunnelPolicyColumns)
	}
	var legacyInsecureTLSColumns int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('endpoints') WHERE name='allow_insecure_tls'`).Scan(&legacyInsecureTLSColumns); err != nil {
		t.Fatal(err)
	}
	if legacyInsecureTLSColumns != 0 {
		t.Fatalf("endpoints.allow_insecure_tls must be physically removed, found %d column", legacyInsecureTLSColumns)
	}
	for _, column := range []string{"gateway_mode", "gateway_name", "gateway_status", "runtime_type", "runtime_address"} {
		var count int
		if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('projects') WHERE name=?`, column).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("projects.%s must be physically removed, found %d column", column, count)
		}
	}
	for _, indexName := range []string{"idx_discovery_jobs_project_created", "idx_access_sessions_project_status_expiry"} {
		var count int
		if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name=?`, indexName).Scan(&count); err != nil || count != 1 {
			t.Fatalf("migration index %s count = %d, err = %v", indexName, count, err)
		}
	}
	assertQueryUsesIndex(t, db, ctx, `SELECT id FROM discovery_jobs WHERE project_id=? ORDER BY created_at DESC`, "idx_discovery_jobs_project_created", "project")
	assertQueryUsesIndex(t, db, ctx, `SELECT COUNT(*) FROM access_sessions WHERE project_id=? AND status='active' AND expires_at>?`, "idx_access_sessions_project_status_expiry", "project", "2000-01-01T00:00:00Z")
	node, err := db.CreateNode(ctx, CreateNodeInput{Name: "测试节点", APIURL: "https://node.test:6443", TLSServerName: "node.test", CredentialRef: "env://NODE_TOKEN", PortStart: 22000, PortEnd: 22999}, AuditInput{Actor: "test", Action: "node.create", ResourceType: "node", Result: "success", RequestID: "req-1", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := 1
	project, err := db.CreateProject(ctx, "PRJ-TEST-001", CreateProjectInput{Name: "测试项目", NodeID: node.ID, OwnerName: "管理员", ClientID: &clientID}, AuditInput{Actor: "test", Action: "project.create", ResourceType: "project", Result: "success", RequestID: "req-2", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ports, err := db.ProjectScanPorts(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != len(DefaultProjectScanPorts) {
		t.Fatalf("default project scan ports = %#v", ports)
	}
	for index := range DefaultProjectScanPorts {
		if ports[index] != DefaultProjectScanPorts[index] {
			t.Fatalf("default project scan port %d = %#v, want %#v", index, ports[index], DefaultProjectScanPorts[index])
		}
	}
	customPorts := []DiscoveryPort{{Name: "Web 服务", Protocol: "http", Port: 80}, {Name: "自定义后台", Protocol: "https", Port: 9443}}
	if err := db.ReplaceProjectScanPorts(ctx, project.ID, customPorts, AuditInput{Actor: "test", Action: "project.scan_ports.update", ResourceType: "project", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	ports, err = db.ProjectScanPorts(ctx, project.ID)
	if err != nil || len(ports) != 2 || ports[1] != customPorts[1] {
		t.Fatalf("updated project scan ports = %#v, err = %v", ports, err)
	}
	project, err = db.UpdateProject(ctx, project.ID, UpdateProjectInput{Name: project.Name, OwnerName: project.OwnerName, Networks: []string{"10.10.0.0/16", "192.168.1.0/24"}}, AuditInput{Actor: "test", Action: "project.update", ResourceType: "project", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if len(project.Networks) != 2 || project.NodeID != node.ID {
		t.Fatalf("unexpected project: %#v", project)
	}
	projects, err := db.ListProjects(ctx)
	if err != nil || len(projects) != 1 || len(projects[0].Networks) != 2 {
		t.Fatalf("projects = %#v, err = %v", projects, err)
	}
	device, err := db.CreateDevice(ctx, project.ID, CreateDeviceInput{Host: "10.10.0.1", Name: "OpenWrt", DeviceType: "network", Vendor: "OpenWrt", Source: "manual", Endpoints: []CreateEndpointInput{{Name: "LuCI", Protocol: "https", TargetPort: 9443}, {Name: "AdGuard Home", Protocol: "http", TargetPort: 3000}, {Name: "设备维护", Protocol: "ssh", TargetPort: 2222}, {Name: "主码流", Protocol: "rtsp", TargetPort: 554}}}, AuditInput{Actor: "test", Action: "device.create", ResourceType: "device", Result: "success", RequestID: "req-3", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(device.Endpoints) != 4 || device.Endpoints[0].AccessType != "web_proxy" || device.Endpoints[2].AccessType != "web_ssh" || device.Endpoints[3].AccessType != "port_forward" {
		t.Fatalf("unexpected endpoints: %#v", device.Endpoints)
	}
	devices, err := db.ListDevices(ctx, project.ID)
	if err != nil || len(devices) != 1 || len(devices[0].Endpoints) != 4 {
		t.Fatalf("devices = %#v, err = %v", devices, err)
	}
	job, err := db.CreateDiscoveryJob(ctx, project.ID, []string{"10.10.0.0/24"}, []DiscoveryPort{{Port: 3000, Protocol: "http", Name: "AdGuard Home"}, {Port: 2222, Protocol: "ssh", Name: "SSH 维护"}}, AuditInput{Actor: "test", Action: "discovery.create", ResourceType: "discovery_job", Result: "success", RequestID: "req-4", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetDiscoveryJobState(ctx, job.ID, "running", 50); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveryResult(ctx, job.ID, DiscoveryProbeResult{Host: "10.10.0.2", Port: 3000, Protocol: "http", ServiceName: "AdGuard Home", Fingerprint: "HTTP 200", Confidence: 95}); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveDiscoveryResult(ctx, job.ID, DiscoveryProbeResult{Host: "10.10.0.2", Port: 2222, Protocol: "ssh", ServiceName: "SSH 维护", Fingerprint: "SSH-2.0", Confidence: 98}); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDiscoveryJobState(ctx, job.ID, "completed", 100); err != nil {
		t.Fatal(err)
	}
	discovered, err := db.ImportDiscoveryDevice(ctx, job.ID, CreateDeviceInput{Host: "10.10.0.2", Name: "发现网关", DeviceType: "network", Vendor: "OpenWrt", Endpoints: []CreateEndpointInput{{Name: "AdGuard Home", Protocol: "http", TargetPort: 3000}, {Name: "SSH 维护", Protocol: "ssh", TargetPort: 2222}, {Name: "人工补充", Protocol: "http", TargetPort: 3001}}}, AuditInput{Actor: "test", Action: "discovery.import", ResourceType: "device", Result: "success", RequestID: "req-5", SourceIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(discovered.Endpoints) != 3 || discovered.Endpoints[0].VerificationStatus != "verified" || discovered.Endpoints[2].VerificationStatus != "unverified" {
		t.Fatalf("unexpected imported device: %#v", discovered)
	}
}

func TestMigrationElevenPreservesAdminForOnboardingAndRevokesOldSession(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "migration-v10.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for index, migration := range migrations[:10] {
		if _, err := db.db.ExecContext(ctx, migration); err != nil {
			t.Fatalf("apply legacy migration %d: %v", index+1, err)
		}
		if _, err := db.db.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, index+1, "2026-08-01T00:00:00Z"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.db.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at) VALUES('legacy-admin','legacy-admin','迁移管理员','existing-password-hash','system_admin',1,'2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.ExecContext(ctx, `INSERT INTO auth_sessions(id,user_id,token_hash,csrf_hash,status,expires_at,created_at,last_seen_at) VALUES('legacy-session','legacy-admin','legacy-token','legacy-csrf','active','2099-01-01T00:00:00Z','2026-08-01T00:00:00Z','2026-08-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	credential, err := db.UserCredentialByUsername(ctx, "legacy-admin")
	if err != nil || credential.PasswordHash != "existing-password-hash" || !credential.PasswordChangeRequired || credential.MFAEnabled {
		t.Fatalf("legacy admin onboarding state = %#v, err = %v", credential, err)
	}
	var status string
	if err := db.db.QueryRowContext(ctx, `SELECT status FROM auth_sessions WHERE id='legacy-session'`).Scan(&status); err != nil || status != "revoked" {
		t.Fatalf("legacy session status = %q, err = %v", status, err)
	}
}

func assertQueryUsesIndex(t *testing.T, db *Store, ctx context.Context, query, indexName string, args ...any) {
	t.Helper()
	rows, err := db.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(plan, "\n"), indexName) {
		t.Fatalf("query plan does not use %s: %v", indexName, plan)
	}
}

func TestEndpointEditsPreserveVerificationUntilRouteChanges(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "endpoint-edit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	node, err := db.CreateNode(ctx, CreateNodeInput{Name: "节点", APIURL: "https://node.test", TLSServerName: "node.test", CredentialRef: "env://NODE_TOKEN", PortStart: 24000, PortEnd: 24999}, AuditInput{Actor: "test", Action: "node.create", ResourceType: "node", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := 1
	project, err := db.CreateProject(ctx, "PRJ-ENDPOINT", CreateProjectInput{Name: "项目", NodeID: node.ID, OwnerName: "管理员", ClientID: &clientID}, AuditInput{Actor: "test", Action: "project.create", ResourceType: "project", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	project, err = db.UpdateProject(ctx, project.ID, UpdateProjectInput{Name: project.Name, OwnerName: project.OwnerName, Networks: []string{"10.30.0.0/16"}}, AuditInput{Actor: "test", Action: "project.update", ResourceType: "project", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.CreateDevice(ctx, project.ID, CreateDeviceInput{Host: "10.30.0.1", Name: "设备", DeviceType: "network", Source: "manual", Endpoints: []CreateEndpointInput{{Name: "SSH", Protocol: "ssh", TargetPort: 22, CredentialRef: "db://ssh/test"}}}, AuditInput{Actor: "test", Action: "device.create", ResourceType: "device", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	endpointID := device.Endpoints[0].ID
	verifiedAt := "2026-08-01T12:00:00Z"
	if _, err := db.db.ExecContext(ctx, `UPDATE endpoints SET verification_status='verified',last_verified_at=? WHERE id=?`, verifiedAt, endpointID); err != nil {
		t.Fatal(err)
	}
	replacement := []CreateEndpointInput{{ID: endpointID, Name: "SSH 运维", Protocol: "ssh", TargetPort: 22, SSHHostKeyFingerprint: "SHA256:test"}}
	device, err = db.UpdateDevice(ctx, project.ID, device.ID, UpdateDeviceInput{Host: device.Host, Name: "设备已改名", DeviceType: device.DeviceType, Vendor: device.Vendor, Endpoints: &replacement}, AuditInput{Actor: "test", Action: "device.update", ResourceType: "device", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if len(device.Endpoints) != 1 || device.Endpoints[0].VerificationStatus != "verified" || device.Endpoints[0].LastVerifiedAt == nil || !device.Endpoints[0].CredentialConfigured {
		t.Fatalf("device-level route-preserving edit lost state: %#v", device.Endpoints)
	}
	replacement = []CreateEndpointInput{{ID: endpointID, Name: "SSH 运维", Protocol: "ssh", TargetPort: 2222, SSHHostKeyFingerprint: "SHA256:test"}}
	device, err = db.UpdateDevice(ctx, project.ID, device.ID, UpdateDeviceInput{Host: device.Host, Name: device.Name, DeviceType: device.DeviceType, Vendor: device.Vendor, Endpoints: &replacement}, AuditInput{Actor: "test", Action: "device.update", ResourceType: "device", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	updated := device.Endpoints[0]
	if updated.VerificationStatus != "unverified" || updated.LastVerifiedAt != nil || !updated.CredentialConfigured {
		t.Fatalf("route-changing device edit did not invalidate verification correctly: %#v", updated)
	}
}

func TestDeviceBatchAndEndpointReplacementAreAtomic(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "atomic.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	node, err := db.CreateNode(ctx, CreateNodeInput{Name: "原子节点", APIURL: "https://node.test", TLSServerName: "node.test", CredentialRef: "env://NODE_TOKEN", PortStart: 23000, PortEnd: 23999}, AuditInput{Actor: "test", Action: "node.create", ResourceType: "node", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	clientID := 8
	project, err := db.CreateProject(ctx, "PRJ-ATOMIC", CreateProjectInput{Name: "原子项目", NodeID: node.ID, OwnerName: "管理员", ClientID: &clientID}, AuditInput{Actor: "test", Action: "project.create", ResourceType: "project", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	project, err = db.UpdateProject(ctx, project.ID, UpdateProjectInput{Name: project.Name, OwnerName: project.OwnerName, Networks: []string{"10.20.0.0/16"}}, AuditInput{Actor: "test", Action: "project.update", ResourceType: "project", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.CreateDevice(ctx, project.ID, CreateDeviceInput{Host: "10.20.0.1", Name: "原设备", DeviceType: "network", Source: "manual", Endpoints: []CreateEndpointInput{{Name: "后台", Protocol: "http", TargetPort: 80}}}, AuditInput{Actor: "test", Action: "device.create", ResourceType: "device", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.CreateDevices(ctx, project.ID, []CreateDeviceInput{
		{Host: "10.20.0.2", Name: "不应保留", DeviceType: "other", Source: "import"},
		{Host: "10.20.0.1", Name: "重复地址", DeviceType: "other", Source: "import"},
	}, AuditInput{Actor: "test", Action: "device.batch_create", ResourceType: "device", Result: "success"})
	if err == nil {
		t.Fatal("batch with duplicate project host unexpectedly succeeded")
	}
	devices, err := db.ListDevices(ctx, project.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("partial batch data remained: %#v, err=%v", devices, err)
	}
	invalidEndpointID := "01INVALIDENDPOINT000000000000"
	endpoints := []CreateEndpointInput{{ID: device.Endpoints[0].ID, Name: "新后台", Protocol: "http", TargetPort: 8080}, {ID: invalidEndpointID, Name: "非法入口", Protocol: "ssh", TargetPort: 22}}
	_, err = db.UpdateDevice(ctx, project.ID, device.ID, UpdateDeviceInput{Host: device.Host, Name: "不应改名", DeviceType: device.DeviceType, Vendor: device.Vendor, Endpoints: &endpoints}, AuditInput{Actor: "test", Action: "device.update", ResourceType: "device", Result: "success"})
	if err == nil {
		t.Fatal("endpoint replacement with foreign id unexpectedly succeeded")
	}
	devices, err = db.ListDevices(ctx, project.ID)
	if err != nil || devices[0].Name != "原设备" || devices[0].Endpoints[0].TargetPort != 80 {
		t.Fatalf("partial endpoint update remained: %#v, err=%v", devices, err)
	}
}

func TestRestoreDatabaseRetainsSafetyBackup(t *testing.T) {
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.db")
	source, err := Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := source.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = source.CreateNode(ctx, CreateNodeInput{Name: "恢复后的节点", APIURL: "https://source.test", TLSServerName: "source.test", CredentialRef: "env://SOURCE", PortStart: 24000, PortEnd: 24999}, AuditInput{Actor: "test", Action: "node.create", ResourceType: "node", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(directory, "export.db")
	if err := source.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(directory, "target.db")
	target, err := Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = target.CreateNode(ctx, CreateNodeInput{Name: "恢复前的节点", APIURL: "https://target.test", TLSServerName: "target.test", CredentialRef: "env://TARGET", PortStart: 25000, PortEnd: 25999}, AuditInput{Actor: "test", Action: "node.create", ResourceType: "node", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	rollbackPath, err := RestoreDatabase(ctx, targetPath, backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if rollbackPath == "" {
		t.Fatal("restore did not retain the pre-restore database")
	}
	if _, err := os.Stat(rollbackPath); err != nil {
		t.Fatalf("pre-restore backup unavailable: %v", err)
	}
	restored, err := Open(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	nodes, err := restored.ListNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "恢复后的节点" {
		t.Fatalf("restored nodes = %#v, err=%v", nodes, err)
	}
}
