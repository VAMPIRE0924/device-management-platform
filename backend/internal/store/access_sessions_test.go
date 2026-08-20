package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessSessionIdleExpiryAndRandomRouteIsolation(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "access-sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	audit := AuditInput{Actor: "test", Action: "test", ResourceType: "test", Result: "success", RequestID: "test", SourceIP: "127.0.0.1"}
	user, err := db.CreateInitialAdmin(ctx, CreateUserInput{Username: "admin", DisplayName: "Admin", PasswordHash: "not-used"}, audit)
	if err != nil {
		t.Fatal(err)
	}
	node, err := db.CreateNode(ctx, CreateNodeInput{Name: "node", APIURL: "https://node.test", CredentialRef: "db://node/test", PortStart: 22000, PortEnd: 22999}, audit)
	if err != nil {
		t.Fatal(err)
	}
	clientID := 1
	project, err := db.CreateProject(ctx, "PRJ-SESSION", CreateProjectInput{Name: "project", NodeID: node.ID, OwnerName: "Admin", ClientID: &clientID}, audit)
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.CreateDevice(ctx, project.ID, CreateDeviceInput{Host: "10.0.0.1", Name: "device", DeviceType: "network", Source: "manual", Endpoints: []CreateEndpointInput{{Name: "Web", Protocol: "http", TargetPort: 80}}}, audit)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authSession, err := db.CreateAuthSession(ctx, user.ID, "auth-token-hash", "csrf-hash", now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	input := CreateAccessSessionInput{UserID: &user.ID, AuthSessionID: authSession.ID, ProjectID: project.ID, EndpointID: device.Endpoints[0].ID, TokenHash: "route-hash", RouteLabel: "web-01234567", GrantHash: "grant-one", Mode: "web", SourceIP: "127.0.0.1", ExpiresAt: now.Add(time.Hour)}
	first, err := db.CreateAccessSession(ctx, input, audit)
	if err != nil {
		t.Fatal(err)
	}
	secondInput := input
	secondInput.TokenHash = "route-hash-two"
	secondInput.RouteLabel = "web-76543210"
	secondInput.GrantHash = "grant-two"
	second, err := db.CreateAccessSession(ctx, secondInput, audit)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("independent random routes reused an access session")
	}
	// Recreate the exact pre-schema-28 state and verify that migration 28
	// backfills existing sessions before installing its persistence triggers.
	if _, err := db.db.ExecContext(ctx, `
DROP TRIGGER trg_access_sessions_log_insert;
DROP TRIGGER trg_access_sessions_log_update;
DROP TABLE access_logs;
DELETE FROM schema_migrations WHERE version=28;
`); err != nil {
		t.Fatalf("prepare schema 27 access-session fixture: %v", err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate access-session history to schema 28: %v", err)
	}
	backfilled, err := db.ListAccessLogs(ctx, "project", 100, 0)
	if err != nil || len(backfilled) != 2 {
		t.Fatalf("schema 28 access history backfill = %#v, err=%v", backfilled, err)
	}
	collisionInput := input
	collisionInput.GrantHash = "collision-grant"
	if _, err := db.CreateAccessSession(ctx, collisionInput, audit); err != ErrInUse {
		t.Fatalf("active route collision error = %v, want ErrInUse", err)
	}
	if _, _, err := db.ExchangeAccessGrant(ctx, first.TokenHash, input.GrantHash, now.Add(-15*time.Minute)); err != nil {
		t.Fatalf("exchange first access grant: %v", err)
	}
	if err := db.RevokeAccessSession(ctx, first.ID, audit); err != nil {
		t.Fatal(err)
	}
	touchAt := now.Add(10 * time.Minute)
	if err := db.TouchAccessSession(ctx, second.ID, touchAt, now.Add(-time.Minute)); err != nil {
		t.Fatalf("touch active access session: %v", err)
	}
	var accessLastSeen, authLastSeen string
	if err := db.db.QueryRowContext(ctx, `SELECT s.last_seen_at,a.last_seen_at FROM access_sessions s JOIN auth_sessions a ON a.id=s.auth_session_id WHERE s.id=?`, second.ID).Scan(&accessLastSeen, &authLastSeen); err != nil {
		t.Fatal(err)
	}
	if accessLastSeen != touchAt.Format(time.RFC3339Nano) || authLastSeen != touchAt.Format(time.RFC3339Nano) {
		t.Fatalf("touch timestamps = %q / %q", accessLastSeen, authLastSeen)
	}
	active, err := db.ListActiveAccessSessions(ctx, now.Add(-15*time.Minute))
	if err != nil || len(active) != 1 || active[0].ID != second.ID {
		t.Fatalf("active sessions after revocation = %#v, err=%v", active, err)
	}
	if active[0].TokenHash != secondInput.TokenHash {
		t.Fatalf("active session token hash = %q, want %q", active[0].TokenHash, secondInput.TokenHash)
	}
	if active[0].DomainPrefix != secondInput.RouteLabel {
		t.Fatalf("active session route label = %q, want %q", active[0].DomainPrefix, secondInput.RouteLabel)
	}
	idleAt := now.Add(-20 * time.Minute).Format(time.RFC3339Nano)
	if _, err := db.db.ExecContext(ctx, `UPDATE access_sessions SET last_seen_at=? WHERE id=?`, idleAt, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ExchangeAccessGrant(ctx, secondInput.TokenHash, secondInput.GrantHash, now.Add(-15*time.Minute)); err != ErrNotFound {
		t.Fatalf("idle grant exchange error = %v, want ErrNotFound", err)
	}
	active, err = db.ListActiveAccessSessions(ctx, now.Add(-15*time.Minute))
	if err != nil || len(active) != 0 {
		t.Fatalf("idle session remained active = %#v, err=%v", active, err)
	}
	expired, err := db.ExpireAccessSessions(ctx, now, now.Add(-15*time.Minute))
	if err != nil || expired != 1 {
		t.Fatalf("expired sessions = %d, err=%v", expired, err)
	}
	if err := db.TouchAccessSession(ctx, second.ID, now.Add(time.Minute), now.Add(-time.Minute)); err != ErrNotFound {
		t.Fatalf("touch expired session error = %v, want ErrNotFound", err)
	}
	logs, err := db.ListAccessLogs(ctx, "device", 100, 0)
	if err != nil || len(logs) != 2 {
		t.Fatalf("access history = %#v, err=%v", logs, err)
	}
	var firstLog *AccessLog
	for index := range logs {
		if logs[index].ID == first.ID {
			firstLog = &logs[index]
			break
		}
	}
	if firstLog == nil || firstLog.Username != "admin" || firstLog.ProjectName != "project" || firstLog.DeviceName != "device" || firstLog.EndpointName != "Web" || firstLog.AccessedAt == nil || firstLog.EndedAt == nil || firstLog.Status != "revoked" {
		t.Fatalf("enriched access history item = %#v", firstLog)
	}
	missing, err := db.ListAccessLogs(ctx, "does-not-exist", 100, 0)
	if err != nil || len(missing) != 0 {
		t.Fatalf("filtered access history = %#v, err=%v", missing, err)
	}
	cleaned, err := db.CleanupAuthSessions(ctx, now.Add(2*time.Hour))
	if err != nil || cleaned != 1 {
		t.Fatalf("cleanup auth sessions = %d, err=%v", cleaned, err)
	}
	var remainingSessions int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_sessions`).Scan(&remainingSessions); err != nil || remainingSessions != 0 {
		t.Fatalf("access sessions after auth cleanup = %d, err=%v", remainingSessions, err)
	}
	persisted, err := db.ListAccessLogs(ctx, "project", 100, 0)
	if err != nil || len(persisted) != 2 {
		t.Fatalf("access logs were lost with auth session cleanup: %#v, err=%v", persisted, err)
	}
	if err := db.DeleteProject(ctx, project.ID, audit); err != nil {
		t.Fatalf("delete project after sessions ended: %v", err)
	}
	persisted, err = db.ListAccessLogs(ctx, "project", 100, 0)
	if err != nil || len(persisted) != 2 || persisted[0].ProjectName != "project" {
		t.Fatalf("access log snapshots were lost with project deletion: %#v, err=%v", persisted, err)
	}
}
