package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAccessSessionIdleExpiryAndRouteRotation(t *testing.T) {
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
	input := CreateAccessSessionInput{UserID: &user.ID, AuthSessionID: authSession.ID, ProjectID: project.ID, EndpointID: device.Endpoints[0].ID, TokenHash: "stable-route-hash", GrantHash: "grant-one", Mode: "web", SourceIP: "127.0.0.1", ExpiresAt: now.Add(time.Hour)}
	first, err := db.CreateAccessSession(ctx, input, audit)
	if err != nil {
		t.Fatal(err)
	}
	input.GrantHash = "grant-two"
	second, err := db.CreateAccessSession(ctx, input, audit)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID {
		t.Fatal("route rotation must replace the logical access session")
	}
	active, err := db.ListActiveAccessSessions(ctx, now.Add(-15*time.Minute))
	if err != nil || len(active) != 1 || active[0].ID != second.ID {
		t.Fatalf("active sessions after route rotation = %#v, err=%v", active, err)
	}
	idleAt := now.Add(-20 * time.Minute).Format(time.RFC3339Nano)
	if _, err := db.db.ExecContext(ctx, `UPDATE access_sessions SET last_seen_at=? WHERE id=?`, idleAt, second.ID); err != nil {
		t.Fatal(err)
	}
	active, err = db.ListActiveAccessSessions(ctx, now.Add(-15*time.Minute))
	if err != nil || len(active) != 0 {
		t.Fatalf("idle session remained active = %#v, err=%v", active, err)
	}
	expired, err := db.ExpireAccessSessions(ctx, now, now.Add(-15*time.Minute))
	if err != nil || expired != 1 {
		t.Fatalf("expired sessions = %d, err=%v", expired, err)
	}
}
