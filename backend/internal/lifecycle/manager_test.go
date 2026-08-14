package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"i5cloud/internal/store"
)

type fakeStore struct {
	forwards       []store.PortForward
	statuses       []string
	deleted        []string
	expiredSession bool
	cleanedAuth    bool
}

func (f *fakeStore) ListExpiredPortForwards(context.Context, time.Time) ([]store.PortForward, error) {
	return f.forwards, nil
}
func (f *fakeStore) SetPortForwardStatus(_ context.Context, id, status string, _ store.AuditInput) error {
	f.statuses = append(f.statuses, id+":"+status)
	return nil
}
func (f *fakeStore) DeletePortForward(_ context.Context, id string, _ store.AuditInput) error {
	f.deleted = append(f.deleted, id)
	return nil
}
func (f *fakeStore) ExpireAccessSessions(context.Context, time.Time) (int64, error) {
	f.expiredSession = true
	return 1, nil
}
func (f *fakeStore) CleanupAuthSessions(context.Context, time.Time) (int64, error) {
	f.cleanedAuth = true
	return 1, nil
}

type fakeNodes struct {
	failID int
	seen   []int
}

func (f *fakeNodes) DeletePortForward(_ context.Context, _ string, taskID int) error {
	f.seen = append(f.seen, taskID)
	if taskID == f.failID {
		return errors.New("node unavailable")
	}
	return nil
}

func TestSweepDeletesExpiredTasksAndRetainsFailedCleanup(t *testing.T) {
	taskOne, taskTwo := 10, 20
	database := &fakeStore{forwards: []store.PortForward{
		{ID: "ok", NodeID: "node", NodeTaskID: &taskOne},
		{ID: "retry", NodeID: "node", NodeTaskID: &taskTwo},
		{ID: "reserved-only", NodeID: "node"},
	}}
	nodes := &fakeNodes{failID: taskTwo}
	manager := New(database, nodes, time.Minute)
	manager.now = func() time.Time { return time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC) }
	if err := manager.Sweep(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(database.deleted) != 2 || database.deleted[0] != "ok" || database.deleted[1] != "reserved-only" {
		t.Fatalf("deleted = %#v", database.deleted)
	}
	if len(database.statuses) != 1 || database.statuses[0] != "retry:cleanup_failed" {
		t.Fatalf("statuses = %#v", database.statuses)
	}
	if !database.expiredSession || !database.cleanedAuth {
		t.Fatal("expected session maintenance")
	}
}
