package lifecycle

import (
	"context"
	"log/slog"
	"time"

	"i5cloud/internal/store"
)

type storage interface {
	ListExpiredPortForwards(context.Context, time.Time) ([]store.PortForward, error)
	SetPortForwardStatus(context.Context, string, string, store.AuditInput) error
	DeletePortForward(context.Context, string, store.AuditInput) error
	ExpireAccessSessions(context.Context, time.Time) (int64, error)
	CleanupAuthSessions(context.Context, time.Time) (int64, error)
}

type nodeControl interface {
	DeletePortForward(context.Context, string, int) error
}

type Manager struct {
	store    storage
	nodes    nodeControl
	interval time.Duration
	now      func() time.Time
}

func New(store storage, nodes nodeControl, interval time.Duration) *Manager {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Manager{store: store, nodes: nodes, interval: interval, now: time.Now}
}

func (m *Manager) Run(ctx context.Context) {
	if err := m.Sweep(ctx); err != nil && ctx.Err() == nil {
		slog.Error("initial lifecycle sweep failed", "error", err)
	}
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Sweep(ctx); err != nil && ctx.Err() == nil {
				slog.Error("lifecycle sweep failed", "error", err)
			}
		}
	}
}

func (m *Manager) Sweep(ctx context.Context) error {
	now := m.now().UTC()
	forwards, err := m.store.ListExpiredPortForwards(ctx, now)
	if err != nil {
		return err
	}
	for _, forward := range forwards {
		if forward.NodeTaskID != nil {
			if err := m.nodes.DeletePortForward(ctx, forward.NodeID, *forward.NodeTaskID); err != nil {
				audit := systemAudit("port_forward.expire_cleanup_failed", "port_forward", forward.ID, "failed")
				if updateErr := m.store.SetPortForwardStatus(ctx, forward.ID, "cleanup_failed", audit); updateErr != nil {
					slog.Error("record expired port forward cleanup failure", "forward_id", forward.ID, "error", updateErr)
				}
				slog.Error("delete expired node port forward", "forward_id", forward.ID, "error", err)
				continue
			}
		}
		if err := m.store.DeletePortForward(ctx, forward.ID, systemAudit("port_forward.expire", "port_forward", forward.ID, "success")); err != nil {
			slog.Error("release expired port forward", "forward_id", forward.ID, "error", err)
		}
	}
	if _, err := m.store.ExpireAccessSessions(ctx, now); err != nil {
		return err
	}
	if _, err := m.store.CleanupAuthSessions(ctx, now); err != nil {
		return err
	}
	return nil
}

func systemAudit(action, resourceType, resourceID, result string) store.AuditInput {
	return store.AuditInput{Actor: "system", Action: action, ResourceType: resourceType, ResourceID: resourceID, Result: result}
}
