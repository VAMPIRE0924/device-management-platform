package nodeadapter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

func TestLiveNPSContract(t *testing.T) {
	baseURL := os.Getenv("DMP_NPS_INTEGRATION_URL")
	authKey := os.Getenv("DMP_NPS_INTEGRATION_AUTH_KEY")
	if baseURL == "" || authKey == "" {
		t.Skip("set DMP_NPS_INTEGRATION_URL and DMP_NPS_INTEGRATION_AUTH_KEY to run against NPS")
	}
	credential, err := json.Marshal(Credential{Type: "signed", AuthKey: authKey})
	if err != nil {
		t.Fatal(err)
	}
	adapter := New(&fakeNodes{connection: store.NodeConnection{
		ID: "live-nps", APIURL: baseURL, CredentialRef: "env://LIVE_NPS", Enabled: true,
	}}, fakeSecrets{value: string(credential)})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	verifyKey := fmt.Sprintf("dmp-live-%d", time.Now().UnixNano())
	client, err := adapter.CreateClient(ctx, "live-nps", "DMP live contract", verifyKey, "dmp-live-user", "dmp-live-password")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = adapter.SetManagedTunnel(cleanupCtx, "live-nps", client.ID, false)
		_ = adapter.DeleteClient(cleanupCtx, "live-nps", client.ID)
	})
	if client.ID < 1 {
		t.Fatalf("created Client has invalid ID: %#v", client)
	}
	tunnels, err := adapter.ListManagedTunnels(ctx, "live-nps")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tunnel := range tunnels {
		if tunnel.ClientID == client.ID {
			found = true
			if tunnel.ID != client.ID || tunnel.Port < 1 || tunnel.Running {
				t.Fatalf("new managed SOCKS state = %#v", tunnel)
			}
		}
	}
	if !found {
		t.Fatalf("managed SOCKS for Client %d was not listed", client.ID)
	}
	if err := adapter.SetManagedTunnel(ctx, "live-nps", client.ID, true); err != nil {
		t.Fatal(err)
	}
	status, err := adapter.ManagedTunnelStatus(ctx, "live-nps", client.ID)
	if err != nil || !status.Running {
		t.Fatalf("started managed SOCKS status = %#v, err = %v", status, err)
	}
	route, err := adapter.SOCKSRoute(ctx, "live-nps", client.ID)
	if err != nil || route.Address == "" || route.Username != "dmp-live-user" || route.Password != "dmp-live-password" {
		t.Fatalf("managed SOCKS route = %#v, err = %v", route, err)
	}
	if err := adapter.SetManagedTunnel(ctx, "live-nps", client.ID, false); err != nil {
		t.Fatal(err)
	}
}

func TestLiveNPSReadOnlyStatus(t *testing.T) {
	baseURL := os.Getenv("DMP_NPS_READONLY_URL")
	authKey := os.Getenv("DMP_NPS_READONLY_AUTH_KEY")
	tlsServerName := os.Getenv("DMP_NPS_READONLY_TLS_SERVER_NAME")
	if baseURL == "" || authKey == "" {
		t.Skip("set DMP_NPS_READONLY_URL and DMP_NPS_READONLY_AUTH_KEY to run the read-only production probe")
	}
	credential, err := json.Marshal(Credential{Type: "signed", AuthKey: authKey})
	if err != nil {
		t.Fatal(err)
	}
	adapter := New(&fakeNodes{connection: store.NodeConnection{
		ID: "readonly-nps", APIURL: baseURL, TLSServerName: tlsServerName,
		CredentialRef: "env://READONLY_NPS", Enabled: true,
	}}, fakeSecrets{value: string(credential)})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	clients, err := adapter.ListClients(ctx, "readonly-nps")
	if err != nil {
		t.Fatal(err)
	}
	tunnels, err := adapter.ListManagedTunnels(ctx, "readonly-nps")
	if err != nil {
		t.Fatal(err)
	}
	running, active, countdown := 0, 0, 0
	for _, tunnel := range tunnels {
		if tunnel.Running {
			running++
		}
		if tunnel.Active {
			active++
		}
		if tunnel.Countdown {
			countdown++
			if tunnel.RemainingSeconds < 0 || tunnel.AutoCloseAt <= 0 {
				t.Fatal("NPS returned an invalid managed SOCKS countdown")
			}
		}
		if !tunnel.Running && (tunnel.Active || tunnel.Countdown || tunnel.RemainingSeconds != 0 || tunnel.AutoCloseAt != 0) {
			t.Fatal("stopped managed SOCKS returned live activity or countdown state")
		}
	}
	t.Logf("read-only NPS status verified: clients=%d managed_socks=%d running=%d active=%d countdown=%d", len(clients), len(tunnels), running, active, countdown)
}
