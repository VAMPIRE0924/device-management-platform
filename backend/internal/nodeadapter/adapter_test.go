package nodeadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

type fakeNodes struct {
	connection store.NodeConnection
}

func (f *fakeNodes) GetNodeConnection(context.Context, string) (store.NodeConnection, error) {
	return f.connection, nil
}

func (f *fakeNodes) UpdateNodeHealth(context.Context, string, string, time.Time) error { return nil }

type fakeSecrets struct{ value string }

func (f fakeSecrets) Resolve(context.Context, string) (string, error) { return f.value, nil }

func TestSignedAPIListsAndControlsManagedTunnels(t *testing.T) {
	tunnelRunning := false
	clientCreated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("timestamp") == "" || r.Form.Get("auth_key") == "" {
			t.Fatalf("signed parameters missing: %#v", r.Form)
		}
		switch r.URL.Path {
		case "/client/list":
			verifyKey := "existing-vkey"
			if clientCreated {
				verifyKey = "new-vkey"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 1, "Remark": "Client 1", "VerifyKey": verifyKey, "Cnf": map[string]any{"U": "basic-user", "P": "basic-password"}, "Status": true, "IsConnect": true, "Flow": map[string]any{"InletFlow": 10, "ExportFlow": 20}}}, "total": 1})
		case "/index/gettunnel":
			if r.Form.Get("type") != "socks5" {
				t.Fatalf("unexpected tunnel type %q", r.Form.Get("type"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 1, "Port": 10001, "Status": true, "RunStatus": tunnelRunning, "Client": map[string]any{"Id": 1, "Remark": "Client 1"}}}, "total": 1})
		case "/index/start":
			if r.Form.Get("id") != "1" || r.Form.Get("type") != "socks5" {
				t.Fatalf("unexpected start form: %#v", r.Form)
			}
			tunnelRunning = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/getclient":
			if r.Form.Get("id") != "1" {
				t.Fatalf("unexpected client form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"Id": 1, "VerifyKey": "existing-vkey", "Cnf": map[string]any{"U": "basic-user", "P": "basic-password"}}})
		case "/client/add":
			if r.Form.Get("vkey") != "new-vkey" || r.Form.Get("u") != "socks-user" || r.Form.Get("p") != "socks-password" {
				t.Fatalf("unexpected create client form: %#v", r.Form)
			}
			clientCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/del":
			if r.Form.Get("id") != "1" {
				t.Fatalf("unexpected delete client form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	clients, err := adapter.ListClients(t.Context(), "node-1")
	if err != nil || len(clients) != 1 || !clients[0].Connected {
		t.Fatalf("clients = %#v, err = %v", clients, err)
	}
	clientCredentials, err := adapter.ClientCredentials(t.Context(), "node-1", 1)
	if err != nil || clientCredentials.BasicUsername != "basic-user" || clientCredentials.BasicPassword != "basic-password" || clientCredentials.VerifyKey != "existing-vkey" {
		t.Fatalf("client credentials = %#v, err = %v", clientCredentials, err)
	}
	tunnels, err := adapter.ListManagedTunnels(t.Context(), "node-1")
	if err != nil || len(tunnels) != 1 || tunnels[0].Port != 10001 || tunnels[0].Running {
		t.Fatalf("tunnels = %#v, err = %v", tunnels, err)
	}
	if err := adapter.SetManagedTunnel(t.Context(), "node-1", 1, true); err != nil {
		t.Fatal(err)
	}
	route, err := adapter.SOCKSRoute(t.Context(), "node-1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if route.Address != "127.0.0.1:10001" || route.Username != "basic-user" || route.Password != "basic-password" {
		t.Fatalf("unexpected SOCKS route: %#v", route)
	}
	created, err := adapter.CreateClient(t.Context(), "node-1", "Client 1", "new-vkey", "socks-user", "socks-password")
	if err != nil || created.ID != 1 {
		t.Fatalf("created client = %#v, err = %v", created, err)
	}
	if err := adapter.DeleteClient(t.Context(), "node-1", 1); err != nil {
		t.Fatal(err)
	}
}

func TestManagedTunnelOperationFailsWhenNodeStateDoesNotChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/index/gettunnel":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 1, "Port": 10001, "Status": true, "RunStatus": false, "Client": map[string]any{"Id": 1}}}, "total": 1})
		case "/index/start":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "accepted but unchanged"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	adapter.stateWait = 25 * time.Millisecond
	err := adapter.SetManagedTunnel(t.Context(), "node-1", 1, true)
	if err == nil || !strings.Contains(err.Error(), "did not reach requested state") {
		t.Fatalf("expected state verification failure, got %v", err)
	}
}

func TestSessionLoginKeepsCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/verify":
			_ = r.ParseForm()
			if r.Form.Get("username") != "admin" || r.Form.Get("password") != "secret" {
				t.Fatal("missing login credentials")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/list":
			cookie, err := r.Cookie("session")
			if err != nil || cookie.Value != "ok" {
				t.Fatal("session cookie was not retained")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}, "total": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "session", Username: "admin", Password: "secret"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "file://secret", Enabled: true}}, fakeSecrets{value: string(credential)})
	if _, err := adapter.ListClients(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
}

func TestResolveEndpointPreservesBasePath(t *testing.T) {
	got, err := resolveEndpoint("https://node.example/internal/", "/client/list")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(got)
	if !strings.HasSuffix(parsed.Path, "/internal/client/list") {
		t.Fatalf("unexpected endpoint %s", got)
	}
}

func TestPortForwardLifecycle(t *testing.T) {
	created := false
	running := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("type") != "portForward" {
			t.Fatalf("unexpected task type: %#v", r.Form)
		}
		switch r.URL.Path {
		case "/index/gettunnel":
			rows := []map[string]any{}
			if created {
				rows = append(rows, map[string]any{"Id": 92, "Port": 22022, "Status": true, "RunStatus": running, "Remark": "device ssh", "Target": map[string]any{"TargetStr": "10.10.0.1:2222"}, "Client": map[string]any{"Id": 1, "Remark": "Client 1"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows, "total": len(rows)})
		case "/index/add":
			if r.Form.Get("client_id") != "1" || r.Form.Get("port") != "22022" || r.Form.Get("target") != "10.10.0.1:2222" {
				t.Fatalf("unexpected create form: %#v", r.Form)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/index/stop", "/index/start", "/index/del":
			if r.Form.Get("id") != "92" {
				t.Fatalf("unexpected lifecycle form: %#v", r.Form)
			}
			if r.URL.Path == "/index/stop" {
				running = false
			}
			if r.URL.Path == "/index/start" {
				running = true
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	forward, err := adapter.CreatePortForward(t.Context(), "node-1", 1, 22022, "10.10.0.1:2222", "device ssh")
	if err != nil {
		t.Fatal(err)
	}
	if forward.ID != 92 || forward.Target != "10.10.0.1:2222" || !forward.Running {
		t.Fatalf("unexpected forward: %#v", forward)
	}
	if err := adapter.SetPortForward(t.Context(), "node-1", 92, false); err != nil {
		t.Fatal(err)
	}
	if err := adapter.DeletePortForward(t.Context(), "node-1", 92); err != nil {
		t.Fatal(err)
	}
}

func TestPortForwardOperationFailsWhenNodeStateDoesNotChange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/index/stop":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "accepted"})
		case "/index/gettunnel":
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 92, "Port": 22022, "Status": true, "RunStatus": true, "Target": map[string]any{"TargetStr": "10.10.0.1:22"}, "Client": map[string]any{"Id": 1}}}, "total": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	adapter.stateWait = 25 * time.Millisecond
	err := adapter.SetPortForward(t.Context(), "node-1", 92, false)
	if err == nil || !strings.Contains(err.Error(), "did not reach requested state") {
		t.Fatalf("expected state confirmation timeout, got %v", err)
	}
}

func TestCreatePortForwardRejectsNodeWidePortCollision(t *testing.T) {
	addCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/index/gettunnel":
			if r.Form.Get("client_id") != "" {
				t.Fatalf("collision preflight must inspect the whole node: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 77, "Port": 22022, "Status": true, "RunStatus": true, "Target": map[string]any{"TargetStr": "10.20.0.5:22"}, "Client": map[string]any{"Id": 2, "Remark": "Other Client"}}}, "total": 1})
		case "/index/add":
			addCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "unexpected"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	_, err := adapter.CreatePortForward(t.Context(), "node-1", 1, 22022, "10.10.0.1:22", "ssh")
	if err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("expected node-wide port collision, got %v", err)
	}
	if addCalled {
		t.Fatal("adapter attempted to create a colliding listener")
	}
}
