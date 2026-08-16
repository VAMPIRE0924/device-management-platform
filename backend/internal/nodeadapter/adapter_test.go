package nodeadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		for _, header := range []string{npsTimestampHeader, npsNonceHeader, npsSignatureHeader} {
			if r.Header.Get(header) == "" {
				t.Fatalf("signed header %s missing", header)
			}
		}
		if r.Form.Get("timestamp") != "" || r.Form.Get("auth_key") != "" {
			t.Fatalf("legacy signing parameters leaked into body: %#v", r.Form)
		}
		wantSignature := signNPSRequest(r.Method, pathWithRawQuery(r.URL), r.Header.Get(npsTimestampHeader), r.Header.Get(npsNonceHeader), body, "test-auth-key")
		if got := r.Header.Get(npsSignatureHeader); got != wantSignature {
			t.Fatalf("signature = %s, want %s for body %q", got, wantSignature, body)
		}
		switch r.URL.Path {
		case "/client/list/":
			verifyKey := "existing-vkey"
			if clientCreated {
				verifyKey = "new-vkey"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 1, "Remark": "Client 1", "VerifyKey": verifyKey, "Cnf": map[string]any{"U": "basic-user", "P": "basic-password"}, "Status": true, "IsConnect": true, "Flow": map[string]any{"InletFlow": 10, "ExportFlow": 20}}}, "total": 1})
		case "/index/gettunnel/":
			if r.Form.Get("type") != "socks5" {
				t.Fatalf("unexpected tunnel type %q", r.Form.Get("type"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 1, "Port": 10001, "Status": true, "RunStatus": tunnelRunning, "Client": map[string]any{"Id": 1, "Remark": "Client 1"}}}, "total": 1})
		case "/index/socksstatus/":
			if r.Form.Get("client_id") != "1" {
				t.Fatalf("unexpected SOCKS status form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{
				"id": 1, "client_id": 1, "enabled": tunnelRunning, "running": tunnelRunning,
				"active": false, "countdown": tunnelRunning, "remaining_seconds": 1200,
				"auto_close_at": 1800001200, "auto_close_timeout_seconds": 1800,
				"inlet_flow": 10, "export_flow": 20,
			}})
		case "/index/start/":
			if r.Form.Get("id") != "1" || r.Form.Get("type") != "socks5" {
				t.Fatalf("unexpected start form: %#v", r.Form)
			}
			tunnelRunning = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/getclient/":
			if r.Form.Get("id") != "1" {
				t.Fatalf("unexpected client form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"Id": 1, "VerifyKey": "existing-vkey", "Cnf": map[string]any{"U": "basic-user", "P": "basic-password"}}})
		case "/index/getonetunnel/":
			if r.Form.Get("id") != "1" || r.Form.Get("type") != "socks5" {
				t.Fatalf("unexpected tunnel detail form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"Id": 1, "Port": 10001}})
		case "/client/add/":
			if r.Form.Get("vkey") != "new-vkey" || r.Form.Get("u") != "socks-user" || r.Form.Get("p") != "socks-password" {
				t.Fatalf("unexpected create client form: %#v", r.Form)
			}
			clientCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/del/":
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
		case "/index/socksstatus/":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{"id": 1, "client_id": 1, "enabled": false, "running": false}})
		case "/index/start/":
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

func TestLegacySessionCredentialIsRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("legacy session credential must fail before an NPS request is sent")
	}))
	defer server.Close()
	credential := []byte(`{"type":"session","username":"admin","password":"secret"}`)
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "file://secret", Enabled: true}}, fakeSecrets{value: string(credential)})
	if _, err := adapter.ListClients(t.Context(), "node-1"); err == nil || !strings.Contains(err.Error(), "unsupported node credential type") {
		t.Fatalf("expected legacy credential rejection, got %v", err)
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
		case "/index/gettunnel/":
			rows := []map[string]any{}
			if created {
				rows = append(rows, map[string]any{"Id": 92, "Port": 22022, "Status": true, "RunStatus": running, "Remark": "device ssh", "Target": map[string]any{"TargetStr": "10.10.0.1:2222"}, "Client": map[string]any{"Id": 1, "Remark": "Client 1"}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": rows, "total": len(rows)})
		case "/index/add/":
			if r.Form.Get("client_id") != "1" || r.Form.Get("port") != "22022" || r.Form.Get("target") != "10.10.0.1:2222" {
				t.Fatalf("unexpected create form: %#v", r.Form)
			}
			created = true
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/index/stop/", "/index/start/", "/index/del/":
			if r.Form.Get("id") != "92" {
				t.Fatalf("unexpected lifecycle form: %#v", r.Form)
			}
			if r.URL.Path == "/index/stop/" {
				running = false
			}
			if r.URL.Path == "/index/start/" {
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
		case "/index/stop/":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "accepted"})
		case "/index/gettunnel/":
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
		case "/index/gettunnel/":
			if r.Form.Get("client_id") != "" {
				t.Fatalf("collision preflight must inspect the whole node: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"rows": []map[string]any{{"Id": 77, "Port": 22022, "Status": true, "RunStatus": true, "Target": map[string]any{"TargetStr": "10.20.0.5:22"}, "Client": map[string]any{"Id": 2, "Remark": "Other Client"}}}, "total": 1})
		case "/index/add/":
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

func TestUpdateClientReadsThenSendsCompleteForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/client/getclient/":
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "data": map[string]any{
				"Id": 7, "Remark": "old", "VerifyKey": "existing-verify-key", "RateLimit": 12,
				"MaxConn": 13, "MaxTunnelNum": 14, "WebUserName": "web-user", "WebPassword": "web-pass",
				"ConfigConnAllow": true, "Cnf": map[string]any{"U": "basic-user", "P": "basic-pass", "Compress": true, "Crypt": true},
				"Flow": map[string]any{"FlowLimit": 15},
			}})
		case "/client/edit/":
			want := map[string]string{
				"id": "7", "remark": "new remark", "vkey": "existing-verify-key", "u": "basic-user", "p": "basic-pass",
				"compress": "1", "crypt": "1", "config_conn_allow": "1", "rate_limit": "12", "flow_limit": "15",
				"max_conn": "13", "max_tunnel": "14", "web_username": "web-user", "web_password": "web-pass",
			}
			for key, value := range want {
				if got := r.Form.Get(key); got != value {
					t.Fatalf("complete client field %s = %q, want %q; form=%#v", key, got, value, r.Form)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		case "/client/basic/":
			if r.Form.Get("ids") != "7,9" || r.Form.Get("u") != "batch-user" || r.Form.Get("p") != "batch-pass" {
				t.Fatalf("unexpected atomic Basic update form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": 1, "msg": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-auth-key"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	remark := "new remark"
	if err := adapter.UpdateClient(t.Context(), "node-1", 7, ClientUpdate{Remark: &remark}); err != nil {
		t.Fatal(err)
	}
	if err := adapter.UpdateClientBasic(t.Context(), "node-1", []int{7, 9}, "batch-user", "batch-pass"); err != nil {
		t.Fatal(err)
	}
}

func TestCallSignsExactBodyWithBasePathAndRawQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		const wantBody = "item=first&item=second&value=%E8%AE%BE%E5%A4%87"
		if string(body) != wantBody {
			t.Fatalf("body = %q, want %q", body, wantBody)
		}
		if got := pathWithRawQuery(r.URL); got != "/nps/client/list/?scope=%2Fraw&order=b%2Ba" {
			t.Fatalf("signed request path = %q", got)
		}
		wantSignature := signNPSRequest(http.MethodPost, pathWithRawQuery(r.URL), "1800000000", "nonce-0123456789", body, "test-secret")
		if got := r.Header.Get(npsSignatureHeader); got != wantSignature {
			t.Fatalf("signature = %q, want %q", got, wantSignature)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}, "total": 0})
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-secret"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL + "/nps", CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	adapter.now = func() time.Time { return time.Unix(1800000000, 0) }
	adapter.nonce = func() (string, error) { return "nonce-0123456789", nil }
	var response tableResponse[rawClient]
	err := adapter.call(t.Context(), "node-1", "/client/list/?scope=%2Fraw&order=b%2Ba", url.Values{"value": {"设备"}, "item": {"first", "second"}}, &response)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCallClassifiesHTTPAndBusinessFailures(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		payload string
		kind    ErrorKind
	}{
		{name: "missing headers", status: http.StatusUnauthorized, payload: `{"msg":"missing API authentication headers"}`, kind: ErrorAuthentication},
		{name: "method", status: http.StatusMethodNotAllowed, payload: `{"msg":"method not allowed"}`, kind: ErrorMethod},
		{name: "status business", status: http.StatusOK, payload: `{"status":0,"msg":"rejected"}`, kind: ErrorBusiness},
		{name: "code business", status: http.StatusOK, payload: `{"code":0,"msg":"not found"}`, kind: ErrorBusiness},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.payload))
			}))
			defer server.Close()
			credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-secret"})
			adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
			var response map[string]any
			err := adapter.call(t.Context(), "node-1", "/client/list/", nil, &response)
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Kind != test.kind {
				t.Fatalf("error = %#v, want API kind %s", err, test.kind)
			}
		})
	}
}

func TestSeparateCallsUseSeparateNonces(t *testing.T) {
	nonces := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonces = append(nonces, r.Header.Get(npsNonceHeader))
		_ = json.NewEncoder(w).Encode(map[string]any{"rows": []any{}, "total": 0})
	}))
	defer server.Close()
	credential, _ := json.Marshal(Credential{Type: "signed", AuthKey: "test-secret"})
	adapter := New(&fakeNodes{connection: store.NodeConnection{ID: "node-1", APIURL: server.URL, CredentialRef: "env://NODE", Enabled: true}}, fakeSecrets{value: string(credential)})
	sequence := 0
	adapter.nonce = func() (string, error) {
		sequence++
		return "nonce-012345678" + strconv.Itoa(sequence), nil
	}
	if _, err := adapter.ListClients(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.ListClients(t.Context(), "node-1"); err != nil {
		t.Fatal(err)
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("request nonces = %#v", nonces)
	}
}
