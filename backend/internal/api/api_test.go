package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/auth"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/config"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/secrets"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/webroutelabel"
)

type fakeNodeControl struct {
	started          bool
	createdClients   int
	deletedClientIDs []int
	deleteClientErr  error
}

type fakeDiscoveryControl struct{}

type fakeEmailSender struct{}

var testEmailDelivery struct {
	sync.Mutex
	code string
}

func (fakeEmailSender) SendCode(_ context.Context, _ string, code string, _ time.Duration) error {
	testEmailDelivery.Lock()
	defer testEmailDelivery.Unlock()
	testEmailDelivery.code = code
	return nil
}

func deliveredEmailCode(t *testing.T) string {
	t.Helper()
	testEmailDelivery.Lock()
	defer testEmailDelivery.Unlock()
	if testEmailDelivery.code == "" {
		t.Fatal("email verification code was not delivered")
	}
	code := testEmailDelivery.code
	testEmailDelivery.code = ""
	return code
}

func (fakeDiscoveryControl) Start(context.Context, store.DiscoveryJob, store.DiscoveryRoute) error {
	return nil
}
func (fakeDiscoveryControl) Verify(_ context.Context, _ store.DiscoveryRoute, host string, ports []store.DiscoveryPort) ([]store.DiscoveryProbeResult, error) {
	results := make([]store.DiscoveryProbeResult, 0, len(ports))
	for _, port := range ports {
		results = append(results, store.DiscoveryProbeResult{Host: host, Port: port.Port, Protocol: port.Protocol, ServiceName: port.Name, Confidence: 100})
	}
	return results, nil
}
func (fakeDiscoveryControl) Cancel(string) bool { return true }

func (f *fakeNodeControl) Health(context.Context, string) nodeadapter.Health {
	return nodeadapter.Health{Reachable: true}
}

func (f *fakeNodeControl) ListClients(context.Context, string) ([]nodeadapter.Client, error) {
	return []nodeadapter.Client{{ID: 1, Remark: "Client 1", Connected: true}}, nil
}

func (f *fakeNodeControl) ClientCredentials(context.Context, string, int) (nodeadapter.ClientCredentials, error) {
	return nodeadapter.ClientCredentials{BasicUsername: "basic-user", BasicPassword: "basic-password", VerifyKey: "unique-vkey"}, nil
}

func (f *fakeNodeControl) ListManagedTunnels(context.Context, string) ([]nodeadapter.ManagedTunnel, error) {
	return []nodeadapter.ManagedTunnel{{ID: 1, ClientID: 1, Port: 10001, Running: true, Active: true, InletFlow: 1234, ExportFlow: 5678}}, nil
}

func (f *fakeNodeControl) ManagedTunnelStatus(context.Context, string, int) (nodeadapter.ManagedTunnel, error) {
	return nodeadapter.ManagedTunnel{ID: 1, ClientID: 1, Port: 10001, Configured: f.started, Running: f.started, Active: f.started, RemainingSeconds: 1800}, nil
}

func (f *fakeNodeControl) SetManagedTunnel(_ context.Context, _ string, _ int, running bool) error {
	f.started = running
	return nil
}

func (f *fakeNodeControl) SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error) {
	return nodeadapter.SOCKSRoute{Address: "127.0.0.1:1"}, nil
}

func (f *fakeNodeControl) CreatePortForward(_ context.Context, _ string, clientID, serverPort int, target, remark string) (nodeadapter.PortForward, error) {
	return nodeadapter.PortForward{ID: 91, Type: "portForward", ClientID: clientID, Port: serverPort, Target: target, Remark: remark, Running: true}, nil
}

func (f *fakeNodeControl) SetPortForward(context.Context, string, int, bool) error { return nil }

func (f *fakeNodeControl) DeletePortForward(context.Context, string, int) error { return nil }

func (f *fakeNodeControl) CreateClient(context.Context, string, string, string, string, string) (nodeadapter.Client, error) {
	f.createdClients++
	return nodeadapter.Client{ID: 28, Remark: "created"}, nil
}

func (f *fakeNodeControl) DeleteClient(_ context.Context, _ string, clientID int) error {
	f.deletedClientIDs = append(f.deletedClientIDs, clientID)
	return f.deleteClientErr
}

func testServer(t *testing.T) http.Handler {
	return testServerWithAccessDomain(t, "remote.example.test")
}

func namedCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func testServerWithAccessDomain(t *testing.T, accessDomain string) http.Handler {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	const browserToken = "browser-test-token"
	const browserCSRF = "browser-test-csrf"
	vault, err := secrets.LoadOrCreateNodeCredentialVault(db, filepath.Join(dir, "node-credentials.key"))
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Store: db, Nodes: &fakeNodeControl{}, NodeCredentials: vault, Discovery: fakeDiscoveryControl{}, APIToken: "test-token", AccessDomain: accessDomain, AccessScheme: "https", Mode: "pro", Version: "test", MFA: testMFA(t), MFAEnabled: true, MFAMethods: []string{"totp", "email"}, EmailSender: fakeEmailSender{}, EmailCodeTTL: 10 * time.Minute, TLSConfigured: true})
	var browserSessionMu sync.Mutex
	browserSessionCreated := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == "/api/v1/access-sessions" || r.URL.Path == "/api/v1/access-sessions/launch") {
			if _, cookieErr := r.Cookie(authCookieName); cookieErr != nil {
				browserSessionMu.Lock()
				if !browserSessionCreated {
					users, listErr := db.ListUsers(r.Context())
					if listErr != nil {
						browserSessionMu.Unlock()
						t.Fatal(listErr)
					}
					var admin store.User
					if len(users) == 0 {
						passwordHash, hashErr := auth.HashPassword("test administrator password")
						if hashErr != nil {
							browserSessionMu.Unlock()
							t.Fatal(hashErr)
						}
						admin, listErr = db.CreateInitialAdmin(r.Context(), store.CreateUserInput{Username: "test-admin", DisplayName: "Test Admin", PasswordHash: passwordHash}, store.AuditInput{Actor: "system", Action: "test.bootstrap", ResourceType: "user", Result: "success"})
					} else {
						admin = users[0]
					}
					if listErr == nil {
						_, listErr = db.CreateAuthSession(r.Context(), admin.ID, digestString(browserToken), digestString(browserCSRF), time.Now().Add(time.Hour))
					}
					if listErr != nil {
						browserSessionMu.Unlock()
						t.Fatal(listErr)
					}
					browserSessionCreated = true
				}
				browserSessionMu.Unlock()
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: authCookieName, Value: browserToken})
				if r.URL.Path == "/api/v1/access-sessions" {
					r.Header.Set("X-CSRF-Token", browserCSRF)
				}
			}
		}
		handler.ServeHTTP(w, r)
	})
}

func testMFA(t *testing.T) *auth.MFA {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "mfa.key")
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := auth.LoadOrCreateMFA(keyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func completeTestMFA(t *testing.T, handler http.Handler, login *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	var challenge struct {
		ChallengeToken string `json:"challengeToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.ChallengeToken == "" {
		t.Fatalf("invalid MFA challenge: %s", login.Body.String())
	}
	password := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/password", map[string]any{"challengeToken": challenge.ChallengeToken, "newPassword": "a new permanent password"}, false)
	if password.Code != http.StatusOK {
		t.Fatalf("onboarding password = %d: %s", password.Code, password.Body.String())
	}
	sent := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/email/send", map[string]any{"challengeToken": challenge.ChallengeToken, "email": "user@example.test"}, false)
	if sent.Code != http.StatusOK {
		t.Fatalf("onboarding email send = %d: %s", sent.Code, sent.Body.String())
	}
	verified := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/email/verify", map[string]any{"challengeToken": challenge.ChallengeToken, "code": deliveredEmailCode(t)}, false)
	if verified.Code != http.StatusOK {
		t.Fatalf("onboarding email verify = %d: %s", verified.Code, verified.Body.String())
	}
	started := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/start", map[string]any{"challengeToken": challenge.ChallengeToken, "method": "totp"}, false)
	if started.Code != http.StatusOK {
		t.Fatalf("MFA enrollment start = %d: %s", started.Code, started.Body.String())
	}
	var enrollment struct {
		Enrollment struct {
			ManualKey string `json:"manualKey"`
		} `json:"enrollment"`
	}
	if err := json.Unmarshal(started.Body.Bytes(), &enrollment); err != nil || enrollment.Enrollment.ManualKey == "" {
		t.Fatalf("invalid MFA enrollment: %s", started.Body.String())
	}
	return request(t, handler, http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challengeToken": challenge.ChallengeToken, "code": currentTestTOTP(enrollment.Enrollment.ManualKey, time.Now())}, false)
}

func currentTestTOTP(secret string, now time.Time) string {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(now.UTC().Unix()/30))
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(buffer)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}

func request(t *testing.T, handler http.Handler, method, path string, body any, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	var payload bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&payload).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &payload)
	if authenticated {
		req.Header.Set("Authorization", "Bearer test-token")
	}
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func configureProjectNetworks(t *testing.T, handler http.Handler, project store.Project, networks ...string) store.Project {
	t.Helper()
	response := request(t, handler, http.MethodPatch, "/api/v1/projects/"+project.ID, map[string]any{"name": project.Name, "ownerName": project.OwnerName, "networks": networks}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("configure project networks = %d: %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	return project
}

func TestCanonicalCIDRsAcceptsSingleIPAndDoesNotHideInvalidInput(t *testing.T) {
	got := canonicalCIDRs([]string{
		"10.10.0.1",
		"10.10.0.1/32",
		"10.10.0.42/24",
		"invalid-range",
		"  ",
	})
	want := []string{"10.10.0.1/32", "10.10.0.0/24", "invalid-range"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("canonical discovery networks = %#v, want %#v", got, want)
	}
	clientID := 1
	validInput := store.CreateProjectInput{Name: "project", NodeID: "node", OwnerName: "owner", ClientID: &clientID}
	if fields := validateProject(validInput); fields["networks"] != "" {
		t.Fatalf("empty optional discovery range was rejected: %#v", fields)
	}
	validInput.Networks = canonicalCIDRs([]string{"10.10.0.1"})
	if fields := validateProject(validInput); fields["networks"] != "" {
		t.Fatalf("single-IP discovery range was rejected: %#v", fields)
	}
	validInput.Networks = canonicalCIDRs([]string{"not-an-ip"})
	if fields := validateProject(validInput); fields["networks"] == "" {
		t.Fatalf("invalid discovery range was silently discarded: %#v", fields)
	}
}

func TestHealthAndAuthentication(t *testing.T) {
	handler := testServer(t)
	if got := request(t, handler, http.MethodGet, "/health/ready", nil, false).Code; got != http.StatusOK {
		t.Fatalf("ready status = %d", got)
	}
	if got := request(t, handler, http.MethodGet, "/api/v1/meta", nil, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", got)
	}
	if got := request(t, handler, http.MethodGet, "/api/v1/meta", nil, true).Code; got != http.StatusOK {
		t.Fatalf("meta status = %d", got)
	}
}

func TestDevelopmentModeDoesNotGrantImplicitAdministrator(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Store: db, Nodes: &fakeNodeControl{}, Mode: "dev", Version: "test"})
	response := request(t, handler, http.MethodGet, "/api/v1/nodes", nil, false)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("implicit development authentication status = %d: %s", response.Code, response.Body.String())
	}
}

func TestPasswordChangeRequiredWithoutMFA(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Store: db, Nodes: &fakeNodeControl{}, APIToken: "test-token", Mode: "pro", Version: "test", MFAEnabled: false})
	created := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "password-only-user", "displayName": "仅改密用户", "password": "temporary password value", "role": "operator", "enabled": true,
	}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create user = %d: %s", created.Code, created.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "password-only-user", "password": "temporary password value"}, false)
	var challenge struct {
		Next           string   `json:"next"`
		ChallengeToken string   `json:"challengeToken"`
		Steps          []string `json:"steps"`
	}
	if login.Code != http.StatusAccepted || json.Unmarshal(login.Body.Bytes(), &challenge) != nil || challenge.Next != "onboard" || len(challenge.Steps) != 1 || challenge.Steps[0] != "password" {
		t.Fatalf("password challenge = %d: %s", login.Code, login.Body.String())
	}
	completed := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/password", map[string]any{"challengeToken": challenge.ChallengeToken, "newPassword": "permanent password value"}, false)
	if completed.Code != http.StatusOK || !bytes.Contains(completed.Body.Bytes(), []byte(`"passwordChangeRequired":false`)) || len(completed.Result().Cookies()) != 2 {
		t.Fatalf("password completion = %d: %s", completed.Code, completed.Body.String())
	}
	if completed.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("password completion cache policy = %q", completed.Header().Get("Cache-Control"))
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "password-only-user", "password": "temporary password value"}, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("temporary password remained valid: %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "password-only-user", "password": "permanent password value"}, false); response.Code != http.StatusOK {
		t.Fatalf("permanent password login = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/password", map[string]any{"challengeToken": challenge.ChallengeToken, "newPassword": "another permanent password"}, false); response.Code != http.StatusGone {
		t.Fatalf("consumed challenge reuse = %d: %s", response.Code, response.Body.String())
	}
}

func TestRequestIDValidationAndCSVFormulaNeutralization(t *testing.T) {
	handler := testServer(t)
	valid := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	valid.Header.Set("X-Request-ID", "trace_123:child-1")
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if got := validResponse.Header().Get("X-Request-ID"); got != "trace_123:child-1" {
		t.Fatalf("valid request id = %q", got)
	}
	invalid := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	invalid.Header.Set("X-Request-ID", "=FORMULA("+strings.Repeat("x", 256))
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	if got := invalidResponse.Header().Get("X-Request-ID"); got == invalid.Header.Get("X-Request-ID") || !validRequestID(got) {
		t.Fatalf("invalid request id was reflected or replacement invalid: %q", got)
	}
	for _, input := range []string{"=1+1", " +cmd", "-2", "@SUM(A1)", "\tformula", "\rformula"} {
		if got := safeCSVCell(input); !strings.HasPrefix(got, "'") {
			t.Errorf("unsafe CSV cell %q was not neutralized: %q", input, got)
		}
	}
	if got := safeCSVCell("normal value"); got != "normal value" {
		t.Fatalf("normal CSV cell changed: %q", got)
	}
}

func TestAuthSessionIdleTimeoutRevokesSession(t *testing.T) {
	handler, db, token, sessionID := idleSessionTestServer(t, 15*time.Minute)
	if err := db.TouchAuthSession(t.Context(), sessionID, time.Now().UTC().Add(-16*time.Minute)); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	req.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "session_idle_timeout") {
		t.Fatalf("idle session status = %d: %s", response.Code, response.Body.String())
	}
	if _, err := db.ResolveAuthSession(t.Context(), digestString(token)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("idle auth session was not revoked: %v", err)
	}
}

func TestOnlyExplicitBrowserActivityTouchesAuthSession(t *testing.T) {
	handler, db, token, _ := idleSessionTestServer(t, 15*time.Minute)
	before, err := db.ResolveAuthSession(t.Context(), digestString(token))
	if err != nil {
		t.Fatal(err)
	}
	background := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	background.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
	backgroundResponse := httptest.NewRecorder()
	handler.ServeHTTP(backgroundResponse, background)
	if backgroundResponse.Code != http.StatusOK {
		t.Fatalf("background request = %d: %s", backgroundResponse.Code, backgroundResponse.Body.String())
	}
	afterBackground, err := db.ResolveAuthSession(t.Context(), digestString(token))
	if err != nil {
		t.Fatal(err)
	}
	if !afterBackground.LastSeenAt.Equal(before.LastSeenAt) {
		t.Fatalf("background polling extended session: before=%s after=%s", before.LastSeenAt, afterBackground.LastSeenAt)
	}

	time.Sleep(2 * time.Millisecond)
	active := httptest.NewRequest(http.MethodGet, "/api/v1/meta", nil)
	active.AddCookie(&http.Cookie{Name: authCookieName, Value: token})
	active.Header.Set("X-DMP-User-Activity", "1")
	activeResponse := httptest.NewRecorder()
	handler.ServeHTTP(activeResponse, active)
	if activeResponse.Code != http.StatusOK {
		t.Fatalf("active request = %d: %s", activeResponse.Code, activeResponse.Body.String())
	}
	afterActive, err := db.ResolveAuthSession(t.Context(), digestString(token))
	if err != nil {
		t.Fatal(err)
	}
	if !afterActive.LastSeenAt.After(afterBackground.LastSeenAt) {
		t.Fatalf("explicit browser activity did not extend session: before=%s after=%s", afterBackground.LastSeenAt, afterActive.LastSeenAt)
	}
}

func idleSessionTestServer(t *testing.T, idleTTL time.Duration) (http.Handler, *store.Store, string, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "idle-session.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	passwordHash, err := auth.HashPassword("test administrator password")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := db.CreateInitialAdmin(t.Context(), store.CreateUserInput{Username: "idle-admin", DisplayName: "Idle Admin", PasswordHash: passwordHash}, store.AuditInput{Actor: "system", Action: "test.bootstrap", ResourceType: "user", Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	const token = "idle-session-browser-token"
	session, err := db.CreateAuthSession(t.Context(), admin.ID, digestString(token), digestString("idle-csrf"), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	handler := New(Dependencies{Store: db, Nodes: &fakeNodeControl{}, Mode: "pro", Version: "test", AuthSessionIdleTTL: idleTTL})
	return handler, db, token, session.ID
}

func TestSystemAdminCanPersistSecuritySettingsWithoutSecretDisclosure(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		ConfigFile: filepath.Join(dir, "platform.conf"), OverrideFile: filepath.Join(dir, "settings.override.conf"), Mode: "dev",
		ListenAddress: "127.0.0.1:18080", DataDirectory: dir, DatabasePath: filepath.Join(dir, "api.db"),
		MFAEnabled: false, MFAMethods: []string{"totp"}, MFAKeyFile: filepath.Join(dir, "mfa.key"), EmailCodeTTL: 10 * time.Minute,
		SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https",
	}
	handler := New(Dependencies{Store: db, Nodes: &fakeNodeControl{}, APIToken: "test-token", Mode: "dev", Version: "test", Settings: config.NewSettingsManager(cfg)})
	response := request(t, handler, http.MethodPut, "/api/v1/settings/security", map[string]any{
		"mfaEnabled": true, "mfaMethods": []string{"totp", "email"}, "emailCodeTTL": "10m", "mfaKeyFile": cfg.MFAKeyFile,
		"smtpHost": "smtp.example.test", "smtpPort": 587, "smtpUsername": "notifier@example.test", "smtpPassword": "smtp-api-test-secret",
		"smtpFrom": "设备管理平台 <notifier@example.test>", "tlsCertFile": "", "tlsKeyFile": "", "accessTlsCertFile": "", "accessTlsKeyFile": "", "httpPort": 80, "httpsPort": 443, "reusePanelPorts": true, "accessHttpPort": 0, "accessHttpsPort": 0, "accessDomain": "remote.example.test",
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("save settings = %d: %s", response.Code, response.Body.String())
	}
	if bytes.Contains(response.Body.Bytes(), []byte("smtp-api-test-secret")) || !bytes.Contains(response.Body.Bytes(), []byte(`"restartRequired":true`)) {
		t.Fatalf("unsafe or incomplete settings response: %s", response.Body.String())
	}
	loaded := request(t, handler, http.MethodGet, "/api/v1/settings/security", nil, true)
	if loaded.Code != http.StatusOK || bytes.Contains(loaded.Body.Bytes(), []byte("smtp-api-test-secret")) || !bytes.Contains(loaded.Body.Bytes(), []byte(`"smtpPasswordConfigured":true`)) {
		t.Fatalf("get settings = %d: %s", loaded.Code, loaded.Body.String())
	}
	audit := request(t, handler, http.MethodGet, "/api/v1/audit-logs?search=settings.security_update", nil, true)
	if audit.Code != http.StatusOK || !bytes.Contains(audit.Body.Bytes(), []byte("settings.security_update")) {
		t.Fatalf("settings audit = %d: %s", audit.Code, audit.Body.String())
	}
}

func TestTrustedProxySourceOnlyAcceptsConfiguredPeer(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	s := &server{trustedProxyCIDRs: []netip.Prefix{prefix}}
	var source string
	handler := s.trustedProxySource(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { source = requestSourceIP(r) }))
	trustedRequest := httptest.NewRequest(http.MethodGet, "http://platform.test/", nil)
	trustedRequest.RemoteAddr = "10.0.0.8:12345"
	trustedRequest.Header.Set("X-Forwarded-For", "198.51.100.24, 10.0.0.8")
	handler.ServeHTTP(httptest.NewRecorder(), trustedRequest)
	if source != "198.51.100.24" {
		t.Fatalf("trusted proxy source = %q", source)
	}
	untrustedRequest := httptest.NewRequest(http.MethodGet, "http://platform.test/", nil)
	untrustedRequest.RemoteAddr = "192.0.2.9:12345"
	untrustedRequest.Header.Set("X-Forwarded-For", "198.51.100.99")
	untrustedRequest.Header.Set("X-Forwarded-Proto", "https")
	handler.ServeHTTP(httptest.NewRecorder(), untrustedRequest)
	if source != "192.0.2.9" {
		t.Fatalf("untrusted proxy spoof was accepted: %q", source)
	}
	var forwardedProto string
	s.trustedProxySource(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		forwardedProto = r.Header.Get("X-Forwarded-Proto")
	})).ServeHTTP(httptest.NewRecorder(), untrustedRequest)
	if forwardedProto != "" {
		t.Fatalf("untrusted forwarded protocol reached authentication: %q", forwardedProto)
	}
}

func TestSessionCookieSecurityFollowsRequestProtocol(t *testing.T) {
	s := &server{}
	expiresAt := time.Now().Add(time.Hour)

	httpRequest := httptest.NewRequest(http.MethodPost, "http://platform.test/api/v1/auth/login", nil)
	httpResponse := httptest.NewRecorder()
	s.setAuthCookies(httpResponse, httpRequest, "token", "csrf", expiresAt)
	for _, cookie := range httpResponse.Result().Cookies() {
		if cookie.Secure {
			t.Fatalf("plain HTTP cookie %s unexpectedly marked Secure", cookie.Name)
		}
	}

	httpsRequest := httptest.NewRequest(http.MethodPost, "https://platform.test/api/v1/auth/login", nil)
	httpsResponse := httptest.NewRecorder()
	s.setAuthCookies(httpsResponse, httpsRequest, "token", "csrf", expiresAt)
	for _, cookie := range httpsResponse.Result().Cookies() {
		if !cookie.Secure {
			t.Fatalf("HTTPS cookie %s must be marked Secure", cookie.Name)
		}
	}

	proxyRequest := httptest.NewRequest(http.MethodPost, "http://platform.test/api/v1/auth/login", nil)
	proxyRequest.Header.Set("X-Forwarded-Proto", "https")
	proxyResponse := httptest.NewRecorder()
	s.setAuthCookies(proxyResponse, proxyRequest, "token", "csrf", expiresAt)
	for _, cookie := range proxyResponse.Result().Cookies() {
		if !cookie.Secure {
			t.Fatalf("trusted HTTPS proxy cookie %s must be marked Secure", cookie.Name)
		}
	}
}

func TestAccessDomainLaunchAndProxyHeaderIsolation(t *testing.T) {
	handler := testServerWithAccessDomain(t, "remote.example.test")
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "会话域名节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 22000, "portEnd": 22999,
	}, true)
	if nodeResponse.Code != http.StatusCreated {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	var node store.Node
	if err := json.Unmarshal(nodeResponse.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	projectResponse := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "会话域名项目", "nodeId": node.ID, "ownerName": "管理员", "clientId": 1,
	}, true)
	if projectResponse.Code != http.StatusCreated {
		t.Fatalf("create project = %d: %s", projectResponse.Code, projectResponse.Body.String())
	}
	var project store.Project
	if err := json.Unmarshal(projectResponse.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	project = configureProjectNetworks(t, handler, project, "10.10.0.0/16")
	deviceResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices", map[string]any{
		"host": "10.10.0.1", "name": "设备后台", "deviceType": "network", "source": "manual", "endpoints": []map[string]any{{"name": "管理后台", "protocol": "http", "targetPort": 80}},
	}, true)
	if deviceResponse.Code != http.StatusCreated {
		t.Fatalf("create device = %d: %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	var device store.Device
	if err := json.Unmarshal(deviceResponse.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	missingCSRFForm := url.Values{"endpointId": {device.Endpoints[0].ID}}
	missingCSRFRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access-sessions/launch", strings.NewReader(missingCSRFForm.Encode()))
	missingCSRFRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRFResponse, missingCSRFRequest)
	if missingCSRFResponse.Code != http.StatusForbidden {
		t.Fatalf("Web launch form without CSRF = %d: %s", missingCSRFResponse.Code, missingCSRFResponse.Body.String())
	}
	launchForm := url.Values{"endpointId": {device.Endpoints[0].ID}, "csrfToken": {"browser-test-csrf"}}
	launchFormRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access-sessions/launch", strings.NewReader(launchForm.Encode()))
	launchFormRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	launchFormResponse := httptest.NewRecorder()
	handler.ServeHTTP(launchFormResponse, launchFormRequest)
	if launchFormResponse.Code != http.StatusOK {
		t.Fatalf("Web launch form = %d: %s", launchFormResponse.Code, launchFormResponse.Body.String())
	}
	launchPage := launchFormResponse.Body.String()
	for _, expected := range []string{"I5CLOUD 远程管理平台", `method="post"`, `/.dmp/session`, `name="grant"`, `document.getElementById('dmp-web-launch').submit()`} {
		if !strings.Contains(launchPage, expected) {
			t.Fatalf("Web launch page missing %q: %s", expected, launchPage)
		}
	}
	if strings.Contains(launchPage, "#grant=") || strings.Contains(launchPage, "about:blank") || strings.Contains(launchPage, "browser-test-csrf") {
		t.Fatalf("Web launch page exposed an unsafe navigation flow: %s", launchPage)
	}
	if got := launchFormResponse.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Web launch Referrer-Policy = %q", got)
	}
	sessionResponse := request(t, handler, http.MethodPost, "/api/v1/access-sessions", map[string]any{"endpointId": device.Endpoints[0].ID, "mode": "web"}, true)
	if sessionResponse.Code != http.StatusCreated {
		t.Fatalf("create session = %d: %s", sessionResponse.Code, sessionResponse.Body.String())
	}
	var session struct {
		LaunchURL string    `json:"launchUrl"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.Unmarshal(sessionResponse.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	launchURL, err := url.Parse(session.LaunchURL)
	if err != nil {
		t.Fatal(err)
	}
	if launchURL.Scheme != "https" || !strings.HasSuffix(launchURL.Hostname(), ".remote.example.test") || !strings.HasPrefix(launchURL.Fragment, "grant=") || launchURL.RawQuery != "" {
		t.Fatalf("unexpected access-domain URL: %s", session.LaunchURL)
	}
	if launchURL.Path != "/.dmp/authorize" {
		t.Fatalf("Web launch must use the dedicated authorization endpoint: %s", session.LaunchURL)
	}
	grant := strings.TrimPrefix(launchURL.Fragment, "grant=")
	if decoded, decodeErr := hex.DecodeString(grant); decodeErr != nil || len(decoded) != 24 {
		t.Fatalf("launch fragment does not contain a valid one-time grant: %q", launchURL.Fragment)
	}
	remaining := time.Until(session.ExpiresAt)
	if remaining < 55*time.Minute || remaining > 61*time.Minute {
		t.Fatalf("access session expiry %s does not follow the platform login expiry", remaining)
	}
	token := strings.TrimSuffix(launchURL.Hostname(), ".remote.example.test")
	unauthorizedRequest := httptest.NewRequest(http.MethodGet, "https://"+token+".remote.example.test/", nil)
	unauthorizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedResponse, unauthorizedRequest)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("access route without grant = %d, want 401", unauthorizedResponse.Code)
	}
	queryGrantRequest := httptest.NewRequest(http.MethodGet, "https://"+launchURL.Host+"/?grant="+grant, nil)
	queryGrantResponse := httptest.NewRecorder()
	handler.ServeHTTP(queryGrantResponse, queryGrantRequest)
	if queryGrantResponse.Code != http.StatusUnauthorized || len(queryGrantResponse.Result().Cookies()) != 0 {
		t.Fatalf("Web query grant unexpectedly authorized access: status=%d cookies=%d", queryGrantResponse.Code, len(queryGrantResponse.Result().Cookies()))
	}
	exchangeRequest := httptest.NewRequest(http.MethodPost, "https://"+launchURL.Host+"/.dmp/session", strings.NewReader(`{"grant":"`+grant+`"}`))
	exchangeRequest.Header.Set("Content-Type", "application/json")
	exchangeRequest.Header.Set("Origin", "https://"+launchURL.Host)
	exchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(exchangeResponse, exchangeRequest)
	accessCookie := namedCookie(exchangeResponse.Result().Cookies(), "dmp_access_grant")
	if exchangeResponse.Code != http.StatusNoContent || accessCookie == nil {
		t.Fatalf("grant exchange = %d cookies=%d: %s", exchangeResponse.Code, len(exchangeResponse.Result().Cookies()), exchangeResponse.Body.String())
	}
	replayRequest := httptest.NewRequest(http.MethodPost, "https://"+launchURL.Host+"/.dmp/session", strings.NewReader(`{"grant":"`+grant+`"}`))
	replayRequest.Header.Set("Content-Type", "application/json")
	replayRequest.Header.Set("Origin", "https://"+launchURL.Host)
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusGone || len(replayResponse.Result().Cookies()) != 0 {
		t.Fatalf("one-time Web grant was replayable: status=%d cookies=%d", replayResponse.Code, len(replayResponse.Result().Cookies()))
	}
	proxyRequest := httptest.NewRequest(http.MethodGet, "https://"+token+".remote.example.test/", nil)
	proxyRequest.AddCookie(accessCookie)
	proxyResponse := httptest.NewRecorder()
	handler.ServeHTTP(proxyResponse, proxyRequest)
	if got := proxyResponse.Header().Get("Permissions-Policy"); got != "" {
		t.Fatalf("device application inherited control-plane Permissions-Policy: %q", got)
	}
	if got := proxyResponse.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("device application inherited control-plane frame policy: %q", got)
	}
	reopenedResponse := request(t, handler, http.MethodPost, "/api/v1/access-sessions", map[string]any{"endpointId": device.Endpoints[0].ID, "mode": "web"}, true)
	if reopenedResponse.Code != http.StatusCreated {
		t.Fatalf("reopen session = %d: %s", reopenedResponse.Code, reopenedResponse.Body.String())
	}
	var reopened struct {
		LaunchURL string `json:"launchUrl"`
	}
	if err := json.Unmarshal(reopenedResponse.Body.Bytes(), &reopened); err != nil {
		t.Fatal(err)
	}
	reopenedURL, err := url.Parse(reopened.LaunchURL)
	if err != nil {
		t.Fatal(err)
	}
	if reopenedURL.Hostname() == launchURL.Hostname() {
		t.Fatalf("independent Web sessions reused a routing host: first=%s reopened=%s", launchURL.Hostname(), reopenedURL.Hostname())
	}
	if reopenedURL.Fragment == launchURL.Fragment {
		t.Fatal("reopened access reused the one-time grant")
	}
	// Every random Web hostname must bootstrap its own host-scoped grant before
	// proxying device content.
	reopenBootstrapRequest := httptest.NewRequest(http.MethodGet, reopenedURL.Scheme+"://"+reopenedURL.Host+reopenedURL.EscapedPath(), nil)
	reopenBootstrapResponse := httptest.NewRecorder()
	handler.ServeHTTP(reopenBootstrapResponse, reopenBootstrapRequest)
	if reopenBootstrapResponse.Code != http.StatusOK || !strings.Contains(reopenBootstrapResponse.Body.String(), ".dmp/session") {
		t.Fatalf("reopen bootstrap with stale cookie at %s = %d: %s", reopenedURL.String(), reopenBootstrapResponse.Code, reopenBootstrapResponse.Body.String())
	}
	reopenedGrant := strings.TrimPrefix(reopenedURL.Fragment, "grant=")
	reopenExchangeRequest := httptest.NewRequest(http.MethodPost, "https://"+reopenedURL.Host+"/.dmp/session", strings.NewReader(`{"grant":"`+reopenedGrant+`"}`))
	reopenExchangeRequest.Header.Set("Content-Type", "application/json")
	reopenExchangeRequest.Header.Set("Origin", "https://"+reopenedURL.Host)
	reopenExchangeResponse := httptest.NewRecorder()
	handler.ServeHTTP(reopenExchangeResponse, reopenExchangeRequest)
	reopenedAccessCookie := namedCookie(reopenExchangeResponse.Result().Cookies(), "dmp_access_grant")
	if reopenExchangeResponse.Code != http.StatusNoContent || reopenedAccessCookie == nil {
		t.Fatalf("reopen grant exchange = %d cookies=%d: %s", reopenExchangeResponse.Code, len(reopenExchangeResponse.Result().Cookies()), reopenExchangeResponse.Body.String())
	}
	previousRequest := httptest.NewRequest(http.MethodGet, "https://"+token+".remote.example.test/", nil)
	previousRequest.AddCookie(accessCookie)
	previousResponse := httptest.NewRecorder()
	handler.ServeHTTP(previousResponse, previousRequest)
	if previousResponse.Code == http.StatusUnauthorized || previousResponse.Code == http.StatusGone || previousResponse.Code == http.StatusForbidden {
		t.Fatalf("independent previous Web session stopped working: status=%d", previousResponse.Code)
	}
	reopenedToken := strings.TrimSuffix(reopenedURL.Hostname(), ".remote.example.test")
	refreshedRequest := httptest.NewRequest(http.MethodGet, "https://"+reopenedToken+".remote.example.test/", nil)
	refreshedRequest.AddCookie(reopenedAccessCookie)
	refreshedResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshedResponse, refreshedRequest)
	if refreshedResponse.Code == http.StatusUnauthorized || refreshedResponse.Code == http.StatusGone || refreshedResponse.Code == http.StatusForbidden {
		t.Fatalf("new grant did not authorize reopened Web route: status=%d body=%s", refreshedResponse.Code, refreshedResponse.Body.String())
	}
	activeResponse := request(t, handler, http.MethodGet, "/api/v1/access-sessions", nil, true)
	if activeResponse.Code != http.StatusOK {
		t.Fatalf("list active sessions = %d: %s", activeResponse.Code, activeResponse.Body.String())
	}
	var active struct {
		Items []store.AccessSession `json:"items"`
	}
	if err := json.Unmarshal(activeResponse.Body.Bytes(), &active); err != nil {
		t.Fatal(err)
	}
	prefixes := make(map[string]struct{}, len(active.Items))
	for _, item := range active.Items {
		if item.ID == "" || !webroutelabel.IsCurrent(item.DomainPrefix) {
			t.Fatalf("active Web session omitted its short random prefix: %#v", item)
		}
		prefixes[item.DomainPrefix] = struct{}{}
	}
	if len(active.Items) != 3 || len(prefixes) != len(active.Items) {
		t.Fatalf("independent Web sessions were not listed with distinct random prefixes: %#v", active.Items)
	}
}

func TestOpaqueWebRouteLabelsAreAcceptedWithoutOpeningArbitraryHosts(t *testing.T) {
	label, err := webroutelabel.New()
	if err != nil {
		t.Fatal(err)
	}
	if !validAccessRouteLabel(label) {
		t.Fatalf("generated opaque route label was rejected: %q", label)
	}
	if validAccessRouteLabel("web-short") || validAccessRouteLabel("web-iiiiiiii") || validAccessRouteLabel("arbitrary") {
		t.Fatal("invalid Web route labels were accepted")
	}
}

func TestAccessSessionIdleTTLNeverExceedsManagedSOCKSLimit(t *testing.T) {
	for _, test := range []struct {
		authIdle time.Duration
		want     time.Duration
	}{
		{authIdle: 15 * time.Minute, want: 15 * time.Minute},
		{authIdle: 30 * time.Minute, want: nodeadapter.ManagedSOCKSIdleTTL},
		{authIdle: 2 * time.Hour, want: nodeadapter.ManagedSOCKSIdleTTL},
	} {
		server := &server{authSessionIdleTTL: test.authIdle}
		if got := server.accessSessionIdleTTL(); got != test.want {
			t.Fatalf("access idle TTL for auth %s = %s, want %s", test.authIdle, got, test.want)
		}
	}
}

func TestAccessSessionDomainPrefixAcceptsOnlyStoredCurrentRoute(t *testing.T) {
	userID := "user-one"
	endpointID := "endpoint-one"
	randomLabel, err := webroutelabel.New()
	if err != nil {
		t.Fatal(err)
	}
	randomSession := store.AccessSession{Mode: "web", UserID: &userID, EndpointID: endpointID, TokenHash: accessTokenHash(randomLabel), DomainPrefix: randomLabel}
	if actual := accessSessionDomainPrefix(randomSession); actual != randomLabel {
		t.Fatalf("random domain prefix = %q, want %q", actual, randomLabel)
	}
	for _, session := range []store.AccessSession{
		{Mode: "web", UserID: &userID, EndpointID: endpointID, TokenHash: accessTokenHash(randomLabel)},
		{Mode: "web", UserID: &userID, EndpointID: endpointID, TokenHash: accessTokenHash(randomLabel), DomainPrefix: "invalid-route"},
		{Mode: "web", UserID: &userID, EndpointID: endpointID, TokenHash: accessTokenHash("web-deadbeef"), DomainPrefix: randomLabel},
	} {
		if actual := accessSessionDomainPrefix(session); actual != "" {
			t.Fatalf("invalid, missing, or mismatched domain prefix was exposed: %q", actual)
		}
	}
	if actual := accessSessionDomainPrefix(store.AccessSession{Mode: "ssh", UserID: &userID, EndpointID: endpointID, TokenHash: accessTokenHash(randomLabel), DomainPrefix: randomLabel}); actual != "" {
		t.Fatalf("SSH session exposed a domain prefix: %q", actual)
	}
	encoded, err := json.Marshal(store.AccessSession{Mode: "web", UserID: &userID, EndpointID: endpointID, TokenHash: "sensitive-hash", DomainPrefix: randomLabel})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sensitive-hash") || !strings.Contains(string(encoded), `"domainPrefix":"`+randomLabel+`"`) {
		t.Fatalf("serialized access session leaked the token hash or omitted its domain prefix: %s", encoded)
	}
}

func TestConfiguredPanelAndAccessDomainsAreStrictlySeparated(t *testing.T) {
	server := &server{panelDomain: "dmp.example.test", accessDomain: "console.example.test"}
	opaqueRoute, err := webroutelabel.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		host       string
		path       string
		wantStatus int
		wantPath   string
	}{
		{name: "panel", host: "dmp.example.test:4043", path: "/login", wantStatus: http.StatusNoContent, wantPath: "/login"},
		{name: "panel cannot use internal Web route", host: "dmp.example.test:4043", path: "/access/web/" + opaqueRoute + "/", wantStatus: http.StatusNotFound},
		{name: "opaque access route", host: opaqueRoute + ".console.example.test:4043", path: "/cgi-bin/luci/", wantStatus: http.StatusNoContent, wantPath: "/access/web/" + opaqueRoute + "/cgi-bin/luci/"},
		{name: "invalid short child", host: "web-short.console.example.test:4043", path: "/cgi-bin/luci/", wantStatus: http.StatusNotFound},
		{name: "invalid long child", host: "invalid-route-label-that-is-too-long.console.example.test:4043", path: "/login", wantStatus: http.StatusNotFound},
		{name: "arbitrary access child", host: "anything.console.example.test:4043", path: "/login", wantStatus: http.StatusNotFound},
		{name: "bare access domain", host: "console.example.test:4043", path: "/login", wantStatus: http.StatusNotFound},
		{name: "unknown panel host", host: "other.example.test:4043", path: "/login", wantStatus: http.StatusNotFound},
		{name: "loopback panel denied", host: "127.0.0.1:4043", path: "/login", wantStatus: http.StatusNotFound},
		{name: "loopback readiness allowed", host: "127.0.0.1:4043", path: "/health/ready", wantStatus: http.StatusNoContent, wantPath: "/health/ready"},
	} {
		t.Run(test.name, func(t *testing.T) {
			forwardedPath := ""
			handler := server.accessDomainRouting(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwardedPath = r.URL.Path
				w.WriteHeader(http.StatusNoContent)
			}))
			request := httptest.NewRequest(http.MethodGet, "https://"+test.host+test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || forwardedPath != test.wantPath {
				t.Fatalf("status/path = %d/%q, want %d/%q", response.Code, forwardedPath, test.wantStatus, test.wantPath)
			}
		})
	}
}

func TestDevelopmentAccessDomainLaunchPreservesLocalPort(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/v1/access-sessions", nil)
	launchURL := webAccessLaunchURL(request, "http", "localhost", "dev", "web-01234567", 3000, true)
	want := "http://web-01234567.localhost:3000/"
	if launchURL != want {
		t.Fatalf("launch URL = %q, want %q", launchURL, want)
	}

	productionURL := webAccessLaunchURL(request, "https", "remote.example.test", "pro", "web-12345678", 443, true)
	productionWant := "https://web-12345678.remote.example.test/"
	if productionURL != productionWant {
		t.Fatalf("production launch URL = %q, want %q", productionURL, productionWant)
	}

	customHTTPSRequest := httptest.NewRequest(http.MethodPost, "https://console.example.test:4043/api/v1/access-sessions", nil)
	customHTTPSURL := webAccessLaunchURL(customHTTPSRequest, "https", "console.example.test", "pro", "web-23456789", 4043, true)
	customHTTPSWant := "https://web-23456789.console.example.test:4043/"
	if customHTTPSURL != customHTTPSWant {
		t.Fatalf("custom HTTPS launch URL = %q, want %q", customHTTPSURL, customHTTPSWant)
	}
	proxiedHTTPSRequest := httptest.NewRequest(http.MethodPost, "https://console.example.test/api/v1/access-sessions", nil)
	proxiedHTTPSURL := webAccessLaunchURL(proxiedHTTPSRequest, "https", "console.example.test", "pro", "web-3456789a", 4043, true)
	proxiedHTTPSWant := "https://web-3456789a.console.example.test/"
	if proxiedHTTPSURL != proxiedHTTPSWant {
		t.Fatalf("default external HTTPS launch URL = %q, want %q", proxiedHTTPSURL, proxiedHTTPSWant)
	}

	localProductionURL := webAccessLaunchURL(request, "http", "admin.platform.localhost", "pro", "web-456789ab", 3000, true)
	localProductionWant := "http://web-456789ab.admin.platform.localhost:3000/"
	if localProductionURL != localProductionWant {
		t.Fatalf("local production launch URL = %q, want %q", localProductionURL, localProductionWant)
	}

	localDNSURL := webAccessLaunchURL(request, "http", "admin.platform.127.0.0.1.nip.io", "pro", "web-56789abc", 3000, true)
	localDNSWant := "http://web-56789abc.admin.platform.127.0.0.1.nip.io:3000/"
	if localDNSURL != localDNSWant {
		t.Fatalf("local wildcard DNS launch URL = %q, want %q", localDNSURL, localDNSWant)
	}

	independentURL := webAccessLaunchURL(customHTTPSRequest, "https", "console.example.test", "pro", "web-6789abcd", 5443, false)
	independentWant := "https://web-6789abcd.console.example.test:5443/"
	if independentURL != independentWant {
		t.Fatalf("independent access port URL = %q, want %q", independentURL, independentWant)
	}
}

func TestFirstRunSetupIsSingleUse(t *testing.T) {
	handler := testServer(t)
	status := request(t, handler, http.MethodGet, "/api/v1/setup/status", nil, false)
	if status.Code != http.StatusOK || !bytes.Contains(status.Body.Bytes(), []byte(`"initialized":false`)) {
		t.Fatalf("setup status = %d: %s", status.Code, status.Body.String())
	}
	created := request(t, handler, http.MethodPost, "/api/v1/setup", map[string]any{"username": "first-admin", "displayName": "首位管理员", "password": "correct horse battery staple"}, false)
	if created.Code != http.StatusCreated {
		t.Fatalf("setup = %d: %s", created.Code, created.Body.String())
	}
	again := request(t, handler, http.MethodPost, "/api/v1/setup", map[string]any{"username": "second-admin", "displayName": "第二管理员", "password": "correct horse battery staple"}, false)
	if again.Code != http.StatusConflict {
		t.Fatalf("second setup = %d: %s", again.Code, again.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "first-admin", "password": "correct horse battery staple"}, false)
	if login.Code != http.StatusAccepted {
		t.Fatalf("first admin login = %d: %s", login.Code, login.Body.String())
	}
	if completed := completeTestMFA(t, handler, login); completed.Code != http.StatusOK {
		t.Fatalf("first admin MFA enrollment = %d: %s", completed.Code, completed.Body.String())
	}
}

func TestCreateNodeAndProject(t *testing.T) {
	handler := testServer(t)
	unsupportedCredential := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "未配置外部密钥节点", "apiUrl": "https://unsupported.test:6443", "tlsServerName": "unsupported.test", "credentialRef": "vault://nodes/unsupported", "portStart": 21000, "portEnd": 21999,
	}, true)
	if unsupportedCredential.Code != http.StatusBadRequest {
		t.Fatalf("unsupported credential reference status = %d: %s", unsupportedCredential.Code, unsupportedCredential.Body.String())
	}
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "测试节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 22000, "portEnd": 22999,
	}, true)
	if nodeResponse.Code != http.StatusCreated {
		t.Fatalf("create node status = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	var node store.Node
	if err := json.Unmarshal(nodeResponse.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	clientID := 1
	projectResponse := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "真实验收项目", "nodeId": node.ID, "ownerName": "管理员", "clientId": clientID,
	}, true)
	if projectResponse.Code != http.StatusCreated {
		t.Fatalf("create project status = %d: %s", projectResponse.Code, projectResponse.Body.String())
	}
	var project store.Project
	if err := json.Unmarshal(projectResponse.Body.Bytes(), &project); err != nil {
		t.Fatal(err)
	}
	if len(project.Networks) != 0 {
		t.Fatalf("project created without a discovery range = %#v", project.Networks)
	}
	project = configureProjectNetworks(t, handler, project, "10.10.0.1")
	if len(project.Networks) != 1 || project.Networks[0] != "10.10.0.1/32" {
		t.Fatalf("single-IP project discovery range = %#v", project.Networks)
	}
	project = configureProjectNetworks(t, handler, project, "10.10.0.0/16", "192.168.1.0/24")
	temporaryUserResponse := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "temporary-user", "displayName": "临时运维", "password": "temporary access password", "role": "temporary",
	}, true)
	if temporaryUserResponse.Code != http.StatusCreated {
		t.Fatalf("create temporary user status = %d: %s", temporaryUserResponse.Code, temporaryUserResponse.Body.String())
	}
	var temporaryUser store.User
	if err := json.Unmarshal(temporaryUserResponse.Body.Bytes(), &temporaryUser); err != nil {
		t.Fatal(err)
	}
	policyResponse := request(t, handler, http.MethodPost, "/api/v1/access-policies", map[string]any{
		"name": "项目 Web 临时访问", "projectIds": []string{project.ID}, "userIds": []string{temporaryUser.ID}, "capabilities": []string{"web"},
	}, true)
	if policyResponse.Code != http.StatusCreated || !bytes.Contains(policyResponse.Body.Bytes(), []byte("项目 Web 临时访问")) {
		t.Fatalf("create access policy status = %d: %s", policyResponse.Code, policyResponse.Body.String())
	}
	unsupportedPolicy := request(t, handler, http.MethodPost, "/api/v1/access-policies", map[string]any{
		"name": "错误管理授权", "projectIds": []string{project.ID}, "userIds": []string{temporaryUser.ID}, "capabilities": []string{"port_forward"},
	}, true)
	if unsupportedPolicy.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported policy capability status = %d: %s", unsupportedPolicy.Code, unsupportedPolicy.Body.String())
	}
	operatorResponse := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "project-operator", "displayName": "项目运维", "password": "project operator password", "role": "operator", "projectIds": []string{project.ID},
	}, true)
	if operatorResponse.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d: %s", operatorResponse.Code, operatorResponse.Body.String())
	}
	var operator store.User
	if err := json.Unmarshal(operatorResponse.Body.Bytes(), &operator); err != nil {
		t.Fatal(err)
	}
	nonTemporaryPolicy := request(t, handler, http.MethodPost, "/api/v1/access-policies", map[string]any{
		"name": "错误角色授权", "projectIds": []string{project.ID}, "userIds": []string{operator.ID}, "capabilities": []string{"web"},
	}, true)
	if nonTemporaryPolicy.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-temporary policy status = %d: %s", nonTemporaryPolicy.Code, nonTemporaryPolicy.Body.String())
	}
	discoveryResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/discovery-jobs", map[string]any{
		"networks": []string{"10.10.0.0/24"}, "ports": []map[string]any{{"port": 3000, "protocol": "http", "name": "AdGuard Home"}, {"port": 2222, "protocol": "ssh", "name": "SSH 维护"}},
	}, true)
	if discoveryResponse.Code != http.StatusAccepted || !bytes.Contains(discoveryResponse.Body.Bytes(), []byte("AdGuard Home")) {
		t.Fatalf("create discovery status = %d: %s", discoveryResponse.Code, discoveryResponse.Body.String())
	}
	deviceResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices", map[string]any{
		"host": "10.10.0.1", "name": "OpenWrt", "deviceType": "network", "vendor": "OpenWrt", "source": "manual", "endpoints": []map[string]any{{"name": "LuCI", "protocol": "https", "targetPort": 9443, "tlsServerName": "router.test"}, {"name": "AdGuard Home", "protocol": "http", "targetPort": 3000}, {"name": "设备维护", "protocol": "ssh", "targetPort": 2222, "sshCredential": map[string]any{"method": "password", "username": "root", "password": "ssh-password"}, "sshHostKeyFingerprint": "SHA256:test-host-key"}},
	}, true)
	if deviceResponse.Code != http.StatusCreated || !bytes.Contains(deviceResponse.Body.Bytes(), []byte("AdGuard Home")) {
		t.Fatalf("create device status = %d: %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	var device store.Device
	if err := json.Unmarshal(deviceResponse.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	if device.Endpoints[0].TLSServerName != "router.test" || !device.Endpoints[2].CredentialConfigured || device.Endpoints[2].SSHHostKeyFingerprint != "SHA256:test-host-key" {
		t.Fatalf("endpoint trust configuration was not returned: %#v", device.Endpoints)
	}
	verifyResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices/"+device.ID+"/verify", nil, true)
	if verifyResponse.Code != http.StatusOK || !bytes.Contains(verifyResponse.Body.Bytes(), []byte(`"verified":3`)) || !bytes.Contains(verifyResponse.Body.Bytes(), []byte(`"status":"online"`)) {
		t.Fatalf("verify device status = %d: %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	for _, endpoint := range device.Endpoints {
		if endpoint.VerificationStatus != "unverified" {
			t.Fatalf("create response should remain an unverified snapshot: %#v", device.Endpoints)
		}
	}
	sessionResponse := request(t, handler, http.MethodPost, "/api/v1/access-sessions", map[string]any{"endpointId": device.Endpoints[0].ID, "mode": "web"}, true)
	if sessionResponse.Code != http.StatusCreated || bytes.Contains(sessionResponse.Body.Bytes(), []byte("10.10.0.1")) || !bytes.Contains(sessionResponse.Body.Bytes(), []byte(".remote.example.test/")) {
		t.Fatalf("create session status = %d: %s", sessionResponse.Code, sessionResponse.Body.String())
	}
	var sessionResult struct {
		SessionID string `json:"sessionId"`
		LaunchURL string `json:"launchUrl"`
	}
	if err := json.Unmarshal(sessionResponse.Body.Bytes(), &sessionResult); err != nil {
		t.Fatal(err)
	}
	if len(sessionResult.LaunchURL) < 50 {
		t.Fatalf("launch URL is not opaque enough: %s", sessionResult.LaunchURL)
	}
	forwardResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/port-forwards", map[string]any{"endpointId": device.Endpoints[2].ID, "serverPort": 22000}, true)
	if forwardResponse.Code != http.StatusCreated || !bytes.Contains(forwardResponse.Body.Bytes(), []byte("10.10.0.1:2222")) {
		t.Fatalf("create port forward status = %d: %s", forwardResponse.Code, forwardResponse.Body.String())
	}
	var forward store.PortForward
	if err := json.Unmarshal(forwardResponse.Body.Bytes(), &forward); err != nil {
		t.Fatal(err)
	}
	stopForward := request(t, handler, http.MethodPost, "/api/v1/port-forwards/"+forward.ID+"/stop", nil, true)
	if stopForward.Code != http.StatusOK || !bytes.Contains(stopForward.Body.Bytes(), []byte("stopped")) {
		t.Fatalf("stop port forward status = %d: %s", stopForward.Code, stopForward.Body.String())
	}
	listForwards := request(t, handler, http.MethodGet, "/api/v1/projects/"+project.ID+"/port-forwards", nil, true)
	if listForwards.Code != http.StatusOK || !bytes.Contains(listForwards.Body.Bytes(), []byte("22000")) {
		t.Fatalf("list port forwards status = %d: %s", listForwards.Code, listForwards.Body.String())
	}
	deleteForward := request(t, handler, http.MethodDelete, "/api/v1/port-forwards/"+forward.ID, nil, true)
	if deleteForward.Code != http.StatusNoContent {
		t.Fatalf("delete port forward status = %d: %s", deleteForward.Code, deleteForward.Body.String())
	}
	activeSessions := request(t, handler, http.MethodGet, "/api/v1/access-sessions", nil, true)
	if activeSessions.Code != http.StatusOK || !bytes.Contains(activeSessions.Body.Bytes(), []byte(sessionResult.SessionID)) {
		t.Fatalf("active sessions status = %d: %s", activeSessions.Code, activeSessions.Body.String())
	}
	revokeSession := request(t, handler, http.MethodDelete, "/api/v1/access-sessions/"+sessionResult.SessionID, nil, true)
	if revokeSession.Code != http.StatusNoContent {
		t.Fatalf("revoke session status = %d: %s", revokeSession.Code, revokeSession.Body.String())
	}
	accessLogs := request(t, handler, http.MethodGet, "/api/v1/access-logs?search="+url.QueryEscape(sessionResult.SessionID), nil, true)
	if accessLogs.Code != http.StatusOK || !bytes.Contains(accessLogs.Body.Bytes(), []byte(sessionResult.SessionID)) || !bytes.Contains(accessLogs.Body.Bytes(), []byte("OpenWrt")) || !bytes.Contains(accessLogs.Body.Bytes(), []byte("LuCI")) || !bytes.Contains(accessLogs.Body.Bytes(), []byte(`"status":"revoked"`)) {
		t.Fatalf("access log status = %d: %s", accessLogs.Code, accessLogs.Body.String())
	}
	for _, secret := range []string{"tokenHash", "grantHash", "node-password", "ssh-password"} {
		if bytes.Contains(accessLogs.Body.Bytes(), []byte(secret)) {
			t.Fatalf("access log disclosed %q: %s", secret, accessLogs.Body.String())
		}
	}
	operationOnly := request(t, handler, http.MethodGet, "/api/v1/audit-logs?category=operation&search=access_session", nil, true)
	if operationOnly.Code != http.StatusOK || !bytes.Contains(operationOnly.Body.Bytes(), []byte(`"items":[]`)) || bytes.Contains(operationOnly.Body.Bytes(), []byte(sessionResult.SessionID)) {
		t.Fatalf("access session events leaked into operation log: %d %s", operationOnly.Code, operationOnly.Body.String())
	}
	accessExport := request(t, handler, http.MethodGet, "/api/v1/access-logs/export?search="+url.QueryEscape(sessionResult.SessionID), nil, true)
	if accessExport.Code != http.StatusOK || !strings.Contains(accessExport.Header().Get("Content-Disposition"), "access-logs.csv") || !bytes.Contains(accessExport.Body.Bytes(), []byte(sessionResult.SessionID)) {
		t.Fatalf("access log export = %d %q: %s", accessExport.Code, accessExport.Header().Get("Content-Disposition"), accessExport.Body.String())
	}
	updateProject := request(t, handler, http.MethodPatch, "/api/v1/projects/"+project.ID, map[string]any{
		"name": "真实验收项目 A", "ownerName": "系统管理员", "networks": []string{"10.10.0.0/16", "192.168.1.0/24"},
	}, true)
	if updateProject.Code != http.StatusOK || !bytes.Contains(updateProject.Body.Bytes(), []byte("真实验收项目 A")) {
		t.Fatalf("update project status = %d: %s", updateProject.Code, updateProject.Body.String())
	}
	updateDevice := request(t, handler, http.MethodPatch, "/api/v1/projects/"+project.ID+"/devices/"+device.ID, map[string]any{"name": "OpenWrt 主网关", "deviceType": "network", "vendor": "OpenWrt 24.10"}, true)
	if updateDevice.Code != http.StatusOK || !bytes.Contains(updateDevice.Body.Bytes(), []byte("OpenWrt 主网关")) {
		t.Fatalf("update device status = %d: %s", updateDevice.Code, updateDevice.Body.String())
	}
	outsideResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices", map[string]any{
		"host": "172.18.0.3", "name": "容器地址", "deviceType": "other", "source": "manual", "endpoints": []map[string]any{},
	}, true)
	if outsideResponse.Code != http.StatusCreated {
		t.Fatalf("manually added target outside discovery range was rejected: %d %s", outsideResponse.Code, outsideResponse.Body.String())
	}
	listResponse := request(t, handler, http.MethodGet, "/api/v1/projects", nil, true)
	if listResponse.Code != http.StatusOK || !bytes.Contains(listResponse.Body.Bytes(), []byte("10.10.0.0/16")) {
		t.Fatalf("list projects status = %d: %s", listResponse.Code, listResponse.Body.String())
	}
	auditResponse := request(t, handler, http.MethodGet, "/api/v1/audit-logs?limit=200", nil, true)
	if auditResponse.Code != http.StatusOK {
		t.Fatalf("list audit logs status = %d: %s", auditResponse.Code, auditResponse.Body.String())
	}
	for _, secret := range []string{"node-password", "ssh-password"} {
		if bytes.Contains(auditResponse.Body.Bytes(), []byte(secret)) {
			t.Fatalf("audit log disclosed submitted credential %q: %s", secret, auditResponse.Body.String())
		}
	}
}

func TestNodeAuthKeyIsWriteOnlyAndCanBeReplaced(t *testing.T) {
	handler := testServer(t)
	created := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "加密认证节点", "apiUrl": "https://secure-node.test:6443", "tlsServerName": "secure-node.test",
		"credential": map[string]any{"type": "signed", "authKey": "initial-node-auth-key-0123456789-ab"},
		"portStart":  23000, "portEnd": 23999,
	}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create encrypted node = %d: %s", created.Code, created.Body.String())
	}
	if bytes.Contains(created.Body.Bytes(), []byte("initial-node-auth-key-0123456789-ab")) || bytes.Contains(created.Body.Bytes(), []byte("db://")) {
		t.Fatalf("node credential leaked in response: %s", created.Body.String())
	}
	var node store.Node
	if err := json.Unmarshal(created.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	if !node.CredentialConfigured {
		t.Fatal("encrypted node credential was not marked configured")
	}

	updated := request(t, handler, http.MethodPatch, "/api/v1/nodes/"+node.ID, map[string]any{
		"name": node.Name, "apiUrl": node.APIURL, "tlsServerName": node.TLSServerName,
		"credential": map[string]any{"type": "signed", "authKey": "replacement-node-auth-key-01234567"},
		"portStart":  node.PortStart, "portEnd": node.PortEnd, "enabled": true,
	}, true)
	if updated.Code != http.StatusOK {
		t.Fatalf("replace encrypted node auth key = %d: %s", updated.Code, updated.Body.String())
	}
	if bytes.Contains(updated.Body.Bytes(), []byte("replacement-node-auth-key-01234567")) || bytes.Contains(updated.Body.Bytes(), []byte("db://")) {
		t.Fatalf("updated node credential leaked in response: %s", updated.Body.String())
	}

	forbidden := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "伪造密文引用", "apiUrl": "https://forbidden.test:6443", "tlsServerName": "forbidden.test",
		"credentialRef": "db://node/" + node.ID, "portStart": 24000, "portEnd": 24999,
	}, true)
	if forbidden.Code != http.StatusBadRequest {
		t.Fatalf("internal credential reference status = %d: %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestNodeClientsAreReadOnlyAndCanBeCreated(t *testing.T) {
	handler := testServer(t)
	createdNode := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "Client 管理节点", "apiUrl": "https://client-node.test:6443", "tlsServerName": "client-node.test",
		"credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 25000, "portEnd": 25999,
	}, true)
	if createdNode.Code != http.StatusCreated {
		t.Fatalf("create client node = %d: %s", createdNode.Code, createdNode.Body.String())
	}
	var node store.Node
	if err := json.Unmarshal(createdNode.Body.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	listing := request(t, handler, http.MethodGet, "/api/v1/nodes/"+node.ID+"/clients", nil, true)
	if listing.Code != http.StatusOK || !bytes.Contains(listing.Body.Bytes(), []byte(`"total":1`)) {
		t.Fatalf("list clients = %d: %s", listing.Code, listing.Body.String())
	}
	created := request(t, handler, http.MethodPost, "/api/v1/nodes/"+node.ID+"/clients", map[string]any{"remark": "新增只读 Client", "basicUsername": "new-basic-user", "basicPassword": "new-basic-password", "verifyKey": "new-unique-vkey"}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create client = %d: %s", created.Code, created.Body.String())
	}
	if !bytes.Contains(created.Body.Bytes(), []byte(`"client"`)) || !bytes.Contains(created.Body.Bytes(), []byte(`"credentials"`)) || bytes.Contains(created.Body.Bytes(), []byte(`"bootstrap"`)) || bytes.Contains(created.Body.Bytes(), []byte(`"serverPort"`)) {
		t.Fatalf("client create response = %s", created.Body.String())
	}
	autoGenerated := request(t, handler, http.MethodPost, "/api/v1/nodes/"+node.ID+"/clients", map[string]any{"remark": "自动生成凭据 Client", "basicUsername": "required-user", "basicPassword": "", "verifyKey": ""}, true)
	if autoGenerated.Code != http.StatusCreated {
		t.Fatalf("auto-generate client credentials = %d: %s", autoGenerated.Code, autoGenerated.Body.String())
	}
	var generated struct {
		Credentials nodeadapter.ClientCredentials `json:"credentials"`
	}
	if err := json.Unmarshal(autoGenerated.Body.Bytes(), &generated); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"password": generated.Credentials.BasicPassword, "verifyKey": generated.Credentials.VerifyKey} {
		if len(value) != 16 || strings.Trim(value, "0123456789abcdefghijklmnopqrstuvwxyz") != "" {
			t.Fatalf("generated %s does not match NPS credential format: %q", name, value)
		}
	}
	credentials := request(t, handler, http.MethodGet, "/api/v1/nodes/"+node.ID+"/clients/1/credentials", nil, true)
	if credentials.Code != http.StatusOK || credentials.Header().Get("Cache-Control") != "no-store" || !bytes.Contains(credentials.Body.Bytes(), []byte(`"basicUsername":"basic-user"`)) || !bytes.Contains(credentials.Body.Bytes(), []byte(`"verifyKey":"unique-vkey"`)) {
		t.Fatalf("client credentials = %d: %s", credentials.Code, credentials.Body.String())
	}
	deleted := request(t, handler, http.MethodDelete, "/api/v1/nodes/"+node.ID+"/clients/28", nil, true)
	if deleted.Code != http.StatusNotFound && deleted.Code != http.StatusMethodNotAllowed {
		t.Fatalf("client delete endpoint unexpectedly exists: %d", deleted.Code)
	}
}

func TestMonitorSnapshotUsesRealNodeCounters(t *testing.T) {
	handler := testServer(t)
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "监控节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 24000, "portEnd": 24999,
	}, true)
	if nodeResponse.Code != http.StatusCreated {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	snapshotResponse := request(t, handler, http.MethodGet, "/api/v1/monitor/snapshot", nil, true)
	if snapshotResponse.Code != http.StatusOK {
		t.Fatalf("monitor snapshot = %d: %s", snapshotResponse.Code, snapshotResponse.Body.String())
	}
	var snapshot struct {
		DatabaseStatus string `json:"databaseStatus"`
		NodeTotal      int    `json:"nodeTotal"`
		NodeReachable  int    `json:"nodeReachable"`
		TunnelTotal    int    `json:"tunnelTotal"`
		TunnelRunning  int    `json:"tunnelRunning"`
		InletFlow      int64  `json:"inletFlow"`
		ExportFlow     int64  `json:"exportFlow"`
		Nodes          []struct {
			Status         string `json:"status"`
			Reachable      bool   `json:"reachable"`
			TunnelCount    int    `json:"tunnelCount"`
			RunningTunnels int    `json:"runningTunnels"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(snapshotResponse.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.DatabaseStatus != "ready" || snapshot.NodeTotal != 1 || snapshot.NodeReachable != 1 || snapshot.TunnelTotal != 1 || snapshot.TunnelRunning != 1 || snapshot.InletFlow != 1234 || snapshot.ExportFlow != 5678 {
		t.Fatalf("unexpected monitor snapshot: %+v", snapshot)
	}
	if len(snapshot.Nodes) != 1 || !snapshot.Nodes[0].Reachable || snapshot.Nodes[0].Status != "healthy" || snapshot.Nodes[0].TunnelCount != 1 || snapshot.Nodes[0].RunningTunnels != 1 {
		t.Fatalf("unexpected node snapshot: %+v", snapshot.Nodes)
	}
}

func TestRejectsUnsafeOrIncompleteInput(t *testing.T) {
	handler := testServer(t)
	response := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "", "apiUrl": "https://10.0.0.2:6443", "portStart": 70000, "portEnd": 1,
	}, true)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("validation status = %d: %s", response.Code, response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte("tlsServerName")) || !bytes.Contains(response.Body.Bytes(), []byte("portRange")) {
		t.Fatalf("missing validation fields: %s", response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte("credential")) {
		t.Fatalf("missing node credential was not rejected: %s", response.Body.String())
	}
}

func TestManagedTunnelRoutesUseCompositeIdentity(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "tunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	control := &fakeNodeControl{}
	handler := New(Dependencies{Store: db, Nodes: control, APIToken: "test-token", Mode: "pro", Version: "test"})
	response := request(t, handler, http.MethodPost, "/api/v1/nodes/node-1/managed-tunnels/1/start", nil, true)
	if response.Code != http.StatusOK || !control.started {
		t.Fatalf("start tunnel status = %d: %s", response.Code, response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"active":true`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"remainingSeconds":1800`)) {
		t.Fatalf("start tunnel did not return fresh runtime state: %s", response.Body.String())
	}
	list := request(t, handler, http.MethodGet, "/api/v1/nodes/node-1/managed-tunnels", nil, true)
	if list.Code != http.StatusOK || !bytes.Contains(list.Body.Bytes(), []byte("10001")) {
		t.Fatalf("list tunnel status = %d: %s", list.Code, list.Body.String())
	}
}

func TestProjectDeletionLifecycle(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "project-delete.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.LoadOrCreateNodeCredentialVault(db, filepath.Join(dir, "node-credentials.key"))
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeNodeControl{}
	handler := New(Dependencies{Store: db, Nodes: control, NodeCredentials: vault, Discovery: fakeDiscoveryControl{}, APIToken: "test-token", Mode: "pro", Version: "test"})
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "项目删除节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 28000, "portEnd": 28999,
	}, true)
	var node store.Node
	if nodeResponse.Code != http.StatusCreated || json.Unmarshal(nodeResponse.Body.Bytes(), &node) != nil {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	createProject := func(name string, clientID int) store.Project {
		t.Helper()
		response := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
			"name": name, "nodeId": node.ID, "ownerName": "管理员", "clientId": clientID,
		}, true)
		var project store.Project
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &project) != nil {
			t.Fatalf("create %s = %d: %s", name, response.Code, response.Body.String())
		}
		return project
	}

	bound := createProject("绑定既有 Client", 1)
	if control.createdClients != 0 {
		t.Fatalf("project creation must not create node Client, got %d calls", control.createdClients)
	}
	if response := request(t, handler, http.MethodDelete, "/api/v1/projects/"+bound.ID, nil, true); response.Code != http.StatusNoContent {
		t.Fatalf("delete bound project = %d: %s", response.Code, response.Body.String())
	}
	if len(control.deletedClientIDs) != 0 {
		t.Fatalf("bound client must be preserved, deleted = %v", control.deletedClientIDs)
	}

	if response := request(t, handler, http.MethodGet, "/api/v1/projects", nil, true); response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(bound.ID)) {
		t.Fatalf("deleted projects remained = %d: %s", response.Code, response.Body.String())
	}
}

func TestProjectDeletionBlocksDependenciesAndNodeFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "project-delete-conflict.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.LoadOrCreateNodeCredentialVault(db, filepath.Join(dir, "node-credentials.key"))
	if err != nil {
		t.Fatal(err)
	}
	control := &fakeNodeControl{}
	handler := New(Dependencies{Store: db, Nodes: control, NodeCredentials: vault, Discovery: fakeDiscoveryControl{}, APIToken: "test-token", Mode: "pro", Version: "test"})
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "删除依赖节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 29000, "portEnd": 29999,
	}, true)
	var node store.Node
	if nodeResponse.Code != http.StatusCreated || json.Unmarshal(nodeResponse.Body.Bytes(), &node) != nil {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	projectResponse := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "依赖项目", "nodeId": node.ID, "ownerName": "管理员", "clientId": 1,
	}, true)
	var project store.Project
	if projectResponse.Code != http.StatusCreated || json.Unmarshal(projectResponse.Body.Bytes(), &project) != nil {
		t.Fatalf("create project = %d: %s", projectResponse.Code, projectResponse.Body.String())
	}
	project = configureProjectNetworks(t, handler, project, "10.90.0.0/16")
	deviceResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices", map[string]any{
		"host": "10.90.0.1", "name": "SSH 设备", "deviceType": "network", "source": "manual", "endpoints": []map[string]any{{"name": "SSH", "protocol": "ssh", "targetPort": 2222}},
	}, true)
	var device store.Device
	if deviceResponse.Code != http.StatusCreated || json.Unmarshal(deviceResponse.Body.Bytes(), &device) != nil {
		t.Fatalf("create device = %d: %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	forwardResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/port-forwards", map[string]any{"endpointId": device.Endpoints[0].ID, "serverPort": 29000}, true)
	var forward store.PortForward
	if forwardResponse.Code != http.StatusCreated || json.Unmarshal(forwardResponse.Body.Bytes(), &forward) != nil {
		t.Fatalf("create forward = %d: %s", forwardResponse.Code, forwardResponse.Body.String())
	}
	blocked := request(t, handler, http.MethodDelete, "/api/v1/projects/"+project.ID, nil, true)
	if blocked.Code != http.StatusConflict || !bytes.Contains(blocked.Body.Bytes(), []byte("端口转发")) {
		t.Fatalf("delete with forward = %d: %s", blocked.Code, blocked.Body.String())
	}
	if response := request(t, handler, http.MethodDelete, "/api/v1/port-forwards/"+forward.ID, nil, true); response.Code != http.StatusNoContent {
		t.Fatalf("delete forward = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodDelete, "/api/v1/projects/"+project.ID, nil, true); response.Code != http.StatusNoContent {
		t.Fatalf("delete project after cleanup = %d: %s", response.Code, response.Body.String())
	}

}

func TestBrowserLoginSessionAndCSRF(t *testing.T) {
	handler := testServer(t)
	created := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "admin-user", "displayName": "系统管理员", "password": "correct horse battery staple", "role": "system_admin",
	}, true)
	if created.Code != http.StatusCreated || bytes.Contains(created.Body.Bytes(), []byte("passwordHash")) {
		t.Fatalf("create user status = %d: %s", created.Code, created.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "admin-user", "password": "correct horse battery staple"}, false)
	if login.Code != http.StatusAccepted {
		t.Fatalf("login status = %d: %s", login.Code, login.Body.String())
	}
	login = completeTestMFA(t, handler, login)
	if login.Code != http.StatusOK {
		t.Fatalf("MFA enrollment status = %d: %s", login.Code, login.Body.String())
	}
	var result struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &result); err != nil || result.CSRFToken == "" {
		t.Fatalf("login response = %s, err = %v", login.Body.String(), err)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 2 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[1].HttpOnly || cookies[1].Name != csrfCookieName {
		t.Fatalf("unexpected session cookie: %#v", cookies)
	}
	meRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meRequest.AddCookie(cookies[0])
	meResponse := httptest.NewRecorder()
	handler.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK || !bytes.Contains(meResponse.Body.Bytes(), []byte("admin-user")) {
		t.Fatalf("me status = %d: %s", meResponse.Code, meResponse.Body.String())
	}
	logoutWithoutCSRF := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutWithoutCSRF.AddCookie(cookies[0])
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, logoutWithoutCSRF)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF status = %d", blocked.Code)
	}
	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.AddCookie(cookies[0])
	logout.Header.Set("X-CSRF-Token", result.CSRFToken)
	logoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d: %s", logoutResponse.Code, logoutResponse.Body.String())
	}
}

func TestAuthenticatedUserCanChangeOwnPassword(t *testing.T) {
	handler := testServer(t)
	created := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "self-password-user", "displayName": "自助改密用户", "password": "temporary password value", "role": "operator", "enabled": true, "projectIds": []string{},
	}, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("create user = %d: %s", created.Code, created.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "self-password-user", "password": "temporary password value"}, false)
	login = completeTestMFA(t, handler, login)
	if login.Code != http.StatusOK {
		t.Fatalf("complete enrollment = %d: %s", login.Code, login.Body.String())
	}
	var session struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil || session.CSRFToken == "" {
		t.Fatalf("login session = %s, err = %v", login.Body.String(), err)
	}
	oldCookie := login.Result().Cookies()[0]
	change := func(currentPassword, newPassword string) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(map[string]string{"currentPassword": currentPassword, "newPassword": newPassword})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/auth/password", bytes.NewReader(payload))
		req.AddCookie(oldCookie)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", session.CSRFToken)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if wrong := change("incorrect current password", "an even newer secure password"); wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password = %d: %s", wrong.Code, wrong.Body.String())
	}
	changed := change("a new permanent password", "an even newer secure password")
	if changed.Code != http.StatusOK || len(changed.Result().Cookies()) != 2 {
		t.Fatalf("change password = %d: %s", changed.Code, changed.Body.String())
	}
	oldSessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	oldSessionRequest.AddCookie(oldCookie)
	oldSessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(oldSessionResponse, oldSessionRequest)
	if oldSessionResponse.Code != http.StatusUnauthorized {
		t.Fatalf("old session remained active = %d: %s", oldSessionResponse.Code, oldSessionResponse.Body.String())
	}
	newSessionRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	newSessionRequest.AddCookie(changed.Result().Cookies()[0])
	newSessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(newSessionResponse, newSessionRequest)
	if newSessionResponse.Code != http.StatusOK {
		t.Fatalf("rotated session = %d: %s", newSessionResponse.Code, newSessionResponse.Body.String())
	}
	if oldLogin := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "self-password-user", "password": "a new permanent password"}, false); oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password remained valid = %d: %s", oldLogin.Code, oldLogin.Body.String())
	}
	if newLogin := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "self-password-user", "password": "an even newer secure password"}, false); newLogin.Code != http.StatusAccepted {
		t.Fatalf("new password login = %d: %s", newLogin.Code, newLogin.Body.String())
	}
}

func TestEmailMFARecoveryAndAdministrativeReset(t *testing.T) {
	handler := testServer(t)
	created := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "email-mfa-user", "displayName": "邮箱验证用户", "password": "temporary email password", "role": "operator",
	}, true)
	var user store.User
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &user) != nil {
		t.Fatalf("create user = %d: %s", created.Code, created.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "temporary email password"}, false)
	var challenge APITestChallenge
	if login.Code != http.StatusAccepted || json.Unmarshal(login.Body.Bytes(), &challenge) != nil || challenge.Next != "onboard" {
		t.Fatalf("onboarding challenge = %d: %s", login.Code, login.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/password", map[string]any{"challengeToken": challenge.ChallengeToken, "newPassword": "permanent email password"}, false); response.Code != http.StatusOK {
		t.Fatalf("set permanent password = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/email/send", map[string]any{"challengeToken": challenge.ChallengeToken, "email": "email-user@example.test"}, false); response.Code != http.StatusOK {
		t.Fatalf("send verification email = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/onboarding/email/verify", map[string]any{"challengeToken": challenge.ChallengeToken, "code": deliveredEmailCode(t)}, false); response.Code != http.StatusOK {
		t.Fatalf("verify onboarding email = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/start", map[string]any{"challengeToken": challenge.ChallengeToken, "method": "email"}, false); response.Code != http.StatusOK {
		t.Fatalf("start email MFA enrollment = %d: %s", response.Code, response.Body.String())
	}
	completed := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challengeToken": challenge.ChallengeToken, "code": deliveredEmailCode(t)}, false)
	var enrolled struct {
		User          store.User `json:"user"`
		RecoveryCodes []string   `json:"recoveryCodes"`
	}
	if completed.Code != http.StatusOK || json.Unmarshal(completed.Body.Bytes(), &enrolled) != nil || !enrolled.User.MFAEnabled || len(enrolled.RecoveryCodes) != 10 {
		t.Fatalf("complete email MFA enrollment = %d: %s", completed.Code, completed.Body.String())
	}

	login = request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "permanent email password"}, false)
	challenge = APITestChallenge{}
	if login.Code != http.StatusAccepted || json.Unmarshal(login.Body.Bytes(), &challenge) != nil || challenge.PreferredMethod != "email" {
		t.Fatalf("email MFA challenge = %d: %s", login.Code, login.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/start", map[string]any{"challengeToken": challenge.ChallengeToken, "method": "email"}, false); response.Code != http.StatusOK {
		t.Fatalf("send login email = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challengeToken": challenge.ChallengeToken, "code": deliveredEmailCode(t)}, false); response.Code != http.StatusOK {
		t.Fatalf("email MFA login = %d: %s", response.Code, response.Body.String())
	}

	login = request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "permanent email password"}, false)
	challenge = APITestChallenge{}
	_ = json.Unmarshal(login.Body.Bytes(), &challenge)
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challengeToken": challenge.ChallengeToken, "code": enrolled.RecoveryCodes[0]}, false); response.Code != http.StatusOK {
		t.Fatalf("recovery code login = %d: %s", response.Code, response.Body.String())
	}
	login = request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "permanent email password"}, false)
	challenge = APITestChallenge{}
	_ = json.Unmarshal(login.Body.Bytes(), &challenge)
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/mfa/complete", map[string]any{"challengeToken": challenge.ChallengeToken, "code": enrolled.RecoveryCodes[0]}, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("used recovery code = %d: %s", response.Code, response.Body.String())
	}

	if response := request(t, handler, http.MethodPost, "/api/v1/users/"+user.ID+"/mfa/reset", nil, true); response.Code != http.StatusNoContent {
		t.Fatalf("administrative MFA reset = %d: %s", response.Code, response.Body.String())
	}
	users := request(t, handler, http.MethodGet, "/api/v1/users", nil, true)
	if users.Code != http.StatusOK || !bytes.Contains(users.Body.Bytes(), []byte(`"passwordChangeRequired":true`)) || !bytes.Contains(users.Body.Bytes(), []byte(`"mfaEnabled":false`)) {
		t.Fatalf("user state after MFA reset = %d: %s", users.Code, users.Body.String())
	}
}

type APITestChallenge struct {
	Next            string `json:"next"`
	ChallengeToken  string `json:"challengeToken"`
	PreferredMethod string `json:"preferredMethod"`
}

func TestAdministrativeNodeStateAndPasswordReset(t *testing.T) {
	handler := testServer(t)
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "维护状态节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 30000, "portEnd": 30999,
	}, true)
	var node store.Node
	if nodeResponse.Code != http.StatusCreated || json.Unmarshal(nodeResponse.Body.Bytes(), &node) != nil {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	disabled := request(t, handler, http.MethodPatch, "/api/v1/nodes/"+node.ID, map[string]any{
		"name": node.Name, "apiUrl": node.APIURL, "tlsServerName": node.TLSServerName,
		"portStart": node.PortStart, "portEnd": node.PortEnd, "enabled": false,
	}, true)
	if disabled.Code != http.StatusOK || !bytes.Contains(disabled.Body.Bytes(), []byte(`"enabled":false`)) {
		t.Fatalf("disable node = %d: %s", disabled.Code, disabled.Body.String())
	}

	userResponse := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "password-reset-user", "displayName": "密码重置用户", "password": "original password value", "role": "operator", "enabled": true, "projectIds": []string{},
	}, true)
	var user store.User
	if userResponse.Code != http.StatusCreated || json.Unmarshal(userResponse.Body.Bytes(), &user) != nil {
		t.Fatalf("create user = %d: %s", userResponse.Code, userResponse.Body.String())
	}
	updated := request(t, handler, http.MethodPatch, "/api/v1/users/"+user.ID, map[string]any{
		"displayName": user.DisplayName, "password": "replacement password value", "role": user.Role, "enabled": true, "projectIds": []string{},
	}, true)
	if updated.Code != http.StatusOK {
		t.Fatalf("reset password = %d: %s", updated.Code, updated.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "original password value"}, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("old password login = %d: %s", response.Code, response.Body.String())
	}
	if response := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": user.Username, "password": "replacement password value"}, false); response.Code != http.StatusAccepted {
		t.Fatalf("new password login = %d: %s", response.Code, response.Body.String())
	}
}

func TestTemporaryPolicyScopeAndRouteBoundaries(t *testing.T) {
	handler := testServer(t)
	nodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "策略节点", "apiUrl": "https://node.test:6443", "tlsServerName": "node.test", "credential": map[string]any{"type": "signed", "authKey": "test-node-auth-key-0123456789-abcd"}, "portStart": 26000, "portEnd": 26999,
	}, true)
	var node store.Node
	if nodeResponse.Code != http.StatusCreated || json.Unmarshal(nodeResponse.Body.Bytes(), &node) != nil {
		t.Fatalf("create node = %d: %s", nodeResponse.Code, nodeResponse.Body.String())
	}
	projectResponse := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "临时授权项目", "nodeId": node.ID, "ownerName": "管理员", "clientId": 1,
	}, true)
	var project store.Project
	if projectResponse.Code != http.StatusCreated || json.Unmarshal(projectResponse.Body.Bytes(), &project) != nil {
		t.Fatalf("create project = %d: %s", projectResponse.Code, projectResponse.Body.String())
	}
	project = configureProjectNetworks(t, handler, project, "10.30.0.0/16")
	deviceResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+project.ID+"/devices", map[string]any{
		"host": "10.30.0.1", "name": "授权设备", "deviceType": "network", "source": "manual", "endpoints": []map[string]any{{"name": "后台", "protocol": "http", "targetPort": 8080}, {"name": "维护终端", "protocol": "ssh", "targetPort": 22}},
	}, true)
	var device store.Device
	if deviceResponse.Code != http.StatusCreated || json.Unmarshal(deviceResponse.Body.Bytes(), &device) != nil {
		t.Fatalf("create device = %d: %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	otherNodeResponse := request(t, handler, http.MethodPost, "/api/v1/nodes", map[string]any{
		"name": "其他策略节点", "apiUrl": "https://other-node.test:6443", "tlsServerName": "other-node.test", "credential": map[string]any{"type": "signed", "authKey": "other-node-auth-key-0123456789-abcd"}, "portStart": 27000, "portEnd": 27999,
	}, true)
	var otherNode store.Node
	if otherNodeResponse.Code != http.StatusCreated || json.Unmarshal(otherNodeResponse.Body.Bytes(), &otherNode) != nil {
		t.Fatalf("create other node = %d: %s", otherNodeResponse.Code, otherNodeResponse.Body.String())
	}
	otherProjectResponse := request(t, handler, http.MethodPost, "/api/v1/projects", map[string]any{
		"name": "未授权项目", "nodeId": otherNode.ID, "ownerName": "其他管理员", "clientId": 1,
	}, true)
	var otherProject store.Project
	if otherProjectResponse.Code != http.StatusCreated || json.Unmarshal(otherProjectResponse.Body.Bytes(), &otherProject) != nil {
		t.Fatalf("create other project = %d: %s", otherProjectResponse.Code, otherProjectResponse.Body.String())
	}
	otherProject = configureProjectNetworks(t, handler, otherProject, "10.40.0.0/16")
	otherDeviceResponse := request(t, handler, http.MethodPost, "/api/v1/projects/"+otherProject.ID+"/devices", map[string]any{
		"host": "10.40.0.1", "name": "未授权设备", "deviceType": "network", "source": "manual", "endpoints": []map[string]any{{"name": "后台", "protocol": "http", "targetPort": 8080}},
	}, true)
	var otherDevice store.Device
	if otherDeviceResponse.Code != http.StatusCreated || json.Unmarshal(otherDeviceResponse.Body.Bytes(), &otherDevice) != nil {
		t.Fatalf("create other device = %d: %s", otherDeviceResponse.Code, otherDeviceResponse.Body.String())
	}
	userResponse := request(t, handler, http.MethodPost, "/api/v1/users", map[string]any{
		"username": "temporary-policy", "displayName": "临时用户", "password": "temporary policy password", "role": "temporary", "projectIds": []string{},
	}, true)
	var user store.User
	if userResponse.Code != http.StatusCreated || json.Unmarshal(userResponse.Body.Bytes(), &user) != nil {
		t.Fatalf("create user = %d: %s", userResponse.Code, userResponse.Body.String())
	}
	policyResponse := request(t, handler, http.MethodPost, "/api/v1/access-policies", map[string]any{
		"name": "临时 Web", "projectIds": []string{project.ID}, "userIds": []string{user.ID}, "capabilities": []string{"web"},
	}, true)
	if policyResponse.Code != http.StatusCreated {
		t.Fatalf("create policy = %d: %s", policyResponse.Code, policyResponse.Body.String())
	}
	login := request(t, handler, http.MethodPost, "/api/v1/auth/login", map[string]any{"username": "temporary-policy", "password": "temporary policy password"}, false)
	if login.Code != http.StatusAccepted {
		t.Fatalf("login = %d: %s", login.Code, login.Body.String())
	}
	login = completeTestMFA(t, handler, login)
	if login.Code != http.StatusOK {
		t.Fatalf("MFA enrollment = %d: %s", login.Code, login.Body.String())
	}
	var loginBody struct {
		CSRFToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}
	authCookie := login.Result().Cookies()[0]
	getAsTemporary := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(authCookie)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := getAsTemporary("/api/v1/projects"); response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(project.ID)) {
		t.Fatalf("temporary projects = %d: %s", response.Code, response.Body.String())
	} else if bytes.Contains(response.Body.Bytes(), []byte("10.30.0.0/16")) || bytes.Contains(response.Body.Bytes(), []byte(`"clientId":1`)) {
		t.Fatalf("temporary project response disclosed control-plane topology: %s", response.Body.String())
	}
	if response := getAsTemporary("/api/v1/nodes"); response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(node.ID)) {
		t.Fatalf("temporary nodes = %d: %s", response.Code, response.Body.String())
	} else if bytes.Contains(response.Body.Bytes(), []byte("node.test")) || bytes.Contains(response.Body.Bytes(), []byte("26000")) {
		t.Fatalf("temporary node response disclosed control-plane topology: %s", response.Body.String())
	}
	if response := getAsTemporary("/api/v1/projects/" + project.ID + "/devices"); response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(device.ID)) {
		t.Fatalf("temporary devices = %d: %s", response.Code, response.Body.String())
	} else if bytes.Contains(response.Body.Bytes(), []byte("10.30.0.1")) || bytes.Contains(response.Body.Bytes(), []byte(`"targetPort":8080`)) || bytes.Contains(response.Body.Bytes(), []byte(`"protocol":"ssh"`)) {
		t.Fatalf("temporary device response disclosed internal or unauthorized endpoint metadata: %s", response.Body.String())
	}
	if response := getAsTemporary("/api/v1/projects/" + otherProject.ID + "/devices"); response.Code != http.StatusForbidden {
		t.Fatalf("temporary user crossed project boundary: %d: %s", response.Code, response.Body.String())
	}
	if response := getAsTemporary("/api/v1/projects/" + project.ID + "/port-forwards"); response.Code != http.StatusForbidden {
		t.Fatalf("temporary port forwards status = %d", response.Code)
	}
	if response := getAsTemporary("/api/v1/users"); response.Code != http.StatusForbidden {
		t.Fatalf("temporary users status = %d", response.Code)
	}
	payload, _ := json.Marshal(map[string]any{"endpointId": device.Endpoints[0].ID, "mode": "web"})
	sessionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access-sessions", bytes.NewReader(payload))
	sessionRequest.AddCookie(authCookie)
	sessionRequest.Header.Set("X-CSRF-Token", loginBody.CSRFToken)
	sessionRequest.Header.Set("Content-Type", "application/json")
	sessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(sessionResponse, sessionRequest)
	if sessionResponse.Code != http.StatusCreated {
		t.Fatalf("temporary web session = %d: %s", sessionResponse.Code, sessionResponse.Body.String())
	}
	launchForm := url.Values{"endpointId": {device.Endpoints[0].ID}, "csrfToken": {loginBody.CSRFToken}}
	launchRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access-sessions/launch", strings.NewReader(launchForm.Encode()))
	launchRequest.AddCookie(authCookie)
	launchRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	launchResponse := httptest.NewRecorder()
	handler.ServeHTTP(launchResponse, launchRequest)
	if launchResponse.Code != http.StatusOK {
		t.Fatalf("temporary web launch = %d: %s", launchResponse.Code, launchResponse.Body.String())
	}
	otherPayload, _ := json.Marshal(map[string]any{"endpointId": otherDevice.Endpoints[0].ID, "mode": "web"})
	otherSessionRequest := httptest.NewRequest(http.MethodPost, "/api/v1/access-sessions", bytes.NewReader(otherPayload))
	otherSessionRequest.AddCookie(authCookie)
	otherSessionRequest.Header.Set("X-CSRF-Token", loginBody.CSRFToken)
	otherSessionRequest.Header.Set("Content-Type", "application/json")
	otherSessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(otherSessionResponse, otherSessionRequest)
	if otherSessionResponse.Code != http.StatusForbidden {
		t.Fatalf("temporary user created session for another project: %d: %s", otherSessionResponse.Code, otherSessionResponse.Body.String())
	}
}
