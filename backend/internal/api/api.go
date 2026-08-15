package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/access"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/auth"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/config"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/id"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/secrets"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

type storage interface {
	Ping(context.Context) error
	SchemaVersion(context.Context) (int, error)
	ListNodes(context.Context) ([]store.Node, error)
	CreateNode(context.Context, store.CreateNodeInput, store.AuditInput) (store.Node, error)
	UpdateNode(context.Context, string, store.UpdateNodeInput, store.AuditInput) (store.Node, error)
	DeleteNode(context.Context, string, store.AuditInput) error
	NodeCredentialReference(context.Context, string) (string, error)
	ListProjects(context.Context) ([]store.Project, error)
	ProjectByID(context.Context, string) (store.Project, error)
	CreateProject(context.Context, string, store.CreateProjectInput, store.AuditInput) (store.Project, error)
	UpdateProject(context.Context, string, store.UpdateProjectInput, store.AuditInput) (store.Project, error)
	DeleteProject(context.Context, string, store.AuditInput) error
	ProjectNetworks(context.Context, string) ([]string, error)
	ProjectScanPorts(context.Context, string) ([]store.DiscoveryPort, error)
	ReplaceProjectScanPorts(context.Context, string, []store.DiscoveryPort, store.AuditInput) error
	ListDevices(context.Context, string) ([]store.Device, error)
	CreateDevice(context.Context, string, store.CreateDeviceInput, store.AuditInput) (store.Device, error)
	CreateDevices(context.Context, string, []store.CreateDeviceInput, store.AuditInput) ([]store.Device, error)
	UpdateDevice(context.Context, string, string, store.UpdateDeviceInput, store.AuditInput) (store.Device, error)
	DeleteDevice(context.Context, string, string, store.AuditInput) error
	VerifyDeviceEndpoints(context.Context, string, string, map[string]bool, store.AuditInput) (store.Device, error)
	EndpointRoute(context.Context, string) (store.EndpointRoute, error)
	CreateAccessSession(context.Context, store.CreateAccessSessionInput, store.AuditInput) (store.AccessSession, error)
	ListActiveAccessSessions(context.Context) ([]store.AccessSession, error)
	RevokeAccessSession(context.Context, string, store.AuditInput) error
	ResolveAccessToken(context.Context, string) (store.AccessSession, store.EndpointRoute, error)
	ListPortForwards(context.Context, string) ([]store.PortForward, error)
	ReservePortForward(context.Context, store.ReservePortForwardInput, store.AuditInput) (store.PortForward, error)
	ActivatePortForward(context.Context, string, int) error
	PortForwardByID(context.Context, string) (store.PortForward, error)
	SetPortForwardStatus(context.Context, string, string, store.AuditInput) error
	DeletePortForward(context.Context, string, store.AuditInput) error
	DiscoveryRoute(context.Context, string) (store.DiscoveryRoute, error)
	CreateDiscoveryJob(context.Context, string, []string, []store.DiscoveryPort, store.AuditInput) (store.DiscoveryJob, error)
	SetDiscoveryJobState(context.Context, string, string, int) error
	DiscoveryJob(context.Context, string) (store.DiscoveryJob, error)
	ListDiscoveryJobs(context.Context, string) ([]store.DiscoveryJob, error)
	ListDiscoveryResults(context.Context, string) ([]store.DiscoveryResult, error)
	ImportDiscoveryDevice(context.Context, string, store.CreateDeviceInput, store.AuditInput) (store.Device, error)
	ListUsers(context.Context) ([]store.User, error)
	HasUsers(context.Context) (bool, error)
	CreateInitialAdmin(context.Context, store.CreateUserInput, store.AuditInput) (store.User, error)
	CreateUser(context.Context, store.CreateUserInput, store.AuditInput) (store.User, error)
	UpdateUser(context.Context, string, store.UpdateUserInput, store.AuditInput) (store.User, error)
	DeleteUser(context.Context, string, store.AuditInput) error
	UserCredentialByUsername(context.Context, string) (store.UserCredential, error)
	CreateAuthSession(context.Context, string, string, string, time.Time) (store.AuthSession, error)
	ResolveAuthSession(context.Context, string) (store.AuthSession, error)
	RevokeAuthSession(context.Context, string) error
	CreateMFAChallenge(context.Context, string, string, string, string, string, time.Time) (store.MFAChallenge, error)
	SetMFAChallengeMethod(context.Context, string, string, string, string, time.Time) error
	SetOnboardingPassword(context.Context, string, string) error
	SetOnboardingEmailDelivery(context.Context, string, string, string, time.Time) error
	VerifyOnboardingEmail(context.Context, string, string) error
	ClearMFAEmailDelivery(context.Context, string, string) error
	MFAChallengeByToken(context.Context, string) (store.MFAChallenge, error)
	FailMFAChallenge(context.Context, string) error
	CompleteMFAEnrollment(context.Context, store.CompleteMFAInput) (store.AuthSession, error)
	CompleteMFAAuthentication(context.Context, store.CompleteMFAInput) (store.AuthSession, error)
	RecoveryCodeCount(context.Context, string) (int, error)
	ResetUserMFA(context.Context, string, store.AuditInput) error
	ListAccessPolicies(context.Context) ([]store.AccessPolicy, error)
	CreateAccessPolicy(context.Context, store.SaveAccessPolicyInput, store.AuditInput) (store.AccessPolicy, error)
	UpdateAccessPolicy(context.Context, string, store.SaveAccessPolicyInput, store.AuditInput) (store.AccessPolicy, error)
	DeleteAccessPolicy(context.Context, string, store.AuditInput) error
	HasPolicyCapability(context.Context, string, string, string, time.Time) (bool, error)
	ListAuditLogs(context.Context, string, int, int) ([]store.AuditLog, error)
	AppendAudit(context.Context, store.AuditInput) error
	Backup(context.Context, string) error
}

type nodeControl interface {
	Health(context.Context, string) nodeadapter.Health
	ListClients(context.Context, string) ([]nodeadapter.Client, error)
	ClientCredentials(context.Context, string, int) (nodeadapter.ClientCredentials, error)
	ListManagedTunnels(context.Context, string) ([]nodeadapter.ManagedTunnel, error)
	SetManagedTunnel(context.Context, string, int, bool) error
	SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error)
	CreatePortForward(context.Context, string, int, int, string, string) (nodeadapter.PortForward, error)
	SetPortForward(context.Context, string, int, bool) error
	DeletePortForward(context.Context, string, int) error
	CreateClient(context.Context, string, string, string, string, string) (nodeadapter.Client, error)
	DeleteClient(context.Context, string, int) error
}

type Dependencies struct {
	Store             storage
	Nodes             nodeControl
	Discovery         discoveryControl
	SSHGateway        http.Handler
	UI                http.Handler
	APIToken          string
	AccessDomain      string
	AccessScheme      string
	TrustedProxyCIDRs []string
	Mode              string
	Version           string
	CookieSecure      bool
	MFA               *auth.MFA
	MFAEnabled        bool
	MFAMethods        []string
	EmailSender       auth.EmailSender
	EmailCodeTTL      time.Duration
	TLSConfigured     bool
	Settings          securitySettingsManager
	NodeCredentials   nodeCredentialManager
}

type nodeCredentialManager interface {
	Save(context.Context, string, string, secrets.NodeCredentialPatch) (string, func(), error)
	SaveSSH(context.Context, string, string, secrets.SSHCredentialPatch) (string, func(), error)
	Delete(string) error
}

type securitySettingsManager interface {
	Current() config.PanelSettings
	Save(config.PanelSettings) (config.PanelSettings, error)
}

type server struct {
	store             storage
	nodes             nodeControl
	discovery         discoveryControl
	sshGateway        http.Handler
	sessionRevoker    accessSessionRevoker
	ui                http.Handler
	apiToken          string
	accessDomain      string
	accessScheme      string
	mode              string
	version           string
	cookieSecure      bool
	trustedProxyCIDRs []netip.Prefix
	loginLimiter      *auth.LoginLimiter
	mfa               *auth.MFA
	mfaEnabled        bool
	mfaMethods        []string
	emailSender       auth.EmailSender
	emailCodeTTL      time.Duration
	tlsConfigured     bool
	settings          securitySettingsManager
	nodeCredentials   nodeCredentialManager
}

type accessSessionRevoker interface {
	Revoke(string) bool
}

type discoveryControl interface {
	Start(context.Context, store.DiscoveryJob, store.DiscoveryRoute) error
	Verify(context.Context, store.DiscoveryRoute, string, []store.DiscoveryPort) ([]store.DiscoveryProbeResult, error)
	Cancel(string) bool
}

type errorBody struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	RequestID string            `json:"requestId"`
}

func New(deps Dependencies) http.Handler {
	s := &server{store: deps.Store, nodes: deps.Nodes, discovery: deps.Discovery, sshGateway: deps.SSHGateway, ui: deps.UI, apiToken: deps.APIToken, accessDomain: strings.ToLower(deps.AccessDomain), accessScheme: deps.AccessScheme, mode: deps.Mode, version: deps.Version, cookieSecure: deps.CookieSecure, loginLimiter: auth.NewLoginLimiter(5, 10*time.Minute), mfa: deps.MFA, mfaEnabled: deps.MFAEnabled, mfaMethods: deps.MFAMethods, emailSender: deps.EmailSender, emailCodeTTL: deps.EmailCodeTTL, tlsConfigured: deps.TLSConfigured, settings: deps.Settings, nodeCredentials: deps.NodeCredentials}
	if s.emailCodeTTL == 0 {
		s.emailCodeTTL = 10 * time.Minute
	}
	if revoker, ok := deps.SSHGateway.(accessSessionRevoker); ok {
		s.sessionRevoker = revoker
	}
	for _, cidr := range deps.TrustedProxyCIDRs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			s.trustedProxyCIDRs = append(s.trustedProxyCIDRs, prefix)
		}
	}
	if s.accessScheme == "" {
		s.accessScheme = "https"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health/live", s.live)
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/mfa/complete", s.completeMFA)
	mux.HandleFunc("POST /api/v1/auth/mfa/start", s.startMFA)
	mux.HandleFunc("POST /api/v1/auth/onboarding/password", s.setOnboardingPassword)
	mux.HandleFunc("POST /api/v1/auth/onboarding/email/send", s.sendOnboardingEmail)
	mux.HandleFunc("POST /api/v1/auth/onboarding/email/verify", s.verifyOnboardingEmail)
	mux.HandleFunc("GET /api/v1/setup/status", s.setupStatus)
	mux.HandleFunc("POST /api/v1/setup", s.setup)
	mux.Handle("GET /api/v1/auth/me", s.requireAuth(http.HandlerFunc(s.me)))
	mux.Handle("POST /api/v1/auth/logout", s.requireAuth(http.HandlerFunc(s.logout)))
	mux.Handle("GET /api/v1/users", s.requireAuth(http.HandlerFunc(s.listUsers)))
	mux.Handle("POST /api/v1/users", s.requireAuth(http.HandlerFunc(s.createUser)))
	mux.Handle("PATCH /api/v1/users/{userID}", s.requireAuth(http.HandlerFunc(s.updateUser)))
	mux.Handle("DELETE /api/v1/users/{userID}", s.requireAuth(http.HandlerFunc(s.deleteUser)))
	mux.Handle("POST /api/v1/users/{userID}/mfa/reset", s.requireAuth(http.HandlerFunc(s.resetUserMFA)))
	mux.Handle("GET /api/v1/access-policies", s.requireAuth(http.HandlerFunc(s.listAccessPolicies)))
	mux.Handle("POST /api/v1/access-policies", s.requireAuth(http.HandlerFunc(s.createAccessPolicy)))
	mux.Handle("PATCH /api/v1/access-policies/{policyID}", s.requireAuth(http.HandlerFunc(s.updateAccessPolicy)))
	mux.Handle("DELETE /api/v1/access-policies/{policyID}", s.requireAuth(http.HandlerFunc(s.deleteAccessPolicy)))
	mux.Handle("GET /api/v1/audit-logs", s.requireAuth(http.HandlerFunc(s.listAuditLogs)))
	mux.Handle("GET /api/v1/audit-logs/export", s.requireAuth(http.HandlerFunc(s.exportAuditLogs)))
	mux.Handle("GET /api/v1/data/backup", s.requireAuth(http.HandlerFunc(s.backupData)))
	mux.Handle("GET /api/v1/meta", s.requireAuth(http.HandlerFunc(s.meta)))
	mux.Handle("GET /api/v1/settings/security", s.requireAuth(http.HandlerFunc(s.securitySettings)))
	mux.Handle("PUT /api/v1/settings/security", s.requireAuth(http.HandlerFunc(s.updateSecuritySettings)))
	mux.Handle("GET /api/v1/nodes", s.requireAuth(http.HandlerFunc(s.listNodes)))
	mux.Handle("POST /api/v1/nodes", s.requireAuth(http.HandlerFunc(s.createNode)))
	mux.Handle("PATCH /api/v1/nodes/{nodeID}", s.requireAuth(http.HandlerFunc(s.updateNode)))
	mux.Handle("DELETE /api/v1/nodes/{nodeID}", s.requireAuth(http.HandlerFunc(s.deleteNode)))
	mux.Handle("GET /api/v1/nodes/{nodeID}/health", s.requireAuth(http.HandlerFunc(s.nodeHealth)))
	mux.Handle("GET /api/v1/nodes/{nodeID}/clients", s.requireAuth(http.HandlerFunc(s.nodeClients)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/clients", s.requireAuth(http.HandlerFunc(s.createNodeClient)))
	mux.Handle("GET /api/v1/nodes/{nodeID}/clients/{clientID}/credentials", s.requireAuth(http.HandlerFunc(s.nodeClientCredentials)))
	mux.Handle("GET /api/v1/nodes/{nodeID}/managed-tunnels", s.requireAuth(http.HandlerFunc(s.managedTunnels)))
	mux.Handle("POST /api/v1/nodes/{nodeID}/managed-tunnels/{clientID}/{action}", s.requireAuth(http.HandlerFunc(s.setManagedTunnel)))
	mux.Handle("GET /api/v1/projects", s.requireAuth(http.HandlerFunc(s.listProjects)))
	mux.Handle("POST /api/v1/projects", s.requireAuth(http.HandlerFunc(s.createProject)))
	mux.Handle("PATCH /api/v1/projects/{projectID}", s.requireAuth(http.HandlerFunc(s.updateProject)))
	mux.Handle("DELETE /api/v1/projects/{projectID}", s.requireAuth(http.HandlerFunc(s.deleteProject)))
	mux.Handle("GET /api/v1/projects/{projectID}/devices", s.requireAuth(http.HandlerFunc(s.listDevices)))
	mux.Handle("POST /api/v1/projects/{projectID}/devices", s.requireAuth(http.HandlerFunc(s.createDevice)))
	mux.Handle("POST /api/v1/projects/{projectID}/devices/batch", s.requireAuth(http.HandlerFunc(s.createDeviceBatch)))
	mux.Handle("PATCH /api/v1/projects/{projectID}/devices/{deviceID}", s.requireAuth(http.HandlerFunc(s.updateDevice)))
	mux.Handle("DELETE /api/v1/projects/{projectID}/devices/{deviceID}", s.requireAuth(http.HandlerFunc(s.deleteDevice)))
	mux.Handle("POST /api/v1/projects/{projectID}/devices/{deviceID}/verify", s.requireAuth(http.HandlerFunc(s.verifyDevice)))
	mux.Handle("GET /api/v1/access-sessions", s.requireAuth(http.HandlerFunc(s.listAccessSessions)))
	mux.Handle("GET /api/v1/monitor/snapshot", s.requireAuth(http.HandlerFunc(s.monitorSnapshot)))
	mux.Handle("POST /api/v1/access-sessions", s.requireAuth(http.HandlerFunc(s.createAccessSession)))
	mux.Handle("DELETE /api/v1/access-sessions/{sessionID}", s.requireAuth(http.HandlerFunc(s.revokeAccessSession)))
	mux.Handle("GET /api/v1/projects/{projectID}/port-forwards", s.requireAuth(http.HandlerFunc(s.listPortForwards)))
	mux.Handle("POST /api/v1/projects/{projectID}/port-forwards", s.requireAuth(http.HandlerFunc(s.createPortForward)))
	mux.Handle("POST /api/v1/port-forwards/{forwardID}/{action}", s.requireAuth(http.HandlerFunc(s.setPortForward)))
	mux.Handle("DELETE /api/v1/port-forwards/{forwardID}", s.requireAuth(http.HandlerFunc(s.deletePortForward)))
	mux.Handle("GET /api/v1/projects/{projectID}/discovery-jobs", s.requireAuth(http.HandlerFunc(s.listDiscoveryJobs)))
	mux.Handle("POST /api/v1/projects/{projectID}/discovery-jobs", s.requireAuth(http.HandlerFunc(s.createDiscoveryJob)))
	mux.Handle("GET /api/v1/projects/{projectID}/scan-ports", s.requireAuth(http.HandlerFunc(s.getProjectScanPorts)))
	mux.Handle("PUT /api/v1/projects/{projectID}/scan-ports", s.requireAuth(http.HandlerFunc(s.updateProjectScanPorts)))
	mux.Handle("GET /api/v1/discovery-jobs/{jobID}", s.requireAuth(http.HandlerFunc(s.getDiscoveryJob)))
	mux.Handle("POST /api/v1/discovery-jobs/{jobID}/cancel", s.requireAuth(http.HandlerFunc(s.cancelDiscoveryJob)))
	mux.Handle("POST /api/v1/discovery-jobs/{jobID}/import", s.requireAuth(http.HandlerFunc(s.importDiscoveryDevice)))
	if s.nodes != nil {
		mux.Handle("/access/web/{token}/{path...}", access.NewWebGateway(s.store, s.nodes))
	}
	if s.sshGateway != nil {
		mux.Handle("GET /access/ssh/{token}", s.sshGateway)
		mux.Handle("GET /access/ssh/{token}/ws", s.sshGateway)
	}
	if s.ui != nil {
		mux.Handle("/", s.ui)
	}
	return s.requestContext(s.trustedProxySource(s.accessDomainRouting(s.securityHeaders(mux))))
}

func (s *server) trustedProxySource(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.trustedProxyCIDRs) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		direct := requestSourceIP(r)
		directAddress, err := netip.ParseAddr(direct)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		trusted := false
		for _, prefix := range s.trustedProxyCIDRs {
			if prefix.Contains(directAddress.Unmap()) {
				trusted = true
				break
			}
		}
		if !trusted {
			next.ServeHTTP(w, r)
			return
		}
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		clientAddress, err := netip.ParseAddr(forwarded)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		clone := r.Clone(r.Context())
		clone.RemoteAddr = clientAddress.Unmap().String()
		next.ServeHTTP(w, clone)
	})
}

func (s *server) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "device-management-platform"})
}

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "database_unavailable", "数据库暂不可用", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (s *server) meta(w http.ResponseWriter, r *http.Request) {
	version, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取数据库版本", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"service": "device-management-platform", "version": s.version, "mode": s.mode, "schemaVersion": version, "apiVersion": "v1"})
}

func (s *server) securitySettings(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	if s.settings != nil {
		writeJSON(w, http.StatusOK, s.settings.Current())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mfaEnabled":     s.mfaEnabled,
		"mfaMethods":     s.mfaMethods,
		"smtpConfigured": s.emailSender != nil,
		"tlsConfigured":  s.tlsConfigured,
		"emailCodeTTL":   s.emailCodeTTL.String(),
		"source":         "configuration_file",
	})
}

func (s *server) updateSecuritySettings(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	if s.settings == nil {
		writeError(w, r, http.StatusServiceUnavailable, "settings_unavailable", "网页配置保存尚未启用", nil)
		return
	}
	var input config.PanelSettings
	if !decodeJSON(w, r, &input) {
		return
	}
	updated, err := s.settings.Save(input)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "settings_invalid", "配置校验失败："+err.Error(), map[string]string{"settings": err.Error()})
		return
	}
	audit := auditFromRequest(r, "settings.security_update", "settings")
	audit.ResourceID = "security"
	metadata, _ := json.Marshal(map[string]any{"restartRequired": updated.RestartRequired, "mfaEnabled": updated.MFAEnabled, "mfaMethods": updated.MFAMethods, "smtpConfigured": updated.SMTPConfigured, "tlsConfigured": updated.TLSConfigured})
	audit.MetadataJSON = string(metadata)
	if err := s.store.AppendAudit(r.Context(), audit); err != nil {
		writeError(w, r, http.StatusInternalServerError, "audit_write_failed", "配置已保存，但审计写入失败；请刷新确认并检查数据库", nil)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *server) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取接入节点失败", nil)
		return
	}
	current := principalFromRequest(r)
	if !current.Bootstrap && current.Role != "system_admin" {
		projects, projectErr := s.store.ListProjects(r.Context())
		if projectErr != nil {
			writeError(w, r, http.StatusInternalServerError, "database_error", "读取节点授权范围失败", nil)
			return
		}
		allowedNodes := map[string]struct{}{}
		for _, project := range projects {
			allowed := canAccessProject(current, project.ID, "read")
			if current.Role == "temporary" {
				web, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, project.ID, "web", time.Now().UTC())
				webSSH, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, project.ID, "webssh", time.Now().UTC())
				allowed = web || webSSH
			}
			if allowed {
				allowedNodes[project.NodeID] = struct{}{}
			}
		}
		filtered := make([]store.Node, 0, len(nodes))
		for _, node := range nodes {
			if _, allowed := allowedNodes[node.ID]; allowed {
				// Scoped users only need node identity and health for project labels.
				// Management and port-allocation topology remains an
				// administrator-only control-plane concern.
				node.APIURL = ""
				node.TLSServerName = ""
				node.CredentialConfigured = false
				node.PortStart = 0
				node.PortEnd = 0
				filtered = append(filtered, node)
			}
		}
		nodes = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": nodes, "total": len(nodes)})
}

type saveNodeRequest struct {
	store.CreateNodeInput
	Credential *secrets.NodeCredentialPatch `json:"credential,omitempty"`
}

type updateNodeRequest struct {
	store.UpdateNodeInput
	Credential *secrets.NodeCredentialPatch `json:"credential,omitempty"`
}

func (s *server) createNode(w http.ResponseWriter, r *http.Request) {
	var request saveNodeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	input := request.CreateNodeInput
	var err error
	input.ID, err = id.New()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "id_generation_failed", "无法生成节点标识", nil)
		return
	}
	rollbackCredential := func() {}
	if request.Credential != nil {
		if s.nodeCredentials == nil {
			writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable", "节点密码安全存储尚未配置", nil)
			return
		}
		input.CredentialRef, rollbackCredential, err = s.nodeCredentials.Save(r.Context(), input.ID, "", *request.Credential)
		if err != nil {
			writeError(w, r, http.StatusUnprocessableEntity, "credential_invalid", "节点认证信息校验失败", map[string]string{"credential": err.Error()})
			return
		}
	}
	fields := validateNode(input)
	if len(fields) > 0 {
		rollbackCredential()
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "节点配置校验失败", fields)
		return
	}
	node, err := s.store.CreateNode(r.Context(), input, auditFromRequest(r, "node.create", "node"))
	if err != nil {
		rollbackCredential()
		writeError(w, r, http.StatusConflict, "node_create_failed", "接入节点创建失败，名称或端口配置可能冲突", nil)
		return
	}
	writeJSON(w, http.StatusCreated, node)
}

func (s *server) updateNode(w http.ResponseWriter, r *http.Request) {
	var request updateNodeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	input := request.UpdateNodeInput
	rollbackCredential := func() {}
	if request.Credential != nil {
		if s.nodeCredentials == nil {
			writeError(w, r, http.StatusServiceUnavailable, "credential_store_unavailable", "节点密码安全存储尚未配置", nil)
			return
		}
		currentReference, err := s.store.NodeCredentialReference(r.Context(), r.PathValue("nodeID"))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "node_not_found", "接入节点不存在", nil)
			return
		}
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取节点认证状态", nil)
			return
		}
		input.CredentialRef, rollbackCredential, err = s.nodeCredentials.Save(r.Context(), r.PathValue("nodeID"), currentReference, *request.Credential)
		if err != nil {
			writeError(w, r, http.StatusUnprocessableEntity, "credential_invalid", "节点认证信息校验失败", map[string]string{"credential": err.Error()})
			return
		}
	}
	credentialRef := input.CredentialRef
	if credentialRef == "" {
		input.CredentialRef = "db://node/" + r.PathValue("nodeID")
	}
	fields := validateNode(input.CreateNodeInput)
	input.CredentialRef = credentialRef
	if len(fields) > 0 {
		rollbackCredential()
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "节点配置校验失败", fields)
		return
	}
	node, err := s.store.UpdateNode(r.Context(), r.PathValue("nodeID"), input, auditFromRequest(r, "node.update", "node"))
	if errors.Is(err, store.ErrNotFound) {
		rollbackCredential()
		writeError(w, r, http.StatusNotFound, "node_not_found", "接入节点不存在", nil)
		return
	}
	if err != nil {
		rollbackCredential()
		writeError(w, r, http.StatusConflict, "node_update_failed", "节点更新失败，名称或端口配置可能冲突", nil)
		return
	}
	writeJSON(w, http.StatusOK, node)
}

func (s *server) deleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("nodeID")
	err := s.store.DeleteNode(r.Context(), nodeID, auditFromRequest(r, "node.delete", "node"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "node_not_found", "接入节点不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "node_in_use", "节点仍关联客户项目，不能删除", nil)
		return
	}
	if s.nodeCredentials != nil {
		_ = s.nodeCredentials.Delete(nodeID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) nodeHealth(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	result := s.nodes.Health(r.Context(), r.PathValue("nodeID"))
	status := http.StatusOK
	if !result.Reachable {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, result)
}

type monitorNodeSnapshot struct {
	NodeID         string    `json:"nodeId"`
	Name           string    `json:"name"`
	Status         string    `json:"status"`
	Reachable      bool      `json:"reachable"`
	LatencyMS      int64     `json:"latencyMs"`
	TunnelCount    int       `json:"tunnelCount"`
	RunningTunnels int       `json:"runningTunnels"`
	InletFlow      int64     `json:"inletFlow"`
	ExportFlow     int64     `json:"exportFlow"`
	Message        string    `json:"message"`
	CheckedAt      time.Time `json:"checkedAt"`
}

type monitorSnapshotResponse struct {
	CollectedAt         time.Time             `json:"collectedAt"`
	DatabaseStatus      string                `json:"databaseStatus"`
	NodeTotal           int                   `json:"nodeTotal"`
	NodeReachable       int                   `json:"nodeReachable"`
	TunnelTotal         int                   `json:"tunnelTotal"`
	TunnelRunning       int                   `json:"tunnelRunning"`
	ActiveSessions      int                   `json:"activeSessions"`
	RunningPortForwards int                   `json:"runningPortForwards"`
	InletFlow           int64                 `json:"inletFlow"`
	ExportFlow          int64                 `json:"exportFlow"`
	Nodes               []monitorNodeSnapshot `json:"nodes"`
}

func (s *server) monitorSnapshot(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	ctx := r.Context()
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取监控节点失败", nil)
		return
	}
	projects, err := s.store.ListProjects(ctx)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取监控项目失败", nil)
		return
	}
	sessions, err := s.store.ListActiveAccessSessions(ctx)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取活动会话失败", nil)
		return
	}
	runningForwards := 0
	for _, project := range projects {
		forwards, listErr := s.store.ListPortForwards(ctx, project.ID)
		if listErr != nil {
			writeError(w, r, http.StatusInternalServerError, "database_error", "读取端口转发状态失败", nil)
			return
		}
		for _, forward := range forwards {
			if forward.Status == "running" {
				runningForwards++
			}
		}
	}

	collectedAt := time.Now().UTC()
	result := monitorSnapshotResponse{
		CollectedAt: collectedAt, DatabaseStatus: "ready", NodeTotal: len(nodes),
		ActiveSessions: len(sessions), RunningPortForwards: runningForwards,
		Nodes: make([]monitorNodeSnapshot, len(nodes)),
	}
	var group sync.WaitGroup
	for index, node := range nodes {
		result.Nodes[index] = monitorNodeSnapshot{NodeID: node.ID, Name: node.Name, Status: "maintenance", Message: "节点已停用", CheckedAt: collectedAt}
		if !node.Enabled {
			continue
		}
		if s.nodes == nil {
			result.Nodes[index].Status = "unavailable"
			result.Nodes[index].Message = "节点适配器未启用"
			continue
		}
		group.Add(1)
		go func(itemIndex int, nodeID string) {
			defer group.Done()
			started := time.Now()
			requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			tunnels, listErr := s.nodes.ListManagedTunnels(requestCtx, nodeID)
			checkedAt := time.Now().UTC()
			nodeResult := &result.Nodes[itemIndex]
			nodeResult.CheckedAt = checkedAt
			nodeResult.LatencyMS = time.Since(started).Milliseconds()
			if listErr != nil {
				nodeResult.Status = "unreachable"
				nodeResult.Message = "节点 API 或托管通道接口不可达"
				return
			}
			nodeResult.Status = "healthy"
			nodeResult.Reachable = true
			nodeResult.Message = "ok"
			nodeResult.TunnelCount = len(tunnels)
			for _, tunnel := range tunnels {
				if tunnel.Running {
					nodeResult.RunningTunnels++
				}
				nodeResult.InletFlow += tunnel.InletFlow
				nodeResult.ExportFlow += tunnel.ExportFlow
			}
		}(index, node.ID)
	}
	group.Wait()
	for _, node := range result.Nodes {
		if node.Reachable {
			result.NodeReachable++
		}
		result.TunnelTotal += node.TunnelCount
		result.TunnelRunning += node.RunningTunnels
		result.InletFlow += node.InletFlow
		result.ExportFlow += node.ExportFlow
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) nodeClients(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	clients, err := s.nodes.ListClients(r.Context(), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_request_failed", "读取节点客户端失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": clients, "total": len(clients)})
}

func (s *server) nodeClientCredentials(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	clientID, err := strconv.Atoi(r.PathValue("clientID"))
	if err != nil || clientID < 1 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Client ID 无效", nil)
		return
	}
	credentials, err := s.nodes.ClientCredentials(r.Context(), r.PathValue("nodeID"), clientID)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_request_failed", "读取 Client 认证信息失败", nil)
		return
	}
	audit := auditFromRequest(r, "node_client.credentials.read", "node_client")
	audit.ResourceID = fmt.Sprintf("%s:%d", r.PathValue("nodeID"), clientID)
	if err := s.store.AppendAudit(r.Context(), audit); err != nil {
		writeError(w, r, http.StatusInternalServerError, "audit_write_failed", "无法记录凭据查看审计", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, credentials)
}

func (s *server) createNodeClient(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	var input struct {
		Remark        string `json:"remark"`
		BasicUsername string `json:"basicUsername"`
		BasicPassword string `json:"basicPassword"`
		VerifyKey     string `json:"verifyKey"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Remark = strings.TrimSpace(input.Remark)
	input.BasicUsername = strings.TrimSpace(input.BasicUsername)
	input.VerifyKey = strings.TrimSpace(input.VerifyKey)
	if input.Remark == "" || len([]rune(input.Remark)) > 120 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Client 配置校验失败", map[string]string{"remark": "Client 名称必填且不能超过 120 个字符"})
		return
	}
	if input.BasicUsername == "" || len([]rune(input.BasicUsername)) > 120 || len([]rune(input.BasicPassword)) > 256 || (input.VerifyKey != "" && len([]rune(input.VerifyKey)) < 8) || len([]rune(input.VerifyKey)) > 256 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Client 认证信息校验失败", map[string]string{"credentials": "Basic 用户名必填；密码和唯一验证密钥可留空自动生成"})
		return
	}
	generatedVerifyKey := input.VerifyKey == ""
	if input.BasicPassword == "" {
		generatedPassword, generationErr := newNPSCompatibleSecret(16)
		if generationErr != nil {
			writeError(w, r, http.StatusInternalServerError, "credential_generation_failed", "无法生成 Basic 认证密码", nil)
			return
		}
		input.BasicPassword = generatedPassword
	}
	if generatedVerifyKey {
		generatedKey, generationErr := newNPSCompatibleSecret(16)
		if generationErr != nil {
			writeError(w, r, http.StatusInternalServerError, "credential_generation_failed", "无法生成唯一验证密钥", nil)
			return
		}
		input.VerifyKey = generatedKey
	}
	nodeID := r.PathValue("nodeID")
	var client nodeadapter.Client
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		client, err = s.nodes.CreateClient(r.Context(), nodeID, input.Remark, input.VerifyKey, input.BasicUsername, input.BasicPassword)
		if !errors.Is(err, nodeadapter.ErrDuplicateVerifyKey) || !generatedVerifyKey {
			break
		}
		input.VerifyKey, err = newNPSCompatibleSecret(16)
		if err != nil {
			break
		}
	}
	if err != nil {
		if errors.Is(err, nodeadapter.ErrDuplicateVerifyKey) {
			writeError(w, r, http.StatusConflict, "verify_key_conflict", "唯一验证密钥已被其他 Client 使用", nil)
			return
		}
		writeError(w, r, http.StatusBadGateway, "client_create_failed", "接入节点创建 Client 失败", nil)
		return
	}
	audit := auditFromRequest(r, "node_client.create", "node_client")
	audit.ResourceID = fmt.Sprintf("%s:%d", nodeID, client.ID)
	metadata, _ := json.Marshal(map[string]any{"nodeId": nodeID, "clientId": client.ID, "remark": input.Remark})
	audit.MetadataJSON = string(metadata)
	if err := s.store.AppendAudit(r.Context(), audit); err != nil {
		_ = s.nodes.DeleteClient(context.WithoutCancel(r.Context()), nodeID, client.ID)
		writeError(w, r, http.StatusInternalServerError, "audit_write_failed", "Client 创建已回滚，审计写入失败", nil)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"client":      client,
		"credentials": nodeadapter.ClientCredentials{BasicUsername: input.BasicUsername, BasicPassword: input.BasicPassword, VerifyKey: input.VerifyKey},
	})
}

func (s *server) managedTunnels(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	tunnels, err := s.nodes.ListManagedTunnels(r.Context(), r.PathValue("nodeID"))
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "node_request_failed", "读取托管通道失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": tunnels, "total": len(tunnels)})
}

func (s *server) setManagedTunnel(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	clientID, err := strconv.Atoi(r.PathValue("clientID"))
	if err != nil || clientID < 1 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "Client ID 必须是正整数", map[string]string{"clientId": "必须是正整数"})
		return
	}
	action := r.PathValue("action")
	if action != "start" && action != "stop" {
		writeError(w, r, http.StatusNotFound, "not_found", "不支持的通道操作", nil)
		return
	}
	running := action == "start"
	if err := s.nodes.SetManagedTunnel(r.Context(), r.PathValue("nodeID"), clientID, running); err != nil {
		writeError(w, r, http.StatusBadGateway, "tunnel_operation_failed", "托管通道操作失败", nil)
		return
	}
	audit := auditFromRequest(r, "managed_tunnel."+action, "managed_tunnel")
	audit.ResourceID = fmt.Sprintf("%s:socks5:%d", r.PathValue("nodeID"), clientID)
	if err := s.store.AppendAudit(r.Context(), audit); err != nil {
		writeError(w, r, http.StatusInternalServerError, "audit_write_failed", "通道操作已执行，但审计写入失败，请立即核对节点状态", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"clientId": clientID, "running": running})
}

func (s *server) listProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.store.ListProjects(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取客户项目失败", nil)
		return
	}
	current := principalFromRequest(r)
	if !current.Bootstrap && current.Role != "system_admin" {
		allowed := map[string]struct{}{}
		for _, projectID := range current.ProjectIDs {
			allowed[projectID] = struct{}{}
		}
		if current.Role == "temporary" {
			for _, project := range projects {
				web, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, project.ID, "web", time.Now().UTC())
				webSSH, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, project.ID, "webssh", time.Now().UTC())
				if web || webSSH {
					allowed[project.ID] = struct{}{}
				}
			}
		}
		filtered := make([]store.Project, 0, len(projects))
		for _, project := range projects {
			if _, exists := allowed[project.ID]; exists {
				if current.Role == "temporary" {
					// Temporary access only needs the opaque project identity.
					// Do not disclose the bound Client or CIDR scope.
					project.OwnerName = ""
					project.ClientID = nil
					project.Networks = []string{}
				}
				filtered = append(filtered, project)
			}
		}
		projects = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": projects, "total": len(projects)})
}

func (s *server) createProject(w http.ResponseWriter, r *http.Request) {
	var input store.CreateProjectInput
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Networks = canonicalCIDRs(input.Networks)
	fields := validateProject(input)
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "项目配置校验失败", fields)
		return
	}
	codeSuffix, err := id.New()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "id_generation_failed", "无法生成项目编号", nil)
		return
	}
	code := fmt.Sprintf("PRJ-%d-%s", time.Now().UTC().Year(), strings.ToUpper(strings.ReplaceAll(codeSuffix[:8], "-", "")))
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	clients, err := s.nodes.ListClients(r.Context(), input.NodeID)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "client_lookup_failed", "无法校验所选 Client", nil)
		return
	}
	clientFound := false
	for _, client := range clients {
		if input.ClientID != nil && client.ID == *input.ClientID {
			clientFound = true
			break
		}
	}
	if !clientFound {
		writeError(w, r, http.StatusUnprocessableEntity, "client_not_found", "所选 Client 不存在于当前节点", map[string]string{"clientId": "Client 不存在"})
		return
	}
	tunnels, err := s.nodes.ListManagedTunnels(r.Context(), input.NodeID)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "tunnel_lookup_failed", "无法校验所选 Client 对应的 SOCKS 代理", nil)
		return
	}
	tunnelFound := false
	for _, tunnel := range tunnels {
		if input.ClientID != nil && tunnel.ID == *input.ClientID && tunnel.ClientID == *input.ClientID {
			tunnelFound = true
			break
		}
	}
	if !tunnelFound {
		writeError(w, r, http.StatusUnprocessableEntity, "tunnel_not_found", "所选 Client 没有同 ID 的 SOCKS 代理", map[string]string{"clientId": "Client ID 与 SOCKS 代理 ID 不一致或代理不存在"})
		return
	}
	project, err := s.store.CreateProject(r.Context(), code, input, auditFromRequest(r, "project.create", "project"))
	if err != nil {
		writeError(w, r, http.StatusConflict, "project_create_failed", "项目创建失败，请检查节点、Client 或项目名称", nil)
		return
	}
	writeJSON(w, http.StatusCreated, project)
}

func (s *server) updateProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	var input store.UpdateProjectInput
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Networks = canonicalCIDRs(input.Networks)
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "项目名称不能为空"
	}
	if strings.TrimSpace(input.OwnerName) == "" {
		fields["ownerName"] = "负责人不能为空"
	}
	for _, network := range input.Networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil || !prefix.Addr().Is4() {
			fields["networks"] = "设备发现网段必须是合法 IPv4 CIDR"
		}
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "项目设置校验失败", fields)
		return
	}
	project, err := s.store.UpdateProject(r.Context(), projectID, input, auditFromRequest(r, "project.update", "project"))
	if err != nil {
		writeError(w, r, http.StatusConflict, "project_update_failed", "项目设置更新失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, project)
}

func (s *server) deleteProject(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	projectID := r.PathValue("projectID")
	_, err := s.store.ProjectByID(r.Context(), projectID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取待删除项目", nil)
		return
	}
	forwards, err := s.store.ListPortForwards(r.Context(), projectID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法检查项目端口转发", nil)
		return
	}
	if len(forwards) > 0 {
		writeError(w, r, http.StatusConflict, "project_in_use", "项目仍有端口转发，请先在项目的端口转发页删除并释放节点端口", nil)
		return
	}
	sessions, err := s.store.ListActiveAccessSessions(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法检查项目活动访问会话", nil)
		return
	}
	for _, session := range sessions {
		if session.ProjectID == projectID {
			writeError(w, r, http.StatusConflict, "project_in_use", "项目仍有活动访问会话，请先在运行监控中终止会话", nil)
			return
		}
	}
	jobs, err := s.store.ListDiscoveryJobs(r.Context(), projectID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法检查项目扫描任务", nil)
		return
	}
	for _, job := range jobs {
		if job.Status == "queued" || job.Status == "running" {
			writeError(w, r, http.StatusConflict, "project_in_use", "项目仍有正在排队或运行的扫描任务，请先取消扫描", nil)
			return
		}
	}
	if err := s.store.DeleteProject(r.Context(), projectID, auditFromRequest(r, "project.delete", "project")); errors.Is(err, store.ErrInUse) {
		writeError(w, r, http.StatusConflict, "project_in_use", "项目仍有活动访问会话或扫描任务，请先终止后再删除", nil)
		return
	} else if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusInternalServerError, "project_delete_failed", "项目删除失败", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.store.ListDevices(r.Context(), r.PathValue("projectID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取项目设备失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": devices, "total": len(devices)})
}

func (s *server) createDevice(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	var input store.CreateDeviceInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Source == "" {
		input.Source = "manual"
	}
	normalizeEndpointTLS(input.Endpoints)
	fields := validateDevice(input)
	_, err := s.store.ProjectNetworks(r.Context(), projectID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取客户项目失败", nil)
		return
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "设备配置校验失败", fields)
		return
	}
	rollbacks, err := s.prepareSSHCredentials(r.Context(), input.Endpoints)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "ssh_credential_invalid", err.Error(), nil)
		return
	}
	device, err := s.store.CreateDevice(r.Context(), projectID, input, auditFromRequest(r, "device.create", "device"))
	if err != nil {
		runRollbacks(rollbacks)
		writeError(w, r, http.StatusConflict, "device_create_failed", "设备创建失败，同一项目不能重复登记相同地址或服务", nil)
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

type createDeviceBatchRequest struct {
	Items []store.CreateDeviceInput `json:"items"`
}

func (s *server) createDeviceBatch(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	var input createDeviceBatchRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Items) < 1 || len(input.Items) > 500 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "批量导入必须包含 1-500 台设备", map[string]string{"items": "数量必须位于 1-500"})
		return
	}
	_, err := s.store.ProjectNetworks(r.Context(), projectID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取客户项目失败", nil)
		return
	}
	fields := map[string]string{}
	hosts := map[string]int{}
	for index := range input.Items {
		item := &input.Items[index]
		if item.Source == "" {
			item.Source = "import"
		}
		normalizeEndpointTLS(item.Endpoints)
		for key, message := range validateDevice(*item) {
			fields[fmt.Sprintf("items[%d].%s", index, key)] = message
		}
		if previous, exists := hosts[item.Host]; exists {
			fields[fmt.Sprintf("items[%d].host", index)] = fmt.Sprintf("与第 %d 台设备地址重复", previous+1)
		} else {
			hosts[item.Host] = index
		}
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "批量设备配置校验失败", fields)
		return
	}
	devices, err := s.store.CreateDevices(r.Context(), projectID, input.Items, auditFromRequest(r, "device.batch_create", "device"))
	if err != nil {
		writeError(w, r, http.StatusConflict, "device_batch_create_failed", "批量导入未写入任何数据；请检查项目内重复地址或服务", nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"items": devices, "total": len(devices)})
}

func (s *server) updateDevice(w http.ResponseWriter, r *http.Request) {
	var input store.UpdateDeviceInput
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "设备名称不能为空"
	}
	if input.Host != "" && net.ParseIP(input.Host) == nil {
		fields["host"] = "设备地址必须是合法 IP"
	}
	if input.Endpoints != nil {
		normalizeEndpointTLS(*input.Endpoints)
		endpointFields := validateDevice(store.CreateDeviceInput{Host: "127.0.0.1", Name: input.Name, Source: "manual", Endpoints: *input.Endpoints})
		delete(endpointFields, "host")
		delete(endpointFields, "name")
		for key, message := range endpointFields {
			fields[key] = message
		}
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "设备配置校验失败", fields)
		return
	}
	rollbacks := []func(){}
	var err error
	if input.Endpoints != nil {
		rollbacks, err = s.prepareSSHCredentials(r.Context(), *input.Endpoints)
		if err != nil {
			writeError(w, r, http.StatusUnprocessableEntity, "ssh_credential_invalid", err.Error(), nil)
			return
		}
	}
	device, err := s.store.UpdateDevice(r.Context(), r.PathValue("projectID"), r.PathValue("deviceID"), input, auditFromRequest(r, "device.update", "device"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "device_not_found", "设备不存在", nil)
		return
	}
	if err != nil {
		runRollbacks(rollbacks)
		message := "设备更新失败"
		if strings.Contains(err.Error(), "is in use") {
			message = "该访问入口正在使用中，只能修改名称和安全设置；停止访问后才能删除或修改协议、端口"
		}
		writeError(w, r, http.StatusConflict, "device_update_failed", message, nil)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func runRollbacks(rollbacks []func()) {
	for index := len(rollbacks) - 1; index >= 0; index-- {
		rollbacks[index]()
	}
}

func (s *server) prepareSSHCredentials(ctx context.Context, endpoints []store.CreateEndpointInput) ([]func(), error) {
	rollbacks := []func(){}
	for index := range endpoints {
		endpoint := &endpoints[index]
		if endpoint.Protocol != "ssh" || endpoint.SSHCredential == nil {
			continue
		}
		credential := endpoint.SSHCredential
		credential.Method = strings.TrimSpace(credential.Method)
		credential.Username = strings.TrimSpace(credential.Username)
		if credential.Username == "" {
			runRollbacks(rollbacks)
			return nil, fmt.Errorf("SSH 用户名不能为空")
		}
		if endpoint.ID == "" {
			generated, err := id.New()
			if err != nil {
				runRollbacks(rollbacks)
				return nil, err
			}
			endpoint.ID = generated
			endpoint.IsNew = true
		}
		currentReference := ""
		if route, err := s.store.EndpointRoute(ctx, endpoint.ID); err == nil {
			currentReference = route.CredentialRef
		}
		switch credential.Method {
		case "password":
			if s.nodeCredentials == nil {
				runRollbacks(rollbacks)
				return nil, fmt.Errorf("SSH 加密凭据库不可用")
			}
			reference, rollback, err := s.nodeCredentials.SaveSSH(ctx, endpoint.ID, currentReference, secrets.SSHCredentialPatch{Username: credential.Username, Password: credential.Password})
			if err != nil {
				runRollbacks(rollbacks)
				return nil, err
			}
			endpoint.CredentialRef = reference
			endpoint.SSHAuthMethod = "password"
			endpoint.SSHUsername = credential.Username
			endpoint.SSHKeyPath = ""
			rollbacks = append(rollbacks, rollback)
		case "key":
			path := strings.TrimSpace(credential.KeyPath)
			if !filepath.IsAbs(path) {
				runRollbacks(rollbacks)
				return nil, fmt.Errorf("SSH 私钥必须填写服务器上的绝对路径")
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				runRollbacks(rollbacks)
				return nil, fmt.Errorf("SSH 私钥文件不存在或不可读")
			}
			endpoint.CredentialRef = "file://" + path
			endpoint.SSHAuthMethod = "key"
			endpoint.SSHUsername = credential.Username
			endpoint.SSHKeyPath = path
		default:
			runRollbacks(rollbacks)
			return nil, fmt.Errorf("SSH 登录方式必须选择密码或密钥")
		}
		endpoint.SSHCredential = nil
	}
	return rollbacks, nil
}

func (s *server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	err := s.store.DeleteDevice(r.Context(), r.PathValue("projectID"), r.PathValue("deviceID"), auditFromRequest(r, "device.delete", "device"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "device_not_found", "设备不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "device_in_use", "设备仍有转发或活动访问会话，请先终止相关资源", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) verifyDevice(w http.ResponseWriter, r *http.Request) {
	if s.discovery == nil {
		writeError(w, r, http.StatusServiceUnavailable, "discovery_unavailable", "设备检测服务尚未启用", nil)
		return
	}
	projectID, deviceID := r.PathValue("projectID"), r.PathValue("deviceID")
	devices, err := s.store.ListDevices(r.Context(), projectID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取设备失败", nil)
		return
	}
	var device *store.Device
	for index := range devices {
		if devices[index].ID == deviceID {
			device = &devices[index]
			break
		}
	}
	if device == nil {
		writeError(w, r, http.StatusNotFound, "device_not_found", "设备不存在", nil)
		return
	}
	if len(device.Endpoints) == 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "device_has_no_endpoints", "设备没有可检测的已登记服务", nil)
		return
	}
	route, err := s.store.DiscoveryRoute(r.Context(), projectID)
	if err != nil {
		writeError(w, r, http.StatusConflict, "gateway_not_bound", "项目尚未绑定可用通道", nil)
		return
	}
	ports := make([]store.DiscoveryPort, 0, len(device.Endpoints))
	for _, endpoint := range device.Endpoints {
		ports = append(ports, store.DiscoveryPort{Name: endpoint.Name, Protocol: endpoint.Protocol, Port: endpoint.TargetPort})
	}
	probeCtx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	results, err := s.discovery.Verify(probeCtx, route, device.Host, ports)
	if err != nil {
		writeError(w, r, http.StatusBadGateway, "device_verify_failed", "设备检测无法完成："+err.Error(), nil)
		return
	}
	verifiedKeys := make(map[string]bool, len(results))
	for _, result := range results {
		verifiedKeys[fmt.Sprintf("%s:%d", result.Protocol, result.Port)] = true
	}
	statuses := make(map[string]bool, len(device.Endpoints))
	for _, endpoint := range device.Endpoints {
		statuses[endpoint.ID] = verifiedKeys[fmt.Sprintf("%s:%d", endpoint.Protocol, endpoint.TargetPort)]
	}
	updated, err := s.store.VerifyDeviceEndpoints(r.Context(), projectID, deviceID, statuses, auditFromRequest(r, "device.verify", "device"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "device_not_found", "设备或服务已被删除，请刷新后重试", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "device_verify_store_failed", "检测已完成，但状态保存失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device": updated, "verified": len(results), "failed": len(device.Endpoints) - len(results)})
}

type createAccessSessionRequest struct {
	EndpointID string `json:"endpointId"`
	Mode       string `json:"mode"`
}

func (s *server) createAccessSession(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	var input createAccessSessionRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Mode != "web" && input.Mode != "ssh" {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "访问模式必须为 web 或 ssh", map[string]string{"mode": "仅支持 web 或 ssh"})
		return
	}
	route, err := s.store.EndpointRoute(r.Context(), input.EndpointID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "endpoint_not_found", "访问入口不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取访问入口失败", nil)
		return
	}
	current := principalFromRequest(r)
	allowed := canAccessProject(current, route.ProjectID, input.Mode)
	if !allowed && current.Role == "temporary" {
		capability := "web"
		if input.Mode == "ssh" {
			capability = "webssh"
		}
		allowed, _ = s.store.HasPolicyCapability(r.Context(), current.UserID, route.ProjectID, capability, time.Now().UTC())
	}
	if !allowed {
		writeError(w, r, http.StatusForbidden, "forbidden", "当前用户无权访问该项目或该类型入口", nil)
		return
	}
	if (input.Mode == "web" && route.AccessType != "web_proxy") || (input.Mode == "ssh" && route.AccessType != "web_ssh") {
		writeError(w, r, http.StatusUnprocessableEntity, "mode_mismatch", "访问模式与 Endpoint 类型不匹配", nil)
		return
	}
	if route.ClientID < 1 {
		writeError(w, r, http.StatusConflict, "gateway_not_bound", "项目尚未绑定可用 Client", nil)
		return
	}
	if err := s.nodes.SetManagedTunnel(r.Context(), route.NodeID, route.ClientID, true); err != nil {
		writeError(w, r, http.StatusBadGateway, "managed_tunnel_unavailable", "远程访问前无法启动托管通道", nil)
		return
	}
	token, tokenHash, err := newAccessToken()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "token_generation_failed", "无法创建安全访问令牌", nil)
		return
	}
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	session, err := s.store.CreateAccessSession(r.Context(), store.CreateAccessSessionInput{ProjectID: route.ProjectID, EndpointID: route.EndpointID, TokenHash: tokenHash, Mode: input.Mode, SourceIP: requestSourceIP(r), ExpiresAt: expiresAt}, auditFromRequest(r, "access_session.create", "access_session"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "session_create_failed", "访问会话创建失败", nil)
		return
	}
	launchURL := "/access/web/" + token + "/"
	if input.Mode == "web" && s.accessDomain != "" {
		launchURL = webAccessLaunchURL(r, s.accessScheme, s.accessDomain, s.mode, token)
	}
	if input.Mode == "ssh" {
		launchURL = "/access/ssh/" + token
	}
	writeJSON(w, http.StatusCreated, map[string]any{"sessionId": session.ID, "launchUrl": launchURL, "expiresAt": session.ExpiresAt})
}

func webAccessLaunchURL(r *http.Request, scheme, accessDomain, mode, token string) string {
	authority := token + "." + accessDomain
	// Local wildcard domains run the production binary on a high loopback port.
	// Preserve that port so *.localhost exercises exactly the same one-session,
	// one-origin routing model as a deployed wildcard DNS domain.
	if mode == "dev" || accessDomain == "localhost" || strings.HasSuffix(accessDomain, ".localhost") || strings.HasSuffix(accessDomain, ".127.0.0.1.nip.io") {
		if _, port, err := net.SplitHostPort(r.Host); err == nil && port != "" {
			authority = net.JoinHostPort(authority, port)
		}
	}
	return scheme + "://" + authority + "/"
}

func (s *server) listAccessSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.ListActiveAccessSessions(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取活动访问会话失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": sessions, "total": len(sessions)})
}

func (s *server) revokeAccessSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("sessionID")
	err := s.store.RevokeAccessSession(r.Context(), sessionID, auditFromRequest(r, "access_session.revoke", "access_session"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "session_not_found", "活动访问会话不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "session_revoke_failed", "访问会话吊销失败", nil)
		return
	}
	if s.sessionRevoker != nil {
		s.sessionRevoker.Revoke(sessionID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listPortForwards(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListPortForwards(r.Context(), r.PathValue("projectID"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取端口转发失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

type createPortForwardRequest struct {
	EndpointID string     `json:"endpointId"`
	ServerPort int        `json:"serverPort"`
	ExpiresAt  *time.Time `json:"expiresAt"`
}

func (s *server) createPortForward(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	var input createPortForwardRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := map[string]string{}
	if strings.TrimSpace(input.EndpointID) == "" {
		fields["endpointId"] = "必须选择非 Web 访问入口"
	}
	if input.ServerPort < 0 || input.ServerPort > 65535 {
		fields["serverPort"] = "指定端口必须位于 1-65535，或传 0 自动分配"
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC()) {
		fields["expiresAt"] = "到期时间必须晚于当前时间"
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "端口转发配置校验失败", fields)
		return
	}
	projectID := r.PathValue("projectID")
	forward, err := s.store.ReservePortForward(r.Context(), store.ReservePortForwardInput{ProjectID: projectID, EndpointID: input.EndpointID, ServerPort: input.ServerPort, ExpiresAt: input.ExpiresAt}, auditFromRequest(r, "port_forward.reserve", "port_forward"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "endpoint_not_found", "项目或访问入口不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "port_reservation_failed", "无法预留转发端口，请检查端口池、重复服务或 Endpoint 类型", nil)
		return
	}
	nodeTask, err := s.nodes.CreatePortForward(r.Context(), forward.NodeID, forward.ClientID, forward.ServerPort, forward.Target, forward.EndpointName)
	if err != nil {
		_ = s.store.DeletePortForward(context.WithoutCancel(r.Context()), forward.ID, auditFromRequest(r, "port_forward.provision_failed", "port_forward"))
		writeError(w, r, http.StatusBadGateway, "node_port_forward_failed", "接入节点创建端口转发失败，预留已释放", nil)
		return
	}
	if err := s.store.ActivatePortForward(r.Context(), forward.ID, nodeTask.ID); err != nil {
		_ = s.nodes.DeletePortForward(context.WithoutCancel(r.Context()), forward.NodeID, nodeTask.ID)
		_ = s.store.DeletePortForward(context.WithoutCancel(r.Context()), forward.ID, auditFromRequest(r, "port_forward.rollback", "port_forward"))
		writeError(w, r, http.StatusInternalServerError, "port_forward_commit_failed", "转发任务已回滚，请重试", nil)
		return
	}
	forward.NodeTaskID = &nodeTask.ID
	forward.Status = "running"
	writeJSON(w, http.StatusCreated, forward)
}

func (s *server) setPortForward(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	action := r.PathValue("action")
	if action != "start" && action != "stop" {
		writeError(w, r, http.StatusNotFound, "not_found", "不支持的转发操作", nil)
		return
	}
	forward, err := s.store.PortForwardByID(r.Context(), r.PathValue("forwardID"))
	if errors.Is(err, store.ErrNotFound) || forward.NodeTaskID == nil {
		writeError(w, r, http.StatusNotFound, "port_forward_not_found", "端口转发不存在或尚未完成创建", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取端口转发失败", nil)
		return
	}
	running := action == "start"
	if err := s.nodes.SetPortForward(r.Context(), forward.NodeID, *forward.NodeTaskID, running); err != nil {
		writeError(w, r, http.StatusBadGateway, "node_port_forward_failed", "接入节点未能执行转发操作", nil)
		return
	}
	status := "stopped"
	if running {
		status = "running"
	}
	if err := s.store.SetPortForwardStatus(r.Context(), forward.ID, status, auditFromRequest(r, "port_forward."+action, "port_forward")); err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "节点操作已执行，但平台状态写入失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": forward.ID, "status": status})
}

func (s *server) deletePortForward(w http.ResponseWriter, r *http.Request) {
	if s.nodes == nil {
		writeError(w, r, http.StatusServiceUnavailable, "node_adapter_unavailable", "节点适配器尚未启用", nil)
		return
	}
	forward, err := s.store.PortForwardByID(r.Context(), r.PathValue("forwardID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "port_forward_not_found", "端口转发不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取端口转发失败", nil)
		return
	}
	if forward.NodeTaskID != nil {
		if err := s.nodes.DeletePortForward(r.Context(), forward.NodeID, *forward.NodeTaskID); err != nil {
			writeError(w, r, http.StatusBadGateway, "node_port_forward_failed", "接入节点删除转发失败，平台记录已保留", nil)
			return
		}
	}
	if err := s.store.DeletePortForward(r.Context(), forward.ID, auditFromRequest(r, "port_forward.delete", "port_forward")); err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "删除端口转发记录失败", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createDiscoveryJobRequest struct {
	Networks []string              `json:"networks"`
	Ports    []store.DiscoveryPort `json:"ports"`
}

func (s *server) getProjectScanPorts(w http.ResponseWriter, r *http.Request) {
	ports, err := s.store.ProjectScanPorts(r.Context(), r.PathValue("projectID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取项目扫描端口失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ports})
}

func (s *server) updateProjectScanPorts(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Ports []store.DiscoveryPort `json:"ports"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := validateDiscoveryPorts(input.Ports)
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "扫描端口配置校验失败", fields)
		return
	}
	projectID := r.PathValue("projectID")
	if err := s.store.ReplaceProjectScanPorts(r.Context(), projectID, input.Ports, auditFromRequest(r, "project.scan_ports.update", "project")); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusConflict, "scan_ports_update_failed", "保存项目扫描端口失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": input.Ports})
}

func (s *server) createDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	if s.discovery == nil {
		writeError(w, r, http.StatusServiceUnavailable, "discovery_unavailable", "自动发现 Worker 尚未启用", nil)
		return
	}
	projectID := r.PathValue("projectID")
	route, err := s.store.DiscoveryRoute(r.Context(), projectID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "project_not_found", "客户项目不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取项目发现范围", nil)
		return
	}
	var input createDiscoveryJobRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Networks) == 0 {
		input.Networks = append([]string(nil), route.Networks...)
	}
	if len(input.Ports) == 0 {
		input.Ports, err = s.store.ProjectScanPorts(r.Context(), projectID)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "database_error", "读取项目扫描端口失败", nil)
			return
		}
	}
	input.Networks = canonicalCIDRs(input.Networks)
	fields := validateDiscoveryInput(input, route.Networks)
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "自动发现配置校验失败", fields)
		return
	}
	job, err := s.store.CreateDiscoveryJob(r.Context(), projectID, input.Networks, input.Ports, auditFromRequest(r, "discovery.create", "discovery_job"))
	if err != nil {
		writeError(w, r, http.StatusConflict, "discovery_create_failed", "无法创建自动发现任务", nil)
		return
	}
	if err := s.discovery.Start(r.Context(), job, route); err != nil {
		_ = s.store.SetDiscoveryJobState(context.WithoutCancel(r.Context()), job.ID, "failed", 0)
		writeError(w, r, http.StatusUnprocessableEntity, "discovery_start_failed", "自动发现任务无法启动，请检查范围、端口数和项目通道", nil)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *server) listDiscoveryJobs(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.ListDiscoveryJobs(r.Context(), r.PathValue("projectID"))
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取发现任务失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *server) getDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.DiscoveryJob(r.Context(), r.PathValue("jobID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "discovery_not_found", "发现任务不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取发现任务失败", nil)
		return
	}
	results, err := s.store.ListDiscoveryResults(r.Context(), job.ID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取发现结果失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "results": results})
}

func (s *server) cancelDiscoveryJob(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("jobID")
	if _, err := s.store.DiscoveryJob(r.Context(), jobID); errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "discovery_not_found", "发现任务不存在", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取发现任务失败", nil)
		return
	}
	if s.discovery != nil {
		s.discovery.Cancel(jobID)
	}
	if err := s.store.SetDiscoveryJobState(r.Context(), jobID, "canceled", 0); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusInternalServerError, "database_error", "取消发现任务失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": jobID, "status": "canceled"})
}

func (s *server) importDiscoveryDevice(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.DiscoveryJob(r.Context(), r.PathValue("jobID"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "discovery_not_found", "发现任务不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取发现任务失败", nil)
		return
	}
	var input store.CreateDeviceInput
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Source = "discovery"
	normalizeEndpointTLS(input.Endpoints)
	fields := validateDevice(input)
	if _, exists := fields["host"]; !exists && !addressAllowedByCIDRs(input.Host, job.Networks) {
		fields["host"] = "设备地址不属于本次发现任务的扫描网段"
	}
	if len(input.Endpoints) == 0 {
		fields["endpoints"] = "至少选择或补充一个命名服务"
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "发现结果导入校验失败", fields)
		return
	}
	device, err := s.store.ImportDiscoveryDevice(r.Context(), job.ID, input, auditFromRequest(r, "discovery.import", "device"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "discovery_result_not_found", "该主机不属于当前发现结果", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "discovery_import_failed", "发现结果导入或合并失败，任务必须已完成", nil)
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func validateDiscoveryInput(input createDiscoveryJobRequest, allowedNetworks []string) map[string]string {
	fields := map[string]string{}
	if len(input.Networks) == 0 {
		fields["networks"] = "至少选择一个项目扫描网段"
	}
	for _, network := range input.Networks {
		requested, err := netip.ParsePrefix(network)
		if err != nil || !requested.Addr().Is4() {
			fields["networks"] = "发现范围必须是合法 IPv4 CIDR"
			break
		}
		allowed := false
		for _, value := range allowedNetworks {
			parent, parseErr := netip.ParsePrefix(value)
			if parseErr == nil && requested.Bits() >= parent.Bits() && parent.Contains(requested.Addr()) {
				allowed = true
				break
			}
		}
		if !allowed {
			fields["networks"] = "发现范围不能超出项目配置的扫描网段"
			break
		}
	}
	for key, value := range validateDiscoveryPorts(input.Ports) {
		fields[key] = value
	}
	return fields
}

func validateDiscoveryPorts(ports []store.DiscoveryPort) map[string]string {
	fields := map[string]string{}
	if len(ports) == 0 || len(ports) > 64 {
		fields["ports"] = "必须配置 1-64 个扫描端口"
	}
	seen := map[string]struct{}{}
	for index, port := range ports {
		key := fmt.Sprintf("%s:%d", port.Protocol, port.Port)
		if strings.TrimSpace(port.Name) == "" {
			fields[fmt.Sprintf("ports[%d].name", index)] = "服务名称不能为空"
		}
		if port.Port < 1 || port.Port > 65535 {
			fields[fmt.Sprintf("ports[%d].port", index)] = "端口必须位于 1-65535"
		}
		if !supportedDiscoveryProtocol(port.Protocol) {
			fields[fmt.Sprintf("ports[%d].protocol", index)] = "探测协议不受支持"
		}
		if _, exists := seen[key]; exists {
			fields[fmt.Sprintf("ports[%d]", index)] = "不能重复配置相同端口和协议"
		}
		seen[key] = struct{}{}
	}
	return fields
}

func supportedDiscoveryProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "auto", "http", "https", "ssh", "rtsp", "tcp", "rdp", "mysql", "postgresql":
		return true
	default:
		return false
	}
}

func newAccessToken() (string, string, error) {
	// 24 random bytes provide 192 bits of entropy while the 48-character hex
	// representation remains a valid single DNS label (maximum 63 characters).
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := hex.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(digest[:]), nil
}

func newOpaqueSecret(bytesCount int) (string, error) {
	raw := make([]byte, bytesCount)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// newNPSCompatibleSecret matches NPS's 16-character lowercase alphanumeric
// credential format while using crypto/rand instead of a time-seeded PRNG.
func newNPSCompatibleSecret(length int) (string, error) {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	result := make([]byte, 0, length)
	buffer := make([]byte, length*2)
	for len(result) < length {
		if _, err := rand.Read(buffer); err != nil {
			return "", err
		}
		for _, value := range buffer {
			if value >= 252 {
				continue
			}
			result = append(result, alphabet[int(value)%len(alphabet)])
			if len(result) == length {
				break
			}
		}
	}
	return string(result), nil
}

func requestSourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func validateNode(input store.CreateNodeInput) map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "节点名称不能为空"
	}
	parsedURL, err := url.ParseRequestURI(input.APIURL)
	if err != nil || parsedURL.Host == "" || parsedURL.Scheme != "https" {
		fields["apiUrl"] = "API 地址必须是有效的 HTTPS 地址"
	}
	if parsedURL != nil && parsedURL.Scheme == "https" && strings.TrimSpace(input.TLSServerName) == "" {
		fields["tlsServerName"] = "HTTPS 节点必须配置 TLS 校验主机名"
	}
	if !validNodeCredentialReference(input.CredentialRef) {
		fields["credential"] = "必须填写并加密保存节点认证信息"
	}
	if input.PortStart < 1 || input.PortEnd > 65535 || input.PortEnd < input.PortStart {
		fields["portRange"] = "端口池必须位于 1-65535 且结束端口不小于起始端口"
	}
	return fields
}

func validCredentialReference(value string) bool {
	for _, prefix := range []string{"file://", "db://ssh/"} {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) && len(strings.TrimSpace(value)) > len(prefix) {
			return true
		}
	}
	return false
}

func validNodeCredentialReference(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "db://node/") && len(trimmed) > len("db://node/")
}

func canonicalCIDRs(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			continue
		}
		canonical := prefix.Masked().String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	return result
}

func validateProject(input store.CreateProjectInput) map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "项目名称不能为空"
	}
	if strings.TrimSpace(input.NodeID) == "" {
		fields["nodeId"] = "必须选择接入节点"
	}
	if strings.TrimSpace(input.OwnerName) == "" {
		fields["ownerName"] = "负责人不能为空"
	}
	if input.ClientID == nil || *input.ClientID < 1 {
		fields["clientId"] = "必须选择或输入合法 Client ID"
	}
	for _, network := range input.Networks {
		prefix, err := netip.ParsePrefix(network)
		if err != nil || !prefix.Addr().Is4() {
			fields["networks"] = "设备发现网段必须是合法 IPv4 CIDR"
			break
		}
	}
	return fields
}

func validateDevice(input store.CreateDeviceInput) map[string]string {
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "设备名称不能为空"
	}
	address, err := netip.ParseAddr(strings.TrimSpace(input.Host))
	if err != nil || !address.Is4() {
		fields["host"] = "V1 必须填写可校验的 IPv4 地址；主机名需在后续 DNS 固定解析功能中启用"
	}
	if input.Source != "manual" && input.Source != "import" && input.Source != "discovery" {
		fields["source"] = "设备来源必须为 manual、import 或 discovery"
	}
	seen := map[string]struct{}{}
	for index, endpoint := range input.Endpoints {
		prefix := fmt.Sprintf("endpoints[%d]", index)
		if strings.TrimSpace(endpoint.Name) == "" {
			fields[prefix+".name"] = "服务名称不能为空"
		}
		if !supportedEndpointProtocol(endpoint.Protocol) {
			fields[prefix+".protocol"] = "不支持的服务协议"
		}
		if endpoint.TargetPort < 1 || endpoint.TargetPort > 65535 {
			fields[prefix+".targetPort"] = "目标端口必须位于 1-65535"
		}
		if endpoint.Protocol != "https" && (strings.TrimSpace(endpoint.TLSServerName) != "" || endpoint.AllowInsecureTLS) {
			fields[prefix+".tls"] = "仅 HTTPS 服务可配置 TLS 校验选项"
		}
		if endpoint.Protocol != "ssh" && (strings.TrimSpace(endpoint.CredentialRef) != "" || strings.TrimSpace(endpoint.SSHHostKeyFingerprint) != "") {
			fields[prefix+".ssh"] = "仅 SSH 服务可配置凭据和主机密钥校验"
		}
		if endpoint.Protocol == "ssh" && strings.TrimSpace(endpoint.CredentialRef) != "" && !validCredentialReference(endpoint.CredentialRef) {
			fields[prefix+".credentialRef"] = "SSH 授权凭据必须使用密钥引用，不能保存明文"
		}
		key := fmt.Sprintf("%s:%d", endpoint.Protocol, endpoint.TargetPort)
		if _, exists := seen[key]; exists {
			fields[prefix] = "同一设备不能重复登记相同协议和端口"
		}
		seen[key] = struct{}{}
	}
	return fields
}

func normalizeEndpointTLS(endpoints []store.CreateEndpointInput) {
	for index := range endpoints {
		endpoints[index].AllowInsecureTLS = endpoints[index].Protocol == "https"
	}
}

func supportedEndpointProtocol(protocol string) bool {
	switch protocol {
	case "http", "https", "ssh", "rtsp", "tcp", "rdp", "mysql", "postgresql":
		return true
	default:
		return false
	}
}

func addressAllowedByCIDRs(host string, cidrs []string) bool {
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(address) {
			return true
		}
	}
	return false
}

const (
	authCookieName = "dmp_session"
	csrfCookieName = "dmp_csrf"
)

type principal struct {
	UserID      string
	Username    string
	DisplayName string
	Role        string
	ProjectIDs  []string
	Bootstrap   bool
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *server) setupStatus(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.store.HasUsers(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取平台初始化状态", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"initialized": initialized, "mfaEnabled": s.mfaEnabled, "mfaMethods": s.mfaMethods, "smtpConfigured": s.emailSender != nil})
}

type setupRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	var input setupRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	fields := map[string]string{}
	if len(input.Username) < 3 || len(input.Username) > 64 || strings.ContainsAny(input.Username, " /\\@:") {
		fields["username"] = "管理员账号必须为 3-64 位且不能包含空格或路径符号"
	}
	if input.DisplayName == "" {
		fields["displayName"] = "管理员显示名称不能为空"
	}
	passwordHash, err := auth.HashPassword(input.Password)
	if err != nil {
		fields["password"] = "管理员密码必须至少 12 个字符"
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "初始化信息校验失败", fields)
		return
	}
	audit := store.AuditInput{Actor: input.Username, Action: "platform.initialize", ResourceType: "user", Result: "success", RequestID: requestID(r), SourceIP: requestSourceIP(r)}
	user, err := s.store.CreateInitialAdmin(r.Context(), store.CreateUserInput{Username: input.Username, DisplayName: input.DisplayName, PasswordHash: passwordHash, Role: "system_admin", Enabled: true}, audit)
	if errors.Is(err, store.ErrAlreadyInitialized) {
		writeError(w, r, http.StatusConflict, "already_initialized", "平台已经完成初始化", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "setup_failed", "平台初始化失败", nil)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	input.Username = strings.TrimSpace(input.Username)
	if len(input.Username) > 256 || len(input.Password) > 4096 {
		writeError(w, r, http.StatusBadRequest, "invalid_credentials", "登录参数无效", nil)
		return
	}
	now := time.Now().UTC()
	limiterKey := requestSourceIP(r) + "\x00" + strings.ToLower(input.Username)
	if blocked, retry := s.loginLimiter.Blocked(limiterKey, now); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Round(time.Second).Seconds())))
		s.auditLogin(r, input.Username, "rate_limited")
		writeError(w, r, http.StatusTooManyRequests, "login_rate_limited", "登录失败次数过多，请稍后重试", nil)
		return
	}
	credential, err := s.store.UserCredentialByUsername(r.Context(), input.Username)
	if errors.Is(err, store.ErrNotFound) {
		auth.VerifyDummy(input.Password)
		s.loginLimiter.Failure(limiterKey, now)
		s.auditLogin(r, input.Username, "failed")
		writeError(w, r, http.StatusUnauthorized, "login_failed", "用户名或密码错误", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "登录服务暂时不可用", nil)
		return
	}
	if !credential.Enabled || !auth.VerifyPassword(credential.PasswordHash, input.Password) {
		s.loginLimiter.Failure(limiterKey, now)
		s.auditLogin(r, input.Username, "failed")
		writeError(w, r, http.StatusUnauthorized, "login_failed", "用户名或密码错误", nil)
		return
	}
	if !s.mfaEnabled {
		s.loginLimiter.Success(limiterKey)
		if err := s.createPasswordSession(w, r, credential); err != nil {
			writeError(w, r, http.StatusInternalServerError, "session_create_failed", "无法创建登录会话", nil)
		}
		return
	}
	if s.mfa == nil {
		writeError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "双重认证服务尚未配置", nil)
		return
	}
	challengeToken, err := newOpaqueSecret(32)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "challenge_generation_failed", "无法创建双重认证挑战", nil)
		return
	}
	purpose := "verify"
	response := map[string]any{"next": "verify", "challengeToken": challengeToken}
	if credential.PasswordChangeRequired || credential.Email == "" || !credential.MFAEnabled {
		purpose = "onboard"
		response["next"] = "onboard"
		response["methods"] = s.mfaMethods
		response["steps"] = []string{"password", "email", "mfa"}
	} else {
		response["methods"] = []string{credential.MFAPreferredMethod}
		response["preferredMethod"] = credential.MFAPreferredMethod
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	challenge, err := s.store.CreateMFAChallenge(r.Context(), credential.ID, digestString(challengeToken), purpose, "", requestSourceIP(r), expiresAt)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "challenge_create_failed", "无法创建双重认证挑战", nil)
		return
	}
	if credential.MFAEnabled && credential.MFAPreferredMethod == "totp" {
		if err := s.store.SetMFAChallengeMethod(r.Context(), challenge.ID, "totp", "", "", expiresAt); err != nil {
			writeError(w, r, http.StatusInternalServerError, "challenge_create_failed", "无法创建双重认证挑战", nil)
			return
		}
	}
	response["expiresAt"] = expiresAt
	s.loginLimiter.Success(limiterKey)
	s.auditLogin(r, input.Username, "mfa_required")
	writeJSON(w, http.StatusAccepted, response)
}

func (s *server) createPasswordSession(w http.ResponseWriter, r *http.Request, credential store.UserCredential) error {
	token, err := newOpaqueSecret(32)
	if err != nil {
		return err
	}
	csrfToken, err := newOpaqueSecret(32)
	if err != nil {
		return err
	}
	expiresAt := time.Now().UTC().Add(12 * time.Hour)
	sessionRecord, err := s.store.CreateAuthSession(r.Context(), credential.ID, digestString(token), digestString(csrfToken), expiresAt)
	if err != nil {
		return err
	}
	s.auditLogin(r, credential.Username, "success")
	s.setAuthCookies(w, token, csrfToken, expiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"user": sessionRecord.User, "csrfToken": csrfToken, "expiresAt": expiresAt})
	return nil
}

type onboardingPasswordRequest struct {
	ChallengeToken string `json:"challengeToken"`
	NewPassword    string `json:"newPassword"`
}

func (s *server) setOnboardingPassword(w http.ResponseWriter, r *http.Request) {
	var input onboardingPasswordRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	challenge, ok := s.loadOnboardingChallenge(w, r, input.ChallengeToken)
	if !ok {
		return
	}
	credential, err := s.store.UserCredentialByUsername(r.Context(), challenge.User.Username)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取用户凭据状态", nil)
		return
	}
	passwordHash, err := auth.HashPassword(input.NewPassword)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "新密码必须至少 12 个字符", map[string]string{"newPassword": "至少 12 个字符"})
		return
	}
	if auth.VerifyPassword(credential.PasswordHash, input.NewPassword) {
		writeError(w, r, http.StatusUnprocessableEntity, "password_unchanged", "新密码不能与当前密码相同", map[string]string{"newPassword": "必须使用不同密码"})
		return
	}
	if err := s.store.SetOnboardingPassword(r.Context(), challenge.ID, passwordHash); err != nil {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "首次登录引导已失效，请重新登录", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"next": "email"})
}

type onboardingEmailRequest struct {
	ChallengeToken string `json:"challengeToken"`
	Email          string `json:"email"`
	Code           string `json:"code"`
}

func (s *server) sendOnboardingEmail(w http.ResponseWriter, r *http.Request) {
	if s.emailSender == nil {
		writeError(w, r, http.StatusServiceUnavailable, "smtp_unavailable", "邮箱验证尚未配置，请联系部署管理员", nil)
		return
	}
	var input onboardingEmailRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	challenge, ok := s.loadOnboardingChallenge(w, r, input.ChallengeToken)
	if !ok {
		return
	}
	if challenge.NewPasswordHash == "" {
		writeError(w, r, http.StatusConflict, "onboarding_step_required", "请先完成初始密码修改", nil)
		return
	}
	emailAddress, err := auth.NormalizeEmail(input.Email)
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "invalid_email", "请输入有效邮箱地址", map[string]string{"email": "邮箱格式无效"})
		return
	}
	code, err := auth.NewEmailCode()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "email_code_failed", "无法生成邮箱验证码", nil)
		return
	}
	codeHash := s.mfa.EmailCodeHash(challenge.ID, code)
	expiresAt := time.Now().UTC().Add(s.emailCodeTTL)
	if err := s.store.SetOnboardingEmailDelivery(r.Context(), challenge.ID, emailAddress, codeHash, expiresAt); errors.Is(err, store.ErrMFACooldown) {
		writeError(w, r, http.StatusTooManyRequests, "email_rate_limited", "验证码发送过于频繁，请 60 秒后重试", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "首次登录引导已失效，请重新登录", nil)
		return
	}
	if err := s.emailSender.SendCode(r.Context(), emailAddress, code, s.emailCodeTTL); err != nil {
		_ = s.store.ClearMFAEmailDelivery(r.Context(), challenge.ID, codeHash)
		writeError(w, r, http.StatusBadGateway, "smtp_delivery_failed", "验证码邮件发送失败，请检查发件服务器配置", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"maskedEmail": auth.MaskEmail(emailAddress), "expiresAt": expiresAt, "resendAfterSeconds": 60})
}

func (s *server) verifyOnboardingEmail(w http.ResponseWriter, r *http.Request) {
	var input onboardingEmailRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	challenge, ok := s.loadOnboardingChallenge(w, r, input.ChallengeToken)
	if !ok {
		return
	}
	codeHash := s.mfa.EmailCodeHash(challenge.ID, input.Code)
	if err := s.store.VerifyOnboardingEmail(r.Context(), challenge.ID, codeHash); err != nil {
		_ = s.store.FailMFAChallenge(r.Context(), challenge.ID)
		writeError(w, r, http.StatusUnauthorized, "invalid_email_code", "邮箱验证码无效或已过期", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"next": "mfa", "email": auth.MaskEmail(challenge.Email), "methods": s.mfaMethods})
}

type startMFARequest struct {
	ChallengeToken string `json:"challengeToken"`
	Method         string `json:"method"`
}

func (s *server) startMFA(w http.ResponseWriter, r *http.Request) {
	if s.mfa == nil {
		writeError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "双重认证服务尚未配置", nil)
		return
	}
	var input startMFARequest
	if !decodeJSON(w, r, &input) {
		return
	}
	challenge, err := s.store.MFAChallengeByToken(r.Context(), digestString(strings.TrimSpace(input.ChallengeToken)))
	if err != nil {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "双重认证挑战已失效，请重新登录", nil)
		return
	}
	input.Method = strings.ToLower(strings.TrimSpace(input.Method))
	if !s.mfaMethodAllowed(input.Method) {
		writeError(w, r, http.StatusUnprocessableEntity, "mfa_method_unavailable", "该双重认证方式未在配置文件中启用", nil)
		return
	}
	if challenge.Purpose == "onboard" && (challenge.NewPasswordHash == "" || !challenge.EmailVerified) {
		writeError(w, r, http.StatusConflict, "onboarding_step_required", "请先完成密码修改和邮箱验证", nil)
		return
	}
	if challenge.Purpose == "verify" && input.Method != challenge.MFAPreferredMethod {
		writeError(w, r, http.StatusUnprocessableEntity, "mfa_method_unavailable", "该账号未绑定所选认证方式", nil)
		return
	}
	expiresAt := time.Now().UTC().Add(10 * time.Minute)
	if input.Method == "totp" {
		encryptedSecret := ""
		response := map[string]any{"method": "totp", "expiresAt": expiresAt}
		if challenge.Purpose == "onboard" {
			enrollment, enrollmentErr := s.mfa.NewEnrollment(challenge.User.Username)
			if enrollmentErr != nil {
				writeError(w, r, http.StatusInternalServerError, "mfa_enrollment_failed", "无法生成认证器绑定信息", nil)
				return
			}
			encryptedSecret, enrollmentErr = s.mfa.EncryptSecret(challenge.User.ID, enrollment.Secret)
			if enrollmentErr != nil {
				writeError(w, r, http.StatusInternalServerError, "mfa_enrollment_failed", "无法保护认证器密钥", nil)
				return
			}
			response["enrollment"] = map[string]string{"qrCodeDataUrl": enrollment.QRCodeDataURL, "manualKey": enrollment.Secret}
		}
		if err := s.store.SetMFAChallengeMethod(r.Context(), challenge.ID, "totp", encryptedSecret, "", expiresAt); err != nil {
			writeError(w, r, http.StatusGone, "mfa_challenge_expired", "双重认证挑战已失效，请重新登录", nil)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if s.emailSender == nil {
		writeError(w, r, http.StatusServiceUnavailable, "smtp_unavailable", "邮箱双重认证尚未配置", nil)
		return
	}
	emailAddress := challenge.User.Email
	if challenge.Purpose == "onboard" {
		emailAddress = challenge.Email
	}
	code, err := auth.NewEmailCode()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "email_code_failed", "无法生成邮箱验证码", nil)
		return
	}
	codeHash := s.mfa.EmailCodeHash(challenge.ID, code)
	if err := s.store.SetMFAChallengeMethod(r.Context(), challenge.ID, "email", "", codeHash, expiresAt); errors.Is(err, store.ErrMFACooldown) {
		writeError(w, r, http.StatusTooManyRequests, "email_rate_limited", "验证码发送过于频繁，请 60 秒后重试", nil)
		return
	} else if err != nil {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "双重认证挑战已失效，请重新登录", nil)
		return
	}
	if err := s.emailSender.SendCode(r.Context(), emailAddress, code, s.emailCodeTTL); err != nil {
		_ = s.store.ClearMFAEmailDelivery(r.Context(), challenge.ID, codeHash)
		writeError(w, r, http.StatusBadGateway, "smtp_delivery_failed", "验证码邮件发送失败，请检查发件服务器配置", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"method": "email", "maskedEmail": auth.MaskEmail(emailAddress), "expiresAt": expiresAt, "resendAfterSeconds": 60})
}

func (s *server) loadOnboardingChallenge(w http.ResponseWriter, r *http.Request, token string) (store.MFAChallenge, bool) {
	challenge, err := s.store.MFAChallengeByToken(r.Context(), digestString(strings.TrimSpace(token)))
	if err != nil || challenge.Purpose != "onboard" {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "首次登录引导已失效，请重新登录", nil)
		return store.MFAChallenge{}, false
	}
	return challenge, true
}

func (s *server) mfaMethodAllowed(method string) bool {
	for _, allowed := range s.mfaMethods {
		if method == allowed {
			return true
		}
	}
	return false
}

type completeMFARequest struct {
	ChallengeToken string `json:"challengeToken"`
	Code           string `json:"code"`
}

func (s *server) completeMFA(w http.ResponseWriter, r *http.Request) {
	if s.mfa == nil {
		writeError(w, r, http.StatusServiceUnavailable, "mfa_unavailable", "双重认证服务尚未配置", nil)
		return
	}
	var input completeMFARequest
	if !decodeJSON(w, r, &input) {
		return
	}
	input.ChallengeToken = strings.TrimSpace(input.ChallengeToken)
	input.Code = strings.TrimSpace(input.Code)
	if len(input.ChallengeToken) < 32 || len(input.ChallengeToken) > 256 || len(input.Code) < 6 || len(input.Code) > 64 {
		writeError(w, r, http.StatusBadRequest, "invalid_mfa_request", "双重认证参数无效", nil)
		return
	}
	challenge, err := s.store.MFAChallengeByToken(r.Context(), digestString(input.ChallengeToken))
	if errors.Is(err, store.ErrMFAChallenge) {
		writeError(w, r, http.StatusGone, "mfa_challenge_expired", "双重认证挑战已失效，请重新登录", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "双重认证服务暂时不可用", nil)
		return
	}
	method := challenge.Method
	counter := int64(0)
	codeHash := ""
	if auth.LooksLikeRecoveryCode(input.Code) && challenge.Purpose == "verify" {
		method = "recovery"
		codeHash = s.mfa.RecoveryCodeHash(input.Code)
	} else if method == "email" {
		expected := s.mfa.EmailCodeHash(challenge.ID, input.Code)
		if challenge.EmailCodeHash == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(challenge.EmailCodeHash)) != 1 {
			_ = s.store.FailMFAChallenge(r.Context(), challenge.ID)
			s.auditLogin(r, challenge.User.Username, "mfa_failed")
			writeError(w, r, http.StatusUnauthorized, "invalid_mfa_code", "邮箱验证码无效或已过期", nil)
			return
		}
	} else if method == "totp" {
		secretCiphertext := challenge.MFASecretCiphertext
		if challenge.Purpose == "onboard" {
			secretCiphertext = challenge.SecretCiphertext
		}
		secret, decryptErr := s.mfa.DecryptSecret(challenge.User.ID, secretCiphertext)
		if decryptErr != nil {
			writeError(w, r, http.StatusConflict, "mfa_key_unavailable", "双重认证密钥不可用，请由管理员执行恢复重置", nil)
			return
		}
		matchedCounter, valid := s.mfa.ValidateTOTP(secret, input.Code, time.Now().UTC())
		if !valid {
			_ = s.store.FailMFAChallenge(r.Context(), challenge.ID)
			s.auditLogin(r, challenge.User.Username, "mfa_failed")
			writeError(w, r, http.StatusUnauthorized, "invalid_mfa_code", "动态验证码无效", nil)
			return
		}
		counter = matchedCounter
	} else {
		_ = s.store.FailMFAChallenge(r.Context(), challenge.ID)
		s.auditLogin(r, challenge.User.Username, "mfa_failed")
		writeError(w, r, http.StatusConflict, "mfa_start_required", "请先选择并启动双重认证方式", nil)
		return
	}
	token, err := newOpaqueSecret(32)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "session_generation_failed", "无法创建登录会话", nil)
		return
	}
	csrfToken, err := newOpaqueSecret(32)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "session_generation_failed", "无法创建登录会话", nil)
		return
	}
	expiresAt := time.Now().UTC().Add(12 * time.Hour)
	completion := store.CompleteMFAInput{ChallengeID: challenge.ID, Method: method, Counter: counter, CodeHash: codeHash, TokenHash: digestString(token), CSRFHash: digestString(csrfToken), ExpiresAt: expiresAt, Audit: store.AuditInput{Actor: challenge.User.Username, Action: "auth.login", ResourceType: "auth_session", Result: "success", RequestID: requestID(r), SourceIP: requestSourceIP(r)}}
	recoveryCodes := []string(nil)
	if challenge.Purpose == "onboard" {
		var recoveryHashes []string
		recoveryCodes, recoveryHashes, err = s.mfa.NewRecoveryCodes(10)
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "recovery_generation_failed", "无法生成恢复码", nil)
			return
		}
		completion.Recovery = recoveryHashes
		completion.MethodBound = challenge.Method
		completion.Audit.Action = "auth.onboarding_complete"
	}
	var sessionRecord store.AuthSession
	if challenge.Purpose == "onboard" {
		sessionRecord, err = s.store.CompleteMFAEnrollment(r.Context(), completion)
	} else {
		sessionRecord, err = s.store.CompleteMFAAuthentication(r.Context(), completion)
	}
	if errors.Is(err, store.ErrMFAChallenge) || errors.Is(err, store.ErrMFAReplay) {
		_ = s.store.FailMFAChallenge(r.Context(), challenge.ID)
		s.auditLogin(r, challenge.User.Username, "mfa_failed")
		writeError(w, r, http.StatusUnauthorized, "invalid_mfa_code", "动态验证码或恢复码无效或已使用", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "session_create_failed", "无法完成双重认证登录", nil)
		return
	}
	s.setAuthCookies(w, token, csrfToken, expiresAt)
	remaining, _ := s.store.RecoveryCodeCount(r.Context(), challenge.User.ID)
	writeJSON(w, http.StatusOK, map[string]any{"user": sessionRecord.User, "csrfToken": csrfToken, "expiresAt": expiresAt, "recoveryCodes": recoveryCodes, "recoveryCodeUsed": method == "recovery", "recoveryCodesRemaining": remaining})
}

func (s *server) setAuthCookies(w http.ResponseWriter, token, csrfToken string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode, Expires: expiresAt, MaxAge: int(time.Until(expiresAt).Seconds())})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrfToken, Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode, Expires: expiresAt, MaxAge: int(time.Until(expiresAt).Seconds())})
}

func (s *server) auditLogin(r *http.Request, username, result string) {
	metadata, _ := json.Marshal(map[string]string{"username": username})
	_ = s.store.AppendAudit(r.Context(), store.AuditInput{Actor: username, Action: "auth.login", ResourceType: "auth_session", Result: result, RequestID: requestID(r), SourceIP: requestSourceIP(r), MetadataJSON: string(metadata)})
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	current := principalFromRequest(r)
	credential, err := s.store.UserCredentialByUsername(r.Context(), current.Username)
	if err != nil && !current.Bootstrap {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法读取当前用户", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": current.UserID, "username": current.Username, "displayName": current.DisplayName, "email": credential.Email, "role": current.Role, "projectIds": current.ProjectIDs, "bootstrap": current.Bootstrap, "mfaEnabled": current.Bootstrap || credential.MFAEnabled, "passwordChangeRequired": !current.Bootstrap && credential.PasswordChangeRequired})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(authCookieName); err == nil {
		_ = s.store.RevokeAuthSession(r.Context(), digestString(cookie.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: authCookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: "", Path: "/", HttpOnly: false, Secure: s.cookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取用户失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users, "total": len(users)})
}

type createUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	Enabled     *bool    `json:"enabled"`
	ProjectIDs  []string `json:"projectIds"`
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	var input createUserRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := map[string]string{}
	input.Username = strings.TrimSpace(input.Username)
	if len(input.Username) < 3 || len(input.Username) > 64 || strings.ContainsAny(input.Username, " /\\@:") {
		fields["username"] = "用户名必须为 3-64 位且不能包含空格或路径符号"
	}
	if strings.TrimSpace(input.DisplayName) == "" {
		fields["displayName"] = "显示名称不能为空"
	}
	if !validRole(input.Role) {
		fields["role"] = "不支持的用户角色"
	}
	passwordHash, passwordErr := auth.HashPassword(input.Password)
	if passwordErr != nil {
		fields["password"] = "密码必须至少 12 个字符"
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "用户配置校验失败", fields)
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	user, err := s.store.CreateUser(r.Context(), store.CreateUserInput{Username: input.Username, DisplayName: input.DisplayName, PasswordHash: passwordHash, Role: input.Role, Enabled: enabled, ProjectIDs: input.ProjectIDs}, auditFromRequest(r, "user.create", "user"))
	if err != nil {
		writeError(w, r, http.StatusConflict, "user_create_failed", "用户创建失败，用户名可能已存在或项目授权无效", nil)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

type updateUserRequest struct {
	DisplayName string   `json:"displayName"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	Enabled     *bool    `json:"enabled"`
	ProjectIDs  []string `json:"projectIds"`
}

func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	var input updateUserRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := map[string]string{}
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	if input.DisplayName == "" {
		fields["displayName"] = "显示名称不能为空"
	}
	if !validRole(input.Role) {
		fields["role"] = "不支持的用户角色"
	}
	passwordHash := ""
	if input.Password != "" {
		var err error
		passwordHash, err = auth.HashPassword(input.Password)
		if err != nil {
			fields["password"] = "新密码必须至少 12 个字符"
		}
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "用户配置校验失败", fields)
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	user, err := s.store.UpdateUser(r.Context(), r.PathValue("userID"), store.UpdateUserInput{DisplayName: input.DisplayName, PasswordHash: passwordHash, Role: input.Role, Enabled: enabled, ProjectIDs: input.ProjectIDs}, auditFromRequest(r, "user.update", "user"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "user_not_found", "用户不存在", nil)
		return
	}
	if errors.Is(err, store.ErrLastAdmin) {
		writeError(w, r, http.StatusConflict, "last_admin", "不能停用或降级最后一名系统管理员", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "user_update_failed", "用户更新失败，请检查项目授权", nil)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	userID := r.PathValue("userID")
	current := principalFromRequest(r)
	if !current.Bootstrap && current.UserID == userID {
		writeError(w, r, http.StatusConflict, "cannot_delete_self", "不能删除当前登录用户", nil)
		return
	}
	err := s.store.DeleteUser(r.Context(), userID, auditFromRequest(r, "user.delete", "user"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "user_not_found", "用户不存在", nil)
		return
	}
	if errors.Is(err, store.ErrLastAdmin) {
		writeError(w, r, http.StatusConflict, "last_admin", "不能删除最后一名系统管理员", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "user_delete_failed", "删除用户失败", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) resetUserMFA(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	userID := r.PathValue("userID")
	current := principalFromRequest(r)
	if !current.Bootstrap && current.UserID == userID {
		writeError(w, r, http.StatusConflict, "cannot_reset_own_mfa", "不能在当前会话中重置自己的双重认证；请使用恢复码或离线恢复命令", nil)
		return
	}
	err := s.store.ResetUserMFA(r.Context(), userID, auditFromRequest(r, "user.mfa_reset", "user"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "user_not_found", "用户不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "mfa_reset_failed", "重置双重认证失败", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type saveAccessPolicyRequest struct {
	Name         string     `json:"name"`
	ProjectIDs   []string   `json:"projectIds"`
	UserIDs      []string   `json:"userIds"`
	Capabilities []string   `json:"capabilities"`
	ValidFrom    *time.Time `json:"validFrom"`
	ValidUntil   *time.Time `json:"validUntil"`
	Enabled      *bool      `json:"enabled"`
}

func (s *server) listAccessPolicies(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	policies, err := s.store.ListAccessPolicies(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取访问策略失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": policies, "total": len(policies)})
}

func (s *server) createAccessPolicy(w http.ResponseWriter, r *http.Request) {
	s.saveAccessPolicy(w, r, "")
}

func (s *server) updateAccessPolicy(w http.ResponseWriter, r *http.Request) {
	s.saveAccessPolicy(w, r, r.PathValue("policyID"))
}

func (s *server) saveAccessPolicy(w http.ResponseWriter, r *http.Request, policyID string) {
	if !requireSystemAdmin(w, r) {
		return
	}
	var input saveAccessPolicyRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	fields := map[string]string{}
	if strings.TrimSpace(input.Name) == "" {
		fields["name"] = "策略名称不能为空"
	}
	if len(input.ProjectIDs) == 0 {
		fields["projectIds"] = "至少选择一个客户项目"
	}
	if len(input.UserIDs) == 0 {
		fields["userIds"] = "至少选择一个授权用户"
	}
	if len(input.Capabilities) == 0 {
		fields["capabilities"] = "至少授权一项访问能力"
	}
	seen := map[string]struct{}{}
	for _, capability := range input.Capabilities {
		if capability != "web" && capability != "webssh" {
			fields["capabilities"] = "包含不受支持的授权能力"
		}
		if _, exists := seen[capability]; exists {
			fields["capabilities"] = "授权能力不能重复"
		}
		seen[capability] = struct{}{}
	}
	users, userErr := s.store.ListUsers(r.Context())
	if userErr != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "无法校验策略授权用户", nil)
		return
	}
	userRoles := map[string]string{}
	for _, user := range users {
		userRoles[user.ID] = user.Role
	}
	for _, userID := range input.UserIDs {
		if userRoles[userID] != "temporary" {
			fields["userIds"] = "V1 访问策略只能授权临时用户；其他角色使用项目成员范围"
			break
		}
	}
	if input.ValidFrom != nil && input.ValidUntil != nil && !input.ValidUntil.After(*input.ValidFrom) {
		fields["validUntil"] = "策略结束时间必须晚于开始时间"
	}
	if len(fields) > 0 {
		writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "访问策略配置校验失败", fields)
		return
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	storeInput := store.SaveAccessPolicyInput{Name: input.Name, ProjectIDs: input.ProjectIDs, UserIDs: input.UserIDs, Capabilities: input.Capabilities, ValidFrom: input.ValidFrom, ValidUntil: input.ValidUntil, Enabled: enabled}
	var policy store.AccessPolicy
	var err error
	status := http.StatusCreated
	if policyID == "" {
		policy, err = s.store.CreateAccessPolicy(r.Context(), storeInput, auditFromRequest(r, "access_policy.create", "access_policy"))
	} else {
		policy, err = s.store.UpdateAccessPolicy(r.Context(), policyID, storeInput, auditFromRequest(r, "access_policy.update", "access_policy"))
		status = http.StatusOK
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "policy_not_found", "访问策略不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusConflict, "policy_save_failed", "访问策略保存失败，请检查用户、项目或策略名称", nil)
		return
	}
	writeJSON(w, status, policy)
}

func (s *server) deleteAccessPolicy(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	err := s.store.DeleteAccessPolicy(r.Context(), r.PathValue("policyID"), auditFromRequest(r, "access_policy.delete", "access_policy"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "policy_not_found", "访问策略不存在", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "policy_delete_failed", "删除访问策略失败", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, err := s.store.ListAuditLogs(r.Context(), strings.TrimSpace(r.URL.Query().Get("search")), limit, offset)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "读取审计日志失败", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "limit": limit, "offset": offset})
}

func (s *server) exportAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	items, err := s.store.ListAuditLogs(r.Context(), strings.TrimSpace(r.URL.Query().Get("search")), 1000, 0)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "database_error", "导出审计日志失败", nil)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"time", "actor", "action", "resource_type", "resource_id", "result", "request_id", "source_ip", "metadata"})
	for _, item := range items {
		_ = writer.Write([]string{item.CreatedAt.Format(time.RFC3339), item.Actor, item.Action, item.ResourceType, item.ResourceID, item.Result, item.RequestID, item.SourceIP, item.MetadataJSON})
	}
	writer.Flush()
}

func (s *server) backupData(w http.ResponseWriter, r *http.Request) {
	if !requireSystemAdmin(w, r) {
		return
	}
	temporary, err := os.CreateTemp("", "device-management-platform-backup-*.db")
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "backup_failed", "无法创建临时备份文件", nil)
		return
	}
	path := temporary.Name()
	_ = temporary.Close()
	defer os.Remove(path)
	if err := s.store.Backup(r.Context(), path); err != nil {
		writeError(w, r, http.StatusInternalServerError, "backup_failed", "SQLite 一致性备份创建失败", nil)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "backup_failed", "无法读取备份文件", nil)
		return
	}
	defer file.Close()
	audit := auditFromRequest(r, "data.backup", "database")
	if err := s.store.AppendAudit(r.Context(), audit); err != nil {
		writeError(w, r, http.StatusInternalServerError, "audit_write_failed", "备份已生成但审计写入失败", nil)
		return
	}
	filename := "device-management-platform-backup-" + time.Now().UTC().Format("20060102T150405Z") + ".db"
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, time.Now(), file)
}

func validRole(role string) bool {
	return role == "system_admin" || role == "project_admin" || role == "operator" || role == "temporary"
}

func requireSystemAdmin(w http.ResponseWriter, r *http.Request) bool {
	current := principalFromRequest(r)
	if current.Bootstrap || current.Role == "system_admin" {
		return true
	}
	writeError(w, r, http.StatusForbidden, "forbidden", "仅系统管理员可执行该操作", nil)
	return false
}

func canAccessProject(current principal, projectID, capability string) bool {
	if current.Bootstrap || current.Role == "system_admin" {
		return true
	}
	member := false
	for _, allowedProject := range current.ProjectIDs {
		if allowedProject == projectID {
			member = true
			break
		}
	}
	if !member {
		return false
	}
	if current.Role == "project_admin" || current.Role == "operator" {
		return true
	}
	return false
}

func digestString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (s *server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.apiToken == "" && s.mode == "dev" {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal{Username: "bootstrap-admin", DisplayName: "Bootstrap Admin", Role: "system_admin", Bootstrap: true})))
			return
		}
		if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
			provided := strings.TrimPrefix(authorization, "Bearer ")
			if len(provided) == len(s.apiToken) && subtle.ConstantTimeCompare([]byte(provided), []byte(s.apiToken)) == 1 {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal{Username: "bootstrap-admin", DisplayName: "Bootstrap Admin", Role: "system_admin", Bootstrap: true})))
				return
			}
		}
		cookie, err := r.Cookie(authCookieName)
		if err != nil || cookie.Value == "" {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "需要登录或有效的平台访问令牌", nil)
			return
		}
		sessionRecord, err := s.store.ResolveAuthSession(r.Context(), digestString(cookie.Value))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "session_expired", "登录会话已失效，请重新登录", nil)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			csrfHash := digestString(r.Header.Get("X-CSRF-Token"))
			if len(csrfHash) != len(sessionRecord.CSRFHash) || subtle.ConstantTimeCompare([]byte(csrfHash), []byte(sessionRecord.CSRFHash)) != 1 {
				writeError(w, r, http.StatusForbidden, "csrf_failed", "CSRF 校验失败", nil)
				return
			}
		}
		user := sessionRecord.User
		current := principal{UserID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Role: user.Role, ProjectIDs: user.ProjectIDs}
		if !s.authorizeRequest(r, current) {
			writeError(w, r, http.StatusForbidden, "forbidden", "当前角色或项目范围无权执行该操作", nil)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, current)))
	})
}

func (s *server) authorizeRequest(r *http.Request, current principal) bool {
	if current.Bootstrap || current.Role == "system_admin" {
		return true
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/v1/auth/") || path == "/api/v1/meta" {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/users") {
		return false
	}
	if path == "/api/v1/nodes" {
		return r.Method == http.MethodGet
	}
	if strings.HasPrefix(path, "/api/v1/nodes/") {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/access-policies") {
		return false
	}
	if path == "/api/v1/projects" {
		return r.Method == http.MethodGet
	}
	if projectID := r.PathValue("projectID"); projectID != "" {
		if current.Role == "temporary" {
			if r.Method != http.MethodGet || !strings.HasSuffix(path, "/devices") {
				return false
			}
			web, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, projectID, "web", time.Now().UTC())
			webSSH, _ := s.store.HasPolicyCapability(r.Context(), current.UserID, projectID, "webssh", time.Now().UTC())
			return web || webSSH
		}
		if !canAccessProject(current, projectID, "manage") {
			return false
		}
		if current.Role == "project_admin" {
			return true
		}
		return r.Method == http.MethodGet
	}
	if endpointID := r.PathValue("endpointID"); endpointID != "" {
		route, err := s.store.EndpointRoute(r.Context(), endpointID)
		if err != nil || !canAccessProject(current, route.ProjectID, "manage") {
			return false
		}
		return current.Role == "project_admin"
	}
	if forwardID := r.PathValue("forwardID"); forwardID != "" {
		forward, err := s.store.PortForwardByID(r.Context(), forwardID)
		return err == nil && current.Role == "project_admin" && canAccessProject(current, forward.ProjectID, "manage")
	}
	if jobID := r.PathValue("jobID"); jobID != "" {
		job, err := s.store.DiscoveryJob(r.Context(), jobID)
		return err == nil && current.Role == "project_admin" && canAccessProject(current, job.ProjectID, "manage")
	}
	if path == "/api/v1/access-sessions" && r.Method == http.MethodPost {
		return current.Role == "project_admin" || current.Role == "operator" || current.Role == "temporary"
	}
	return false
}

type contextKey string

const requestIDKey contextKey = "requestID"
const principalKey contextKey = "principal"

func principalFromRequest(r *http.Request) principal {
	value, _ := r.Context().Value(principalKey).(principal)
	return value
}

func (s *server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" {
			requestID, _ = id.New()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, requestID)))
	})
}

func (s *server) accessDomainRouting(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.accessDomain == "" {
			next.ServeHTTP(w, r)
			return
		}
		host := strings.ToLower(r.Host)
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		suffix := "." + s.accessDomain
		if !strings.HasSuffix(host, suffix) {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimSuffix(host, suffix)
		if len(token) != 48 {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := hex.DecodeString(token); err != nil {
			next.ServeHTTP(w, r)
			return
		}
		clone := r.Clone(r.Context())
		clone.URL.Path = "/access/web/" + token + "/" + strings.TrimPrefix(r.URL.Path, "/")
		clone.URL.RawPath = ""
		next.ServeHTTP(w, access.WithSessionSubdomainAccess(clone))
	})
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Device Web applications are isolated by their short-lived access token
		// (and, in production, by a dedicated session subdomain). Do not impose the
		// control plane's CSP/Permissions-Policy on upstream applications: camera,
		// microphone, USB and vendor-specific browser APIs may be legitimate there.
		if strings.HasPrefix(r.URL.Path, "/access/web/") {
			if r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if !strings.HasPrefix(r.URL.Path, "/access/ssh/") {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:")
		}
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func auditFromRequest(r *http.Request, action, resourceType string) store.AuditInput {
	current := principalFromRequest(r)
	actor := current.Username
	if actor == "" {
		actor = "unauthenticated"
	}
	return store.AuditInput{Actor: actor, Action: action, ResourceType: resourceType, Result: "success", RequestID: requestID(r), SourceIP: requestSourceIP(r)}
}

func requestID(r *http.Request) string {
	value, _ := r.Context().Value(requestIDKey).(string)
	return value
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "请求 JSON 无效或包含未知字段", nil)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象", nil)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, fields map[string]string) {
	writeJSON(w, status, errorBody{Error: apiError{Code: code, Message: message, Fields: fields, RequestID: requestID(r)}})
}
