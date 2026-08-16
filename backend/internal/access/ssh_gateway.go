package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"golang.org/x/crypto/ssh"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

type SecretResolver interface {
	Resolve(context.Context, string) (string, error)
}

type accessSessionToucher interface {
	TouchAccessSession(context.Context, string, time.Time, time.Time) error
}

const sshActivityPersistInterval = 30 * time.Second

type SSHGateway struct {
	sessions sessionResolver
	routes   routeResolver
	secrets  SecretResolver
	timeout  time.Duration
	idleTTL  time.Duration
	touchTTL time.Duration
	activeMu sync.Mutex
	active   map[string]map[uint64]context.CancelFunc
	revoked  map[string]time.Time
	nextID   uint64
}

type sshAuthMessage struct {
	Type     string `json:"type"`
	Method   string `json:"method"`
	Username string `json:"username"`
	Password string `json:"password"`
	Columns  int    `json:"columns"`
	Rows     int    `json:"rows"`
}

type sshClientMessage struct {
	Type    string `json:"type"`
	Data    string `json:"data"`
	Columns int    `json:"columns"`
	Rows    int    `json:"rows"`
}

type sshServerMessage struct {
	Type        string `json:"type"`
	Data        string `json:"data,omitempty"`
	Code        string `json:"code,omitempty"`
	Message     string `json:"message,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type storedSSHCredential struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"privateKey"`
	Passphrase string `json:"passphrase"`
}

func NewSSHGateway(sessions sessionResolver, routes routeResolver, secrets SecretResolver, idleTTLs ...time.Duration) *SSHGateway {
	idleTTL := nodeadapter.ManagedSOCKSIdleTTL
	if len(idleTTLs) > 0 && idleTTLs[0] > 0 {
		idleTTL = idleTTLs[0]
	}
	return &SSHGateway{sessions: sessions, routes: routes, secrets: secrets, timeout: 15 * time.Second, idleTTL: idleTTL, touchTTL: sshActivityPersistInterval, active: map[string]map[uint64]context.CancelFunc{}, revoked: map[string]time.Time{}}
}

// Revoke immediately terminates every active WebSSH connection for a platform
// access session. The tombstone also closes the small race where revocation is
// committed after token resolution but before the WebSocket is registered.
func (g *SSHGateway) Revoke(sessionID string) bool {
	g.activeMu.Lock()
	g.pruneRevokedLocked(time.Now().UTC())
	g.revoked[sessionID] = time.Now().UTC()
	cancels := make([]context.CancelFunc, 0, len(g.active[sessionID]))
	for _, cancel := range g.active[sessionID] {
		cancels = append(cancels, cancel)
	}
	g.activeMu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels) > 0
}

func (g *SSHGateway) register(sessionID string, cancel context.CancelFunc) (uint64, bool) {
	g.activeMu.Lock()
	defer g.activeMu.Unlock()
	g.pruneRevokedLocked(time.Now().UTC())
	if _, revoked := g.revoked[sessionID]; revoked {
		return 0, false
	}
	g.nextID++
	connectionID := g.nextID
	if g.active[sessionID] == nil {
		g.active[sessionID] = map[uint64]context.CancelFunc{}
	}
	g.active[sessionID][connectionID] = cancel
	return connectionID, true
}

func (g *SSHGateway) unregister(sessionID string, connectionID uint64) {
	g.activeMu.Lock()
	defer g.activeMu.Unlock()
	delete(g.active[sessionID], connectionID)
	if len(g.active[sessionID]) == 0 {
		delete(g.active, sessionID)
	}
}

func (g *SSHGateway) pruneRevokedLocked(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for sessionID, revokedAt := range g.revoked {
		if revokedAt.Before(cutoff) {
			delete(g.revoked, sessionID)
		}
	}
}

func (g *SSHGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/ws") {
		g.serveWebSocket(w, r)
		return
	}
	g.serveTerminalPage(w, r)
}

func (g *SSHGateway) serveTerminalPage(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !validAccessToken(token) {
		gatewayError(w, http.StatusNotFound, "访问会话不存在")
		return
	}
	sessionRecord, route, ok := resolveAuthorizedAccessWithURLGrant(w, r, g.sessions, token, g.idleTTL, "/access/ssh/"+token)
	if !ok {
		return
	}
	if sessionRecord.SourceIP != "" && sessionRecord.SourceIP != directSourceIP(r) {
		gatewayError(w, http.StatusForbidden, "访问会话与当前来源地址不匹配")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'")
	autoConnect := "false"
	if route.CredentialRef != "" {
		autoConnect = "true"
	}
	page := strings.Replace(terminalPage, `data-auto-connect="false"`, `data-auto-connect="`+autoConnect+`"`, 1)
	_, _ = io.WriteString(w, page)
}

func (g *SSHGateway) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !validAccessToken(token) {
		gatewayError(w, http.StatusNotFound, "访问会话不存在")
		return
	}
	sessionRecord, route, ok := resolveAuthorizedAccessWithURLGrant(w, r, g.sessions, token, g.idleTTL, "/access/ssh/"+token)
	if !ok {
		return
	}
	if sessionRecord.SourceIP != "" && sessionRecord.SourceIP != directSourceIP(r) {
		gatewayError(w, http.StatusForbidden, "访问会话与当前来源地址不匹配")
		return
	}
	if sessionRecord.Mode != "ssh" || route.AccessType != "web_ssh" || route.Protocol != "ssh" {
		gatewayError(w, http.StatusForbidden, "该会话不是 WebSSH 会话")
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)
	ctx, cancel := context.WithDeadline(context.Background(), sessionRecord.ExpiresAt)
	defer cancel()
	connectionID, accepted := g.register(sessionRecord.ID, cancel)
	if !accepted {
		_ = conn.Close(websocket.StatusPolicyViolation, "access session revoked")
		return
	}
	defer g.unregister(sessionRecord.ID, connectionID)
	var auth sshAuthMessage
	authCtx, authCancel := context.WithTimeout(ctx, 90*time.Second)
	err = wsjson.Read(authCtx, conn, &auth)
	authCancel()
	if err != nil || auth.Type != "auth" {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "invalid_auth_message", Message: "请先提交 SSH 认证信息"})
		return
	}
	credential, err := g.resolveCredential(ctx, route, auth)
	clearSSHAuth(&auth)
	if err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "credential_rejected", Message: "SSH 凭据无效或未授权"})
		return
	}
	socksRoute, err := g.routes.SOCKSRoute(ctx, route.NodeID, route.ClientID)
	if err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "route_unavailable", Message: "项目通道路由不可用"})
		return
	}
	target := net.JoinHostPort(route.Host, strconv.Itoa(route.TargetPort))
	dialer := SOCKSDialer{ProxyAddress: socksRoute.Address, Username: socksRoute.Username, Password: socksRoute.Password, Timeout: g.timeout}
	networkConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "target_unreachable", Message: "SSH 目标暂时不可达"})
		return
	}
	defer networkConn.Close()
	_ = networkConn.SetDeadline(time.Now().Add(g.timeout))
	observedFingerprint := ""
	config, err := sshClientConfig(credential, route, &observedFingerprint)
	if err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "credential_rejected", Message: "SSH 私钥或认证配置无效"})
		return
	}
	clientConn, channels, requests, err := ssh.NewClientConn(networkConn, target, config)
	if err != nil {
		message := sshServerMessage{Type: "error", Code: "ssh_handshake_failed", Message: "SSH 握手或认证失败", Fingerprint: observedFingerprint}
		_ = wsjson.Write(ctx, conn, message)
		return
	}
	_ = networkConn.SetDeadline(time.Time{})
	sshClient := ssh.NewClient(clientConn, channels, requests)
	defer sshClient.Close()
	sshSession, err := sshClient.NewSession()
	if err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "session_failed", Message: "无法创建 SSH 终端"})
		return
	}
	defer sshSession.Close()
	stdin, _ := sshSession.StdinPipe()
	stdout, _ := sshSession.StdoutPipe()
	stderr, _ := sshSession.StderrPipe()
	columns, rows := normalizeTerminalSize(auth.Columns, auth.Rows)
	if err := sshSession.RequestPty("xterm-256color", rows, columns, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "pty_failed", Message: "SSH 服务器拒绝分配 PTY"})
		return
	}
	if err := sshSession.Shell(); err != nil {
		_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "error", Code: "shell_failed", Message: "SSH 服务器拒绝启动 Shell"})
		return
	}
	if err := wsjson.Write(ctx, conn, sshServerMessage{Type: "ready", Message: "SSH 终端已连接"}); err != nil {
		return
	}
	activity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	go g.monitorSSHActivity(ctx, cancel, sessionRecord.ID, activity)
	output := make(chan []byte, 32)
	var outputReaders sync.WaitGroup
	readOutput := func(reader io.Reader) {
		defer outputReaders.Done()
		buffer := make([]byte, 16<<10)
		for {
			count, err := reader.Read(buffer)
			if count > 0 {
				signalActivity()
				chunk := append([]byte(nil), buffer[:count]...)
				select {
				case output <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	outputReaders.Add(2)
	go readOutput(stdout)
	go readOutput(stderr)
	go func() {
		outputReaders.Wait()
		close(output)
	}()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			var message sshClientMessage
			if err := wsjson.Read(ctx, conn, &message); err != nil {
				return
			}
			signalActivity()
			switch message.Type {
			case "input":
				_, _ = io.WriteString(stdin, message.Data)
			case "resize":
				newColumns, newRows := normalizeTerminalSize(message.Columns, message.Rows)
				_ = sshSession.WindowChange(newRows, newColumns)
			}
		}
	}()
	go func() { _ = sshSession.Wait() }()
	for {
		select {
		case chunk, ok := <-output:
			if !ok {
				_ = wsjson.Write(ctx, conn, sshServerMessage{Type: "closed", Message: "SSH 会话已结束"})
				return
			}
			if err := wsjson.Write(ctx, conn, sshServerMessage{Type: "output", Data: string(chunk)}); err != nil {
				return
			}
		case <-readDone:
			return
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusPolicyViolation, "访问会话已撤销或过期")
			return
		}
	}
}

func (g *SSHGateway) monitorSSHActivity(ctx context.Context, cancel context.CancelFunc, sessionID string, activity <-chan struct{}) {
	idleTimer := time.NewTimer(g.idleTTL)
	defer idleTimer.Stop()
	lastPersisted := time.Now().UTC()
	for {
		select {
		case <-ctx.Done():
			return
		case <-idleTimer.C:
			cancel()
			return
		case <-activity:
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(g.idleTTL)
			now := time.Now().UTC()
			if now.Sub(lastPersisted) < g.touchTTL {
				continue
			}
			toucher, ok := g.sessions.(accessSessionToucher)
			if !ok {
				lastPersisted = now
				continue
			}
			touchCtx, touchCancel := context.WithTimeout(ctx, 5*time.Second)
			err := toucher.TouchAccessSession(touchCtx, sessionID, now, now.Add(-g.idleTTL))
			touchCancel()
			if err != nil {
				cancel()
				return
			}
			lastPersisted = now
		}
	}
}

func (g *SSHGateway) resolveCredential(ctx context.Context, route store.EndpointRoute, input sshAuthMessage) (storedSSHCredential, error) {
	credential := storedSSHCredential{Username: input.Username, Password: input.Password}
	if input.Method == "stored" {
		if route.CredentialRef == "" {
			return storedSSHCredential{}, errors.New("stored credential unavailable")
		}
		if route.SSHAuthMethod == "key" {
			privateKey, err := os.ReadFile(route.SSHKeyPath)
			if err != nil {
				return storedSSHCredential{}, err
			}
			credential = storedSSHCredential{Username: route.SSHUsername, PrivateKey: string(privateKey)}
		} else {
			if g.secrets == nil {
				return storedSSHCredential{}, errors.New("stored credential unavailable")
			}
			value, err := g.secrets.Resolve(ctx, route.CredentialRef)
			if err != nil {
				return storedSSHCredential{}, err
			}
			if err := json.Unmarshal([]byte(value), &credential); err != nil {
				return storedSSHCredential{}, err
			}
		}
	}
	if strings.TrimSpace(credential.Username) == "" || (credential.Password == "" && credential.PrivateKey == "") {
		return storedSSHCredential{}, errors.New("username and authentication material are required")
	}
	return credential, nil
}

func sshClientConfig(credential storedSSHCredential, route store.EndpointRoute, observedFingerprint *string) (*ssh.ClientConfig, error) {
	authMethods := []ssh.AuthMethod{}
	if credential.Password != "" {
		authMethods = append(authMethods, ssh.Password(credential.Password))
	}
	if credential.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if credential.Passphrase == "" {
			signer, err = ssh.ParsePrivateKey([]byte(credential.PrivateKey))
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(credential.PrivateKey), []byte(credential.Passphrase))
		}
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	hostKeyCallback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint := ssh.FingerprintSHA256(key)
		*observedFingerprint = fingerprint
		if route.SSHHostKeyFingerprint != "" {
			if fingerprint != route.SSHHostKeyFingerprint {
				return fmt.Errorf("SSH host key fingerprint mismatch")
			}
			return nil
		}
		return nil
	}
	return &ssh.ClientConfig{User: credential.Username, Auth: authMethods, HostKeyCallback: hostKeyCallback, Timeout: 15 * time.Second}, nil
}

func normalizeTerminalSize(columns, rows int) (int, int) {
	if columns < 20 || columns > 500 {
		columns = 120
	}
	if rows < 5 || rows > 300 {
		rows = 30
	}
	return columns, rows
}

func validAccessToken(token string) bool {
	return len(token) >= 32 && len(token) <= 128 && !strings.ContainsAny(token, "/\\ ")
}

func clearSSHAuth(auth *sshAuthMessage) {
	auth.Password = ""
}

const terminalPage = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>设备管理平台 WebSSH</title><style>
*{box-sizing:border-box}html,body{height:100%;margin:0}body{background:#071317;color:#d8eeeb;font:14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{height:100%;display:grid;grid-template-rows:auto minmax(0,1fr) 24px}.login-shell{padding:28px 20px;background:linear-gradient(135deg,#0b3039,#08242d);border-bottom:1px solid #1c4b53}.login-card{max-width:720px;margin:auto}.login-title{display:flex;align-items:center;gap:12px;margin-bottom:18px}.login-icon{width:42px;height:42px;display:grid;place-items:center;border-radius:11px;background:#0aa49e;color:#fff;font-size:20px}.login-title h1{margin:0;font-size:18px}.login-title p{margin:4px 0 0;color:#8fb1b2;font-size:12px}.credentials{display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:end}.credentials label{display:flex;flex-direction:column;gap:6px;color:#a9c1c1;font-size:11px;font-weight:650}.credentials input{height:42px;padding:0 12px;border:1px solid #37646a;border-radius:8px;outline:none;background:#092831;color:#f3fffd;font:14px inherit}.credentials input:focus{border-color:#45bdb4;box-shadow:0 0 0 3px #0aa49e22}.credentials button{height:42px;padding:0 22px;border:0;border-radius:8px;background:#0aa49e;color:#fff;font-weight:750;cursor:pointer}.credentials button:disabled{opacity:.55}.status{margin-left:auto;color:#71ddd4}#terminal{min-width:0;min-height:0;height:100%;background:#071317;overflow:hidden}#terminal .xterm{height:100%}#terminal .xterm-viewport{scrollbar-color:#315158 #071317}.terminal-safe-area{background:#071317}.hidden{display:none!important}@media(max-width:680px){main{grid-template-rows:auto minmax(0,1fr) 18px}.credentials{grid-template-columns:1fr}.credentials button{width:100%}.status{display:block;margin:8px 0 0}}
</style></head><body><main><section class="login-shell" id="authShell"><form class="login-card" id="auth" autocomplete="off" data-auto-connect="false"><div class="login-title"><span class="login-icon">⌨</span><div><h1>连接 SSH</h1><p>请输入目标设备的 SSH 账号</p></div><span class="status" id="status">等待连接</span></div><div class="credentials"><label>SSH 用户名<input id="username" required autocomplete="off" spellcheck="false" placeholder="例如 root"></label><label>SSH 密码<input id="password" required type="password" autocomplete="off" placeholder="输入当次连接密码"></label><button id="connect" type="submit">连接</button></div></form></section><div id="terminal" role="application" aria-label="SSH 终端"></div><div class="terminal-safe-area" aria-hidden="true"></div></main><script type="module" src="/assets/webssh.js"></script></body></html>`
