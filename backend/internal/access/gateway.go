package access

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/webroutelabel"
)

type sessionResolver interface {
	ExchangeAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error)
	ResolveAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error)
}

type routeResolver interface {
	SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error)
}

type sessionSubdomainContextKey struct{}

// WithSessionSubdomainAccess marks a request that the control-plane router has
// already matched against the configured wildcard access domain. A context
// value is deliberately used instead of a request header: callers must not be
// able to disable path-prefix isolation by forging an internal routing header.
func WithSessionSubdomainAccess(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionSubdomainContextKey{}, true))
}

func usesSessionSubdomain(r *http.Request) bool {
	value, _ := r.Context().Value(sessionSubdomainContextKey{}).(bool)
	return value
}

type WebGateway struct {
	sessions sessionResolver
	routes   routeResolver
	timeout  time.Duration
	idleTTL  time.Duration
	// Transports are shared per endpoint and SOCKS route. Creating one transport
	// per asset request leaves a separate idle connection pool behind and causes
	// connection and memory growth on Web applications with many resources.
	transportsMu sync.Mutex
	transports   map[string]proxyTransportEntry
	activeMu     sync.Mutex
	active       map[string]map[uint64]*webActivityConn
	revoked      map[string]time.Time
	nextID       uint64
}

func NewWebGateway(sessions sessionResolver, routes routeResolver, idleTTLs ...time.Duration) *WebGateway {
	idleTTL := nodeadapter.ManagedSOCKSIdleTTL
	if len(idleTTLs) > 0 && idleTTLs[0] > 0 {
		idleTTL = idleTTLs[0]
	}
	return &WebGateway{
		sessions:   sessions,
		routes:     routes,
		timeout:    20 * time.Second,
		idleTTL:    idleTTL,
		transports: make(map[string]proxyTransportEntry),
		active:     make(map[string]map[uint64]*webActivityConn),
		revoked:    make(map[string]time.Time),
	}
}

// Revoke immediately closes every active upstream connection for a Web access
// session. The short-lived tombstone closes the race where a request resolved
// its database grant just before revocation but had not dialed SOCKS yet.
func (g *WebGateway) Revoke(sessionID string) bool {
	g.activeMu.Lock()
	g.pruneRevokedLocked(time.Now().UTC())
	g.revoked[sessionID] = time.Now().UTC()
	connections := make([]*webActivityConn, 0, len(g.active[sessionID]))
	for _, connection := range g.active[sessionID] {
		connections = append(connections, connection)
	}
	g.activeMu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return len(connections) > 0
}

func (g *WebGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !usesSessionSubdomain(r) {
		gatewayError(w, http.StatusNotFound, "访问入口不存在")
		return
	}
	token := r.PathValue("token")
	if !validGatewayRouteToken(token) {
		gatewayError(w, http.StatusNotFound, "访问会话不存在或已失效")
		return
	}
	pathValue := webRequestPath(r)
	switch pathValue {
	case webGrantAuthorizePath:
		serveGrantBootstrap(w, r)
		return
	case webGrantExchangePath:
		g.exchangeGrant(w, r, token)
		return
	}
	session, route, ok := resolveAuthorizedAccess(w, r, g.sessions, token, g.idleTTL)
	if !ok {
		return
	}
	if session.SourceIP != "" && session.SourceIP != directSourceIP(r) {
		gatewayError(w, http.StatusForbidden, "访问会话与当前来源地址不匹配")
		return
	}
	if session.Mode != "web" || route.AccessType != "web_proxy" || (route.Protocol != "http" && route.Protocol != "https") {
		gatewayError(w, http.StatusForbidden, "该会话不是 Web 访问会话")
		return
	}
	socksRoute, err := g.routes.SOCKSRoute(r.Context(), route.NodeID, route.ClientID)
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "无法获取项目通道路由")
		return
	}
	g.proxy(w, r, token, pathValue, session, route, socksRoute)
}

func validGatewayRouteToken(token string) bool {
	return webroutelabel.IsCurrent(token)
}

const accessGrantCookie = "dmp_access_grant"
const webGrantAuthorizePath = ".dmp/authorize"
const webGrantExchangePath = ".dmp/session"

type webGrantRequest struct {
	Grant string `json:"grant"`
}

func (g *WebGateway) exchangeGrant(w http.ResponseWriter, r *http.Request, token string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		gatewayError(w, http.StatusMethodNotAllowed, "访问授权交换仅支持 POST")
		return
	}
	formNavigation := strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))), "application/x-www-form-urlencoded")
	var grant string
	if formNavigation {
		// The control plane creates the 192-bit one-time grant and submits it as a
		// top-level POST. This avoids an opener-controlled about:blank redirect and
		// keeps the grant out of URLs, request logs and Referer headers.
		if mode := strings.TrimSpace(r.Header.Get("Sec-Fetch-Mode")); mode != "" && mode != "navigate" {
			gatewayError(w, http.StatusForbidden, "访问授权导航方式无效")
			return
		}
		if destination := strings.TrimSpace(r.Header.Get("Sec-Fetch-Dest")); destination != "" && destination != "document" {
			gatewayError(w, http.StatusForbidden, "访问授权导航目标无效")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		if err := r.ParseForm(); err != nil || len(r.PostForm) != 1 || len(r.PostForm["grant"]) != 1 {
			gatewayError(w, http.StatusBadRequest, "访问授权格式无效")
			return
		}
		grant = strings.TrimSpace(r.PostForm.Get("grant"))
	} else {
		expectedOrigin := "http://" + r.Host
		if accessRequestUsesHTTPS(r) {
			expectedOrigin = "https://" + r.Host
		}
		if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Origin")), expectedOrigin) {
			gatewayError(w, http.StatusForbidden, "访问授权来源无效")
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		var input webGrantRequest
		if err := decoder.Decode(&input); err != nil {
			gatewayError(w, http.StatusBadRequest, "访问授权格式无效")
			return
		}
		grant = strings.TrimSpace(input.Grant)
	}
	if !validAccessToken(grant) {
		gatewayError(w, http.StatusBadRequest, "访问授权格式无效")
		return
	}
	tokenDigest := sha256.Sum256([]byte(token))
	grantDigest := sha256.Sum256([]byte(grant))
	idleCutoff := time.Now().UTC().Add(-g.idleTTL)
	session, _, err := g.sessions.ExchangeAccessGrant(r.Context(), hex.EncodeToString(tokenDigest[:]), hex.EncodeToString(grantDigest[:]), idleCutoff)
	if err != nil {
		gatewayError(w, http.StatusGone, "访问授权不存在、已使用或登录已超时")
		return
	}
	sameSite := http.SameSiteStrictMode
	if formNavigation {
		sameSite = http.SameSiteLaxMode
	}
	http.SetCookie(w, &http.Cookie{Name: accessGrantCookie, Value: grant, Path: "/", HttpOnly: true, Secure: accessRequestUsesHTTPS(r), SameSite: sameSite, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
	// A previous visit may have followed a device HTTP -> HTTPS redirect. Do not
	// let that short-lived upstream choice leak into a newly authorized visit.
	clearUpstreamSchemeCookies(w, r)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if formNavigation {
		serveGrantExchangeComplete(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func serveGrantExchangeComplete(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>I5CLOUD 内网设备代理</title><style>body{font:16px system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f8fa;color:#23313d}main{position:relative;box-sizing:border-box;max-width:42rem;margin:1rem;padding:2rem 4rem;border:1px solid #d7e1e8;border-radius:14px;background:#fff;text-align:center;box-shadow:0 12px 32px rgba(16,42,67,.1)}strong{display:block;font-size:1.3rem;margin-bottom:.75rem}p{line-height:1.65;color:#526471}button{position:absolute;top:12px;right:12px;width:32px;height:32px;border:1px solid #aab9c4;border-radius:8px;background:#fff;color:#23313d;font:700 21px/28px system-ui,sans-serif;cursor:pointer}</style><main data-i5cloud-proxy-notice="true"><button id="dismiss" type="button" aria-label="&#x5173;&#x95ED;&#x63D0;&#x793A;" title="&#x5173;&#x95ED;&#x63D0;&#x793A;">&#xD7;</button><strong>I5CLOUD 远程管理平台</strong><p>&#x8FDC;&#x7A0B;&#x8FDE;&#x63A5;&#x5B89;&#x5168;&#x8BBF;&#x95EE;&#x901A;&#x9053; &#xB7; &#x5DF2;&#x8FDE;&#x63A5;&#x76EE;&#x6807;&#x5185;&#x7F51;&#x8BBE;&#x5907; &#xB7; &#x9875;&#x9762;&#x5185;&#x5BB9;&#x7531;&#x76EE;&#x6807;&#x8BBE;&#x5907;&#x63D0;&#x4F9B;</p><p>请仅在确认设备身份后输入该设备的凭据。</p></main><script>(()=>{let entered=false;const enter=()=>{if(entered)return;entered=true;location.replace("/")};document.getElementById('dismiss').addEventListener('click',enter);setTimeout(enter,1500)})()</script></html>`)
}

func clearUpstreamSchemeCookies(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     upstreamSchemeCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   accessRequestUsesHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}

func serveGrantBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		gatewayError(w, http.StatusMethodNotAllowed, "访问授权入口仅支持 GET")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>I5CLOUD 内网设备代理</title><style>body{font:16px system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f8fa;color:#23313d}main{position:relative;box-sizing:border-box;max-width:42rem;margin:1rem;padding:2rem 4rem;border:1px solid #d7e1e8;border-radius:14px;background:#fff;text-align:center;box-shadow:0 12px 32px rgba(16,42,67,.1)}strong{display:block;font-size:1.25rem;margin-bottom:.75rem}p{line-height:1.65;color:#526471}button{position:absolute;top:12px;right:12px;width:32px;height:32px;border:1px solid #aab9c4;border-radius:8px;background:#fff;color:#23313d;font:700 21px/28px system-ui,sans-serif;cursor:pointer}button:disabled{cursor:wait;opacity:.45}</style><main data-i5cloud-proxy-notice="true"><button id="dismiss" type="button" disabled aria-label="&#x5173;&#x95ED;&#x63D0;&#x793A;" title="&#x5173;&#x95ED;&#x63D0;&#x793A;">&#xD7;</button><strong>I5CLOUD 远程管理平台</strong><p>&#x8FDC;&#x7A0B;&#x8FDE;&#x63A5;&#x5B89;&#x5168;&#x8BBF;&#x95EE;&#x901A;&#x9053; &#xB7; &#x9875;&#x9762;&#x5185;&#x5BB9;&#x7531;&#x76EE;&#x6807;&#x8BBE;&#x5907;&#x63D0;&#x4F9B;</p><p id="status">正在建立安全访问…</p></main><script>(()=>{const match=/^#grant=([0-9a-f]{48})$/.exec(location.hash);const status=document.getElementById('status');const dismiss=document.getElementById('dismiss');let ready=false;let entered=false;const enter=()=>{if(!ready||entered)return;entered=true;location.replace('/'+location.search)};dismiss.addEventListener('click',enter);if(!match){status.textContent='访问授权无效，请返回平台重新打开';return}fetch('/.dmp/session',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant:match[1]})}).then(response=>{if(!response.ok)throw new Error('exchange failed');history.replaceState(null,'','/'+location.search);ready=true;dismiss.disabled=false;status.textContent='安全访问已建立，正在进入设备页面';setTimeout(enter,1500)}).catch(()=>{history.replaceState(null,'','/'+location.search);status.textContent='访问授权已失效，请返回平台重新打开'})})();</script></html>`)
}

func webRequestPath(r *http.Request) string {
	return strings.TrimPrefix(r.PathValue("path"), "/")
}

func resolveAuthorizedAccessWithURLGrant(w http.ResponseWriter, r *http.Request, sessions sessionResolver, token string, idleTTL time.Duration, cookiePath string) (store.AccessSession, store.EndpointRoute, bool) {
	if grant := strings.TrimSpace(r.URL.Query().Get("grant")); validAccessToken(grant) {
		tokenDigest := sha256.Sum256([]byte(token))
		tokenHash := hex.EncodeToString(tokenDigest[:])
		idleCutoff := time.Now().UTC().Add(-idleTTL)
		grantDigest := sha256.Sum256([]byte(grant))
		session, _, err := sessions.ExchangeAccessGrant(r.Context(), tokenHash, hex.EncodeToString(grantDigest[:]), idleCutoff)
		if err != nil {
			gatewayError(w, http.StatusGone, "访问授权不存在、已使用或登录已超时")
			return store.AccessSession{}, store.EndpointRoute{}, false
		}
		http.SetCookie(w, &http.Cookie{Name: accessGrantCookie, Value: grant, Path: cookiePath, HttpOnly: true, Secure: accessRequestUsesHTTPS(r), SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
		w.Header().Set("Referrer-Policy", "no-referrer")
		cleanURL := *r.URL
		query := cleanURL.Query()
		query.Del("grant")
		cleanURL.RawQuery = query.Encode()
		http.Redirect(w, r, cleanURL.String(), http.StatusSeeOther)
		return store.AccessSession{}, store.EndpointRoute{}, false
	}
	return resolveAuthorizedAccess(w, r, sessions, token, idleTTL)
}

func resolveAuthorizedAccess(w http.ResponseWriter, r *http.Request, sessions sessionResolver, token string, idleTTL time.Duration) (store.AccessSession, store.EndpointRoute, bool) {
	tokenDigest := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(tokenDigest[:])
	idleCutoff := time.Now().UTC().Add(-idleTTL)
	cookie, err := r.Cookie(accessGrantCookie)
	if err != nil || !validAccessToken(cookie.Value) {
		gatewayError(w, http.StatusUnauthorized, "需要从平台内重新发起访问")
		return store.AccessSession{}, store.EndpointRoute{}, false
	}
	grantDigest := sha256.Sum256([]byte(cookie.Value))
	session, route, err := sessions.ResolveAccessGrant(r.Context(), tokenHash, hex.EncodeToString(grantDigest[:]), idleCutoff)
	if errors.Is(err, store.ErrNotFound) {
		gatewayError(w, http.StatusGone, "访问会话不存在或已失效")
		return store.AccessSession{}, store.EndpointRoute{}, false
	}
	if err != nil {
		gatewayError(w, http.StatusBadGateway, "无法校验访问会话")
		return store.AccessSession{}, store.EndpointRoute{}, false
	}
	return session, route, true
}

func (g *WebGateway) proxy(w http.ResponseWriter, r *http.Request, token, requestPath string, session store.AccessSession, route store.EndpointRoute, socksRoute nodeadapter.SOCKSRoute) {
	stickyHTTPS := false
	if cookie, err := r.Cookie(upstreamSchemeCookie); err == nil && cookie.Value == "https" {
		stickyHTTPS = true
	}
	upstreamScheme, upstreamPort, upstreamPath := gatewayUpstream(route, requestPath, stickyHTTPS)
	targetAuthority := net.JoinHostPort(route.Host, strconv.Itoa(upstreamPort))
	upstreamHost := route.Host
	if upstreamScheme == "https" && strings.TrimSpace(route.TLSServerName) != "" {
		upstreamHost = strings.TrimSpace(route.TLSServerName)
	}
	upstreamAuthority := net.JoinHostPort(upstreamHost, strconv.Itoa(upstreamPort))
	transport := g.proxyTransport(token, session.ID, route, socksRoute)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			request := proxyRequest.Out
			stripControlPlaneHeaders(request.Header)
			request.URL.Scheme = upstreamScheme
			request.URL.Host = targetAuthority
			request.URL.Path = upstreamPath
			request.URL.RawPath = ""
			// Dial the stored private destination while preserving the configured
			// logical TLS host for SNI, HTTP virtual-host routing and origin checks.
			request.Host = upstreamAuthority
			rewriteBrowserOrigin(request.Header, upstreamScheme+"://"+upstreamAuthority)
		},
		ModifyResponse: func(response *http.Response) error {
			// The target response body is an opaque stream. Never inspect, buffer or
			// inject platform markup here: LuCI applications use HTML content types
			// for logs and package-operation output, and any body transform can break
			// the real device UI or data flow. The disclosure lives only on the
			// gateway-owned authorization page shown before this proxy starts.
			rewriteLocation(response.Header, upstreamScheme, route.Host, upstreamPort, route.TLSServerName)
			// Rewrite upstream cookies first. That function intentionally discards
			// names reserved by the platform, so the trusted gateway marker must be
			// appended afterwards instead of being mistaken for an injected device
			// cookie and removed again.
			rewriteCookies(response.Header)
			appendTrustedUpstreamSchemeCookie(response.Header, r, route.Protocol, upstreamScheme)
			response.Header.Set("Cache-Control", "no-store")
			response.Header.Set("Referrer-Policy", "no-referrer")
			response.Header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
			return nil
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, err error) {
			// Network errors may contain the SOCKS address, private destination or
			// other deployment details. Keep them in server-side diagnostics only;
			// the browser receives a stable message without internal topology.
			_ = err
			gatewayError(writer, http.StatusBadGateway, "内网 Web 服务暂时无法访问")
		},
	}
	proxy.ServeHTTP(w, r)
}

func appendTrustedUpstreamSchemeCookie(header http.Header, r *http.Request, routeProtocol, upstreamScheme string) {
	if routeProtocol != "http" || upstreamScheme != "https" {
		return
	}
	header.Add("Set-Cookie", (&http.Cookie{
		Name:     upstreamSchemeCookie,
		Value:    "https",
		Path:     "/",
		HttpOnly: true,
		Secure:   accessRequestUsesHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	}).String())
}

type proxyTransportConfig struct {
	sessionID  string
	protocol   string
	host       string
	targetPort int
	tlsName    string
	socksAddr  string
	socksUser  string
	socksPass  string
}

type proxyTransportEntry struct {
	config    proxyTransportConfig
	transport *http.Transport
	lastUsed  time.Time
}

func (g *WebGateway) proxyTransport(token, sessionID string, route store.EndpointRoute, socksRoute nodeadapter.SOCKSRoute) *http.Transport {
	config := proxyTransportConfig{
		sessionID:  sessionID,
		protocol:   route.Protocol,
		host:       route.Host,
		targetPort: route.TargetPort,
		tlsName:    route.TLSServerName,
		socksAddr:  socksRoute.Address,
		socksUser:  socksRoute.Username,
		socksPass:  socksRoute.Password,
	}
	endpointKey := route.EndpointID
	if endpointKey == "" {
		endpointKey = route.Protocol + "://" + net.JoinHostPort(route.Host, strconv.Itoa(route.TargetPort))
	}
	// Keep upstream connection pools inside one random browser access origin so
	// connection-bound device authentication cannot cross access sessions.
	transportKey := token + "\x00" + endpointKey
	g.transportsMu.Lock()
	defer g.transportsMu.Unlock()
	now := time.Now().UTC()
	for key, entry := range g.transports {
		if now.Sub(entry.lastUsed) > g.idleTTL {
			entry.transport.CloseIdleConnections()
			delete(g.transports, key)
		}
	}
	if cached, ok := g.transports[transportKey]; ok && cached.config == config {
		cached.lastUsed = now
		g.transports[transportKey] = cached
		return cached.transport
	}
	dialer := SOCKSDialer{ProxyAddress: socksRoute.Address, Username: socksRoute.Username, Password: socksRoute.Password, Timeout: g.timeout}
	tracker := newWebSessionActivityTracker(g.sessions, sessionID, g.idleTTL)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := dialer.DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return g.trackWebActivityConn(connection, tracker)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          128,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       45 * time.Second,
		TLSHandshakeTimeout:   12 * time.Second,
		ResponseHeaderTimeout: g.timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: firstNonEmpty(route.TLSServerName, route.Host),
			// Customer-device administration pages commonly use private CAs or
			// self-signed certificates. The destination remains fixed by the stored
			// endpoint and project SOCKS route; browsers never dial it directly.
			InsecureSkipVerify: true, //nolint:gosec -- fixed private endpoint over authenticated project SOCKS
		},
	}
	if previous, ok := g.transports[transportKey]; ok {
		previous.transport.CloseIdleConnections()
	}
	g.transports[transportKey] = proxyTransportEntry{config: config, transport: transport, lastUsed: now}
	return transport
}

const webActivityPersistInterval = 30 * time.Second

type webSessionActivityTracker struct {
	toucher         accessSessionToucher
	sessionID       string
	idleTTL         time.Duration
	persistInterval time.Duration
	mu              sync.Mutex
	lastPersisted   time.Time
}

func newWebSessionActivityTracker(sessions sessionResolver, sessionID string, idleTTL time.Duration) *webSessionActivityTracker {
	toucher, _ := sessions.(accessSessionToucher)
	return &webSessionActivityTracker{toucher: toucher, sessionID: sessionID, idleTTL: idleTTL, persistInterval: webActivityPersistInterval}
}

func (t *webSessionActivityTracker) touch(now time.Time) error {
	if t == nil || t.toucher == nil || t.sessionID == "" {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.lastPersisted.IsZero() && now.Sub(t.lastPersisted) < t.persistInterval {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := t.toucher.TouchAccessSession(ctx, t.sessionID, now, now.Add(-t.idleTTL)); err != nil {
		return err
	}
	t.lastPersisted = now
	return nil
}

type webActivityConn struct {
	net.Conn
	tracker      *webSessionActivityTracker
	idleTTL      time.Duration
	gateway      *WebGateway
	connectionID uint64
	closeOnce    sync.Once
	closeErr     error
}

func newWebActivityConn(connection net.Conn, tracker *webSessionActivityTracker) *webActivityConn {
	if connection == nil || tracker == nil {
		return nil
	}
	tracked := &webActivityConn{Conn: connection, tracker: tracker, idleTTL: tracker.idleTTL}
	tracked.refreshDeadline(time.Now())
	return tracked
}

func (g *WebGateway) trackWebActivityConn(connection net.Conn, tracker *webSessionActivityTracker) (net.Conn, error) {
	tracked := newWebActivityConn(connection, tracker)
	if tracked == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errors.New("invalid Web activity connection")
	}
	g.activeMu.Lock()
	g.pruneRevokedLocked(time.Now().UTC())
	if _, revoked := g.revoked[tracker.sessionID]; revoked {
		g.activeMu.Unlock()
		_ = tracked.Close()
		return nil, store.ErrNotFound
	}
	g.nextID++
	tracked.gateway = g
	tracked.connectionID = g.nextID
	if g.active[tracker.sessionID] == nil {
		g.active[tracker.sessionID] = make(map[uint64]*webActivityConn)
	}
	g.active[tracker.sessionID][tracked.connectionID] = tracked
	g.activeMu.Unlock()
	return tracked, nil
}

func (g *WebGateway) unregisterWebActivityConn(sessionID string, connectionID uint64) {
	g.activeMu.Lock()
	defer g.activeMu.Unlock()
	delete(g.active[sessionID], connectionID)
	if len(g.active[sessionID]) == 0 {
		delete(g.active, sessionID)
	}
}

func (g *WebGateway) pruneRevokedLocked(now time.Time) {
	cutoff := now.Add(-10 * time.Minute)
	for sessionID, revokedAt := range g.revoked {
		if revokedAt.Before(cutoff) {
			delete(g.revoked, sessionID)
		}
	}
}

func (c *webActivityConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	if count == 0 {
		if err != nil {
			_ = c.Close()
		}
		return count, err
	}
	now := time.Now().UTC()
	if touchErr := c.tracker.touch(now); touchErr != nil {
		_ = c.Close()
		return 0, touchErr
	}
	c.refreshDeadline(now)
	return count, err
}

func (c *webActivityConn) Write(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return c.Conn.Write(buffer)
	}
	now := time.Now().UTC()
	if err := c.tracker.touch(now); err != nil {
		_ = c.Close()
		return 0, err
	}
	count, err := c.Conn.Write(buffer)
	if count > 0 {
		c.refreshDeadline(now)
	}
	if err != nil {
		_ = c.Close()
	}
	return count, err
}

func (c *webActivityConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		if c.gateway != nil && c.tracker != nil {
			c.gateway.unregisterWebActivityConn(c.tracker.sessionID, c.connectionID)
		}
	})
	return c.closeErr
}

func (c *webActivityConn) refreshDeadline(now time.Time) {
	if c.idleTTL > 0 {
		_ = c.Conn.SetDeadline(now.Add(c.idleTTL))
	}
}

const httpsUpgradePath = ".dmp-upstream/https"
const upstreamSchemeCookie = "dmp_upstream_scheme"

// gatewayUpstream keeps same-device HTTP -> HTTPS upgrades inside the access
// session. The marker is intentionally limited to HTTPS on port 443, so it
// cannot be used to widen a session into an arbitrary-port proxy.
func gatewayUpstream(route store.EndpointRoute, pathValue string, stickyHTTPS bool) (scheme string, port int, path string) {
	scheme, port = route.Protocol, route.TargetPort
	trimmed := strings.TrimPrefix(pathValue, "/")
	markedHTTPS := route.Protocol == "http" && (trimmed == httpsUpgradePath || strings.HasPrefix(trimmed, httpsUpgradePath+"/"))
	if route.Protocol == "http" && (markedHTTPS || stickyHTTPS) {
		scheme, port = "https", 443
		if markedHTTPS {
			trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, httpsUpgradePath), "/")
		}
	}
	path = "/" + trimmed
	return
}

// stripControlPlaneHeaders prevents platform credentials and caller-supplied
// forwarding metadata from crossing the trust boundary into a customer device.
// Device cookies issued by the proxied application are preserved.
func stripControlPlaneHeaders(header http.Header) {
	cookieRequest := &http.Request{Header: http.Header{"Cookie": append([]string(nil), header.Values("Cookie")...)}}
	header.Del("Cookie")
	deviceCookies := make([]string, 0)
	for _, cookie := range cookieRequest.Cookies() {
		if cookie.Name == "dmp_session" || cookie.Name == "dmp_csrf" || cookie.Name == upstreamSchemeCookie || cookie.Name == accessGrantCookie {
			continue
		}
		deviceCookies = append(deviceCookies, cookie.String())
	}
	if len(deviceCookies) > 0 {
		header.Set("Cookie", strings.Join(deviceCookies, "; "))
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "X-CSRF-Token", "X-Real-IP",
		"X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-DMP-Access-Subdomain",
	} {
		header.Del(name)
	}
	// A nil value tells httputil.ReverseProxy not to append the caller IP.
	header["X-Forwarded-For"] = nil
}

func rewriteBrowserOrigin(header http.Header, targetOrigin string) {
	parts := strings.SplitN(targetOrigin, "://", 2)
	if len(parts) != 2 {
		return
	}
	if header.Get("Origin") != "" {
		header.Set("Origin", targetOrigin)
	}
	if referer := header.Get("Referer"); referer != "" {
		if parsed, err := url.Parse(referer); err == nil {
			parsed.Scheme = parts[0]
			parsed.Host = parts[1]
			parsed.RawQuery = ""
			parsed.Fragment = ""
			header.Set("Referer", parsed.String())
		}
	}
}

func rewriteLocation(header http.Header, scheme, targetHost string, targetPort int, trustedAliases ...string) {
	location := header.Get("Location")
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return
	}
	prefix := ""
	if parsed.IsAbs() {
		trustedHost := strings.EqualFold(parsed.Hostname(), targetHost)
		for _, alias := range trustedAliases {
			if strings.TrimSpace(alias) != "" && strings.EqualFold(parsed.Hostname(), strings.TrimSpace(alias)) {
				trustedHost = true
				break
			}
		}
		if !trustedHost {
			header.Set("Location", "/")
			return
		}
		locationPort := defaultURLPort(parsed.Scheme, parsed.Port())
		if strings.EqualFold(parsed.Scheme, scheme) && locationPort == targetPort {
			// Same upstream origin; keep the current session prefix.
		} else if scheme == "http" && strings.EqualFold(parsed.Scheme, "https") && (locationPort == 443 || locationPort == targetPort) {
			// Embedded devices often redirect http://host[:80] to https://host,
			// and some incorrectly retain :80. Use the registered HTTPS default
			// without letting the browser escape to the private address.
			prefix = "/" + httpsUpgradePath
		} else {
			header.Set("Location", "/")
			return
		}
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	rewritten := prefix + path
	if parsed.RawQuery != "" {
		rewritten += "?" + parsed.RawQuery
	}
	if parsed.Fragment != "" {
		rewritten += "#" + parsed.Fragment
	}
	header.Set("Location", rewritten)
}

func accessRequestUsesHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func defaultURLPort(scheme, explicit string) int {
	if explicit != "" {
		port, err := strconv.Atoi(explicit)
		if err == nil {
			return port
		}
		return 0
	}
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	if strings.EqualFold(scheme, "http") {
		return 80
	}
	return 0
}

func rewriteCookies(header http.Header) {
	response := &http.Response{Header: header}
	cookies := response.Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if cookie.Name == "dmp_session" || cookie.Name == "dmp_csrf" || cookie.Name == upstreamSchemeCookie || cookie.Name == accessGrantCookie {
			continue
		}
		cookie.Domain = ""
		if cookie.Path == "" || cookie.Path == "/" {
			cookie.Path = "/"
		} else {
			cookie.Path = "/" + strings.TrimPrefix(cookie.Path, "/")
		}
		header.Add("Set-Cookie", cookie.String())
	}
}

func directSourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func gatewayError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message))
}
