package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
)

type sessionResolver interface {
	ExchangeAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error)
	ResolveAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error)
}

type routeResolver interface {
	SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error)
}

type managedTunnelRestarter interface {
	SetManagedTunnel(context.Context, string, int, bool) error
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
	restartMu    sync.Mutex
}

func NewWebGateway(sessions sessionResolver, routes routeResolver, idleTTLs ...time.Duration) *WebGateway {
	idleTTL := 15 * time.Minute
	if len(idleTTLs) > 0 && idleTTLs[0] > 0 {
		idleTTL = idleTTLs[0]
	}
	return &WebGateway{sessions: sessions, routes: routes, timeout: 20 * time.Second, idleTTL: idleTTL, transports: make(map[string]proxyTransportEntry)}
}

func (g *WebGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if len(token) < 32 || len(token) > 128 || strings.ContainsAny(token, "/\\ ") {
		gatewayError(w, http.StatusNotFound, "访问会话不存在或已失效")
		return
	}
	pathValue := webRequestPath(r, token)
	switch pathValue {
	case webGrantAuthorizePath:
		serveGrantBootstrap(w, r)
		return
	case webGrantExchangePath:
		g.exchangeGrant(w, r, token, webAccessCookiePath(r, token))
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
	g.proxy(w, r, token, pathValue, route, socksRoute)
}

const accessGrantCookie = "dmp_access_grant"
const webGrantAuthorizePath = ".dmp/authorize"
const webGrantExchangePath = ".dmp/session"

type webGrantRequest struct {
	Grant string `json:"grant"`
}

func (g *WebGateway) exchangeGrant(w http.ResponseWriter, r *http.Request, token, cookiePath string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		gatewayError(w, http.StatusMethodNotAllowed, "访问授权交换仅支持 POST")
		return
	}
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
	if err := decoder.Decode(&input); err != nil || !validAccessToken(strings.TrimSpace(input.Grant)) {
		gatewayError(w, http.StatusBadRequest, "访问授权格式无效")
		return
	}
	grant := strings.TrimSpace(input.Grant)
	tokenDigest := sha256.Sum256([]byte(token))
	grantDigest := sha256.Sum256([]byte(grant))
	idleCutoff := time.Now().UTC().Add(-g.idleTTL)
	session, _, err := g.sessions.ExchangeAccessGrant(r.Context(), hex.EncodeToString(tokenDigest[:]), hex.EncodeToString(grantDigest[:]), idleCutoff)
	if err != nil {
		gatewayError(w, http.StatusGone, "访问授权不存在、已使用或登录已超时")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: accessGrantCookie, Value: grant, Path: cookiePath, HttpOnly: true, Secure: accessRequestUsesHTTPS(r), SameSite: http.SameSiteStrictMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
	// A previous visit may have followed a device HTTP -> HTTPS redirect. Do not
	// let that short-lived upstream choice leak into a newly authorized visit.
	clearUpstreamSchemeCookies(w, r, cookiePath)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusNoContent)
}

func clearUpstreamSchemeCookies(w http.ResponseWriter, r *http.Request, cookiePath string) {
	paths := []string{cookiePath}
	// Older releases stored this marker at the origin root. Expire that legacy
	// cookie as well so a newly opened HTTP endpoint cannot inherit an obsolete
	// HTTPS upgrade from an earlier visit.
	if cookiePath != "/" {
		paths = append(paths, "/")
	}
	for _, path := range paths {
		http.SetCookie(w, &http.Cookie{
			Name:     upstreamSchemeCookie,
			Value:    "",
			Path:     path,
			HttpOnly: true,
			Secure:   accessRequestUsesHTTPS(r),
			SameSite: http.SameSiteStrictMode,
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
		})
	}
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>正在建立安全访问</title><style>body{font:16px system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f8fa;color:#23313d}main{max-width:32rem;padding:2rem;text-align:center}</style><main><p id="status">正在建立安全访问…</p></main><script>(()=>{const match=/^#grant=([0-9a-f]{48})$/.exec(location.hash);const status=document.getElementById('status');if(!match){status.textContent='访问授权无效，请返回平台重新打开';return}const suffix='/.dmp/authorize';const path=location.pathname;const root=path.endsWith(suffix)?path.slice(0,-suffix.length)+'/':'/';const endpoint=path.endsWith(suffix)?path.slice(0,-'authorize'.length)+'session':root+'.dmp/session';fetch(endpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant:match[1]})}).then(response=>{if(!response.ok)throw new Error('exchange failed');history.replaceState(null,'',root+location.search);location.replace(root+location.search)}).catch(()=>{history.replaceState(null,'',root+location.search);status.textContent='访问授权已失效，请返回平台重新打开'})})();</script></html>`)
}

func webAccessCookiePath(r *http.Request, token string) string {
	if usesSessionSubdomain(r) {
		return "/"
	}
	return "/access/web/" + token + "/"
}

// webRequestPath derives the upstream path from the rewritten request URL.
// Access-domain routing changes URL.Path before the request reaches ServeMux;
// using that canonical path also keeps the gateway independent from stale path
// values on cloned requests created by outer middleware.
func webRequestPath(r *http.Request, token string) string {
	prefix := "/access/web/" + token + "/"
	if strings.HasPrefix(r.URL.Path, prefix) {
		return strings.TrimPrefix(r.URL.Path, prefix)
	}
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

func (g *WebGateway) proxy(w http.ResponseWriter, r *http.Request, token, requestPath string, route store.EndpointRoute, socksRoute nodeadapter.SOCKSRoute) {
	basePrefix := "/access/web/" + token
	if usesSessionSubdomain(r) {
		basePrefix = ""
	}
	stickyHTTPS := false
	if cookie, err := r.Cookie(upstreamSchemeCookie); err == nil && cookie.Value == "https" {
		stickyHTTPS = true
	}
	upstreamScheme, upstreamPort, upstreamPath, responsePrefix := gatewayUpstream(route, requestPath, basePrefix, stickyHTTPS)
	targetAuthority := net.JoinHostPort(route.Host, strconv.Itoa(upstreamPort))
	upstreamHost := route.Host
	if upstreamScheme == "https" && strings.TrimSpace(route.TLSServerName) != "" {
		upstreamHost = strings.TrimSpace(route.TLSServerName)
	}
	upstreamAuthority := net.JoinHostPort(upstreamHost, strconv.Itoa(upstreamPort))
	transport := g.proxyTransport(token, route, socksRoute)
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			request := proxyRequest.Out
			stripControlPlaneHeaders(request.Header)
			// Path-prefix access needs textual response rewriting. Removing the
			// browser's Accept-Encoding lets net/http transparently decompress the
			// upstream body before ModifyResponse sees it.
			if responsePrefix != "" {
				request.Header.Del("Accept-Encoding")
			}
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
			rewriteLocation(response.Header, upstreamScheme, route.Host, upstreamPort, basePrefix, responsePrefix, route.TLSServerName)
			// Rewrite upstream cookies first. That function intentionally discards
			// names reserved by the platform, so the trusted gateway marker must be
			// appended afterwards instead of being mistaken for an injected device
			// cookie and removed again.
			rewriteCookies(response.Header, responsePrefix)
			appendTrustedUpstreamSchemeCookie(response.Header, r, token, route.Protocol, upstreamScheme)
			if err := rewriteTextResponse(response, responsePrefix); err != nil {
				return err
			}
			response.Header.Set("Cache-Control", "no-store")
			response.Header.Set("Referrer-Policy", "no-referrer")
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

func appendTrustedUpstreamSchemeCookie(header http.Header, r *http.Request, token, routeProtocol, upstreamScheme string) {
	if routeProtocol != "http" || upstreamScheme != "https" {
		return
	}
	header.Add("Set-Cookie", (&http.Cookie{
		Name:     upstreamSchemeCookie,
		Value:    "https",
		Path:     webAccessCookiePath(r, token),
		HttpOnly: true,
		Secure:   accessRequestUsesHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	}).String())
}

type proxyTransportConfig struct {
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

func (g *WebGateway) proxyTransport(token string, route store.EndpointRoute, socksRoute nodeadapter.SOCKSRoute) *http.Transport {
	config := proxyTransportConfig{
		protocol:   route.Protocol,
		host:       route.Host,
		targetPort: route.TargetPort,
		tlsName:    route.TLSServerName,
		socksAddr:  socksRoute.Address,
		socksUser:  socksRoute.Username,
		socksPass:  socksRoute.Password,
	}
	endpointSlot := route.EndpointID
	if endpointSlot == "" {
		endpointSlot = route.Protocol + "://" + net.JoinHostPort(route.Host, strconv.Itoa(route.TargetPort))
	}
	// Keep upstream connection pools inside one browser access origin. Some
	// legacy device UIs use connection-bound authentication, so sharing a TCP
	// connection between two users would defeat cookie and hostname isolation.
	slot := token + "\x00" + endpointSlot
	g.transportsMu.Lock()
	defer g.transportsMu.Unlock()
	now := time.Now().UTC()
	for key, entry := range g.transports {
		if now.Sub(entry.lastUsed) > g.idleTTL {
			entry.transport.CloseIdleConnections()
			delete(g.transports, key)
		}
	}
	if cached, ok := g.transports[slot]; ok && cached.config == config {
		cached.lastUsed = now
		g.transports[slot] = cached
		return cached.transport
	}
	dialer := SOCKSDialer{ProxyAddress: socksRoute.Address, Username: socksRoute.Username, Password: socksRoute.Password, Timeout: g.timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := dialer.DialContext(ctx, network, address)
			if err == nil || !errors.Is(err, errSOCKSProxyUnavailable) {
				return connection, err
			}
			// NPS persistently stops a managed SOCKS listener after 30 minutes
			// without flow changes. A still-authorized platform session should
			// lazily resume that listener once, then retry the original dial.
			if restartErr := g.restartManagedTunnel(ctx, route.NodeID, route.ClientID); restartErr != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, address)
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
	if previous, ok := g.transports[slot]; ok {
		previous.transport.CloseIdleConnections()
	}
	g.transports[slot] = proxyTransportEntry{config: config, transport: transport, lastUsed: now}
	return transport
}

func (g *WebGateway) restartManagedTunnel(ctx context.Context, nodeID string, clientID int) error {
	controller, ok := g.routes.(managedTunnelRestarter)
	if !ok {
		return errors.New("managed tunnel restart is unavailable")
	}
	// Asset bursts after an idle close can otherwise issue many concurrent NPS
	// start requests. SetManagedTunnel is idempotent, so serialize only recovery.
	g.restartMu.Lock()
	defer g.restartMu.Unlock()
	return controller.SetManagedTunnel(ctx, nodeID, clientID, true)
}

const httpsUpgradePath = ".dmp-upstream/https"
const upstreamSchemeCookie = "dmp_upstream_scheme"

// gatewayUpstream keeps same-device HTTP -> HTTPS upgrades inside the access
// session. The marker is intentionally limited to HTTPS on port 443, so it
// cannot be used to widen a session into an arbitrary-port proxy.
func gatewayUpstream(route store.EndpointRoute, pathValue, basePrefix string, stickyHTTPS bool) (scheme string, port int, path, responsePrefix string) {
	scheme, port = route.Protocol, route.TargetPort
	trimmed := strings.TrimPrefix(pathValue, "/")
	responsePrefix = basePrefix
	markedHTTPS := route.Protocol == "http" && (trimmed == httpsUpgradePath || strings.HasPrefix(trimmed, httpsUpgradePath+"/"))
	if route.Protocol == "http" && (markedHTTPS || stickyHTTPS) {
		scheme, port = "https", 443
		if markedHTTPS {
			trimmed = strings.TrimPrefix(strings.TrimPrefix(trimmed, httpsUpgradePath), "/")
		}
		if basePrefix != "" {
			responsePrefix = basePrefix + "/" + httpsUpgradePath
		}
	}
	path = "/" + trimmed
	return
}

const maxRewrittenResponseBytes = 16 << 20

// rewriteTextResponse preserves access-session path isolation when a device UI
// is mounted below /access/web/{token}. Many embedded UIs (including LuCI) emit
// origin-root URLs such as /luci-static/... from HTML, JavaScript and CSS. Left
// untouched those requests escape the access session and hit the control plane.
// Production deployments should still prefer the configured wildcard access
// domain, where each session owns an origin and no body rewriting is required.
func rewriteTextResponse(response *http.Response, prefix string) error {
	if prefix == "" || response.Body == nil || !isRewritableContentType(response.Header.Get("Content-Type")) {
		return nil
	}
	if encoding := strings.TrimSpace(response.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRewrittenResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read upstream text response: %w", err)
	}
	if len(body) > maxRewrittenResponseBytes {
		response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), response.Body))
		return nil
	}
	_ = response.Body.Close()
	rewritten := prefixRootURLs(body, prefix)
	response.Body = io.NopCloser(bytes.NewReader(rewritten))
	response.ContentLength = int64(len(rewritten))
	response.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
	response.Header.Del("ETag")
	response.Header.Del("Content-MD5")
	return nil
}

func isRewritableContentType(contentType string) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	return mediaType == "text/html" || mediaType == "application/xhtml+xml" || mediaType == "text/css" ||
		strings.Contains(mediaType, "javascript") || strings.Contains(mediaType, "json")
}

// prefixRootURLs deliberately targets only quoted root paths and CSS url(/...)
// forms. It leaves protocol-relative URLs (//cdn.example/...) and ordinary text
// untouched, while also handling JSON's optional escaped slash form (\"\\/api\").
func prefixRootURLs(input []byte, prefix string) []byte {
	if len(input) == 0 || prefix == "" {
		return input
	}
	prefixBytes := []byte(prefix)
	output := make([]byte, 0, len(input)+len(prefixBytes)*8)
	for index := 0; index < len(input); index++ {
		current := input[index]
		output = append(output, current)
		if current == '\'' || current == '"' || current == '`' {
			// Quotes can legally occur inside JavaScript regular-expression
			// literals, for example /'/g. A quote immediately following the
			// opening slash is not a string boundary and must remain untouched.
			if index > 0 && input[index-1] == '/' {
				continue
			}
			if index+2 < len(input) && input[index+1] == '/' && isURLPathStart(input[index+2]) {
				output = append(output, prefixBytes...)
			} else if index+3 < len(input) && input[index+1] == '\\' && input[index+2] == '/' && isURLPathStart(input[index+3]) {
				output = append(output, prefixBytes...)
			}
			continue
		}
		if current == '(' && index >= 3 && index+2 < len(input) && input[index+1] == '/' && isURLPathStart(input[index+2]) {
			if strings.EqualFold(string(input[index-3:index]), "url") {
				output = append(output, prefixBytes...)
			}
		}
	}
	return output
}

func isURLPathStart(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '_' || value == '-' || value == '.' || value == '~'
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

func rewriteLocation(header http.Header, scheme, targetHost string, targetPort int, basePrefix, responsePrefix string, trustedAliases ...string) {
	location := header.Get("Location")
	if location == "" {
		return
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return
	}
	prefix := responsePrefix
	if parsed.IsAbs() {
		trustedHost := strings.EqualFold(parsed.Hostname(), targetHost)
		for _, alias := range trustedAliases {
			if strings.TrimSpace(alias) != "" && strings.EqualFold(parsed.Hostname(), strings.TrimSpace(alias)) {
				trustedHost = true
				break
			}
		}
		if !trustedHost {
			header.Set("Location", accessSessionRoot(basePrefix))
			return
		}
		locationPort := defaultURLPort(parsed.Scheme, parsed.Port())
		if strings.EqualFold(parsed.Scheme, scheme) && locationPort == targetPort {
			// Same upstream origin; keep the current session prefix.
		} else if scheme == "http" && strings.EqualFold(parsed.Scheme, "https") && (locationPort == 443 || locationPort == targetPort) {
			// Embedded devices often redirect http://host[:80] to https://host,
			// and some incorrectly retain :80. Use the registered HTTPS default
			// without letting the browser escape to the private address.
			prefix = basePrefix + "/" + httpsUpgradePath
		} else {
			header.Set("Location", accessSessionRoot(basePrefix))
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

func accessSessionRoot(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return strings.TrimSuffix(prefix, "/") + "/"
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

func rewriteCookies(header http.Header, prefix string) {
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
			cookie.Path = prefix + "/"
		} else {
			cookie.Path = prefix + "/" + strings.TrimPrefix(cookie.Path, "/")
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
