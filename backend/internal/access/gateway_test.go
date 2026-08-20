package access

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/webroutelabel"
	"github.com/coder/websocket"
)

type fakeSessionResolver struct {
	session store.AccessSession
	route   store.EndpointRoute
	err     error
}

func (f fakeSessionResolver) ExchangeAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error) {
	return f.session, f.route, f.err
}

func (f fakeSessionResolver) ResolveAccessGrant(context.Context, string, string, time.Time) (store.AccessSession, store.EndpointRoute, error) {
	return f.session, f.route, f.err
}

func authorizeGatewayRequest(request *http.Request) {
	request.AddCookie(&http.Cookie{Name: accessGrantCookie, Value: strings.Repeat("g", 43)})
}

func testWebRoute(t *testing.T) string {
	t.Helper()
	label, err := webroutelabel.New()
	if err != nil {
		t.Fatal(err)
	}
	return label
}

func gatewayNamedCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func TestWebGatewayBootstrapsAndExchangesFragmentGrant(t *testing.T) {
	token := testWebRoute(t)
	grant := strings.Repeat("b", 48)
	gateway := NewWebGateway(
		fakeSessionResolver{session: store.AccessSession{ExpiresAt: time.Now().Add(time.Hour)}},
		fakeRouteResolver{},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)

	bootstrapRequest := httptest.NewRequest(http.MethodGet, "https://access.example/access/web/"+token+"/.dmp/authorize", nil)
	// The authorization endpoint must process a new fragment instead of
	// attempting to proxy with an unrelated access cookie.
	bootstrapRequest.AddCookie(&http.Cookie{Name: accessGrantCookie, Value: strings.Repeat("c", 48)})
	bootstrapResponse := httptest.NewRecorder()
	mux.ServeHTTP(bootstrapResponse, WithSessionSubdomainAccess(bootstrapRequest))
	if bootstrapResponse.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d: %s", bootstrapResponse.Code, bootstrapResponse.Body.String())
	}
	if got := bootstrapResponse.Header().Get("X-Robots-Tag"); got != "noindex, nofollow, noarchive" {
		t.Fatalf("bootstrap X-Robots-Tag = %q", got)
	}
	body := bootstrapResponse.Body.String()
	if !strings.Contains(body, "location.hash") || !strings.Contains(body, "fetch('/.dmp/session'") || strings.Contains(body, "?grant=") || !strings.Contains(body, `data-i5cloud-proxy-notice="true"`) || !strings.Contains(body, `id="dismiss"`) || !strings.Contains(body, `aria-label="&#x5173;&#x95ED;&#x63D0;&#x793A;"`) {
		t.Fatalf("bootstrap does not use fragment-to-POST exchange: %s", body)
	}

	exchangeRequest := httptest.NewRequest(http.MethodPost, "https://access.example/access/web/"+token+"/.dmp/session", strings.NewReader(`{"grant":"`+grant+`"}`))
	exchangeRequest.Header.Set("Origin", "https://access.example")
	exchangeResponse := httptest.NewRecorder()
	mux.ServeHTTP(exchangeResponse, WithSessionSubdomainAccess(exchangeRequest))
	if exchangeResponse.Code != http.StatusNoContent {
		t.Fatalf("exchange status = %d: %s", exchangeResponse.Code, exchangeResponse.Body.String())
	}
	cookies := exchangeResponse.Result().Cookies()
	var accessCookie *http.Cookie
	var clearedSchemePaths []string
	for _, cookie := range cookies {
		if cookie.Name == accessGrantCookie {
			accessCookie = cookie
		}
		if cookie.Name == upstreamSchemeCookie && cookie.MaxAge < 0 {
			clearedSchemePaths = append(clearedSchemePaths, cookie.Path)
		}
	}
	if accessCookie == nil || accessCookie.Value != grant || !accessCookie.HttpOnly || !accessCookie.Secure {
		t.Fatalf("exchange cookie = %#v", cookies)
	}
	if accessCookie.Path != "/" {
		t.Fatalf("exchange cookie path = %q", accessCookie.Path)
	}
	if got := strings.Join(clearedSchemePaths, ","); got != "/" {
		t.Fatalf("cleared scheme cookie paths = %q", got)
	}

	formRequest := httptest.NewRequest(http.MethodPost, "https://device-route.access.example/access/web/"+token+"/.dmp/session", strings.NewReader("grant="+grant))
	formRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formRequest.Header.Set("Origin", "https://panel.example")
	formRequest.Header.Set("Sec-Fetch-Mode", "navigate")
	formRequest.Header.Set("Sec-Fetch-Dest", "document")
	formRequest.Header.Set("Sec-Fetch-Site", "same-site")
	formResponse := httptest.NewRecorder()
	mux.ServeHTTP(formResponse, WithSessionSubdomainAccess(formRequest))
	formCookie := gatewayNamedCookie(formResponse.Result().Cookies(), accessGrantCookie)
	if formResponse.Code != http.StatusOK || formResponse.Header().Get("Location") != "" || !strings.Contains(formResponse.Body.String(), "I5CLOUD 远程管理平台") || !strings.Contains(formResponse.Body.String(), `location.replace("/")`) || !strings.Contains(formResponse.Body.String(), `id="dismiss"`) {
		t.Fatalf("form exchange = %d location=%q: %s", formResponse.Code, formResponse.Header().Get("Location"), formResponse.Body.String())
	}
	if formCookie == nil || formCookie.Path != "/" || formCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("form exchange cookie = %#v", formCookie)
	}
	if got := formResponse.Header().Get("X-Robots-Tag"); got != "noindex, nofollow, noarchive" {
		t.Fatalf("form exchange X-Robots-Tag = %q", got)
	}

	foreignOriginRequest := httptest.NewRequest(http.MethodPost, "https://access.example/access/web/"+token+"/.dmp/session", strings.NewReader(`{"grant":"`+grant+`"}`))
	foreignOriginRequest.Header.Set("Origin", "https://attacker.example")
	foreignOriginResponse := httptest.NewRecorder()
	mux.ServeHTTP(foreignOriginResponse, WithSessionSubdomainAccess(foreignOriginRequest))
	if foreignOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("foreign origin exchange status = %d", foreignOriginResponse.Code)
	}
}

func TestRandomOriginDeviceCookiesKeepNativeNames(t *testing.T) {
	responseHeader := http.Header{}
	responseHeader.Add("Set-Cookie", "device_session=value-a; Path=/; HttpOnly")
	rewriteCookies(responseHeader)
	rewritten := (&http.Response{Header: responseHeader}).Cookies()
	if len(rewritten) != 1 || rewritten[0].Name != "device_session" || rewritten[0].Path != "/" {
		t.Fatalf("rewritten response cookies = %#v", rewritten)
	}

	requestHeader := http.Header{}
	requestHeader.Set("Cookie", "device_session=value-a; unrelated=device-value; dmp_session=platform")
	stripControlPlaneHeaders(requestHeader)
	if got := requestHeader.Get("Cookie"); got != "device_session=value-a; unrelated=device-value" {
		t.Fatalf("device cookies were changed or platform cookies leaked upstream: %q", got)
	}
}

func TestWebGatewayReusesTransportForSameEndpointRoute(t *testing.T) {
	gateway := NewWebGateway(fakeSessionResolver{}, fakeRouteResolver{})
	route := store.EndpointRoute{EndpointID: "endpoint-1", Protocol: "https", Host: "10.0.0.8", TLSServerName: "router.lan"}
	socksRoute := nodeadapter.SOCKSRoute{Address: "127.0.0.1:1080", Username: "user", Password: "pass"}
	first := gateway.proxyTransport("web-route-one", "session-one", route, socksRoute)
	second := gateway.proxyTransport("web-route-one", "session-one", route, socksRoute)
	if first != second {
		t.Fatal("same access origin and endpoint created more than one transport")
	}
	if first == gateway.proxyTransport("web-route-two", "session-two", route, socksRoute) {
		t.Fatal("different access origins shared an upstream connection pool")
	}
	rotated := socksRoute
	rotated.Password = "new-pass"
	if first == gateway.proxyTransport("web-route-one", "session-one", route, rotated) {
		t.Fatal("rotated SOCKS credentials reused the previous transport")
	}
}

func TestWebTrafficPersistsSessionActivity(t *testing.T) {
	resolver := &touchSessionResolver{}
	tracker := newWebSessionActivityTracker(resolver, "web-session", time.Minute)
	tracker.persistInterval = time.Hour
	client, server := net.Pipe()
	defer server.Close()
	connection := newWebActivityConn(client, tracker)
	defer connection.Close()
	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 4)
		count, _ := io.ReadFull(server, buffer)
		received <- string(buffer[:count])
	}()
	if _, err := connection.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "ping" {
		t.Fatalf("proxied bytes = %q", got)
	}
	resolver.mu.Lock()
	touches := resolver.touches
	resolver.mu.Unlock()
	if touches != 1 {
		t.Fatalf("persisted Web activity = %d, want 1", touches)
	}
}

func TestWebTrafficCannotReviveExpiredSession(t *testing.T) {
	resolver := &touchSessionResolver{err: store.ErrNotFound}
	tracker := newWebSessionActivityTracker(resolver, "expired-web-session", time.Minute)
	client, server := net.Pipe()
	defer server.Close()
	connection := newWebActivityConn(client, tracker)
	defer connection.Close()
	if _, err := connection.Write([]byte("blocked")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired Web activity error = %v, want ErrNotFound", err)
	}
	_ = server.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buffer := make([]byte, 1)
	if count, _ := server.Read(buffer); count != 0 {
		t.Fatalf("expired Web session forwarded %d bytes", count)
	}
}

func TestIdleWebConnectionClosesAtAccessSessionLimit(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	tracker := newWebSessionActivityTracker(fakeSessionResolver{}, "", 25*time.Millisecond)
	connection := newWebActivityConn(client, tracker)
	defer connection.Close()
	started := time.Now()
	buffer := make([]byte, 1)
	_, err := connection.Read(buffer)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("idle Web connection error = %v, want timeout", err)
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatalf("idle Web connection did not close near its access-session limit")
	}
}

func TestWebGatewayRevocationImmediatelyClosesActiveConnections(t *testing.T) {
	gateway := NewWebGateway(fakeSessionResolver{}, fakeRouteResolver{})
	tracker := newWebSessionActivityTracker(fakeSessionResolver{}, "revoked-web-session", time.Minute)
	client, server := net.Pipe()
	defer server.Close()
	connection, err := gateway.trackWebActivityConn(client, tracker)
	if err != nil {
		t.Fatal(err)
	}
	if !gateway.Revoke("revoked-web-session") {
		t.Fatal("active Web connection was not found during revocation")
	}
	if _, err := connection.Write([]byte("blocked")); err == nil {
		t.Fatal("revoked Web connection remained writable")
	}

	lateClient, lateServer := net.Pipe()
	defer lateServer.Close()
	if _, err := gateway.trackWebActivityConn(lateClient, tracker); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("late Web connection error = %v, want ErrNotFound", err)
	}
}

type fakeRouteResolver struct {
	route nodeadapter.SOCKSRoute
}

func (f fakeRouteResolver) SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error) {
	return f.route, nil
}

func TestWebGatewayProxiesThroughAuthenticatedSOCKS(t *testing.T) {
	var requestPath, requestHost, requestOrigin, requestCookie, requestAuthorization, requestForwardedFor string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.RequestURI()
		requestHost = r.Host
		requestOrigin = r.Header.Get("Origin")
		requestCookie = r.Header.Get("Cookie")
		requestAuthorization = r.Header.Get("Authorization")
		requestForwardedFor = r.Header.Get("X-Forwarded-For")
		http.SetCookie(w, &http.Cookie{Name: "device_session", Value: "ok", Path: "/", HttpOnly: true})
		w.Header().Set("Location", "/next?from=device")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{
			session: store.AccessSession{Mode: "web", SourceIP: "192.0.2.1"},
			route:   store.EndpointRoute{Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/login?x=1", nil)
	authorizeGatewayRequest(request)
	request.Header.Set("Origin", "http://platform.example")
	request.Header.Set("Authorization", "Bearer platform-secret")
	request.Header.Set("X-CSRF-Token", "platform-csrf")
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	request.Header.Set("X-DMP-Access-Subdomain", "1")
	request.Header.Set("Cookie", "dmp_session=platform-session; dmp_csrf=platform-csrf; device_session=device-value")
	authorizeGatewayRequest(request)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, WithSessionSubdomainAccess(request))
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if requestPath != "/login?x=1" {
		t.Fatalf("upstream path = %q", requestPath)
	}
	if requestHost != upstreamAddress || requestOrigin != upstream.URL {
		t.Fatalf("host/origin = %q / %q", requestHost, requestOrigin)
	}
	if requestCookie != "device_session=device-value" || requestAuthorization != "" || requestForwardedFor != "" {
		t.Fatalf("control-plane headers leaked: cookie=%q authorization=%q forwarded-for=%q", requestCookie, requestAuthorization, requestForwardedFor)
	}
	wantLocation := "/next?from=device"
	if got := response.Header().Get("Location"); got != wantLocation {
		t.Fatalf("location = %q, want %q", got, wantLocation)
	}
	if cookie := response.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Path=/") || !strings.Contains(cookie, "HttpOnly") || strings.Contains(cookie, "/access/web/") {
		t.Fatalf("cookie was not scoped to the random origin: %q", cookie)
	}
}

func TestWebGatewayPreservesAllUpstreamBodiesWithoutInjection(t *testing.T) {
	const logBody = "2026-08-20 passwall service started\n"
	const packageUpdatePath = "/cgi-bin/luci/admin/system/package-manager/update"
	const packageUpdateRequest = "update=1"
	const packageUpdateBody = "Downloading https://downloads.openwrt.org/Packages.gz\nUpdated list of available packages\n"
	const packageArchivePath = "/downloads/openwrt/base/Packages.gz"
	const compressedPagePath = "/cgi-bin/luci/compressed"
	const documentBody = "<!doctype html><html><head><meta charset=utf-8></head><body>OpenWrt</body></html>"
	packageArchiveBody := []byte{0x1f, 0x8b, 0x08, 0x00, 0x50, 0x4b, 0x47, 0x00}
	compressedPageBody := []byte{0x1f, 0x8b, 0x08, 0x00, 0x48, 0x54, 0x4d, 0x4c}
	var headerMu sync.Mutex
	acceptEncoding := make(map[string]string)
	requestBodies := make(map[string]string)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, _ := io.ReadAll(r.Body)
		headerMu.Lock()
		acceptEncoding[r.URL.Path] = r.Header.Get("Accept-Encoding")
		requestBodies[r.URL.Path] = string(requestBody)
		headerMu.Unlock()
		switch r.URL.Path {
		case "/cgi-bin/luci/admin/services/passwall/get_log":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, logBody)
		case packageUpdatePath:
			// LuCI package actions commonly return command output through an AJAX
			// endpoint whose content type is text/html.
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, packageUpdateBody)
		case packageArchivePath:
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(packageArchiveBody)
		case compressedPagePath:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressedPageBody)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, documentBody)
		}
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{
			session: store.AccessSession{Mode: "web"},
			route:   store.EndpointRoute{Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)

	logRequest := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/cgi-bin/luci/admin/services/passwall/get_log", nil)
	authorizeGatewayRequest(logRequest)
	logRequest.Header.Set("Sec-Fetch-Dest", "empty")
	logRequest.Header.Set("Sec-Fetch-Mode", "cors")
	logRequest.Header.Set("Accept-Encoding", "br")
	logResponse := httptest.NewRecorder()
	mux.ServeHTTP(logResponse, WithSessionSubdomainAccess(logRequest))
	if logResponse.Code != http.StatusOK || logResponse.Body.String() != logBody {
		t.Fatalf("PassWall log response changed: status=%d body=%q", logResponse.Code, logResponse.Body.String())
	}
	if strings.Contains(logResponse.Body.String(), "data-i5cloud-proxy-notice") {
		t.Fatalf("proxy disclosure leaked into PassWall log: %q", logResponse.Body.String())
	}

	packageUpdate := httptest.NewRequest(http.MethodPost, "/access/web/"+token+packageUpdatePath, strings.NewReader(packageUpdateRequest))
	authorizeGatewayRequest(packageUpdate)
	packageUpdate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	packageUpdate.Header.Set("Sec-Fetch-Dest", "empty")
	packageUpdate.Header.Set("Sec-Fetch-Mode", "cors")
	packageUpdate.Header.Set("Accept-Encoding", "gzip, br, zstd")
	packageUpdateResponse := httptest.NewRecorder()
	mux.ServeHTTP(packageUpdateResponse, WithSessionSubdomainAccess(packageUpdate))
	if packageUpdateResponse.Code != http.StatusOK || packageUpdateResponse.Body.String() != packageUpdateBody {
		t.Fatalf("OpenWrt package update response changed: status=%d body=%q", packageUpdateResponse.Code, packageUpdateResponse.Body.String())
	}

	packageArchive := httptest.NewRequest(http.MethodGet, "/access/web/"+token+packageArchivePath, nil)
	authorizeGatewayRequest(packageArchive)
	packageArchive.Header.Set("Sec-Fetch-Dest", "document")
	packageArchive.Header.Set("Sec-Fetch-Mode", "navigate")
	packageArchive.Header.Set("Accept-Encoding", "gzip, br, zstd")
	packageArchiveResponse := httptest.NewRecorder()
	mux.ServeHTTP(packageArchiveResponse, WithSessionSubdomainAccess(packageArchive))
	if packageArchiveResponse.Code != http.StatusOK || !bytes.Equal(packageArchiveResponse.Body.Bytes(), packageArchiveBody) {
		t.Fatalf("OpenWrt package archive changed: status=%d body=%x", packageArchiveResponse.Code, packageArchiveResponse.Body.Bytes())
	}

	compressedPage := httptest.NewRequest(http.MethodGet, "/access/web/"+token+compressedPagePath, nil)
	authorizeGatewayRequest(compressedPage)
	compressedPage.Header.Set("Sec-Fetch-Dest", "document")
	compressedPage.Header.Set("Sec-Fetch-Mode", "navigate")
	compressedPage.Header.Set("Accept-Encoding", "gzip")
	compressedPageResponse := httptest.NewRecorder()
	mux.ServeHTTP(compressedPageResponse, WithSessionSubdomainAccess(compressedPage))
	if compressedPageResponse.Code != http.StatusOK || compressedPageResponse.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(compressedPageResponse.Body.Bytes(), compressedPageBody) {
		t.Fatalf("compressed OpenWrt page changed: status=%d encoding=%q body=%x", compressedPageResponse.Code, compressedPageResponse.Header().Get("Content-Encoding"), compressedPageResponse.Body.Bytes())
	}

	documentRequest := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
	authorizeGatewayRequest(documentRequest)
	documentRequest.Header.Set("Sec-Fetch-Dest", "document")
	documentRequest.Header.Set("Sec-Fetch-Mode", "navigate")
	documentRequest.Header.Set("Accept-Encoding", "br")
	documentResponse := httptest.NewRecorder()
	mux.ServeHTTP(documentResponse, WithSessionSubdomainAccess(documentRequest))
	if documentResponse.Code != http.StatusOK || documentResponse.Body.String() != documentBody {
		t.Fatalf("OpenWrt document response changed: status=%d body=%q", documentResponse.Code, documentResponse.Body.String())
	}
	if strings.Contains(documentResponse.Body.String(), "data-i5cloud-proxy-notice") {
		t.Fatalf("platform notice leaked into OpenWrt document: %q", documentResponse.Body.String())
	}
	headerMu.Lock()
	logEncoding := acceptEncoding["/cgi-bin/luci/admin/services/passwall/get_log"]
	updateEncoding := acceptEncoding[packageUpdatePath]
	archiveEncoding := acceptEncoding[packageArchivePath]
	compressedEncoding := acceptEncoding[compressedPagePath]
	documentEncoding := acceptEncoding["/"]
	gotPackageUpdateRequest := requestBodies[packageUpdatePath]
	headerMu.Unlock()
	if logEncoding != "br" {
		t.Fatalf("subresource Accept-Encoding changed: %q", logEncoding)
	}
	if updateEncoding != "gzip, br, zstd" || archiveEncoding != "gzip, br, zstd" || compressedEncoding != "gzip" || documentEncoding != "br" {
		t.Fatalf("Accept-Encoding changed: update=%q archive=%q compressed=%q document=%q", updateEncoding, archiveEncoding, compressedEncoding, documentEncoding)
	}
	if gotPackageUpdateRequest != packageUpdateRequest {
		t.Fatalf("OpenWrt package update request changed: %q", gotPackageUpdateRequest)
	}
}

func TestWebGatewayStreamsOpaqueHTMLWithoutWaitingForEOF(t *testing.T) {
	const firstChunk = "package operation started\n"
	const secondChunk = "package operation completed\n"
	firstWritten := make(chan struct{})
	releaseUpstream := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseUpstream) }) }

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, firstChunk)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		close(firstWritten)
		<-releaseUpstream
		_, _ = io.WriteString(w, secondChunk)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{
			session: store.AccessSession{Mode: "web"},
			route:   store.EndpointRoute{Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	gatewayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, WithSessionSubdomainAccess(r))
	}))
	defer gatewayServer.Close()
	defer release()

	type firstReadResult struct {
		response *http.Response
		chunk    string
		err      error
	}
	result := make(chan firstReadResult, 1)
	go func() {
		request, err := http.NewRequest(http.MethodPost, gatewayServer.URL+"/access/web/"+token+"/package/update", strings.NewReader("update=1"))
		if err != nil {
			result <- firstReadResult{err: err}
			return
		}
		authorizeGatewayRequest(request)
		request.Header.Set("Sec-Fetch-Dest", "empty")
		request.Header.Set("Sec-Fetch-Mode", "cors")
		response, err := gatewayServer.Client().Do(request)
		if err != nil {
			result <- firstReadResult{err: err}
			return
		}
		buffer := make([]byte, len(firstChunk))
		_, err = io.ReadFull(response.Body, buffer)
		result <- firstReadResult{response: response, chunk: string(buffer), err: err}
	}()

	select {
	case <-firstWritten:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not produce the first streaming chunk")
	}
	var first firstReadResult
	select {
	case first = <-result:
	case <-time.After(time.Second):
		release()
		<-result
		t.Fatal("gateway waited for the upstream HTML response to finish before forwarding data")
	}
	if first.err != nil {
		t.Fatal(first.err)
	}
	if first.response.StatusCode != http.StatusOK || first.chunk != firstChunk {
		t.Fatalf("first streamed chunk changed: status=%d chunk=%q", first.response.StatusCode, first.chunk)
	}
	release()
	rest, err := io.ReadAll(first.response.Body)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.response.Body.Close()
	if string(rest) != secondChunk {
		t.Fatalf("remaining streamed body changed: %q", rest)
	}
}

func TestWebGatewayProxiesWebSocketThroughAuthenticatedSOCKS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		messageType, message, err := connection.Read(r.Context())
		if err != nil {
			return
		}
		_ = connection.Write(r.Context(), messageType, append([]byte("device:"), message...))
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{
			session: store.AccessSession{Mode: "web"},
			route:   store.EndpointRoute{EndpointID: "websocket-endpoint", Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, WithSessionSubdomainAccess(r))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, response, err := websocket.Dial(
		ctx,
		"ws"+strings.TrimPrefix(server.URL, "http")+"/access/web/"+token+"/socket",
		&websocket.DialOptions{HTTPHeader: http.Header{"Cookie": []string{accessGrantCookie + "=" + strings.Repeat("g", 43)}}},
	)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial gateway websocket: %v (status %d)", err, status)
	}
	defer connection.CloseNow()
	if err := connection.Write(ctx, websocket.MessageText, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	messageType, message, err := connection.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageText || string(message) != "device:ping" {
		t.Fatalf("websocket response = %d %q", messageType, message)
	}
}

func TestWebGatewayUsesServerContextForSubdomainIsolation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "device_session", Value: "ok", Path: "/", HttpOnly: true})
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{session: store.AccessSession{Mode: "web"}, route: store.EndpointRoute{Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1}},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
	authorizeGatewayRequest(request)
	request = WithSessionSubdomainAccess(request)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, WithSessionSubdomainAccess(request))
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Location"); got != "/next" {
		t.Fatalf("subdomain location = %q", got)
	}
	if cookie := response.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Path=/") || strings.Contains(cookie, "/access/web/") {
		t.Fatalf("subdomain cookie was incorrectly path-prefixed: %q", cookie)
	}
}

func TestWebGatewayRejectsDifferentSourceIP(t *testing.T) {
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{session: store.AccessSession{Mode: "web", SourceIP: "10.0.0.8"}, route: store.EndpointRoute{Protocol: "http", AccessType: "web_proxy"}},
		fakeRouteResolver{},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
	authorizeGatewayRequest(request)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, WithSessionSubdomainAccess(request))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestWebGatewayHTTPSAcceptsPrivateDeviceCertificates(t *testing.T) {
	var upstreamHost string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHost = r.Host
		_, _ = io.WriteString(w, "secure-device-ui")
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "https://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := testWebRoute(t)

	requestThroughGateway := func() *httptest.ResponseRecorder {
		gateway := NewWebGateway(
			fakeSessionResolver{
				session: store.AccessSession{Mode: "web"},
				route:   store.EndpointRoute{Protocol: "https", TargetPort: port, AccessType: "web_proxy", Host: host, TLSServerName: "device.internal.example", NodeID: "node-1", ClientID: 1},
			},
			fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
		)
		mux := http.NewServeMux()
		mux.Handle("/access/web/{token}/{path...}", gateway)
		request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
		authorizeGatewayRequest(request)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, WithSessionSubdomainAccess(request))
		return response
	}

	if response := requestThroughGateway(); response.Code != http.StatusOK || response.Body.String() != "secure-device-ui" {
		t.Fatalf("private device certificate failed: status = %d, body = %q", response.Code, response.Body.String())
	}
	if want := net.JoinHostPort("device.internal.example", portText); upstreamHost != want {
		t.Fatalf("TLS virtual host = %q, want %q", upstreamHost, want)
	}
}

func TestWebGatewayKeepsHTTPToHTTPSRedirectInsideSession(t *testing.T) {
	header := http.Header{"Location": []string{"https://10.10.0.25/console?view=main"}}
	rewriteLocation(header, "http", "10.10.0.25", 80)
	want := "/" + httpsUpgradePath + "/console?view=main"
	if got := header.Get("Location"); got != want {
		t.Fatalf("upgraded location = %q, want %q", got, want)
	}
	scheme, port, path := gatewayUpstream(store.EndpointRoute{Protocol: "http", TargetPort: 80}, httpsUpgradePath+"/console", false)
	if scheme != "https" || port != 443 || path != "/console" {
		t.Fatalf("upgraded route = %q %d %q", scheme, port, path)
	}
}

func TestWebGatewayKeepsTrustedHTTPSMarkerAfterRewritingDeviceCookies(t *testing.T) {
	header := http.Header{}
	header.Add("Set-Cookie", "device_session=ok; Path=/; HttpOnly")
	// A device must not be able to inject a platform-reserved routing marker.
	header.Add("Set-Cookie", upstreamSchemeCookie+"=http; Path=/")
	rewriteCookies(header)

	request := httptest.NewRequest(http.MethodGet, "https://access.example/"+httpsUpgradePath+"/", nil)
	appendTrustedUpstreamSchemeCookie(header, request, "http", "https")

	var deviceCookie, schemeCookie *http.Cookie
	for _, cookie := range (&http.Response{Header: header}).Cookies() {
		switch cookie.Name {
		case "device_session":
			deviceCookie = cookie
		case upstreamSchemeCookie:
			schemeCookie = cookie
		}
	}
	if deviceCookie == nil || deviceCookie.Path != "/" || !deviceCookie.HttpOnly {
		t.Fatalf("rewritten device cookie = %#v", deviceCookie)
	}
	if schemeCookie == nil || schemeCookie.Value != "https" || schemeCookie.Path != "/" || !schemeCookie.HttpOnly || !schemeCookie.Secure {
		t.Fatalf("trusted HTTPS marker = %#v", schemeCookie)
	}
}

func TestWebGatewayNormalizesBrokenHTTPSRedirectPort(t *testing.T) {
	header := http.Header{"Location": []string{"https://10.1.1.165:80/"}}
	rewriteLocation(header, "http", "10.1.1.165", 80)
	if got := header.Get("Location"); got != "/"+httpsUpgradePath+"/" {
		t.Fatalf("broken device redirect escaped session: %q", got)
	}
}

func TestWebGatewayContainsCrossOriginRedirectsInsideSession(t *testing.T) {
	header := http.Header{"Location": []string{"https://other-device.invalid/login?token=secret"}}
	rewriteLocation(header, "https", "10.1.1.165", 443)
	if got := header.Get("Location"); got != "/" {
		t.Fatalf("external redirect escaped session: got %q", got)
	}
}

func TestWebGatewayDoesNotExposeInternalNetworkErrors(t *testing.T) {
	token := testWebRoute(t)
	gateway := NewWebGateway(
		fakeSessionResolver{
			session: store.AccessSession{Mode: "web"},
			route:   store.EndpointRoute{Protocol: "http", TargetPort: 80, AccessType: "web_proxy", Host: "10.10.10.10", NodeID: "node-1", ClientID: 1},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: "127.0.0.1:1", Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
	authorizeGatewayRequest(request)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, WithSessionSubdomainAccess(request))
	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := strings.TrimSpace(response.Body.String()); got != "内网 Web 服务暂时无法访问" {
		t.Fatalf("gateway error leaked internal details: %q", got)
	}
}

func startForwardingSOCKS(t *testing.T, upstreamAddress, username, password string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveForwardingSOCKS(t, listener, upstreamAddress, username, password)
	return listener.Addr().String()
}

func serveForwardingSOCKS(t *testing.T, listener net.Listener, upstreamAddress, username, password string) {
	t.Helper()
	var connections sync.WaitGroup
	t.Cleanup(func() {
		_ = listener.Close()
		connections.Wait()
	})
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer client.Close()
				if !acceptSOCKSHandshake(client, username, password) {
					return
				}
				upstream, err := net.Dial("tcp", upstreamAddress)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
				copyDone := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, client); copyDone <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); copyDone <- struct{}{} }()
				<-copyDone
			}()
		}
	}()
}

func acceptSOCKSHandshake(conn net.Conn, username, password string) bool {
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil || greeting[0] != 0x05 {
		return false
	}
	_, _ = conn.Write([]byte{0x05, 0x02})
	authHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHeader); err != nil {
		return false
	}
	user := make([]byte, int(authHeader[1]))
	_, _ = io.ReadFull(conn, user)
	passwordLength := []byte{0}
	_, _ = io.ReadFull(conn, passwordLength)
	pass := make([]byte, int(passwordLength[0]))
	_, _ = io.ReadFull(conn, pass)
	if string(user) != username || string(pass) != password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return false
	}
	_, _ = conn.Write([]byte{0x01, 0x00})
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	addressLength := 0
	switch header[3] {
	case 0x01:
		addressLength = 4
	case 0x04:
		addressLength = 16
	case 0x03:
		length := []byte{0}
		_, _ = io.ReadFull(conn, length)
		addressLength = int(length[0])
	default:
		return false
	}
	addressAndPort := make([]byte, addressLength+2)
	if _, err := io.ReadFull(conn, addressAndPort); err != nil {
		return false
	}
	return binary.BigEndian.Uint16(addressAndPort[addressLength:]) > 0
}
