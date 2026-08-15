package access

import (
	"context"
	"encoding/binary"
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
	token := strings.Repeat("a", 43)
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
	mux.ServeHTTP(response, request)
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
	wantLocation := "/access/web/" + token + "/next?from=device"
	if got := response.Header().Get("Location"); got != wantLocation {
		t.Fatalf("location = %q, want %q", got, wantLocation)
	}
	if cookie := response.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Path=/access/web/"+token+"/") || !strings.Contains(cookie, "HttpOnly") {
		t.Fatalf("cookie was not scoped to session: %q", cookie)
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
	token := strings.Repeat("s", 43)
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
	mux.ServeHTTP(response, request)
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

func TestWebGatewayRewritesRootPathsInTextResponses(t *testing.T) {
	var upstreamAcceptEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAcceptEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"upstream-etag"`)
		_, _ = io.WriteString(w, `<link href="/luci-static/app.css"><script>const api="\/ubus\/";const cdn="//cdn.example/app.js"</script><div style="background:url(/image.png)"></div>`)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := strings.Repeat("e", 43)
	prefix := "/access/web/" + token
	gateway := NewWebGateway(
		fakeSessionResolver{session: store.AccessSession{Mode: "web"}, route: store.EndpointRoute{Protocol: "http", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1}},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, prefix+"/cgi-bin/luci/", nil)
	authorizeGatewayRequest(request)
	request.Header.Set("Accept-Encoding", "gzip, br")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(upstreamAcceptEncoding, "br") {
		t.Fatalf("browser Accept-Encoding reached upstream in path-prefix mode: %q", upstreamAcceptEncoding)
	}
	body := response.Body.String()
	for _, expected := range []string{
		`href="` + prefix + `/luci-static/app.css"`,
		`"` + prefix + `\/ubus\/"`,
		`url(` + prefix + `/image.png)`,
		`"//cdn.example/app.js"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("rewritten body missing %q: %s", expected, body)
		}
	}
	if response.Header().Get("ETag") != "" {
		t.Fatalf("upstream ETag survived rewritten body")
	}
	if got := response.Header().Get("Content-Length"); got != strconv.Itoa(response.Body.Len()) {
		t.Fatalf("Content-Length = %q, body length = %d", got, response.Body.Len())
	}
}

func TestWebGatewayOnlyRewritesURLLikeJavaScriptStrings(t *testing.T) {
	script := `const slash="/"; const sentinel="/$"; const cidr=value.match(/^(.+)\/(\d+)$/); const quote=value.replace(/'/g,'"'); const login="/login.html";`
	response := &http.Response{Header: http.Header{"Content-Type": []string{"text/javascript; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(script)), ContentLength: int64(len(script))}
	if err := rewriteTextResponse(response, "/access/web/session-token"); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := `const slash="/"; const sentinel="/$"; const cidr=value.match(/^(.+)\/(\d+)$/); const quote=value.replace(/'/g,'"'); const login="/access/web/session-token/login.html";`
	if string(body) != want {
		t.Fatalf("JavaScript response = %s, want %s", body, want)
	}
}

func TestWebGatewayRejectsDifferentSourceIP(t *testing.T) {
	token := strings.Repeat("b", 43)
	gateway := NewWebGateway(
		fakeSessionResolver{session: store.AccessSession{Mode: "web", SourceIP: "10.0.0.8"}, route: store.EndpointRoute{Protocol: "http", AccessType: "web_proxy"}},
		fakeRouteResolver{},
	)
	mux := http.NewServeMux()
	mux.Handle("/access/web/{token}/{path...}", gateway)
	request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
	authorizeGatewayRequest(request)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestWebGatewayHTTPSAcceptsPrivateDeviceCertificates(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure-device-ui")
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "https://")
	socksAddress := startForwardingSOCKS(t, upstreamAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	token := strings.Repeat("c", 43)

	requestThroughGateway := func() *httptest.ResponseRecorder {
		gateway := NewWebGateway(
			fakeSessionResolver{
				session: store.AccessSession{Mode: "web"},
				route:   store.EndpointRoute{Protocol: "https", TargetPort: port, AccessType: "web_proxy", Host: host, NodeID: "node-1", ClientID: 1},
			},
			fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
		)
		mux := http.NewServeMux()
		mux.Handle("/access/web/{token}/{path...}", gateway)
		request := httptest.NewRequest(http.MethodGet, "/access/web/"+token+"/", nil)
		authorizeGatewayRequest(request)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		return response
	}

	if response := requestThroughGateway(); response.Code != http.StatusOK || response.Body.String() != "secure-device-ui" {
		t.Fatalf("private device certificate failed: status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestWebGatewayKeepsHTTPToHTTPSRedirectInsideSession(t *testing.T) {
	token := strings.Repeat("u", 43)
	basePrefix := "/access/web/" + token
	header := http.Header{"Location": []string{"https://10.10.0.25/console?view=main"}}
	rewriteLocation(header, "http", "10.10.0.25", 80, basePrefix, basePrefix)
	want := basePrefix + "/" + httpsUpgradePath + "/console?view=main"
	if got := header.Get("Location"); got != want {
		t.Fatalf("upgraded location = %q, want %q", got, want)
	}
	scheme, port, path, responsePrefix := gatewayUpstream(store.EndpointRoute{Protocol: "http", TargetPort: 80}, httpsUpgradePath+"/console", basePrefix, false)
	if scheme != "https" || port != 443 || path != "/console" || responsePrefix != basePrefix+"/"+httpsUpgradePath {
		t.Fatalf("upgraded route = %q %d %q %q", scheme, port, path, responsePrefix)
	}
}

func TestWebGatewayNormalizesBrokenHTTPSRedirectPort(t *testing.T) {
	basePrefix := "/access/web/session"
	header := http.Header{"Location": []string{"https://10.1.1.165:80/"}}
	rewriteLocation(header, "http", "10.1.1.165", 80, basePrefix, basePrefix)
	if got := header.Get("Location"); got != basePrefix+"/"+httpsUpgradePath+"/" {
		t.Fatalf("broken device redirect escaped session: %q", got)
	}
}

func TestWebGatewayContainsCrossOriginRedirectsInsideSession(t *testing.T) {
	for _, prefix := range []string{"", "/access/web/session"} {
		header := http.Header{"Location": []string{"https://other-device.invalid/login?token=secret"}}
		rewriteLocation(header, "https", "10.1.1.165", 443, prefix, prefix)
		if got, want := header.Get("Location"), accessSessionRoot(prefix); got != want {
			t.Fatalf("external redirect escaped session: got %q, want %q", got, want)
		}
	}
}

func TestWebGatewayDoesNotExposeInternalNetworkErrors(t *testing.T) {
	token := strings.Repeat("n", 43)
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
	mux.ServeHTTP(response, request)
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
	return listener.Addr().String()
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
