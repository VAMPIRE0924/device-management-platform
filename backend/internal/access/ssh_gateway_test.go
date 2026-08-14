package access

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"golang.org/x/crypto/ssh"

	"i5cloud/internal/nodeadapter"
	"i5cloud/internal/store"
)

func TestWebSSHGatewayConnectsThroughSOCKS(t *testing.T) {
	sshAddress, fingerprint := startTestSSHServer(t, "root", "secret")
	socksAddress := startForwardingSOCKS(t, sshAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(sshAddress)
	port, _ := strconv.Atoi(portText)
	token := strings.Repeat("s", 43)
	gateway := NewSSHGateway(
		fakeSessionResolver{
			session: store.AccessSession{ID: "session-password", Mode: "ssh", ExpiresAt: time.Now().Add(time.Minute)},
			route:   store.EndpointRoute{Protocol: "ssh", AccessType: "web_ssh", Host: host, TargetPort: port, NodeID: "node-1", ClientID: 1, SSHHostKeyFingerprint: fingerprint},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
		nil,
	)
	mux := http.NewServeMux()
	mux.Handle("GET /access/ssh/{token}/ws", gateway)
	server := httptest.NewServer(mux)
	defer server.Close()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/access/ssh/" + token + "/ws"
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := wsjson.Write(ctx, conn, sshAuthMessage{Type: "auth", Method: "password", Username: "root", Password: "secret", Columns: 100, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	ready := false
	for !ready {
		var message sshServerMessage
		if err := wsjson.Read(ctx, conn, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "error" {
			t.Fatalf("SSH gateway error: %#v", message)
		}
		ready = message.Type == "ready"
	}
	if err := wsjson.Write(ctx, conn, sshClientMessage{Type: "input", Data: "hello\n"}); err != nil {
		t.Fatal(err)
	}
	for {
		var message sshServerMessage
		if err := wsjson.Read(ctx, conn, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "output" && strings.Contains(message.Data, "received:hello") {
			break
		}
	}
}

func TestWebSSHGatewayRevocationTerminatesActiveConnection(t *testing.T) {
	sshAddress, fingerprint := startTestSSHServer(t, "root", "secret")
	socksAddress := startForwardingSOCKS(t, sshAddress, "proxy-user", "proxy-pass")
	host, portText, _ := net.SplitHostPort(sshAddress)
	port, _ := strconv.Atoi(portText)
	token := strings.Repeat("r", 43)
	gateway := NewSSHGateway(
		fakeSessionResolver{
			session: store.AccessSession{ID: "revoked-session", Mode: "ssh", ExpiresAt: time.Now().Add(time.Minute)},
			route:   store.EndpointRoute{Protocol: "ssh", AccessType: "web_ssh", Host: host, TargetPort: port, NodeID: "node-1", ClientID: 1, SSHHostKeyFingerprint: fingerprint},
		},
		fakeRouteResolver{route: nodeadapter.SOCKSRoute{Address: socksAddress, Username: "proxy-user", Password: "proxy-pass"}},
		nil,
	)
	mux := http.NewServeMux()
	mux.Handle("GET /access/ssh/{token}/ws", gateway)
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/access/ssh/"+token+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	if err := wsjson.Write(ctx, conn, sshAuthMessage{Type: "auth", Method: "password", Username: "root", Password: "secret", Columns: 100, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	for {
		var message sshServerMessage
		if err := wsjson.Read(ctx, conn, &message); err != nil {
			t.Fatal(err)
		}
		if message.Type == "ready" {
			break
		}
	}
	if !gateway.Revoke("revoked-session") {
		t.Fatal("active WebSSH connection was not registered")
	}
	readCtx, readCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer readCancel()
	var message sshServerMessage
	if err := wsjson.Read(readCtx, conn, &message); err == nil {
		t.Fatalf("revoked WebSSH connection remained readable: %#v", message)
	}
}

func TestSSHClientConfigAllowsUnknownHostKeyWhenFingerprintIsEmpty(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	observed := ""
	config, err := sshClientConfig(storedSSHCredential{Username: "root", Password: "secret"}, store.EndpointRoute{}, &observed)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.HostKeyCallback("target", nil, key); err != nil || observed == "" {
		t.Fatalf("unknown host key was not accepted, observed = %q, error = %v", observed, err)
	}
}

func TestTerminalPageUsesEphemeralPasswordAuthentication(t *testing.T) {
	for _, fragment := range []string{`SSH 用户名`, `SSH 密码`, `autocomplete="off"`, `data-auto-connect="false"`, `aria-label="SSH 终端"`, `src="/assets/webssh.js"`} {
		if !strings.Contains(terminalPage, fragment) {
			t.Fatalf("terminal page is missing ephemeral password authentication fragment %q", fragment)
		}
	}
	for _, forbidden := range []string{`用户名和密码仅用于本次连接`, `id="privateKey"`, `id="passphrase"`, `value="stored"`, `__HAS_STORED_CREDENTIAL__`, `cleanTerminalOutput`, `textContent+=`} {
		if strings.Contains(terminalPage, forbidden) {
			t.Fatalf("terminal page still exposes removed credential option %q", forbidden)
		}
	}
}

func startTestSSHServer(t *testing.T, username, password string) (string, string) {
	t.Helper()
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if metadata.User() == username && string(pass) == password {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
	}}
	return startTestSSHServerWithConfig(t, config)
}

func startTestSSHServerWithPublicKey(t *testing.T, username string, authorizedKey ssh.PublicKey) (string, string) {
	t.Helper()
	config := &ssh.ServerConfig{PublicKeyCallback: func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if metadata.User() == username && bytes.Equal(key.Marshal(), authorizedKey.Marshal()) {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
	}}
	return startTestSSHServerWithConfig(t, config)
}

func startTestSSHServerWithConfig(t *testing.T, config *ssh.ServerConfig) (string, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			networkConn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer networkConn.Close()
				serverConn, channels, requests, err := ssh.NewServerConn(networkConn, config)
				if err != nil {
					return
				}
				defer serverConn.Close()
				go ssh.DiscardRequests(requests)
				for channelRequest := range channels {
					if channelRequest.ChannelType() != "session" {
						_ = channelRequest.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, channelRequests, err := channelRequest.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for request := range channelRequests {
							switch request.Type {
							case "pty-req", "window-change":
								_ = request.Reply(true, nil)
							case "shell":
								_ = request.Reply(true, nil)
								buffer := make([]byte, 256)
								count, _ := channel.Read(buffer)
								_, _ = channel.Write([]byte("received:" + strings.TrimSpace(string(buffer[:count])) + "\r\n"))
								return
							default:
								_ = request.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}
