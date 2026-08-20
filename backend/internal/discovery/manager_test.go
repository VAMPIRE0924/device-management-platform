package discovery

import (
	"bufio"
	"context"
	"fmt"
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

type fakeDiscoveryStore struct {
	mu      sync.Mutex
	status  string
	results []store.DiscoveryProbeResult
	done    chan struct{}
}

func (f *fakeDiscoveryStore) SetDiscoveryJobState(_ context.Context, _ string, status string, _ int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
	if status == "completed" || status == "failed" || status == "canceled" {
		select {
		case <-f.done:
		default:
			close(f.done)
		}
	}
	return nil
}

func (f *fakeDiscoveryStore) SaveDiscoveryResult(_ context.Context, _ string, result store.DiscoveryProbeResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, result)
	return nil
}

type fakeDiscoveryNodes struct{ address string }

func (f fakeDiscoveryNodes) SetManagedTunnel(context.Context, string, int, bool) error { return nil }
func (f fakeDiscoveryNodes) SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error) {
	return nodeadapter.SOCKSRoute{Address: f.address}, nil
}

func TestManagerDiscoversHTTPOnConfiguredNonStandardPort(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "OpenWrt-test")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	upstreamAddress := strings.TrimPrefix(upstream.URL, "http://")
	socksAddress := startNoAuthSOCKS(t, upstreamAddress)
	_, portText, _ := net.SplitHostPort(upstreamAddress)
	port, _ := strconv.Atoi(portText)
	state := &fakeDiscoveryStore{done: make(chan struct{})}
	manager := NewManager(state, fakeDiscoveryNodes{address: socksAddress})
	manager.concurrency = 2
	manager.timeout = 2 * time.Second
	job := store.DiscoveryJob{ID: "job-1", Networks: []string{"127.0.0.1/32"}, Ports: []store.DiscoveryPort{{Port: port, Protocol: "http", Name: "OpenWrt LuCI"}}}
	if err := manager.Start(t.Context(), job, store.DiscoveryRoute{NodeID: "node-1", ClientID: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not finish")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.status != "completed" || len(state.results) != 1 {
		t.Fatalf("status/results = %q / %#v", state.status, state.results)
	}
	if state.results[0].Protocol != "http" || state.results[0].ServiceName != "OpenWrt LuCI" || state.results[0].Confidence < 90 {
		t.Fatalf("unexpected result: %#v", state.results[0])
	}
}

func TestCountHostsTreatsCIDRAsCompleteScanRange(t *testing.T) {
	count, err := countHosts([]string{"192.168.10.0/24", "10.0.0.1"})
	if err != nil || count != 257 {
		t.Fatalf("count = %d, err = %v", count, err)
	}
}

func TestForEachHostIncludesEveryAddressFromDotZeroThroughDot255(t *testing.T) {
	hosts := make([]string, 0, 256)
	if err := forEachHost("10.10.0.0/24", func(host string) bool {
		hosts = append(hosts, host)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 256 {
		t.Fatalf("full /24 range count = %d, want 256", len(hosts))
	}
	if hosts[0] != "10.10.0.0" || hosts[255] != "10.10.0.255" {
		t.Fatalf("full /24 boundaries = %q through %q", hosts[0], hosts[255])
	}
	for index, host := range hosts {
		want := fmt.Sprintf("10.10.0.%d", index)
		if host != want {
			t.Fatalf("host %d = %q, want %q", index, host, want)
		}
	}
}

func TestForEachHostAcceptsSingleIPv4Address(t *testing.T) {
	hosts := []string{}
	if err := forEachHost("10.10.0.1", func(host string) bool {
		hosts = append(hosts, host)
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "10.10.0.1" {
		t.Fatalf("single-IP scan = %#v", hosts)
	}
}

func TestProtocolProbesRequireApplicationEvidence(t *testing.T) {
	tests := []struct {
		name   string
		server func(net.Conn)
		probe  func(net.Conn) (protocolProbeResult, bool)
		want   bool
	}{
		{name: "rtsp", server: func(conn net.Conn) {
			reader := bufio.NewReader(conn)
			for {
				line, _ := reader.ReadString('\n')
				if line == "\r\n" || line == "" {
					break
				}
			}
			_, _ = io.WriteString(conn, "RTSP/1.0 401 Unauthorized\r\n\r\n")
		}, probe: func(conn net.Conn) (protocolProbeResult, bool) { return probeRTSP(conn, "10.0.0.8", 554) }, want: true},
		{name: "rdp", server: func(conn net.Conn) {
			request := make([]byte, 19)
			_, _ = io.ReadFull(conn, request)
			_, _ = conn.Write([]byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00})
		}, probe: probeRDP, want: true},
		{name: "mysql", server: func(conn net.Conn) { _, _ = conn.Write([]byte{0x20, 0x00, 0x00, 0x00, 0x0a}) }, probe: probeMySQL, want: true},
		{name: "postgresql", server: func(conn net.Conn) {
			request := make([]byte, 8)
			_, _ = io.ReadFull(conn, request)
			_, _ = conn.Write([]byte{'S'})
		}, probe: probePostgreSQL, want: true},
		{name: "tcp banner", server: func(conn net.Conn) { _, _ = io.WriteString(conn, "CUSTOM/1 ready\r\n") }, probe: probeTCPBanner, want: true},
		{name: "silent tcp", server: func(conn net.Conn) {}, probe: probeTCPBanner, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			go func() { defer server.Close(); test.server(server) }()
			_, ok := test.probe(client)
			if ok != test.want {
				t.Fatalf("probe evidence = %v, want %v", ok, test.want)
			}
		})
	}
}

func startNoAuthSOCKS(t *testing.T, upstreamAddress string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer client.Close()
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(client, greeting); err != nil {
					return
				}
				_, _ = client.Write([]byte{0x05, 0x00})
				header := make([]byte, 4)
				if _, err := io.ReadFull(client, header); err != nil {
					return
				}
				length := 0
				switch header[3] {
				case 0x01:
					length = 4
				case 0x04:
					length = 16
				case 0x03:
					buffer := []byte{0}
					_, _ = io.ReadFull(client, buffer)
					length = int(buffer[0])
				default:
					return
				}
				_, _ = io.ReadFull(client, make([]byte, length+2))
				upstream, err := net.Dial("tcp", upstreamAddress)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80})
				done := make(chan struct{}, 2)
				go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
				go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return listener.Addr().String()
}
