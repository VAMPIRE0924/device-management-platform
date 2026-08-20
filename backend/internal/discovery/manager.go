package discovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/access"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

type storage interface {
	SetDiscoveryJobState(context.Context, string, string, int) error
	SaveDiscoveryResult(context.Context, string, store.DiscoveryProbeResult) error
}

type nodeRoutes interface {
	SetManagedTunnel(context.Context, string, int, bool) error
	SOCKSRoute(context.Context, string, int) (nodeadapter.SOCKSRoute, error)
}

type Manager struct {
	store       storage
	nodes       nodeRoutes
	concurrency int
	timeout     time.Duration
	mu          sync.Mutex
	cancels     map[string]context.CancelFunc
}

func NewManager(store storage, nodes nodeRoutes) *Manager {
	return &Manager{store: store, nodes: nodes, concurrency: 32, timeout: 1200 * time.Millisecond, cancels: map[string]context.CancelFunc{}}
}

func (m *Manager) Start(parent context.Context, job store.DiscoveryJob, route store.DiscoveryRoute) error {
	if route.ClientID < 1 {
		return errors.New("project has no bound client")
	}
	totalHosts, err := countHosts(job.Networks)
	if err != nil {
		return err
	}
	if totalHosts == 0 || len(job.Ports) == 0 {
		return errors.New("discovery scope has no probes")
	}
	if totalHosts*len(job.Ports) > 2_000_000 {
		return fmt.Errorf("discovery request exceeds 2000000 probes")
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(parent))
	m.mu.Lock()
	if _, exists := m.cancels[job.ID]; exists {
		m.mu.Unlock()
		cancel()
		return errors.New("discovery job is already running")
	}
	m.cancels[job.ID] = cancel
	m.mu.Unlock()
	go m.run(ctx, job, route, totalHosts*len(job.Ports))
	return nil
}

func (m *Manager) Cancel(jobID string) bool {
	m.mu.Lock()
	cancel, exists := m.cancels[jobID]
	m.mu.Unlock()
	if exists {
		cancel()
	}
	return exists
}

// Verify probes only the explicitly registered services of one device. It is
// intentionally separate from Start: no CIDR is enumerated and no additional
// ports are inferred, so a user pressing "检测" cannot expand the discovery
// boundary by accident.
func (m *Manager) Verify(ctx context.Context, route store.DiscoveryRoute, host string, ports []store.DiscoveryPort) ([]store.DiscoveryProbeResult, error) {
	if route.ClientID < 1 {
		return nil, errors.New("project has no bound client")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return nil, errors.New("device host is not a valid IP address")
	}
	if len(ports) == 0 || len(ports) > 256 {
		return nil, errors.New("device verification requires 1-256 registered services")
	}
	if err := m.nodes.SetManagedTunnel(ctx, route.NodeID, route.ClientID, true); err != nil {
		return nil, fmt.Errorf("start managed tunnel: %w", err)
	}
	socksRoute, err := m.nodes.SOCKSRoute(ctx, route.NodeID, route.ClientID)
	if err != nil {
		return nil, fmt.Errorf("resolve managed tunnel route: %w", err)
	}
	type result struct {
		probe *store.DiscoveryProbeResult
	}
	results := make(chan result, len(ports))
	limit := make(chan struct{}, m.concurrency)
	var workers sync.WaitGroup
	for _, port := range ports {
		port := port
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case limit <- struct{}{}:
				defer func() { <-limit }()
			case <-ctx.Done():
				return
			}
			probeResult := m.probe(ctx, socksRoute, probe{host: host, port: port})
			select {
			case results <- result{probe: probeResult}:
			case <-ctx.Done():
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
	verified := make([]store.DiscoveryProbeResult, 0, len(ports))
	for item := range results {
		if item.probe != nil {
			verified = append(verified, *item.probe)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return verified, nil
}

func (m *Manager) run(ctx context.Context, job store.DiscoveryJob, route store.DiscoveryRoute, total int) {
	defer func() {
		m.mu.Lock()
		delete(m.cancels, job.ID)
		m.mu.Unlock()
	}()
	if err := m.store.SetDiscoveryJobState(ctx, job.ID, "running", 0); err != nil {
		return
	}
	if err := m.nodes.SetManagedTunnel(ctx, route.NodeID, route.ClientID, true); err != nil {
		_ = m.store.SetDiscoveryJobState(context.WithoutCancel(ctx), job.ID, "failed", 0)
		return
	}
	socksRoute, err := m.nodes.SOCKSRoute(ctx, route.NodeID, route.ClientID)
	if err != nil {
		_ = m.store.SetDiscoveryJobState(context.WithoutCancel(ctx), job.ID, "failed", 0)
		return
	}
	tasks := make(chan probe)
	results := make(chan *store.DiscoveryProbeResult, m.concurrency)
	var workers sync.WaitGroup
	for index := 0; index < m.concurrency; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range tasks {
				result := m.probe(ctx, socksRoute, task)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(tasks)
		for _, cidr := range job.Networks {
			_ = forEachHost(cidr, func(host string) bool {
				for _, port := range job.Ports {
					select {
					case tasks <- probe{host: host, port: port}:
					case <-ctx.Done():
						return false
					}
				}
				return true
			})
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()
	completed := 0
	lastProgress := -1
	for result := range results {
		completed++
		if result != nil {
			_ = m.store.SaveDiscoveryResult(context.WithoutCancel(ctx), job.ID, *result)
		}
		progress := completed * 100 / total
		if progress != lastProgress {
			lastProgress = progress
			_ = m.store.SetDiscoveryJobState(context.WithoutCancel(ctx), job.ID, "running", progress)
		}
	}
	if ctx.Err() != nil {
		_ = m.store.SetDiscoveryJobState(context.Background(), job.ID, "canceled", completed*100/total)
		return
	}
	_ = m.store.SetDiscoveryJobState(context.Background(), job.ID, "completed", 100)
}

type probe struct {
	host string
	port store.DiscoveryPort
}

func (m *Manager) probe(ctx context.Context, route nodeadapter.SOCKSRoute, task probe) *store.DiscoveryProbeResult {
	probeCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	dialer := access.SOCKSDialer{ProxyAddress: route.Address, Username: route.Username, Password: route.Password, Timeout: m.timeout}
	address := net.JoinHostPort(task.host, strconv.Itoa(task.port.Port))
	conn, err := dialer.DialContext(probeCtx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(m.timeout))
	protocol := normalizedProtocol(task.port)
	name := strings.TrimSpace(task.port.Name)
	fingerprint := ""
	summary := ""
	confidence := 0
	if protocol == "ssh" {
		banner, _ := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
		banner = sanitizeBanner(banner)
		if !strings.HasPrefix(banner, "SSH-") {
			return nil
		}
		fingerprint, summary, confidence = banner, banner, 98
		if name == "" {
			name = "SSH"
		}
	} else if protocol == "http" || protocol == "https" {
		result, ok := probeHTTP(conn, task.host, protocol == "https", m.timeout)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
		if name == "" {
			name = result.name
		}
	} else if protocol == "rtsp" {
		result, ok := probeRTSP(conn, task.host, task.port.Port)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
	} else if protocol == "rdp" {
		result, ok := probeRDP(conn)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
	} else if protocol == "mysql" {
		result, ok := probeMySQL(conn)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
	} else if protocol == "postgresql" {
		result, ok := probePostgreSQL(conn)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
	} else if protocol == "tcp" {
		result, ok := probeTCPBanner(conn)
		if !ok {
			return nil
		}
		fingerprint, summary, confidence = result.fingerprint, result.summary, result.confidence
	} else if protocol == "auto" {
		if isTLSPort(task.port.Port) {
			if result, ok := probeHTTP(conn, task.host, true, m.timeout); ok {
				protocol, fingerprint, summary, confidence = "https", result.fingerprint, result.summary, result.confidence
				if name == "" {
					name = result.name
				}
			} else {
				return nil
			}
		} else if result, ok := probeHTTP(conn, task.host, false, m.timeout); ok {
			protocol, fingerprint, summary, confidence = "http", result.fingerprint, result.summary, result.confidence
			if name == "" {
				name = result.name
			}
		} else {
			return nil
		}
	}
	if name == "" {
		name = defaultServiceName(protocol, task.port.Port)
	}
	return &store.DiscoveryProbeResult{Host: task.host, Port: task.port.Port, Protocol: protocol, ServiceName: name, Fingerprint: fingerprint, ResponseSummary: summary, Confidence: confidence}
}

type httpProbeResult struct {
	name        string
	fingerprint string
	summary     string
	confidence  int
}

type protocolProbeResult struct {
	fingerprint string
	summary     string
	confidence  int
}

func probeRTSP(conn net.Conn, host string, port int) (protocolProbeResult, bool) {
	request := fmt.Sprintf("OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: 设备管理平台-Discovery/1\r\n\r\n", net.JoinHostPort(host, strconv.Itoa(port)))
	if _, err := io.WriteString(conn, request); err != nil {
		return protocolProbeResult{}, false
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 2048)).ReadString('\n')
	line = sanitizeBanner(line)
	if (err != nil && line == "") || !strings.HasPrefix(line, "RTSP/") {
		return protocolProbeResult{}, false
	}
	return protocolProbeResult{fingerprint: line, summary: line, confidence: 96}, true
}

func probeRDP(conn net.Conn) (protocolProbeResult, bool) {
	// TPKT + X.224 Connection Request with an RDP negotiation request.
	request := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
	if _, err := conn.Write(request); err != nil {
		return protocolProbeResult{}, false
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 0x03 || header[1] != 0x00 {
		return protocolProbeResult{}, false
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 7 || length > 4096 {
		return protocolProbeResult{}, false
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil || len(payload) < 3 || payload[1] != 0xd0 {
		return protocolProbeResult{}, false
	}
	return protocolProbeResult{fingerprint: "RDP X.224", summary: "RDP negotiation response", confidence: 97}, true
}

func probeMySQL(conn net.Conn) (protocolProbeResult, bool) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return protocolProbeResult{}, false
	}
	payloadLength := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if payloadLength < 1 || payloadLength > 1<<20 || header[3] != 0 || (header[4] != 0x09 && header[4] != 0x0a) {
		return protocolProbeResult{}, false
	}
	version := "10"
	if header[4] == 0x09 {
		version = "9"
	}
	return protocolProbeResult{fingerprint: "MySQL protocol " + version, summary: "MySQL server handshake", confidence: 98}, true
}

func probePostgreSQL(conn net.Conn) (protocolProbeResult, bool) {
	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request[0:4], 8)
	binary.BigEndian.PutUint32(request[4:8], 80877103) // SSLRequest
	if _, err := conn.Write(request); err != nil {
		return protocolProbeResult{}, false
	}
	response := []byte{0}
	if _, err := io.ReadFull(conn, response); err != nil || (response[0] != 'S' && response[0] != 'N') {
		return protocolProbeResult{}, false
	}
	summary := "PostgreSQL SSL supported"
	if response[0] == 'N' {
		summary = "PostgreSQL SSL not supported"
	}
	return protocolProbeResult{fingerprint: "PostgreSQL", summary: summary, confidence: 98}, true
}

func probeTCPBanner(conn net.Conn) (protocolProbeResult, bool) {
	buffer := make([]byte, 512)
	count, err := conn.Read(buffer)
	if err != nil && count == 0 {
		return protocolProbeResult{}, false
	}
	banner := sanitizeBanner(string(buffer[:count]))
	if banner == "" {
		return protocolProbeResult{}, false
	}
	return protocolProbeResult{fingerprint: banner, summary: "TCP banner: " + banner, confidence: 80}, true
}

func probeHTTP(raw net.Conn, host string, secure bool, timeout time.Duration) (httpProbeResult, bool) {
	conn := raw
	if secure {
		tlsConn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true}) // Discovery verifies protocol response only; trust remains unverified.
		if err := tlsConn.Handshake(); err != nil {
			return httpProbeResult{}, false
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	request := "HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: 设备管理平台-Discovery/1\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return httpProbeResult{}, false
	}
	response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(conn, 16<<10)), &http.Request{Method: http.MethodHead})
	if err != nil {
		return httpProbeResult{}, false
	}
	defer response.Body.Close()
	server := sanitizeBanner(response.Header.Get("Server"))
	name := "Web 管理"
	fingerprint := strings.TrimSpace(strings.Join([]string{response.Proto, strconv.Itoa(response.StatusCode), server}, " "))
	return httpProbeResult{name: name, fingerprint: fingerprint, summary: response.Status, confidence: 95}, true
}

func normalizedProtocol(port store.DiscoveryPort) string {
	protocol := strings.ToLower(strings.TrimSpace(port.Protocol))
	if protocol != "" && protocol != "auto" {
		return protocol
	}
	switch port.Port {
	case 22, 2222, 22022:
		return "ssh"
	case 443, 8443, 9443:
		return "https"
	case 80, 81, 3000, 3001, 8000, 8080, 8081, 8888, 9000:
		return "http"
	default:
		return "auto"
	}
}

func isTLSPort(port int) bool {
	return port == 443 || port == 8443 || port == 9443
}

func defaultServiceName(protocol string, port int) string {
	return strings.ToUpper(protocol) + " " + strconv.Itoa(port)
}

func sanitizeBanner(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		value = value[:240]
	}
	return value
}

func countHosts(cidrs []string) (int, error) {
	total := 0
	for _, cidr := range cidrs {
		prefix, err := parseDiscoveryPrefix(cidr)
		if err != nil {
			return 0, fmt.Errorf("invalid IPv4 discovery network %q", cidr)
		}
		bits := 32 - prefix.Bits()
		count := 1 << bits
		total += count
	}
	return total, nil
}

func forEachHost(cidr string, fn func(string) bool) error {
	prefix, err := parseDiscoveryPrefix(cidr)
	if err != nil {
		return err
	}
	prefix = prefix.Masked()
	address := prefix.Addr()
	remaining, _ := countHosts([]string{cidr})
	for index := 0; index < remaining; index++ {
		if !fn(address.String()) {
			return nil
		}
		address = address.Next()
	}
	return nil
}

func parseDiscoveryPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil && address.Is4() {
		return netip.PrefixFrom(address, 32), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 discovery network")
	}
	return prefix.Masked(), nil
}
