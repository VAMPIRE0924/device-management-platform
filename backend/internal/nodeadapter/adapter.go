package nodeadapter

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

// ManagedSOCKSIdleTTL is the inactivity limit enforced by the managed NPS
// SOCKS implementation. Platform Web and SSH access sessions must never remain
// active beyond this limit without real proxied traffic.
const ManagedSOCKSIdleTTL = 30 * time.Minute

var ErrDuplicateVerifyKey = errors.New("client verify key already exists")

type nodeSource interface {
	GetNodeConnection(context.Context, string) (store.NodeConnection, error)
	UpdateNodeHealth(context.Context, string, string, time.Time) error
}

type secretResolver interface {
	Resolve(context.Context, string) (string, error)
}

type Adapter struct {
	nodes     nodeSource
	secrets   secretResolver
	timeout   time.Duration
	stateWait time.Duration
	newClient func(store.NodeConnection) (*http.Client, error)
}

type Credential struct {
	Type     string `json:"type"`
	AuthKey  string `json:"authKey,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type Client struct {
	ID         int    `json:"id"`
	Remark     string `json:"remark"`
	Address    string `json:"address"`
	Enabled    bool   `json:"enabled"`
	Connected  bool   `json:"connected"`
	Version    string `json:"version"`
	InletFlow  int64  `json:"inletFlow"`
	ExportFlow int64  `json:"exportFlow"`
}

type ClientCredentials struct {
	BasicUsername string `json:"basicUsername"`
	BasicPassword string `json:"basicPassword"`
	VerifyKey     string `json:"verifyKey"`
}

type ManagedTunnel struct {
	ID         int    `json:"id"`
	ClientID   int    `json:"clientId"`
	ClientName string `json:"clientName"`
	Port       int    `json:"port"`
	Configured bool   `json:"configured"`
	Running    bool   `json:"running"`
	InletFlow  int64  `json:"inletFlow"`
	ExportFlow int64  `json:"exportFlow"`
}

type PortForward struct {
	ID         int    `json:"id"`
	ClientID   int    `json:"clientId"`
	ClientName string `json:"clientName"`
	Port       int    `json:"port"`
	Target     string `json:"target"`
	Remark     string `json:"remark"`
	Configured bool   `json:"configured"`
	Running    bool   `json:"running"`
	InletFlow  int64  `json:"inletFlow"`
	ExportFlow int64  `json:"exportFlow"`
}

type Health struct {
	Reachable bool      `json:"reachable"`
	CheckedAt time.Time `json:"checkedAt"`
	LatencyMS int64     `json:"latencyMs"`
	Message   string    `json:"message"`
}

// SOCKSRoute is the internal connection material used by the platform gateway.
// It must never be serialized by a public API handler.
type SOCKSRoute struct {
	Address  string
	Username string
	Password string
}

type tableResponse[T any] struct {
	Rows  []T `json:"rows"`
	Total int `json:"total"`
}

type rawFlow struct {
	InletFlow  int64
	ExportFlow int64
}

type rawClient struct {
	ID        int        `json:"Id"`
	Remark    string     `json:"Remark"`
	Addr      string     `json:"Addr"`
	Status    bool       `json:"Status"`
	IsConnect bool       `json:"IsConnect"`
	Version   string     `json:"Version"`
	Flow      *rawFlow   `json:"Flow"`
	Config    *rawConfig `json:"Cnf"`
	VerifyKey string     `json:"VerifyKey"`
}

type rawConfig struct {
	Username string `json:"U"`
	Password string `json:"P"`
}

type rawTunnel struct {
	ID         int        `json:"Id"`
	Port       int        `json:"Port"`
	Status     bool       `json:"Status"`
	RunStatus  bool       `json:"RunStatus"`
	Client     *rawClient `json:"Client"`
	Flow       *rawFlow   `json:"Flow"`
	Target     *rawTarget `json:"Target"`
	TargetAddr string     `json:"TargetAddr"`
	Remark     string     `json:"Remark"`
}

type rawTarget struct {
	Target string `json:"TargetStr"`
}

type actionResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

type clientResponse struct {
	Code int       `json:"code"`
	Data rawClient `json:"data"`
}

func New(nodes nodeSource, secrets secretResolver) *Adapter {
	a := &Adapter{nodes: nodes, secrets: secrets, timeout: 12 * time.Second, stateWait: 5 * time.Second}
	a.newClient = a.defaultHTTPClient
	return a
}

func (a *Adapter) Health(ctx context.Context, nodeID string) Health {
	started := time.Now()
	_, err := a.ListClients(ctx, nodeID)
	checked := time.Now().UTC()
	result := Health{Reachable: err == nil, CheckedAt: checked, LatencyMS: time.Since(started).Milliseconds(), Message: "ok"}
	status := "healthy"
	if err != nil {
		result.Message = err.Error()
		status = "unreachable"
	}
	_ = a.nodes.UpdateNodeHealth(context.WithoutCancel(ctx), nodeID, status, checked)
	return result
}

func (a *Adapter) ListClients(ctx context.Context, nodeID string) ([]Client, error) {
	var response tableResponse[rawClient]
	if err := a.call(ctx, nodeID, "/client/list", url.Values{"offset": {"0"}, "limit": {"10000"}}, &response); err != nil {
		return nil, err
	}
	clients := make([]Client, 0, len(response.Rows))
	for _, raw := range response.Rows {
		client := Client{ID: raw.ID, Remark: raw.Remark, Address: raw.Addr, Enabled: raw.Status, Connected: raw.IsConnect, Version: raw.Version}
		if raw.Flow != nil {
			client.InletFlow = raw.Flow.InletFlow
			client.ExportFlow = raw.Flow.ExportFlow
		}
		clients = append(clients, client)
	}
	return clients, nil
}

func (a *Adapter) ClientCredentials(ctx context.Context, nodeID string, clientID int) (ClientCredentials, error) {
	if clientID < 1 {
		return ClientCredentials{}, fmt.Errorf("client id must be positive")
	}
	var response clientResponse
	if err := a.call(ctx, nodeID, "/client/getclient", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return ClientCredentials{}, err
	}
	if response.Code != 1 || response.Data.ID != clientID {
		return ClientCredentials{}, fmt.Errorf("client %d was not found on node", clientID)
	}
	credentials := ClientCredentials{VerifyKey: response.Data.VerifyKey}
	if response.Data.Config != nil {
		credentials.BasicUsername = response.Data.Config.Username
		credentials.BasicPassword = response.Data.Config.Password
	}
	return credentials, nil
}

func (a *Adapter) CreateClient(ctx context.Context, nodeID, remark, verifyKey, socksUsername, socksPassword string) (Client, error) {
	if strings.TrimSpace(remark) == "" || strings.TrimSpace(verifyKey) == "" || socksUsername == "" || socksPassword == "" {
		return Client{}, fmt.Errorf("client remark and generated credentials are required")
	}
	var existing tableResponse[rawClient]
	if err := a.call(ctx, nodeID, "/client/list", url.Values{"offset": {"0"}, "limit": {"10000"}}, &existing); err != nil {
		return Client{}, err
	}
	for _, raw := range existing.Rows {
		if raw.VerifyKey == verifyKey {
			return Client{}, ErrDuplicateVerifyKey
		}
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/client/add", url.Values{
		"remark": {remark}, "vkey": {verifyKey}, "u": {socksUsername}, "p": {socksPassword},
		"compress": {"false"}, "crypt": {"true"}, "config_conn_allow": {"false"},
	}, &response); err != nil {
		return Client{}, err
	}
	if response.Status != 1 {
		return Client{}, fmt.Errorf("node rejected client creation: %s", response.Msg)
	}
	var listing tableResponse[rawClient]
	if err := a.call(ctx, nodeID, "/client/list", url.Values{"offset": {"0"}, "limit": {"10000"}}, &listing); err != nil {
		return Client{}, err
	}
	for _, raw := range listing.Rows {
		if raw.VerifyKey == verifyKey {
			return Client{ID: raw.ID, Remark: raw.Remark, Address: raw.Addr, Enabled: raw.Status, Connected: raw.IsConnect, Version: raw.Version}, nil
		}
	}
	return Client{}, fmt.Errorf("node accepted client but it was not returned by verification query")
}

func (a *Adapter) DeleteClient(ctx context.Context, nodeID string, clientID int) error {
	if clientID < 1 {
		return fmt.Errorf("client id must be positive")
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/client/del", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return fmt.Errorf("node rejected client deletion: %s", response.Msg)
	}
	return nil
}

func (a *Adapter) ListManagedTunnels(ctx context.Context, nodeID string) ([]ManagedTunnel, error) {
	var response tableResponse[rawTunnel]
	if err := a.call(ctx, nodeID, "/index/gettunnel", url.Values{"offset": {"0"}, "limit": {"10000"}, "type": {"socks5"}}, &response); err != nil {
		return nil, err
	}
	tunnels := make([]ManagedTunnel, 0, len(response.Rows))
	for _, raw := range response.Rows {
		tunnel := ManagedTunnel{ID: raw.ID, Port: raw.Port, Configured: raw.Status, Running: raw.RunStatus}
		if raw.Client != nil {
			tunnel.ClientID = raw.Client.ID
			tunnel.ClientName = raw.Client.Remark
		}
		if raw.Flow != nil {
			tunnel.InletFlow = raw.Flow.InletFlow
			tunnel.ExportFlow = raw.Flow.ExportFlow
		}
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, nil
}

func (a *Adapter) ListPortForwards(ctx context.Context, nodeID string, clientID int) ([]PortForward, error) {
	form := url.Values{"offset": {"0"}, "limit": {"10000"}, "type": {"portForward"}}
	if clientID > 0 {
		form.Set("client_id", strconv.Itoa(clientID))
	}
	var response tableResponse[rawTunnel]
	if err := a.call(ctx, nodeID, "/index/gettunnel", form, &response); err != nil {
		return nil, err
	}
	result := make([]PortForward, 0, len(response.Rows))
	for _, raw := range response.Rows {
		item := PortForward{ID: raw.ID, Port: raw.Port, Remark: raw.Remark, Configured: raw.Status, Running: raw.RunStatus, Target: raw.TargetAddr}
		if raw.Client != nil {
			item.ClientID = raw.Client.ID
			item.ClientName = raw.Client.Remark
		}
		if raw.Target != nil && raw.Target.Target != "" {
			item.Target = raw.Target.Target
		}
		if raw.Flow != nil {
			item.InletFlow = raw.Flow.InletFlow
			item.ExportFlow = raw.Flow.ExportFlow
		}
		result = append(result, item)
	}
	return result, nil
}

func (a *Adapter) CreatePortForward(ctx context.Context, nodeID string, clientID, serverPort int, target, remark string) (PortForward, error) {
	if clientID < 1 || serverPort < 1 || serverPort > 65535 || strings.TrimSpace(target) == "" {
		return PortForward{}, fmt.Errorf("invalid port forward configuration")
	}
	// Server ports are node-global. Inspect every existing port-forward task,
	// not only tasks owned by the selected Client, before asking the node to
	// bind a listener.
	existing, err := a.ListPortForwards(ctx, nodeID, 0)
	if err != nil {
		return PortForward{}, err
	}
	for _, item := range existing {
		if item.Port != serverPort {
			continue
		}
		if item.Target == target && item.ClientID == clientID {
			if !item.Running {
				if err := a.SetPortForward(ctx, nodeID, item.ID, true); err != nil {
					return PortForward{}, fmt.Errorf("restart existing port forward: %w", err)
				}
				item.Running = true
			}
			return item, nil
		}
		return PortForward{}, fmt.Errorf("server port %d is already in use", serverPort)
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/index/add", url.Values{
		"type": {"portForward"}, "client_id": {strconv.Itoa(clientID)}, "port": {strconv.Itoa(serverPort)},
		"target": {target}, "remark": {remark}, "server_ip": {"0.0.0.0"},
	}, &response); err != nil {
		return PortForward{}, err
	}
	if response.Status != 1 {
		return PortForward{}, fmt.Errorf("node rejected port forward creation: %s", response.Msg)
	}
	created, err := a.ListPortForwards(ctx, nodeID, clientID)
	if err != nil {
		return PortForward{}, err
	}
	for _, item := range created {
		if item.Port == serverPort && item.Target == target && item.ClientID == clientID {
			if !item.Running {
				if err := a.SetPortForward(ctx, nodeID, item.ID, true); err != nil {
					return PortForward{}, fmt.Errorf("start created port forward: %w", err)
				}
				item.Running = true
			}
			return item, nil
		}
	}
	return PortForward{}, fmt.Errorf("node accepted port forward but it was not returned by verification query")
}

func (a *Adapter) SetPortForward(ctx context.Context, nodeID string, taskID int, running bool) error {
	if taskID < 1 {
		return fmt.Errorf("task id must be positive")
	}
	action := "/index/start"
	if !running {
		action = "/index/stop"
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, action, url.Values{"id": {strconv.Itoa(taskID)}, "type": {"portForward"}}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return fmt.Errorf("node rejected port forward operation: %s", response.Msg)
	}
	return a.waitForPortForwardState(ctx, nodeID, taskID, running)
}

func (a *Adapter) waitForPortForwardState(ctx context.Context, nodeID string, taskID int, running bool) error {
	waitCtx, cancel := context.WithTimeout(ctx, a.stateWait)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		forwards, inspectErr := a.ListPortForwards(waitCtx, nodeID, 0)
		if inspectErr == nil {
			for _, forward := range forwards {
				if forward.ID == taskID && forward.Running == running {
					return nil
				}
			}
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("port forward %d did not reach requested state: %w", taskID, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (a *Adapter) DeletePortForward(ctx context.Context, nodeID string, taskID int) error {
	if taskID < 1 {
		return fmt.Errorf("task id must be positive")
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/index/del", url.Values{"id": {strconv.Itoa(taskID)}, "type": {"portForward"}}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return fmt.Errorf("node rejected port forward deletion: %s", response.Msg)
	}
	return nil
}

func (a *Adapter) SetManagedTunnel(ctx context.Context, nodeID string, clientID int, running bool) error {
	if clientID < 1 {
		return fmt.Errorf("client id must be positive")
	}
	tunnels, err := a.ListManagedTunnels(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("inspect managed tunnel before operation: %w", err)
	}
	found := false
	for _, tunnel := range tunnels {
		if tunnel.ID != clientID && tunnel.ClientID != clientID {
			continue
		}
		found = true
		if tunnel.Running == running {
			return nil
		}
		break
	}
	if !found {
		return fmt.Errorf("managed tunnel for client %d was not found", clientID)
	}
	action := "/index/start"
	if !running {
		action = "/index/stop"
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, action, url.Values{"id": {strconv.Itoa(clientID)}, "type": {"socks5"}}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return fmt.Errorf("node rejected tunnel operation: %s", response.Msg)
	}
	waitCtx, cancel := context.WithTimeout(ctx, a.stateWait)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		tunnels, inspectErr := a.ListManagedTunnels(waitCtx, nodeID)
		if inspectErr == nil {
			for _, tunnel := range tunnels {
				if (tunnel.ID == clientID || tunnel.ClientID == clientID) && tunnel.Running == running {
					return nil
				}
			}
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("managed tunnel for client %d did not reach requested state: %w", clientID, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func (a *Adapter) SOCKSRoute(ctx context.Context, nodeID string, clientID int) (SOCKSRoute, error) {
	if clientID < 1 {
		return SOCKSRoute{}, fmt.Errorf("client id must be positive")
	}
	node, err := a.nodes.GetNodeConnection(ctx, nodeID)
	if err != nil {
		return SOCKSRoute{}, err
	}
	if !node.Enabled {
		return SOCKSRoute{}, fmt.Errorf("node is disabled")
	}
	apiURL, err := url.Parse(node.APIURL)
	if err != nil || strings.TrimSpace(apiURL.Hostname()) == "" {
		return SOCKSRoute{}, fmt.Errorf("node API host is invalid")
	}
	var response clientResponse
	if err := a.call(ctx, nodeID, "/client/getclient", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return SOCKSRoute{}, err
	}
	if response.Code != 1 || response.Data.ID != clientID {
		return SOCKSRoute{}, fmt.Errorf("client %d was not found on node", clientID)
	}
	if response.Data.Config == nil {
		return SOCKSRoute{}, fmt.Errorf("client %d has no SOCKS credential configuration", clientID)
	}
	return SOCKSRoute{
		Address:  net.JoinHostPort(apiURL.Hostname(), strconv.Itoa(10000+clientID)),
		Username: response.Data.Config.Username,
		Password: response.Data.Config.Password,
	}, nil
}

func (a *Adapter) call(ctx context.Context, nodeID, path string, form url.Values, target any) error {
	node, err := a.nodes.GetNodeConnection(ctx, nodeID)
	if err != nil {
		return err
	}
	if !node.Enabled {
		return fmt.Errorf("node is disabled")
	}
	secret, err := a.secrets.Resolve(ctx, node.CredentialRef)
	if err != nil {
		return fmt.Errorf("resolve node credential: %w", err)
	}
	var credential Credential
	if err := json.Unmarshal([]byte(secret), &credential); err != nil {
		return fmt.Errorf("decode node credential bundle: %w", err)
	}
	client, err := a.newClient(node)
	if err != nil {
		return err
	}
	if credential.Type == "session" {
		if err := a.login(ctx, client, node.APIURL, credential); err != nil {
			return err
		}
	} else if credential.Type == "signed" {
		if strings.TrimSpace(credential.AuthKey) == "" {
			return fmt.Errorf("signed credential requires a non-empty auth key")
		}
		timestamp := time.Now().Unix()
		sum := md5.Sum([]byte(credential.AuthKey + strconv.FormatInt(timestamp, 10)))
		form.Set("timestamp", strconv.FormatInt(timestamp, 10))
		form.Set("auth_key", hex.EncodeToString(sum[:]))
	} else {
		return fmt.Errorf("unsupported node credential type")
	}
	endpoint, err := resolveEndpoint(node.APIURL, path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("node request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("node returned HTTP %d", response.StatusCode)
	}
	if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		return fmt.Errorf("node returned HTML instead of JSON; authentication may have failed")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode node response: %w", err)
	}
	return nil
}

func (a *Adapter) login(ctx context.Context, client *http.Client, baseURL string, credential Credential) error {
	if credential.Username == "" || credential.Password == "" {
		return fmt.Errorf("session credential requires username and password")
	}
	endpoint, err := resolveEndpoint(baseURL, "/login/verify")
	if err != nil {
		return err
	}
	form := url.Values{"username": {credential.Username}, "password": {credential.Password}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("node login: %w", err)
	}
	defer response.Body.Close()
	var result actionResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode node login: %w", err)
	}
	if result.Status != 1 {
		return errors.New("node login rejected")
	}
	return nil
}

func (a *Adapter) defaultHTTPClient(node store.NodeConnection) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: node.TLSServerName}
	transport.ResponseHeaderTimeout = a.timeout
	return &http.Client{Transport: transport, Jar: jar, Timeout: a.timeout}, nil
}

func resolveEndpoint(baseURL, path string) (string, error) {
	base, err := url.Parse(strings.TrimRight(baseURL, "/") + "/")
	if err != nil {
		return "", err
	}
	relative, err := url.Parse(strings.TrimLeft(path, "/"))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(relative).String(), nil
}
