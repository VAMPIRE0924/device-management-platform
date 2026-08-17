package nodeadapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	now       func() time.Time
	nonce     func() (string, error)
}

type Credential struct {
	Type    string `json:"type"`
	AuthKey string `json:"authKey,omitempty"`
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

// ClientUpdate is a patch at the platform boundary. UpdateClient always reads
// the current NPS Client first and sends a complete edit form, because the NPS
// edit endpoint is replacement-based rather than PATCH-based.
type ClientUpdate struct {
	Remark          *string
	VerifyKey       *string
	BasicUsername   *string
	BasicPassword   *string
	Compress        *bool
	Crypt           *bool
	ConfigConnAllow *bool
	RateLimit       *int
	FlowLimit       *int64
	MaxConn         *int
	MaxTunnel       *int
	WebUsername     *string
	WebPassword     *string
}

type ManagedTunnel struct {
	ID                      int       `json:"id"`
	ClientID                int       `json:"clientId"`
	ClientName              string    `json:"clientName"`
	Port                    int       `json:"port"`
	Configured              bool      `json:"configured"`
	Running                 bool      `json:"running"`
	Active                  bool      `json:"active"`
	Countdown               bool      `json:"countdown"`
	LastActiveAt            int64     `json:"lastActiveAt"`
	IdleSeconds             int64     `json:"idleSeconds"`
	RemainingSeconds        int64     `json:"remainingSeconds"`
	AutoCloseAt             int64     `json:"autoCloseAt"`
	AutoCloseTimeoutSeconds int64     `json:"autoCloseTimeoutSeconds"`
	InletFlow               int64     `json:"inletFlow"`
	ExportFlow              int64     `json:"exportFlow"`
	ObservedAt              time.Time `json:"observedAt"`
}

type PortForward struct {
	ID         int    `json:"id"`
	Type       string `json:"type"`
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
	FlowLimit  int64
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
	RateLimit int        `json:"RateLimit"`
	MaxConn   int        `json:"MaxConn"`
	MaxTunnel int        `json:"MaxTunnelNum"`
	WebUser   string     `json:"WebUserName"`
	WebPass   string     `json:"WebPassword"`
	ConfigOK  bool       `json:"ConfigConnAllow"`
}

type rawConfig struct {
	Username string `json:"U"`
	Password string `json:"P"`
	Compress bool   `json:"Compress"`
	Crypt    bool   `json:"Crypt"`
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

type rawSocksStatus struct {
	ID                      int   `json:"id"`
	ClientID                int   `json:"client_id"`
	Enabled                 bool  `json:"enabled"`
	Running                 bool  `json:"running"`
	Active                  bool  `json:"active"`
	Countdown               bool  `json:"countdown"`
	LastActiveAt            int64 `json:"last_active_at"`
	IdleSeconds             int64 `json:"idle_seconds"`
	RemainingSeconds        int64 `json:"remaining_seconds"`
	AutoCloseAt             int64 `json:"auto_close_at"`
	AutoCloseTimeoutSeconds int64 `json:"auto_close_timeout_seconds"`
	InletFlow               int64 `json:"inlet_flow"`
	ExportFlow              int64 `json:"export_flow"`
}

type actionResponse struct {
	Status int    `json:"status"`
	Msg    string `json:"msg"`
}

type clientResponse struct {
	Code int       `json:"code"`
	Data rawClient `json:"data"`
}

type tunnelResponse struct {
	Code int       `json:"code"`
	Data rawTunnel `json:"data"`
}

type socksStatusResponse struct {
	Code int            `json:"code"`
	Data rawSocksStatus `json:"data"`
}

func New(nodes nodeSource, secrets secretResolver) *Adapter {
	a := &Adapter{
		nodes: nodes, secrets: secrets, timeout: 12 * time.Second, stateWait: 5 * time.Second,
		now: time.Now, nonce: newNonce,
	}
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
	if err := a.call(ctx, nodeID, "/client/list/", url.Values{"offset": {"0"}, "limit": {"10000"}}, &response); err != nil {
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
	if err := a.call(ctx, nodeID, "/client/getclient/", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
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

func (a *Adapter) getRawClient(ctx context.Context, nodeID string, clientID int) (rawClient, error) {
	if clientID < 1 {
		return rawClient{}, fmt.Errorf("client id must be positive")
	}
	var response clientResponse
	if err := a.call(ctx, nodeID, "/client/getclient/", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return rawClient{}, err
	}
	if response.Code != 1 || response.Data.ID != clientID {
		return rawClient{}, fmt.Errorf("client %d was not found on node", clientID)
	}
	return response.Data, nil
}

func boolForm(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func completeClientForm(client rawClient) url.Values {
	form := url.Values{
		"id": {strconv.Itoa(client.ID)}, "remark": {client.Remark}, "vkey": {client.VerifyKey},
		"rate_limit": {strconv.Itoa(client.RateLimit)}, "max_conn": {strconv.Itoa(client.MaxConn)},
		"max_tunnel": {strconv.Itoa(client.MaxTunnel)}, "web_username": {client.WebUser},
		"web_password": {client.WebPass}, "config_conn_allow": {boolForm(client.ConfigOK)},
	}
	if client.Config != nil {
		form.Set("u", client.Config.Username)
		form.Set("p", client.Config.Password)
		form.Set("compress", boolForm(client.Config.Compress))
		form.Set("crypt", boolForm(client.Config.Crypt))
	} else {
		form.Set("u", "")
		form.Set("p", "")
		form.Set("compress", "0")
		form.Set("crypt", "0")
	}
	flowLimit := int64(0)
	if client.Flow != nil {
		flowLimit = client.Flow.FlowLimit
	}
	form.Set("flow_limit", strconv.FormatInt(flowLimit, 10))
	return form
}

func (a *Adapter) UpdateClient(ctx context.Context, nodeID string, clientID int, update ClientUpdate) error {
	client, err := a.getRawClient(ctx, nodeID, clientID)
	if err != nil {
		return err
	}
	if client.Config == nil {
		client.Config = &rawConfig{}
	}
	if client.Flow == nil {
		client.Flow = &rawFlow{}
	}
	if update.Remark != nil {
		client.Remark = *update.Remark
	}
	if update.VerifyKey != nil {
		client.VerifyKey = *update.VerifyKey
	}
	if update.BasicUsername != nil {
		client.Config.Username = *update.BasicUsername
	}
	if update.BasicPassword != nil {
		client.Config.Password = *update.BasicPassword
	}
	if update.Compress != nil {
		client.Config.Compress = *update.Compress
	}
	if update.Crypt != nil {
		client.Config.Crypt = *update.Crypt
	}
	if update.ConfigConnAllow != nil {
		client.ConfigOK = *update.ConfigConnAllow
	}
	if update.RateLimit != nil {
		client.RateLimit = *update.RateLimit
	}
	if update.FlowLimit != nil {
		client.Flow.FlowLimit = *update.FlowLimit
	}
	if update.MaxConn != nil {
		client.MaxConn = *update.MaxConn
	}
	if update.MaxTunnel != nil {
		client.MaxTunnel = *update.MaxTunnel
	}
	if update.WebUsername != nil {
		client.WebUser = *update.WebUsername
	}
	if update.WebPassword != nil {
		client.WebPass = *update.WebPassword
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/client/edit/", completeClientForm(client), &response); err != nil {
		return err
	}
	return nil
}

func (a *Adapter) UpdateClientBasic(ctx context.Context, nodeID string, clientIDs []int, username, password string) error {
	if len(clientIDs) == 0 {
		return fmt.Errorf("at least one client id is required")
	}
	ids := make([]string, len(clientIDs))
	for index, clientID := range clientIDs {
		if clientID < 1 {
			return fmt.Errorf("client id must be positive")
		}
		ids[index] = strconv.Itoa(clientID)
	}
	var response actionResponse
	return a.call(ctx, nodeID, "/client/basic/", url.Values{"ids": {strings.Join(ids, ",")}, "u": {username}, "p": {password}}, &response)
}

func (a *Adapter) CreateClient(ctx context.Context, nodeID, remark, verifyKey, socksUsername, socksPassword string) (Client, error) {
	if strings.TrimSpace(remark) == "" || strings.TrimSpace(verifyKey) == "" || socksUsername == "" || socksPassword == "" {
		return Client{}, fmt.Errorf("client remark and generated credentials are required")
	}
	var existing tableResponse[rawClient]
	if err := a.call(ctx, nodeID, "/client/list/", url.Values{"offset": {"0"}, "limit": {"10000"}}, &existing); err != nil {
		return Client{}, err
	}
	for _, raw := range existing.Rows {
		if raw.VerifyKey == verifyKey {
			return Client{}, ErrDuplicateVerifyKey
		}
	}
	var response actionResponse
	if err := a.call(ctx, nodeID, "/client/add/", url.Values{
		"remark": {remark}, "vkey": {verifyKey}, "u": {socksUsername}, "p": {socksPassword},
		"compress": {"0"}, "crypt": {"1"}, "config_conn_allow": {"0"},
		"rate_limit": {"0"}, "flow_limit": {"0"}, "max_conn": {"0"}, "max_tunnel": {"0"},
		"web_username": {""}, "web_password": {""},
	}, &response); err != nil {
		return Client{}, err
	}
	if response.Status != 1 {
		return Client{}, fmt.Errorf("node rejected client creation: %s", response.Msg)
	}
	var listing tableResponse[rawClient]
	if err := a.call(ctx, nodeID, "/client/list/", url.Values{"offset": {"0"}, "limit": {"10000"}}, &listing); err != nil {
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
	if err := a.call(ctx, nodeID, "/client/del/", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return fmt.Errorf("node rejected client deletion: %s", response.Msg)
	}
	return nil
}

func (a *Adapter) ListManagedTunnels(ctx context.Context, nodeID string) ([]ManagedTunnel, error) {
	var response tableResponse[rawTunnel]
	if err := a.call(ctx, nodeID, "/index/gettunnel/", url.Values{"offset": {"0"}, "limit": {"10000"}, "type": {"socks5"}}, &response); err != nil {
		return nil, err
	}
	tunnels := make([]ManagedTunnel, 0, len(response.Rows))
	for _, raw := range response.Rows {
		tunnel := ManagedTunnel{ID: raw.ID, Port: raw.Port, Configured: raw.Status}
		if raw.Client != nil {
			tunnel.ClientID = raw.Client.ID
			tunnel.ClientName = raw.Client.Remark
		}
		lookupID := tunnel.ClientID
		if lookupID == 0 {
			lookupID = tunnel.ID
		}
		status, err := a.ManagedTunnelStatus(ctx, nodeID, lookupID)
		if err != nil {
			return nil, fmt.Errorf("read managed SOCKS status for client %d: %w", lookupID, err)
		}
		tunnel.Configured = status.Configured
		tunnel.Running = status.Running
		tunnel.Active = status.Active
		tunnel.Countdown = status.Countdown
		tunnel.LastActiveAt = status.LastActiveAt
		tunnel.IdleSeconds = status.IdleSeconds
		tunnel.RemainingSeconds = status.RemainingSeconds
		tunnel.AutoCloseAt = status.AutoCloseAt
		tunnel.AutoCloseTimeoutSeconds = status.AutoCloseTimeoutSeconds
		tunnel.InletFlow = status.InletFlow
		tunnel.ExportFlow = status.ExportFlow
		tunnel.ObservedAt = status.ObservedAt
		tunnels = append(tunnels, tunnel)
	}
	return tunnels, nil
}

func (a *Adapter) ManagedTunnelStatus(ctx context.Context, nodeID string, clientID int) (ManagedTunnel, error) {
	if clientID < 1 {
		return ManagedTunnel{}, fmt.Errorf("client id must be positive")
	}
	var response socksStatusResponse
	if err := a.call(ctx, nodeID, "/index/socksstatus/", url.Values{"client_id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return ManagedTunnel{}, err
	}
	raw := response.Data
	if response.Code != 1 || raw.ClientID != clientID {
		return ManagedTunnel{}, fmt.Errorf("managed tunnel for client %d was not found", clientID)
	}
	return ManagedTunnel{
		ID: raw.ID, ClientID: raw.ClientID, Configured: raw.Enabled, Running: raw.Running,
		Active: raw.Active, Countdown: raw.Countdown, LastActiveAt: raw.LastActiveAt,
		IdleSeconds: raw.IdleSeconds, RemainingSeconds: raw.RemainingSeconds,
		AutoCloseAt: raw.AutoCloseAt, AutoCloseTimeoutSeconds: raw.AutoCloseTimeoutSeconds,
		InletFlow: raw.InletFlow, ExportFlow: raw.ExportFlow, ObservedAt: a.now().UTC(),
	}, nil
}

func (a *Adapter) ListPortForwards(ctx context.Context, nodeID string, clientID int) ([]PortForward, error) {
	form := url.Values{"offset": {"0"}, "limit": {"10000"}, "type": {"portForward"}}
	if clientID > 0 {
		form.Set("client_id", strconv.Itoa(clientID))
	}
	var response tableResponse[rawTunnel]
	if err := a.call(ctx, nodeID, "/index/gettunnel/", form, &response); err != nil {
		return nil, err
	}
	result := make([]PortForward, 0, len(response.Rows))
	for _, raw := range response.Rows {
		item := PortForward{ID: raw.ID, Type: "portForward", Port: raw.Port, Remark: raw.Remark, Configured: raw.Status, Running: raw.RunStatus, Target: raw.TargetAddr}
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
	if err := a.call(ctx, nodeID, "/index/add/", url.Values{
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
	action := "/index/start/"
	if !running {
		action = "/index/stop/"
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
	if err := a.call(ctx, nodeID, "/index/del/", url.Values{"id": {strconv.Itoa(taskID)}, "type": {"portForward"}}, &response); err != nil {
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
	status, err := a.ManagedTunnelStatus(ctx, nodeID, clientID)
	if err != nil {
		return fmt.Errorf("inspect managed tunnel before operation: %w", err)
	}
	if status.Running == running {
		return nil
	}
	action := "/index/start/"
	if !running {
		action = "/index/stop/"
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
		status, inspectErr := a.ManagedTunnelStatus(waitCtx, nodeID, clientID)
		if inspectErr == nil && status.Running == running {
			return nil
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
	if err := a.call(ctx, nodeID, "/client/getclient/", url.Values{"id": {strconv.Itoa(clientID)}}, &response); err != nil {
		return SOCKSRoute{}, err
	}
	if response.Code != 1 || response.Data.ID != clientID {
		return SOCKSRoute{}, fmt.Errorf("client %d was not found on node", clientID)
	}
	if response.Data.Config == nil {
		return SOCKSRoute{}, fmt.Errorf("client %d has no SOCKS credential configuration", clientID)
	}
	var tunnel tunnelResponse
	if err := a.call(ctx, nodeID, "/index/getonetunnel/", url.Values{"id": {strconv.Itoa(clientID)}, "type": {"socks5"}}, &tunnel); err != nil {
		return SOCKSRoute{}, err
	}
	if tunnel.Code != 1 || tunnel.Data.ID != clientID || tunnel.Data.Port < 1 || tunnel.Data.Port > 65535 {
		return SOCKSRoute{}, fmt.Errorf("managed tunnel for client %d has no valid route", clientID)
	}
	return SOCKSRoute{
		Address:  net.JoinHostPort(apiURL.Hostname(), strconv.Itoa(tunnel.Data.Port)),
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
	endpoint, err := resolveEndpoint(node.APIURL, path)
	if err != nil {
		return err
	}
	body := []byte(form.Encode())
	if len(body) > 1<<20 {
		return fmt.Errorf("NPS request body exceeds 1 MiB limit")
	}
	client, err := a.newClient(node)
	if err != nil {
		return err
	}
	if credential.Type == "signed" {
		if strings.TrimSpace(credential.AuthKey) == "" {
			return fmt.Errorf("signed credential requires a non-empty auth key")
		}
	} else {
		return fmt.Errorf("unsupported node credential type")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if credential.Type == "signed" {
		nonce, nonceErr := a.nonce()
		if nonceErr != nil {
			return nonceErr
		}
		applyNPSSignature(request, body, credential.AuthKey, nonce, a.now())
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("node request: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("read node response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return classifyNPSHTTPError(response.StatusCode, payload)
	}
	if strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		return fmt.Errorf("node returned HTML instead of JSON; authentication may have failed")
	}
	if err := validateNPSBusinessResponse(payload); err != nil {
		return err
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode node response: %w", err)
	}
	return nil
}

func (a *Adapter) defaultHTTPClient(node store.NodeConnection) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: node.TLSServerName}
	transport.ResponseHeaderTimeout = a.timeout
	return &http.Client{Transport: transport, Timeout: a.timeout}, nil
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
