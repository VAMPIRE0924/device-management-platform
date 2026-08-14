package store

import "time"

type Node struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	APIURL               string     `json:"apiUrl"`
	TLSServerName        string     `json:"tlsServerName"`
	CredentialConfigured bool       `json:"credentialConfigured"`
	PortStart            int        `json:"portStart"`
	PortEnd              int        `json:"portEnd"`
	Enabled              bool       `json:"enabled"`
	HealthStatus         string     `json:"healthStatus"`
	LastCheckedAt        *time.Time `json:"lastCheckedAt"`
	CreatedAt            time.Time  `json:"createdAt"`
	UpdatedAt            time.Time  `json:"updatedAt"`
}

type CreateNodeInput struct {
	ID            string `json:"-"`
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	TLSServerName string `json:"tlsServerName"`
	CredentialRef string `json:"-"`
	PortStart     int    `json:"portStart"`
	PortEnd       int    `json:"portEnd"`
}

type UpdateNodeInput struct {
	CreateNodeInput
	Enabled *bool `json:"enabled"`
}

type Project struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	NodeID    string    `json:"nodeId"`
	OwnerName string    `json:"ownerName"`
	ClientID  *int      `json:"clientId"`
	Networks  []string  `json:"networks"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type CreateProjectInput struct {
	Name      string   `json:"name"`
	NodeID    string   `json:"nodeId"`
	OwnerName string   `json:"ownerName"`
	ClientID  *int     `json:"clientId"`
	Networks  []string `json:"networks"`
}

type AuditInput struct {
	Actor        string
	Action       string
	ResourceType string
	ResourceID   string
	Result       string
	RequestID    string
	SourceIP     string
	MetadataJSON string
}

type DeviceEndpoint struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	Protocol              string     `json:"protocol"`
	TargetPort            int        `json:"targetPort"`
	AccessType            string     `json:"accessType"`
	VerificationStatus    string     `json:"verificationStatus"`
	LastVerifiedAt        *time.Time `json:"lastVerifiedAt"`
	TLSServerName         string     `json:"tlsServerName"`
	AllowInsecureTLS      bool       `json:"allowInsecureTls"`
	CredentialConfigured  bool       `json:"credentialConfigured"`
	SSHAuthMethod         string     `json:"sshAuthMethod"`
	SSHUsername           string     `json:"sshUsername"`
	SSHKeyPath            string     `json:"sshKeyPath"`
	SSHHostKeyFingerprint string     `json:"sshHostKeyFingerprint"`
}

type SSHCredentialInput struct {
	Method   string `json:"method"`
	Username string `json:"username"`
	Password string `json:"password"`
	KeyPath  string `json:"keyPath"`
}

type Device struct {
	ID         string           `json:"id"`
	ProjectID  string           `json:"projectId"`
	Host       string           `json:"host"`
	Name       string           `json:"name"`
	DeviceType string           `json:"deviceType"`
	Vendor     string           `json:"vendor"`
	Source     string           `json:"source"`
	Status     string           `json:"status"`
	LastSeenAt *time.Time       `json:"lastSeenAt"`
	Endpoints  []DeviceEndpoint `json:"endpoints"`
	CreatedAt  time.Time        `json:"createdAt"`
	UpdatedAt  time.Time        `json:"updatedAt"`
}

type CreateEndpointInput struct {
	ID                    string              `json:"id,omitempty"`
	IsNew                 bool                `json:"-"`
	Name                  string              `json:"name"`
	Protocol              string              `json:"protocol"`
	TargetPort            int                 `json:"targetPort"`
	TLSServerName         string              `json:"tlsServerName"`
	AllowInsecureTLS      bool                `json:"allowInsecureTls"`
	CredentialRef         string              `json:"-"`
	SSHCredential         *SSHCredentialInput `json:"sshCredential,omitempty"`
	SSHAuthMethod         string              `json:"-"`
	SSHUsername           string              `json:"-"`
	SSHKeyPath            string              `json:"-"`
	SSHHostKeyFingerprint string              `json:"sshHostKeyFingerprint"`
}

type CreateDeviceInput struct {
	Host       string                `json:"host"`
	Name       string                `json:"name"`
	DeviceType string                `json:"deviceType"`
	Vendor     string                `json:"vendor"`
	Source     string                `json:"source"`
	Endpoints  []CreateEndpointInput `json:"endpoints"`
}

type UpdateDeviceInput struct {
	Host       string                 `json:"host"`
	Name       string                 `json:"name"`
	DeviceType string                 `json:"deviceType"`
	Vendor     string                 `json:"vendor"`
	Endpoints  *[]CreateEndpointInput `json:"endpoints,omitempty"`
}

type UpdateProjectInput struct {
	Name      string   `json:"name"`
	OwnerName string   `json:"ownerName"`
	Networks  []string `json:"networks"`
}

type EndpointRoute struct {
	EndpointID            string
	EndpointName          string
	Protocol              string
	TargetPort            int
	AccessType            string
	DeviceID              string
	DeviceName            string
	Host                  string
	ProjectID             string
	ProjectName           string
	NodeID                string
	ClientID              int
	TLSServerName         string
	AllowInsecureTLS      bool
	CredentialRef         string
	SSHAuthMethod         string
	SSHUsername           string
	SSHKeyPath            string
	SSHHostKeyFingerprint string
}

type AccessSession struct {
	ID           string     `json:"id"`
	UserID       *string    `json:"userId"`
	ProjectID    string     `json:"projectId"`
	EndpointID   string     `json:"endpointId"`
	EndpointName string     `json:"endpointName"`
	DeviceName   string     `json:"deviceName"`
	Mode         string     `json:"mode"`
	SourceIP     string     `json:"sourceIp"`
	Status       string     `json:"status"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	StartedAt    time.Time  `json:"startedAt"`
	EndedAt      *time.Time `json:"endedAt"`
}

type CreateAccessSessionInput struct {
	UserID     *string
	ProjectID  string
	EndpointID string
	TokenHash  string
	Mode       string
	SourceIP   string
	ExpiresAt  time.Time
}

type PortForward struct {
	ID           string     `json:"id"`
	ProjectID    string     `json:"projectId"`
	EndpointID   string     `json:"endpointId"`
	EndpointName string     `json:"endpointName"`
	DeviceName   string     `json:"deviceName"`
	NodeID       string     `json:"nodeId"`
	ClientID     int        `json:"clientId"`
	Target       string     `json:"target"`
	ServerPort   int        `json:"serverPort"`
	NodeTaskID   *int       `json:"nodeTaskId"`
	Status       string     `json:"status"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

type ReservePortForwardInput struct {
	ProjectID  string
	EndpointID string
	ServerPort int
	ExpiresAt  *time.Time
}

type DiscoveryRoute struct {
	ProjectID string
	NodeID    string
	ClientID  int
	Networks  []string
}

type DiscoveryPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name"`
}

type DiscoveryJob struct {
	ID         string          `json:"id"`
	ProjectID  string          `json:"projectId"`
	Networks   []string        `json:"networks"`
	Ports      []DiscoveryPort `json:"ports"`
	Status     string          `json:"status"`
	Progress   int             `json:"progress"`
	CreatedAt  time.Time       `json:"createdAt"`
	StartedAt  *time.Time      `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
}

type DiscoveryResult struct {
	ID              string    `json:"id"`
	JobID           string    `json:"jobId"`
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Protocol        string    `json:"protocol"`
	ServiceName     string    `json:"serviceName"`
	Fingerprint     string    `json:"fingerprint"`
	ResponseSummary string    `json:"responseSummary"`
	Confidence      int       `json:"confidence"`
	ImportStatus    string    `json:"importStatus"`
	CreatedAt       time.Time `json:"createdAt"`
}

type DiscoveryProbeResult struct {
	Host            string
	Port            int
	Protocol        string
	ServiceName     string
	Fingerprint     string
	ResponseSummary string
	Confidence      int
}

type User struct {
	ID                     string    `json:"id"`
	Username               string    `json:"username"`
	DisplayName            string    `json:"displayName"`
	Email                  string    `json:"email"`
	Role                   string    `json:"role"`
	Enabled                bool      `json:"enabled"`
	ProjectIDs             []string  `json:"projectIds"`
	MFAEnabled             bool      `json:"mfaEnabled"`
	PasswordChangeRequired bool      `json:"passwordChangeRequired"`
	CreatedAt              time.Time `json:"createdAt"`
	UpdatedAt              time.Time `json:"updatedAt"`
}

type CreateUserInput struct {
	Username     string   `json:"username"`
	DisplayName  string   `json:"displayName"`
	PasswordHash string   `json:"-"`
	Role         string   `json:"role"`
	Enabled      bool     `json:"enabled"`
	ProjectIDs   []string `json:"projectIds"`
}

type UpdateUserInput struct {
	DisplayName  string
	PasswordHash string
	Role         string
	Enabled      bool
	ProjectIDs   []string
}

type UserCredential struct {
	User
	PasswordHash        string
	MFASecretCiphertext string
	MFAPreferredMethod  string
}

type AuthSession struct {
	ID        string
	User      User
	ExpiresAt time.Time
	CSRFHash  string
}

type MFAChallenge struct {
	ID                  string
	User                User
	Purpose             string
	Method              string
	SecretCiphertext    string
	Email               string
	EmailCodeHash       string
	EmailVerified       bool
	NewPasswordHash     string
	MFASecretCiphertext string
	MFAPreferredMethod  string
	Attempts            int
	ExpiresAt           time.Time
}

type CompleteMFAInput struct {
	ChallengeID string
	Method      string
	Counter     int64
	CodeHash    string
	TokenHash   string
	CSRFHash    string
	ExpiresAt   time.Time
	Recovery    []string
	Email       string
	MethodBound string
	Audit       AuditInput
}

type AccessPolicy struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ProjectIDs   []string   `json:"projectIds"`
	UserIDs      []string   `json:"userIds"`
	Capabilities []string   `json:"capabilities"`
	ValidFrom    *time.Time `json:"validFrom"`
	ValidUntil   *time.Time `json:"validUntil"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

type AuditLog struct {
	ID           string    `json:"id"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	Result       string    `json:"result"`
	RequestID    string    `json:"requestId"`
	SourceIP     string    `json:"sourceIp"`
	MetadataJSON string    `json:"metadataJson"`
	CreatedAt    time.Time `json:"createdAt"`
}

type SaveAccessPolicyInput struct {
	Name         string
	ProjectIDs   []string
	UserIDs      []string
	Capabilities []string
	ValidFrom    *time.Time
	ValidUntil   *time.Time
	Enabled      bool
}
