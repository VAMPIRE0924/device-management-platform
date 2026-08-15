package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PanelSettings is the non-secret configuration surface editable by a system
// administrator. SMTPPassword is accepted on write but is never populated on read.
type PanelSettings struct {
	MFAEnabled             bool     `json:"mfaEnabled"`
	MFAMethods             []string `json:"mfaMethods"`
	EmailCodeTTL           string   `json:"emailCodeTTL"`
	MFAKeyFile             string   `json:"mfaKeyFile"`
	SMTPHost               string   `json:"smtpHost"`
	SMTPPort               int      `json:"smtpPort"`
	SMTPUsername           string   `json:"smtpUsername"`
	SMTPPassword           string   `json:"smtpPassword,omitempty"`
	SMTPPasswordConfigured bool     `json:"smtpPasswordConfigured"`
	ClearSMTPPassword      bool     `json:"clearSMTPPassword,omitempty"`
	SMTPConfigured         bool     `json:"smtpConfigured"`
	SMTPFrom               string   `json:"smtpFrom"`
	TLSCertFile            string   `json:"tlsCertFile"`
	TLSKeyFile             string   `json:"tlsKeyFile"`
	TLSConfigured          bool     `json:"tlsConfigured"`
	AccessTLSCertFile      string   `json:"accessTlsCertFile"`
	AccessTLSKeyFile       string   `json:"accessTlsKeyFile"`
	AccessTLSConfigured    bool     `json:"accessTlsConfigured"`
	ReusePanelPorts        bool     `json:"reusePanelPorts"`
	AccessHTTPPort         int      `json:"accessHttpPort"`
	AccessHTTPSPort        int      `json:"accessHttpsPort"`
	HTTPPort               int      `json:"httpPort"`
	HTTPSPort              int      `json:"httpsPort"`
	PanelDomain            string   `json:"panelDomain"`
	AccessDomain           string   `json:"accessDomain"`
	RestartRequired        bool     `json:"restartRequired"`
	LockedFields           []string `json:"lockedFields"`
	Source                 string   `json:"source"`
}

type SettingsManager struct {
	mu     sync.Mutex
	active Config
}

func NewSettingsManager(active Config) *SettingsManager {
	if strings.TrimSpace(active.ListenAddress) == "" {
		active.ListenAddress = "0.0.0.0:80"
	}
	if strings.TrimSpace(active.HTTPSListenAddress) == "" {
		active.HTTPSListenAddress = "0.0.0.0:443"
	}
	return &SettingsManager{active: active}
}

func (m *SettingsManager) Current() PanelSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := m.desiredConfig()
	settings := panelSettingsFromConfig(desired)
	settings.RestartRequired = !sameEditableConfig(m.active, desired)
	settings.LockedFields = environmentLockedFields()
	settings.Source = "web_override"
	return settings
}

func (m *SettingsManager) Save(input PanelSettings) (PanelSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fieldLocked("smtpPassword") && (strings.TrimSpace(input.SMTPPassword) != "" || input.ClearSMTPPassword) {
		return PanelSettings{}, fmt.Errorf("smtpPassword is controlled by an environment variable")
	}
	input.MFAMethods = normalizedMethods(input.MFAMethods)
	input.SMTPHost = strings.TrimSpace(input.SMTPHost)
	input.SMTPUsername = strings.TrimSpace(input.SMTPUsername)
	input.SMTPFrom = strings.TrimSpace(input.SMTPFrom)
	input.TLSCertFile = strings.TrimSpace(input.TLSCertFile)
	input.TLSKeyFile = strings.TrimSpace(input.TLSKeyFile)
	input.AccessTLSCertFile = strings.TrimSpace(input.AccessTLSCertFile)
	input.AccessTLSKeyFile = strings.TrimSpace(input.AccessTLSKeyFile)
	input.PanelDomain = strings.ToLower(strings.Trim(strings.TrimSpace(input.PanelDomain), "."))
	input.AccessDomain = strings.ToLower(strings.Trim(strings.TrimSpace(input.AccessDomain), "."))
	if input.MFAKeyFile != "" && strings.TrimSpace(input.MFAKeyFile) != m.active.MFAKeyFile {
		return PanelSettings{}, fmt.Errorf("mfa_key_file is read-only in the web interface")
	}
	for name, value := range map[string]string{
		"emailCodeTTL": input.EmailCodeTTL, "smtpHost": input.SMTPHost, "smtpUsername": input.SMTPUsername,
		"smtpFrom": input.SMTPFrom, "tlsCertFile": input.TLSCertFile,
		"tlsKeyFile": input.TLSKeyFile, "accessTlsCertFile": input.AccessTLSCertFile, "accessTlsKeyFile": input.AccessTLSKeyFile,
		"panelDomain": input.PanelDomain, "accessDomain": input.AccessDomain,
	} {
		if strings.ContainsAny(value, "\r\n") {
			return PanelSettings{}, fmt.Errorf("%s cannot contain line breaks", name)
		}
	}

	// Start from the pending override, not only the running configuration. This
	// preserves write-only values such as the SMTP password when an administrator
	// saves another setting before restarting the container.
	candidate := m.desiredConfig()
	candidate.MFAEnabled = input.MFAEnabled
	candidate.MFAMethods = input.MFAMethods
	parsedTTL, err := time.ParseDuration(strings.TrimSpace(input.EmailCodeTTL))
	if err != nil {
		return PanelSettings{}, fmt.Errorf("mfa_email_code_ttl must be a duration such as 10m")
	}
	candidate.EmailCodeTTL = parsedTTL
	candidate.SMTPHost = input.SMTPHost
	candidate.SMTPPort = input.SMTPPort
	candidate.SMTPUsername = input.SMTPUsername
	candidate.SMTPFrom = input.SMTPFrom
	candidate.SMTPTLSMode = smtpTLSModeForPort(input.SMTPPort)
	candidate.TLSCertFile = input.TLSCertFile
	candidate.TLSKeyFile = input.TLSKeyFile
	candidate.AccessTLSCertFile = input.AccessTLSCertFile
	candidate.AccessTLSKeyFile = input.AccessTLSKeyFile
	if input.ReusePanelPorts || (input.AccessHTTPPort == 0 && input.AccessHTTPSPort == 0) {
		candidate.AccessHTTPPort = 0
		candidate.AccessHTTPSPort = 0
	} else {
		candidate.AccessHTTPPort = input.AccessHTTPPort
		candidate.AccessHTTPSPort = input.AccessHTTPSPort
	}
	if input.HTTPPort < 1 || input.HTTPPort > 65535 || input.HTTPSPort < 1 || input.HTTPSPort > 65535 {
		return PanelSettings{}, fmt.Errorf("HTTP and HTTPS ports must be between 1 and 65535")
	}
	if input.HTTPPort == input.HTTPSPort {
		return PanelSettings{}, fmt.Errorf("HTTP and HTTPS ports must be different")
	}
	candidate.ListenAddress = listenAddressWithPort(m.active.ListenAddress, input.HTTPPort)
	candidate.HTTPSListenAddress = listenAddressWithPort(m.active.HTTPSListenAddress, input.HTTPSPort)
	candidate.PanelDomain = input.PanelDomain
	candidate.AccessDomain = input.AccessDomain
	if candidate.AccessDomain != "" {
		if isLocalAccessDomain(candidate.AccessDomain) {
			candidate.AccessScheme = "http"
		} else {
			candidate.AccessScheme = "https"
		}
	}
	if strings.TrimSpace(input.SMTPPassword) != "" {
		candidate.SMTPPassword = input.SMTPPassword
	}
	if input.ClearSMTPPassword && strings.TrimSpace(input.SMTPPassword) != "" {
		return PanelSettings{}, fmt.Errorf("smtpPassword and clearSMTPPassword cannot be used together")
	}
	if input.ClearSMTPPassword {
		candidate.SMTPPassword = ""
	}
	if err := candidate.validate(); err != nil {
		return PanelSettings{}, err
	}
	if err := rejectLockedChanges(m.active, candidate); err != nil {
		return PanelSettings{}, err
	}

	passwordFile := ""
	if input.ClearSMTPPassword {
		passwordFile = ""
	} else if strings.TrimSpace(input.SMTPPassword) != "" {
		passwordFile = filepath.Join(m.active.DataDirectory, "smtp-password")
		if err := writePrivateFile(passwordFile, []byte(input.SMTPPassword+"\n")); err != nil {
			return PanelSettings{}, fmt.Errorf("write SMTP password: %w", err)
		}
	} else if candidate.SMTPPassword != "" {
		passwordFile = configuredSMTPPasswordFile(m.active)
		if passwordFile == "" && strings.TrimSpace(os.Getenv("DMP_SMTP_PASSWORD")) == "" {
			passwordFile = filepath.Join(m.active.DataDirectory, "smtp-password")
			if err := writePrivateFile(passwordFile, []byte(candidate.SMTPPassword+"\n")); err != nil {
				return PanelSettings{}, fmt.Errorf("protect existing SMTP password: %w", err)
			}
		}
	}
	content := renderOverride(candidate, passwordFile)
	if err := writePrivateFile(m.active.OverrideFile, []byte(content)); err != nil {
		return PanelSettings{}, fmt.Errorf("write settings override: %w", err)
	}
	if input.ClearSMTPPassword {
		managedPasswordFile := filepath.Join(m.active.DataDirectory, "smtp-password")
		if err := os.Remove(managedPasswordFile); err != nil && !os.IsNotExist(err) {
			return PanelSettings{}, fmt.Errorf("remove managed SMTP password: %w", err)
		}
	}
	settings := panelSettingsFromConfig(candidate)
	settings.RestartRequired = !sameEditableConfig(m.active, candidate)
	settings.LockedFields = environmentLockedFields()
	settings.Source = "web_override"
	return settings, nil
}

func (m *SettingsManager) desiredConfig() Config {
	desired := m.active
	if values, err := readConfigFile(m.active.OverrideFile); err == nil && len(values) > 0 {
		desired = applyEditableValues(desired, values)
	}
	return preserveEnvironmentControlledValues(m.active, desired)
}

// The override file may contain values written before a deployment started
// controlling the same setting through an environment variable. Keep the
// running environment authoritative when presenting or saving pending settings;
// otherwise the UI reports a false restart requirement and can rewrite stale
// values back into the override file.
func preserveEnvironmentControlledValues(active, desired Config) Config {
	if fieldLocked("mfaEnabled") {
		desired.MFAEnabled = active.MFAEnabled
	}
	if fieldLocked("mfaMethods") {
		desired.MFAMethods = append([]string{}, active.MFAMethods...)
	}
	if fieldLocked("emailCodeTTL") {
		desired.EmailCodeTTL = active.EmailCodeTTL
	}
	if fieldLocked("smtpHost") {
		desired.SMTPHost = active.SMTPHost
	}
	if fieldLocked("smtpPort") {
		desired.SMTPPort = active.SMTPPort
		desired.SMTPTLSMode = active.SMTPTLSMode
	}
	if fieldLocked("smtpUsername") {
		desired.SMTPUsername = active.SMTPUsername
	}
	if fieldLocked("smtpPassword") {
		desired.SMTPPassword = active.SMTPPassword
	}
	if fieldLocked("smtpFrom") {
		desired.SMTPFrom = active.SMTPFrom
	}
	if fieldLocked("tlsCertFile") {
		desired.TLSCertFile = active.TLSCertFile
	}
	if fieldLocked("tlsKeyFile") {
		desired.TLSKeyFile = active.TLSKeyFile
	}
	if fieldLocked("accessTlsCertFile") {
		desired.AccessTLSCertFile = active.AccessTLSCertFile
	}
	if fieldLocked("accessTlsKeyFile") {
		desired.AccessTLSKeyFile = active.AccessTLSKeyFile
	}
	if fieldLocked("reusePanelPorts") || fieldLocked("accessHttpPort") || fieldLocked("accessHttpsPort") {
		desired.AccessHTTPPort = active.AccessHTTPPort
		desired.AccessHTTPSPort = active.AccessHTTPSPort
	}
	if fieldLocked("httpPort") {
		desired.ListenAddress = active.ListenAddress
	}
	if fieldLocked("httpsPort") {
		desired.HTTPSListenAddress = active.HTTPSListenAddress
	}
	if fieldLocked("panelDomain") {
		desired.PanelDomain = active.PanelDomain
	}
	if fieldLocked("accessDomain") {
		desired.AccessDomain = active.AccessDomain
		desired.AccessScheme = active.AccessScheme
	}
	if strings.TrimSpace(os.Getenv("DMP_ACCESS_SCHEME")) != "" {
		desired.AccessScheme = active.AccessScheme
	}
	return desired
}

func panelSettingsFromConfig(cfg Config) PanelSettings {
	return PanelSettings{
		MFAEnabled: cfg.MFAEnabled, MFAMethods: append([]string{}, cfg.MFAMethods...), EmailCodeTTL: formatDurationMinutes(cfg.EmailCodeTTL),
		MFAKeyFile: cfg.MFAKeyFile, SMTPHost: cfg.SMTPHost, SMTPPort: cfg.SMTPPort, SMTPUsername: cfg.SMTPUsername,
		SMTPPasswordConfigured: cfg.SMTPPassword != "", SMTPConfigured: cfg.SMTPHost != "" && cfg.SMTPFrom != "", SMTPFrom: cfg.SMTPFrom,
		TLSCertFile: cfg.TLSCertFile, TLSKeyFile: cfg.TLSKeyFile, TLSConfigured: cfg.TLSCertFile != "" && cfg.TLSKeyFile != "",
		AccessTLSCertFile: cfg.AccessTLSCertFile, AccessTLSKeyFile: cfg.AccessTLSKeyFile, AccessTLSConfigured: cfg.AccessTLSCertFile != "" && cfg.AccessTLSKeyFile != "",
		ReusePanelPorts: cfg.AccessHTTPPort == 0 && cfg.AccessHTTPSPort == 0, AccessHTTPPort: cfg.AccessHTTPPort, AccessHTTPSPort: cfg.AccessHTTPSPort,
		HTTPPort: listenPort(cfg.ListenAddress), HTTPSPort: listenPort(cfg.HTTPSListenAddress), PanelDomain: cfg.PanelDomain, AccessDomain: cfg.AccessDomain,
	}
}

func listenPort(address string) int {
	_, value, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(value)
	return port
}

func listenAddressWithPort(address string, port int) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func formatDurationMinutes(value time.Duration) string {
	return strconv.FormatInt(int64(value/time.Minute), 10) + "m"
}

func applyEditableValues(cfg Config, values map[string]string) Config {
	if value, ok := values["mfa_enabled"]; ok {
		cfg.MFAEnabled, _ = strconv.ParseBool(value)
	}
	if value, ok := values["mfa_methods"]; ok {
		cfg.MFAMethods = splitList(value)
	}
	if value, ok := values["mfa_email_code_ttl"]; ok {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.EmailCodeTTL = parsed
		}
	}
	if value, ok := values["smtp_host"]; ok {
		cfg.SMTPHost = value
	}
	if value, ok := values["smtp_port"]; ok {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.SMTPPort = parsed
		}
	}
	if value, ok := values["smtp_username"]; ok {
		cfg.SMTPUsername = value
	}
	if value, ok := values["smtp_from"]; ok {
		cfg.SMTPFrom = value
	}
	cfg.SMTPTLSMode = smtpTLSModeForPort(cfg.SMTPPort)
	if value, ok := values["tls_cert_file"]; ok {
		cfg.TLSCertFile = value
	}
	if value, ok := values["tls_key_file"]; ok {
		cfg.TLSKeyFile = value
	}
	if value, ok := values["access_tls_cert_file"]; ok {
		cfg.AccessTLSCertFile = value
	}
	if value, ok := values["access_tls_key_file"]; ok {
		cfg.AccessTLSKeyFile = value
	}
	if value, ok := values["access_http_port"]; ok {
		cfg.AccessHTTPPort, _ = parseOptionalPort(value, "access_http_port")
	}
	if value, ok := values["access_https_port"]; ok {
		cfg.AccessHTTPSPort, _ = parseOptionalPort(value, "access_https_port")
	}
	if value, ok := values["listen_addr"]; ok {
		cfg.ListenAddress = value
	}
	if value, ok := values["https_listen_addr"]; ok {
		cfg.HTTPSListenAddress = value
	}
	if value, ok := values["panel_domain"]; ok {
		cfg.PanelDomain = value
	}
	if value, ok := values["access_domain"]; ok {
		cfg.AccessDomain = value
	}
	if value, ok := values["access_scheme"]; ok {
		cfg.AccessScheme = value
	}
	if value, ok := values["smtp_password_file"]; ok && strings.TrimSpace(value) != "" {
		if content, err := os.ReadFile(strings.TrimSpace(value)); err == nil {
			cfg.SMTPPassword = strings.TrimSpace(string(content))
		}
	}
	return cfg
}

func renderOverride(cfg Config, smtpPasswordFile string) string {
	lines := []string{
		"# 由 设备管理平台 系统设置生成。可由部署配置或环境变量覆盖。",
		"mfa_enabled = " + strconv.FormatBool(cfg.MFAEnabled),
		"mfa_methods = " + strings.Join(cfg.MFAMethods, ","),
		"mfa_email_code_ttl = " + cfg.EmailCodeTTL.String(),
		"smtp_host = " + cfg.SMTPHost,
		"smtp_port = " + strconv.Itoa(cfg.SMTPPort),
		"smtp_username = " + cfg.SMTPUsername,
		"smtp_password = ",
		"smtp_from = " + cfg.SMTPFrom,
		"tls_cert_file = " + cfg.TLSCertFile,
		"tls_key_file = " + cfg.TLSKeyFile,
		"access_tls_cert_file = " + cfg.AccessTLSCertFile,
		"access_tls_key_file = " + cfg.AccessTLSKeyFile,
		"access_http_port = " + strconv.Itoa(cfg.AccessHTTPPort),
		"access_https_port = " + strconv.Itoa(cfg.AccessHTTPSPort),
		"listen_addr = " + cfg.ListenAddress,
		"https_listen_addr = " + cfg.HTTPSListenAddress,
		"panel_domain = " + cfg.PanelDomain,
		"access_domain = " + cfg.AccessDomain,
		"access_scheme = " + cfg.AccessScheme,
	}
	if smtpPasswordFile != "" {
		lines = append(lines, "smtp_password_file = "+smtpPasswordFile)
	}
	return strings.Join(lines, "\n") + "\n"
}

func writePrivateFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".platform-settings-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func configuredSMTPPasswordFile(cfg Config) string {
	if path := strings.TrimSpace(os.Getenv("DMP_SMTP_PASSWORD_FILE")); path != "" {
		return path
	}
	if values, err := readConfigFile(cfg.OverrideFile); err == nil {
		if path := strings.TrimSpace(values["smtp_password_file"]); path != "" {
			return path
		}
	}
	if values, err := readConfigFile(cfg.ConfigFile); err == nil {
		return strings.TrimSpace(values["smtp_password_file"])
	}
	return ""
}

func normalizedMethods(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func sameEditableConfig(left, right Config) bool {
	return left.MFAEnabled == right.MFAEnabled && methodsKey(left.MFAMethods) == methodsKey(right.MFAMethods) &&
		left.EmailCodeTTL == right.EmailCodeTTL && left.SMTPHost == right.SMTPHost && left.SMTPPort == right.SMTPPort &&
		left.SMTPUsername == right.SMTPUsername && left.SMTPPassword == right.SMTPPassword && left.SMTPFrom == right.SMTPFrom &&
		left.TLSCertFile == right.TLSCertFile && left.TLSKeyFile == right.TLSKeyFile && left.AccessTLSCertFile == right.AccessTLSCertFile && left.AccessTLSKeyFile == right.AccessTLSKeyFile &&
		left.AccessHTTPPort == right.AccessHTTPPort && left.AccessHTTPSPort == right.AccessHTTPSPort &&
		left.ListenAddress == right.ListenAddress && left.HTTPSListenAddress == right.HTTPSListenAddress && left.PanelDomain == right.PanelDomain &&
		left.AccessDomain == right.AccessDomain && left.AccessScheme == right.AccessScheme
}

var editableEnvironment = map[string]string{
	"mfaEnabled": "DMP_MFA_ENABLED", "mfaMethods": "DMP_MFA_METHODS", "emailCodeTTL": "DMP_MFA_EMAIL_CODE_TTL",
	"smtpHost": "DMP_SMTP_HOST", "smtpPort": "DMP_SMTP_PORT", "smtpUsername": "DMP_SMTP_USERNAME",
	"smtpPassword": "DMP_SMTP_PASSWORD", "smtpFrom": "DMP_SMTP_FROM",
	"tlsCertFile": "DMP_TLS_CERT_FILE", "tlsKeyFile": "DMP_TLS_KEY_FILE",
	"accessTlsCertFile": "DMP_ACCESS_TLS_CERT_FILE", "accessTlsKeyFile": "DMP_ACCESS_TLS_KEY_FILE",
	"reusePanelPorts": "DMP_ACCESS_HTTP_PORT,DMP_ACCESS_HTTPS_PORT", "accessHttpPort": "DMP_ACCESS_HTTP_PORT", "accessHttpsPort": "DMP_ACCESS_HTTPS_PORT",
	"panelDomain": "DMP_PANEL_DOMAIN", "accessDomain": "DMP_ACCESS_DOMAIN",
	"httpPort": "DMP_LISTEN_ADDR", "httpsPort": "DMP_HTTPS_LISTEN_ADDR",
}

func environmentLockedFields() []string {
	locked := []string{}
	for field, envName := range editableEnvironment {
		lockedByEnvironment := false
		for _, candidate := range strings.Split(envName, ",") {
			if strings.TrimSpace(os.Getenv(candidate)) != "" {
				lockedByEnvironment = true
				break
			}
		}
		if lockedByEnvironment {
			locked = append(locked, field)
		}
	}
	if strings.TrimSpace(os.Getenv("DMP_SMTP_PASSWORD_FILE")) != "" {
		locked = append(locked, "smtpPassword")
	}
	sort.Strings(locked)
	return locked
}

func fieldLocked(field string) bool {
	for _, locked := range environmentLockedFields() {
		if locked == field {
			return true
		}
	}
	return false
}

func rejectLockedChanges(active, candidate Config) error {
	locked := map[string]bool{}
	for _, field := range environmentLockedFields() {
		locked[field] = true
	}
	checks := map[string]bool{
		"mfaEnabled": active.MFAEnabled != candidate.MFAEnabled, "mfaMethods": methodsKey(active.MFAMethods) != methodsKey(candidate.MFAMethods),
		"emailCodeTTL": active.EmailCodeTTL != candidate.EmailCodeTTL, "smtpHost": active.SMTPHost != candidate.SMTPHost,
		"smtpPort": active.SMTPPort != candidate.SMTPPort, "smtpUsername": active.SMTPUsername != candidate.SMTPUsername,
		"smtpFrom":    active.SMTPFrom != candidate.SMTPFrom,
		"tlsCertFile": active.TLSCertFile != candidate.TLSCertFile, "tlsKeyFile": active.TLSKeyFile != candidate.TLSKeyFile,
		"accessTlsCertFile": active.AccessTLSCertFile != candidate.AccessTLSCertFile, "accessTlsKeyFile": active.AccessTLSKeyFile != candidate.AccessTLSKeyFile,
		"reusePanelPorts": (active.AccessHTTPPort == 0 && active.AccessHTTPSPort == 0) != (candidate.AccessHTTPPort == 0 && candidate.AccessHTTPSPort == 0),
		"accessHttpPort":  active.AccessHTTPPort != candidate.AccessHTTPPort, "accessHttpsPort": active.AccessHTTPSPort != candidate.AccessHTTPSPort,
		"httpPort": active.ListenAddress != candidate.ListenAddress, "httpsPort": active.HTTPSListenAddress != candidate.HTTPSListenAddress,
		"panelDomain": active.PanelDomain != candidate.PanelDomain, "accessDomain": active.AccessDomain != candidate.AccessDomain,
	}
	for field, changed := range checks {
		if locked[field] && changed {
			return fmt.Errorf("%s is controlled by an environment variable", field)
		}
	}
	return nil
}

func methodsKey(methods []string) string {
	copyOfMethods := append([]string{}, methods...)
	sort.Strings(copyOfMethods)
	return strings.Join(copyOfMethods, ",")
}
