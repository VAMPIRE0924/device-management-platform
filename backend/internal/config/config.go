package config

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ConfigFile         string
	OverrideFile       string
	Mode               string
	ListenAddress      string
	HTTPSListenAddress string
	DataDirectory      string
	DatabasePath       string
	APIToken           string
	MFAEnabled         bool
	MFAMethods         []string
	MFAKeyFile         string
	EmailCodeTTL       time.Duration
	AuthSessionTTL     time.Duration
	AuthSessionIdleTTL time.Duration
	SMTPHost           string
	SMTPPort           int
	SMTPUsername       string
	SMTPPassword       string
	SMTPFrom           string
	SMTPTLSMode        string
	TLSCertFile        string
	TLSKeyFile         string
	AccessTLSCertFile  string
	AccessTLSKeyFile   string
	AccessHTTPPort     int
	AccessHTTPSPort    int
	PanelDomain        string
	AccessDomain       string
	AccessScheme       string
	TrustedProxyCIDRs  []string
}

func Load() (Config, error) {
	configPath := strings.TrimSpace(os.Getenv("DMP_CONFIG_FILE"))
	if configPath == "" {
		configPath = "./conf/device-management-platform.conf"
	}
	values, err := readConfigFile(configPath)
	if err != nil {
		return Config{}, err
	}
	dataDirectory := firstConfigured(os.Getenv("DMP_DATA_DIR"), values["data_dir"], "./data")
	overridePath := firstConfigured(os.Getenv("DMP_SETTINGS_OVERRIDE_FILE"), values["settings_override_file"], filepath.Join(dataDirectory, "settings.override.conf"))
	overrides, err := readConfigFile(overridePath)
	if err != nil {
		return Config{}, fmt.Errorf("read settings override: %w", err)
	}
	for key, configured := range overrides {
		values[key] = configured
	}
	value := func(envName, key, fallback string) string {
		if configured := strings.TrimSpace(os.Getenv(envName)); configured != "" {
			return configured
		}
		if configured, exists := values[key]; exists {
			return strings.TrimSpace(configured)
		}
		return fallback
	}
	dataDirectory = value("DMP_DATA_DIR", "data_dir", dataDirectory)
	databasePath := value("DMP_DB_PATH", "database_path", filepath.Join(dataDirectory, "platform.db"))
	mode := strings.ToLower(value("DMP_MODE", "run_mode", "pro"))
	apiToken, err := loadConfiguredSecret("DMP_API_TOKEN", "DMP_API_TOKEN_FILE", values["api_token"], values["api_token_file"])
	if err != nil {
		return Config{}, err
	}
	if mode == "pro" && apiToken == "" {
		apiToken, err = loadOrCreateAPIToken(filepath.Join(dataDirectory, "api.token"))
		if err != nil {
			return Config{}, err
		}
	}
	smtpPassword, err := loadConfiguredSecret("DMP_SMTP_PASSWORD", "DMP_SMTP_PASSWORD_FILE", values["smtp_password"], values["smtp_password_file"])
	if err != nil {
		return Config{}, err
	}
	mfaEnabled, err := parseBool(value("DMP_MFA_ENABLED", "mfa_enabled", "false"), "mfa_enabled")
	if err != nil {
		return Config{}, err
	}
	smtpPort, err := parsePort(value("DMP_SMTP_PORT", "smtp_port", "587"), "smtp_port")
	if err != nil {
		return Config{}, err
	}
	accessHTTPPort, err := parseOptionalPort(value("DMP_ACCESS_HTTP_PORT", "access_http_port", "0"), "access_http_port")
	if err != nil {
		return Config{}, err
	}
	accessHTTPSPort, err := parseOptionalPort(value("DMP_ACCESS_HTTPS_PORT", "access_https_port", "0"), "access_https_port")
	if err != nil {
		return Config{}, err
	}
	emailCodeTTL, err := time.ParseDuration(value("DMP_MFA_EMAIL_CODE_TTL", "mfa_email_code_ttl", "10m"))
	if err != nil || emailCodeTTL < time.Minute || emailCodeTTL > 30*time.Minute {
		return Config{}, fmt.Errorf("mfa_email_code_ttl must be between 1m and 30m")
	}
	authSessionTTL, err := time.ParseDuration(value("DMP_AUTH_SESSION_TTL", "auth_session_ttl", "12h"))
	if err != nil || authSessionTTL < time.Hour || authSessionTTL > 30*24*time.Hour {
		return Config{}, fmt.Errorf("auth_session_ttl must be between 1h and 720h")
	}
	authSessionIdleTTL, err := time.ParseDuration(value("DMP_AUTH_SESSION_IDLE_TTL", "auth_session_idle_ttl", "15m"))
	if err != nil || authSessionIdleTTL < 5*time.Minute || authSessionIdleTTL > 24*time.Hour || authSessionIdleTTL > authSessionTTL {
		return Config{}, fmt.Errorf("auth_session_idle_ttl must be between 5m and 24h and not exceed auth_session_ttl")
	}
	cfg := Config{
		ConfigFile:         configPath,
		OverrideFile:       overridePath,
		Mode:               mode,
		ListenAddress:      value("DMP_LISTEN_ADDR", "listen_addr", "0.0.0.0:80"),
		HTTPSListenAddress: value("DMP_HTTPS_LISTEN_ADDR", "https_listen_addr", "0.0.0.0:443"),
		DataDirectory:      dataDirectory,
		DatabasePath:       databasePath,
		APIToken:           apiToken,
		MFAEnabled:         mfaEnabled,
		MFAMethods:         splitList(value("DMP_MFA_METHODS", "mfa_methods", "totp")),
		MFAKeyFile:         value("DMP_MFA_KEY_FILE", "mfa_key_file", filepath.Join(filepath.Dir(databasePath), "mfa.key")),
		EmailCodeTTL:       emailCodeTTL,
		AuthSessionTTL:     authSessionTTL,
		AuthSessionIdleTTL: authSessionIdleTTL,
		SMTPHost:           value("DMP_SMTP_HOST", "smtp_host", ""),
		SMTPPort:           smtpPort,
		SMTPUsername:       value("DMP_SMTP_USERNAME", "smtp_username", ""),
		SMTPPassword:       smtpPassword,
		SMTPFrom:           value("DMP_SMTP_FROM", "smtp_from", ""),
		SMTPTLSMode:        smtpTLSModeForPort(smtpPort),
		TLSCertFile:        value("DMP_TLS_CERT_FILE", "tls_cert_file", ""),
		TLSKeyFile:         value("DMP_TLS_KEY_FILE", "tls_key_file", ""),
		AccessTLSCertFile:  value("DMP_ACCESS_TLS_CERT_FILE", "access_tls_cert_file", ""),
		AccessTLSKeyFile:   value("DMP_ACCESS_TLS_KEY_FILE", "access_tls_key_file", ""),
		AccessHTTPPort:     accessHTTPPort,
		AccessHTTPSPort:    accessHTTPSPort,
		PanelDomain:        strings.ToLower(strings.Trim(value("DMP_PANEL_DOMAIN", "panel_domain", ""), ".")),
		AccessDomain:       strings.ToLower(strings.Trim(value("DMP_ACCESS_DOMAIN", "access_domain", ""), ".")),
		AccessScheme:       strings.ToLower(value("DMP_ACCESS_SCHEME", "access_scheme", "https")),
		TrustedProxyCIDRs:  splitList(value("DMP_TRUSTED_PROXY_CIDRS", "trusted_proxy_cidrs", "")),
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func firstConfigured(values ...string) string {
	for _, value := range values {
		if configured := strings.TrimSpace(value); configured != "" {
			return configured
		}
	}
	return ""
}

func (cfg Config) validate() error {
	if cfg.Mode != "dev" && cfg.Mode != "pro" {
		return fmt.Errorf("run_mode must be dev or pro")
	}
	if cfg.Mode == "pro" && len(cfg.APIToken) < 32 {
		return fmt.Errorf("api_token must contain at least 32 characters in pro mode")
	}
	if cfg.AccessScheme != "http" && cfg.AccessScheme != "https" {
		return fmt.Errorf("access_scheme must be http or https")
	}
	if strings.ContainsAny(cfg.AccessDomain, "/: ") {
		return fmt.Errorf("access_domain must be a DNS name without scheme or port")
	}
	if strings.ContainsAny(cfg.PanelDomain, "/: ") {
		return fmt.Errorf("panel_domain must be a DNS name without scheme or port")
	}
	if cfg.PanelDomain != "" && cfg.AccessDomain != "" && (cfg.PanelDomain == cfg.AccessDomain || strings.HasSuffix(cfg.PanelDomain, "."+cfg.AccessDomain)) {
		return fmt.Errorf("panel_domain must not equal or be a subdomain of access_domain")
	}
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("trusted_proxy_cidrs contains invalid CIDR %q", cidr)
		}
	}
	if strings.TrimSpace(cfg.ListenAddress) == "" || strings.TrimSpace(cfg.HTTPSListenAddress) == "" || strings.TrimSpace(cfg.DatabasePath) == "" || strings.TrimSpace(cfg.MFAKeyFile) == "" {
		return fmt.Errorf("listen_addr, https_listen_addr, database_path and mfa_key_file cannot be empty")
	}
	_, httpPort, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen_addr must contain a valid host and port: %w", err)
	}
	if _, err := parsePort(httpPort, "listen_addr"); err != nil {
		return err
	}
	_, httpsPort, err := net.SplitHostPort(cfg.HTTPSListenAddress)
	if err != nil {
		return fmt.Errorf("https_listen_addr must contain a valid host and port: %w", err)
	}
	if _, err := parsePort(httpsPort, "https_listen_addr"); err != nil {
		return err
	}
	if httpPort == httpsPort {
		return fmt.Errorf("listen_addr and https_listen_addr must use different ports")
	}
	if (cfg.AccessHTTPPort == 0) != (cfg.AccessHTTPSPort == 0) {
		return fmt.Errorf("access_http_port and access_https_port must both be zero for reuse or both be configured")
	}
	if cfg.AccessHTTPPort != 0 {
		if cfg.AccessDomain == "" {
			return fmt.Errorf("access_domain is required when independent access ports are configured")
		}
		if cfg.AccessHTTPPort == cfg.AccessHTTPSPort {
			return fmt.Errorf("access_http_port and access_https_port must use different ports")
		}
		panelHTTPPort, _ := strconv.Atoi(httpPort)
		panelHTTPSPort, _ := strconv.Atoi(httpsPort)
		if cfg.AccessHTTPPort == panelHTTPPort || cfg.AccessHTTPPort == panelHTTPSPort || cfg.AccessHTTPSPort == panelHTTPPort || cfg.AccessHTTPSPort == panelHTTPSPort {
			return fmt.Errorf("independent access ports cannot conflict with panel HTTP or HTTPS ports")
		}
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("tls_cert_file and tls_key_file must be configured together")
	}
	if (cfg.AccessTLSCertFile == "") != (cfg.AccessTLSKeyFile == "") {
		return fmt.Errorf("access_tls_cert_file and access_tls_key_file must be configured together")
	}
	if cfg.AccessTLSCertFile != "" && cfg.TLSCertFile == "" {
		return fmt.Errorf("panel TLS certificate must be configured before an access TLS certificate")
	}
	if cfg.AccessTLSCertFile != "" && cfg.AccessDomain == "" {
		return fmt.Errorf("access_domain is required when an access TLS certificate is configured")
	}
	allowedMethods := map[string]bool{"totp": true, "email": true}
	seen := map[string]bool{}
	for _, method := range cfg.MFAMethods {
		if !allowedMethods[method] || seen[method] {
			return fmt.Errorf("mfa_methods supports unique values totp and email")
		}
		seen[method] = true
	}
	if cfg.MFAEnabled && len(cfg.MFAMethods) == 0 {
		return fmt.Errorf("mfa_methods cannot be empty when mfa_enabled=true")
	}
	if cfg.MFAEnabled {
		if cfg.SMTPHost == "" || cfg.SMTPFrom == "" {
			return fmt.Errorf("smtp_host and smtp_from are required when MFA is enabled because first login verifies email")
		}
		if _, err := mail.ParseAddress(cfg.SMTPFrom); err != nil {
			return fmt.Errorf("smtp_from is invalid: %w", err)
		}
	}
	localWildcardDomain := isLocalAccessDomain(cfg.AccessDomain)
	if cfg.Mode == "pro" && cfg.AccessDomain != "" && cfg.AccessScheme != "https" && !localWildcardDomain {
		return fmt.Errorf("access_scheme must be https when access_domain is configured in pro mode")
	}
	return nil
}

func isLocalAccessDomain(domain string) bool {
	return domain == "localhost" || strings.HasSuffix(domain, ".localhost") || strings.HasSuffix(domain, ".127.0.0.1.nip.io")
}

func readConfigFile(path string) (map[string]string, error) {
	values := map[string]string{}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return values, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, configured, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid config line %d", lineNumber)
		}
		configured = strings.TrimSpace(configured)
		if len(configured) >= 2 && ((configured[0] == '"' && configured[len(configured)-1] == '"') || (configured[0] == '\'' && configured[len(configured)-1] == '\'')) {
			configured = configured[1 : len(configured)-1]
		}
		values[strings.ToLower(strings.TrimSpace(key))] = configured
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return values, nil
}

func smtpTLSModeForPort(port int) string {
	if port == 465 {
		return "tls"
	}
	return "starttls"
}

func splitList(value string) []string {
	items := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' })
	return items
}

func loadConfiguredSecret(valueName, fileName, configuredValue, configuredFile string) (string, error) {
	if secret := strings.TrimSpace(os.Getenv(valueName)); secret != "" {
		return secret, nil
	}
	secret := strings.TrimSpace(configuredValue)
	secretFile := strings.TrimSpace(os.Getenv(fileName))
	if secretFile == "" {
		secretFile = strings.TrimSpace(configuredFile)
	}
	if secret != "" {
		return secret, nil
	}
	if secretFile == "" {
		return "", nil
	}
	content, err := os.ReadFile(secretFile)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", fileName, err)
	}
	secret = strings.TrimSpace(string(content))
	if secret == "" {
		return "", fmt.Errorf("%s points to an empty secret", fileName)
	}
	return secret, nil
}

func loadOrCreateAPIToken(path string) (string, error) {
	if content, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(content))
		if len(token) < 32 {
			return "", fmt.Errorf("generated API token file %s is invalid", path)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return "", fmt.Errorf("secure generated API token file: %w", err)
		}
		return token, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read generated API token: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("create data directory for generated API token: %w", err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate API token: %w", err)
	}
	token := hex.EncodeToString(random)
	temporary, err := os.CreateTemp(filepath.Dir(path), ".api-token-*")
	if err != nil {
		return "", fmt.Errorf("create generated API token file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", fmt.Errorf("secure generated API token file: %w", err)
	}
	if _, err := temporary.WriteString(token + "\n"); err != nil {
		temporary.Close()
		return "", fmt.Errorf("write generated API token: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", fmt.Errorf("sync generated API token: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close generated API token: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return "", fmt.Errorf("install generated API token: %w", err)
	}
	return token, nil
}

func parseBool(value, name string) (bool, error) {
	if strings.TrimSpace(value) == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", name)
	}
	return parsed, nil
}

func parsePort(value, name string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed < 1 || parsed > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", name)
	}
	return parsed, nil
}

func parseOptionalPort(value, name string) (int, error) {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) == "0" {
		return 0, nil
	}
	return parsePort(value, name)
}
