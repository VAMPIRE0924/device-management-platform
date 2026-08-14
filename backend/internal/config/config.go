package config

import (
	"bufio"
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
	ConfigFile        string
	OverrideFile      string
	Mode              string
	ListenAddress     string
	DataDirectory     string
	DatabasePath      string
	APIToken          string
	SetupToken        string
	MFAEnabled        bool
	MFAMethods        []string
	MFAKeyFile        string
	EmailCodeTTL      time.Duration
	SMTPHost          string
	SMTPPort          int
	SMTPUsername      string
	SMTPPassword      string
	SMTPFrom          string
	SMTPTLSMode       string
	TLSCertFile       string
	TLSKeyFile        string
	PanelDomain       string
	AccessDomain      string
	AccessScheme      string
	TrustedProxyCIDRs []string
	CookieSecure      bool
}

func Load() (Config, error) {
	configPath := strings.TrimSpace(os.Getenv("I5CLOUD_CONFIG_FILE"))
	if configPath == "" {
		configPath = "./conf/i5cloud.conf"
	}
	values, err := readConfigFile(configPath)
	if err != nil {
		return Config{}, err
	}
	dataDirectory := firstConfigured(os.Getenv("I5CLOUD_DATA_DIR"), values["data_dir"], "./data")
	overridePath := firstConfigured(os.Getenv("I5CLOUD_SETTINGS_OVERRIDE_FILE"), values["settings_override_file"], filepath.Join(dataDirectory, "i5cloud.override.conf"))
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
	dataDirectory = value("I5CLOUD_DATA_DIR", "data_dir", dataDirectory)
	databasePath := value("I5CLOUD_DB_PATH", "database_path", filepath.Join(dataDirectory, "i5cloud.db"))
	apiToken, err := loadConfiguredSecret("I5CLOUD_API_TOKEN", "I5CLOUD_API_TOKEN_FILE", values["api_token"], values["api_token_file"])
	if err != nil {
		return Config{}, err
	}
	setupToken, err := loadConfiguredSecret("I5CLOUD_SETUP_TOKEN", "I5CLOUD_SETUP_TOKEN_FILE", values["setup_token"], values["setup_token_file"])
	if err != nil {
		return Config{}, err
	}
	smtpPassword, err := loadConfiguredSecret("I5CLOUD_SMTP_PASSWORD", "I5CLOUD_SMTP_PASSWORD_FILE", values["smtp_password"], values["smtp_password_file"])
	if err != nil {
		return Config{}, err
	}
	mfaEnabled, err := parseBool(value("I5CLOUD_MFA_ENABLED", "mfa_enabled", "false"), "mfa_enabled")
	if err != nil {
		return Config{}, err
	}
	cookieSecure, err := parseBool(value("I5CLOUD_COOKIE_SECURE", "cookie_secure", ""), "cookie_secure")
	if err != nil {
		return Config{}, err
	}
	smtpPort, err := parsePort(value("I5CLOUD_SMTP_PORT", "smtp_port", "587"), "smtp_port")
	if err != nil {
		return Config{}, err
	}
	emailCodeTTL, err := time.ParseDuration(value("I5CLOUD_MFA_EMAIL_CODE_TTL", "mfa_email_code_ttl", "10m"))
	if err != nil || emailCodeTTL < time.Minute || emailCodeTTL > 30*time.Minute {
		return Config{}, fmt.Errorf("mfa_email_code_ttl must be between 1m and 30m")
	}
	cfg := Config{
		ConfigFile:        configPath,
		OverrideFile:      overridePath,
		Mode:              strings.ToLower(value("I5CLOUD_MODE", "run_mode", "dev")),
		ListenAddress:     value("I5CLOUD_LISTEN_ADDR", "listen_addr", "127.0.0.1:8088"),
		DataDirectory:     dataDirectory,
		DatabasePath:      databasePath,
		APIToken:          apiToken,
		SetupToken:        setupToken,
		MFAEnabled:        mfaEnabled,
		MFAMethods:        splitList(value("I5CLOUD_MFA_METHODS", "mfa_methods", "totp")),
		MFAKeyFile:        value("I5CLOUD_MFA_KEY_FILE", "mfa_key_file", filepath.Join(filepath.Dir(databasePath), "mfa.key")),
		EmailCodeTTL:      emailCodeTTL,
		SMTPHost:          value("I5CLOUD_SMTP_HOST", "smtp_host", ""),
		SMTPPort:          smtpPort,
		SMTPUsername:      value("I5CLOUD_SMTP_USERNAME", "smtp_username", ""),
		SMTPPassword:      smtpPassword,
		SMTPFrom:          value("I5CLOUD_SMTP_FROM", "smtp_from", ""),
		SMTPTLSMode:       smtpTLSModeForPort(smtpPort),
		TLSCertFile:       value("I5CLOUD_TLS_CERT_FILE", "tls_cert_file", ""),
		TLSKeyFile:        value("I5CLOUD_TLS_KEY_FILE", "tls_key_file", ""),
		PanelDomain:       strings.ToLower(strings.Trim(value("I5CLOUD_PANEL_DOMAIN", "panel_domain", ""), ".")),
		AccessDomain:      strings.ToLower(strings.Trim(value("I5CLOUD_ACCESS_DOMAIN", "access_domain", ""), ".")),
		AccessScheme:      strings.ToLower(value("I5CLOUD_ACCESS_SCHEME", "access_scheme", "https")),
		TrustedProxyCIDRs: splitList(value("I5CLOUD_TRUSTED_PROXY_CIDRS", "trusted_proxy_cidrs", "")),
	}
	if strings.TrimSpace(os.Getenv("I5CLOUD_COOKIE_SECURE")) == "" && strings.TrimSpace(values["cookie_secure"]) == "" {
		cfg.CookieSecure = cfg.Mode == "pro"
	} else {
		cfg.CookieSecure = cookieSecure
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
	if cfg.Mode == "pro" && len(cfg.SetupToken) < 24 {
		return fmt.Errorf("setup_token must contain at least 24 characters in pro mode")
	}
	if cfg.Mode == "pro" && cfg.APIToken == cfg.SetupToken {
		return fmt.Errorf("api_token and setup_token must be different in pro mode")
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
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("trusted_proxy_cidrs contains invalid CIDR %q", cidr)
		}
	}
	if strings.TrimSpace(cfg.ListenAddress) == "" || strings.TrimSpace(cfg.DatabasePath) == "" || strings.TrimSpace(cfg.MFAKeyFile) == "" {
		return fmt.Errorf("listen_addr, database_path and mfa_key_file cannot be empty")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return fmt.Errorf("tls_cert_file and tls_key_file must be configured together")
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
	if cfg.Mode == "pro" && !cfg.CookieSecure && !listenIsLoopback(cfg.ListenAddress) {
		return fmt.Errorf("cookie_secure may be false in pro mode only on a loopback listener")
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

func listenIsLoopback(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed, err := netip.ParseAddr(host)
	return err == nil && parsed.IsLoopback()
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
