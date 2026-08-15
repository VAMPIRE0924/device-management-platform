package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionRequiresStrongToken(t *testing.T) {
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected production token validation error")
	}
}

func TestReadsTokenFromSecretFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-token")
	token := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "")
	t.Setenv("DMP_API_TOKEN_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIToken != token {
		t.Fatalf("unexpected token %q", cfg.APIToken)
	}
}

func TestProductionGeneratesAndPersistsAPIToken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_DATA_DIR", dir)
	t.Setenv("DMP_DB_PATH", filepath.Join(dir, "platform.db"))
	t.Setenv("DMP_API_TOKEN", "")
	t.Setenv("DMP_API_TOKEN_FILE", "")
	first, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.APIToken) != 64 {
		t.Fatalf("generated API token length = %d, want 64", len(first.APIToken))
	}
	second, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if second.APIToken != first.APIToken {
		t.Fatal("generated API token did not persist across reload")
	}
	info, err := os.Stat(filepath.Join(dir, "api.token"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("generated API token mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("DMP_TRUSTED_PROXY_CIDRS", "10.0.0.0/24,not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid trusted proxy CIDR error")
	}
}

func TestDefaultListenerPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DMP_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("DMP_DATA_DIR", dir)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "0.0.0.0:80" || cfg.HTTPSListenAddress != "0.0.0.0:443" {
		t.Fatalf("default listeners = %q and %q", cfg.ListenAddress, cfg.HTTPSListenAddress)
	}
}

func TestRejectsInvalidOrDuplicateListenerPorts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DMP_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("DMP_DATA_DIR", dir)
	t.Setenv("DMP_LISTEN_ADDR", "0.0.0.0:70000")
	if _, err := Load(); err == nil {
		t.Fatal("expected out-of-range HTTP port to be rejected")
	}
	t.Setenv("DMP_LISTEN_ADDR", "0.0.0.0:443")
	if _, err := Load(); err == nil {
		t.Fatal("expected duplicate HTTP and HTTPS ports to be rejected")
	}
}

func TestProductionAllowsHTTPLoginOnPublicListener(t *testing.T) {
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("DMP_LISTEN_ADDR", "0.0.0.0:18080")
	_, err := Load()
	if err != nil {
		t.Fatalf("direct HTTP production config rejected: %v", err)
	}
}

func TestProductionAllowsLoopbackHTTP(t *testing.T) {
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("DMP_LISTEN_ADDR", "127.0.0.1:18080")
	if _, err := Load(); err != nil {
		t.Fatalf("loopback acceptance config rejected: %v", err)
	}
}

func TestProductionAccessDomainRequiresHTTPS(t *testing.T) {
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("DMP_ACCESS_DOMAIN", "remote.example.com")
	t.Setenv("DMP_ACCESS_SCHEME", "http")
	if _, err := Load(); err == nil {
		t.Fatal("expected production access domain HTTPS validation error")
	}
}

func TestProductionLocalWildcardDomainAllowsHTTPAcceptance(t *testing.T) {
	t.Setenv("DMP_MODE", "pro")
	t.Setenv("DMP_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("DMP_ACCESS_DOMAIN", "admin.platform.localhost")
	t.Setenv("DMP_ACCESS_SCHEME", "http")
	if _, err := Load(); err != nil {
		t.Fatalf("local wildcard acceptance config rejected: %v", err)
	}
	t.Setenv("DMP_ACCESS_DOMAIN", "admin.platform.127.0.0.1.nip.io")
	if _, err := Load(); err != nil {
		t.Fatalf("loopback wildcard DNS acceptance config rejected: %v", err)
	}
}

func TestReadsPanelConfigWithMandatoryEmailVerification(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "platform.conf")
	content := `
run_mode = pro
listen_addr = 127.0.0.1:18080
database_path = ` + filepath.Join(dir, "panel.db") + `
api_token = api-token-0123456789abcdef0123456789
mfa_enabled = true
mfa_methods = totp,email
mfa_key_file = ` + filepath.Join(dir, "mfa.key") + `
smtp_host = smtp.example.test
smtp_port = 587
smtp_username = notifier@example.test
smtp_password = test-only-secret
smtp_from = 设备管理平台 <notifier@example.test>
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DMP_CONFIG_FILE", configPath)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MFAEnabled || len(cfg.MFAMethods) != 2 || cfg.SMTPHost != "smtp.example.test" || cfg.SMTPFrom == "" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestMFARequiresSMTPBecauseOnboardingBindsEmail(t *testing.T) {
	t.Setenv("DMP_CONFIG_FILE", filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("DMP_MFA_ENABLED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("expected MFA configuration without SMTP to be rejected")
	}
}

func TestWebSettingsOverridePersistsWithoutExposingSMTPPassword(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "platform.conf")
	overridePath := filepath.Join(dir, "settings.override.conf")
	content := `
run_mode = dev
listen_addr = 127.0.0.1:18080
data_dir = ` + dir + `
database_path = ` + filepath.Join(dir, "panel.db") + `
settings_override_file = ` + overridePath + `
mfa_enabled = false
mfa_methods = totp
smtp_host = old.example.test
smtp_from = Old <old@example.test>
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DMP_CONFIG_FILE", configPath)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	manager := NewSettingsManager(cfg)
	updated, err := manager.Save(PanelSettings{
		MFAEnabled: true, MFAMethods: []string{"email", "totp"}, EmailCodeTTL: "8m", MFAKeyFile: cfg.MFAKeyFile,
		SMTPHost: "smtp.example.test", SMTPPort: 587, SMTPUsername: "notifier@example.test", SMTPPassword: "smtp-test-password",
		SMTPFrom: "设备管理平台 <notifier@example.test>", HTTPPort: 18080, HTTPSPort: 18443, AccessDomain: "remote.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.RestartRequired || !updated.SMTPPasswordConfigured || updated.SMTPPassword != "" {
		t.Fatalf("unexpected saved settings: %#v", updated)
	}
	overrideContent, err := os.ReadFile(overridePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(overrideContent), "smtp-test-password") {
		t.Fatal("SMTP password leaked into override configuration")
	}
	reloaded, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.MFAEnabled || reloaded.SMTPHost != "smtp.example.test" || reloaded.SMTPPassword != "smtp-test-password" || reloaded.ListenAddress != "127.0.0.1:18080" || reloaded.HTTPSListenAddress != "0.0.0.0:18443" || reloaded.AccessDomain != "remote.example.test" || reloaded.AccessScheme != "https" {
		t.Fatalf("web override did not survive reload: %#v", reloaded)
	}
	if NewSettingsManager(reloaded).Current().RestartRequired {
		t.Fatal("loaded override should not remain pending after restart")
	}
	for _, path := range []string{overridePath, filepath.Join(dir, "smtp-password")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
		}
	}
}

func TestSMTPPasswordOnlyChangeRequiresRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{ConfigFile: filepath.Join(dir, "missing.conf"), OverrideFile: filepath.Join(dir, "override.conf"), Mode: "dev", ListenAddress: "127.0.0.1:18080", DataDirectory: dir, DatabasePath: filepath.Join(dir, "db"), MFAKeyFile: filepath.Join(dir, "mfa.key"), MFAMethods: []string{"totp"}, EmailCodeTTL: 10 * time.Minute, SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https"}
	manager := NewSettingsManager(cfg)
	settings := manager.Current()
	settings.SMTPPassword = "new-password"
	updated, err := manager.Save(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.RestartRequired {
		t.Fatal("SMTP password change must require email sender restart")
	}
}

func TestPendingSavePreservesWriteOnlySMTPPassword(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{ConfigFile: filepath.Join(dir, "missing.conf"), OverrideFile: filepath.Join(dir, "override.conf"), Mode: "dev", ListenAddress: "127.0.0.1:18080", DataDirectory: dir, DatabasePath: filepath.Join(dir, "db"), MFAKeyFile: filepath.Join(dir, "mfa.key"), MFAMethods: []string{"totp"}, EmailCodeTTL: 10 * time.Minute, SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https"}
	manager := NewSettingsManager(cfg)
	settings := manager.Current()
	settings.SMTPPassword = "pending-password"
	if _, err := manager.Save(settings); err != nil {
		t.Fatal(err)
	}
	settings = manager.Current()
	settings.PanelDomain = "panel.example.test"
	if _, err := manager.Save(settings); err != nil {
		t.Fatal(err)
	}
	password, err := os.ReadFile(filepath.Join(dir, "smtp-password"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(password)) != "pending-password" {
		t.Fatalf("pending SMTP password changed: %q", password)
	}
}

func TestWebSettingsCannotOverrideEnvironmentControlledField(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DMP_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("DMP_DATA_DIR", dir)
	t.Setenv("DMP_MFA_ENABLED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := NewSettingsManager(cfg).Current()
	settings.MFAEnabled = true
	settings.MFAMethods = []string{"totp"}
	settings.SMTPHost = "smtp.example.test"
	settings.SMTPFrom = "设备管理平台 <notifier@example.test>"
	if _, err := NewSettingsManager(cfg).Save(settings); err == nil || !strings.Contains(err.Error(), "environment variable") {
		t.Fatalf("expected environment lock error, got %v", err)
	}
}

func TestEnvironmentLockedMethodsUseSetEquality(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DMP_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("DMP_DATA_DIR", dir)
	t.Setenv("DMP_MFA_METHODS", "totp,email")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := NewSettingsManager(cfg).Current()
	settings.MFAMethods = []string{"email", "totp"}
	if _, err := NewSettingsManager(cfg).Save(settings); err != nil {
		t.Fatalf("method order should not override an environment-controlled set: %v", err)
	}
}

func TestWebSettingsCanClearManagedSMTPPassword(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{ConfigFile: filepath.Join(dir, "missing.conf"), OverrideFile: filepath.Join(dir, "override.conf"), Mode: "dev", ListenAddress: "127.0.0.1:18080", DataDirectory: dir, DatabasePath: filepath.Join(dir, "db"), MFAKeyFile: filepath.Join(dir, "mfa.key"), MFAMethods: []string{"totp"}, EmailCodeTTL: 10 * time.Minute, SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https", SMTPPassword: "existing"}
	manager := NewSettingsManager(cfg)
	settings := manager.Current()
	settings.ClearSMTPPassword = true
	updated, err := manager.Save(settings)
	if err != nil {
		t.Fatal(err)
	}
	if updated.SMTPPasswordConfigured {
		t.Fatal("SMTP password remains configured after explicit clear")
	}
	reloadedValues, err := readConfigFile(cfg.OverrideFile)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedValues["smtp_password"] != "" || reloadedValues["smtp_password_file"] != "" {
		t.Fatalf("override still references an SMTP password: %#v", reloadedValues)
	}
}

func TestPanelSettingsSerializesEmptyListsAsArrays(t *testing.T) {
	settings := NewSettingsManager(Config{MFAKeyFile: "mfa.key", EmailCodeTTL: 10 * time.Minute}).Current()
	if settings.MFAMethods == nil || settings.LockedFields == nil {
		t.Fatalf("settings lists must be empty arrays, not null: %#v", settings)
	}
	if settings.EmailCodeTTL != "10m" {
		t.Fatalf("email TTL = %q, want a form-selectable value", settings.EmailCodeTTL)
	}
}
