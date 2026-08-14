package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProductionRequiresStrongToken(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "short")
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
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "")
	t.Setenv("I5CLOUD_API_TOKEN_FILE", path)
	t.Setenv("I5CLOUD_SETUP_TOKEN", "setup-token-0123456789abcdef")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIToken != token {
		t.Fatalf("unexpected token %q", cfg.APIToken)
	}
}

func TestProductionRequiresSetupToken(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected production setup token validation error")
	}
}

func TestRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	t.Setenv("I5CLOUD_TRUSTED_PROXY_CIDRS", "10.0.0.0/24,not-a-cidr")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid trusted proxy CIDR error")
	}
}

func TestProductionRequiresDistinctTokens(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "same-token-0123456789abcdef01234567")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "same-token-0123456789abcdef01234567")
	if _, err := Load(); err == nil {
		t.Fatal("expected distinct production token validation error")
	}
}

func TestProductionRejectsInsecureCookieOnPublicListener(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "setup-token-0123456789abcdef")
	t.Setenv("I5CLOUD_COOKIE_SECURE", "false")
	t.Setenv("I5CLOUD_LISTEN_ADDR", "0.0.0.0:8088")
	if _, err := Load(); err == nil {
		t.Fatal("expected insecure production cookie validation error")
	}
}

func TestProductionAllowsInsecureCookieForLoopbackAcceptance(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "setup-token-0123456789abcdef")
	t.Setenv("I5CLOUD_COOKIE_SECURE", "false")
	t.Setenv("I5CLOUD_LISTEN_ADDR", "127.0.0.1:8088")
	if _, err := Load(); err != nil {
		t.Fatalf("loopback acceptance config rejected: %v", err)
	}
}

func TestProductionAccessDomainRequiresHTTPS(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "setup-token-0123456789abcdef")
	t.Setenv("I5CLOUD_ACCESS_DOMAIN", "remote.example.com")
	t.Setenv("I5CLOUD_ACCESS_SCHEME", "http")
	if _, err := Load(); err == nil {
		t.Fatal("expected production access domain HTTPS validation error")
	}
}

func TestProductionLocalWildcardDomainAllowsHTTPAcceptance(t *testing.T) {
	t.Setenv("I5CLOUD_MODE", "pro")
	t.Setenv("I5CLOUD_API_TOKEN", "api-token-0123456789abcdef0123456789")
	t.Setenv("I5CLOUD_SETUP_TOKEN", "setup-token-0123456789abcdef")
	t.Setenv("I5CLOUD_ACCESS_DOMAIN", "admin.i5cloud.localhost")
	t.Setenv("I5CLOUD_ACCESS_SCHEME", "http")
	if _, err := Load(); err != nil {
		t.Fatalf("local wildcard acceptance config rejected: %v", err)
	}
	t.Setenv("I5CLOUD_ACCESS_DOMAIN", "admin.i5cloud.127.0.0.1.nip.io")
	if _, err := Load(); err != nil {
		t.Fatalf("loopback wildcard DNS acceptance config rejected: %v", err)
	}
}

func TestReadsPanelConfigWithMandatoryEmailVerification(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "i5cloud.conf")
	content := `
run_mode = pro
listen_addr = 127.0.0.1:18088
database_path = ` + filepath.Join(dir, "panel.db") + `
api_token = api-token-0123456789abcdef0123456789
setup_token = setup-token-0123456789abcdef
mfa_enabled = true
mfa_methods = totp,email
mfa_key_file = ` + filepath.Join(dir, "mfa.key") + `
smtp_host = smtp.example.test
smtp_port = 587
smtp_username = notifier@example.test
smtp_password = test-only-secret
smtp_from = I5CLOUD <notifier@example.test>
cookie_secure = false
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("I5CLOUD_CONFIG_FILE", configPath)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.MFAEnabled || len(cfg.MFAMethods) != 2 || cfg.SMTPHost != "smtp.example.test" || cfg.SMTPFrom == "" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestMFARequiresSMTPBecauseOnboardingBindsEmail(t *testing.T) {
	t.Setenv("I5CLOUD_CONFIG_FILE", filepath.Join(t.TempDir(), "missing.conf"))
	t.Setenv("I5CLOUD_MFA_ENABLED", "true")
	if _, err := Load(); err == nil {
		t.Fatal("expected MFA configuration without SMTP to be rejected")
	}
}

func TestWebSettingsOverridePersistsWithoutExposingSMTPPassword(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "i5cloud.conf")
	overridePath := filepath.Join(dir, "i5cloud.override.conf")
	content := `
run_mode = dev
listen_addr = 127.0.0.1:18088
data_dir = ` + dir + `
database_path = ` + filepath.Join(dir, "panel.db") + `
settings_override_file = ` + overridePath + `
mfa_enabled = false
mfa_methods = totp
smtp_host = old.example.test
smtp_from = Old <old@example.test>
cookie_secure = false
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("I5CLOUD_CONFIG_FILE", configPath)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	manager := NewSettingsManager(cfg)
	updated, err := manager.Save(PanelSettings{
		MFAEnabled: true, MFAMethods: []string{"email", "totp"}, EmailCodeTTL: "8m", MFAKeyFile: cfg.MFAKeyFile,
		SMTPHost: "smtp.example.test", SMTPPort: 587, SMTPUsername: "notifier@example.test", SMTPPassword: "smtp-test-password",
		SMTPFrom: "I5CLOUD <notifier@example.test>", AccessDomain: "remote.example.test",
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
	if !reloaded.MFAEnabled || reloaded.SMTPHost != "smtp.example.test" || reloaded.SMTPPassword != "smtp-test-password" || reloaded.AccessDomain != "remote.example.test" || reloaded.AccessScheme != "https" {
		t.Fatalf("web override did not survive reload: %#v", reloaded)
	}
	if NewSettingsManager(reloaded).Current().RestartRequired {
		t.Fatal("loaded override should not remain pending after restart")
	}
	for _, path := range []string{overridePath, filepath.Join(dir, "i5cloud.smtp-password")} {
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
	cfg := Config{ConfigFile: filepath.Join(dir, "missing.conf"), OverrideFile: filepath.Join(dir, "override.conf"), Mode: "dev", ListenAddress: "127.0.0.1:8088", DataDirectory: dir, DatabasePath: filepath.Join(dir, "db"), MFAKeyFile: filepath.Join(dir, "mfa.key"), MFAMethods: []string{"totp"}, EmailCodeTTL: 10 * time.Minute, SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https"}
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

func TestWebSettingsCannotOverrideEnvironmentControlledField(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("I5CLOUD_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("I5CLOUD_DATA_DIR", dir)
	t.Setenv("I5CLOUD_MFA_ENABLED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	settings := NewSettingsManager(cfg).Current()
	settings.MFAEnabled = true
	settings.MFAMethods = []string{"totp"}
	settings.SMTPHost = "smtp.example.test"
	settings.SMTPFrom = "I5CLOUD <notifier@example.test>"
	if _, err := NewSettingsManager(cfg).Save(settings); err == nil || !strings.Contains(err.Error(), "environment variable") {
		t.Fatalf("expected environment lock error, got %v", err)
	}
}

func TestEnvironmentLockedMethodsUseSetEquality(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("I5CLOUD_CONFIG_FILE", filepath.Join(dir, "missing.conf"))
	t.Setenv("I5CLOUD_DATA_DIR", dir)
	t.Setenv("I5CLOUD_MFA_METHODS", "totp,email")
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
	cfg := Config{ConfigFile: filepath.Join(dir, "missing.conf"), OverrideFile: filepath.Join(dir, "override.conf"), Mode: "dev", ListenAddress: "127.0.0.1:8088", DataDirectory: dir, DatabasePath: filepath.Join(dir, "db"), MFAKeyFile: filepath.Join(dir, "mfa.key"), MFAMethods: []string{"totp"}, EmailCodeTTL: 10 * time.Minute, SMTPPort: 587, SMTPTLSMode: "starttls", AccessScheme: "https", SMTPPassword: "existing"}
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
