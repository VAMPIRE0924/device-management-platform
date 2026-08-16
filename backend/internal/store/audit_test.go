package store

import (
	"strings"
	"testing"
)

func TestSanitizeAuditMetadataRedactsSecretsRecursively(t *testing.T) {
	raw := `{"username":"root","password":"ssh-password","nested":{"verify_key":"node-key","cookie":"session-cookie"},"items":[{"privateKey":"pem-data"}],"result":"ok"}`
	metadata := sanitizeAuditMetadata(raw)
	for _, secret := range []string{"ssh-password", "node-key", "session-cookie", "pem-data"} {
		if strings.Contains(metadata, secret) {
			t.Fatalf("audit metadata leaked %q: %s", secret, metadata)
		}
	}
	if !strings.Contains(metadata, `"username":"root"`) || !strings.Contains(metadata, `"result":"ok"`) {
		t.Fatalf("non-sensitive audit metadata was lost: %s", metadata)
	}
	if count := strings.Count(metadata, "[REDACTED]"); count != 4 {
		t.Fatalf("redacted field count = %d, want 4: %s", count, metadata)
	}
}

func TestSanitizeAuditMetadataDropsMalformedText(t *testing.T) {
	if metadata := sanitizeAuditMetadata(`password=do-not-store`); metadata != "{}" {
		t.Fatalf("malformed audit metadata = %q, want empty object", metadata)
	}
}
