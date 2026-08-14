package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEnvironmentAndFileSecrets(t *testing.T) {
	resolver := Resolver{}
	t.Setenv("I5CLOUD_TEST_SECRET", "environment-value")
	value, err := resolver.Resolve(t.Context(), "env://I5CLOUD_TEST_SECRET")
	if err != nil || value != "environment-value" {
		t.Fatalf("environment secret = %q, err = %v", value, err)
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("file-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err = resolver.Resolve(t.Context(), "file://"+path)
	if err != nil || value != "file-value" {
		t.Fatalf("file secret = %q, err = %v", value, err)
	}
}

func TestRejectsPlaintextAndUnavailableProviders(t *testing.T) {
	resolver := Resolver{}
	for _, reference := range []string{"plaintext", "vault://node", "secret://node"} {
		if _, err := resolver.Resolve(t.Context(), reference); err == nil {
			t.Fatalf("expected %s to be rejected", reference)
		}
	}
}
