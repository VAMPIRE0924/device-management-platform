package secrets_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/secrets"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
)

func TestNodeCredentialVaultEncryptsPersistsAndRotates(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "credentials.key")
	vault, err := secrets.LoadOrCreateNodeCredentialVault(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	reference, _, err := vault.Save(t.Context(), "node-1", "", secrets.NodeCredentialPatch{Type: "session", Username: "node-admin", Password: "first-password"})
	if err != nil {
		t.Fatal(err)
	}
	if reference != "db://node/node-1" {
		t.Fatalf("credential reference = %q", reference)
	}
	nonce, ciphertext, err := db.NodeCredential(t.Context(), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) == 0 || bytes.Contains(ciphertext, []byte("node-admin")) || bytes.Contains(ciphertext, []byte("first-password")) {
		t.Fatalf("credential was not stored as opaque ciphertext: %q", ciphertext)
	}

	reopened, err := secrets.LoadOrCreateNodeCredentialVault(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := reopened.Resolve(t.Context(), reference)
	if err != nil {
		t.Fatal(err)
	}
	var credential secrets.NodeCredentialPatch
	if err := json.Unmarshal([]byte(resolved), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Username != "node-admin" || credential.Password != "first-password" {
		t.Fatalf("resolved credential = %#v", credential)
	}

	if _, _, err := reopened.Save(t.Context(), "node-1", reference, secrets.NodeCredentialPatch{Type: "session", Password: "replacement-password"}); err != nil {
		t.Fatal(err)
	}
	resolved, err = reopened.Resolve(t.Context(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(resolved), &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Username != "node-admin" || credential.Password != "replacement-password" {
		t.Fatalf("rotated credential = %#v", credential)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key permissions = %o", info.Mode().Perm())
	}
}

func TestNodeCredentialVaultRejectsWrongMasterKey(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	vault, err := secrets.LoadOrCreateNodeCredentialVault(db, filepath.Join(dir, "correct.key"))
	if err != nil {
		t.Fatal(err)
	}
	reference, _, err := vault.Save(t.Context(), "node-2", "", secrets.NodeCredentialPatch{Type: "session", Username: "admin", Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyPath := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrongKeyPath, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrongVault, err := secrets.LoadOrCreateNodeCredentialVault(db, wrongKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongVault.Resolve(t.Context(), reference); err == nil {
		t.Fatal("credential decrypted with the wrong master key")
	}
}
