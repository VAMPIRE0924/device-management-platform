package auth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMFAEnrollmentEncryptionAndCodes(t *testing.T) {
	service, err := NewMFAForKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.NewEnrollment("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enrollment.OTPAuthURI, "otpauth://totp/") || !strings.HasPrefix(enrollment.QRCodeDataURL, "data:image/png;base64,") {
		t.Fatalf("invalid enrollment: %#v", enrollment)
	}
	ciphertext, err := service.EncryptSecret("user-1", enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := service.DecryptSecret("user-1", ciphertext)
	if err != nil || plain != enrollment.Secret {
		t.Fatalf("decrypted = %q, err = %v", plain, err)
	}
	if _, err := service.DecryptSecret("user-2", ciphertext); err == nil {
		t.Fatal("encrypted secret was not bound to the user")
	}
	now := time.Unix(1_785_568_000, 0)
	code := totpCode(enrollment.Secret, now.Unix()/totpPeriod)
	counter, valid := service.ValidateTOTP(enrollment.Secret, code, now)
	if !valid || counter != now.Unix()/totpPeriod {
		t.Fatalf("counter = %d, valid = %v", counter, valid)
	}
	codes, hashes, err := service.NewRecoveryCodes(10)
	if err != nil || len(codes) != 10 || len(hashes) != 10 || service.RecoveryCodeHash(codes[0]) != hashes[0] {
		t.Fatalf("codes = %d, hashes = %d, err = %v", len(codes), len(hashes), err)
	}
}

func TestLoadOrCreateMFAKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "mfa.key")
	first, err := LoadOrCreateMFA(keyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateMFA(keyPath, true)
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(first.key) != base64.RawURLEncoding.EncodeToString(second.key) {
		t.Fatal("persisted key changed")
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, err = %v", info.Mode().Perm(), err)
	}
}
