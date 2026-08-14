package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const (
	totpPeriod       = int64(30)
	totpDigits       = 6
	recoveryCodeSize = 12
)

type MFA struct {
	key []byte
}

type Enrollment struct {
	Secret        string
	OTPAuthURI    string
	QRCodeDataURL string
}

func LoadOrCreateMFA(path string, production bool) (*MFA, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve MFA key path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return nil, fmt.Errorf("create MFA key directory: %w", err)
	}
	content, err := os.ReadFile(abs)
	if errors.Is(err, os.ErrNotExist) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate MFA key: %w", err)
		}
		encoded := []byte(base64.RawURLEncoding.EncodeToString(key) + "\n")
		file, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create MFA key: %w", err)
		}
		_, writeErr := file.Write(encoded)
		closeErr := file.Close()
		if writeErr != nil {
			return nil, fmt.Errorf("write MFA key: %w", writeErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close MFA key: %w", closeErr)
		}
		return &MFA{key: key}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read MFA key: %w", err)
	}
	if info, statErr := os.Stat(abs); statErr != nil {
		return nil, fmt.Errorf("stat MFA key: %w", statErr)
	} else if production && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("MFA key file must not be accessible by group or others in pro mode")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(content)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("MFA key must be a base64url encoded 32-byte key")
	}
	return &MFA{key: key}, nil
}

func NewMFAForKey(key []byte) (*MFA, error) {
	if len(key) != 32 {
		return nil, errors.New("MFA key must contain 32 bytes")
	}
	return &MFA{key: append([]byte(nil), key...)}, nil
}

func (m *MFA) NewEnrollment(username string) (Enrollment, error) {
	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return Enrollment{}, err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	label := "I5CLOUD:" + username
	query := url.Values{}
	query.Set("secret", secret)
	query.Set("issuer", "I5CLOUD")
	query.Set("algorithm", "SHA1")
	query.Set("digits", strconv.Itoa(totpDigits))
	query.Set("period", strconv.FormatInt(totpPeriod, 10))
	otpURI := "otpauth://totp/" + url.PathEscape(label) + "?" + query.Encode()
	png, err := qrcode.Encode(otpURI, qrcode.Medium, 256)
	if err != nil {
		return Enrollment{}, fmt.Errorf("encode MFA QR code: %w", err)
	}
	return Enrollment{Secret: secret, OTPAuthURI: otpURI, QRCodeDataURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)}, nil
}

func (m *MFA) EncryptSecret(userID, secret string) (string, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(secret), []byte(userID))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *MFA) DecryptSecret(userID, encoded string) (string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", errors.New("invalid encrypted MFA secret")
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < aead.NonceSize() {
		return "", errors.New("invalid encrypted MFA secret")
	}
	plain, err := aead.Open(nil, payload[:aead.NonceSize()], payload[aead.NonceSize():], []byte(userID))
	if err != nil {
		return "", errors.New("MFA secret cannot be decrypted with the configured key")
	}
	return string(plain), nil
}

func (m *MFA) ValidateTOTP(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	for _, value := range code {
		if value < '0' || value > '9' {
			return 0, false
		}
	}
	current := now.UTC().Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		counter := current + offset
		if counter >= 0 && hmac.Equal([]byte(totpCode(secret, counter)), []byte(code)) {
			return counter, true
		}
	}
	return 0, false
}

func CurrentTOTP(secret string, now time.Time) string {
	return totpCode(secret, now.UTC().Unix()/totpPeriod)
}

func totpCode(secret string, counter int64) string {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return ""
	}
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(counter))
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(buffer)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 | uint32(digest[offset+1])<<16 | uint32(digest[offset+2])<<8 | uint32(digest[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}

func (m *MFA) NewRecoveryCodes(count int) ([]string, []string, error) {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	codes := make([]string, 0, count)
	hashes := make([]string, 0, count)
	for len(codes) < count {
		random := make([]byte, recoveryCodeSize)
		if _, err := rand.Read(random); err != nil {
			return nil, nil, err
		}
		plain := make([]byte, recoveryCodeSize)
		for index := range random {
			plain[index] = alphabet[int(random[index])%len(alphabet)]
		}
		code := string(plain[:4]) + "-" + string(plain[4:8]) + "-" + string(plain[8:])
		codes = append(codes, code)
		hashes = append(hashes, m.RecoveryCodeHash(code))
	}
	return codes, hashes, nil
}

func (m *MFA) RecoveryCodeHash(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte(normalized))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *MFA) EmailCodeHash(challengeID, code string) string {
	mac := hmac.New(sha256.New, m.key)
	_, _ = mac.Write([]byte("email:" + challengeID + ":" + strings.TrimSpace(code)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func LooksLikeRecoveryCode(code string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(code), "-", "")
	return len(normalized) == recoveryCodeSize
}
