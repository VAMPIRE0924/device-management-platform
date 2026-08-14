package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type NodeCredentialPatch struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
	AuthKey  string `json:"authKey"`
}

type SSHCredentialPatch struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type credentialDatabase interface {
	SaveNodeCredential(context.Context, string, []byte, []byte) error
	NodeCredential(context.Context, string) ([]byte, []byte, error)
	DeleteNodeCredential(context.Context, string) error
}

// NodeCredentialVault encrypts node credentials before they enter SQLite.
// The database backup therefore contains the credential ciphertext, while the
// independent 0600 master key remains the recovery boundary.
type NodeCredentialVault struct {
	database credentialDatabase
	aead     cipher.AEAD
	resolver Resolver
}

func LoadOrCreateNodeCredentialVault(database credentialDatabase, keyFile string) (*NodeCredentialVault, error) {
	key, err := loadOrCreateKey(keyFile)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &NodeCredentialVault{database: database, aead: aead}, nil
}

func (v *NodeCredentialVault) Resolve(ctx context.Context, reference string) (string, error) {
	const prefix = "db://node/"
	if !strings.HasPrefix(reference, prefix) {
		return v.resolver.Resolve(ctx, reference)
	}
	nodeID := strings.TrimPrefix(reference, prefix)
	nonce, ciphertext, err := v.database.NodeCredential(ctx, nodeID)
	if err != nil {
		return "", fmt.Errorf("read encrypted node credential: %w", err)
	}
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, []byte(nodeID))
	if err != nil {
		return "", fmt.Errorf("decrypt node credential: master key does not match the database")
	}
	return string(plaintext), nil
}

func (v *NodeCredentialVault) Save(ctx context.Context, nodeID, currentReference string, patch NodeCredentialPatch) (string, func(), error) {
	current := NodeCredentialPatch{}
	if strings.TrimSpace(currentReference) != "" {
		if value, err := v.Resolve(ctx, currentReference); err == nil {
			_ = json.Unmarshal([]byte(value), &current)
		}
	}
	credential := current
	if value := strings.TrimSpace(patch.Type); value != "" {
		credential.Type = value
	}
	if value := strings.TrimSpace(patch.Username); value != "" {
		credential.Username = value
	}
	if patch.Password != "" {
		credential.Password = patch.Password
	}
	if patch.AuthKey != "" {
		credential.AuthKey = patch.AuthKey
	}
	if credential.Type == "" {
		credential.Type = "session"
	}
	switch credential.Type {
	case "session":
		if strings.TrimSpace(credential.Username) == "" || credential.Password == "" {
			return "", nil, fmt.Errorf("账号密码认证必须填写认证账号和密码")
		}
		credential.AuthKey = ""
	case "signed":
		if strings.TrimSpace(credential.AuthKey) == "" {
			return "", nil, fmt.Errorf("签名认证必须填写认证密钥")
		}
		credential.Username = ""
		credential.Password = ""
	default:
		return "", nil, fmt.Errorf("不支持的节点认证方式")
	}
	plaintext, err := json.Marshal(credential)
	if err != nil {
		return "", nil, err
	}
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	ciphertext := v.aead.Seal(nil, nonce, plaintext, []byte(nodeID))
	oldNonce, oldCiphertext, oldErr := v.database.NodeCredential(ctx, nodeID)
	hadOld := oldErr == nil
	if err := v.database.SaveNodeCredential(ctx, nodeID, nonce, ciphertext); err != nil {
		return "", nil, err
	}
	rollback := func() {
		if hadOld {
			_ = v.database.SaveNodeCredential(context.Background(), nodeID, oldNonce, oldCiphertext)
		} else {
			_ = v.database.DeleteNodeCredential(context.Background(), nodeID)
		}
	}
	return "db://node/" + nodeID, rollback, nil
}

// SaveSSH encrypts an SSH username/password pair with the same persisted
// master key used for node credentials. The endpoint-scoped reference is safe
// to include in database backups while the plaintext is never returned.
func (v *NodeCredentialVault) SaveSSH(ctx context.Context, endpointID, currentReference string, patch SSHCredentialPatch) (string, func(), error) {
	current := SSHCredentialPatch{}
	if strings.TrimSpace(currentReference) != "" {
		if value, err := v.Resolve(ctx, currentReference); err == nil {
			_ = json.Unmarshal([]byte(value), &current)
		}
	}
	if username := strings.TrimSpace(patch.Username); username != "" {
		current.Username = username
	}
	if patch.Password != "" {
		current.Password = patch.Password
	}
	if strings.TrimSpace(current.Username) == "" || current.Password == "" {
		return "", nil, fmt.Errorf("SSH 密码登录必须填写用户名和密码")
	}
	plaintext, err := json.Marshal(current)
	if err != nil {
		return "", nil, err
	}
	credentialID := "ssh-" + endpointID
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	ciphertext := v.aead.Seal(nil, nonce, plaintext, []byte(credentialID))
	oldNonce, oldCiphertext, oldErr := v.database.NodeCredential(ctx, credentialID)
	hadOld := oldErr == nil
	if err := v.database.SaveNodeCredential(ctx, credentialID, nonce, ciphertext); err != nil {
		return "", nil, err
	}
	rollback := func() {
		if hadOld {
			_ = v.database.SaveNodeCredential(context.Background(), credentialID, oldNonce, oldCiphertext)
		} else {
			_ = v.database.DeleteNodeCredential(context.Background(), credentialID)
		}
	}
	return "db://node/" + credentialID, rollback, nil
}

func (v *NodeCredentialVault) Delete(nodeID string) error {
	return v.database.DeleteNodeCredential(context.Background(), nodeID)
}

func loadOrCreateKey(path string) ([]byte, error) {
	if content, err := os.ReadFile(path); err == nil {
		key, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(content)))
		if decodeErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("node credential master key is invalid")
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".credential-key-*")
	if err != nil {
		return nil, err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := temporary.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return nil, err
	}
	return key, nil
}
