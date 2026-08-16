package nodeadapter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	npsTimestampHeader = "X-NPS-Timestamp"
	npsNonceHeader     = "X-NPS-Nonce"
	npsSignatureHeader = "X-NPS-Signature"
)

func newNonce() (string, error) {
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate NPS request nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(random), nil
}

func pathWithRawQuery(parsed *url.URL) string {
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func signNPSRequest(method, path, timestamp, nonce string, body []byte, secret string) string {
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{
		strings.ToUpper(method),
		path,
		timestamp,
		nonce,
		hex.EncodeToString(bodyHash[:]),
	}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func applyNPSSignature(request *http.Request, body []byte, secret, nonce string, now time.Time) {
	timestamp := strconv.FormatInt(now.Unix(), 10)
	request.Header.Set(npsTimestampHeader, timestamp)
	request.Header.Set(npsNonceHeader, nonce)
	request.Header.Set(npsSignatureHeader, signNPSRequest(
		request.Method,
		pathWithRawQuery(request.URL),
		timestamp,
		nonce,
		body,
		secret,
	))
}
