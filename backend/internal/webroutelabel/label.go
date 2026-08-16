package webroutelabel

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

const (
	prefix                  = "web-"
	encodedDigestBytes      = 5
	CollisionCandidateCount = 4
)

var routeEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// New returns a short, opaque route label backed by crypto/rand. The label is
// routing information rather than an authorization secret, but generating it
// independently for every Web access session prevents a Safe Browsing false
// positive on one hostname from becoming permanent for that user and endpoint.
func New() (string, error) {
	raw := make([]byte, encodedDigestBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + strings.ToLower(routeEncoding.EncodeToString(raw)), nil
}

func IsCurrent(label string) bool {
	if !strings.HasPrefix(label, prefix) || len(label) != len(prefix)+routeEncoding.EncodedLen(encodedDigestBytes) {
		return false
	}
	encoded := strings.TrimPrefix(label, prefix)
	if encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := routeEncoding.DecodeString(encoded)
	return err == nil
}
