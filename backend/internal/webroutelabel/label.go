package webroutelabel

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	prefix                   = "web-"
	encodedDigestBytes       = 5
	legacyEncodedDigestBytes = 20
	CollisionCandidateCount  = 4
)

var routeEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// StableCandidates returns opaque, deterministic labels for one platform user
// and Web endpoint. The first label is the normal route; the remaining labels
// only exist to resolve a practically impossible truncated-digest collision.
// This is not a bounded pool: every user/endpoint pair has its own candidates.
func StableCandidates(userID, endpointID string) []string {
	labels := make([]string, 0, CollisionCandidateCount)
	for candidate := 0; candidate < CollisionCandidateCount; candidate++ {
		digest := sha256.Sum256([]byte("dmp-web-route-v3\x00" + userID + "\x00" + endpointID + "\x00" + strconv.Itoa(candidate)))
		labels = append(labels, prefix+strings.ToLower(routeEncoding.EncodeToString(digest[:encodedDigestBytes])))
	}
	return labels
}

func IsCurrent(label string) bool {
	return isOpaqueLabel(label, encodedDigestBytes)
}

func isOpaqueLabel(label string, digestBytes int) bool {
	if !strings.HasPrefix(label, prefix) || len(label) != len(prefix)+routeEncoding.EncodedLen(digestBytes) {
		return false
	}
	encoded := strings.TrimPrefix(label, prefix)
	if encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := routeEncoding.DecodeString(encoded)
	return err == nil
}

func IsAllowed(label string) bool {
	return IsCurrent(label) || isOpaqueLabel(label, legacyEncodedDigestBytes) || isLegacyPoolLabel(label) || isLegacyDeviceLabel(label)
}

func isLegacyPoolLabel(label string) bool {
	if !strings.HasPrefix(label, prefix) || len(label) != len("web-00") {
		return false
	}
	slot, err := strconv.Atoi(strings.TrimPrefix(label, prefix))
	return err == nil && slot >= 1 && slot <= 32
}

func isLegacyDeviceLabel(label string) bool {
	if !strings.HasPrefix(label, "device-") {
		return false
	}
	encoded := strings.TrimPrefix(label, "device-")
	if len(encoded) != 32 || encoded != strings.ToLower(encoded) {
		return false
	}
	_, err := hex.DecodeString(encoded)
	return err == nil
}
