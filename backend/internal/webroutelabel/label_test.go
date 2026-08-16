package webroutelabel

import (
	"strconv"
	"strings"
	"testing"
)

func TestStableCandidatesAreOpaqueAndUnboundedBySharedSlots(t *testing.T) {
	first := StableCandidates("user-one", "endpoint-one")
	reopened := StableCandidates("user-one", "endpoint-one")
	if len(first) != CollisionCandidateCount || strings.Join(first, ",") != strings.Join(reopened, ",") {
		t.Fatal("the same user and endpoint must keep the same route candidates")
	}
	seen := make(map[string]bool, len(first))
	for _, label := range first {
		if seen[label] || !IsCurrent(label) {
			t.Fatalf("invalid or repeated opaque route label: %q", label)
		}
		seen[label] = true
	}
	if first[0] == StableCandidates("user-two", "endpoint-one")[0] || first[0] == StableCandidates("user-one", "endpoint-two")[0] {
		t.Fatal("different users or endpoints must not share their primary route label")
	}
}

func TestPrimaryLabelsRemainUniqueAcrossFiftyThousandRoutes(t *testing.T) {
	seen := make(map[string]struct{}, 50_000)
	for index := 0; index < 50_000; index++ {
		label := StableCandidates("user-"+strconv.Itoa(index%500), "endpoint-"+strconv.Itoa(index))[0]
		if _, exists := seen[label]; exists {
			t.Fatalf("duplicate primary label at route %d: %q", index, label)
		}
		seen[label] = struct{}{}
	}
}

func TestAllowedLabelsKeepOnlyExplicitMigrationFormats(t *testing.T) {
	for _, label := range []string{StableCandidates("user", "endpoint")[0], "web-01", "web-32", "device-0123456789abcdef0123456789abcdef"} {
		if !IsAllowed(label) {
			t.Fatalf("expected allowed label: %q", label)
		}
	}
	for _, label := range []string{"web-00", "web-33", "web-99", "web-deadbeef", "anything", "device-0123456789ABCDEF0123456789ABCDEF"} {
		if IsAllowed(label) {
			t.Fatalf("unexpected allowed label: %q", label)
		}
	}
}
