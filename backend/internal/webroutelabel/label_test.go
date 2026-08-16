package webroutelabel

import "testing"

func TestNewLabelsAreShortRandomAndUnboundedBySharedSlots(t *testing.T) {
	seen := make(map[string]bool, 2_000)
	for index := 0; index < 2_000; index++ {
		label, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if len(label) != len("web-")+8 || !IsCurrent(label) || seen[label] {
			t.Fatalf("invalid or repeated random route label: %q", label)
		}
		seen[label] = true
	}
}

func TestRandomLabelsRemainUniqueAcrossFiftyThousandRoutes(t *testing.T) {
	seen := make(map[string]struct{}, 50_000)
	collisions := 0
	for index := 0; index < 50_000; index++ {
		label, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := seen[label]; exists {
			collisions++
		}
		seen[label] = struct{}{}
	}
	// A 40-bit random space has no fixed capacity. Permit the vanishingly rare
	// birthday collision here because production retries with a fresh label.
	if collisions > CollisionCandidateCount {
		t.Fatalf("unexpectedly many random label collisions: %d", collisions)
	}
}

func TestAllowedLabelsAcceptOnlyCurrentRandomFormat(t *testing.T) {
	randomLabel, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !IsCurrent(randomLabel) {
		t.Fatalf("expected current random label: %q", randomLabel)
	}
	for _, label := range []string{"web-short", "web-iiiiiiii", "web-uppercase", "web-0123456789abcdefghjkmnpqrstvwxyz", "anything", "invalid-route-label-that-is-too-long"} {
		if IsCurrent(label) {
			t.Fatalf("obsolete or invalid label was accepted: %q", label)
		}
	}
}
