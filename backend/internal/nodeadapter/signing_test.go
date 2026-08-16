package nodeadapter

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestNPSSigningFixedVector(t *testing.T) {
	got := signNPSRequest(
		http.MethodPost,
		"/index/socksstatus/",
		"1800000000",
		"nonce-0123456789",
		[]byte("id=3"),
		"test-secret",
	)
	const want = "98c00fd4ee715fe8388b8144e9ca60f5c7fe791934cf9a201d4caad8dba32212"
	if got != want {
		t.Fatalf("signature = %s, want %s", got, want)
	}
}

func TestNPSSigningUsesExactBodyAndRawPrefixedPath(t *testing.T) {
	parsed, err := url.Parse("https://node.example/nps/index/example/?b=2&a=%2Fraw")
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: http.MethodPost, URL: parsed, Header: make(http.Header)}
	body := []byte("value=%E8%AE%BE%E5%A4%87&item=first&item=second")
	applyNPSSignature(request, body, "test-secret", "nonce-0123456789", time.Unix(1800000000, 0))

	if got := pathWithRawQuery(parsed); got != "/nps/index/example/?b=2&a=%2Fraw" {
		t.Fatalf("signed path = %q", got)
	}
	if got := request.Header.Get(npsTimestampHeader); got != "1800000000" {
		t.Fatalf("timestamp = %q", got)
	}
	if got := request.Header.Get(npsNonceHeader); got != "nonce-0123456789" {
		t.Fatalf("nonce = %q", got)
	}
	want := signNPSRequest(http.MethodPost, "/nps/index/example/?b=2&a=%2Fraw", "1800000000", "nonce-0123456789", body, "test-secret")
	if got := request.Header.Get(npsSignatureHeader); got != want {
		t.Fatalf("signature = %q, want %q", got, want)
	}
	if changed := signNPSRequest(http.MethodPost, "/nps/index/example/?b=2&a=%2Fraw", "1800000000", "nonce-0123456789", []byte("item=first&item=second&value=%E8%AE%BE%E5%A4%87"), "test-secret"); changed == want {
		t.Fatal("signature did not preserve body parameter order")
	}
}

func TestNPSSigningEmptyBody(t *testing.T) {
	first := signNPSRequest(http.MethodPost, "/nps/client/list/", "1800000000", "nonce-0123456789", nil, "test-secret")
	second := signNPSRequest(http.MethodPost, "/nps/client/list/", "1800000000", "nonce-0123456789", []byte{}, "test-secret")
	if first != second {
		t.Fatalf("nil and empty body signatures differ: %s != %s", first, second)
	}
}
