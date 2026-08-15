package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/config"
)

func TestHealthcheckUsesAlwaysAvailableHTTPListener(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{ListenAddress: parsed.Host, TLSCertFile: "configured"}
	if err := checkHealth(cfg); err != nil {
		t.Fatal(err)
	}
}
