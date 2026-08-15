package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/config"
)

func TestHealthcheckSupportsHTTPAndTLSListeners(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	for _, testCase := range []struct {
		name string
		tls  bool
	}{
		{name: "http"},
		{name: "https", tls: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var server *httptest.Server
			if testCase.tls {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			parsed, err := url.Parse(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{ListenAddress: parsed.Host}
			if testCase.tls {
				cfg.TLSCertFile = "configured"
			}
			if err := checkHealth(cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
}
