package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
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

func TestReadRuntimeTLSDescriptorReadsInheritedFileDirectly(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "runtime-tls")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("certificate material"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	contents, err := readRuntimeTLSDescriptor(strconv.Itoa(int(file.Fd())), "certificate")
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "certificate material" {
		t.Fatalf("unexpected descriptor contents %q", contents)
	}
}

func TestLoadRuntimeTLSCertificateRequiresDescriptorPair(t *testing.T) {
	t.Setenv("DMP_RUNTIME_TLS_CERT_FD", "3")
	if _, err := loadRuntimeTLSCertificate(); err == nil {
		t.Fatal("expected incomplete runtime TLS descriptor configuration to fail")
	}
}
