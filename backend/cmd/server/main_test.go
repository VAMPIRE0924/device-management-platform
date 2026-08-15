package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

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
	duplicatedFD, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	contents, err := readRuntimeTLSDescriptor(strconv.Itoa(duplicatedFD), "certificate")
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "certificate material" {
		t.Fatalf("unexpected descriptor contents %q", contents)
	}
}

func TestLoadTLSCertificateRequiresDescriptorPair(t *testing.T) {
	t.Setenv("DMP_RUNTIME_TLS_CERT_FD", "3")
	if _, err := loadTLSCertificate("panel", "", "", "DMP_RUNTIME_TLS_CERT_FD", "DMP_RUNTIME_TLS_KEY_FD"); err == nil {
		t.Fatal("expected incomplete runtime TLS descriptor configuration to fail")
	}
}

func TestTLSCertificatesSelectAccessCertificateBySNI(t *testing.T) {
	panelCertFile, panelKeyFile, panelSerial := writeTestCertificate(t, "panel.example.test")
	accessCertFile, accessKeyFile, accessSerial := writeTestCertificate(t, "*.access.example.test")
	certificates, err := loadTLSCertificates(config.Config{
		TLSCertFile: panelCertFile, TLSKeyFile: panelKeyFile,
		AccessTLSCertFile: accessCertFile, AccessTLSKeyFile: accessKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 2 {
		t.Fatalf("certificate count = %d, want 2", len(certificates))
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: certificates})
	serverErrors := make(chan error, 2)
	go func() {
		for range 2 {
			connection, acceptErr := tlsListener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				continue
			}
			serverErrors <- connection.(*tls.Conn).Handshake()
			_ = connection.Close()
		}
	}()

	for _, test := range []struct {
		serverName string
		wantSerial *big.Int
	}{{"panel.example.test", panelSerial}, {"session.access.example.test", accessSerial}} {
		connection, dialErr := tls.Dial("tcp", listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, ServerName: test.serverName, InsecureSkipVerify: true}) //nolint:gosec -- certificate identity is asserted below
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		peer := connection.ConnectionState().PeerCertificates[0]
		_ = connection.Close()
		if peer.SerialNumber.Cmp(test.wantSerial) != 0 {
			t.Fatalf("SNI %s selected serial %s, want %s", test.serverName, peer.SerialNumber, test.wantSerial)
		}
		if serverErr := <-serverErrors; serverErr != nil {
			t.Fatal(serverErr)
		}
	}
}

func TestIndependentAccessListenerRejectsControlPlaneHosts(t *testing.T) {
	forwarded := 0
	handler := accessOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded++
		w.WriteHeader(http.StatusNoContent)
	}), "remote.example.test")

	for _, test := range []struct {
		host       string
		wantStatus int
	}{{"panel.example.test", http.StatusNotFound}, {"remote.example.test", http.StatusNotFound}, {"session.remote.example.test:28443", http.StatusNoContent}} {
		request := httptest.NewRequest(http.MethodGet, "http://"+test.host+"/", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.wantStatus {
			t.Fatalf("host %s status = %d, want %d", test.host, response.Code, test.wantStatus)
		}
	}
	if forwarded != 1 {
		t.Fatalf("forwarded request count = %d, want 1", forwarded)
	}
}

func writeTestCertificate(t *testing.T, dnsName string) (string, string, *big.Int) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 120)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := directory + "/cert.pem"
	keyFile := directory + "/key.pem"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile, serial
}
