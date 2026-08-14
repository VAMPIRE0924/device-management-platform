package auth

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type smtpTestServer struct {
	listener  net.Listener
	tlsConfig *tls.Config
	mode      string
	messages  chan string
}

func newSMTPTestServer(t *testing.T, mode string) (*smtpTestServer, *x509.CertPool) {
	t.Helper()
	certificate, pool := testTLSCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &smtpTestServer{listener: listener, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, mode: mode, messages: make(chan string, 1)}
	go server.serve()
	t.Cleanup(func() { listener.Close() })
	return server, pool
}

func (server *smtpTestServer) serve() {
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			return
		}
		go server.handle(connection)
	}
}

func (server *smtpTestServer) handle(connection net.Conn) {
	defer connection.Close()
	secure := false
	if server.mode == "tls" {
		wrapped := tls.Server(connection, server.tlsConfig)
		if wrapped.Handshake() != nil {
			return
		}
		connection = wrapped
		secure = true
	}
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	writeSMTPLine(writer, "220 localhost ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimSpace(line)
		upper := strings.ToUpper(command)
		switch {
		case strings.HasPrefix(upper, "EHLO") || strings.HasPrefix(upper, "HELO"):
			if server.mode == "starttls" && !secure {
				writeSMTPRaw(writer, "250-localhost\r\n250-STARTTLS\r\n250 OK\r\n")
			} else {
				writeSMTPLine(writer, "250 localhost")
			}
		case upper == "STARTTLS" && server.mode == "starttls" && !secure:
			writeSMTPLine(writer, "220 Ready to start TLS")
			wrapped := tls.Server(connection, server.tlsConfig)
			if wrapped.Handshake() != nil {
				return
			}
			connection = wrapped
			reader = bufio.NewReader(connection)
			writer = bufio.NewWriter(connection)
			secure = true
		case strings.HasPrefix(upper, "MAIL FROM:") || strings.HasPrefix(upper, "RCPT TO:"):
			writeSMTPLine(writer, "250 OK")
		case upper == "DATA":
			writeSMTPLine(writer, "354 End data with <CR><LF>.<CR><LF>")
			var message strings.Builder
			for {
				dataLine, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if strings.TrimSpace(dataLine) == "." {
					break
				}
				message.WriteString(dataLine)
			}
			select {
			case server.messages <- message.String():
			default:
			}
			writeSMTPLine(writer, "250 queued")
		case upper == "QUIT":
			writeSMTPLine(writer, "221 bye")
			return
		default:
			writeSMTPLine(writer, "502 unsupported")
		}
	}
}

func writeSMTPLine(writer *bufio.Writer, value string) {
	writeSMTPRaw(writer, value+"\r\n")
}

func writeSMTPRaw(writer *bufio.Writer, value string) {
	_, _ = writer.WriteString(value)
	_ = writer.Flush()
}

func testTLSCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certificatePEM)
	return certificate, pool
}

func (server *smtpTestServer) address(t *testing.T) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestSMTPEmailSenderUsesEncryptedConnections(t *testing.T) {
	for _, mode := range []string{"starttls", "tls"} {
		t.Run(mode, func(t *testing.T) {
			server, roots := newSMTPTestServer(t, mode)
			host, port := server.address(t)
			sender, err := NewSMTPEmailSender(SMTPConfig{Host: host, Port: port, From: "I5CLOUD <sender@example.test>", TLSMode: mode, ServerName: "localhost", RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.SendCode(t.Context(), "recipient@example.test", "482913", 10*time.Minute); err != nil {
				t.Fatal(err)
			}
			select {
			case message := <-server.messages:
				if !strings.Contains(message, "482913") || !strings.Contains(message, "recipient@example.test") {
					t.Fatalf("unexpected SMTP message: %s", message)
				}
			case <-time.After(time.Second):
				t.Fatal("SMTP message was not delivered")
			}
		})
	}
}

func TestSMTPEmailSenderRejectsMissingSTARTTLS(t *testing.T) {
	server, roots := newSMTPTestServer(t, "none")
	host, port := server.address(t)
	sender, err := NewSMTPEmailSender(SMTPConfig{Host: host, Port: port, From: "sender@example.test", TLSMode: "starttls", ServerName: "localhost", RootCAs: roots})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendCode(t.Context(), "recipient@example.test", "482913", 10*time.Minute); err == nil || !strings.Contains(err.Error(), "does not support STARTTLS") {
		t.Fatalf("expected STARTTLS capability error, got %v", err)
	}
}

func TestNewEmailCodeHasSixDigits(t *testing.T) {
	code, err := NewEmailCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("code %q does not have six digits", code)
	}
	if _, err := fmt.Sscanf(code, "%06d", new(int)); err != nil {
		t.Fatalf("code %q is not numeric", code)
	}
}
