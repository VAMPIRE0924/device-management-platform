package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/VAMPIRE0924/device-management-platform/backend/internal/access"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/api"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/auth"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/config"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/discovery"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/lifecycle"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/nodeadapter"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/secrets"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/store"
	"github.com/VAMPIRE0924/device-management-platform/backend/internal/ui"
)

var version = "dev"
var errRestartRequested = errors.New("panel restart requested")

func main() {
	for {
		err := run()
		if errors.Is(err, errRestartRequested) {
			slog.Info("device management platform reloading saved settings")
			continue
		}
		if err != nil {
			slog.Error("device management platform stopped", "error", err)
			os.Exit(1)
		}
		return
	}
}

func run() error {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	if command == "version" {
		fmt.Println(version)
		return nil
	}
	if command != "serve" && command != "migrate" && command != "restore" && command != "mfa-reset" && command != "healthcheck" {
		return fmt.Errorf("unknown command %q (use serve, migrate, restore, mfa-reset, healthcheck, or version)", command)
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if command == "healthcheck" {
		return checkHealth(cfg)
	}
	if command == "restore" {
		if len(os.Args) != 3 {
			return fmt.Errorf("usage: device-management-platform restore /path/to/device-management-platform-backup.db")
		}
		rollbackPath, err := store.RestoreDatabase(context.Background(), cfg.DatabasePath, os.Args[2])
		if err != nil {
			return err
		}
		if rollbackPath == "" {
			slog.Info("database restore complete", "path", cfg.DatabasePath)
		} else {
			slog.Info("database restore complete", "path", cfg.DatabasePath, "pre_restore_backup", rollbackPath)
		}
		return nil
	}

	db, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if err := db.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	if command == "migrate" {
		slog.Info("database migrations complete", "path", cfg.DatabasePath)
		return nil
	}
	if command == "mfa-reset" {
		if len(os.Args) != 3 {
			return fmt.Errorf("usage: device-management-platform mfa-reset username")
		}
		audit := store.AuditInput{Actor: "break-glass-cli", Action: "user.mfa_reset", ResourceType: "user", Result: "success", RequestID: "offline-cli", SourceIP: "local-console"}
		if err := db.ResetUserMFAByUsername(context.Background(), os.Args[2], audit); err != nil {
			return fmt.Errorf("reset MFA: %w", err)
		}
		slog.Info("MFA reset complete; the user must enroll again after password verification", "username", os.Args[2])
		return nil
	}
	nodeCredentialVault, err := secrets.LoadOrCreateNodeCredentialVault(db, filepath.Join(cfg.DataDirectory, "credentials.key"))
	if err != nil {
		return fmt.Errorf("initialize node credential vault: %w", err)
	}

	var mfaService *auth.MFA
	var emailSender auth.EmailSender
	if cfg.MFAEnabled {
		mfaService, err = auth.LoadOrCreateMFA(cfg.MFAKeyFile, cfg.Mode == "pro")
		if err != nil {
			return fmt.Errorf("initialize MFA: %w", err)
		}
		emailSender, err = auth.NewSMTPEmailSender(auth.SMTPConfig{Host: cfg.SMTPHost, Port: cfg.SMTPPort, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword, From: cfg.SMTPFrom, TLSMode: cfg.SMTPTLSMode})
		if err != nil {
			return fmt.Errorf("initialize SMTP: %w", err)
		}
	}

	nodes := nodeadapter.New(db, nodeCredentialVault)
	discoveryManager := discovery.NewManager(db, nodes)
	sshGateway := access.NewSSHGateway(db, nodes, nodeCredentialVault, cfg.AuthSessionIdleTTL)
	lifecycleManager := lifecycle.New(db, nodes, 30*time.Second)
	restartRequested := make(chan struct{}, 1)
	handler := api.New(api.Dependencies{
		Store:              db,
		Nodes:              nodes,
		Discovery:          discoveryManager,
		SSHGateway:         sshGateway,
		UI:                 ui.Handler(),
		MFA:                mfaService,
		MFAEnabled:         cfg.MFAEnabled,
		MFAMethods:         cfg.MFAMethods,
		EmailSender:        emailSender,
		EmailCodeTTL:       cfg.EmailCodeTTL,
		AuthSessionTTL:     cfg.AuthSessionTTL,
		AuthSessionIdleTTL: cfg.AuthSessionIdleTTL,
		TLSConfigured:      cfg.TLSCertFile != "",
		Settings:           config.NewSettingsManager(cfg),
		NodeCredentials:    nodeCredentialVault,
		APIToken:           cfg.APIToken,
		AccessDomain:       cfg.AccessDomain,
		AccessScheme:       cfg.AccessScheme,
		HTTPPort:           portFromAddress(cfg.ListenAddress),
		HTTPSPort:          portFromAddress(cfg.HTTPSListenAddress),
		AccessHTTPPort:     cfg.AccessHTTPPort,
		AccessHTTPSPort:    cfg.AccessHTTPSPort,
		TrustedProxyCIDRs:  cfg.TrustedProxyCIDRs,
		Mode:               cfg.Mode,
		Version:            version,
		Restart: func() {
			select {
			case restartRequested <- struct{}{}:
			default:
			}
		},
	})
	tlsCertificates, err := loadTLSCertificates(cfg)
	if err != nil {
		return err
	}
	tlsConfigured := len(tlsCertificates) > 0
	servers := []managedServer{{name: "panel HTTP", server: newApplicationServer(cfg.ListenAddress, handler, nil)}}
	if tlsConfigured {
		servers = append(servers, managedServer{name: "panel HTTPS", tls: true, server: newApplicationServer(cfg.HTTPSListenAddress, handler, tlsCertificates)})
	}
	if cfg.AccessHTTPPort != 0 {
		accessHandler := accessOnlyHandler(handler, cfg.AccessDomain)
		servers = append(servers, managedServer{name: "access HTTP", server: newApplicationServer(addressWithPort(cfg.ListenAddress, cfg.AccessHTTPPort), accessHandler, nil)})
		if tlsConfigured {
			servers = append(servers, managedServer{name: "access HTTPS", tls: true, server: newApplicationServer(addressWithPort(cfg.HTTPSListenAddress, cfg.AccessHTTPSPort), accessHandler, tlsCertificates)})
		}
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go lifecycleManager.Run(shutdownContext)
	var shutdownOnce sync.Once
	shutdownServers := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			for _, managed := range servers {
				if err := managed.server.Shutdown(ctx); err != nil {
					slog.Error("graceful shutdown failed", "address", managed.server.Addr, "error", err)
				}
			}
		})
	}
	go func() {
		<-shutdownContext.Done()
		shutdownServers()
	}()

	errCh := make(chan error, len(servers))
	for _, managed := range servers {
		slog.Info("device management platform listener started", "listener", managed.name, "address", managed.server.Addr, "mode", cfg.Mode, "version", version)
		go func(item managedServer) {
			if item.tls {
				errCh <- item.server.ListenAndServeTLS("", "")
				return
			}
			errCh <- item.server.ListenAndServe()
		}(managed)
	}
	select {
	case <-restartRequested:
		stop()
		shutdownServers()
		return errRestartRequested
	case err = <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		stop()
		shutdownServers()
		return err
	}
}

type managedServer struct {
	name   string
	server *http.Server
	tls    bool
}

func newApplicationServer(address string, handler http.Handler, certificates []tls.Certificate) *http.Server {
	server := &http.Server{
		Addr: address, Handler: handler, ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
	}
	if len(certificates) > 0 {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: certificates}
	}
	return server
}

func portFromAddress(address string) int {
	_, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		return 0
	}
	port, _ := strconv.Atoi(rawPort)
	return port
}

func addressWithPort(address string, port int) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func accessOnlyHandler(application http.Handler, accessDomain string) http.Handler {
	suffix := "." + strings.ToLower(strings.TrimSpace(accessDomain))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		if suffix == "." || !strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), suffix) {
			http.NotFound(w, r)
			return
		}
		application.ServeHTTP(w, r)
	})
}

func loadTLSCertificates(cfg config.Config) ([]tls.Certificate, error) {
	pairs := []struct {
		label                     string
		certFile, keyFile         string
		certFDEnvironmentVariable string
		keyFDEnvironmentVariable  string
	}{
		{label: "panel", certFile: cfg.TLSCertFile, keyFile: cfg.TLSKeyFile, certFDEnvironmentVariable: "DMP_RUNTIME_TLS_CERT_FD", keyFDEnvironmentVariable: "DMP_RUNTIME_TLS_KEY_FD"},
		{label: "access", certFile: cfg.AccessTLSCertFile, keyFile: cfg.AccessTLSKeyFile, certFDEnvironmentVariable: "DMP_RUNTIME_ACCESS_TLS_CERT_FD", keyFDEnvironmentVariable: "DMP_RUNTIME_ACCESS_TLS_KEY_FD"},
	}
	certificates := make([]tls.Certificate, 0, len(pairs))
	for _, pair := range pairs {
		certificate, err := loadTLSCertificate(pair.label, pair.certFile, pair.keyFile, pair.certFDEnvironmentVariable, pair.keyFDEnvironmentVariable)
		if err != nil {
			return nil, err
		}
		if certificate != nil {
			certificates = append(certificates, *certificate)
		}
	}
	return certificates, nil
}

func loadTLSCertificate(label, certFile, keyFile, certFDEnvironmentVariable, keyFDEnvironmentVariable string) (*tls.Certificate, error) {
	certFD, certConfigured := os.LookupEnv(certFDEnvironmentVariable)
	keyFD, keyConfigured := os.LookupEnv(keyFDEnvironmentVariable)
	if certConfigured != keyConfigured {
		return nil, fmt.Errorf("runtime %s TLS certificate and key descriptors must be configured together", label)
	}
	if !certConfigured && certFile == "" && keyFile == "" {
		return nil, nil
	}
	// The entrypoint may open a root-readable NAS certificate before dropping
	// privileges. That descriptor is valid only for the path it was opened
	// from. When a saved setting changes the path, load the new path instead of
	// silently continuing to serve the old certificate.
	if certConfigured {
		certPathVariable := strings.TrimSuffix(certFDEnvironmentVariable, "_FD") + "_PATH"
		keyPathVariable := strings.TrimSuffix(keyFDEnvironmentVariable, "_FD") + "_PATH"
		openedCertPath, certPathConfigured := os.LookupEnv(certPathVariable)
		openedKeyPath, keyPathConfigured := os.LookupEnv(keyPathVariable)
		if certPathConfigured != keyPathConfigured {
			return nil, fmt.Errorf("runtime %s TLS certificate and key paths must be configured together", label)
		}
		if certPathConfigured && (certFile != openedCertPath || keyFile != openedKeyPath) {
			certConfigured = false
		}
	}
	var certificate tls.Certificate
	var err error
	if certConfigured {
		certPEM, readErr := readRuntimeTLSDescriptor(certFD, label+" certificate")
		if readErr != nil {
			return nil, readErr
		}
		keyPEM, readErr := readRuntimeTLSDescriptor(keyFD, label+" private key")
		if readErr != nil {
			return nil, readErr
		}
		certificate, err = tls.X509KeyPair(certPEM, keyPEM)
	} else {
		certificate, err = tls.LoadX509KeyPair(certFile, keyFile)
	}
	if err != nil {
		return nil, fmt.Errorf("load %s TLS certificate: %w", label, err)
	}
	if certificate.Leaf == nil && len(certificate.Certificate) > 0 {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse %s TLS certificate: %w", label, err)
		}
	}
	return &certificate, nil
}

func readRuntimeTLSDescriptor(rawFD, label string) ([]byte, error) {
	fd, err := strconv.ParseUint(rawFD, 10, 31)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("invalid runtime TLS %s descriptor", label)
	}
	// Keep the inherited descriptor open for the lifetime of the process. The
	// server can reload saved settings without restarting the container, so a
	// TLS certificate may need to be read more than once. Rewind the duplicate
	// for every read while leaving the inherited descriptor itself open.
	duplicatedFD, err := syscall.Dup(int(fd))
	if err != nil {
		return nil, fmt.Errorf("duplicate runtime TLS %s descriptor: %w", label, err)
	}
	file := os.NewFile(uintptr(duplicatedFD), "runtime TLS "+label)
	if file == nil {
		_ = syscall.Close(duplicatedFD)
		return nil, fmt.Errorf("open runtime TLS %s descriptor", label)
	}
	defer file.Close()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind runtime TLS %s: %w", label, err)
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read runtime TLS %s: %w", label, err)
	}
	return contents, nil
}

func checkHealth(cfg config.Config) error {
	_, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("parse listen address for healthcheck: %w", err)
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/health/ready")
	if err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned %s", response.Status)
	}
	return nil
}
