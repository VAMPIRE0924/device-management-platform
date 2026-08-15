package main

import (
	"context"
	"crypto/tls"
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

func main() {
	if err := run(); err != nil {
		slog.Error("device management platform stopped", "error", err)
		os.Exit(1)
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
	sshGateway := access.NewSSHGateway(db, nodes, nodeCredentialVault)
	lifecycleManager := lifecycle.New(db, nodes, 30*time.Second)
	handler := api.New(api.Dependencies{
		Store:             db,
		Nodes:             nodes,
		Discovery:         discoveryManager,
		SSHGateway:        sshGateway,
		UI:                ui.Handler(),
		MFA:               mfaService,
		MFAEnabled:        cfg.MFAEnabled,
		MFAMethods:        cfg.MFAMethods,
		EmailSender:       emailSender,
		EmailCodeTTL:      cfg.EmailCodeTTL,
		TLSConfigured:     cfg.TLSCertFile != "",
		Settings:          config.NewSettingsManager(cfg),
		NodeCredentials:   nodeCredentialVault,
		APIToken:          cfg.APIToken,
		AccessDomain:      cfg.AccessDomain,
		AccessScheme:      cfg.AccessScheme,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
		Mode:              cfg.Mode,
		Version:           version,
	})
	runtimeTLSCertificate, err := loadRuntimeTLSCertificate()
	if err != nil {
		return err
	}
	tlsConfigured := cfg.TLSCertFile != "" || runtimeTLSCertificate != nil
	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	servers := []*http.Server{httpServer}
	if tlsConfigured {
		httpsServer := &http.Server{
			Addr:              cfg.HTTPSListenAddress,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       90 * time.Second,
		}
		if runtimeTLSCertificate != nil {
			httpsServer.TLSConfig = &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{*runtimeTLSCertificate},
			}
		}
		servers = append(servers, httpsServer)
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go lifecycleManager.Run(shutdownContext)
	var shutdownOnce sync.Once
	shutdownServers := func() {
		shutdownOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			for _, server := range servers {
				if err := server.Shutdown(ctx); err != nil {
					slog.Error("graceful shutdown failed", "address", server.Addr, "error", err)
				}
			}
		})
	}
	go func() {
		<-shutdownContext.Done()
		shutdownServers()
	}()

	errCh := make(chan error, len(servers))
	slog.Info("device management platform HTTP listening", "address", cfg.ListenAddress, "mode", cfg.Mode, "version", version)
	go func() { errCh <- httpServer.ListenAndServe() }()
	if tlsConfigured {
		httpsServer := servers[1]
		slog.Info("device management platform HTTPS listening", "address", cfg.HTTPSListenAddress, "mode", cfg.Mode, "version", version)
		certFile, keyFile := cfg.TLSCertFile, cfg.TLSKeyFile
		if runtimeTLSCertificate != nil {
			certFile, keyFile = "", ""
		}
		go func() { errCh <- httpsServer.ListenAndServeTLS(certFile, keyFile) }()
	}
	err = <-errCh
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	stop()
	shutdownServers()
	return err
}

func loadRuntimeTLSCertificate() (*tls.Certificate, error) {
	certFD, certConfigured := os.LookupEnv("DMP_RUNTIME_TLS_CERT_FD")
	keyFD, keyConfigured := os.LookupEnv("DMP_RUNTIME_TLS_KEY_FD")
	if certConfigured != keyConfigured {
		return nil, fmt.Errorf("runtime TLS certificate and key descriptors must be configured together")
	}
	if !certConfigured {
		return nil, nil
	}
	certPEM, err := readRuntimeTLSDescriptor(certFD, "certificate")
	if err != nil {
		return nil, err
	}
	keyPEM, err := readRuntimeTLSDescriptor(keyFD, "private key")
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load mounted TLS certificate: %w", err)
	}
	return &certificate, nil
}

func readRuntimeTLSDescriptor(rawFD, label string) ([]byte, error) {
	fd, err := strconv.ParseUint(rawFD, 10, 31)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("invalid runtime TLS %s descriptor", label)
	}
	file := os.NewFile(uintptr(fd), "runtime TLS "+label)
	if file == nil {
		return nil, fmt.Errorf("open runtime TLS %s descriptor", label)
	}
	defer file.Close()
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
