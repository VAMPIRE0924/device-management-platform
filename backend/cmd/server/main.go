package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
		CookieSecure:      cfg.CookieSecure,
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
	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	shutdownContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go lifecycleManager.Run(shutdownContext)
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
		}
	}()

	slog.Info("device management platform API listening", "address", cfg.ListenAddress, "mode", cfg.Mode, "version", version)
	if cfg.TLSCertFile != "" {
		err = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func checkHealth(cfg config.Config) error {
	_, port, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("parse listen address for healthcheck: %w", err)
	}
	scheme := "http"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.TLSCertFile != "" {
		scheme = "https"
		// The probe connects only to this container's loopback listener. Certificate
		// trust and hostname are validated on real client-facing connections.
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: transport}
	response, err := client.Get(scheme + "://" + net.JoinHostPort("127.0.0.1", port) + "/health/ready")
	if err != nil {
		return fmt.Errorf("health probe failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health probe returned %s", response.Status)
	}
	return nil
}
