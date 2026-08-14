package store

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RestoreDatabase replaces an offline database with a validated SQLite backup.
// If a database already exists, a consistent pre-restore snapshot is retained
// next to it and returned to the caller.
func RestoreDatabase(ctx context.Context, databasePath, backupPath string) (string, error) {
	target, err := filepath.Abs(databasePath)
	if err != nil {
		return "", fmt.Errorf("resolve database destination: %w", err)
	}
	source, err := filepath.Abs(backupPath)
	if err != nil {
		return "", fmt.Errorf("resolve backup source: %w", err)
	}
	if target == source {
		return "", fmt.Errorf("backup source and database destination must differ")
	}
	if err := validateBackup(ctx, source); err != nil {
		return "", fmt.Errorf("validate backup: %w", err)
	}
	if _, err := os.Stat(target + "-shm"); err == nil {
		return "", fmt.Errorf("database appears to be in use (%s exists); stop the service before restore", target+"-shm")
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("check database lock state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return "", fmt.Errorf("create database directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".i5cloud-restore-*.db")
	if err != nil {
		return "", fmt.Errorf("create restore staging file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", fmt.Errorf("secure restore staging file: %w", err)
	}
	input, err := os.Open(source)
	if err != nil {
		temporary.Close()
		return "", fmt.Errorf("open backup: %w", err)
	}
	_, copyErr := io.Copy(temporary, input)
	closeInputErr := input.Close()
	syncErr := temporary.Sync()
	closeTemporaryErr := temporary.Close()
	if copyErr != nil {
		return "", fmt.Errorf("copy backup: %w", copyErr)
	}
	if closeInputErr != nil || syncErr != nil || closeTemporaryErr != nil {
		return "", fmt.Errorf("flush restore staging file")
	}
	if err := validateBackup(ctx, temporaryPath); err != nil {
		return "", fmt.Errorf("validate staged backup: %w", err)
	}

	rollbackPath := ""
	if _, err := os.Stat(target); err == nil {
		current, openErr := Open(target)
		if openErr != nil {
			return "", fmt.Errorf("open current database for safety backup: %w", openErr)
		}
		rollbackPath = target + ".before-restore-" + time.Now().UTC().Format("20060102T150405Z") + ".db"
		backupErr := current.Backup(ctx, rollbackPath)
		closeErr := current.Close()
		if backupErr != nil {
			return "", fmt.Errorf("create pre-restore safety backup: %w", backupErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close current database: %w", closeErr)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("inspect current database: %w", err)
	}
	_ = os.Remove(target + "-wal")
	_ = os.Remove(target + "-shm")
	if err := os.Rename(temporaryPath, target); err != nil {
		return rollbackPath, fmt.Errorf("replace database: %w", err)
	}
	restored, err := Open(target)
	if err != nil {
		return rollbackPath, fmt.Errorf("open restored database: %w", err)
	}
	defer restored.Close()
	if err := restored.Migrate(ctx); err != nil {
		return rollbackPath, fmt.Errorf("migrate restored database: %w", err)
	}
	if err := restored.integrityCheck(ctx); err != nil {
		return rollbackPath, fmt.Errorf("verify restored database: %w", err)
	}
	return rollbackPath, nil
}

func validateBackup(ctx context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() < 100 {
		return fmt.Errorf("source is not a usable regular SQLite file")
	}
	dsn := (&url.URL{Scheme: "file", Path: path}).String() + "?mode=ro&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	var result string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if strings.ToLower(result) != "ok" {
		return fmt.Errorf("integrity_check returned %q", result)
	}
	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if !version.Valid || version.Int64 < 1 {
		return fmt.Errorf("backup has no schema version")
	}
	if version.Int64 > int64(schemaVersion) {
		return fmt.Errorf("backup schema version %d is newer than supported version %d", version.Int64, schemaVersion)
	}
	return nil
}

func (s *Store) integrityCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if strings.ToLower(result) != "ok" {
		return fmt.Errorf("integrity_check returned %q", result)
	}
	return nil
}
