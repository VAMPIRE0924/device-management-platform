package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	dsn := (&url.URL{Scheme: "file", Path: absPath}).String() + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) Backup(ctx context.Context, destination string) error {
	abs, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve backup destination: %w", err)
	}
	if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous backup: %w", err)
	}
	quoted := strings.ReplaceAll(abs, "'", "''")
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO '"+quoted+"'"); err != nil {
		return fmt.Errorf("create sqlite backup: %w", err)
	}
	return nil
}

func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	for index, migration := range migrations {
		version := index + 1
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&exists)
		if err != nil {
			return err
		}
		if exists > 0 {
			continue
		}
		if version == 13 {
			var legacyColumnCount int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='access_type'`).Scan(&legacyColumnCount); err != nil {
				return fmt.Errorf("inspect legacy node schema: %w", err)
			}
			if legacyColumnCount > 0 {
				if _, err := tx.ExecContext(ctx, `ALTER TABLE nodes DROP COLUMN access_type`); err != nil {
					return fmt.Errorf("remove legacy node access type: %w", err)
				}
			}
		}
		if version == 14 {
			var legacyColumnCount int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('projects') WHERE name='tunnel_on_demand'`).Scan(&legacyColumnCount); err != nil {
				return fmt.Errorf("inspect legacy project schema: %w", err)
			}
			if legacyColumnCount > 0 {
				if _, err := tx.ExecContext(ctx, `ALTER TABLE projects DROP COLUMN tunnel_on_demand`); err != nil {
					return fmt.Errorf("remove legacy project tunnel policy: %w", err)
				}
			}
		}
		if version == 15 {
			for _, column := range []string{"gateway_mode", "gateway_name", "gateway_status", "runtime_type", "runtime_address"} {
				var count int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('projects') WHERE name=?`, column).Scan(&count); err != nil {
					return fmt.Errorf("inspect legacy project column %s: %w", column, err)
				}
				if count > 0 {
					if _, err := tx.ExecContext(ctx, `ALTER TABLE projects DROP COLUMN `+column); err != nil {
						return fmt.Errorf("remove legacy project column %s: %w", column, err)
					}
				}
			}
		}
		if strings.TrimSpace(migration) != "" {
			if _, err := tx.ExecContext(ctx, migration); err != nil {
				return fmt.Errorf("apply migration %d: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, err
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}
