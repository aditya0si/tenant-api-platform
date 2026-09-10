// Package migrations embeds the schema migrations and applies them
// forward-only under a Postgres advisory lock.
//
// Design notes (see docs/adr/ADR-014-migrations.md):
//   - Forward-only. A failed migration rolls back atomically because each file
//     runs inside its own transaction; corrections ship as new files.
//   - A checksum is recorded per applied migration, so editing history is
//     detected instead of silently diverging across environments.
//   - pg_advisory_lock serialises concurrent deploys: the second deployer waits
//     rather than racing.
package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.sql
var embedded embed.FS

// advisoryLockKey is an arbitrary constant namespacing the migration lock.
const advisoryLockKey int64 = 0x7461702D6D696772 // "tap-migr"

// Migration is one embedded .sql file.
type Migration struct {
	Version  string // numeric prefix, e.g. "0001"
	Name     string // full file name, e.g. "0001_init.sql"
	SQL      string
	Checksum string // sha256 of the file contents
}

// Result reports what a run did.
type Result struct {
	Applied        []string
	AlreadyCurrent int
}

// Load reads and validates the embedded migrations, sorted by file name.
func Load() ([]Migration, error) {
	entries, err := fs.ReadDir(embedded, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	var out []Migration
	seen := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := embedded.ReadFile(e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		sum := sha256.Sum256(raw)
		version, _, ok := strings.Cut(e.Name(), "_")
		if !ok || version == "" {
			return nil, fmt.Errorf("migration %s must be named <version>_<name>.sql", e.Name())
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("duplicate migration version %s (%s and %s)", version, prev, e.Name())
		}
		seen[version] = e.Name()
		out = append(out, Migration{
			Version:  version,
			Name:     e.Name(),
			SQL:      string(raw),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	if len(out) == 0 {
		return nil, errors.New("no embedded migrations found")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Status is one row of applied migration history.
type Status struct {
	Version   string
	Name      string
	Checksum  string
	AppliedAt string
}

// Up applies every pending migration. Safe to call concurrently: the advisory
// lock makes a second caller wait, then observe the work as already done.
func Up(ctx context.Context, pool *pgxpool.Pool) (Result, error) {
	migs, err := Load()
	if err != nil {
		return Result{}, err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return Result{}, fmt.Errorf("take advisory lock: %w", err)
	}
	defer func() {
		// Unlock with a context that survives caller cancellation, otherwise a
		// cancelled deploy would hold the lock until the session ends.
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text PRIMARY KEY,
		name       text NOT NULL,
		checksum   text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return Result{}, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	applied, err := appliedChecksums(ctx, conn)
	if err != nil {
		return Result{}, err
	}

	var res Result
	for _, m := range migs {
		if prev, ok := applied[m.Version]; ok {
			if prev != m.Checksum {
				return res, fmt.Errorf(
					"migration %s changed after it was applied (recorded checksum differs); migrations are immutable — add a new file instead",
					m.Name)
			}
			res.AlreadyCurrent++
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return res, err
		}
		res.Applied = append(res.Applied, m.Name)
	}

	// Migration history is not application data: the app role must not be able
	// to rewrite it. Default privileges granted it DML above, so revoke it.
	if _, err := conn.Exec(ctx, `DO $$
	BEGIN
		IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
			REVOKE ALL ON TABLE schema_migrations FROM app_rw;
		END IF;
	END $$`); err != nil {
		return res, fmt.Errorf("restrict schema_migrations: %w", err)
	}
	return res, nil
}

func appliedChecksums(ctx context.Context, conn *pgxpool.Conn) (map[string]string, error) {
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out[version] = checksum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return out, nil
}

func applyOne(ctx context.Context, conn *pgxpool.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin %s: %w", m.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("apply %s: %w", m.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
		m.Version, m.Name, m.Checksum); err != nil {
		return fmt.Errorf("record %s: %w", m.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit %s: %w", m.Name, err)
	}
	return nil
}

// Applied reports the recorded history, oldest first.
func Applied(ctx context.Context, pool *pgxpool.Pool) ([]Status, error) {
	rows, err := pool.Query(ctx,
		`SELECT version, name, checksum, applied_at::text FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	var out []Status
	for rows.Next() {
		var s Status
		if err := rows.Scan(&s.Version, &s.Name, &s.Checksum, &s.AppliedAt); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
