// Package testsupport wires database-backed tests to a real Postgres instance.
//
// Design choice worth stating plainly: these tests FAIL when the database is not
// configured, rather than skipping. A suite that silently skips its
// tenant-isolation assertions produces a green badge and zero evidence, which is
// worse than a red build. Local runs that genuinely cannot provide a database
// opt out explicitly with SKIP_DB_TESTS=1.
package testsupport

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/migrations"
)

// DB holds the two pools a database-backed test needs.
type DB struct {
	// App authenticates as the unprivileged application role (app_rw), so row
	// level security is genuinely in force for anything it runs.
	App *pgxpool.Pool
	// Owner authenticates as the migration role, used only to migrate the schema
	// and to inspect what the app role cannot see. Nil when no owner URL was
	// configured (the schema is then assumed to be current).
	Owner *pgxpool.Pool
}

var (
	migrateOnce sync.Once
	migrateErr  error
)

// RequireDB returns a migrated database handle or fails the test.
func RequireDB(t *testing.T) *DB {
	t.Helper()

	appURL := os.Getenv("TEST_DATABASE_URL")
	if appURL == "" {
		if os.Getenv("SKIP_DB_TESTS") == "1" {
			t.Skip("SKIP_DB_TESTS=1: skipping database-backed test")
		}
		t.Fatalf(`TEST_DATABASE_URL is not set.

Database-backed tests are mandatory: the tenant-isolation assertions are the
entire point of this package, and a suite that skips them proves nothing.

  docker compose up -d postgres
  make test            # provisions the test database and runs everything

Set SKIP_DB_TESTS=1 only to run the pure-unit subset locally.`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var owner *pgxpool.Pool
	if ownerURL := os.Getenv("TEST_MIGRATE_DATABASE_URL"); ownerURL != "" {
		p, err := pgxpool.New(ctx, ownerURL)
		if err != nil {
			t.Fatalf("testsupport: connect owner pool: %v", err)
		}
		if err := p.Ping(ctx); err != nil {
			t.Fatalf("testsupport: ping owner pool (%s): %v", ownerURL, err)
		}
		owner = p

		migrateOnce.Do(func() {
			mctx, mcancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer mcancel()
			if _, err := migrations.Up(mctx, owner); err != nil {
				migrateErr = err
			}
		})
		if migrateErr != nil {
			t.Fatalf("testsupport: apply migrations: %v", migrateErr)
		}
	}

	app, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatalf("testsupport: connect app pool: %v", err)
	}
	if err := app.Ping(ctx); err != nil {
		t.Fatalf("testsupport: ping app pool (%s): %v", appURL, err)
	}

	t.Cleanup(func() {
		app.Close()
		if owner != nil {
			owner.Close()
		}
	})
	return &DB{App: app, Owner: owner}
}

// AppPoolWithConns returns a second application pool with an explicit, small
// connection budget.
//
// This exists for the GUC-leakage test: with MaxConns=2 and many concurrent
// scopes, connections are guaranteed to be handed back and reused, which is the
// only way a session-scoped setting would reveal itself.
func (d *DB) AppPoolWithConns(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()

	cfg, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("testsupport: parse app url: %v", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = 0
	cfg.MaxConnLifetime = time.Minute
	cfg.MaxConnIdleTime = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("testsupport: build constrained pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
