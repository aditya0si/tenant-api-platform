// Command migrate applies schema migrations and seeds development data.
//
//	migrate up      apply pending migrations   (owner role: MIGRATE_DATABASE_URL)
//	migrate status  print recorded history     (owner role: MIGRATE_DATABASE_URL)
//	migrate seed    create two demo tenants    (app role: DATABASE_URL)
//
// The split is deliberate and load-bearing: the API never holds owner
// credentials, and the seed deliberately runs as the *unprivileged* application
// role so fixture data traverses the same row-level-security policies as
// production traffic. A seed running as the owner could create states the API
// cannot, which is a bug class worth excluding by construction.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/migrations"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// seedPassword is shared by both demo owners so a reviewer can log in
// immediately. It is intentionally obvious and must never be used outside local
// development.
const seedPassword = "SeedPassw0rd!2026"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "up":
		err = runUp(ctx)
	case "status":
		err = runStatus(ctx)
	case "seed":
		err = runSeed(ctx)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: migrate <command>

commands:
  up      apply pending migrations (needs MIGRATE_DATABASE_URL)
  status  show applied migrations  (needs MIGRATE_DATABASE_URL)
  seed    insert demo tenants      (needs DATABASE_URL, the application role)

environment:
  MIGRATE_DATABASE_URL  owner credentials; migrations only
  DATABASE_URL          application role credentials (app_rw)
`)
}

func runUp(ctx context.Context) error {
	pool, err := connect(ctx, ownerURL())
	if err != nil {
		return err
	}
	defer pool.Close()

	res, err := migrations.Up(ctx, pool)
	if err != nil {
		return err
	}
	for _, name := range res.Applied {
		fmt.Println("applied", name)
	}
	fmt.Printf("%d applied, %d already current\n", len(res.Applied), res.AlreadyCurrent)
	return nil
}

func runStatus(ctx context.Context) error {
	pool, err := connect(ctx, ownerURL())
	if err != nil {
		return err
	}
	defer pool.Close()

	migs, err := migrations.Load()
	if err != nil {
		return err
	}
	applied, err := migrations.Applied(ctx, pool)
	if err != nil {
		return err
	}

	seen := map[string]bool{}
	for _, a := range applied {
		seen[a.Version] = true
		fmt.Printf("%s  applied %s  %s\n", a.Version, a.AppliedAt, a.Name)
	}
	for _, m := range migs {
		if !seen[m.Version] {
			fmt.Printf("%s  pending              %s\n", m.Version, m.Name)
		}
	}
	return nil
}

func runSeed(ctx context.Context) error {
	pool, err := connect(ctx, appURL())
	if err != nil {
		return err
	}
	defer pool.Close()

	store := tenant.NewStore(pool)

	// Hashing once and reusing the digest keeps the seed fast; argon2 at the
	// production cost is deliberately slow, and paying it twice adds nothing.
	hash, err := authn.HashPassword(seedPassword)
	if err != nil {
		return fmt.Errorf("hash seed password: %w", err)
	}

	seeds := []struct{ slug, name, ownerEmail string }{
		{"acme", "Acme Corp", "owner@acme.test"},
		{"globex", "Globex Industries", "owner@globex.test"},
	}

	for _, s := range seeds {
		t := tenant.Tenant{ID: uuid.Must(uuid.NewV7()), Slug: s.slug, Name: s.name}
		owner := tenant.Owner{ID: uuid.Must(uuid.NewV7()), Email: s.ownerEmail, PWHash: hash}

		err := store.CreateTenantWithOwner(ctx, t, owner, authz.RoleOwner)
		switch {
		case errors.Is(err, apperr.ErrConflict):
			fmt.Printf("skipped  tenant %-8s already seeded\n", s.slug)
			continue
		case err != nil:
			return fmt.Errorf("seed %s: %w", s.slug, err)
		}
		fmt.Printf("created  tenant %-8s id=%s  owner=%s id=%s\n", s.slug, t.ID, s.ownerEmail, owner.ID)
	}

	fmt.Printf("\nseed login password for both owners: %s\n", seedPassword)
	fmt.Println("probe isolation: request tenant A with tenant B's credentials and expect 404, never 403")
	return nil
}

// connect opens and verifies a pool, so a misconfigured URL fails with a clear
// message instead of surfacing later as a mysterious query error.
func connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	if url == "" {
		return nil, errors.New("no database URL configured; set MIGRATE_DATABASE_URL (owner) and DATABASE_URL (app role)")
	}
	pool, err := db.NewPool(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// ownerURL is the migration/owner connection string.
func ownerURL() string {
	if v := os.Getenv("MIGRATE_DATABASE_URL"); v != "" {
		return v
	}
	return os.Getenv("DATABASE_URL")
}

// appURL is the unprivileged application connection string used by seed.
func appURL() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	return os.Getenv("MIGRATE_DATABASE_URL")
}
