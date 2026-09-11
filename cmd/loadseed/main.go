// Command loadseed provisions tenants and sessions for the k6 load test.
//
// # Why this exists instead of registering through the API
//
// The load test needs N tenants, each a separate rate-limit bucket, because PolicyAPI bounds
// authenticated traffic at 600 requests/minute *per tenant*. Registering those tenants through
// POST /v1/auth/register cannot work: PolicyRegister is 5 attempts per hour per address, so the
// fourth registration is refused. That limit is correct and is not weakened for a benchmark — a
// load test that requires disabling a production control measures a system that is not the one
// deployed. So provisioning happens here, through the store, with no HTTP involved.
//
// # Why the password is in the source
//
// These accounts exist only for a benchmark against a local instance, and a fixed password makes a
// run reproducible. That is indefensible anywhere else, so the command refuses to run against a
// database whose name it does not recognise rather than relying on a comment to prevent it.
//
// # Why the sessions are written to a file
//
// The tokens expire with AccessTokenTTL (ten minutes), and the file is gitignored. Printing them
// instead would mean pasting credentials through a shell history for no benefit.
//
// Usage:
//
//	go run ./cmd/loadseed -tenants 30 -out load/sessions.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/config"
	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// loadPassword is shared by every generated owner. See the note above on why it is acceptable
// here and nowhere else.
const loadPassword = "load-test-password-not-a-secret"

// session is one tenant's credentials, in the shape k6 consumes.
type session struct {
	Token    string `json:"token"`
	TenantID string `json:"tenantID"`
}

func main() {
	tenants := flag.Int("tenants", 30, "how many tenants to provision")
	out := flag.String("out", "load/sessions.json", "write sessions as JSON to this path")
	flag.Parse()

	if *tenants < 1 || *tenants > 500 {
		fmt.Fprintln(os.Stderr, "error: -tenants must be between 1 and 500")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := run(ctx, *tenants, *out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, count int, outPath string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	var dbName string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		return fmt.Errorf("inspect database: %w", err)
	}
	if !looksLocal(dbName) {
		return fmt.Errorf(
			"refusing to seed load accounts into database %q: this command creates accounts whose "+
				"password is in the source tree, so it runs only against a local instance", dbName)
	}

	tokens, err := authn.NewTokenIssuer(cfg.JWTSecret, authn.DefaultIssuer, authn.DefaultAudience, cfg.AccessTokenTTL)
	if err != nil {
		return fmt.Errorf("token issuer: %w", err)
	}

	tenantsStore := tenant.NewStore(pool)
	projectsStore := project.NewStore(pool)

	// Hashed once and reused. argon2 at its production cost is deliberately slow, and paying it
	// once per tenant would dominate a command whose whole job is to set up a benchmark.
	hash, err := authn.HashPassword(loadPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	suffix := idgen.ShortSuffix(8)
	sessions := make([]session, 0, count)

	for i := 0; i < count; i++ {
		tenantID := uuid.Must(uuid.NewV7())
		ownerID := uuid.Must(uuid.NewV7())

		err := tenantsStore.CreateTenantWithOwner(ctx, tenant.Tenant{
			ID:   tenantID,
			Slug: fmt.Sprintf("load-%s-%03d", suffix, i),
			Name: fmt.Sprintf("Load Tenant %03d", i),
		}, tenant.Owner{
			ID:     ownerID,
			Email:  fmt.Sprintf("load-%s-%03d@load.test", suffix, i),
			PWHash: hash,
		}, authz.RoleOwner)
		if err != nil {
			return fmt.Errorf("create tenant %d: %w", i, err)
		}

		// Minted directly rather than obtained by logging in, so no HTTP and no login limit is
		// involved. It is indistinguishable from a logged-in token — same issuer, audience, claims
		// and lifetime — because the same issuer produces it.
		access, _, err := tokens.Mint(ownerID)
		if err != nil {
			return fmt.Errorf("mint token %d: %w", i, err)
		}

		// One seeded project per tenant, so the listing endpoint returns a row rather than an empty
		// set. Measuring an empty result would report the fastest possible query and call it the
		// production number.
		auth, err := tenantsStore.Resolve(ctx, tenantID, ownerID)
		if err != nil {
			return fmt.Errorf("resolve tenant %d: %w", i, err)
		}
		if _, err := projectsStore.Create(ctx, auth, project.CreateInput{
			Name:        "Seed project",
			Description: "created by cmd/loadseed",
		}); err != nil {
			return fmt.Errorf("seed project %d: %w", i, err)
		}

		sessions = append(sessions, session{Token: access, TenantID: tenantID.String()})
	}

	payload, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sessions: %w", err)
	}
	// 0600: the file holds bearer credentials for ten minutes, so it is readable by the owner only.
	if err := os.WriteFile(outPath, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	fmt.Printf("provisioned %d tenants in %s\n", count, dbName)
	fmt.Printf("wrote %s (access tokens expire in %s)\n", outPath, cfg.AccessTokenTTL)
	return nil
}

// looksLocal reports whether a database name identifies a local development instance.
//
// A name check rather than a hostname check, deliberately: the dangerous case is someone pointing
// this at a managed database whose name they happened to keep, and these are the only two names
// this repository creates. It is a guard against a mistake, not a security control.
func looksLocal(name string) bool {
	return name == "tenant_platform" || name == "tenant_platform_test"
}
