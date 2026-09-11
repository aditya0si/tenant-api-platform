package db

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AllowPrivilegedRoleEnv is the escape hatch that permits a privileged connection.
//
// It is an environment variable rather than a permissive default so that running without
// row-level security is a decision someone records, and the name is exported because both
// binaries and their tests refer to the same string.
const AllowPrivilegedRoleEnv = "ALLOW_PRIVILEGED_DB_ROLE"

// AssertUnprivilegedRole refuses to run when the database connection can bypass row-level security.
//
// # Why this is enforced rather than documented
//
// The failure is invisible. Every query still works, every application-level test still passes,
// and the only thing lost is the second layer of tenant isolation — the layer that holds when a
// query forgets its predicate. A service that boots with that layer disabled looks entirely
// healthy, which is exactly why a comment is not enough.
//
// # Why both binaries call it
//
// The API must not run as a superuser because its tenant policies would be decorative. The worker
// must not either, and for a subtler reason: the worker's cross-tenant access is granted by a
// *policy* (`app.worker`, migration 0011), so a superuser worker would still deliver everything —
// it would simply bypass the mechanism that bounds it. Running it privileged would look like it
// worked while removing the constraint the design rests on.
func AssertUnprivilegedRole(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) error {
	if os.Getenv(AllowPrivilegedRoleEnv) == "1" {
		if log == nil {
			log = slog.Default()
		}
		log.Warn("starting with a privileged database role: row-level security is NOT enforced; " +
			"this is only appropriate for a local debugging session")
		return nil
	}

	var (
		currentUser string
		isSuper     bool
		bypassRLS   bool
	)
	err := pool.QueryRow(ctx, `
		SELECT current_user,
		       (SELECT rolsuper     FROM pg_roles WHERE rolname = current_user),
		       (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)`).
		Scan(&currentUser, &isSuper, &bypassRLS)
	if err != nil {
		return fmt.Errorf("inspect database role: %w", err)
	}

	switch {
	case isSuper:
		return fmt.Errorf(
			"database role %q is a SUPERUSER: superusers bypass row-level security unconditionally, "+
				"so every tenant policy would be decorative. Point DATABASE_URL at the application role "+
				"(app_rw, created by the migrations) and keep the owner credentials in "+
				"MIGRATE_DATABASE_URL. Set %s=1 to start anyway, for local debugging only",
			currentUser, AllowPrivilegedRoleEnv)
	case bypassRLS:
		return fmt.Errorf(
			"database role %q has BYPASSRLS: it ignores row-level security, so tenant isolation would "+
				"not be enforced by the database. Use the application role (app_rw). "+
				"Set %s=1 to start anyway, for local debugging only",
			currentUser, AllowPrivilegedRoleEnv)
	}
	return nil
}
