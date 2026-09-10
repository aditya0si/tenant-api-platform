# ADR-011: Forward-only embedded migrations, applied explicitly

**Status:** accepted (M1)

## Context

Schema changes need a mechanism that is safe to re-run, safe to run concurrently
from more than one deployer, and honest about the difference between development
convenience and production practice.

The migration tooling question (goose, golang-migrate, atlas, hand-rolled) turned
out to matter less than four properties of the mechanism:

1. Re-running applies nothing.
2. Two deployers starting at once do not race.
3. A failed migration leaves no partial schema.
4. Editing history is detected rather than silently diverging environments.

## Decision

A small in-repo runner over `//go:embed *.sql`: `internal/platform/migrations`,
driven by `cmd/migrate up|status|seed`.

- **Forward-only.** There are no down-migrations. A failed migration rolls back
  because each file runs inside its own transaction; a mistake is corrected by
  adding a new file. The down-path is where drift and data loss live, and for a
  service with a single deployable there is no case where rolling the schema back
  independently of the binary is the right move.
- **Explicit, not automatic.** The API does not migrate on boot. Holding DDL
  rights at runtime means a compromise or a bad start-up writes schema, and it
  makes the deployed artifact's schema a function of which instance booted first.
  `cmd/migrate up` is a separate step with separate credentials, and compose runs
  it as a one-shot container the API waits on.
- **Owner credentials for migrations, application credentials for everything
  else.** `MIGRATE_DATABASE_URL` is the owner role; `DATABASE_URL` is `app_rw`,
  which deliberately lacks DDL. The API is never issued the owner URL.
- **Advisory lock.** `pg_advisory_lock` serialises concurrent runners, so a
  rolling deploy's second instance waits and then observes the work as done. The
  unlock runs on a non-cancellable context: a cancelled deploy must not hold the
  lock until its session ends.
- **Checksums.** Each applied migration records the SHA-256 of its file. Changing
  an applied file fails the run with an explicit message rather than spreading
  divergence across environments.

## Consequences

- No down-migrations means a bad change is reverted by a new migration. That is a
  deliberate trade: it is slower in an emergency and far safer in the normal case.
- The runner is code this project owns and tests, rather than a dependency. It is
  about 250 lines; the tests cover idempotency, checksum recording, and
  concurrent runners.
- `schema_migrations` is revoked from `app_rw` after each run, so the application
  cannot rewrite its own history even though default privileges would otherwise
  grant it DML.
- Seeding runs as the **application** role, not the owner, so fixture inserts
  traverse the same policies as production traffic. A seed that bypassed RLS would
  be able to create states the API cannot, which is a bug class worth excluding.

## Alternatives considered

- **goose / golang-migrate.** Mature and well-tested, and genuinely reasonable
  here. Rejected because both bring their own history table semantics, their own
  locking model, and (for goose) a `database/sql` adapter alongside the pgx pool
  already in use. The four properties above are the whole requirement, and owning
  ~250 lines bought exact control over the lock and the checksum failure mode.
- **Atlas.** Strong declarative diffing, but it wants to own the schema
  definition, which is a larger commitment than this milestone needs.
- **Auto-migrate on boot.** Rejected as above.
- **Down-migrations.** Rejected as above.
