# Operations

What is implemented today, and how to run it. Sections describe only behaviour that
exists and has been exercised — a runbook for a feature that is not built is worse than
no runbook.

## Migrations

Forward-only, embedded, applied under a Postgres advisory lock. Corrections ship as new
files; there are no down-migrations (ADR-011).

```sh
make migrate          # or: go run ./cmd/migrate up
go run ./cmd/migrate status
```

`up` and `status` need owner credentials (`MIGRATE_DATABASE_URL`). A failed migration
rolls back atomically — each file runs in its own transaction — and a checksum is
recorded per applied migration, so editing history is detected rather than silently
diverging between environments.

## Reaping expired idempotency keys

`idempotency_keys` retains a key for 24 hours, and stale claims left by a process that
died are swept once their lease lapses. Neither is collected automatically.

```sh
go run ./cmd/migrate sweep        # or: make sweep
# swept 0 expired idempotency record(s)
```

**This must run with owner credentials** (`MIGRATE_DATABASE_URL`), which is the same role
that applies migrations.

The reason is exact and worth stating: `idempotency_keys` carries `FORCE ROW LEVEL
SECURITY`, and `FORCE` means the table owner is subject to the policy as well. A delete
issued with no tenant identity is filtered to zero rows *while reporting success*. A
reaper that silently returns zero every night is indistinguishable from a healthy one
until the disk fills.

So `Sweep` refuses rather than lying. If it is run against a role subject to row-level
security it returns an error naming the requirement instead of deleting nothing:

```
sweep: the connected role is subject to row-level security, so the delete would be
silently filtered to zero rows. Run this with owner credentials (the same role that
applies migrations).
```

The printed count is meaningful because of that guard: `swept 0` from a role that can see
every tenant means there was nothing to collect, not that the sweep failed.

## Running the service

```sh
make up               # postgres + redis + migrate + api, via docker compose
make logs             # follow the api
make down             # stop everything, dropping volumes
```

The API connects as `app_rw`, a role with `NOSUPERUSER NOBYPASSRLS`. That is load-bearing
rather than tidy: superusers and `BYPASSRLS` roles ignore row-level security, so pointing
`DATABASE_URL` at one silently disables tenant isolation while every endpoint keeps
returning 200. `cmd/api` refuses to start in that configuration unless
`ALLOW_PRIVILEGED_DB_ROLE=1` is set, which exists for local debugging only.

## Tests

```sh
make test             # recreates the test database, then runs everything
make test-unit        # only the tests that need no database
```

Database-backed tests **fail rather than skip** when `TEST_DATABASE_URL` is unset: the
tenant-isolation assertions are the point of the suite, and a suite that silently skips
them proves nothing. `SKIP_DB_TESTS=1` runs the pure-unit subset during development.

The suite connects as `app_rw` on purpose, so row-level security is genuinely in force.
The isolation tests pass on that role and **fail when connected as superuser** — that
negative control is what makes them a measurement of RLS rather than of application-level
filtering, and it is the first thing to re-run if isolation is ever suspected.

`-race` cannot build natively on a 32-bit MinGW toolchain. On Windows it runs in the
`golang:1.27` container:

```sh
docker run --rm -v "$PWD":/src -w /src -e CGO_ENABLED=1 \
  -e TEST_DATABASE_URL='postgres://app_rw:...@host.docker.internal:5432/tenant_platform_test?sslmode=disable' \
  -e TEST_MIGRATE_DATABASE_URL='postgres://postgres:...@host.docker.internal:5432/tenant_platform_test?sslmode=disable' \
  golang:1.27 go test -race -count=1 ./...
```

## Debugging tenancy

Cross-tenant access returns **404, never 403**. A 403 would confirm that a resource
exists and that the caller simply cannot reach it, which is an enumeration oracle; 404
makes "no such tenant" and "not your tenant" indistinguishable. A 403 from a tenant-
scoped route therefore means a permission problem *within* a tenant the caller does belong
to, and a 404 means they do not belong to it at all.
