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

## Rate limiting

Login, registration, and refresh are limited per client address; authenticated traffic is
limited per tenant. Policies live in `internal/httpx/ratelimit.go` as code constants rather
than configuration, because each is coupled to what it protects (see `docs/adr/ADR-005-rate-limiting.md`).

**Address attribution is the part that needs configuring.** By default the service trusts no
forwarding header and attributes every request to its socket address, which a caller cannot
forge:

```sh
TRUSTED_PROXY_CIDRS=10.0.0.0/8,192.168.0.0/16
```

Set this only when the service is unreachable except through those proxies. Both ways of
getting it wrong are silent, which is why the default is the safe one:

- **Unset while behind a proxy** — every client shares one bucket and throttles each other.
  The service logs this at startup so it is not discovered from a support ticket.
- **Set when the peer is not a proxy** — the limiter is bypassable with one extra header.

Within a trusted chain, `X-Forwarded-For` is walked right to left, because each proxy appends
and the leftmost entry is therefore whatever the original client supplied. An entry that does
not parse as an address stops the walk and the peer is used instead: over-attributing clients
behind a proxy to one bucket is a degradation, while adopting an unparseable value as a key
would let a caller choose its own bucket.

### When Redis is down

The limiter fails **open**: requests are allowed, and that is deliberate, because refusing all
traffic would turn a cache outage into a total outage. The degradation is visible rather than
silent:

- `ratelimit_degraded_total` increments on every fail-open decision (the log line is
  rate-limited to one a minute; the metric carries the volume).
- Responses carry `X-RateLimit-Degraded: true`, and deliberately do **not** advertise
  `Remaining` — room that is not known to exist must not be claimed.

Readiness reports `degraded` while Redis is unreachable but stays **200**, so a functioning
instance is not taken out of rotation over an optional dependency.

A *server-side* error is the opposite case and is fatal at startup: it means the script is
wrong rather than Redis being absent, and a service that starts with an unusable limiter
enforces nothing while reporting healthy. If the API refuses to boot with
`rate limiter script for policy ... is invalid`, the script and Redis disagree and the process
is right not to start.

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
