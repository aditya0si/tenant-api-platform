# tenant-api-platform

[![ci](https://github.com/aditya0si/tenant-api-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/aditya0si/tenant-api-platform/actions/workflows/ci.yml)

A multi-tenant billing API in Go. Many tenants share one Postgres database and their data cannot
mix: isolation is enforced in the application's type system, and again by row-level security inside
the database. It implements the parts of a billing backend that are hard to get right — idempotent
writes, distributed rate limiting, an append-only audit trail, compare-and-set state transitions,
and webhook delivery that survives a crash between committing a change and announcing it.

The design documents came first: [`docs/DESIGN.md`](docs/DESIGN.md) states the requirements, data
model, request flows, and failure table; [`docs/adr/`](docs/adr/) records the fourteen decisions
that shaped the code.

## What it covers

| Area | Implemented |
|---|---|
| Tenancy | Tenants, users, memberships, `owner > admin > member`, permission map in code |
| Auth | argon2id passwords; 10-minute HS256 access tokens; refresh tokens in rotating families with reuse detection; `ak_` API keys stored as SHA-256 |
| Billing | Invoices with line items; money as `int64` minor units; `draft → open → paid` and `void` transitions guarded by compare-and-set; append-only invoice events |
| Cross-cutting | HMAC-signed keyset pagination; `Idempotency-Key` protocol; Redis Lua rate limiting; append-only audit log; webhooks via transactional outbox with retries, a dead-letter queue, and replay |

## Architecture

```mermaid
flowchart LR
    C[Client] -->|JWT or API key| API["cmd/api"]
    API -->|tenant-scoped transactions| PG[(Postgres, RLS forced)]
    API -->|rate limits and idempotency locks| R[(Redis)]
    API -->|outbox row in the same transaction| OB[(webhook_outbox)]
    W["cmd/worker"] -->|FOR UPDATE SKIP LOCKED| OB
    W -->|signed POST| RX[Tenant receiver]
```

- `cmd/api` — the HTTP service.
- `cmd/worker` — delivers outbox rows. Same image, different entrypoint, so the two cannot drift.
- `cmd/migrate` — embedded forward-only migrations: `up`, `status`, `seed`, `sweep`.
- `internal/…` — one package per concern; 28 packages in total.

## Isolation, enforced twice

Every repository method takes a `tenant.Authorized` — a value type constructible only from an
authenticated principal — so an unscoped query does not compile into the happy path. Underneath,
each tenant table carries `FORCE ROW LEVEL SECURITY` with policies keyed on a transaction-scoped
`app.current_tenant_id`, set with `set_config(..., true)` so a pooled connection cannot carry one
tenant's identity into the next request. Cross-tenant access answers 404, never 403.

The suite contains the control that makes those tests mean something: it asserts the connection
role is neither superuser nor `BYPASSRLS`, and `cmd/api` refuses to boot on a privileged role —
because a superuser makes every isolation test pass while proving nothing.

## Running it

```bash
docker compose up --build   # postgres, redis, migrations, api, worker
```

Or against a Postgres and Redis you already run:

```bash
go run ./cmd/migrate up
go run ./cmd/api          # DATABASE_URL, REDIS_URL, JWT_SECRET — see .env.example
go run ./cmd/worker
```

`make up`, `make migrate`, `make seed`, and `make sweep` wrap the same commands.

## Tests

```bash
export TEST_DATABASE_URL='postgres://app_rw:app_rw@localhost:5432/tenant_platform_test?sslmode=disable'
export TEST_MIGRATE_DATABASE_URL='postgres://postgres:postgres@localhost:5432/tenant_platform_test?sslmode=disable'
export TEST_REDIS_URL='redis://localhost:6379/1'
go test -race ./...
```

- 297 test functions across 15 packages, against a real Postgres and a real Redis — the isolation
  tests measure the policies Postgres actually applies, not a fake.
- No test is skipped because a dependency is missing. A silently skipped isolation suite is worse
  than a red build, so the suite fails and says why.
- `.github/workflows/ci.yml` is the reference run: `gofmt`, `go vet`, the migrations, the full suite
  under `-race`, and `docker compose config`.

## Decisions worth arguing about

| Decision | Why |
|---|---|
| [Transactional outbox, not a broker](docs/adr/ADR-001-transactional-outbox.md) | A broker client cannot join a Postgres transaction, so every arrangement either loses events or announces changes that rolled back. |
| [RLS as defence in depth](docs/adr/ADR-003-tenancy-and-rls.md) | The scope type is primary; RLS is the second gate that survives an application bug. |
| [Idempotency is database-primary](docs/adr/ADR-004-idempotency.md) | Redis is a lock, never the record: a cache that loses keys must not duplicate a payment. |
| [Signed keyset cursors](docs/adr/ADR-014-cursor-pagination.md) | `OFFSET` is silently wrong on a live table, and costs more the deeper a client pages. |
| [No token denylist](docs/adr/ADR-012-short-lived-tokens.md) | Access tokens carry identity only, so there is nothing per-request to revoke. |
| [Static RBAC map](docs/adr/ADR-009-static-authorization.md) | The role hierarchy is a property of the product, not tenant data. |

## Status

M0–M8 are implemented, tested, and committed: tenancy, authentication, projects, invoices,
idempotency, rate limiting, audit, and webhooks.

Not done yet, and stated rather than implied: the hand-written OpenAPI spec and its contract test
([ADR-010](docs/adr/ADR-010-router-and-openapi.md)), k6 load numbers, and a deployed instance.

## License

MIT — see [LICENSE](LICENSE).
