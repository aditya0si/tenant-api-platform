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
| Cross-cutting | HMAC-signed keyset pagination; `Idempotency-Key` protocol; Redis Lua rate limiting; append-only audit log; webhooks via transactional outbox with retries, a dead-letter queue, and replay; a hand-written [OpenAPI spec](docs/openapi.yaml) checked against the router |

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

- 304 test functions across 15 packages, against a real Postgres and a real Redis — the isolation
  tests measure the policies Postgres actually applies, not a fake.
- No test is skipped because a dependency is missing. A silently skipped isolation suite is worse
  than a red build, so the suite fails and says why.
- `.github/workflows/ci.yml` is the reference run: `gofmt`, `go vet`, the migrations, the full suite
  under `-race`, and `docker compose config`.
- `scripts/smoke_compose.py` drives the deployed stack end to end: probes on both processes, a
  session, the rate-limit headers, an idempotent retry, the SSRF guard, tenant boundaries, and the
  metrics each process exposes. It runs against `docker compose up` and found three defects the Go
  suite did not — a blocked webhook target answered 500 instead of 400, session responses carried
  no permissions, and the worker's outbox-depth gauge did not exist while the queue was empty.
  Its tests are the regression tests for those; the script is what proves the wiring in the
  deployed binary.

## Measured, not asserted

`load/api.js` is a [k6](https://k6.io) workload and `load/results.json` is the run it produced. The
figures below come from that file, not from a console scroll.

**Workload:** 30 tenants, one virtual user each, four reads per iteration paced to 7 requests/second
per tenant — 210 rps nominal, **192 rps achieved** across a 30-second window. Writes run afterward in
a separate 20-second window at ~24 rps, so their latency cannot contaminate the read figures.

| Endpoint | avg | p95 | p99 |
|---|---:|---:|---:|
| `GET /v1/tenants/{id}/projects` | 20.4 ms | 38.5 ms | 46.2 ms |
| `POST /v1/tenants/{id}/projects` | 36.0 ms | 49.0 ms | 60.1 ms |
| `GET /v1/tenants/{id}/invoices` | 16.4 ms | 25.6 ms | 31.1 ms |
| `GET /v1/tenants/{id}/api-keys` | 13.1 ms | 18.8 ms | 22.5 ms |
| `GET /v1/me` | 11.2 ms | 22.4 ms | 31.5 ms |

6,250 requests, **0 failures**, every threshold in the script passed. `docs/DESIGN.md` targets
p95 < 150 ms for CRUD at 200 rps; the measured p95 is 38.5 ms at 192 rps.

**What this is not.** Every component ran on one 13th-gen i7 laptop: the API as a native Windows
binary, Postgres 16 and Redis 7 in Docker Desktop, all on loopback with no TLS and no network hop. It
bounds this application's own overhead and says nothing about a distributed deployment. The rate
limiter was held at 70% of each tenant's ceiling (7 of 10 rps) so no request was throttled — the
numbers measure the endpoints, not the limiter.

Reproduce with `make load-seed && make load`.

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
idempotency, rate limiting, audit, webhooks, and API-key management. CI is green on `main`.

Not done yet, and stated rather than implied: a deployed instance. Tracing is correlation-id
propagation, not OpenTelemetry — no span is created or exported, and
[`docs/DESIGN.md`](docs/DESIGN.md) says so rather than implying otherwise.

## License

MIT — see [LICENSE](LICENSE).
