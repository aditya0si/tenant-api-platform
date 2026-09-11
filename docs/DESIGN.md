# Tenant API Platform — Engineering Design (Phase 1)

Single-repo Project 1. Project 2 (streaming) starts only after this ships with benchmarks.

## 0. Recon (Phase 0 output)

- `aditya0si`: ~40 repos, zero Go. Strength: Python/TS FastAPI + Postgres + Redis + Docker + RAG/RBAC (`CoverAI`, `DevAtlas`, `schemeGPT`, `Sentinel`). Closest prior art: `CoverAI` — Postgres 15 + Redis 7 + FastAPI + Next.js, Compose with `service_healthy`, single `ci.yml`, `.env.example`, Makefile. Reuse: compose health gating, CI shape, env pattern. Do not copy: Python layering, no RLS, no outbox.
- Resume (`Desktop/resume/Aditya_Singh_SWE_Resume.tex`): IBM medical OCR + KG + hospital deploy; HCL 5-stage LangGraph RAG (96.4% faithfulness, +27.8% ctx precision, rate-limit + Prometheus). Gap for SWE screens: no Go service, no concurrent backend with idempotency/rate-limit/outbox/k6 numbers. This project fills exactly that.
- Toolchain verified: Go 1.27.0, k6 2.2.0, Docker server 29.6.2, gh auth `aditya0si` ok.

## A. Requirements (functional)

1. Orgs/tenants, users, memberships, roles `owner > admin > member`, RBAC permission map in code.
2. Auth: password (argon2id) + short-lived JWT access (10m) + opaque refresh family with rotation + reuse detection; API keys (`ak_` prefix, SHA-256 stored).
3. Projects CRUD, tenant-scoped. Invoices: line items, totals in minor units, state machine `draft → open → paid | void` with compare-and-set + append-only events.
4. Cross-cutting: cursor pagination, idempotency keys on unsafe methods, distributed rate limiting, audit log, webhooks via transactional outbox + retries + DLQ + replay + SSRF guard, OpenAPI with contract test (spec and contract test pending; see ADR-010), structured logs/metrics/traces, health/readiness.
5. Ops: `docker compose up` from fresh clone; seed; migrate; CI green; k6-measured numbers.

Non-requirements: no payments/PSP, no multi-region, no blue/green, no DB-driven policy engine, no NATS/Kafka in P1, no AI features, no microservices.

## B. Non-functional

- Correctness > latency. Tenant leak = P0. Double-apply on retry = P0.
- Local targets (laptop Docker, measured later, not claimed now): p95 < 150ms for CRUD at 200 rps; auth p95 < 100ms; webhook dispatch lag p99 < 30s.
- Availability: single-node; graceful degradation — Redis down → fail-open with metric; DB down → 503 readiness, 500 with envelope, no panic.
- Consistency: read-committed + app invariants; outbox gives at-least-once delivery, effectively-once processing via dedupe.
- Security: server-side tenant enforcement, 404-not-403 on cross-tenant access, HMAC cursors, HMAC webhook signatures with timestamp tolerance, SSRF guard.
- Observability: request ID everywhere, OTel traces HTTP→DB/Redis→worker, Prometheus histograms/counters, Grafana later.

## C. Architecture

Single Go module, two binaries sharing `internal/`:

```
cmd/api/ cmd/worker/ cmd/migrate/
internal/auth/ tenant/ project/ billing/ idempotency/ ratelimit/ webhook/ audit/
internal/platform/ (config, slog, pgx, redis, httperr, cursor, httpserver, metrics, tracing)
migrations/ api/openapi.yaml docs/adr/ load/k6/ deploy/
```

Request path: `chi → RequestID → auth (JWT|API key) → tenant scope → rate limit → idempotency → handler → pgx tx (business + outbox + audit) → commit → async worker (SKIP LOCKED) → webhook delivery`.
Worker: poll outbox `FOR UPDATE SKIP LOCKED`, deliver with backoff, DLQ after 5 attempts, replay API/CLI.

## D. Data model (key tables, full DDL in migrations/)

- `tenants(id UUIDv7 PK, slug UNIQUE, name, created_at)`
- `users(id, email UNIQUE CITEXT, pw_hash, created_at)`
- `memberships(tenant_id, user_id, role, PK(tenant_id,user_id), FKs, CHECK role IN (...))`, index `(user_id, tenant_id)`.
- `refresh_families(id, user_id, tenant_id, revoked_at)` + `refresh_tokens(token_hash PK, family_id, expires_at, consumed_at)` — reuse of consumed token revokes family.
- `api_keys(id, tenant_id, prefix, key_hash UNIQUE, scopes, revoked_at, expires_at)`, index `(tenant_id, prefix)`.
- `projects(id UUIDv7, tenant_id, name, slug, archived_at, created_at, UNIQUE(tenant_id, slug))`, index `(tenant_id, created_at DESC, id DESC)`.
- `idempotency_keys(tenant_id, key, fingerprint, state, status, headers, body, created_at, expires_at, PK(tenant_id,key))`, index expiry.
- `invoices(id, tenant_id, number UNIQUE per tenant, status, subtotal/currency, version, UNIQUE(tenant_id,number))`, `invoice_items`, `invoice_events(id, invoice_id, from,to, actor, at)` append-only.
- `audit_log(id, tenant_id, actor_id, action, resource, resource_id, old/new JSONB, request_id, at)`, index `(tenant_id, at DESC)`.
- `webhook_subs(id, tenant_id, url, secret, events[], active)`, `webhook_outbox(id, tenant_id, sub_id, event, payload, headers incl traceparent, state, attempts, next_at, last_error, created_at)`, index `(state, next_at)`, DLQ = state `dead`.
- RLS as defense-in-depth on tenant tables (`FORCE ROW LEVEL SECURITY`, `USING` + `WITH CHECK` on `app.current_tenant_id` set via `SET LOCAL` inside tx). Primary enforcement: repository methods take `TenantScope` constructible only from authenticated `Principal` — unscoped queries don't compile into the happy path.

Cursor: base64url `{ts, id, sig}` where `sig = HMAC(secret, ts.id)`; predicate `(created_at, id) < (ts, id)` with index `(tenant_id, created_at DESC, id DESC)`.

## E. Flows

- Register/login → argon2id verify → mint access JWT (`iss/aud/exp/nbf`, `tid/uid/roles`) + refresh family → refresh rotates (consume + mint, reuse → revoke family + audit + metric).
- Authed request → scope → rate limit (Lua) → idempotency (`INSERT ON CONFLICT DO NOTHING`, fingerprint check, 422 mismatch / 409 in-progress / replay completed) → tx (business + outbox + audit) → 201 + `Idempotency-Key` echo.
- Webhook: tx inserts outbox → worker leases row → SSRF-check URL → POST with `t,v1` HMAC + timeout → 2xx ack / schedule backoff (1s,5s,30s,5m,1h) / dead → replay re-queues.

## F. Failure modes

| Failure | Detection | Behavior | Recovery |
|---|---|---|---|
| DB down | pgx ping, `/readyz` 503, `db_up` 0 | 500 envelope, no writes | restart, readiness flips, no data loss (tx atomic) |
| Redis down | dial fail, `ratelimit_degraded_total++` | fail-open allow + warn log | auto when back; no lockout |
| Duplicate POST (retry) | fingerprint match | replay stored response, single side effect | client uses same key |
| Mismatched key reuse | fingerprint differs | 422 | client mints new key |
| Webhook 5xx/timeout | non-2xx/ctx deadline | backoff retry ×5 | DLQ + replay |
| Poison message | attempt count exhausted | DLQ with `last_error` + payload | inspect → fix → replay |
| Worker crash mid-delivery | lease/`next_at` not advanced | row re-leased on restart | at-least-once + dedupe downstream |
| Slow downstream | ctx timeout 5s, `webhook_attempt` latency hist | timeout counts as failure | backoff |
| JWT expired/forged | claim validation | 401, no leak | re-login/refresh |
| Cross-tenant ID guess | scope check before load | 404 (not 403) | — |
| Refresh reuse (theft) | consumed token presented | revoke family, 401 all, audit | re-login |
| Queue saturation | `outbox_depth` gauge + alert | bounded poll batch, drop nothing | scale worker, replay |
| Retry storm | jitter + capped backoff, rate-limited delivery pool | no amplification | DLQ |

## G. ADRs (index; full texts in `docs/adr/`)

- ADR-001 Postgres outbox, rejected NATS for P1 (no tx coupling, extra ops surface).
- ADR-002 Single module / two binaries, rejected microservices.
- ADR-003 TenantScope-in-code primary + RLS defense (incl. FORCE RLS, SET LOCAL, 404-not-403).
- ADR-004 Idempotency DB-primary, Redis lock only (durable, tx-coupled).
- ADR-005 Redis Lua single-key rate limit, fail-open on Redis down (rejected fixed window).
- ADR-006 The audit log is append-only, written inside the transaction it describes.
- ADR-007 UUIDv7 PKs (rejected v4/bigserial: locality + no leakage).
- ADR-008 Money int64 minor + currency code (rejected float).
- ADR-009 Static role→perm map (rejected DB policy engine as over-engineering).
- ADR-010 chi + hand-written OpenAPI + contract test (rejected huma: reviewer must see spec authorship; spec text still pending).
- ADR-011 Forward-only embedded migrations, applied explicitly (rejected goose/golang-migrate: their own history tables, their own locking, an extra adapter).
- ADR-012 Short-TTL JWT + refresh-family revocation, no denylist.
- ADR-013 Webhook SSRF guard + timestamped signatures + traceparent in outbox.
- ADR-014 Keyset pagination with signed, query-bound cursors (rejected offset: wrong on live data and O(depth)).
