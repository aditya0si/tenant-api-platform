# ADR-002: One Go module, two binaries — the API and the delivery worker

Status: accepted

## Context

The service has two distinct runtime roles. The API answers requests: it authenticates, authorizes,
enforces rate limits and idempotency, and writes domain changes. The worker delivers webhook events
from the outbox: it polls a table, makes outbound HTTP requests, and settles rows.

The shape resembles microservices — an "API service" and a "delivery service" — which is the
temptation this ADR records a decision against.

## Decision

One Go module. Two binaries built from it: `cmd/api` and `cmd/worker`. One Dockerfile produces one
image containing both; `docker-compose.yml` runs the same image twice with different entrypoints.
Both binaries import the same `internal/` packages.

## Why not separate services

**There is no domain boundary to split along.** The worker's entire job is defined by the API's
writes: it reads the table the API populates inside its transactions and does what each row says.
Splitting them would not separate bounded contexts — it would put a network hop in the middle of one.
The outbox exists precisely because the enqueue and the domain change are one atomic fact
(ADR-001); a service boundary would invite a redesign (publish-on-ack, two-phase commit) that
ADR-001 already rejected on correctness grounds.

**A shared module is the same compiled code, so the two roles cannot drift.** The API writes
`internal/webhook` payloads and the worker delivers them. With separate services, "the API and the
worker agree on the payload format" becomes a version contract that has to be maintained, tested,
and deployed in an order. Here it is a compile-time fact.

**No operational surface is bought.** One module means one build, one dependency graph, one test
suite. Separate repos would add a second pipeline, a shared schema package with its own versioning,
and cross-repo coordination — for a project whose interesting properties live in the data layer,
not in process topology.

**Independent scaling does not require a second module.** The worker is a separate process with its
own replica count, its own resource limits, and its own health semantics (see ADR-001 on the lease,
and the worker's `/readyz`, which pings the database because a worker that cannot reach Postgres
cannot claim or settle anything). Scaling delivery is `docker compose up --scale worker=N` or an
equivalent orchestrator change, not a repository split.

## What the two binaries do not share

- Configuration is loaded once and each binary uses the subset it needs: the worker ignores
  `JWT_SECRET` and `REDIS_URL` entirely, and `.env.example` says so rather than leaving it implied.
- The worker serves no API. Its HTTP listener exists only for `/metrics`, `/healthz`, and
  `/readyz`, on its own port, so a probe cannot land on the wrong process.
- The unprivileged-role assertion is shared (`internal/platform/db.AssertUnprivilegedRole`), not
  duplicated. It moved there from `cmd/api` when the worker needed it, because two copies of a
  security assertion drift and the worker needs it for a subtler reason: the worker is the one
  process trusted to see across tenants by policy, so running it privileged would satisfy the
  constraint on paper while bypassing the mechanism enforcing it.

## When this decision is wrong

Revisit if the delivery path grows real domain concepts of its own — ordered delivery, per-tenant
retry policy stored and evaluated, a second consumer of the same events — or if delivery latency
needs an autoscaling unit decoupled from API traffic. At that point the boundary is genuine and the
split is mechanical: `internal/webhook` moves out with its tests, and the outbox table becomes the
integration point it already is.

## Consequences

- A compile error in the worker is a CI failure, not a separate pipeline's surprise.
- One image means a deploy cannot ship an API and a worker from different commits.
- The coupling between the two roles is real and is the point — the atomicity guarantee depends on
  it — rather than being hidden behind a wire format that would need versioning.
