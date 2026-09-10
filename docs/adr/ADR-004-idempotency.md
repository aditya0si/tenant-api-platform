# ADR-004: Idempotency is database-primary, not cache-primary

Status: accepted

## Context

A client that may retry a write needs the retry to be safe. The mechanism is a
client-generated key: the first request with a key executes and records its response,
and later requests with the same key replay that response instead of executing again.

The effect being deduplicated is a row in Postgres. The obvious place to keep the key is
Redis, which is already in the stack for rate limiting and is far cheaper per operation.

## Decision

The key, its state, and the recorded response live in Postgres, in
`idempotency_keys`, keyed `(tenant_id, key)` and guarded by row-level security.

The claim is a committed transaction of its own, written *before* the handler runs.
The response is recorded in a second transaction, *after* the effect commits.

Retention and lease are code constants, not configuration.

## Alternatives rejected

**Redis-primary, Postgres fallback.** Rejected: the failure modes are inverted. A cache
evicts under memory pressure — and memory pressure is exactly when a client is most
likely to be retrying, because the service is struggling. Losing a key does not degrade
gracefully; it silently re-executes the write the protocol exists to prevent. A
durability property that fails precisely under load is not a durability property.

**One transaction covering claim, effect, and response.** This is the ideal, and it is
not available here. Handlers own their transactions — each repository call opens one
through `db.WithIdentityTx`, and a create may span several — and a transport-level
middleware cannot join a transaction it did not open.

What that costs is stated plainly: there is a window between the effect committing and
the response being recorded. A crash inside that window leaves a completed effect with
an `in_progress` key. Recovery is the lease, and the retry re-executes. That is tolerable
only because it is bounded and the effect is idempotent at the data layer: every state
transition in this service is compare-and-set, so a re-executed create is refused by the
unique index rather than duplicating.

**Recording the response before the effect commits.** Rejected outright. A crash would
then replay a response for an effect that never happened — the client is told a resource
exists when it does not, and acts on it. A false negative is recoverable; a false
positive is a lie the client builds on.

**A Redis lock in front, with Postgres as the record.** Rejected as redundant. The
duplicate-suppression job is done by the `(tenant_id, key)` primary key, which cannot
lose the race. A lock would add a dependency to the hot path and a second expiry rule to
reason about, for no case the unique index does not already cover.

## Consequences

**The claim must commit before the handler runs.** If the `in_progress` row were still
uncommitted while the handler ran, a concurrent duplicate would block inside its own
INSERT — Postgres waits to learn whether the conflicting row commits — for as long as
the first request takes. Committing the claim immediately means the duplicate reads a
*committed* row, sees `in_progress`, and is answered `409` at once. This is why `Begin`
does not wrap the handler.

**Complete runs inline, never deferred.** A `defer` also runs while a panic unwinds, and
chi's `Recoverer` sits *outside* this middleware, so it writes its 500 after the deferred
call has already recorded whatever the handler managed to write. A handler that panicked
before writing anything would be recorded as `200` with an empty body, and the next retry
would be handed that fabricated success. Running inline means a panic skips recording
entirely: the key stays `in_progress` and the lease releases it. Self-healing beats
inventing a response.

**Lease and retention are constants, not settings.** Both are coupled to code: the lease
must exceed the request timeout or a live handler gets taken over, and retention must
exceed any realistic retry schedule or a retry lands after the key was forgotten and
causes the second effect the protocol prevents. A knob nobody can meaningfully tune is a
knob that misleads, so they stay put until a deployment has a measured reason to differ.

**Expiry is evaluated by Postgres, never in Go.** Comparing a database-written `created_at`
against the application's clock is wrong by the skew between the two hosts, in whichever
direction, and produces no symptom except wrong answers — a lease that never lapses, or
one that lapses instantly. The store holds no clock at all; there is no clock to
substitute. The same decision was already made in the refresh store (`internal/authn`).

**The persisted header set is a whitelist, and it is a security boundary.**
`ResponseWriter.Header()` holds everything the handler and middleware set, including
`Set-Cookie`. Persisting that wholesale would serve one client's session to another on
replay, and echo the original's `X-Request-Id` as though it identified the current
request. `encodeHeaders` stores only `Content-Type`, `Location`, and `ETag`, and
`decodeHeaders` re-validates names and values against response splitting on the way out.
A database row is not a trusted source of header *names*.

**The fingerprint hashes the route pattern, not the path.** A retry of
`PATCH /projects/{a}` must match the original even though the path string differs from
`PATCH /projects/{b}`. Hashing the raw path would make a key fail to protect exactly the
requests that most need it.

**Sweeping requires a role that bypasses RLS.** `idempotency_keys` carries
`FORCE ROW LEVEL SECURITY`, and `FORCE` means the table *owner* is subject to the policy
too. A delete with no tenant identity is filtered to zero rows and reports success — a
scheduled reaper would log "0 removed" every night while the table grew unbounded.
`Store.Sweep` therefore checks `rolsuper OR rolbypassrls` before deleting and refuses
loudly otherwise, and it is invoked from `cmd/migrate sweep` holding owner credentials
rather than from the API, which runs as the unprivileged role. See `docs/OPERATIONS.md`.

## Deliberately unprotected writes

Two mutations sit outside the idempotency guard, and that is a decision rather than an
oversight:

- `POST /v1/auth/register` — outside the tenant group, and a key would be scoped to a
  tenant that does not exist until the request succeeds. Deduplicating registration needs
  a key scoped to something other than a tenant (an email or an invite), which is a
  larger design than this protocol.
- `POST /v1/tenants/{tenantID}/members` — inside the tenant group and unprotected only
  because it is not yet grouped with the other writes. `memberships` has
  `PRIMARY KEY (tenant_id, user_id)`, so a duplicate is refused by the data layer, and
  the guard can be extended to it by moving the route into the guarded group.

Both are recorded here so that adding them later is a decision with a reason, not a
discovery.
