# ADR-007: UUIDv7 primary keys generated in the application

**Status:** accepted (M1)

## Context

Primary keys for tenants, users, memberships, and everything downstream are
exposed in URLs, cursors, and audit records, and they are the primary key of a
B-tree index on every table.

Three candidates:

- `bigserial` — smallest and fastest to index, but sequential ids are guessable
  and leak volume: `GET /v1/tenants/1043` tells an attacker how many tenants
  exist and invites enumeration.
- `uuid v4` — unguessable, but random: every insert lands at a random point in the
  index, which fragments it and turns hot pages into random I/O. It also makes
  keys useless for anything time-ordered, so pagination needs a second column.
- `uuid v7` — 48 bits of millisecond timestamp followed by randomness. Unguessable
  (the random tail is 74 bits), and insert-monotonic, so index locality behaves
  like a serial.

## Decision

Generate UUIDv7 in Go with `uuid.NewV7()` and supply it explicitly on insert.

PostgreSQL 16 — the version pinned in compose and CI — has no native `uuidv7()`
function, so there is no `DEFAULT` on the `id` columns. That is a deliberate,
visible consequence rather than an oversight: the database cannot generate these
ids, so the application must, and a NULL id fails the `NOT NULL` constraint
instead of silently producing a random UUID via `gen_random_uuid()`.

The clock component is not a security control. Two ids minted in the same
millisecond are ordered only by their random tails, so any code that needs a total
order — pagination above all — must order by `(created_at, id)` rather than by id
alone. That is exactly what the keyset cursor in ADR-006 does.

## Consequences

- **Index locality** on inserts, without the guessability of a serial.
- **No database default** for `id`; every insert statement supplies it. The
  fixture helpers and repository methods do this, and a missed one fails fast.
- **Time-ordered but not time-sortable.** Ids correlate with creation time at
  millisecond resolution, which is useful for debugging and insufficient for
  ordering. Pagination uses `(created_at, id)`.
- **Not a substitute for `created_at`.** The timestamp embedded in the id is
  best-effort and clock-derived; `created_at` from the database remains the
  authority for anything that matters.

## Alternatives considered

- `bigserial` with an external opaque id (e.g. a public slug) — two identifiers to
  keep in sync, and the internal one still leaks volume wherever it appears.
- `uuid v4` — rejected on index fragmentation and because it cannot support
  keyset pagination without a separate monotonic column.
- `ulid` — equivalent properties, but not a UUID. Staying with UUID keeps one id
  type across Postgres, JSON, and Go, and `google/uuid` is already a dependency.
- Application-side snowflake ids — a distributed-coordination problem this system
  does not have.
