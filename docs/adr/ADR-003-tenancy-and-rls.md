# ADR-003: Tenant isolation in the application, with row-level security as defence in depth

**Status:** accepted (M1)

## Context

Every tenant-scoped table must be protected against two different mistakes, and
they are not the same mistake:

1. A caller who is not entitled to a tenant acting as that tenant — an
   authorization failure.
2. A correctly-authorized query reading or writing another tenant's rows — an
   isolation failure.

The instinct is to reach for one mechanism and call it done. PostgreSQL row-level
security (RLS) is the usual candidate, because it sounds like it answers both.

## Decision

Enforce tenant authorization in the application, and enforce tenant isolation in
the database. Both, deliberately.

**Layer 1 — the membership gate (`internal/tenant`).** Every request resolves to a
`Scope` through `Store.Resolve`, which checks the `memberships` table and returns
the caller's role. A caller who is not a member gets `ErrNotFound`, never
`ErrForbidden`, so the response cannot be used to probe for a tenant's existence.
Successful resolution is the only way to obtain a `Scope`, and repositories accept
nothing else. This is the layer that answers *may this principal act as this
tenant*.

**Layer 2 — row-level security (`migrations/0001_init.sql`).** `tenants` and
`memberships` carry policies keyed on two transaction-scoped GUCs,
`app.current_tenant_id` and `app.current_user_id`. This layer answers *may this
query see these rows*, and it is what bounds the damage from a future query that
forgets a `WHERE` clause.

## Why neither layer is sufficient alone

- **RLS cannot authorize.** Setting `app.current_tenant_id` to tenant B makes B's
  rows visible. Visibility therefore proves nothing about entitlement — only the
  gate can decide whether a caller is allowed to act as B. A design that treats
  "the query returned rows" as authorization has no authorization at all.
- **The gate cannot isolate.** It protects the queries that remember to filter. It
  cannot protect a new query written in a hurry, an ad-hoc report, or a migration.
  RLS is enforced on the table regardless of who is asking, which is exactly the
  property a review cannot guarantee.

They also fail differently, which is the practical argument for keeping both: the
gate fails closed on a missing membership check, and RLS fails closed on a missing
predicate.

## Consequences and residual exposure

- **The application must not connect as a superuser.** Superusers, roles with
  `BYPASSRLS`, and table owners (without `FORCE ROW LEVEL SECURITY`) all ignore
  policies. `migrations/0001_init.sql` therefore creates a dedicated `app_rw`
  role with `NOSUPERUSER NOBYPASSRLS`, and `docker-compose.yml` points the API at
  it while reserving owner credentials for `migrate`. `TestRLS_AppRoleIsSubjectToPolicies`
  asserts this precondition, so pointing the tests at the owner role fails loudly
  instead of quietly measuring nothing.
- **Creating the role in a migration is a development convenience.** In production
  a DBA or Terraform provisions it with a secret-managed password and rotation,
  and the application is never issued the DDL role. Writing it into the migration
  is what makes `docker compose up` work on a fresh clone; it is not a claim that
  shipping credentials in a migration is appropriate in production.
- **`users` has no policy, by design.** A person is a global identity: they may
  belong to several tenants, and authenticating them happens before any tenant is
  selected, so there is no tenant to key a policy on. What keeps this safe is that
  no endpoint returns a user row in isolation — member listings join through
  `memberships`, which *is* governed. The residual exposure is real and worth
  stating: a future query that selects from `users` directly, without joining
  `memberships`, would not be filtered by the database. The mitigation is
  structural (no repository method does this) rather than enforced, and that
  asymmetry is the honest cost of the design.
- **`memberships` needs two policy arms.** The tenant arm bounds readers to the
  active tenant. The user arm lets a principal read their own rows, which is what
  makes the pre-tenant queries work: "which tenants do I belong to" and "what is
  my role in tenant T" both run before a tenant is selected. Without the user arm
  those queries return zero rows, and the tempting fix is a bypass — which is how
  multi-tenant systems acquire their first hole.
- **The `Scope` type is a guard rail, not a proof.** Its field is unexported and
  `NewScope` rejects the nil UUID, so the unsafe path is awkward. The zero value
  is still constructible from any package, so repositories call `Valid()` and
  return `ErrNoScope`; that residual gap is precisely why layer 2 exists.

## Alternatives considered

- **RLS only, no application gate.** Rejected: it cannot answer "is this caller
  entitled to this tenant", which is the actual authorization question.
- **Application gate only.** Rejected: one forgotten predicate becomes a cross-tenant
  leak, and the failure is silent — the query returns rows, just the wrong ones.
- **A separate database or schema per tenant.** Strong isolation, real operational
  cost: migrations fan out across tenants, connection pooling multiplies, and
  cross-tenant reporting becomes a data-warehouse project. Not justified at this
  scale; revisit if a compliance regime or a very large single tenant demands it.
- **`SET LOCAL` instead of `set_config(..., true)`.** Rejected: `SET LOCAL` cannot
  be parameterized, so tenant ids would be interpolated into SQL, and a
  session-scoped `SET` on a pooled connection leaks one request's tenant into the
  next. `set_config(name, value, is_local => true)` is both parameterized and
  transaction-scoped. `TestRLS_ConcurrentScopesDoNotLeak` (32 goroutines, a
  two-connection pool) is the regression test for exactly this.
