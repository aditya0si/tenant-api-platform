# ADR-014: Keyset pagination with signed, query-bound cursors

Status: accepted

## Context

Every listing endpoint — projects, audit entries, invoices, webhook endpoints, deliveries — needs a
way to page. The two candidates are `OFFSET n LIMIT m` and a keyset cursor naming a position.

Offset fails twice, and the second failure is the one that matters because it is silent:

- **Cost grows with depth.** The database walks and discards `n` rows to return `m`, so a request
  for page 500 reads tens of thousands of rows to show fifty. The work per page is proportional to
  how far the client has paged, which is a cost the server pays and the client never sees.
- **It is incorrect on a live table.** Rows inserted or deleted between two requests shift the
  window, so a client paging data that is being written can see the same row twice or miss one
  entirely — and nothing detects it. The response looks like an ordinary page.

## Decision

A cursor names a position: the tuple `(created_at, id)`, compared with `<(ts, id)` so the predicate
seeks into the index `(tenant_id, created_at DESC, id DESC)` rather than scanning. Rows inserted
after the cursor sort after it, so they appear on a later page or not at all — never in the middle
of a page the client already read.

The cursor is opaque to clients: base64url of `{ts, id, sig}`, where `sig` is HMAC-SHA256 over the
position **and a binding** describing the query that produced it — the tenant, the resource, and any
filters that resource supports. The signing key is derived from the service secret via
`cursor.DeriveKey`, not used raw, so the cursor key and the token-signing key are distinct keys.

## What the signature buys, and what it does not

Two properties, deliberately not a third:

- **Integrity.** A truncated or hand-edited cursor fails loudly with a distinct error, instead of
  silently returning a differently-shaped page that a client reads as data loss.
- **Query binding.** A cursor minted for one tenant's project list cannot be replayed against
  another tenant's list, or against the same tenant with different filters, because the binding is
  covered by the signature. Without it the resulting page would be subtly wrong rather than
  obviously rejected.

It is **not** an authorization mechanism. A cursor grants no access; it names a position in a
listing the caller is independently authorized to read, and row-level security plus the tenant gate
still decide which rows exist for that caller. Treating a signed cursor as a capability would be a
category error — which is why cursors carry **no expiry**: a cursor from last week is a position,
and re-reading from it is harmless.

The three rejection modes are kept distinct because the reactions differ: a malformed token is a bug
in how the client stored it, a signature failure means it was altered in transit or by hand, and a
binding mismatch usually means it was carried across a filter change — a client-side state bug
rather than an attack.

## Alternatives rejected

- **Offset / LIMIT.** Incorrect on live data, with a silent failure mode; see above.
- **An id-only cursor.** UUIDv7 is time-ordered, so the id alone is nearly a position — but
  "nearly" is not a total order under backdated writes or clock skew, and the tiebreak costs
  nothing. The composite key is exact.
- **An unsigned cursor.** A client editing a cursor would then choose where the server looks. Row
  level security still bounds what is visible, but a programming error would become a silent,
  well-formed wrong page — the failure mode this design exists to avoid.
- **A server-side snapshot id.** Correct, and a second stateful system to keep consistent for a
  property the composite index already provides.

## Consequences

- Clients must treat the cursor as opaque and pass it back whole. Changing the filter set
  invalidates cursors minted for the previous set, which is deliberate: the alternative is silently
  returning a page that does not match what was asked for.
- Each resource declares a `cursor.Binding`, so what the signature covers is defined in one place
  next to the query it describes, and a query change that forgets the binding is a compile-visible
  omission rather than a silent one.
- Every paginated table needs the composite index `(tenant_id, created_at DESC, id DESC)`. Without
  it the predicate is still correct and the query scans.
