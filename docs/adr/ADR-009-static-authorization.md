# ADR-009: Authorization is a static map in code, not a policy engine

Status: accepted

## Context

Every tenant-scoped request needs an answer to "may this principal do this here?" The model is
small and stable: three roles (owner, admin, member) and a fixed set of permissions per
resource.

## Decision

Roles and permissions are Go constants, and the role → permission mapping is a literal map in
`internal/authz/roles.go`, compiled into the binary.

Permissions are attached to **route groups**, not to individual handlers, so a route added to
the wrong group is visibly in the wrong place rather than silently missing a check that every
sibling has.

## Alternatives rejected

**A database-backed policy engine.** Rejected as over-engineering at this scale, and worse than
over-engineering: it converts an authorization decision into data that can be mutated at
runtime by whoever can write to the table. The hierarchy owner ⊇ admin ⊇ member is a property
of the *product*, not of a tenant, so putting it in a table buys no flexibility anyone has asked
for while adding a class of bug — a policy row edited in production, with no review, no test,
and no deploy history — that a compiled map cannot have.

It also cannot be unit-tested the way the current model is. `roles_test.go` asserts the
hierarchy and the permission sets directly; the equivalent in a policy engine is an integration
test against whatever rows happen to be present.

**An external engine (OPA, Cedar, Casbin).** Rejected. Each adds a dependency, a deployment
surface, and a second language to review, for a model that fits on one screen. The interesting
question — whether the gate runs before the handler and whether the repository can be reached
without it — is answered by *where the middleware is attached*, and no policy language improves
that.

**Per-request permission checks in each handler.** Rejected because it is the failure mode this
design exists to prevent: a handler that forgets its check is indistinguishable from one that
has it, in review and at runtime. Attaching permissions to groups means the omission is a route
in the wrong group, which is visible.

**An interface-based permissions port.** Rejected as indirection without a seam. There is one
implementation and no test double that needs one — the middleware is exercised through the real
router against real Postgres, which is what makes the M-series tests meaningful. An interface
here would be swapped by nothing.

## Consequences

**Adding a permission is a code change with a test, by construction.** A new capability means a
new constant, an entry in the role map, a route with its group, and a test asserting a member is
refused. All four are reviewable in one diff, and the last one fails if it is forgotten.

**Roles are ordered, and the order is asserted.** `owner ⊇ admin ⊇ member` is a claim the code
depends on — the member-management endpoint checks that the granting role outranks the role
being granted — so `roles_test.go` pins it rather than leaving it implied by how the map happens
to read.

**`audit:read` is separate from `tenant:read` deliberately.** The trail names who did what,
including the API keys in use and the request ids to correlate them. An admin who can rename a
workspace is not automatically entitled to enumerate its members' actions, so the two are
distinct permissions even though the same roles hold both today. Splitting them now makes a
future narrower role a permission change rather than a refactor.

**The same reasoning applies to `invoice:settle` versus `invoice:write`.** Editing what an
invoice says is not the same act as declaring it paid. Both are held by admin and owner today;
the split exists so a role that can draft but not settle is expressible without touching
handlers.

**A machine credential is authorized by its scopes, not by a role.** An API key carries an
explicit permission list rather than a role, because a key is a deliberately narrow grant — "let
this deploy job write projects" — and assigning it a role would make it exactly as powerful as a
person in that role, which is not what issuing a key means. `authz.ValidateKeyScopes` is the one
place that list is checked, shared by the issuer and the authenticator.

**Cross-tenant access answers 404, never 403.** This is enforced by the membership gate in
middleware rather than by the role map: a 403 would confirm that a resource exists and that the
caller simply cannot reach it, which is an enumeration oracle. The distinction is stated in
`docs/OPERATIONS.md` as the first thing to check when debugging tenancy, because a 403 from a
tenant-scoped route means something different from what most people expect.

## Not covered

- **Attribute-based rules.** "Only during business hours", "only for invoices under $500" — none
  of these exist, and a static role map is the wrong shape for them. If one is needed, the
  decision is whether it belongs in the permission model or in the domain operation that
  enforces it, and the default should be the domain.
- **Delegated administration.** A tenant cannot define its own roles. That is deliberate: it
  would put the authorization model in tenant data, which is the thing this ADR rejects.
