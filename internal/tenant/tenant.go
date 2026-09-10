// Package tenant owns tenants, memberships, and the authorization gate that
// decides whether a principal may act as a given tenant.
//
// # Two independent layers of tenant safety
//
// Layer 1 — the membership gate (Store.Resolve / Store.Authorize). Tenant
// isolation is enforced in Go, before any data access, by resolving "does this
// principal belong to this tenant, and with which role". A request that fails
// the gate never reaches a repository, and is answered 404 rather than 403 so
// that it cannot be used to probe for the existence of other tenants.
//
// Layer 2 — row-level security (migrations/0001_init.sql). Even a request that
// is correctly scoped to tenant A cannot read or write tenant B's rows, because
// the database filters them. This layer exists to bound the blast radius of an
// application bug — a missing WHERE clause, a new query written in a hurry —
// not to replace the gate.
//
// The two are not redundant, and neither is sufficient alone:
//   - RLS alone is not authorization: setting app.current_tenant_id to tenant B
//     makes B's rows visible, so visibility proves nothing about entitlement.
//     Only the gate can answer "may this principal act as B".
//   - The gate alone is not isolation: it protects the queries that remember to
//     filter, and RLS protects the ones that forget.
//
// Both are tested: TestResolve_NonMemberIsNotFound and
// TestRLS_CrossTenantReadIsEmptyDropsPredicate cover the gate and the database
// respectively, against a non-superuser role so the policies are genuinely in
// force.
package tenant

import (
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
)

// Tenant is an organization. ID is generated in Go as a UUIDv7 (ADR-007): the
// time-ordered prefix gives index locality on insert, and unlike a serial it
// leaks no row count or creation order to an attacker who sees an id.
type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time
}

// Owner is the identity created alongside a new tenant. It is a value, not an
// authn.User, so this package does not depend on the authentication layer.
type Owner struct {
	ID     uuid.UUID
	Email  string
	PWHash string
}

// Membership is one principal's role in one tenant, joined with the tenant's
// display fields for the "my tenants" listing.
type Membership struct {
	TenantID   uuid.UUID
	TenantSlug string
	TenantName string
	Role       authz.Role
	CreatedAt  time.Time
}

// Member is one row of a tenant roster.
type Member struct {
	UserID    uuid.UUID
	Email     string
	Role      authz.Role
	CreatedAt time.Time
}
