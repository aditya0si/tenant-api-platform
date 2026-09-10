package authz

import (
	"context"

	"github.com/google/uuid"
)

// AuthMethod identifies how a principal authenticated.
//
// It is carried on every request because the two methods are not interchangeable
// even when they hold the same permission: an audit entry that cannot say whether
// a human or a machine acted is much less useful, and a policy that means to
// exclude unattended automation has no way to express that without it.
type AuthMethod string

const (
	// MethodJWT is a short-lived access token issued to a human session.
	MethodJWT AuthMethod = "jwt"
	// MethodAPIKey is a tenant-scoped machine credential.
	MethodAPIKey AuthMethod = "api_key"
)

// Principal is the authenticated caller for one request.
//
// # Two authorization shapes in one type
//
// A human session holds a Role, and the role's permission set is static
// (roles.go). An API key holds an explicit permission list, chosen at mint time
// and typically narrower than any role. Both arrive here as a Principal, and
// Allows is the single predicate callers use, so no handler has to remember which
// kind of caller it is looking at.
//
// TenantID is the tenant the request acts on. For a session it is resolved from
// the membership gate; for a key it is a property of the credential, because the
// key is what identifies the tenant. It is empty only on the handful of
// pre-tenant endpoints (login, "list my tenants"), which is why it is not a
// tenant.Scope: a scope carries the guarantee that a tenant was resolved and
// authorized, and that guarantee does not exist yet at that point.
type Principal struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Role     Role
	Scopes   []Perm
	Method   AuthMethod
}

// Allows reports whether the caller may perform perm.
//
// A key is checked against its explicit scopes; a session against its role. An
// unrecognised method is denied: a Principal built by some future code path that
// forgot to set one must fail closed rather than fall through to the role check
// and pick up permissions it was never granted.
//
// # Ordering requirement
//
// A session principal straight from authentication carries no role, because the
// access token asserts identity only (see internal/authn/token.go). Allows
// therefore denies everything for it — deliberately, since a permission cannot be
// evaluated before the caller's role in a tenant is known.
//
// The consequence is a hard ordering rule for the HTTP layer: authentication,
// then tenant resolution, then Require(perm). Middleware placed before tenant
// resolution denies every session request, which is a confusing failure because
// it looks like an authorization bug.
func (p Principal) Allows(perm Perm) bool {
	switch p.Method {
	case MethodJWT:
		return Can(p.Role, perm)
	case MethodAPIKey:
		for _, s := range p.Scopes {
			if s == perm {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// WithResolvedTenant returns a copy of p carrying the tenant and role supplied by
// the membership gate.
//
// This is the seam between the two phases of an authenticated request:
//
//	authentication    -> identity only (UserID; no tenant, no role)
//	tenant resolution -> this method
//	authorization     -> Allows
//
// It exists as a method rather than as field assignment at the call site so that
// enrichment is one named operation, visible in a grep, and so that a role can
// only ever be attached together with the tenant it belongs to. A role without a
// tenant would be meaningless, and a tenant without a role would silently deny.
//
// It is only meaningful for a session principal. An API key already knows its
// tenant from the credential itself and treats it as immutable: a key that could
// be re-scoped to another tenant would be a key that can act anywhere.
func (p Principal) WithResolvedTenant(tenantID uuid.UUID, role Role) Principal {
	if p.Method == MethodAPIKey {
		// Refuse to move a key to a different tenant. Silently allowing it would
		// turn any tenant-resolution bug into full cross-tenant access for every
		// machine credential in the system.
		return p
	}
	p.TenantID = tenantID
	p.Role = role
	return p
}

// Resolved reports whether the principal carries a tenant and a role, and is
// therefore ready for a permission check.
func (p Principal) Resolved() bool {
	return p.TenantID != uuid.Nil && p.Role.Valid()
}

// RoleCarrier is the minimal interface the authorization middleware needs. It
// exists so the middleware can be unit-tested with a two-line stub and so it never
// has to import the authentication package.
type RoleCarrier interface {
	// Allows reports whether the caller may perform a permission.
	Allows(Perm) bool
}

type principalKey struct{}

// WithPrincipal attaches p to ctx. Called by the authentication middleware.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom extracts the principal. The bool is false when the request was not
// authenticated, which is what distinguishes "anonymous" (401) from
// "authenticated but unauthorized" (403).
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
