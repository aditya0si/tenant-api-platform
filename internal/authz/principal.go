package authz

import (
	"context"

	"github.com/google/uuid"
)

// AuthMethod identifies how a principal authenticated. It is carried so that
// audit records and metrics can distinguish a human session from a machine key,
// and so that future policy can restrict key-only operations.
type AuthMethod string

const (
	// MethodJWT is a short-lived access token issued to a human session.
	MethodJWT AuthMethod = "jwt"
	// MethodAPIKey is a tenant-scoped machine credential.
	MethodAPIKey AuthMethod = "api_key"
)

// Principal is the authenticated caller for one request: who they are and what
// role they hold in the tenant they selected.
//
// TenantID is the tenant the request is acting on. It is empty on the handful
// of pre-tenant endpoints (login, "list my tenants"), which is why it is not a
// tenant.Scope: scope carries the guarantee that a tenant was resolved and
// authorized, and that guarantee does not exist yet at that point.
type Principal struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Role     Role
	Method   AuthMethod
}

// RoleCarrier is the minimal interface the authorization middleware needs. It
// exists so the middleware can be unit-tested with a two-line stub and so it
// never has to import the authentication package.
type RoleCarrier interface {
	// RoleOf returns the caller's role in the active tenant.
	RoleOf() Role
}

// RoleOf implements RoleCarrier.
func (p Principal) RoleOf() Role { return p.Role }

type principalKey struct{}

// WithPrincipal attaches p to ctx. Called by the authentication middleware.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom extracts the principal. The bool is false when the request was
// not authenticated, which distinguishes "anonymous" (401) from "authenticated
// but unauthorized" (403).
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
