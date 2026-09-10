package tenant

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Authorized is the result of a successful membership check: a resolved tenant
// scope paired with the principal who was authorized for it.
//
// # Why the principal travels with the scope
//
// The obvious shape for this type is just the tenant id. That shape does not
// work, and the way it fails is instructive. The `tenants` policy is keyed on
// membership — a tenant is visible to principals who hold a membership in it —
// so every query against `tenants` needs `app.current_user_id` set. A method that
// carried only the tenant would set only the tenant GUC, the policy's EXISTS
// subquery would evaluate against a NULL user, and the row would be filtered for
// the legitimate owner. The bug presents as "the owner cannot read their own
// tenant", which looks like a policy bug and is really a missing parameter.
//
// Threading the principal through a single value is what stops that from being a
// parameter somebody forgets at one call site. The row-level-security identity is
// then derived from this one value (see identityFor), so a scoped query cannot be
// issued with a tenant and a principal that were authorized separately — or with
// one of them missing.
//
// # Constructible only by the gate
//
// Fields are unexported and the only constructor is Store.Resolve, so an
// Authorized cannot be fabricated from outside this package or widened after the
// fact. As with Scope, be honest about the limit: the zero value Authorized{} is
// still constructible everywhere, so every repository method calls Valid() and
// returns ErrNoScope. That residual gap is why row-level security is still doing
// real work — see the package doc.
type Authorized struct {
	scope  Scope
	userID uuid.UUID
	role   authz.Role
}

// newAuthorized builds an Authorized. Unexported: Store.Resolve is the only
// caller, and it always authorizes before constructing one.
func newAuthorized(scope Scope, userID uuid.UUID, role authz.Role) (Authorized, error) {
	switch {
	case !scope.Valid():
		return Authorized{}, fmt.Errorf("tenant: authorize with no scope: %w", apperr.ErrNoScope)
	case userID == uuid.Nil:
		return Authorized{}, fmt.Errorf("tenant: authorize with no principal: %w", apperr.ErrUnauthorized)
	case !role.Valid():
		return Authorized{}, fmt.Errorf("tenant: authorize with unknown role %q: %w", role, apperr.ErrValidation)
	}
	return Authorized{scope: scope, userID: userID, role: role}, nil
}

// Scope returns the resolved tenant.
func (a Authorized) Scope() Scope { return a.scope }

// UserID returns the authorized principal.
func (a Authorized) UserID() uuid.UUID { return a.userID }

// Role returns the principal's role in this tenant.
func (a Authorized) Role() authz.Role { return a.role }

// Valid reports whether this carries a resolved, authorized identity.
func (a Authorized) Valid() bool {
	return a.scope.Valid() && a.userID != uuid.Nil && a.role.Valid()
}

// String satisfies fmt.Stringer. Ids and role only: authorization state is not a
// secret, and logging it is what makes authorization bugs diagnosable.
func (a Authorized) String() string {
	return fmt.Sprintf("tenant=%s user=%s role=%s", a.scope, a.userID, a.role)
}
