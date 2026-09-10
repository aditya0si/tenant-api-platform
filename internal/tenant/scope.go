package tenant

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Scope is proof that a request has been resolved to exactly one tenant.
//
// The field is unexported so that no package can fabricate a scope by field
// assignment or widen one by mutation: the only ways to obtain a Scope are
// NewScope and Store.Resolve, and Resolve authorizes before returning.
// Repository methods take a Scope rather than a raw uuid, so "which tenant is
// this query for?" cannot be silently answered with a caller-supplied string.
//
// Be honest about the limit: the zero value Scope{} is still constructible from
// any package, and NewScope itself performs no authorization — it only rejects
// the nil UUID. The type system makes the unsafe path awkward, not impossible.
// That residual gap is exactly why two further checks exist:
//
//   - every repository method calls Valid() and returns ErrNoScope, so an
//     unresolved scope fails loudly instead of querying as "no tenant";
//   - row-level security bounds the query to the named tenant regardless, so a
//     scope that skipped the membership gate still cannot reach a second
//     tenant's rows.
//
// Authorization (may this principal act as this tenant) is answered by the gate,
// never by the type. See the package doc for why the two layers are not
// redundant.
type Scope struct{ id uuid.UUID }

// NewScope builds a scope for tenantID. It rejects the nil UUID because a zero
// scope is a call-site bug, and failing loudly beats querying with an identity
// that silently matches nothing.
func NewScope(tenantID uuid.UUID) (Scope, error) {
	if tenantID == uuid.Nil {
		return Scope{}, fmt.Errorf("tenant: nil tenant id: %w", apperr.ErrNoScope)
	}
	return Scope{id: tenantID}, nil
}

// ID returns the tenant id. Safe to log: tenant ids are not secrets.
func (s Scope) ID() uuid.UUID { return s.id }

// Valid reports whether the scope carries a real tenant.
func (s Scope) Valid() bool { return s.id != uuid.Nil }

// String satisfies fmt.Stringer so scopes render as a tenant id in logs.
func (s Scope) String() string { return s.id.String() }
