package tenant

import (
	"context"
)

// authorizedKey is the context key for an Authorized value. It is an unexported
// empty struct so no other package can collide with it.
type authorizedKey struct{}

// WithAuthorized attaches an authorized caller to ctx.
//
// Handlers read the value with AuthorizedFrom rather than re-resolving, so the
// membership check happens exactly once per request and every downstream call sees
// the same decision. A handler that resolved for itself could disagree with the
// middleware — and the one that runs at the repository would be the one that
// matters, which is a security decision made by accident.
func WithAuthorized(ctx context.Context, a Authorized) context.Context {
	return context.WithValue(ctx, authorizedKey{}, a)
}

// AuthorizedFrom extracts the authorized caller.
//
// The bool is false when no tenant has been resolved, which is the state on the
// pre-tenant endpoints (login, "list my tenants"). Handlers that need a tenant use
// RequireAuthorized, so the false case is a programming error there rather than
// something to handle inline.
func AuthorizedFrom(ctx context.Context) (Authorized, bool) {
	a, ok := ctx.Value(authorizedKey{}).(Authorized)
	return a, ok
}
