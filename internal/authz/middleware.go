package authz

import (
	"net/http"

	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// Require returns middleware that allows the request through only if the
// principal holds permission p.
//
// 401 and 403 are deliberately distinct:
//   - no principal       -> 401, "authenticate first"
//   - principal, no perm -> 403, "you may not do this here"
//
// The tenant boundary is *not* enforced here. This middleware answers "may this
// caller perform this action"; the tenant gate (tenant.Store) answers "does this
// principal belong to this tenant"; and row-level security answers "may this
// query see these rows". A caller who is not a member never reaches a handler, so
// they see 404 rather than 403 and cannot probe for existence.
func Require(p Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFrom(r.Context())
			if !ok {
				httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if !principal.Allows(p) {
				httperr.Write(w, r, http.StatusForbidden, "forbidden",
					"this credential does not grant "+string(p))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
