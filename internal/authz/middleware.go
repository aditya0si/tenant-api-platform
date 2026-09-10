package authz

import (
	"net/http"

	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// Require returns middleware that allows the request through only if the
// principal holds permission p.
//
// 401 and 403 are deliberately distinct:
//   - no principal      -> 401, "authenticate first"
//   - principal, no perm -> 403, "you may not do this here"
//
// The tenant boundary is *not* enforced here. This middleware answers "may this
// role perform this action", while the tenant gate (tenant.Store.Authorize)
// answers "does this principal belong to this tenant", and repositories answer
// "may this request see this row". A caller who is not a member never reaches a
// handler, so they get 404 rather than 403 and cannot probe for existence.
func Require(p Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := PrincipalFrom(r.Context())
			if !ok {
				httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if !Can(principal.Role, p) {
				httperr.Write(w, r, http.StatusForbidden, "forbidden",
					"role "+string(principal.Role)+" does not grant "+string(p))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
