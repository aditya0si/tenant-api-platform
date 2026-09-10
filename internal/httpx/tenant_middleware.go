package httpx

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// ResolveTenant middleware turns an authenticated principal plus a tenant id from
// the URL into an authorized caller.
//
// # What it guarantees
//
// After it runs, either the request is rejected or the context carries a
// tenant.Authorized — a value that cannot be fabricated outside the tenant package
// and that every repository method requires. That is what makes "a handler cannot
// query another tenant's data" a property of the type system rather than of reviewer
// attention.
//
// # Two authorization paths, because there are two kinds of principal
//
// A user session is authorized by a *membership*: the gate checks that the principal
// belongs to the tenant in the path and resolves their role.
//
// An API key is authorized by the *credential itself*: the key's row names its tenant,
// and PrincipalForAPIKey has already verified revocation and expiry against the
// database in this request. There is no membership to check, because the key is not a
// person — which is why routing a key through the human path is not merely
// inconvenient but wrong: the membership gate would be asked "does this user belong
// here" about a principal that has no user id, and would refuse every machine request.
//
// # Why the failure is 404 and never 403
//
// A caller who is not a member of the tenant in the path gets the same response as a
// caller naming a tenant that does not exist. The distinction would confirm that a
// tenant exists, which is enough to enumerate them — and tenant ids appear in URLs, so
// they are the easiest thing to guess at.
func ResolveTenant(store *tenant.Store, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := authz.PrincipalFrom(r.Context())
			if !ok {
				httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}

			tenantID, err := uuidFromPath(r, "tenantID")
			if err != nil {
				// A string that is not a UUID cannot name a real tenant, so this is
				// reported as not-found for the same reason as above: it keeps the
				// response surface uniform.
				httperr.Write(w, r, http.StatusNotFound, "not_found", "the requested resource does not exist")
				return
			}

			// A machine credential carries its tenant, so the path must agree with it.
			// A mismatch is refused rather than resolved: silently honouring the path
			// would let a key for one tenant act as another, and silently honouring the
			// credential would make the URL a lie.
			if principal.Method == authz.MethodAPIKey {
				if principal.TenantID != tenantID {
					httperr.Write(w, r, http.StatusNotFound, "not_found", "the requested resource does not exist")
					return
				}

				scope, err := tenant.NewScope(tenantID)
				if err != nil {
					httperr.Write(w, r, http.StatusNotFound, "not_found", "the requested resource does not exist")
					return
				}
				auth, err := tenant.NewMachineAuthorized(scope, principal.CredentialID)
				if err != nil {
					httperr.Fail(w, r, log, err)
					return
				}

				// The principal is attached unchanged: WithResolvedTenant deliberately
				// refuses to re-scope a machine credential, and a key's permissions come
				// from its own scopes rather than from a role resolved here.
				next.ServeHTTP(w, r.WithContext(tenant.WithAuthorized(r.Context(), auth)))
				return
			}

			auth, err := store.Resolve(r.Context(), tenantID, principal.UserID)
			if err != nil {
				httperr.Fail(w, r, log, err)
				return
			}

			// Enrich rather than replace, so the identity that was authenticated is
			// still the identity in the context, now carrying the tenant and role the
			// gate resolved.
			ctx := authz.WithPrincipal(r.Context(),
				principal.WithResolvedTenant(auth.Scope().ID(), auth.Role()))
			ctx = tenant.WithAuthorized(ctx, auth)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthorized rejects a request that reached a tenant-scoped route without a
// resolved tenant.
//
// It is a programming-error guard rather than a security control: ResolveTenant
// already refuses those requests. It exists so that a route registered outside the
// tenant group fails loudly and immediately instead of reaching a handler that reads a
// zero Authorized and returns a confusing not-found for every request.
func RequireAuthorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := tenant.AuthorizedFrom(r.Context()); !ok {
			httperr.Write(w, r, http.StatusNotFound, "not_found", "the requested resource does not exist")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// uuidFromPath reads a UUID path parameter, mapping a malformed value to an error.
func uuidFromPath(r *http.Request, name string) (uuidValue, error) {
	return parseUUID(chi.URLParam(r, name))
}
