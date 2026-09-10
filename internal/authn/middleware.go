package authn

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// SessionStore is the subset of authn the middleware needs to turn a verified
// access token into a principal.
//
// It is an interface so the middleware can be tested without a database, and so
// that the dependency runs one way: the HTTP layer asks for a principal, and the
// stores decide what that requires.
type SessionStore interface {
	// PrincipalForAccessToken verifies a token and returns the principal it
	// identifies, with no tenant selected. Resolving a tenant is a separate,
	// later step because ownership of a tenant is not a property of the token.
	PrincipalForAccessToken(ctx context.Context, token string) (authz.Principal, error)

	// PrincipalForAPIKey resolves a presented key to the tenant it belongs to.
	PrincipalForAPIKey(ctx context.Context, key string) (authz.Principal, error)
}

// Authenticator is the middleware that turns credentials into a principal.
//
// # Credential transport
//
// A session token is a bearer credential, carried in Authorization: Bearer <jwt>.
// An API key is carried the same way, with its own scheme — Authorization: ApiKey
// <key> — rather than a bespoke header.
//
// The reason to prefer the standard header over X-API-Key is not stylistic: a
// custom header is easy to add to an allowlist by accident during a CORS change,
// because it does not look like a credential to a reviewer skimming the diff. A
// familiar scheme in a familiar header is harder to leak by inattention.
//
// Both are rejected in a query string. A credential in a URL lands in access logs,
// proxy logs, and browser history, and the fix afterwards is to rotate everything.
type Authenticator struct {
	store SessionStore
	log   *slog.Logger
}

// NewAuthenticator builds the middleware. log may be nil.
func NewAuthenticator(store SessionStore, log *slog.Logger) *Authenticator {
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{store: store, log: log}
}

const (
	schemeBearer = "bearer"
	schemeAPIKey = "apikey"
)

// Middleware authenticates every request that presents a credential, and leaves
// unauthenticated requests untouched.
//
// It deliberately does not reject requests with no credential: some endpoints are
// public (health, login), and whether authentication is required is a property of
// the route, not of the middleware. Require(perm) or an explicit authentication
// check at the route supplies that.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, credential, ok := parseAuthorization(r.Header.Get("Authorization"))
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		var (
			principal authz.Principal
			err       error
		)
		switch scheme {
		case schemeBearer:
			principal, err = a.store.PrincipalForAccessToken(r.Context(), credential)
		case schemeAPIKey:
			principal, err = a.store.PrincipalForAPIKey(r.Context(), credential)
		}
		if err != nil {
			// One 401 for every cause. The client can act on none of the
			// distinctions, and the specific reason is exactly what an attacker
			// probing forgeries wants to know.
			//
			// The cause is logged with the request id so an operator can still
			// tell a stale client from a forgery attempt. The credential itself
			// is never logged — not even a prefix — which is why the error is
			// logged as a class, not with the value attached.
			reason := classifyAuthError(err)
			a.log.Info("authentication failed",
				"reason", reason,
				"scheme", scheme,
				"path", r.URL.Path,
			)
			httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "invalid credentials")
			return
		}

		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)))
	})
}

// RequireAuthentication rejects a request that carries no principal.
//
// It exists as a separate middleware from Require(perm) because some routes need
// "authenticated, any permission" — /v1/me, logout — and expressing that as a
// permission would mean inventing one that every role happens to hold, which is
// the kind of coincidence that breaks the first time a role is added.
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.PrincipalFrom(r.Context()); !ok {
			httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// parseAuthorization extracts a scheme and credential.
//
// The scheme match is case-insensitive because RFC 7235 defines it that way, and
// clients in the wild send "Bearer", "bearer", and "BEARER".
func parseAuthorization(header string) (scheme, credential string, ok bool) {
	if header == "" {
		return "", "", false
	}
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	scheme = strings.ToLower(strings.TrimSpace(parts[0]))
	credential = strings.TrimSpace(parts[1])
	if credential == "" {
		return "", "", false
	}
	switch scheme {
	case schemeBearer, schemeAPIKey:
		return scheme, credential, true
	default:
		// An unrecognised scheme is treated as "no credential presented" rather
		// than as a failure. A browser sending Basic credentials for a
		// completely different service should not produce a 401 that looks like
		// a broken login.
		return "", "", false
	}
}

// classifyAuthError reduces an error to a short, log-safe class.
//
// The value of this is operational: "reused" and "expired" mean a client needs to
// re-authenticate and nothing is wrong, while "unknown" repeated across many
// requests means someone is trying credentials. Collapsing them all into
// "unauthorized" throws away the only signal available.
func classifyAuthError(err error) string {
	switch {
	case errors.Is(err, ErrTokenInvalid):
		return "access_token_invalid"
	case errors.Is(err, ErrRefreshUnknown), errors.Is(err, ErrAPIKeyUnknown):
		return "credential_unknown"
	case errors.Is(err, ErrRefreshRevoked), errors.Is(err, ErrAPIKeyRevoked):
		return "credential_revoked"
	case errors.Is(err, ErrRefreshExpired), errors.Is(err, ErrAPIKeyExpired):
		return "credential_expired"
	case errors.Is(err, ErrRefreshReused):
		return "refresh_reused"
	default:
		return "internal_error"
	}
}
