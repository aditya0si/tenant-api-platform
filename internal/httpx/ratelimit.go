package httpx

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/clientip"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/ratelimit"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// Policies, as code constants rather than configuration.
//
// Each is coupled to what it protects. The unauthenticated limits are tight because the
// endpoints they cover are the ones an attacker reaches without credentials: login and
// register are where credential stuffing and account-creation floods land, and the only
// signal available before authentication is volume. The authenticated limit is generous
// because it is a runaway-client guard rather than an abuse control — a legitimate client
// with a batch job should not be throttled by default, and the cost of being wrong is
// asymmetric in the other direction at that volume.
var (
	// PolicyLogin bounds login attempts per address. Deliberately the tightest: this is the
	// credential-stuffing surface, and a legitimate user who has forgotten which password
	// they used does not exceed ten attempts a minute.
	PolicyLogin = ratelimit.Policy{Name: "login", Limit: 10, Window: time.Minute}

	// PolicyRegister bounds account creation per address. Slower than login because
	// legitimate registration is a once-per-user event, while automated signup is the abuse.
	PolicyRegister = ratelimit.Policy{Name: "register", Limit: 5, Window: time.Hour}

	// PolicyRefreshIP bounds token refreshes per address.
	//
	// There is deliberately no keyed-by-principal variant. Keying refresh by the token's
	// owner would mean verifying the token before the limiter runs — duplicating work the
	// handler already does, and making the limiter the component that decides whether a
	// credential is valid. The address is available before anything is parsed, which is what
	// a pre-authentication limit needs.
	PolicyRefreshIP = ratelimit.Policy{Name: "refresh_ip", Limit: 20, Window: time.Minute}

	// PolicyAPI bounds authenticated traffic per tenant. This is a runaway-client and
	// noisy-neighbour guard: it bounds what one tenant can cost the others, which is the
	// per-tenant fairness question rather than an abuse question.
	PolicyAPI = ratelimit.Policy{Name: "api", Limit: 600, Window: time.Minute}
)

// RateLimits are the limiters the router applies.
type RateLimits struct {
	Login    *ratelimit.Limiter
	Register *ratelimit.Limiter
	Refresh  *ratelimit.Limiter
	API      *ratelimit.Limiter

	IP *clientip.Resolver
}

// limitByIP applies an IP-keyed limit.
//
// # Why the address and not the credential
//
// These protect endpoints that have no credential to key on — that is what makes them the
// attack surface. Keying login by the submitted email would let an attacker pick a new
// address per attempt, which is the opposite of a limit; the address is the one thing they
// cannot choose freely.
//
// The address comes from clientip, which honours forwarding headers only from declared
// proxies. Reading X-Forwarded-For directly would make this limiter trivially bypassable by
// varying a header, and it would still look like it was working.
func (d Deps) limitByIP(l *ratelimit.Limiter) func(http.Handler) http.Handler {
	resolver := d.limits().IP
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l == nil {
				next.ServeHTTP(w, r)
				return
			}
			enforce(w, r, l, clientIP(r, resolver), next)
		})
	}
}

// limits returns the configured limiters, or an empty set when none are configured.
//
// Returning an empty RateLimits rather than dereferencing a nil pointer lets route
// registration read d.limits().Login unconditionally. Each builder treats a nil limiter as
// "no limit", so a router assembled without them — which several tests do — behaves as it
// did before rate limiting existed instead of panicking while its routes are registered.
func (d Deps) limits() RateLimits {
	if d.RateLimits == nil {
		return RateLimits{}
	}
	return *d.RateLimits
}

// limitByPrincipal applies a limit keyed on whoever is calling.
//
// # Why the key is the tenant and not the user
//
// The limit exists to bound what one tenant can cost the others, so the tenant is the unit
// that has to be bounded: keying per user would let a tenant with many members multiply its
// share by adding members, which is precisely the noisy-neighbour case this is meant to
// prevent.
//
// A machine credential is keyed by its tenant like any other caller, because the tenant is
// still what it consumes.
func (d Deps) limitByPrincipal(l *ratelimit.Limiter) func(http.Handler) http.Handler {
	resolver := d.limits().IP
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l == nil {
				next.ServeHTTP(w, r)
				return
			}

			bucket := ""
			if auth, ok := tenant.AuthorizedFrom(r.Context()); ok {
				bucket = "tenant:" + auth.Identity().TenantID.String()
			} else if p, ok := authz.PrincipalFrom(r.Context()); ok {
				// Authenticated but pre-tenant: /v1/me and the tenant list. Keyed on the
				// principal, since there is no tenant yet to charge it to.
				bucket = "principal:" + p.UserID.String()
			}

			if bucket == "" {
				// No principal at all. This is not an error state — it is a route the
				// middleware was attached to that has no authentication — so rather than
				// admitting unlimited traffic it falls back to the address, which is the
				// same key the unauthenticated limits use.
				bucket = clientIP(r, resolver)
			}

			enforce(w, r, l, bucket, next)
		})
	}
}

// enforce performs the check and either refuses or annotates the response.
//
// It is shared by both key strategies so the policy headers and the 429 shape cannot drift
// between them — a client should not have to learn two conventions for one limit.
func enforce(w http.ResponseWriter, r *http.Request, l *ratelimit.Limiter, bucket string, next http.Handler) {
	decision := l.Allow(r.Context(), bucket)

	// Headers are set whether or not the request proceeds, so a client can pace itself
	// before being refused rather than only learning the limit by hitting it.
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	if decision.Degraded {
		// Reported explicitly. A client that reads Remaining as "how much room I have" must
		// not be told it has room when the answer is actually "unknown" — and an operator
		// reading a dashboard needs to see degradation rather than infer it.
		w.Header().Set("X-RateLimit-Degraded", "true")
	} else {
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
		if decision.ResetAfter > 0 {
			// Ceil to whole seconds: rounding down would advertise a reset that has not
			// happened, and a client that retries exactly then is refused again.
			seconds := int((decision.ResetAfter + time.Second - 1) / time.Second)
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(seconds))
		}
	}

	if decision.Allowed {
		next.ServeHTTP(w, r)
		return
	}

	// Retry-After is the header an automated client actually honours, and the value is the
	// real time until a slot frees — not the whole window, which would make a client back off
	// further than necessary and is the difference between a limit and an outage for a
	// well-behaved integration.
	if decision.ResetAfter > 0 {
		seconds := int((decision.ResetAfter + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	httperr.Write(w, r, http.StatusTooManyRequests, "rate_limited",
		"too many requests; retry after the interval in Retry-After")
}

// clientIP resolves the caller's address, falling back to the socket peer when no resolver
// is configured.
//
// The fallback is the safe one: RemoteAddr cannot be forged by the client, so a router built
// without a resolver under-limits rather than over-shares a bucket between attackers.
func clientIP(r *http.Request, resolver *clientip.Resolver) string {
	if resolver == nil {
		return "ip:" + hostFromRemote(r.RemoteAddr)
	}
	return "ip:" + resolver.ClientIP(r)
}

// hostFromRemote strips the port from RemoteAddr, which is the socket peer or the value chi
// rewrote it to.
func hostFromRemote(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			// An IPv6 literal without a port ends with a bracket; a colon inside brackets is
			// part of the address.
			if i > 0 && addr[len(addr)-1] == ']' {
				break
			}
			return trimBrackets(addr[:i])
		}
	}
	return trimBrackets(addr)
}

func trimBrackets(s string) string {
	if len(s) >= 2 && s[0] == '[' && s[len(s)-1] == ']' {
		return s[1 : len(s)-1]
	}
	return s
}

// logRateLimitConfig records how address attribution is configured, once at startup.
//
// It is logged because the difference between "behind a trusted proxy" and "trusting
// nothing" changes what the unauthenticated limits actually do, and an operator should be
// able to confirm which one is in force without reading the code or the deploy manifest.
func logRateLimitConfig(log *slog.Logger, resolver *clientip.Resolver) {
	if log == nil {
		return
	}
	if resolver == nil || !resolver.Trusts() {
		log.Info("rate limiting: no trusted proxies configured, so clients are identified by " +
			"socket address and forwarding headers are ignored. Set TRUSTED_PROXY_CIDRS if this " +
			"service runs behind a proxy, or every client behind it shares one limit.")
		return
	}
	log.Info("rate limiting: forwarding headers are trusted from the configured proxy ranges")
}
