package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/idempotency"
	"github.com/aditya0si/tenant-api-platform/internal/invoice"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// Deps are the collaborators the HTTP layer needs.
//
// They are passed as concrete types rather than interfaces because they are
// constructed once in main and never substituted; an interface here would add
// indirection without adding a seam that anything uses. The one exception is the
// authenticator's session store, which is an interface because its behaviour is
// worth testing without a database.
type Deps struct {
	Log *slog.Logger

	// Readiness probes. Nil means "not configured", which readiness reports as
	// degraded rather than crashing.
	DBPing    func(r *http.Request) bool
	RedisPing func(r *http.Request) bool

	Auth     *authn.Service
	Users    *authn.UserStore
	Tenants  *tenant.Store
	Projects *project.Store
	Cursors  *cursor.Codec

	// Invoices owns the billing surface. When nil the invoice routes are not registered at
	// all, so chi's NotFound handler answers and the endpoint genuinely does not exist —
	// rather than existing and panicking inside a nil store, which is what happened before
	// registerInvoiceRoutes checked. See its comment.
	Invoices *invoice.Store

	// Audit reads the append-only trail. There is deliberately no writer here: entries are
	// recorded by the operations they describe, inside those operations' transactions, so
	// the HTTP layer can only ever read them. A nil value makes the endpoint report
	// not-found, which is what a router assembled without one should do.
	Audit *audit.Reader

	// Idempotency implements the idempotency-key protocol for unsafe requests. A nil
	// value disables the middleware's recording, which tests use to isolate other
	// behaviour; production always supplies one.
	Idempotency *idempotency.Store

	// RateLimits are the limiters applied at the HTTP boundary. Nil means no limiting,
	// which lets a test exercise routing without standing up Redis; production always
	// supplies them. A nil field is treated as "no limit" rather than as an error, because
	// the limit protects against abuse rather than correctness.
	RateLimits *RateLimits

	// AccessTokenTTL is reported to clients so they know when to refresh without
	// hard-coding a value that lives in configuration.
	AccessTokenTTL int
}

// registerInvoiceRoutes attaches the billing surface, if this deployment has one.
//
// It is a function rather than an inline block so the nil check can return early. A router
// assembled without a billing store — a probe harness, a test that only exercises routing —
// then gets no invoice endpoints at all, and chi's NotFound handler answers for them.
//
// Registering them anyway panics on the first request: the handler reaches a nil
// *invoice.Store, and Go dispatches the method before any of its own checks can run, so the
// panic happens at the first field access inside Create. That is a 500 for what is a
// configuration decision rather than an error, which is the least useful response available —
// and it was a live bug until this function existed, because the field's own documentation
// promised not-found.
//
// The alternative, a nil check in each of the nine handlers, is nine places to forget.
func registerInvoiceRoutes(r chi.Router, d Deps) {
	if d.Invoices == nil {
		return
	}

	r.Route("/invoices", func(r chi.Router) {
		// Reads need invoice:read, which every role including member holds: an invoice is
		// part of the work someone was invited to do.
		r.With(authz.Require(authz.PermInvoiceRead)).Get("/", d.handleListInvoices)
		r.With(authz.Require(authz.PermInvoiceRead)).Get("/{invoiceID}", d.handleGetInvoice)

		// Edits require invoice:write (admin and owner).
		r.Group(func(r chi.Router) {
			r.Use(writeGuard(string(authz.PermInvoiceWrite), d.Idempotency, d.Log))
			r.Post("/", d.handleCreateInvoice)
			r.Post("/{invoiceID}/items", d.handleAddInvoiceItem)
			r.Delete("/{invoiceID}/items/{itemID}", d.handleRemoveInvoiceItem)
			r.Post("/{invoiceID}/issue", d.handleIssueInvoice)
		})

		// Settling requires invoice:settle, which is stronger than invoice:write and is held
		// by the same roles today. It is a separate permission because the two are
		// conceptually distinct — editing what an invoice says is not the same act as
		// declaring it paid — so a future role that can draft but not settle is a permission
		// change rather than a refactor. Both are guarded writes.
		r.Group(func(r chi.Router) {
			r.Use(writeGuard(string(authz.PermInvoiceSettle), d.Idempotency, d.Log))
			r.Post("/{invoiceID}/pay", d.handlePayInvoice)
			r.Post("/{invoiceID}/void", d.handleVoidInvoice)
		})
	})
}

// requirePerm is the authorization middleware as a plain function, so a composition like
// writeGuard can apply it without going through chi's With().
func requirePerm(perm string) func(http.Handler) http.Handler {
	p := authz.Perm(perm)
	return authz.Require(p)
}

// New builds the router.
//
// # Route organisation, and why it matters for security
//
// The routes are grouped by the authorization they require, and the group is what
// applies the middleware — not the individual handler. A route added to the wrong
// group is then visibly in the wrong place, rather than silently missing a check
// that every sibling has. This is the same reasoning as keeping the tenant gate in
// middleware rather than in each handler.
//
//	/healthz, /readyz, /metrics  unauthenticated infrastructure
//	/v1/auth/*                   unauthenticated by necessity
//	everything else              authenticated
//
// plus a tenant-scoped subgroup under /v1/tenants/{tenantID} where the membership
// gate runs. A handler inside that subgroup can only obtain a tenant.Authorized,
// which is what every repository method requires.
func New(d Deps) http.Handler {
	r := chi.NewRouter()

	// Order is load-bearing: RequestID first so every later layer (including the
	// error renderer and the authenticator's log lines) can attach the same id to
	// what it emits; Recoverer after so a panic is reported with that id rather
	// than as a bare connection close.
	r.Use(middleware.RequestID)
	r.Use(requestIDResponseHeader)
	// middleware.RealIP is deliberately absent.
	//
	// It rewrites RemoteAddr from X-Forwarded-For unconditionally, which is correct only when
	// the service is unreachable except through a proxy that overwrites the header. Anywhere
	// else it lets a caller choose their own apparent address, and an IP-keyed rate limit
	// then costs an attacker one extra header to bypass — leaving a limiter that reports it
	// is enforcing a limit while enforcing nothing.
	//
	// Address attribution is done by clientip, which honours the header only from declared
	// proxy ranges. Removing RealIP is what makes that possible: leaving it in would mean the
	// socket peer had already been overwritten before anything could judge whether the
	// header deserved to be believed.
	r.Use(instrument)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(requestTimeout))

	auth := authn.NewAuthenticator(d.Auth, d.Log)
	r.Use(auth.Middleware)

	logRateLimitConfig(d.Log, d.limits().IP)

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		httperr.Write(w, r, http.StatusNotFound, "not_found", "no such endpoint")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		httperr.Write(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "that method is not supported on this endpoint")
	})

	// --- infrastructure ------------------------------------------------------
	r.Get("/healthz", d.handleHealth)
	r.Get("/readyz", d.handleReady)
	r.Handle("/metrics", promhttp.Handler())

	// --- unauthenticated -----------------------------------------------------
	// Each endpoint carries its own policy, applied per route rather than to the group.
	// Login and register are the endpoints an attacker reaches without credentials, so the
	// tight limits belong on them specifically; a group-wide limit would have to be the
	// loosest of the set to avoid throttling ordinary logins, which would leave the
	// credential-stuffing surface effectively unbounded.
	limits := d.limits()
	r.Route("/v1/auth", func(r chi.Router) {
		r.With(d.limitByIP(limits.Register)).Post("/register", d.handleRegister)
		r.With(d.limitByIP(limits.Login)).Post("/login", d.handleLogin)
		// Refresh and logout take the token in the body rather than a header,
		// because the access token may already be expired at the moment they are
		// called — requiring a valid Authorization header would make both
		// unusable exactly when they are needed.
		r.With(d.limitByIP(limits.Refresh)).Post("/refresh", d.handleRefresh)
		// Logout is deliberately unlimited. It carries a token in the body and performs one
		// indexed delete, so its cost is bounded and it is not a guessing surface: a wrong
		// token is refused without revealing whether it ever existed. Limiting it would add
		// a failure mode to the one endpoint a client calls when it is already in trouble.
		r.Post("/logout", d.handleLogout)
	})

	// --- authenticated, pre-tenant ------------------------------------------
	// These operate on the principal itself, so they need authentication but no
	// tenant: /v1/me answers "who am I", and /v1/tenants answers "which tenants may
	// I act as" — the query a client needs in order to choose one.
	r.Group(func(r chi.Router) {
		r.Use(authn.RequireAuthentication)
		// The authenticated limit applies here as well as inside the tenant group, because
		// /v1/me and /v1/tenants are reached before any tenant is resolved and would
		// otherwise be unbounded — an authenticated client could hammer them freely while
		// every tenant-scoped route was politely limited.
		r.Use(d.limitByPrincipal(limits.API))
		r.Get("/v1/me", d.handleMe)
		r.Get("/v1/tenants", d.handleListMyTenants)
		r.Post("/v1/tenants", d.handleCreateTenant)
	})

	// --- tenant-scoped -------------------------------------------------------
	// ResolveTenant is the membership gate: it rejects a non-member with 404 and
	// puts a tenant.Authorized on the context for everything below.
	r.Route("/v1/tenants/{tenantID}", func(r chi.Router) {
		r.Use(ResolveTenant(d.Tenants, d.Log))
		r.Use(RequireAuthorized)
		// After tenant resolution, so the bucket keys on the tenant: the limit exists to
		// bound what one tenant can cost the others, and keying it any earlier would have to
		// use the address and would let a tenant with many members multiply its own share.
		r.Use(d.limitByPrincipal(limits.API))

		r.Get("/", d.handleGetTenant)
		r.Get("/members", d.handleListMembers)
		r.Post("/members", d.handleAddMember)

		// The audit trail is readable by anyone holding audit:read — admin and owner, not
		// member. It names who did what, including API keys and request ids, so an admin who
		// can rename a workspace is not automatically able to enumerate its users' actions.
		r.With(authz.Require(authz.PermAuditRead)).Get("/audit", d.handleListAudit)

		registerInvoiceRoutes(r, d)

		r.Route("/projects", func(r chi.Router) {
			// Reads are safe, so they need only the read permission — and deliberately no
			// idempotency, because a GET has no effect to duplicate.
			r.With(authz.Require(authz.PermProjectRead)).Get("/", d.handleListProjects)
			r.With(authz.Require(authz.PermProjectRead)).Get("/{projectID}", d.handleGetProject)

			// Writes are grouped so both guards apply to every one of them, in the order
			// that matters: authorization, then idempotency.
			//
			// The ordering is enforced by writeGuard rather than by listing two r.Use calls,
			// because the wrong order is invisible in review — idempotency first still looks
			// correct while letting an unauthorized caller claim rows in the table. A route
			// added to this group inherits both; a route added outside it is visibly outside.
			r.Group(func(r chi.Router) {
				r.Use(writeGuard(string(authz.PermProjectWrite), d.Idempotency, d.Log))

				r.Post("/", d.handleCreateProject)
				r.Patch("/{projectID}", d.handleUpdateProject)
				r.Delete("/{projectID}", d.handleArchiveProject)
			})
		})
	})

	return r
}

// requestTimeout bounds a whole request. It is generous relative to the p95 target
// because it exists to stop a wedged connection from holding a goroutine forever,
// not to enforce a latency budget — the histogram is what surfaces slow endpoints,
// and a timeout that fired first would hide the measurement.
const requestTimeout = 15 * time.Second

// handleHealth is liveness: is the process running and able to serve?
//
// It deliberately checks nothing external. A liveness probe that fails when a
// dependency is down causes an orchestrator to restart a healthy process, which
// turns a partial outage into a full one.
//
// The body is flat rather than wrapped in the API's data envelope: probes are read
// by an orchestrator or a load balancer looking for a field named "status" at the
// top level, and putting it behind {"data":{...}} means the thing that decides
// whether to restart this process cannot find it.
func (d Deps) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeProbe(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleReady is readiness: should this instance receive traffic?
//
// Postgres is required, so its failure is 503 and removes the instance from
// rotation. Redis is not: the rate limiter fails open when Redis is unreachable, so
// a Redis outage degrades a protection rather than breaking requests, and reporting
// not-ready for it would take a functioning instance out of service. The response
// says which is which, so an operator reading it does not have to guess.
func (d Deps) handleReady(w http.ResponseWriter, r *http.Request) {
	dbOK := true
	if d.DBPing != nil {
		dbOK = d.DBPing(r)
	}
	redisOK := true
	if d.RedisPing != nil {
		redisOK = d.RedisPing(r)
	}

	setGauge(metrics.DBUp, dbOK)
	setGauge(metrics.RedisUp, redisOK)

	switch {
	case !dbOK:
		writeProbe(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"reason": "database_unreachable",
		})
	case !redisOK:
		writeProbe(w, http.StatusOK, map[string]any{"status": "degraded", "redis": "unreachable"})
	default:
		writeProbe(w, http.StatusOK, map[string]any{"status": "ready"})
	}
}

// writeProbe writes a flat JSON body for an infrastructure endpoint.
func writeProbe(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
