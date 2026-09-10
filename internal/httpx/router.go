package httpx

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
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

	// AccessTokenTTL is reported to clients so they know when to refresh without
	// hard-coding a value that lives in configuration.
	AccessTokenTTL int
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
	r.Use(middleware.RealIP)
	r.Use(instrument)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(requestTimeout))

	auth := authn.NewAuthenticator(d.Auth, d.Log)
	r.Use(auth.Middleware)

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
	r.Route("/v1/auth", func(r chi.Router) {
		r.Post("/register", d.handleRegister)
		r.Post("/login", d.handleLogin)
		// Refresh and logout take the token in the body rather than a header,
		// because the access token may already be expired at the moment they are
		// called — requiring a valid Authorization header would make both
		// unusable exactly when they are needed.
		r.Post("/refresh", d.handleRefresh)
		r.Post("/logout", d.handleLogout)
	})

	// --- authenticated, pre-tenant ------------------------------------------
	// These operate on the principal itself, so they need authentication but no
	// tenant: /v1/me answers "who am I", and /v1/tenants answers "which tenants may
	// I act as" — the query a client needs in order to choose one.
	r.Group(func(r chi.Router) {
		r.Use(authn.RequireAuthentication)
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

		r.Get("/", d.handleGetTenant)
		r.Get("/members", d.handleListMembers)
		r.Post("/members", d.handleAddMember)

		r.Route("/projects", func(r chi.Router) {
			// Read requires project:read; every mutation requires project:write.
			// Putting the permission on the group rather than the handler means a
			// new route cannot be added without inheriting a check.
			r.With(authz.Require(authz.PermProjectRead)).Get("/", d.handleListProjects)
			r.With(authz.Require(authz.PermProjectRead)).Get("/{projectID}", d.handleGetProject)
			r.With(authz.Require(authz.PermProjectWrite)).Post("/", d.handleCreateProject)
			r.With(authz.Require(authz.PermProjectWrite)).Patch("/{projectID}", d.handleUpdateProject)
			r.With(authz.Require(authz.PermProjectWrite)).Delete("/{projectID}", d.handleArchiveProject)
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
