// Command api runs the tenant API Platform HTTP service.
//
// # Wiring, and why it lives here
//
// This is the only place that knows about every package, which is what keeps the
// dependency graph acyclic: tenant owns the policy-guarded queries and imports
// authz; authn owns sessions and imports authz; neither imports the other, and the
// adapter that connects them (httpx.MembershipLister) is constructed from main.
//
// # Startup order
//
// Configuration is validated first and a bad value stops the process — a service
// that starts with a short JWT secret or a superuser database role is one that
// looks healthy while providing no isolation. Then dependencies are constructed and
// probed, then the server begins accepting traffic.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/httpx"
	"github.com/aditya0si/tenant-api-platform/internal/idempotency"
	"github.com/aditya0si/tenant-api-platform/internal/invoice"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cache"
	"github.com/aditya0si/tenant-api-platform/internal/platform/clientip"
	"github.com/aditya0si/tenant-api-platform/internal/platform/config"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/logging"
	"github.com/aditya0si/tenant-api-platform/internal/platform/ssrf"
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/ratelimit"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/webhook"
)

// shutdownGrace bounds in-flight requests during shutdown.
//
// It is deliberately longer than httpx's per-request timeout: a request that is
// mid-flight when SIGTERM arrives should be allowed to finish, and a grace period
// shorter than the request timeout would cut it off — which, for a write, means the
// client sees a failure for an operation that may have committed.
const shutdownGrace = 20 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database pool: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database unreachable at %s: %w", redactURL(cfg.DatabaseURL), err)
	}

	// A superuser (or BYPASSRLS) connection silently disables every tenant policy:
	// both bypass row-level security unconditionally. Rather than trusting the
	// operator to have provisioned the right role, the service checks and refuses
	// to start — a deployment that runs with isolation disabled is worse than one
	// that refuses to boot, because nothing about it looks wrong.
	// The same check the API makes, from one shared definition.
	//
	// It lives in the db package rather than in cmd/api because both binaries need it, and because
	// the worker needs it for a subtler reason: this process reaches across every tenant by policy
	// (app.worker, migration 0011), so a privileged worker would still deliver everything while
	// bypassing the mechanism that bounds it. The constraint would look satisfied and would not be.
	if err := db.AssertUnprivilegedRole(ctx, pool, log); err != nil {
		return err
	}

	rdb, err := cache.NewClient(cfg.RedisURL)
	if err != nil {
		// Redis is not required: the rate limiter fails open without it. It is
		// constructed so readiness can report on it, and an unparseable URL is a
		// warning rather than a fatal error: failing startup over an optional
		// dependency would make Redis a hard requirement by accident.
		log.Warn("redis URL is invalid; continuing without it", "err", err)
		rdb = nil
	} else {
		defer func() { _ = rdb.Close() }()
	}

	// Trusted proxies are parsed before anything uses the resolver, so a malformed CIDR is a
	// startup failure rather than a runtime surprise. A typo here silently changes every
	// unauthenticated limit from per-client to per-proxy, and the only symptom is that
	// clients start throttling each other.
	proxyResolver, err := clientip.New(cfg.TrustedProxyCIDRs)
	if err != nil {
		return fmt.Errorf("config: TRUSTED_PROXY_CIDRS: %w", err)
	}

	limits := httpx.RateLimits{IP: proxyResolver}
	if rdb != nil {
		limits.Login = ratelimit.New(rdb, httpx.PolicyLogin, log)
		limits.Register = ratelimit.New(rdb, httpx.PolicyRegister, log)
		limits.Refresh = ratelimit.New(rdb, httpx.PolicyRefreshIP, log)
		limits.API = ratelimit.New(rdb, httpx.PolicyAPI, log)

		// The script is loaded once so a broken script is a failed boot rather than a limiter
		// that permits everything while the process reports healthy. An unreachable Redis is
		// not an error here — that is the degraded state the service is designed to run in.
		for _, l := range []*ratelimit.Limiter{limits.Login, limits.Register, limits.Refresh, limits.API} {
			if err := l.Validate(ctx); err != nil {
				return fmt.Errorf("rate limiter script for policy %q is invalid: %w", l.Policy().Name, err)
			}
		}
	} else {
		log.Warn("rate limiting is disabled: no usable Redis URL. Unsafe-endpoint limits " +
			"(login, register, refresh) will not be enforced.")
	}

	tokens, err := authn.NewTokenIssuer(cfg.JWTSecret, authn.DefaultIssuer, authn.DefaultAudience, cfg.AccessTokenTTL)
	if err != nil {
		return fmt.Errorf("token issuer: %w", err)
	}

	// The cursor key is derived from the same secret, so there is one value to
	// rotate rather than two — while remaining a distinct key, so a signature from
	// one mechanism is not a valid signature for the other.
	codec, err := cursor.NewCodec(cursor.DeriveKey(cfg.JWTSecret))
	if err != nil {
		return fmt.Errorf("cursor codec: %w", err)
	}

	tenants := tenant.NewStore(pool)
	projects := project.NewStore(pool)
	auditReader := audit.NewReader(pool)

	// Constructed before the invoice store, which emits through it. The order is the direction the
	// data flows: an invoice mutation writes an outbox row, so the outbox store is a dependency of
	// the invoice store and the wiring reads that way rather than backwards.
	webhooks := webhook.NewStore(pool)
	invoices := invoice.NewStore(pool, webhooks)

	// SSRF protection is constructed, never configured. A tenant supplies the delivery URL, so the
	// guard is what stands between a registered endpoint and the cloud metadata service; making it
	// switchable would mean the setting an operator flips to make a failing delivery work is the one
	// that disables the protection.
	ssrfGuard := ssrf.New()

	// Idempotency retention and lease are deliberately not configurable.
	//
	// Both are coupled to code constants rather than to deployment policy: the lease must
	// exceed the per-request timeout (15s, a const in the httpx package) or a live handler
	// gets taken over, and the retention must exceed any realistic client retry schedule or
	// a retry lands after the key was forgotten and causes the second effect the protocol
	// exists to prevent. A knob nobody can meaningfully tune is a knob that misleads, so
	// these stay put until a deployment has a measured reason to differ.
	idempotencyStore := idempotency.NewStore(pool, 0, 0)

	apiKeys := authn.NewAPIKeyStore(pool)

	// One store, two consumers: the authenticator resolves a presented key before any tenant is
	// known, and the HTTP surface manages keys inside a resolved tenant. Sharing the value keeps
	// the two paths running the same SQL rather than two copies of it.
	authService, err := authn.NewService(
		authn.NewUserStore(pool),
		tokens,
		authn.NewRefreshStore(pool, cfg.RefreshReuseGrace),
		apiKeys,
		httpx.MembershipLister{Tenants: tenants},
		log,
	)
	if err != nil {
		return fmt.Errorf("auth service: %w", err)
	}

	handler := httpx.New(httpx.Deps{
		Log:            log,
		DBPing:         pingFunc(pool),
		RedisPing:      redisPingFunc(rdb),
		Auth:           authService,
		Users:          authn.NewUserStore(pool),
		Tenants:        tenants,
		Projects:       projects,
		Invoices:       invoices,
		Webhooks:       webhooks,
		APIKeys:        apiKeys,
		SSRF:           ssrfGuard,
		Cursors:        codec,
		Audit:          auditReader,
		Idempotency:    idempotencyStore,
		RateLimits:     &limits,
		AccessTokenTTL: int(cfg.AccessTokenTTL.Seconds()),
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: handler,
		// Timeouts are set on every dimension. A server without them holds a
		// connection — and a goroutine — for as long as a client chooses to keep it
		// open, which is the cheapest possible denial of service.
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("api listening", "port", cfg.Port, "env", cfg.Env, "access_token_ttl", cfg.AccessTokenTTL.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received; draining in-flight requests")
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	}

	// Shutdown stops accepting new connections and waits for in-flight requests.
	// The context is not derived from the cancelled one — that would abort the
	// drain immediately, which is the opposite of the intent.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}

// assertUnprivilegedRole was here and now lives in internal/platform/db/role.go.
//
// It moved because cmd/worker needs the identical check, and two copies of a security assertion
// drift: the one that gets fixed is the one somebody remembered, and the other silently keeps
// permitting the thing it was written to prevent. One definition, called by both binaries.

// pingFunc adapts the pool to the readiness probe signature.
func pingFunc(pool *pgxpool.Pool) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		return pool.Ping(ctx) == nil
	}
}

// redisPingFunc adapts the Redis client, tolerating a nil client.
//
// A nil client means the URL was unparseable, and returning a nil probe is how the
// readiness handler is told "Redis is not configured" rather than "Redis is down" —
// the two produce different responses, and conflating them would take a working
// instance out of rotation because of a typo in an optional dependency's address.
func redisPingFunc(rdb *redis.Client) func(r *http.Request) bool {
	if rdb == nil {
		return nil
	}
	return func(r *http.Request) bool {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		return rdb.Ping(ctx).Err() == nil
	}
}

// redactURL strips credentials from a connection string for logging.
//
// A DSN contains a password, and a startup failure is exactly the moment it would
// be printed — into a terminal, a log aggregator, or a CI transcript.
func redactURL(raw string) string {
	at := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return raw
	}
	schemeEnd := 0
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] == ':' && raw[i+1] == '/' && raw[i+2] == '/' {
			schemeEnd = i + 3
			break
		}
	}
	if schemeEnd == 0 || schemeEnd > at {
		return "postgres://[redacted]"
	}
	return raw[:schemeEnd] + "[redacted]" + raw[at:]
}
