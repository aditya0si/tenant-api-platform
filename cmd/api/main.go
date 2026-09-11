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
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/ratelimit"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
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
	if err := assertUnprivilegedRole(ctx, pool); err != nil {
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
	invoices := invoice.NewStore(pool)

	// Idempotency retention and lease are deliberately not configurable.
	//
	// Both are coupled to code constants rather than to deployment policy: the lease must
	// exceed the per-request timeout (15s, a const in the httpx package) or a live handler
	// gets taken over, and the retention must exceed any realistic client retry schedule or
	// a retry lands after the key was forgotten and causes the second effect the protocol
	// exists to prevent. A knob nobody can meaningfully tune is a knob that misleads, so
	// these stay put until a deployment has a measured reason to differ.
	idempotencyStore := idempotency.NewStore(pool, 0, 0)

	authService, err := authn.NewService(
		authn.NewUserStore(pool),
		tokens,
		authn.NewRefreshStore(pool, cfg.RefreshReuseGrace),
		authn.NewAPIKeyStore(pool),
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

// assertUnprivilegedRole refuses to start when the database connection can bypass
// row-level security.
//
// The check is enforced rather than documented because the failure is invisible:
// every query still works, every application-level test still passes, and the only
// thing lost is the second layer of tenant isolation — which is the layer that
// holds when a query forgets its predicate. A service that boots with that layer
// disabled looks entirely healthy.
//
// The escape hatch is an explicit environment variable rather than a permissive
// default, so running without isolation is a decision someone records.
func assertUnprivilegedRole(ctx context.Context, pool *pgxpool.Pool) error {
	if os.Getenv("ALLOW_PRIVILEGED_DB_ROLE") == "1" {
		slog.Default().Warn("starting with a privileged database role: row-level security is NOT enforced; " +
			"this is only appropriate for a local debugging session")
		return nil
	}

	var (
		currentUser string
		isSuper     bool
		bypassRLS   bool
	)
	err := pool.QueryRow(ctx, `
		SELECT current_user,
		       (SELECT rolsuper      FROM pg_roles WHERE rolname = current_user),
		       (SELECT rolbypassrls  FROM pg_roles WHERE rolname = current_user)`).
		Scan(&currentUser, &isSuper, &bypassRLS)
	if err != nil {
		return fmt.Errorf("inspect database role: %w", err)
	}

	switch {
	case isSuper:
		return fmt.Errorf(
			"database role %q is a SUPERUSER: superusers bypass row-level security unconditionally, "+
				"so every tenant policy would be decorative. Point DATABASE_URL at the application role "+
				"(app_rw, created by the migrations) and keep the owner credentials in MIGRATE_DATABASE_URL. "+
				"Set ALLOW_PRIVILEGED_DB_ROLE=1 to start anyway, for local debugging only", currentUser)
	case bypassRLS:
		return fmt.Errorf(
			"database role %q has BYPASSRLS: it ignores row-level security, so tenant isolation would "+
				"not be enforced by the database. Use the application role (app_rw). "+
				"Set ALLOW_PRIVILEGED_DB_ROLE=1 to start anyway, for local debugging only", currentUser)
	}
	return nil
}

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
