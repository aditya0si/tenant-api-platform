package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
)

// Config is validated at startup: a misconfigured service fails immediately and
// loudly rather than at the first request that needs the missing value.
type Config struct {
	Env  string
	Port int

	// DatabaseURL is the application role (app_rw): deliberately not a superuser
	// and not BYPASSRLS, because both bypass row-level security unconditionally.
	// Pointing this at the owner role silently disables tenant isolation, and
	// TestRLS_AppRoleIsSubjectToPolicies exists to catch exactly that.
	DatabaseURL string

	// MigrateDatabaseURL is the owner role, and is only used by cmd/migrate. The
	// API is never given it: the application has no reason to hold DDL rights.
	MigrateDatabaseURL string

	RedisURL string

	// JWTSecret is the access-token signing key; CursorKey is derived from it, so
	// there is one secret to rotate rather than two.
	JWTSecret []byte

	// AccessTokenTTL is bounded on both sides. Too long and a leaked token cannot
	// be revoked — the refresh family cannot invalidate a signature that already
	// exists, so the lifetime is the only lever. Too short and every client
	// refreshes constantly, which turns the refresh endpoint into the hot path.
	AccessTokenTTL time.Duration

	// RefreshTTL is the real session lifetime: how long a client can renew without
	// logging in again.
	RefreshTTL time.Duration

	// RefreshReuseGrace is the window in which re-presenting a consumed refresh
	// token is treated as a concurrent retry rather than as theft. Zero means
	// strictly single-use, at the cost of logging out clients that race themselves.
	RefreshReuseGrace time.Duration

	LogLevel string
}

// Load reads and validates configuration from the environment.
func Load() (Config, error) {
	c := Config{
		Env:                envOr("APP_ENV", "dev"),
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		MigrateDatabaseURL: os.Getenv("MIGRATE_DATABASE_URL"),
		RedisURL:           envOr("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:           envOr("LOG_LEVEL", "info"),
	}

	port, err := intEnv("PORT", 8080)
	if err != nil {
		return Config{}, err
	}
	if port <= 0 || port > 65535 {
		return Config{}, fmt.Errorf("config: PORT must be between 1 and 65535, got %d", port)
	}
	c.Port = port

	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL is required (the application role, e.g. app_rw)")
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		if c.Env == "prod" {
			// A default secret in production is a service whose tokens anyone can
			// forge. Refusing to start is the only safe behaviour.
			return Config{}, fmt.Errorf("config: JWT_SECRET is required when APP_ENV=prod")
		}
		// The development default is long enough to satisfy the length check below
		// and is deliberately obvious, so a deployment that accidentally relies on
		// it is recognisable rather than subtle.
		secret = "dev-only-insecure-secret-change-me-32b-min"
	}
	if len(secret) < 32 {
		// Enforced here as well as in the token issuer: a short HMAC key produces
		// tokens that verify correctly and are trivially forgeable, so the failure
		// mode is silent unless something refuses to start.
		return Config{}, fmt.Errorf("config: JWT_SECRET must be at least 32 characters, got %d", len(secret))
	}
	c.JWTSecret = []byte(secret)

	if c.AccessTokenTTL, err = durationEnv("ACCESS_TOKEN_TTL", authn.DefaultAccessTTL); err != nil {
		return Config{}, err
	}
	if c.RefreshTTL, err = durationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour); err != nil {
		return Config{}, err
	}
	if c.RefreshReuseGrace, err = durationEnv("REFRESH_REUSE_GRACE", 10*time.Second); err != nil {
		return Config{}, err
	}

	if c.AccessTokenTTL > time.Hour {
		return Config{}, fmt.Errorf(
			"config: ACCESS_TOKEN_TTL is %s; an access token longer than an hour cannot be "+
				"revoked (the refresh family cannot invalidate an issued signature), so its "+
				"lifetime is the only bound on a leaked one", c.AccessTokenTTL)
	}
	if c.RefreshTTL <= c.AccessTokenTTL {
		return Config{}, fmt.Errorf(
			"config: REFRESH_TOKEN_TTL (%s) must exceed ACCESS_TOKEN_TTL (%s), otherwise the "+
				"session expires before the credential that renews it",
			c.RefreshTTL, c.AccessTokenTTL)
	}

	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, raw)
	}
	return v, nil
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a duration such as 10m or 24h, got %q", key, raw)
	}
	if d < 0 {
		return 0, fmt.Errorf("config: %s must not be negative, got %s", key, d)
	}
	return d, nil
}
