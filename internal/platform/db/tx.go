package db

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Names of the transaction-scoped settings (GUCs) that row-level-security
// policies read. They are named here, once, because a typo in a string literal
// would not fail to compile and would present as "the policy hides everything".
const (
	// SettingTenantID scopes a request to one tenant.
	SettingTenantID = "app.current_tenant_id"
	// SettingUserID identifies the authenticated principal.
	SettingUserID = "app.current_user_id"
	// SettingRefreshTokenHash carries the presented refresh token's hash, so the
	// pre-authentication refresh lookup can find exactly that row.
	SettingRefreshTokenHash = "app.current_refresh_token_hash"
	// SettingAPIKeyHash carries the presented API key's hash, for the same reason:
	// authentication happens before any tenant is selected.
	SettingAPIKeyHash = "app.current_api_key_hash"
)

// Identity is the request identity written into the policies' GUCs.
//
// Either field may be zero, which means "do not set that GUC":
//   - user only  — pre-tenant operations (login, "my tenants", the membership gate)
//   - both       — tenant-scoped operations
//
// A fully zero Identity is rejected: running a query with no identity at all is
// a bug, and under the policies it would silently return zero rows, which is the
// failure mode least likely to be noticed in review.
type Identity struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
}

// Valid reports whether at least one identity component is set.
func (i Identity) Valid() bool { return i.TenantID != uuid.Nil || i.UserID != uuid.Nil }

// SetLocal applies one transaction-scoped GUC.
//
// is_local => true is the entire point: the value reverts at COMMIT or ROLLBACK,
// so a pooled connection cannot carry one request's tenant into the next. Passing
// false — or using plain SET — is the classic multi-tenant data-leak bug, and
// TestRLS_ConcurrentScopesDoNotLeak (32 goroutines, a two-connection pool) exists
// to catch it.
//
// The value is passed as a bind parameter, which is why this uses set_config
// rather than `SET LOCAL x = ...`: SET cannot be parameterized, so tenant ids
// would have to be interpolated into SQL.
func SetLocal(ctx context.Context, tx pgx.Tx, name, value string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, name, value); err != nil {
		return fmt.Errorf("set %s: %w", name, err)
	}
	return nil
}

// WithSettings runs fn in a transaction with the given settings applied.
//
// It is the general form; WithIdentityTx is the typed convenience built on it.
// Callers that authenticate a credential before knowing a user — the refresh and
// API-key paths — need settings that are neither a tenant nor a user id.
//
// pgx.BeginFunc rolls back on error *and* on panic, so a handler panic cannot
// commit a half-written mutation.
func WithSettings(ctx context.Context, pool *pgxpool.Pool, settings map[string]string, fn func(pgx.Tx) error) error {
	if len(settings) == 0 {
		return apperr.ErrNoScope
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for name, value := range settings {
			if err := SetLocal(ctx, tx, name, value); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// WithIdentityTx runs fn inside a transaction whose RLS GUCs are set to id.
func WithIdentityTx(ctx context.Context, pool *pgxpool.Pool, id Identity, fn func(pgx.Tx) error) error {
	if !id.Valid() {
		return apperr.ErrNoScope
	}
	settings := map[string]string{}
	if id.TenantID != uuid.Nil {
		settings[SettingTenantID] = id.TenantID.String()
	}
	if id.UserID != uuid.Nil {
		settings[SettingUserID] = id.UserID.String()
	}
	return WithSettings(ctx, pool, settings, fn)
}

// WithPresentedSecret runs fn with only the hash of a presented credential set.
//
// This is the pre-authentication shape: the caller holds a secret and nothing
// else, and the policy admits exactly the row that secret identifies (see
// migrations 0002 and 0003). The setting name is chosen by the caller because a
// refresh token and an API key are different credentials with different arms.
func WithPresentedSecret(ctx context.Context, pool *pgxpool.Pool, setting, hash string, fn func(pgx.Tx) error) error {
	return WithSettings(ctx, pool, map[string]string{setting: hash}, fn)
}
