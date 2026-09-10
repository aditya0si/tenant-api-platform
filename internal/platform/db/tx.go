package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Identity is the request identity written into the transaction-scoped GUCs
// that row-level security policies read.
//
// Either field may be zero, which means "do not set that GUC":
//   - user only  — pre-tenant operations (login, "my tenants", the membership gate)
//   - both       — tenant-scoped operations
//
// A fully zero Identity is rejected: running a query with no identity at all is
// a bug, and under the policies it would silently return zero rows, which is the
// failure mode we least want to debug in production.
type Identity struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
}

// Valid reports whether at least one identity component is set.
func (i Identity) Valid() bool { return i.TenantID != uuid.Nil || i.UserID != uuid.Nil }

// WithIdentityTx runs fn inside a transaction whose RLS GUCs are set to id.
//
// set_config(name, value, is_local => true) is transaction-scoped: the values
// revert when the transaction ends, so a pooled connection cannot carry one
// request's tenant into the next. Passing false here (or using plain SET) is the
// classic multi-tenant data-leak bug; do not change it.
//
// pgx.BeginFunc rolls back on error *and* on panic, so a handler panic cannot
// commit a half-written tenant mutation.
func WithIdentityTx(ctx context.Context, pool *pgxpool.Pool, id Identity, fn func(pgx.Tx) error) error {
	if !id.Valid() {
		return apperr.ErrNoScope
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if id.TenantID != uuid.Nil {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_tenant_id', $1, true)`, id.TenantID.String()); err != nil {
				return fmt.Errorf("set tenant scope: %w", err)
			}
		}
		if id.UserID != uuid.Nil {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.current_user_id', $1, true)`, id.UserID.String()); err != nil {
				return fmt.Errorf("set user identity: %w", err)
			}
		}
		return fn(tx)
	})
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint error.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsForeignKeyViolation reports whether err is a Postgres FK violation.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// IsCheckViolation reports whether err is a Postgres CHECK-constraint error.
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}
