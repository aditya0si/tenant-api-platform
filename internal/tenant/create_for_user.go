package tenant

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

// CreateForUser creates a tenant and makes an existing user its owner.
//
// It is the counterpart to CreateTenantWithOwner: that one also creates the user,
// for the sign-up path where neither exists yet; this one takes a user that is
// already authenticated, for "start another organisation without making a second
// account".
//
// The tenant GUC is set to the new tenant so the INSERT policies admit both rows,
// and the membership is what makes the tenant visible on the next request. Both
// statements are in one transaction, so a failure leaves no tenant nobody owns.
func (s *Store) CreateForUser(ctx context.Context, t Tenant, userID uuid.UUID, role authz.Role) error {
	if err := validateNewTenant(t); err != nil {
		return err
	}
	if userID == uuid.Nil {
		return fmt.Errorf("tenant: nil user id: %w", apperr.ErrUnauthorized)
	}
	if !role.Valid() {
		return fmt.Errorf("tenant: unknown role %q: %w", role, apperr.ErrValidation)
	}

	ident := db.Identity{TenantID: t.ID, UserID: userID}
	return db.WithIdentityTx(ctx, s.pool, ident, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
			t.ID, t.Slug, t.Name); err != nil {
			return translate(err, "insert tenant")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)`,
			t.ID, userID, role); err != nil {
			// A foreign-key violation means the user does not exist; reported as
			// not-found so the endpoint cannot be used to probe for accounts.
			if db.IsForeignKeyViolation(err) {
				return apperr.ErrNotFound
			}
			return translate(err, "insert membership")
		}
		return nil
	})
}
