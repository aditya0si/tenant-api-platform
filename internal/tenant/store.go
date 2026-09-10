package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

// Store is the tenant repository.
//
// Tenant-scoped methods take an Authorized, which only Store.Resolve can
// construct, and they run inside a transaction whose row-level-security identity
// is derived from it. There is deliberately no method that accepts a bare tenant
// id for a scoped query: a caller cannot reach tenant data except through the
// membership gate.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool. The pool must authenticate as a role
// that row-level security actually applies to (app_rw). A superuser or BYPASSRLS
// pool makes every policy in migration 0001 decorative — see
// docs/adr/ADR-003-tenancy-and-rls.md.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// CreateTenantWithOwner creates a tenant, its first user, and the owner
// membership in one transaction.
//
// This is the one write that cannot go through Resolve: the tenant does not exist
// yet, so there is no membership to authorize against. It is instead authorized
// structurally — the transaction sets the tenant GUC to the new tenant's id,
// which is exactly what the INSERT policies on tenants and memberships require,
// and the caller is by definition the principal being made owner.
//
// Every step is atomic. TestCreateTenantWithOwner_RollsBackOnConflict proves the
// failure path rolls back rather than leaving a tenant nobody owns.
func (s *Store) CreateTenantWithOwner(ctx context.Context, t Tenant, owner Owner, role authz.Role) error {
	if err := validateNewTenant(t); err != nil {
		return err
	}
	if owner.ID == uuid.Nil {
		return fmt.Errorf("tenant: nil owner id: %w", apperr.ErrValidation)
	}
	if !role.Valid() {
		return fmt.Errorf("tenant: unknown role %q: %w", role, apperr.ErrValidation)
	}
	email, err := normalizeEmail(owner.Email)
	if err != nil {
		return err
	}

	ident := db.Identity{TenantID: t.ID, UserID: owner.ID}
	return db.WithIdentityTx(ctx, s.pool, ident, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $3)`,
			t.ID, t.Slug, t.Name); err != nil {
			return translate(err, "insert tenant")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO users (id, email, pw_hash) VALUES ($1, $2, $3)`,
			owner.ID, email, owner.PWHash); err != nil {
			return translate(err, "insert owner")
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)`,
			t.ID, owner.ID, role); err != nil {
			return translate(err, "insert membership")
		}
		return nil
	})
}

// Resolve is the membership gate: it authorizes userID for tenantID and returns
// the Authorized value every scoped method requires.
//
// This is the only way to obtain an Authorized, so a caller physically cannot
// reach a tenant the principal does not belong to. It returns ErrNotFound —
// never ErrForbidden — when the principal is not a member, so the resulting 404
// tells an attacker nothing about whether the tenant exists.
func (s *Store) Resolve(ctx context.Context, tenantID, userID uuid.UUID) (Authorized, error) {
	scope, err := NewScope(tenantID)
	if err != nil {
		// A nil tenant id is reported as not-found for the same reason: the
		// caller must not be able to distinguish "no such tenant" from "not
		// your tenant" by the shape of the error.
		return Authorized{}, apperr.ErrNotFound
	}
	if userID == uuid.Nil {
		return Authorized{}, apperr.ErrUnauthorized
	}
	role, err := s.Authorize(ctx, scope, userID)
	if err != nil {
		return Authorized{}, err
	}
	return newAuthorized(scope, userID, role)
}

// Authorize reports the role userID holds in scope, or ErrNotFound when the
// principal is not a member of that tenant.
//
// The query is bounded twice: the memberships policies restrict the row set, and
// the WHERE clause pins the specific user. "Not a member" and "no such tenant"
// are intentionally indistinguishable to the caller.
func (s *Store) Authorize(ctx context.Context, scope Scope, userID uuid.UUID) (authz.Role, error) {
	if !scope.Valid() {
		return "", apperr.ErrNoScope
	}
	if userID == uuid.Nil {
		return "", apperr.ErrUnauthorized
	}

	var role authz.Role
	ident := db.Identity{TenantID: scope.ID(), UserID: userID}
	err := db.WithIdentityTx(ctx, s.pool, ident, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT role FROM memberships WHERE tenant_id = $1 AND user_id = $2`,
			scope.ID(), userID).Scan(&role)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", apperr.ErrNotFound
	case err != nil:
		return "", fmt.Errorf("authorize: %w", err)
	}
	return role, nil
}

// Get returns the tenant the caller is authorized for.
//
// Both GUCs are set from auth, and both are required: the tenants policy is keyed
// on membership, so the policy's EXISTS subquery needs app.current_user_id. The
// WHERE clause and the policy overlap on purpose — the predicate keeps the query
// on the primary-key index, and the policy is what keeps it safe if the predicate
// is ever dropped during a refactor.
func (s *Store) Get(ctx context.Context, auth Authorized) (Tenant, error) {
	if !auth.Valid() {
		return Tenant{}, apperr.ErrNoScope
	}

	var t Tenant
	err := db.WithIdentityTx(ctx, s.pool, identityFor(auth), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, slug, name, created_at FROM tenants WHERE id = $1`,
			auth.Scope().ID()).Scan(&t.ID, &t.Slug, &t.Name, &t.CreatedAt)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Tenant{}, apperr.ErrNotFound
	case err != nil:
		return Tenant{}, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

// ListForUser returns every tenant userID belongs to.
//
// This is a pre-tenant query: it runs with only the user GUC set, because no
// tenant has been selected yet — which is the whole reason the memberships policy
// has a user-keyed arm. A policy keyed solely on the tenant would return zero
// rows here and push a future author toward a bypass.
func (s *Store) ListForUser(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	if userID == uuid.Nil {
		return nil, apperr.ErrUnauthorized
	}

	var out []Membership
	ident := db.Identity{UserID: userID}
	err := db.WithIdentityTx(ctx, s.pool, ident, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.tenant_id, t.slug, t.name, m.role, m.created_at
			FROM memberships m
			JOIN tenants t ON t.id = m.tenant_id
			WHERE m.user_id = $1
			ORDER BY t.slug`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Membership
			if err := rows.Scan(&m.TenantID, &m.TenantSlug, &m.TenantName, &m.Role, &m.CreatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list memberships: %w", err)
	}
	return out, nil
}

// ListMembers returns the roster of the caller's tenant, ordered by email.
//
// The tenant predicate and the RLS policy both bound this query. Neither alone
// would be the right answer: the predicate is what an index can use, and the
// policy is what holds when a future query forgets one.
func (s *Store) ListMembers(ctx context.Context, auth Authorized) ([]Member, error) {
	if !auth.Valid() {
		return nil, apperr.ErrNoScope
	}

	var out []Member
	err := db.WithIdentityTx(ctx, s.pool, identityFor(auth), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT m.user_id, u.email, m.role, m.created_at
			FROM memberships m
			JOIN users u ON u.id = m.user_id
			WHERE m.tenant_id = $1
			ORDER BY u.email`, auth.Scope().ID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m Member
			if err := rows.Scan(&m.UserID, &m.Email, &m.Role, &m.CreatedAt); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	return out, nil
}

// AddMember grants an existing user a role in the caller's tenant.
//
// Note which identity is written into the GUCs: the *acting* principal from auth,
// not the user being added. Setting app.current_user_id to the new member would
// still satisfy the INSERT policy (it checks the tenant), but it would mean the
// request silently ran as somebody else — and any policy or audit trigger that
// keys on the principal would be reading the wrong person.
//
// A foreign-key violation means the user does not exist. That is reported as
// ErrNotFound rather than a distinct "unknown user" code so the endpoint cannot
// be used to enumerate accounts across tenants.
func (s *Store) AddMember(ctx context.Context, auth Authorized, userID uuid.UUID, role authz.Role) error {
	if !auth.Valid() {
		return apperr.ErrNoScope
	}
	if userID == uuid.Nil {
		return fmt.Errorf("tenant: nil user id: %w", apperr.ErrValidation)
	}
	if !role.Valid() {
		return fmt.Errorf("tenant: unknown role %q: %w", role, apperr.ErrValidation)
	}

	err := db.WithIdentityTx(ctx, s.pool, identityFor(auth), func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)`,
			auth.Scope().ID(), userID, role)
		if err != nil {
			if db.IsForeignKeyViolation(err) {
				return apperr.ErrNotFound
			}
			return translate(err, "insert membership")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// identityFor derives the row-level-security identity from an authorized caller.
//
// Both fields come from the same value, so a scoped query cannot be issued with a
// tenant and a principal that were authorized separately — or with one of them
// missing, which is the failure mode described in access.go.
func identityFor(auth Authorized) db.Identity {
	return db.Identity{TenantID: auth.Scope().ID(), UserID: auth.UserID()}
}

// translate maps Postgres constraint violations onto sentinel errors so callers
// never have to inspect driver error codes.
func translate(err error, op string) error {
	switch {
	case db.IsUniqueViolation(err):
		return fmt.Errorf("%s: %w", op, apperr.ErrConflict)
	case db.IsCheckViolation(err):
		return fmt.Errorf("%s: %w", op, apperr.ErrValidation)
	default:
		return fmt.Errorf("%s: %w", op, err)
	}
}
