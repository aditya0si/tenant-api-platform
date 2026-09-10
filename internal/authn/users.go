package authn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

// User is a global identity. Users are not tenant-scoped: a person may belong to
// several tenants, and the tenants they can reach is expressed by memberships
// (see ADR-003 for the reasoning and the residual exposure this accepts).
type User struct {
	ID        uuid.UUID
	Email     string
	PWHash    string
	CreatedAt time.Time
}

// UserStore reads and writes users.
//
// Note the absence of a tenant scope on these methods. That is intentional and
// bounded: users is the one table with no row-level-security policy, because
// authenticating a principal is inherently a pre-tenant operation. What keeps
// this safe is that no HTTP handler returns another user's row — member
// listings join through memberships, which *is* governed by policy.
type UserStore struct {
	pool *pgxpool.Pool
}

// NewUserStore returns a UserStore backed by pool.
func NewUserStore(pool *pgxpool.Pool) *UserStore { return &UserStore{pool: pool} }

// Create hashes password and inserts a new user, returning It with the hash
// set. A duplicate email yields ErrConflict.
func (s *UserStore) Create(ctx context.Context, email, password string) (User, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		return User{}, err
	}
	if err := ValidatePasswordStrength(password); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}

	u := User{ID: uuid.Must(uuid.NewV7()), Email: normalized, PWHash: hash}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, email, pw_hash) VALUES ($1, $2, $3)`,
		u.ID, u.Email, u.PWHash)
	if err != nil {
		if db.IsUniqueViolation(err) {
			return User{}, fmt.Errorf("create user: %w", apperr.ErrConflict)
		}
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

// Insert places a pre-built user row (used by seeding, where the hash is
// computed once and shared across fixtures).
func (s *UserStore) Insert(ctx context.Context, u User) error {
	normalized, err := NormalizeEmail(u.Email)
	if err != nil {
		return err
	}
	if u.ID == uuid.Nil {
		return fmt.Errorf("insert user: nil id: %w", apperr.ErrValidation)
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO users (id, email, pw_hash) VALUES ($1, $2, $3)`,
		u.ID, normalized, u.PWHash)
	if err != nil {
		if db.IsUniqueViolation(err) {
			return fmt.Errorf("insert user: %w", apperr.ErrConflict)
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// ByEmail looks up a user for authentication. A missing row yields ErrNotFound;
// the caller must respond identically to a wrong password so the endpoint does
// not become an account oracle.
func (s *UserStore) ByEmail(ctx context.Context, email string) (User, error) {
	normalized, err := NormalizeEmail(email)
	if err != nil {
		// A malformed address cannot match any row: report not-found rather than
		// validation failure, so login responses stay uniform.
		return User{}, apperr.ErrNotFound
	}
	return s.scanOne(ctx, `SELECT id, email, pw_hash, created_at FROM users WHERE email = $1`, normalized)
}

// ByID looks up a user by primary key.
func (s *UserStore) ByID(ctx context.Context, id uuid.UUID) (User, error) {
	if id == uuid.Nil {
		return User{}, apperr.ErrNotFound
	}
	return s.scanOne(ctx, `SELECT id, email, pw_hash, created_at FROM users WHERE id = $1`, id)
}

func (s *UserStore) scanOne(ctx context.Context, query string, arg any) (User, error) {
	var u User
	err := s.pool.QueryRow(ctx, query, arg).Scan(&u.ID, &u.Email, &u.PWHash, &u.CreatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return User{}, apperr.ErrNotFound
	case err != nil:
		return User{}, fmt.Errorf("lookup user: %w", err)
	}
	return u, nil
}

// NormalizeEmail lower-cases and validates an address. The database enforces the
// same rule with a CHECK constraint; doing it here turns a constraint violation
// into a clean validation error.
func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) < 3 || len(email) > 320 {
		return "", fmt.Errorf("authn: email length out of range: %w", apperr.ErrValidation)
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", fmt.Errorf("authn: email must have a local part and a domain: %w", apperr.ErrValidation)
	}
	if !strings.Contains(email[at+1:], ".") {
		return "", fmt.Errorf("authn: email domain must be fully qualified: %w", apperr.ErrValidation)
	}
	return email, nil
}

// ValidatePasswordStrength enforces the minimum policy. Length dominates
// composition rules, so the only hard requirement is length; the upper bound
// protects argon2 from being fed megabyte inputs.
func ValidatePasswordStrength(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("authn: password must be at least 12 characters: %w", apperr.ErrValidation)
	}
	if len(password) > 1024 {
		return fmt.Errorf("authn: password must be at most 1024 characters: %w", apperr.ErrValidation)
	}
	return nil
}
