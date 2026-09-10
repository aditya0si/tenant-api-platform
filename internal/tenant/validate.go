package tenant

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// slugPattern mirrors the CHECK constraint on tenants.slug. Duplicating the rule
// in Go is deliberate: the database is the authority, and the application-level
// copy exists so a caller gets a 400 with a usable message instead of a 500
// wrapping a constraint violation.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func validateNewTenant(t Tenant) error {
	if t.ID == uuid.Nil {
		return fmt.Errorf("tenant: nil tenant id: %w", apperr.ErrValidation)
	}
	if !slugPattern.MatchString(t.Slug) {
		return fmt.Errorf("tenant: slug %q must match %s: %w", t.Slug, slugPattern, apperr.ErrValidation)
	}
	if n := len(strings.TrimSpace(t.Name)); n < 1 || n > 200 {
		return fmt.Errorf("tenant: name must be 1..200 characters: %w", apperr.ErrValidation)
	}
	return nil
}

// normalizeEmail lower-cases and trims an address, then rejects obviously
// malformed input.
//
// The single source of truth for the address format is the monotonic CHECK
// constraint on users.email plus its unique index — normalizing in Go merely
// means the common case produces a clean 400 instead of a 500.
func normalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) < 3 || len(email) > 320 {
		return "", fmt.Errorf("tenant: email length out of range: %w", apperr.ErrValidation)
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", fmt.Errorf("tenant: email must contain a local part and a domain: %w", apperr.ErrValidation)
	}
	if !strings.Contains(email[at+1:], ".") {
		return "", fmt.Errorf("tenant: email domain must be fully qualified: %w", apperr.ErrValidation)
	}
	return email, nil
}
