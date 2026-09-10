// Package apperr defines the sentinel errors the domain and repository layers
// return.
//
// Handlers map these onto HTTP status codes in exactly one place, so a
// repository never has to know about HTTP and a handler never has to
// pattern-match driver errors.
package apperr

import "errors"

var (
	// ErrNotFound is returned when a resource does not exist *or* is not
	// visible to the caller. Callers must never distinguish the two: revealing
	// the difference leaks the existence of other tenants' resources and turns
	// id-guessing into an existence oracle.
	ErrNotFound = errors.New("not found")

	// ErrConflict is returned for uniqueness violations (slug, email, key).
	ErrConflict = errors.New("conflict")

	// ErrNoScope is returned when an operation that requires a resolved tenant
	// scope is called without one. It is a programming error, not a client error.
	ErrNoScope = errors.New("no tenant scope")

	// ErrForbidden is returned when an authenticated principal lacks a
	// permission for a resource it can already see.
	ErrForbidden = errors.New("forbidden")

	// ErrUnauthorized is returned when authentication is missing or invalid.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrValidation is returned when input fails validation at the boundary.
	ErrValidation = errors.New("validation failed")
)

// Is reports whether err (or anything it wraps) is target.
func Is(err, target error) bool { return errors.Is(err, target) }
