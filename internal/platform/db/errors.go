package db

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

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

// IsRLSViolation reports whether err is a row-level-security policy rejection
// (Postgres SQLSTATE 42501 raised by a policy rather than by a missing GRANT).
//
// The distinction matters for diagnosis: a 42501 from a policy means the request
// reached the database with the wrong identity — a bug in the scope plumbing —
// while a 42501 from a missing GRANT means the role was provisioned wrong, and
// the two have completely different fixes.
//
// Postgres does not give the two separate SQLSTATEs, so the message is the only
// discriminator available. It is checked narrowly (a documented prefix) and only
// for logs, never for control flow: nothing in this codebase decides what to do
// based on this function.
func IsRLSViolation(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		return false
	}
	return strings.HasPrefix(pgErr.Message, "new row violates row-level security policy") ||
		strings.HasPrefix(pgErr.Message, "permission denied for table")
}
