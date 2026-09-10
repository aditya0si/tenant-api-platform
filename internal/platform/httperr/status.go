package httperr

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Problem is the HTTP rendering of a domain error.
type Problem struct {
	Status  int
	Code    string
	Message string
	Details map[string]any
}

// Map translates a domain error into the response a client receives.
//
// This is the single place where the domain's vocabulary meets HTTP's, which is
// what keeps the mapping consistent: a repository returns a sentinel, and every
// endpoint that returns it answers the same way, whether or not the author of that
// endpoint thought about it.
//
// # Which messages survive
//
// A client-safe error carries a message written for the API consumer — a malformed
// field, a duplicate slug, a missing resource — and that text is preserved, because
// replacing it with "bad request" is what makes an API unpleasant to integrate
// against. Everything else is replaced with a fixed string, and the original is
// logged by Fail, so a driver error or a file path never reaches the wire.
//
// The decision is made by apperr.ClientSafe, not by inspecting the error's type
// here, so it is made once and deliberately.
func Map(err error) Problem {
	// A typed validation error carries a field name, which becomes structured
	// detail the client can attach to an input rather than parse out of prose.
	var ce *apperr.ClientError
	if errors.As(err, &ce) {
		return Problem{
			Status:  http.StatusBadRequest,
			Code:    "validation_failed",
			Message: ce.Msg,
			Details: fieldDetails(ce.Field),
		}
	}

	switch {
	case errors.Is(err, apperr.ErrNotFound):
		return Problem{http.StatusNotFound, "not_found", clientMessage(err, "the requested resource does not exist"), nil}

	case errors.Is(err, apperr.ErrUnauthorized):
		// Fixed text, never the cause. The client can act on none of the
		// distinctions between an expired token, a revoked one, and a forgery, and
		// the specific reason is what an attacker probing credentials wants to know.
		return Problem{http.StatusUnauthorized, "unauthorized", "authentication required", nil}

	case errors.Is(err, apperr.ErrForbidden):
		return Problem{http.StatusForbidden, "forbidden", clientMessage(err, "this credential may not perform that action"), nil}

	case errors.Is(err, apperr.ErrVersionConflict):
		return Problem{
			http.StatusConflict,
			"version_conflict",
			"the resource changed since it was read; re-read it and retry",
			nil,
		}

	case errors.Is(err, apperr.ErrConflict):
		return Problem{http.StatusConflict, "conflict", clientMessage(err, "that value is already in use"), nil}

	case errors.Is(err, apperr.ErrValidation):
		return Problem{http.StatusBadRequest, "validation_failed", clientMessage(err, "the request failed validation"), nil}

	case errors.Is(err, apperr.ErrUnavailable):
		return Problem{http.StatusServiceUnavailable, "service_unavailable", "the service is temporarily unavailable", nil}

	default:
		// Includes ErrNoScope, which is a programming error rather than a client
		// one: no request shape produces it, so a 4xx would blame the caller for a
		// bug in this service. A 500 is investigated; a 400 is not.
		return Problem{http.StatusInternalServerError, "internal_error", "an internal error occurred", nil}
	}
}

func fieldDetails(field string) map[string]any {
	if field == "" {
		return nil
	}
	return map[string]any{"field": field}
}

// clientMessage renders a wrapped domain error as a sentence for a client.
//
// The domain writes messages like `fmt.Errorf("project: slug %q is already in use
// in this tenant: %w", slug, apperr.ErrConflict)`, which stringifies with the
// sentinel's own name appended. Stripping that suffix is what turns an internal
// phrasing into a client-facing one; without it, every API error ends in
// "…: conflict", which reads as a leak even though it is not one.
//
// The stripping is deliberate and bounded: it removes only the exact ": <sentinel>"
// suffixes this package owns, repeatedly, so a message that genuinely ends in the
// word "conflict" is untouched.
func clientMessage(err error, fallback string) string {
	msg := err.Error()

	// A domain error may wrap more than one level (a translated constraint error
	// wrapping a sentinel, for instance), so the pass repeats until stable. The
	// bound is finite to guarantee termination on a pathological message.
	for range 4 {
		changed := false
		for _, s := range append(sentinelsForTrim(), apperr.ErrUnauthorized) {
			text := s.Error()
			if msg == text {
				msg = ""
				changed = true
				continue
			}
			if suffix := ": " + text; strings.HasSuffix(msg, suffix) {
				msg = strings.TrimSuffix(msg, suffix)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	msg = strings.TrimSpace(msg)
	if msg == "" {
		return fallback
	}
	return msg
}

// sentinelsForTrim lists the sentinels whose text may appear as a suffix. It is
// sourced from apperr so the two cannot drift: a new sentinel is added there once.
func sentinelsForTrim() []error { return apperr.Sentinels() }

var _ = sentinelsForTrim
