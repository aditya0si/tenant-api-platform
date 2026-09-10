package apperr

import "errors"

// ClientError is a failure whose message is written for the API consumer: it
// names the field and says what is wrong with it.
//
// It exists as a distinct type because the two kinds of error want opposite
// treatment at the HTTP boundary. A validation failure is *about the request*, and
// its message is the most useful thing the client can be told — hiding it behind a
// generic "bad request" makes the API hostile to use. An internal failure is about
// *this service*, and its message may name a table, a driver, or a file path.
//
// Carrying the field separately means the response can include structured detail a
// client can map onto a form input, rather than only a sentence to display.
type ClientError struct {
	// Field names the request field the failure concerns, when there is one.
	Field string
	// Msg is the sentence shown to the client.
	Msg string
}

// Error implements error. It returns the client-facing sentence and nothing else:
// no package prefix, no sentinel suffix. The text a client receives is exactly the
// text that was written for it.
func (e *ClientError) Error() string { return e.Msg }

// Unwrap makes errors.Is(err, ErrValidation) true, so ordinary callers can treat a
// ClientError as the validation sentinel while the HTTP layer recovers the field
// and the clean message with errors.As.
func (e *ClientError) Unwrap() error { return ErrValidation }

// Invalid builds a validation error for the API consumer.
//
// Prefer this over fmt.Errorf("...: %w", ErrValidation) at any site whose message
// reaches a client. The wrapped form still matches the sentinel — so control flow
// is unaffected — but its text carries the sentinel's own name appended to it,
// which is noise in an API response.
func Invalid(field, msg string) error {
	return &ClientError{Field: field, Msg: msg}
}

// ClientSafe reports whether err's message may be sent to an API consumer.
//
// The list is explicit rather than derived, and that is the point: adding a
// sentinel means deciding whether its messages are written for a client or for an
// operator, and that decision should be made deliberately rather than inherited
// from whatever the error happens to be.
func ClientSafe(err error) bool {
	switch {
	case errors.Is(err, ErrNotFound),
		errors.Is(err, ErrValidation),
		errors.Is(err, ErrConflict),
		errors.Is(err, ErrVersionConflict),
		errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrForbidden):
		return true
	default:
		// ErrNoScope, ErrUnavailable, and anything unrecognised. ErrNoScope in
		// particular is a programming error: no request shape produces it, so its
		// message describes a bug in this service and must not be published.
		return false
	}
}
