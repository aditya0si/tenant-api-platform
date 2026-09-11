// Package reqid reads the per-request identifier from a context.
//
// It exists so that domain packages can attach a request id to what they record without
// importing the router library. The value is set by chi's RequestID middleware, and reading
// it through one small adapter keeps "the HTTP layer chose chi" out of packages that have no
// other reason to know about HTTP at all — the same reason the membership gate is an adapter
// in main rather than an import in authn.
//
// An absent id yields the empty string rather than an error: a background worker recording an
// audit entry has no request, and that is a legitimate state rather than a failure.
package reqid

import (
	"context"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// From returns the request id for ctx, or "" when there is none.
func From(ctx context.Context) string {
	return middleware.GetReqID(ctx)
}

// traceparentKey is the context key for a propagated W3C trace context.
type traceparentKey struct{}

// WithTraceparent attaches a validated trace context to ctx.
//
// Validation happens before storage rather than at read time, so a value that got this far has
// already been shown to be well-formed: the header is caller-supplied, and it is written into the
// outbox and sent to a tenant's receiver. Storing arbitrary attacker-controlled text and sorting
// it out later is how a trace field becomes an injection vector.
func WithTraceparent(ctx context.Context, tp string) context.Context {
	if !ValidTraceparent(tp) {
		return ctx
	}
	return context.WithValue(ctx, traceparentKey{}, tp)
}

// TraceparentFrom returns the propagated trace context, or "" when there is none.
//
// An empty return is the honest answer for a request that carried no traceparent — including one
// that carried a malformed one, which is dropped rather than repaired. A background process
// enqueuing an event has no inbound trace either, and inventing a value there would make the
// outbox claim a correlation that does not exist.
func TraceparentFrom(ctx context.Context) string {
	tp, _ := ctx.Value(traceparentKey{}).(string)
	return tp
}

// ValidTraceparent reports whether tp is a well-formed W3C trace context.
//
// The format is `version-traceid-spanid-flags`:
//
//	00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//
// All lowercase hex, version 2 characters, trace id 32, span id 16, flags 2. Version ff is
// reserved and rejected. A trailing section for vendor-specific data is permitted by the spec
// when the version is not 00, so it is accepted rather than treated as corruption.
//
// The check is deliberately strict about length and alphabet: a receiver parsing this value is
// entitled to assume the shape, and "close enough" here means a downstream parser disagrees with
// this one about where the fields end.
func ValidTraceparent(tp string) bool {
	if tp == "" || len(tp) < 55 {
		return false
	}
	parts := strings.Split(tp, "-")
	if len(parts) < 4 {
		return false
	}

	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || !isLowerHex(version) {
		return false
	}
	// ff is reserved by the spec and must be rejected rather than accepted as a version.
	if version == "ff" {
		return false
	}
	if len(traceID) != 32 || !isLowerHex(traceID) {
		return false
	}
	if len(spanID) != 16 || !isLowerHex(spanID) {
		return false
	}
	if len(flags) != 2 || !isLowerHex(flags) {
		return false
	}
	// An all-zero trace or span id is invalid: it is the value the spec reserves to mean
	// "absent", and propagating it would make two unrelated requests look correlated.
	if strings.Trim(traceID, "0") == "" || strings.Trim(spanID, "0") == "" {
		return false
	}
	return true
}

// isLowerHex reports whether s is non-empty and drawn only from [0-9a-f].
func isLowerHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
