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

	"github.com/go-chi/chi/v5/middleware"
)

// From returns the request id for ctx, or "" when there is none.
func From(ctx context.Context) string {
	return middleware.GetReqID(ctx)
}
