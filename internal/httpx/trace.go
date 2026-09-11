package httpx

import (
	"net/http"

	"github.com/aditya0si/tenant-api-platform/internal/platform/reqid"
)

// traceContext propagates the caller's W3C trace context.
//
// It reads the `traceparent` header, validates it, and puts it on the context so an outbox row
// can carry it. That is all it does: there is no span being started here and no exporter — the
// header is passed through because a webhook delivery is the one outbound request this service
// makes, and correlating it with the inbound request that caused it is the difference between
// "the receiver says they got nothing" being answerable and not.
//
// The value is validated by reqid before it is stored, and a malformed one is dropped rather
// than repaired. Repairing it would mean guessing where the fields end, and the guess would be
// stored in the outbox and sent to a tenant's receiver — so anything unrecognised becomes
// "no trace context", which the column is nullable for.
//
// Deliberately not middleware.TraceContext or an OTel bridge: neither exists here yet, and a
// header passed through is a smaller claim than a span that was never exported.
func traceContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tp := r.Header.Get("traceparent"); tp != "" {
			r = r.WithContext(reqid.WithTraceparent(r.Context(), tp))
		}
		next.ServeHTTP(w, r)
	})
}
