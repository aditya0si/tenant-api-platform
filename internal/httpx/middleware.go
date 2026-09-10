// Package httpx is the HTTP surface: routing, request decoding, tenant resolution,
// and the translation from domain errors to responses.
//
// It is deliberately the only package that knows about HTTP. The domain packages
// return sentinel errors and take explicit arguments, which is what lets their
// behaviour be tested without a router — and what stops a transport concern from
// leaking into a business rule.
package httpx

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
)

// instrument records request count and latency per route pattern.
//
// It labels on chi's route pattern rather than the raw path, which is the
// difference between a usable metric and a cardinality explosion: a raw path
// carries ids, so every project would mint its own time series and the number of
// series would grow with the data.
func instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			// No route matched: a 404 for an unknown path. Labelling on the raw
			// path here would let a scanner mint unlimited time series, so these
			// are collapsed into one bucket.
			route = "unmatched"
		}
		metrics.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(ww.Status())).Inc()
		metrics.HTTPDuration.WithLabelValues(route).Observe(time.Since(start).Seconds())
	})
}

// requestIDHeader is the response header carrying the request id.
const requestIDHeader = "X-Request-Id"

// requestIDResponseHeader copies the request id into the response.
//
// chi's RequestID middleware puts the id in the request context but deliberately sets
// no response header, and that omission matters more than it sounds: without it, a
// client's only route to the id is parsing the error body, which a log line, a curl
// -i, or a tracing proxy never does. With it, the id a user quotes in a bug report is
// the id in the logs, by construction.
//
// It must be registered after middleware.RequestID, which is what puts the value in
// the context this reads.
func requestIDResponseHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := middleware.GetReqID(r.Context()); id != "" {
			w.Header().Set(requestIDHeader, id)
		}
		next.ServeHTTP(w, r)
	})
}
