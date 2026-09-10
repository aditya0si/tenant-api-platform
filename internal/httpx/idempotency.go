package httpx

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/aditya0si/tenant-api-platform/internal/idempotency"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// idempotentMethods are the methods the middleware protects.
//
// Safe methods are excluded because they have no effect to duplicate, and recording them
// would fill the table with replays of no consequence. The set is explicit rather than
// "anything that is not GET/HEAD/OPTIONS" so a future method is a deliberate decision
// instead of an accident.
var idempotentMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
	http.MethodPut:    true,
}

// Idempotency returns middleware implementing the idempotency-key protocol.
//
// # Where it must sit in the chain, and why the order is not cosmetic
//
//	ResolveTenant -> RequireAuthorized -> Require(perm) -> Idempotency -> handler
//
// Two of those orderings carry real weight:
//
//   - After RequireAuthorized, because a key is scoped to (tenant, key) and a request with
//     no resolved tenant has nowhere to record one. The middleware refuses rather than
//     skipping in that case, since a route registered outside the tenant group is a bug —
//     see the panic guard in authorizedFrom for the same reasoning.
//
//   - After Require(perm), because otherwise every 403 an attacker probes with would claim
//     a row, and idempotency_keys becomes attacker-writable storage. Authorization first
//     means an unauthorized request never touches the table. This is why writeGuard below
//     exists: it composes the two so the ordering cannot be got wrong at a call site.
//
// # When there is no key
//
// A request without the header runs unprotected. That is deliberate: idempotency is opt-in
// per request, and a client that wants it sends the header. A client that sends an empty
// value is rejected — sending the header at all is a request for protection, and silently
// providing none would be the worst outcome.
func Idempotency(store *idempotency.Store, log *slog.Logger) func(http.Handler) http.Handler {
	if log == nil {
		log = slog.Default()
	}

	// A nil store disables recording rather than panicking.
	//
	// The production wiring in httpx.New always supplies one; a test that builds Deps
	// directly may not. Returning the handler untouched keeps that case honest — no key is
	// claimed and nothing is recorded — where dereferencing nil would turn "this test does
	// not exercise idempotency" into a panic on every write.
	//
	// Logged once, here at construction, rather than per request: it is a statement about how
	// this router was assembled, not about any request that reaches it.
	if store == nil {
		log.Warn("idempotency middleware constructed without a store; unsafe requests will not be protected")
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !idempotentMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			// Distinguish "no header" from "present but blank".
			//
			// Header.Get reports "" in both cases, and treating them alike is a silent
			// correctness bug: a client that sends the header with a mistyped or empty value
			// believes it is protected, and the request would run unprotected without any
			// signal. Asking for the header's presence separately is what makes the blank
			// case a loud 400 instead.
			values := r.Header.Values(idempotency.Header)
			if len(values) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			key := strings.TrimSpace(values[0])
			if err := idempotency.ValidateKey(key); err != nil {
				// Validated here rather than left to the store, because the store's only
				// backstop is the CHECK constraint — and that surfaces as a 500 wrapping a
				// constraint violation, telling the client the server broke when the fault is
				// a malformed header. MaxKeyLength's own documentation promises a 400; this is
				// what makes that promise true.
				writeIdempotencyError(w, r, log, err)
				return
			}

			auth, ok := tenant.AuthorizedFrom(r.Context())
			if !ok {
				// A route registered outside the tenant-scoped group. The handler is not
				// wrong; the routing is, and saying so beats recording a key against no
				// tenant (which the schema's NOT NULL would then reject as a 500).
				log.Error("idempotency middleware reached without a resolved tenant",
					"path", r.URL.Path, "method", r.Method)
				httperr.Write(w, r, http.StatusInternalServerError, "internal_error", "an internal error occurred")
				return
			}

			// Read the body once. Both the fingerprint and the handler need it, and a
			// request body cannot be read twice — the second reader sees EOF. The read is
			// bounded by the same cap the decoder uses, so a client cannot make the server
			// buffer an unbounded payload before any handler has run.
			body, err := readBodyOnce(w, r)
			if err != nil {
				writeBodyError(w, r, log, err)
				return
			}

			fp := idempotency.Fingerprint(r.Method, routePattern(r), r.URL.RawQuery, body)

			res, err := store.Begin(r.Context(), auth, key, fp)
			if err != nil {
				writeIdempotencyError(w, r, log, err)
				return
			}

			if res.Outcome == idempotency.OutcomeReplay {
				writeReplay(w, res.Record)
				return
			}

			// We own the key. Run the handler with a capturing writer so the response can
			// be recorded for the next attempt.
			capture := idempotency.NewCapture(w)
			next.ServeHTTP(capture, r)

			// Complete runs inline, after the handler returned, and NOT via defer.
			//
			// This is the sharpest ordering detail in the middleware. A defer would also
			// run while a panic unwinds — and chi's Recoverer sits outside this middleware,
			// so it writes its 500 *after* the deferred call has already recorded whatever
			// the handler managed to write. With a deferred Complete, a handler that panicked
			// before writing anything would be recorded as a 200 with an empty body, and the
			// next retry would be handed that fabricated success.
			//
			// Running inline means a panic skips the recording entirely: the key stays
			// in_progress and is released by the lease. That is self-healing, and it is the
			// correct trade — the alternative invents a response.
			if err := store.Complete(r.Context(), auth, key, capture.Captured()); err != nil {
				// The response has already been written to the client, so this cannot
				// change what they see. The key stays in_progress and the next retry gets
				// 409 until the lease expires, which is self-healing. Logged at warn
				// because a burst of these means the lease is too short for a real
				// handler's latency, and that is worth knowing before it becomes an
				// incident.
				log.Warn("failed to record an idempotency response; a retry will be told the request is in progress until the lease expires",
					"err", err, "path", r.URL.Path, "method", r.Method)
			}
		})
	}
}

// writeGuard composes RBAC and idempotency in the one order that is safe.
//
// The two are easy to attach in the wrong order and the mistake is invisible: idempotency
// first still produces correct-looking behaviour, while quietly letting an unauthorized
// caller claim rows. Composing them here means a call site cannot express the wrong order,
// which is the same argument that put the permission check on a route group rather than in
// each handler.
func writeGuard(perm string, store *idempotency.Store, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return requirePerm(perm)(Idempotency(store, log)(next))
	}
}

// readBodyOnce reads the request body and restores it for the handler.
//
// A request body is a stream: reading it for the fingerprint leaves nothing for the
// handler, which would then decode an empty document and fail validation. Restoring the
// reader — with the original length, so any code that consults ContentLength is not misled —
// is what makes hashing the body compatible with processing it.
//
// The read is bounded. Without a cap, a client could make the server buffer an unbounded
// payload in memory before any handler ran, which is a denial of service that costs the
// attacker nothing. The cap is render.go's maxBodyBytes, so the middleware and the JSON
// decoder agree on what "too large" means; two different limits would make the boundary
// depend on whether a request carried an idempotency key.
func readBodyOnce(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	limited := io.LimitReader(r.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, errBodyUnreadable
	}
	if len(body) > maxBodyBytes {
		return nil, errBodyTooLarge
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return body, nil
}

// Body read failures, kept distinct so writeBodyError can map them to the right status.
//
// They are sentinels rather than apperr values because the HTTP layer, not the domain, owns
// the status code here: an oversized body is a property of the transport, and no handler has
// run yet to have an opinion about it.
var (
	errBodyUnreadable = errors.New("the request body could not be read")
	errBodyTooLarge   = errors.New("the request body exceeds the maximum size")
)

// writeBodyError maps a body-read failure onto a response.
//
// Oversize is 413, not 500. Falling through to the generic handler would answer 500, which
// tells the client the server broke — and a well-behaved client retries a 500, forever, with
// a body that can never succeed. 413 is terminal and says which side has to change.
func writeBodyError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, errBodyTooLarge):
		httperr.Write(w, r, http.StatusRequestEntityTooLarge, "payload_too_large",
			"the request body exceeds the maximum size")
	case errors.Is(err, errBodyUnreadable):
		// A body that cannot be read means the connection failed mid-send. That is the
		// client's transport, not our logic, so it is a 400 rather than a 500.
		httperr.Write(w, r, http.StatusBadRequest, "invalid_request",
			"the request body could not be read")
	default:
		httperr.Fail(w, r, log, err)
	}
}

// routePattern returns chi's matched route pattern, falling back to the raw path.
//
// The pattern rather than the path, because the fingerprint must be stable across
// resources: a retry of PATCH /projects/{a} must match the original even though the path
// string differs from PATCH /projects/{b}. Using the raw path would make a client's
// idempotency key fail to protect exactly the requests that most need it.
//
// The fallback covers a request that matched no route, where the pattern is empty.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if pattern := rc.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	return r.URL.Path
}

// writeReplay returns a recorded response without running the handler.
//
// # The header whitelist is a security boundary, not tidiness
//
// Only the headers stored at completion time are set — Content-Type, Location, and ETag.
// That is what stops a replayed Set-Cookie from handing one client another's session, and
// it also stops the original request's X-Request-Id from being replayed as though it
// identified the current one. The whitelist lives in the idempotency package; this function
// must not add to it.
//
// Idempotent-Replay is set here rather than stored, because it describes *this* response —
// it is false on the original — and recording it would be recording a lie.
func writeReplay(w http.ResponseWriter, rec idempotency.Record) {
	for name, values := range rec.Headers {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.Header().Set("Idempotent-Replay", "true")

	status := rec.StatusCode
	if status == 0 {
		// Unreachable for a completed record, whose status is NOT NULL by CHECK. A zero
		// here would panic WriteHeader, so it is guarded rather than trusted.
		status = http.StatusOK
	}
	w.WriteHeader(status)

	if len(rec.Body) > 0 {
		_, _ = w.Write(rec.Body)
	}
}

// writeIdempotencyError maps the protocol's errors onto responses.
//
// Each outcome needs a different client action, which is why they are distinguished rather
// than collapsed into one error: 409 means "wait, your original is still running", 422 means
// "you reused a key for a different request, which is a bug in your code", and the
// not-replayable case means "your original succeeded but cannot be replayed; use a new key".
func writeIdempotencyError(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	switch {
	case errors.Is(err, idempotency.ErrKeyBlank) || errors.Is(err, idempotency.ErrKeyTooLong):
		// 400, because the request is malformed rather than conflicting: no handler ran and
		// no key was claimed, so retrying the same request unchanged would fail identically.
		httperr.Write(w, r, http.StatusBadRequest, "invalid_idempotency_key", err.Error())

	case errors.Is(err, idempotency.ErrInProgress):
		// Retry-After tells an automated client how long to wait instead of guessing, and
		// the value is the lease — the longest it could take for the claim to be released
		// if the holder died.
		w.Header().Set("Retry-After", "1")
		httperr.Write(w, r, http.StatusConflict, "request_in_progress",
			"an identical request with this idempotency key is already in progress; retry shortly")

	case errors.Is(err, idempotency.ErrFingerprintMismatch):
		httperr.Write(w, r, http.StatusUnprocessableEntity, "idempotency_key_reused",
			"this idempotency key was already used for a different request; use a new key")

	case errors.Is(err, idempotency.ErrNotReplayable):
		httperr.Write(w, r, http.StatusConflict, "idempotent_response_not_replayable",
			"the original request with this key succeeded, but its response was too large to replay; use a new key")

	default:
		httperr.Fail(w, r, log, err)
	}
}
