package httperr

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// dataEnvelope wraps every success payload.
//
// Bodies are always a JSON object, never a bare array, so a field can be added
// later without breaking a client that already parses the response. It is the same
// reasoning that makes the error envelope an object; having one shape for success
// and a different one for failure is how APIs end up with two parsing paths.
type dataEnvelope struct {
	Data any `json:"data"`
}

// pageEnvelope is a listing: the page, plus the cursor for the next one.
//
// NextCursor is omitted rather than sent as an empty string when the page is the
// last, so a client can test for its presence instead of comparing against "" —
// and so a cursor that is legitimately empty is not ambiguous.
type pageEnvelope struct {
	Data       any    `json:"data"`
	NextCursor string `json:"next_cursor,omitempty"`
}

// JSON writes a success payload.
func JSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dataEnvelope{Data: payload})
}

// OK writes a 200 with a payload.
func OK(w http.ResponseWriter, payload any) { JSON(w, http.StatusOK, payload) }

// Created writes a 201 with a payload.
//
// The resource's own URL belongs in a Location header, but it is not set here
// because this helper does not know the resource's canonical path — the handler
// does, and a wrong Location is worse than none. Handlers that set it do so
// explicitly before calling this.
func Created(w http.ResponseWriter, payload any) { JSON(w, http.StatusCreated, payload) }

// Page writes a 200 listing with an optional next cursor.
func Page(w http.ResponseWriter, items any, nextCursor string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(pageEnvelope{Data: items, NextCursor: nextCursor})
}

// NoContent writes a 204. The body is empty by definition, so the Content-Type
// header is deliberately not set: a content type on a response with no content is
// a contradiction some clients handle by waiting for a body that never arrives.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Fail writes the response for a domain error, logging it when it is not
// client-safe.
//
// Every handler ends an error path with this single call, so the decision about
// whether a message reaches the client is made once, in Map, rather than at each of
// the dozens of places an error can originate. A handler that reaches for Write
// directly is the one that leaks a driver error.
//
// The log line carries the request id rather than the error alone, because the
// client is told exactly that id in the response body — that pairing is what makes
// a user-reported failure findable in the logs.
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	p := Map(err)
	if !apperr.ClientSafe(err) {
		if log == nil {
			log = slog.Default()
		}
		log.Error("request failed",
			"err", err,
			"status", p.Status,
			"code", p.Code,
			"method", r.Method,
			"path", r.URL.Path,
			"request_id", middleware.GetReqID(r.Context()),
		)
	}
	WriteDetails(w, r, p.Status, p.Code, p.Message, p.Details)
}
