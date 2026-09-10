package httperr

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// Envelope is the single error shape for the whole API.
//
// The content type is application/json, not application/problem+json. This
// payload is a custom envelope ({"error": {...}}) and does not implement RFC
// 9457: it has no type/title/instance members, and the code field is a stable
// machine-readable string rather than a URI. Advertising problem+json while
// sending a different shape misleads generated clients and any middleware that
// sniffs the type — so the honest header is the plain one. If RFC 9457 is wanted
// later, it is a deliberate migration of this envelope, not a header swap.
type Envelope struct {
	Error ErrorBody `json:"error"`
}

// ErrorBody is the machine-readable error payload.
//
// Message is safe to show a client. Internal causes stay in the logs, correlated
// by request_id, so nothing about schema, driver, or filesystem layout leaks.
type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Write sends a JSON error envelope.
func Write(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeEnvelope(w, r, status, ErrorBody{Code: code, Message: msg})
}

// WriteDetails is Write with machine-readable details (validation failures, etc).
func WriteDetails(w http.ResponseWriter, r *http.Request, status int, code, msg string, details map[string]any) {
	writeEnvelope(w, r, status, ErrorBody{Code: code, Message: msg, Details: details})
}

func writeEnvelope(w http.ResponseWriter, r *http.Request, status int, body ErrorBody) {
	body.RequestID = middleware.GetReqID(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Error: body})
}
