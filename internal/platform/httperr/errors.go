package httperr

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

// Envelope is the single error shape for the whole API.
type Envelope struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	RequestID string         `json:"request_id,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

// Write sends a JSON error envelope. Message is safe for clients;
// internal detail stays in logs.
func Write(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Error: ErrorBody{
		Code:      code,
		Message:   msg,
		RequestID: middleware.GetReqID(r.Context()),
	}})
}

// WriteDetails is Write with machine-readable details (validation, etc).
func WriteDetails(w http.ResponseWriter, r *http.Request, status int, code, msg string, details map[string]any) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Envelope{Error: ErrorBody{
		Code:      code,
		Message:   msg,
		RequestID: middleware.GetReqID(r.Context()),
		Details:   details,
	}})
}
