package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// maxBodyBytes bounds every request body.
//
// Without a limit, a client can make the service allocate until it is killed, which
// is a denial of service that costs the attacker nothing. 1 MiB is far above any
// legitimate payload this API accepts and far below the point where decoding one
// body is a problem.
const maxBodyBytes = 1 << 20

// decodeJSON reads a request body into dst.
//
// Two decisions worth stating:
//
//   - Unknown fields are rejected. A typo in a field name is then a 400 naming the
//     field, rather than a request that silently does nothing — and "silently did
//     nothing" is the failure mode that costs an integrator an afternoon. The cost
//     is that adding a field on the client before the server is a breaking change,
//     which for this API's consumers is the right trade.
//   - The error message is written for the client, because the client is who has to
//     fix it. It states the offset rather than echoing the body: the body may
//     contain a password.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var (
			syntaxErr *json.SyntaxError
			typeErr   *json.UnmarshalTypeError
			maxErr    *http.MaxBytesError
		)
		switch {
		case errors.Is(err, io.EOF):
			return apperr.Invalid("body", "a JSON body is required")
		case errors.As(err, &maxErr):
			return apperr.Invalid("body", fmt.Sprintf("the request body exceeds %d bytes", maxBodyBytes))
		case errors.As(err, &syntaxErr):
			return apperr.Invalid("body", fmt.Sprintf("the body is not valid JSON (at byte %d)", syntaxErr.Offset))
		case errors.As(err, &typeErr):
			field := typeErr.Field
			if field == "" {
				field = "body"
			}
			return apperr.Invalid(field, fmt.Sprintf("expected a %s", typeErr.Type))
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return apperr.Invalid(field, "unknown field")
		default:
			return apperr.Invalid("body", "the body could not be decoded")
		}
	}

	// A second value in the stream means the client sent something the decoder
	// ignored — two concatenated objects, typically. Accepting that silently would
	// mean acting on the first and discarding the rest without saying so.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apperr.Invalid("body", "the body must contain exactly one JSON object")
	}
	return nil
}

// pageParams extracts the pagination parameters of a list request.
//
// A malformed limit or cursor is a client error rather than something to coerce:
// silently treating "limit=abc" as the default would return a page the client did
// not ask for, and a client that cannot tell its parameter was ignored will not fix
// it.
func pageParams(r *http.Request) (limit int, cursorToken string, err error) {
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil {
			return 0, "", apperr.Invalid("limit", "must be an integer")
		}
		limit = n
	}
	return limit, r.URL.Query().Get("cursor"), nil
}

// boolParam reads a boolean query parameter, defaulting to false.
func boolParam(r *http.Request, name string) (bool, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return false, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, apperr.Invalid(name, "must be true or false")
	}
	return v, nil
}

// pathUUID parses a UUID path parameter.
//
// A malformed id is reported as not-found rather than as a bad request. The two
// are indistinguishable to a caller either way — a string that is not a UUID cannot
// name a real resource — and collapsing them keeps the response surface uniform, so
// nothing about the format of ids on this service can be learned from error codes.
func pathUUID(r *http.Request, name string) (uuidValue, error) {
	raw := chi.URLParam(r, name)
	id, err := parseUUID(raw)
	if err != nil {
		return uuidValue{}, apperr.ErrNotFound
	}
	return id, nil
}
