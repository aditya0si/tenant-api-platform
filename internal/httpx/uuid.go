package httpx

import (
	"github.com/google/uuid"
)

// uuidValue is a thin alias so render.go can name the type without importing
// uuid at every call site.
type uuidValue = uuid.UUID

// parseUUID is a convenience wrapper that keeps the not-found mapping in one place.
func parseUUID(raw string) (uuid.UUID, error) {
	return uuid.Parse(raw)
}
