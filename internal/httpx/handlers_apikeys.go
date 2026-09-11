package httpx

import (
	"net/http"
	"time"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// apiKeyResponse is one key on the wire.
//
// The secret is absent, and its absence is the shape of this API: the plaintext is returned once,
// by the creation call, and never again. A list that included it would put a live credential for
// every key into every response, every log line, and every support screenshot.
//
// The prefix is present instead — enough to match a row here against the value configured
// somewhere else, and not enough to be useful, which is the same bargain as a card's last four.
type apiKeyResponse struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Prefix    string   `json:"prefix"`
	Scopes    []string `json:"scopes"`
	CreatedBy string   `json:"created_by"`

	CreatedAt  string  `json:"created_at"`
	LastUsedAt *string `json:"last_used_at,omitempty"`
	ExpiresAt  *string `json:"expires_at,omitempty"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
}

func apiKeyFrom(k authn.APIKey) apiKeyResponse {
	scopes := make([]string, 0, len(k.Scopes))
	for _, s := range k.Scopes {
		scopes = append(scopes, string(s))
	}
	return apiKeyResponse{
		ID:         k.ID.String(),
		Name:       k.Name,
		Prefix:     k.Prefix,
		Scopes:     scopes,
		CreatedBy:  k.CreatedBy.String(),
		CreatedAt:  timestamp(k.CreatedAt),
		LastUsedAt: timestampPtr(k.LastUsedAt),
		ExpiresAt:  timestampPtr(k.ExpiresAt),
		RevokedAt:  timestampPtr(k.RevokedAt),
	}
}

// handleListAPIKeys returns the scoped tenant's keys, newest first.
//
// Not paginated, deliberately. A tenant holds a handful of keys, the response omits the one field
// that would make it large, and a cursor here would be ceremony a client implements for no
// benefit. The count is bounded in practice because apikey:manage may never be granted to a
// machine credential, so minting is a human action.
func (d Deps) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	keys, err := d.APIKeys.List(r.Context(), auth.Scope().ID(), auth.UserID())
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]apiKeyResponse, 0, len(keys))
	for _, k := range keys {
		items = append(items, apiKeyFrom(k))
	}
	httperr.OK(w, items)
}

// handleCreateAPIKey mints a key and returns its plaintext exactly once.
func (d Deps) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
		// ExpiresAt is optional: a deployment credential with no expiry is the ordinary case, and
		// requiring one would push operators toward a far-future date that is indistinguishable
		// from no expiry while looking deliberate.
		ExpiresAt *string `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	scopes := make([]authz.Perm, 0, len(req.Scopes))
	for _, s := range req.Scopes {
		scopes = append(scopes, authz.Perm(s))
	}

	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			httperr.Fail(w, r, d.Log, apperr.Invalid("expires_at", "must be an RFC 3339 timestamp"))
			return
		}
		expiresAt = &parsed
	}

	// Scopes are validated inside Mint against the permission model, including the set a machine
	// credential may never hold (authz.ValidateKeyScopes). Validating here as well would be a
	// second copy, and the copy that drifts is always the one that checks.
	minted, err := d.APIKeys.Mint(r.Context(), auth.Scope().ID(), auth.UserID(), req.Name, scopes, expiresAt)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	w.Header().Set("Location", "/v1/tenants/"+auth.Scope().ID().String()+"/api-keys/"+minted.ID.String())
	httperr.Created(w, struct {
		apiKeyResponse
		// The field name says it rather than relying on documentation the client may not read:
		// this is the only time the plaintext is returned.
		Secret string `json:"secret"`
	}{
		apiKeyResponse: apiKeyFrom(minted.APIKey),
		Secret:         minted.Secret,
	})
}

// handleRevokeAPIKey revokes a key.
//
// It answers 204 whether the key was live or already revoked, because the caller's intent — this
// credential must stop working — is satisfied either way. Distinguishing the cases would turn the
// endpoint into an enumeration oracle over key ids.
func (d Deps) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	keyID, err := parseUUID(chiURLParam(r, "keyID"))
	if err != nil {
		// A malformed id cannot name a real key, so it is reported as not-found rather than as a
		// bad request: collapsing the two keeps the response surface uniform, so nothing about
		// the format of ids can be learned from a status code.
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	// A key in another tenant is not-found rather than forbidden, for the same reason.
	if err := d.APIKeys.Revoke(r.Context(), auth.Scope().ID(), auth.UserID(), keyID); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.NoContent(w)
}
