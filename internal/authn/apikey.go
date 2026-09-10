package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

const (
	// apiKeyPrefixLen is how many characters after the "ak_" marker are kept in
	// clear text. It is enough to tell two keys apart in a list and not enough to
	// be useful, which is the same bargain as a credit-card last-four.
	apiKeyPrefixLen = 8

	// maxAPIKeyNameLen mirrors the CHECK constraint on api_keys.name.
	maxAPIKeyNameLen = 100
)

// APIKey errors.
var (
	ErrAPIKeyUnknown = errors.New("authn: api key not recognised")
	ErrAPIKeyRevoked = errors.New("authn: api key revoked")
	ErrAPIKeyExpired = errors.New("authn: api key expired")
)

// APIKey is a tenant-scoped machine credential.
//
// It is deliberately not a user. A key cannot hold roles, manage members, or mint
// further keys, because those are actions a *person* takes and attributes to
// themselves; a key that could promote its own tenant would make the audit log
// much less useful. What a key holds instead is an explicit permission list,
// which can be narrower than any human role.
type APIKey struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	CreatedBy  uuid.UUID
	Name       string
	Prefix     string
	Scopes     []authz.Perm
	CreatedAt  time.Time
	LastUsedAt *time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
}

// MintedAPIKey carries the plaintext secret, which exists only in the response to
// the creation call. Nothing stores it, so a lost key is replaced rather than
// recovered — and the absence of a "show key again" endpoint is a deliberate
// absence, not an oversight.
type MintedAPIKey struct {
	APIKey
	// Secret is the plaintext credential, shown exactly once.
	Secret string
}

// APIKeyStore owns API-key persistence and verification.
type APIKeyStore struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewAPIKeyStore builds a store.
func NewAPIKeyStore(pool *pgxpool.Pool) *APIKeyStore {
	return &APIKeyStore{pool: pool, now: time.Now}
}

// Mint creates a key for a tenant.
//
// scopes is validated against the permission model, so a typo produces a 400 at
// creation rather than a key that silently authorizes nothing (or, worse, one
// that appears to work until a check fails in production).
func (s *APIKeyStore) Mint(
	ctx context.Context,
	tenantID, createdBy uuid.UUID,
	name string,
	scopes []authz.Perm,
	expiresAt *time.Time,
) (MintedAPIKey, error) {
	if tenantID == uuid.Nil || createdBy == uuid.Nil {
		return MintedAPIKey{}, apperr.ErrNoScope
	}
	if name == "" || len(name) > maxAPIKeyNameLen {
		return MintedAPIKey{}, fmt.Errorf("authn: key name must be 1..%d characters: %w", maxAPIKeyNameLen, apperr.ErrValidation)
	}
	if err := authz.ValidateKeyScopes(scopes); err != nil {
		// The rule lives in authz, next to the permission model it constrains.
		// Keeping a second copy here would mean two places to update when a
		// permission is added, and the copy that drifts is always the one that
		// checks.
		return MintedAPIKey{}, fmt.Errorf("authn: %w: %v", apperr.ErrValidation, err)
	}
	if expiresAt != nil && !expiresAt.After(s.now()) {
		return MintedAPIKey{}, fmt.Errorf("authn: key expiry must be in the future: %w", apperr.ErrValidation)
	}

	secret, prefix, hash, err := newAPIKeySecret()
	if err != nil {
		return MintedAPIKey{}, err
	}

	key := APIKey{
		ID:        uuid.Must(uuid.NewV7()),
		TenantID:  tenantID,
		CreatedBy: createdBy,
		Name:      name,
		Prefix:    prefix,
		Scopes:    scopes,
		CreatedAt: s.now(),
		ExpiresAt: expiresAt,
	}

	scopeStrings := make([]string, 0, len(scopes))
	for _, p := range scopes {
		scopeStrings = append(scopeStrings, string(p))
	}

	err = db.WithIdentityTx(ctx, s.pool, db.Identity{TenantID: tenantID, UserID: createdBy}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO api_keys (id, tenant_id, created_by, name, prefix, key_hash, scopes, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			key.ID, tenantID, createdBy, name, prefix, hash, scopeStrings, expiresAt)
		if err != nil {
			if db.IsUniqueViolation(err) {
				// A hash collision is not a realistic event; this is here so the
				// error is a conflict rather than a 500 if it ever happens.
				return fmt.Errorf("insert api key: %w", apperr.ErrConflict)
			}
			return fmt.Errorf("insert api key: %w", err)
		}
		return nil
	})
	if err != nil {
		return MintedAPIKey{}, err
	}
	return MintedAPIKey{APIKey: key, Secret: secret}, nil
}

// Authenticate resolves a presented key to its tenant and scope.
//
// This is a pre-tenant operation: the key itself is what identifies the tenant,
// so there is no tenant to set. The request carries the key's hash, and the
// policy's hash arm (migration 0002) admits exactly the one matching row — an
// unauthenticated `SELECT * FROM api_keys` still returns nothing.
//
// Revoked and expired keys are rejected explicitly rather than filtered out of
// the query, so the caller can distinguish "no such key" from "this key was
// revoked" for logging. Both produce the same 401 for the client.
func (s *APIKeyStore) Authenticate(ctx context.Context, presented string) (APIKey, error) {
	if presented == "" {
		return APIKey{}, ErrAPIKeyUnknown
	}

	hash := HashAPIKey(presented)

	var (
		key     APIKey
		scopes  []string
		outcome error
	)
	err := db.WithPresentedSecret(ctx, s.pool, db.SettingAPIKeyHash, hash, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT id, tenant_id, created_by, name, prefix, scopes,
			       created_at, last_used_at, expires_at, revoked_at
			FROM api_keys
			WHERE key_hash = $1`, hash).
			Scan(&key.ID, &key.TenantID, &key.CreatedBy, &key.Name, &key.Prefix, &scopes,
				&key.CreatedAt, &key.LastUsedAt, &key.ExpiresAt, &key.RevokedAt)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = ErrAPIKeyUnknown
			return nil
		case err != nil:
			return fmt.Errorf("look up api key: %w", err)
		}

		if key.RevokedAt != nil {
			outcome = ErrAPIKeyRevoked
			return nil
		}
		if key.ExpiresAt != nil && !key.ExpiresAt.After(s.now()) {
			outcome = ErrAPIKeyExpired
			return nil
		}

		// last_used_at is best-effort telemetry for "which keys are actually in
		// use, so which can be retired". The UPDATE ... RETURNING writes it and
		// reads the stored value back in one statement, so the returned key
		// reflects what the database actually recorded rather than what this
		// process intended — and a silent failure to record usage would be visible
		// here instead of presenting as a key that looks permanently unused.
		//
		// It is written inside the lookup transaction, which means an attempt that
		// is recorded and then fails a later authorization check still counts. That
		// is the behaviour an audit trail wants.
		var touched time.Time
		if err := tx.QueryRow(ctx,
			`UPDATE api_keys SET last_used_at = now() WHERE id = $1 RETURNING last_used_at`,
			key.ID).Scan(&touched); err != nil {
			return fmt.Errorf("touch api key: %w", err)
		}
		key.LastUsedAt = &touched

		key.Scopes = make([]authz.Perm, 0, len(scopes))
		for _, sc := range scopes {
			key.Scopes = append(key.Scopes, authz.Perm(sc))
		}
		return nil
	})
	if err != nil {
		return APIKey{}, err
	}
	if outcome != nil {
		return APIKey{}, outcome
	}
	return key, nil
}

// List returns a tenant's keys without their secrets.
//
// last_used_at is included because it is the field that makes this list
// actionable: an unused key is a candidate for revocation, and a list that omits
// it invites the opposite question ("can I delete this?") with no way to answer.
func (s *APIKeyStore) List(ctx context.Context, tenantID, actorID uuid.UUID) ([]APIKey, error) {
	if tenantID == uuid.Nil {
		return nil, apperr.ErrNoScope
	}

	var out []APIKey
	err := db.WithIdentityTx(ctx, s.pool, db.Identity{TenantID: tenantID, UserID: actorID}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, created_by, name, prefix, scopes,
			       created_at, last_used_at, expires_at, revoked_at
			FROM api_keys
			WHERE tenant_id = $1
			ORDER BY created_at DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				k      APIKey
				scopes []string
			)
			if err := rows.Scan(&k.ID, &k.TenantID, &k.CreatedBy, &k.Name, &k.Prefix, &scopes,
				&k.CreatedAt, &k.LastUsedAt, &k.ExpiresAt, &k.RevokedAt); err != nil {
				return err
			}
			k.Scopes = make([]authz.Perm, 0, len(scopes))
			for _, sc := range scopes {
				k.Scopes = append(k.Scopes, authz.Perm(sc))
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	return out, nil
}

// Revoke revokes a key. Revoking an already-revoked key is a no-op rather than an
// error, so a retried request behaves the same as the one it retried.
func (s *APIKeyStore) Revoke(ctx context.Context, tenantID, actorID, keyID uuid.UUID) error {
	if tenantID == uuid.Nil || keyID == uuid.Nil {
		return apperr.ErrNoScope
	}

	return db.WithIdentityTx(ctx, s.pool, db.Identity{TenantID: tenantID, UserID: actorID}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE api_keys
			   SET revoked_at = now()
			 WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, keyID, tenantID)
		if err != nil {
			return fmt.Errorf("revoke api key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// Nothing was updated: either the row is not visible in this tenant, or
			// it was already revoked. The two must be distinguished, because a retry
			// must be idempotent while a cross-tenant probe must not be — another
			// tenant's key ids have to look exactly like unknown ones.
			//
			// Note what this lookup does not do: it never reports "forbidden". A
			// distinct error for a foreign key id would confirm that the id exists,
			// turning the endpoint into an enumeration oracle.
			var revokedAt *time.Time
			err := tx.QueryRow(ctx,
				`SELECT revoked_at FROM api_keys WHERE id = $1 AND tenant_id = $2`,
				keyID, tenantID).Scan(&revokedAt)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				return fmt.Errorf("revoke api key: %w", apperr.ErrNotFound)
			case err != nil:
				return fmt.Errorf("check revocation state: %w", err)
			case revokedAt != nil:
				return nil // already revoked, so the caller's intent is satisfied
			default:
				// Unreachable in practice: a live row in this tenant would have been
				// updated above. Kept explicit rather than returning nil so that a
				// future change to the UPDATE's predicate cannot silently turn this
				// path into a success.
				return fmt.Errorf("revoke api key: %w", apperr.ErrNotFound)
			}
		}
		return nil
	})
}

// newAPIKeySecret returns a fresh key, its display prefix, and its storage hash.
//
// Shape: ak_<8-char prefix><43 chars of secret>. The prefix is stored in clear
// text so a key can be identified later without being usable; the identifier is
// the whole string, and only its SHA-256 is persisted.
func newAPIKeySecret() (secret, prefix, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", fmt.Errorf("authn: read random bytes: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	prefix = encoded[:apiKeyPrefixLen]
	secret = "ak_" + encoded
	return secret, prefix, HashAPIKey(secret), nil
}

// HashAPIKey returns the hex SHA-256 of an API key.
//
// As with refresh tokens, the input is 256 bits of CSPRNG output, so a fast hash
// is correct: there is no dictionary to attack and a slow KDF would only add
// latency to every authenticated request.
func HashAPIKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", sum)
}
