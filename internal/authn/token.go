// Package authn — access tokens.
//
// # Why HS256 and not RS256
//
// A symmetric signature requires every verifier to hold the signing key, which is
// a real limitation — but only in a system with independent verifiers. Here there
// is exactly one: this service. RS256 would add key management (generation,
// rotation, a JWKS endpoint, a second failure mode when the key is fetched)
// while buying nothing, because the only party that verifies is the only party
// that signs.
//
// When a second service needs to verify tokens without the ability to mint them,
// this is the decision to revisit — and the migration is mechanical (publish a
// JWKS endpoint, keep HS256 verification during the overlap). Writing that down
// is the point: the choice is reasoned, not accidental.
package authn

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	// DefaultIssuer and DefaultAudience are asserted on every parse. They stop a
	// token minted for one environment or one audience from being accepted by
	// another — a class of bug that is invisible until two systems share a
	// secret.
	DefaultIssuer   = "tenant-api-platform"
	DefaultAudience = "tenant-api-platform"

	// DefaultAccessTTL is deliberately short.
	//
	// The access token carries identity only (no tenant, no roles — see below),
	// so its lifetime bounds exactly one thing: how long a *stolen* token stays
	// usable. Revocation of a session is handled by the refresh family, which
	// cannot revoke a token already signed, so the only lever on a leaked access
	// token is keeping it short.
	DefaultAccessTTL = 10 * time.Minute

	// DefaultLeeway absorbs clock skew between the minting and verifying clock.
	// Without it, a token minted at the far edge of a skewed clock is rejected as
	// "not valid yet", which presents as an intermittent 401 that is very hard to
	// attribute. 30s is small enough to be immaterial to security.
	DefaultLeeway = 30 * time.Second
)

// ErrTokenInvalid is returned for every rejected token.
//
// Deliberately one error, not one per cause (expired, bad signature, wrong
// audience). The client can act on none of the distinctions, and returning them
// tells an attacker which part of a forged token to fix. The cause is logged.
var ErrTokenInvalid = errors.New("authn: invalid access token")

// AccessClaims is the verified content of an access token.
//
// # What is deliberately absent
//
// There is no tenant, no role, and no permission list. An authorization decision
// cached inside a credential outlives the authorization: if a role travelled in
// the token, removing someone from a tenant would not take effect until the token
// expired, and the "revoke" operation would be a lie for up to ten minutes.
//
// So the token asserts *who*, and nothing else. Every request resolves what they
// may do from the memberships table, which means a revoked membership is enforced
// on the next request rather than the next login. The cost is one indexed lookup
// per request, which the membership gate performs anyway.
type AccessClaims struct {
	UserID    uuid.UUID
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// TokenIssuer mints and verifies access tokens.
type TokenIssuer struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
	leeway   time.Duration

	// now is injectable so tests can mint a token in the past or the future
	// without sleeping. Never nil after NewTokenIssuer.
	now func() time.Time
}

// NewTokenIssuer builds an issuer. secret must be at least 32 bytes: HMAC-SHA256
// accepts any key length, so a short secret fails silently and produces tokens
// that are trivially forgeable rather than tokens that do not work.
func NewTokenIssuer(secret []byte, issuer, audience string, ttl time.Duration) (*TokenIssuer, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("authn: signing secret must be at least 32 bytes, got %d", len(secret))
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("authn: access token TTL must be positive, got %s", ttl)
	}
	if issuer == "" || audience == "" {
		return nil, errors.New("authn: issuer and audience must be set")
	}
	return &TokenIssuer{
		secret:   secret,
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		leeway:   DefaultLeeway,
		now:      time.Now,
	}, nil
}

// SetLeeway overrides the clock-skew allowance. Tests use it; production leaves
// the default.
func (i *TokenIssuer) SetLeeway(d time.Duration) { i.leeway = d }

// TTL reports the configured access-token lifetime, so the login response can
// tell the client when to refresh instead of hard-coding it in two places.
func (i *TokenIssuer) TTL() time.Duration { return i.ttl }

// Mint issues a token for userID.
func (i *TokenIssuer) Mint(userID uuid.UUID) (string, AccessClaims, error) {
	if userID == uuid.Nil {
		return "", AccessClaims{}, fmt.Errorf("authn: mint token for nil user: %w", ErrTokenInvalid)
	}

	now := i.now()
	claims := AccessClaims{
		UserID:    userID,
		TokenID:   uuid.Must(uuid.NewV7()).String(),
		IssuedAt:  now,
		ExpiresAt: now.Add(i.ttl),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": i.issuer,
		"aud": i.audience,
		"sub": claims.UserID.String(),
		"jti": claims.TokenID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": claims.ExpiresAt.Unix(),
	})

	signed, err := token.SignedString(i.secret)
	if err != nil {
		return "", AccessClaims{}, fmt.Errorf("authn: sign token: %w", err)
	}
	return signed, claims, nil
}

// Parse verifies a token and returns its claims.
//
// # Why WithValidMethods is not optional
//
// The `alg` header is attacker-controlled. A verifier that reads it without
// constraining it can be talked into accepting `alg: none` (no signature at all)
// or `alg: HS256` on a token that was supposed to be RS256 — in which case the
// public key, which is public, is used as the HMAC secret and anyone can forge
// tokens. Constraining the accepted algorithms is the fix, and it is the single
// most commonly missed step in JWT verification.
func (i *TokenIssuer) Parse(raw string) (AccessClaims, error) {
	if raw == "" {
		return AccessClaims{}, ErrTokenInvalid
	}

	parsed, err := jwt.Parse(raw,
		func(t *jwt.Token) (any, error) { return i.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(i.issuer),
		jwt.WithAudience(i.audience),
		jwt.WithLeeway(i.leeway),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(i.now),
	)
	if err != nil {
		// The cause is wrapped here for logs; callers see one sentinel so they
		// cannot accidentally leak which check failed.
		return AccessClaims{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if !parsed.Valid {
		return AccessClaims{}, ErrTokenInvalid
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return AccessClaims{}, ErrTokenInvalid
	}

	sub, err := claims.GetSubject()
	if err != nil || sub == "" {
		return AccessClaims{}, ErrTokenInvalid
	}
	userID, err := uuid.Parse(sub)
	if err != nil || userID == uuid.Nil {
		return AccessClaims{}, ErrTokenInvalid
	}

	out := AccessClaims{UserID: userID}

	if jti, err := claims.GetExpirationTime(); err == nil && jti != nil {
		out.ExpiresAt = jti.Time
	}
	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		out.IssuedAt = iat.Time
	}
	if rawJTI, ok := claims["jti"].(string); ok {
		out.TokenID = rawJTI
	}

	return out, nil
}
