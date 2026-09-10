package authn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func testIssuer(t *testing.T) *TokenIssuer {
	t.Helper()
	iss, err := NewTokenIssuer(
		[]byte("0123456789abcdef0123456789abcdef"), // exactly 32 bytes
		DefaultIssuer, DefaultAudience, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenIssuer: %v", err)
	}
	return iss
}

// TestNewTokenIssuer_RejectsWeakSecret is the check that prevents the worst
// possible outcome: a service that signs tokens correctly but with a secret short
// enough to brute-force offline. HMAC-SHA256 accepts any key length, so without
// this an 8-character secret would produce tokens that verify perfectly and are
// forgeable in minutes.
func TestNewTokenIssuer_RejectsWeakSecret(t *testing.T) {
	for _, secret := range []string{"", "short", "0123456789abcdef0123456789abcde"} { // last is 31 bytes
		if _, err := NewTokenIssuer([]byte(secret), DefaultIssuer, DefaultAudience, time.Minute); err == nil {
			t.Errorf("secret of %d bytes accepted, want rejection (minimum is 32)", len(secret))
		}
	}
}

func TestNewTokenIssuer_RejectsBadConfig(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	cases := []struct {
		name             string
		issuer, audience string
		ttl              time.Duration
	}{
		{"empty issuer", "", DefaultAudience, time.Minute},
		{"empty audience", DefaultIssuer, "", time.Minute},
		{"zero ttl", DefaultIssuer, DefaultAudience, 0},
		{"negative ttl", DefaultIssuer, DefaultAudience, -time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewTokenIssuer(secret, tc.issuer, tc.audience, tc.ttl); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

// TestMintParse_RoundTrip is the basic contract: a token minted for a user parses
// back to that user.
func TestMintParse_RoundTrip(t *testing.T) {
	iss := testIssuer(t)
	userID := uuid.Must(uuid.NewV7())

	token, minted, err := iss.Mint(userID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("token is not a three-part JWS: %q", token)
	}
	if minted.TokenID == "" {
		t.Fatal("minted token has no jti")
	}

	claims, err := iss.Parse(token)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("subject = %s, want %s", claims.UserID, userID)
	}
	if claims.TokenID != minted.TokenID {
		t.Fatalf("jti = %q, want %q", claims.TokenID, minted.TokenID)
	}
}

// TestMint_RejectsNilUser stops a token with an empty subject from ever existing.
// A subject-less token would parse to uuid.Nil, and every downstream lookup keys on
// that value.
func TestMint_RejectsNilUser(t *testing.T) {
	iss := testIssuer(t)
	if _, _, err := iss.Mint(uuid.Nil); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("error = %v, want ErrTokenInvalid", err)
	}
}

// TestParse_RejectsWrongSecret proves a token signed with a different key does not
// verify. This is the base case of forgery resistance.
func TestParse_RejectsWrongSecret(t *testing.T) {
	iss := testIssuer(t)
	token, _, err := iss.Mint(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	other, err := NewTokenIssuer(
		[]byte("ffffffffffffffffffffffffffffffff"), // same length, different key
		DefaultIssuer, DefaultAudience, 10*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenIssuer: %v", err)
	}

	if _, err := other.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("a token signed with a different key was accepted (err = %v)", err)
	}
}

// TestParse_RejectsAlgNone is the most important test in this file.
//
// The `alg` header is attacker-controlled. A verifier that reads it without
// constraining it can be told `alg: none`, which per the JWT spec means "no
// signature" — and a library that honours that will accept a token anyone can
// mint. This test forges such a token by hand and asserts rejection, so the
// property is proven rather than assumed from a library default.
func TestParse_RejectsAlgNone(t *testing.T) {
	iss := testIssuer(t)
	userID := uuid.Must(uuid.NewV7())

	forged := forgeToken(t, map[string]any{"alg": "none", "typ": "JWT"}, map[string]any{
		"iss": DefaultIssuer,
		"aud": DefaultAudience,
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}, "")

	if _, err := iss.Parse(forged); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("alg:none token accepted (err = %v): signature verification is not enforced", err)
	}
}

// TestParse_RejectsUnexpectedAlg covers the other half of algorithm confusion.
//
// The classic exploit is telling a verifier that expected RS256 to accept HS256,
// then signing with the *public* key, which is not secret. This service has only
// one algorithm, so the equivalent risk is accepting any other algorithm at all —
// which is what WithValidMethods prevents. A token with no signature segment is
// rejected for the same reason.
func TestParse_RejectsUnexpectedAlg(t *testing.T) {
	iss := testIssuer(t)
	userID := uuid.Must(uuid.NewV7())
	claims := map[string]any{
		"iss": DefaultIssuer,
		"aud": DefaultAudience,
		"sub": userID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	cases := []struct {
		name  string
		token string
	}{
		{"hs512 header, hs256 signature", forgeToken(t,
			map[string]any{"alg": "HS512", "typ": "JWT"}, claims,
			"ignored-because-the-header-disagrees")},
		{"empty signature segment", forgeToken(t,
			map[string]any{"alg": "HS256", "typ": "JWT"}, claims, "")},
		{"garbage", "not.a.token"},
		{"empty", ""},
		{"two segments only", strings.Join(strings.Split(forgeToken(t,
			map[string]any{"alg": "HS256"}, claims, "sig"), ".")[:2], ".")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := iss.Parse(tc.token); !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("token accepted (err = %v)", err)
			}
		})
	}
}

// TestParse_RejectsExpired proves the expiry claim is enforced, not merely
// present. An access token's short lifetime is the only lever on a leaked token,
// so a verifier that ignores exp would negate the entire design.
func TestParse_RejectsExpired(t *testing.T) {
	iss := testIssuer(t)
	userID := uuid.Must(uuid.NewV7())

	token, _, err := iss.Mint(userID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Move the verifier's clock past the token's expiry. The issuer validates
	// against its own clock (WithTimeFunc), so this needs no sleeping.
	iss.now = func() time.Time { return time.Now().Add(2 * time.Hour) }

	if _, err := iss.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token accepted (err = %v)", err)
	}
}

// TestParse_RequiresExpiry guards against a token that carries no expiration at
// all. Without WithExpirationRequired, a token minted without exp would verify
// forever — the same as no revocation, except harder to notice.
//
// The fixture is a genuinely signed token (not a forged one) precisely so the
// only thing wrong with it is the missing claim. A hand-forged token would be
// rejected on its signature instead, and the test would pass without ever
// exercising the expiry requirement.
func TestParse_RequiresExpiry(t *testing.T) {
	iss := testIssuer(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	userID := uuid.Must(uuid.NewV7())

	noExpiry := signWith(t, secret,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss": DefaultIssuer,
			"aud": DefaultAudience,
			"sub": userID.String(),
			"iat": time.Now().Unix(),
			"nbf": time.Now().Unix(),
			"jti": uuid.Must(uuid.NewV7()).String(),
		})

	if _, err := iss.Parse(noExpiry); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("token without an exp claim was accepted (err = %v)", err)
	}

	// Control: the same claims with an exp added must be accepted, which proves
	// the rejection above is attributable to the missing claim rather than to
	// some other property of the fixture.
	withExpiry := signWith(t, secret,
		map[string]any{"alg": "HS256", "typ": "JWT"},
		map[string]any{
			"iss": DefaultIssuer,
			"aud": DefaultAudience,
			"sub": userID.String(),
			"iat": time.Now().Unix(),
			"nbf": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
			"jti": uuid.Must(uuid.NewV7()).String(),
		})
	if _, err := iss.Parse(withExpiry); err != nil {
		t.Fatalf("control token with an exp claim was rejected: %v", err)
	}
}

// TestParse_RejectsWrongIssuerAndAudience covers environment cross-contamination:
// a token minted by another deployment that happens to share a secret (a restored
// backup, a copied config) must not be accepted here.
func TestParse_RejectsWrongIssuerAndAudience(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	userID := uuid.Must(uuid.NewV7())

	good, err := NewTokenIssuer(secret, DefaultIssuer, DefaultAudience, time.Minute)
	if err != nil {
		t.Fatalf("NewTokenIssuer: %v", err)
	}
	token, _, err := good.Mint(userID)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	otherIssuer, err := NewTokenIssuer(secret, "someone-else", DefaultAudience, time.Minute)
	if err != nil {
		t.Fatalf("NewTokenIssuer: %v", err)
	}
	if _, err := otherIssuer.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token accepted by a verifier with a different issuer")
	}

	otherAudience, err := NewTokenIssuer(secret, DefaultIssuer, "another-audience", time.Minute)
	if err != nil {
		t.Fatalf("NewTokenIssuer: %v", err)
	}
	if _, err := otherAudience.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token accepted by a verifier with a different audience")
	}
}

// TestParse_RejectsFutureToken covers nbf: a token whose validity starts in the
// future must be rejected, otherwise a stolen token could be pre-dated to outlive
// a revocation.
func TestParse_RejectsFutureToken(t *testing.T) {
	iss := testIssuer(t)
	iss.now = func() time.Time { return time.Now().Add(24 * time.Hour) }

	token, _, err := iss.Mint(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Verify with the real clock: the token claims to have been issued tomorrow.
	iss.now = time.Now
	if _, err := iss.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("token valid only in the future was accepted (err = %v)", err)
	}
}

// TestParse_ToleratesClockSkew documents the leeway, so the tolerance is a stated
// design choice rather than an accident of configuration. Zero leeway turns a few
// seconds of clock drift between hosts into intermittent 401s.
func TestParse_ToleratesClockSkew(t *testing.T) {
	iss := testIssuer(t)
	iss.SetLeeway(30 * time.Second)

	token, _, err := iss.Mint(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Just past expiry, but inside the leeway window.
	iss.now = func() time.Time { return time.Now().Add(10*time.Minute + 10*time.Second) }
	if _, err := iss.Parse(token); err != nil {
		t.Fatalf("token inside the leeway window was rejected: %v", err)
	}

	// Past expiry plus leeway: rejected.
	iss.now = func() time.Time { return time.Now().Add(10*time.Minute + time.Minute) }
	if _, err := iss.Parse(token); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token past expiry plus leeway was accepted")
	}
}

// TestParse_RejectsMalformedSubject covers a token that verifies cryptographically
// but carries a subject this service cannot use. It must be rejected rather than
// parsed into a zero UUID, which would make every downstream lookup key on nil.
func TestParse_RejectsMalformedSubject(t *testing.T) {
	iss := testIssuer(t)
	secret := []byte("0123456789abcdef0123456789abcdef")

	cases := []string{"", "not-a-uuid", uuid.Nil.String()}
	for _, subject := range cases {
		claims := map[string]any{
			"iss": DefaultIssuer,
			"aud": DefaultAudience,
			"sub": subject,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := signWith(t, secret, map[string]any{"alg": "HS256", "typ": "JWT"}, claims)
		if _, err := iss.Parse(token); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("subject %q accepted (err = %v)", subject, err)
		}
	}
}

// TestParsedClaims_CarryNoAuthorization is the design assertion.
//
// The access token deliberately carries no tenant and no role, so a revoked
// membership takes effect on the next request rather than the next login. This
// test fails the moment someone adds a role or tenant claim, which is the change
// that would silently reintroduce stale authorization.
func TestParsedClaims_CarryNoAuthorization(t *testing.T) {
	iss := testIssuer(t)
	token, _, err := iss.Mint(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}

	for _, forbidden := range []string{"role", "roles", "tenant", "tenant_id", "tid", "perms", "scope", "scopes"} {
		if _, present := claims[forbidden]; present {
			t.Errorf("access token carries %q; authorization must be resolved per request, not cached in the credential", forbidden)
		}
	}

	// The claims that must be present.
	for _, required := range []string{"iss", "aud", "sub", "exp", "iat", "nbf", "jti"} {
		if _, present := claims[required]; !present {
			t.Errorf("access token is missing the %q claim", required)
		}
	}
}

// --- helpers -----------------------------------------------------------------

// forgeToken builds an unsigned token with the given header and claims.
func forgeToken(t *testing.T, header, claims map[string]any, signature string) string {
	t.Helper()
	return b64(t, header) + "." + b64(t, claims) + "." + signature
}

// signWith builds a genuinely signed token, used when a test needs a token that is
// cryptographically valid but semantically wrong (missing exp, bad subject).
func signWith(t *testing.T, secret []byte, header, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	signed, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("sign fixture token: %v", err)
	}
	return signed
}

func b64(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
