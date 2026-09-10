package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// --- middleware behaviour ----------------------------------------------------

// stubSessionStore lets the middleware be tested without a database. The point of
// the interface is exactly this: routing and credential-transport behaviour are
// separable from token verification, so a failure here is unambiguous.
type stubSessionStore struct {
	session   authz.Principal
	sessionFn func(token string) error
	key       authz.Principal
	keyFn     func(key string) error

	calls []string
}

func (s *stubSessionStore) PrincipalForAccessToken(_ context.Context, token string) (authz.Principal, error) {
	s.calls = append(s.calls, "session:"+token)
	if s.sessionFn != nil {
		return authz.Principal{}, s.sessionFn(token)
	}
	if s.session.UserID == uuid.Nil && s.session.Method == "" {
		return authz.Principal{}, ErrTokenInvalid
	}
	return s.session, nil
}

func (s *stubSessionStore) PrincipalForAPIKey(_ context.Context, key string) (authz.Principal, error) {
	s.calls = append(s.calls, "key:"+key)
	if s.keyFn != nil {
		return authz.Principal{}, s.keyFn(key)
	}
	if s.key.Method == "" {
		return authz.Principal{}, ErrAPIKeyUnknown
	}
	return s.key, nil
}

// TestParseAuthorization covers credential transport, which is where a surprising
// number of real authentication bugs live.
func TestParseAuthorization(t *testing.T) {
	cases := []struct {
		name       string
		header     string
		wantScheme string
		wantCred   string
		wantOK     bool
	}{
		{"bearer lowercase", "Bearer abc.def.ghi", "bearer", "abc.def.ghi", true},
		{"bearer uppercase", "BEARER abc.def.ghi", "bearer", "abc.def.ghi", true},
		{"bearer mixed", "BeArEr abc.def.ghi", "bearer", "abc.def.ghi", true},
		{"apikey lowercase", "ApiKey ak_live_secret", "apikey", "ak_live_secret", true},
		{"apikey uppercase", "APIKEY ak_live_secret", "apikey", "ak_live_secret", true},
		{"surrounding whitespace", "  Bearer   abc.def.ghi  ", "bearer", "abc.def.ghi", true},
		// A token may legitimately contain spaces after base64-decoding into a
		// different shape; splitting on the first space only is the correct
		// behaviour, matching RFC 7235.
		{"credential containing a space", "Bearer abc def", "bearer", "abc def", true},

		{"empty", "", "", "", false},
		{"whitespace only", "   ", "", "", false},
		{"scheme without credential", "Bearer", "", "", false},
		{"scheme with empty credential", "Bearer   ", "", "", false},
		// An unrecognised scheme is treated as "no credential presented" rather
		// than as a failure: a browser sending Basic credentials meant for an
		// unrelated service should not produce a 401 that looks like a broken login.
		{"basic", "Basic dXNlcjpwYXNz", "", "", false},
		{"unknown scheme", "Digest abc", "", "", false},
		{"raw token with no scheme", "abc.def.ghi", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme, cred, ok := parseAuthorization(tc.header)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if scheme != tc.wantScheme {
				t.Fatalf("scheme = %q, want %q", scheme, tc.wantScheme)
			}
			if cred != tc.wantCred {
				t.Fatalf("credential = %q, want %q", cred, tc.wantCred)
			}
		})
	}
}

// TestAuthenticator_AttachesPrincipal proves a valid credential becomes a usable
// principal on the request context.
func TestAuthenticator_AttachesPrincipal(t *testing.T) {
	userID := uuid.Must(uuid.NewV7())
	store := &stubSessionStore{session: authz.Principal{UserID: userID, Method: authz.MethodJWT}}

	var (
		got      authz.Principal
		gotFound bool
	)
	handler := NewAuthenticator(store, nil).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, gotFound = authz.PrincipalFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
	req.Header.Set("Authorization", "Bearer a.valid.token")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !gotFound {
		t.Fatal("no principal was attached for a valid credential")
	}
	if got.UserID != userID {
		t.Fatalf("principal user = %s, want %s", got.UserID, userID)
	}
	if got.Method != authz.MethodJWT {
		t.Fatalf("principal method = %s, want jwt", got.Method)
	}
}

// TestAuthenticator_APIKeyScheme proves the ApiKey scheme routes to the key store
// rather than the token verifier. Getting this wrong would present every machine
// credential as an invalid JWT, which reads as "all our API keys stopped working".
func TestAuthenticator_APIKeyScheme(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	store := &stubSessionStore{key: authz.Principal{
		TenantID: tenantID,
		Scopes:   []authz.Perm{authz.PermProjectRead},
		Method:   authz.MethodAPIKey,
	}}

	var got authz.Principal
	handler := NewAuthenticator(store, nil).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = authz.PrincipalFrom(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set("Authorization", "ApiKey ak_live_secret")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got.Method != authz.MethodAPIKey {
		t.Fatalf("principal method = %s, want api_key", got.Method)
	}
	if got.TenantID != tenantID {
		t.Fatalf("principal tenant = %s, want %s", got.TenantID, tenantID)
	}
	if !got.Allows(authz.PermProjectRead) {
		t.Fatal("the key's scopes did not survive the middleware")
	}
	if got.Allows(authz.PermProjectWrite) {
		t.Fatal("the key gained a permission it does not hold")
	}

	// The credential must reach the key store, not the token verifier.
	for _, c := range store.calls {
		if strings.HasPrefix(c, "session:") {
			t.Fatal("an ApiKey credential was routed to the access-token verifier")
		}
	}
}

// TestAuthenticator_InvalidCredentialIs401 proves every rejection looks identical
// from outside. The distinctions survive only in the logs.
func TestAuthenticator_InvalidCredentialIs401(t *testing.T) {
	causes := []error{
		ErrTokenInvalid,
		ErrRefreshUnknown,
		ErrRefreshRevoked,
		ErrRefreshExpired,
		ErrAPIKeyUnknown,
		ErrAPIKeyRevoked,
		ErrAPIKeyExpired,
		ErrRefreshReused,
		errors.New("some internal failure"),
	}

	for _, cause := range causes {
		t.Run(cause.Error(), func(t *testing.T) {
			store := &stubSessionStore{}
			captured := cause
			store.sessionFn = func(string) error { return captured }

			var reached bool
			// The real stack always runs chi's RequestID middleware before the
			// authenticator, so the harness mirrors that rather than constructing a
			// bare handler. Without it the assertion below would be testing the test
			// setup instead of the response contract.
			handler := middleware.RequestID(NewAuthenticator(store, nil).Middleware(
				http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
					reached = true
				})))

			req := httptest.NewRequest(http.MethodGet, "/v1/me", nil)
			req.Header.Set("Authorization", "Bearer whatever")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if reached {
				t.Fatal("the request reached the handler with an invalid credential")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}

			// The body must not name the cause: that is exactly what an attacker
			// probing forgeries wants to learn.
			body := rec.Body.String()
			for _, leak := range []string{"expired", "revoked", "reused", "unknown", "malformed"} {
				if strings.Contains(strings.ToLower(body), leak) {
					t.Fatalf("response body leaks the failure cause (%q): %s", leak, body)
				}
			}
			if !strings.Contains(body, "request_id") {
				t.Errorf("401 body carries no request id, so the cause cannot be correlated in logs: %s", body)
			}
		})
	}
}

// TestAuthenticator_NoCredentialPassesThrough documents that authentication is a
// property of the route, not of the middleware.
//
// The middleware leaves an uncredentialed request alone so that public endpoints
// (health, login) work; RequireAuthentication or Require(perm) at the route is what
// refuses it. Collapsing the two would force every public route to be allow-listed
// in the authenticator, which is a list that grows stale.
func TestAuthenticator_NoCredentialPassesThrough(t *testing.T) {
	store := &stubSessionStore{sessionFn: func(string) error {
		t.Fatal("the store was consulted for a request with no credential")
		return nil
	}}

	var (
		reached  bool
		foundPri bool
	)
	handler := NewAuthenticator(store, nil).Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached = true
		_, foundPri = authz.PrincipalFrom(r.Context())
	}))

	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Digest abc"} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}

	if !reached {
		t.Fatal("an uncredentialed request never reached the handler")
	}
	if foundPri {
		t.Fatal("a principal was attached without a credential")
	}
}

// TestRequireAuthentication proves the gate that turns "no credential" into a 401.
func TestRequireAuthentication(t *testing.T) {
	var reached bool
	handler := RequireAuthentication(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	// Without a principal: rejected.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if reached {
		t.Fatal("an unauthenticated request reached the handler")
	}

	// With a principal: allowed.
	reached = false
	ctx := authz.WithPrincipal(context.Background(), authz.Principal{
		UserID: uuid.Must(uuid.NewV7()),
		Method: authz.MethodJWT,
	})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/me", nil).WithContext(ctx))
	if !reached {
		t.Fatal("an authenticated request was rejected")
	}
}

// TestClassifyAuthError proves each cause maps to a distinct, log-safe class. An
// operator's only signal for "someone is trying credentials" is a spike in one of
// these; collapsing them all into "unauthorized" throws it away.
func TestClassifyAuthError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrTokenInvalid, "access_token_invalid"},
		{ErrRefreshUnknown, "credential_unknown"},
		{ErrAPIKeyUnknown, "credential_unknown"},
		{ErrRefreshRevoked, "credential_revoked"},
		{ErrAPIKeyRevoked, "credential_revoked"},
		{ErrRefreshExpired, "credential_expired"},
		{ErrAPIKeyExpired, "credential_expired"},
		{ErrRefreshReused, "refresh_reused"},
		{errors.New("database on fire"), "internal_error"},
	}
	for _, tc := range cases {
		if got := classifyAuthError(tc.err); got != tc.want {
			t.Errorf("classifyAuthError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// --- API keys against a real database ---------------------------------------

// TestAPIKey_MintAndAuthenticate covers the credential lifecycle and asserts the
// storage contract: the secret exists once, in the response, and never in the
// database.
func TestAPIKey_MintAndAuthenticate(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	tenantID, userID := testsupport.NewTenant(t, d.App, "keys")

	minted, err := store.Mint(ctx, tenantID, userID, "ci deploy", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if !strings.HasPrefix(minted.Secret, "ak_") {
		t.Fatalf("secret %q lacks the ak_ prefix, so the redaction backstop will not recognise it", minted.Secret)
	}
	if len(minted.Secret) < 40 {
		t.Fatalf("secret looks too short to be 256 bits: %q", minted.Secret)
	}
	if minted.Prefix == "" || len(minted.Prefix) > 16 {
		t.Fatalf("display prefix %q is not usable", minted.Prefix)
	}
	if minted.TenantID != tenantID {
		t.Fatalf("key tenant = %s, want %s", minted.TenantID, tenantID)
	}

	// The plaintext must not be recoverable from storage. Checking through the
	// owner connection is deliberate: it bypasses the policies, so this asserts the
	// storage format rather than what the app role is permitted to read.
	if d.Owner != nil {
		var count int
		if err := d.Owner.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE key_hash = $1`, minted.Secret).Scan(&count); err != nil {
			t.Fatalf("owner-side lookup: %v", err)
		}
		if count != 0 {
			t.Fatal("the plaintext API key is stored verbatim; only its hash may be persisted")
		}
		if err := d.Owner.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE key_hash = $1`, HashAPIKey(minted.Secret)).Scan(&count); err != nil {
			t.Fatalf("owner-side hash lookup: %v", err)
		}
		if count != 1 {
			t.Fatalf("stored rows matching the key hash = %d, want 1", count)
		}
	}

	// Authentication round-trips, and yields the key's tenant and scopes.
	key, err := store.Authenticate(ctx, minted.Secret)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if key.TenantID != tenantID {
		t.Fatalf("authenticated tenant = %s, want %s", key.TenantID, tenantID)
	}
	if len(key.Scopes) != 1 || key.Scopes[0] != authz.PermProjectRead {
		t.Fatalf("authenticated scopes = %v, want [project:read]", key.Scopes)
	}
	if key.LastUsedAt == nil {
		t.Error("last_used_at was not recorded; the field that makes key cleanup possible is not populated")
	}

	// A wrong secret is unknown, not a match.
	if _, err := store.Authenticate(ctx, "ak_"+strings.Repeat("x", 43)); !errors.Is(err, ErrAPIKeyUnknown) {
		t.Fatalf("wrong secret error = %v, want ErrAPIKeyUnknown", err)
	}
	if _, err := store.Authenticate(ctx, ""); !errors.Is(err, ErrAPIKeyUnknown) {
		t.Fatalf("empty secret error = %v, want ErrAPIKeyUnknown", err)
	}
}

// TestAPIKey_RevokedAndExpired covers the two ways a key stops working. Both are
// reported distinctly for logging while producing the same 401 for the client.
func TestAPIKey_RevokedAndExpired(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	tenantID, userID := testsupport.NewTenant(t, d.App, "keys-lifecycle")

	t.Run("revoked", func(t *testing.T) {
		minted, err := store.Mint(ctx, tenantID, userID, "to be revoked", []authz.Perm{authz.PermProjectRead}, nil)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		if _, err := store.Authenticate(ctx, minted.Secret); err != nil {
			t.Fatalf("fresh key did not authenticate: %v", err)
		}
		if err := store.Revoke(ctx, tenantID, userID, minted.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := store.Authenticate(ctx, minted.Secret); !errors.Is(err, ErrAPIKeyRevoked) {
			t.Fatalf("revoked key error = %v, want ErrAPIKeyRevoked", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		// Expiry in the past is rejected at mint time, so the expired state is
		// produced by minting with a valid future expiry and then moving the store's
		// clock past it — the same way it happens in production, just faster.
		minted, err := store.Mint(ctx, tenantID, userID, "expiring", []authz.Perm{authz.PermProjectRead}, ptr(time.Now().Add(time.Hour)))
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		_ = past

		if _, err := store.Authenticate(ctx, minted.Secret); err != nil {
			t.Fatalf("unexpired key did not authenticate: %v", err)
		}

		store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
		if _, err := store.Authenticate(ctx, minted.Secret); !errors.Is(err, ErrAPIKeyExpired) {
			t.Fatalf("expired key error = %v, want ErrAPIKeyExpired", err)
		}
		store.now = time.Now
	})

	t.Run("minting with a past expiry is rejected", func(t *testing.T) {
		if _, err := store.Mint(ctx, tenantID, userID, "already dead", []authz.Perm{authz.PermProjectRead}, ptr(time.Now().Add(-time.Minute))); err == nil {
			t.Fatal("a key was minted with an expiry in the past")
		}
	})
}

// TestAPIKey_RevokeIsIdempotent covers retry behaviour: revoking twice must not
// error, because a retried request must behave the same as the one it retried.
func TestAPIKey_RevokeIsIdempotent(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	tenantID, userID := testsupport.NewTenant(t, d.App, "keys-idem")
	minted, err := store.Mint(ctx, tenantID, userID, "twice", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if err := store.Revoke(ctx, tenantID, userID, minted.ID); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := store.Revoke(ctx, tenantID, userID, minted.ID); err != nil {
		t.Fatalf("second Revoke returned an error, so a retry is not idempotent: %v", err)
	}
}

// TestAPIKey_CrossTenantRevokeIsNotFound is the IDOR test at the key layer.
//
// A key id belonging to another tenant must be indistinguishable from an unknown
// id: both are not-found. A distinct "forbidden" would confirm the id exists and
// turn the endpoint into an enumeration oracle.
func TestAPIKey_CrossTenantRevokeIsNotFound(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	victimTenant, victimUser := testsupport.NewTenant(t, d.App, "keys-victim")
	attackerTenant, attackerUser := testsupport.NewTenant(t, d.App, "keys-attacker")

	victimKey, err := store.Mint(ctx, victimTenant, victimUser, "victim key", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	err = store.Revoke(ctx, attackerTenant, attackerUser, victimKey.ID)
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("cross-tenant revoke error = %v, want ErrNotFound", err)
	}

	// The victim's key must still work: a failed attempt must not have side effects.
	if _, err := store.Authenticate(ctx, victimKey.Secret); err != nil {
		t.Fatalf("the victim's key was damaged by a cross-tenant revoke attempt: %v", err)
	}
}

// TestAPIKey_ListIsTenantScoped proves a tenant's listing never contains a
// neighbour's key, and never leaks a secret.
func TestAPIKey_ListIsTenantScoped(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	tenantA, userA := testsupport.NewTenant(t, d.App, "keys-list-a")
	tenantB, userB := testsupport.NewTenant(t, d.App, "keys-list-b")

	mine, err := store.Mint(ctx, tenantA, userA, "mine", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("Mint A: %v", err)
	}
	theirs, err := store.Mint(ctx, tenantB, userB, "theirs", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("Mint B: %v", err)
	}

	listed, err := store.List(ctx, tenantA, userA)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("tenant A sees %d keys, want 1", len(listed))
	}
	if listed[0].ID != mine.ID {
		t.Fatalf("tenant A sees key %s, want %s", listed[0].ID, mine.ID)
	}
	for _, k := range listed {
		if k.ID == theirs.ID {
			t.Fatal("tenant A's key list contains tenant B's key")
		}
		if k.Prefix == "" {
			t.Error("listed key has no display prefix, so it cannot be identified in a UI")
		}
	}
}

// TestAPIKey_MintRejectsBadInput covers validation that must happen before any SQL.
func TestAPIKey_MintRejectsBadInput(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewAPIKeyStore(d.App)
	ctx := context.Background()

	tenantID, userID := testsupport.NewTenant(t, d.App, "keys-validate")

	cases := []struct {
		name   string
		scopes []authz.Perm
		keyT   uuid.UUID
		userT  uuid.UUID
	}{
		{"nil tenant", []authz.Perm{authz.PermProjectRead}, uuid.Nil, userID},
		{"nil creator", []authz.Perm{authz.PermProjectRead}, tenantID, uuid.Nil},
		{"empty scopes", nil, tenantID, userID},
		{"unknown scope", []authz.Perm{authz.Perm("project:destroy")}, tenantID, userID},
		// The escalation guard, asserted at the store boundary too: even if a
		// handler forgets to check, minting cannot produce a key that manages its
		// own existence.
		{"forbidden scope", []authz.Perm{authz.PermAPIKeyManage}, tenantID, userID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.Mint(ctx, tc.keyT, tc.userT, "bad", tc.scopes, nil); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}

	// Name length is bounded by the CHECK constraint; the application mirrors it so
	// the failure is a validation error rather than a 500.
	if _, err := store.Mint(ctx, tenantID, userID, "", []authz.Perm{authz.PermProjectRead}, nil); err == nil {
		t.Fatal("an empty key name was accepted")
	}
	if _, err := store.Mint(ctx, tenantID, userID, strings.Repeat("x", 101), []authz.Perm{authz.PermProjectRead}, nil); err == nil {
		t.Fatal("a 101-character key name was accepted")
	}
}

func ptr[T any](v T) *T { return &v }
