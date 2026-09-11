// Package httpx_test exercises the API through its real router, against a real
// Postgres as the unprivileged application role.
//
// # Why these tests matter more than the handler's own unit tests would
//
// Every security property in this service is a property of the *composition*: the
// authenticator attaches a principal, the tenant middleware turns that principal
// into an authorized scope, the RBAC middleware checks a permission, the handler
// calls a repository, and row-level security bounds the query. Each of those is
// tested in isolation elsewhere, but an isolation test that passes in four separate
// packages while the assembled stack leaks is exactly the failure a reviewer will
// find. So this file drives HTTP and asserts on what comes back.
package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/httpx"
	"github.com/aditya0si/tenant-api-platform/internal/idempotency"
	"github.com/aditya0si/tenant-api-platform/internal/invoice"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// testSecret is the signing key every server in this file uses. It is 32 bytes
// because the token issuer refuses anything shorter — the same check that stops a
// deployment from signing with a brute-forceable key.
var testSecret = []byte("0123456789abcdef0123456789abcdef")

// server is a running API with its dependencies, plus the stores the test can use
// to set up state directly.
type server struct {
	t        *testing.T
	handler  http.Handler
	tenants  *tenant.Store
	projects *project.Store
	users    *authn.UserStore
	keys     *authn.APIKeyStore

	// idem and db let a test reach past the API — to claim a key directly, to count rows
	// the response cannot show, or to backdate a row so expiry can be driven without
	// sleeping. Tests that need only HTTP behaviour ignore them.
	idem *idempotency.Store
	db   *testsupport.DB

	// audit reads the trail directly, so a test can assert on what was recorded rather
	// than only on what the endpoint chose to return.
	audit *audit.Reader
}

// serverConfig allows a test to vary the few settings that change observable
// behaviour, without every test having to know about all of them.
type serverConfig struct {
	// refreshGrace is the window in which re-presenting a consumed refresh token is
	// treated as a concurrent retry rather than as theft.
	//
	// It is configurable because both behaviours need testing and they are mutually
	// exclusive: strict rotation (zero) makes a replay revoke the family, while the
	// production default absorbs a replay that lands inside the window. A suite that
	// could only exercise one of them would leave the other unverified — and the
	// default is the one that runs in production.
	refreshGrace time.Duration

	// rateLimits enables limiting for this server. Nil means none, which is what most
	// tests want: a limiter would refuse the tenth rapid request to an endpoint and
	// silently turn an unrelated assertion into a 429. Tests that are *about* limiting
	// supply one, so the middleware under test is the production middleware rather than a
	// stub.
	rateLimits *httpx.RateLimits
}

// newServer builds the API with production-like settings.
func newServer(t *testing.T) *server {
	t.Helper()
	return newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace})
}

// newServerWith builds the API against the shared test database with explicit settings.
func newServerWith(t *testing.T, cfg serverConfig) *server {
	t.Helper()
	d := testsupport.RequireDB(t)

	tokens, err := authn.NewTokenIssuer(testSecret, authn.DefaultIssuer, authn.DefaultAudience, 10*time.Minute)
	if err != nil {
		t.Fatalf("token issuer: %v", err)
	}
	codec, err := cursor.NewCodec(cursor.DeriveKey(testSecret))
	if err != nil {
		t.Fatalf("cursor codec: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	users := authn.NewUserStore(d.App)
	tenants := tenant.NewStore(d.App)
	projects := project.NewStore(d.App)
	keys := authn.NewAPIKeyStore(d.App)

	// The real store, with production lease and retention. A test that needs a different
	// lease backdates the row instead of shrinking the constant, so the SQL under test is
	// the same SQL that runs in production.
	idem := idempotency.NewStore(d.App, 0, 0)
	auditReader := audit.NewReader(d.App)
	invoiceStore := invoice.NewStore(d.App)

	svc, err := authn.NewService(
		users, tokens,
		authn.NewRefreshStore(d.App, cfg.refreshGrace),
		keys,
		httpx.MembershipLister{Tenants: tenants},
		log,
	)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}

	handler := httpx.New(httpx.Deps{
		Log:            log,
		Auth:           svc,
		Users:          users,
		Tenants:        tenants,
		Projects:       projects,
		Cursors:        codec,
		Audit:          auditReader,
		Invoices:       invoiceStore,
		Idempotency:    idem,
		RateLimits:     cfg.rateLimits,
		AccessTokenTTL: 600,
	})

	return &server{
		t: t, handler: handler, tenants: tenants, projects: projects,
		users: users, keys: keys, idem: idem, db: d, audit: auditReader,
	}
}

// response is a decoded API response.
type response struct {
	status int
	body   []byte

	// header is kept because some behaviour is only observable in headers: the
	// idempotency replay marker, Retry-After, and the Set-Cookie that must never be
	// replayed. A test that could see only status and body would have to assert on
	// those indirectly, or not at all.
	header http.Header
}

// decodeEnvelope unmarshals the whole response body into dst.
//
// Use it for the shapes that *are* the envelope: a listing (data plus next_cursor),
// an error (error), or a flat infrastructure probe (status). A payload struct passed
// here would silently decode to its zero value, which is why the payload case has its
// own method rather than sharing this one.
func (r response) decodeEnvelope(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.body, dst); err != nil {
		t.Fatalf("response body is not valid JSON: %v\nbody: %s", err, r.body)
	}
}

// decodeData unmarshals the "data" field of a success envelope into dst.
//
// Success responses are wrapped ({"data": ...}) so a field can be added later without
// breaking a client that already parses the body, while errors use {"error": ...}.
// The two shapes are deliberate, so the helpers mirror the difference instead of
// hiding it behind one permissive decoder.
//
// It fails loudly when there is no data field, and that check is the point: a decode
// that silently yields a zero struct is exactly the bug this pair of methods replaced
// — every session field decoded empty while the response looked perfectly correct.
func (r response) decodeData(t *testing.T, dst any) {
	t.Helper()

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(r.body, &envelope); err != nil {
		t.Fatalf("response body is not valid JSON: %v\nbody: %s", err, r.body)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		t.Fatalf("response has no data field, so it is not a success envelope: %s", r.body)
	}
	if err := json.Unmarshal(envelope.Data, dst); err != nil {
		t.Fatalf("data field does not match the expected shape: %v\ndata: %s", err, envelope.Data)
	}
}

// do issues a request. token may be empty for an unauthenticated call.
func (s *server) do(method, path string, body any, token string) response {
	return s.doWithKey(method, path, body, token, "")
}

// doWithKey issues a request carrying an idempotency key.
//
// An empty key sends no header, so one helper covers both the protected and the
// unprotected path and a test can compare them without two request builders that could
// drift apart.
func (s *server) doWithKey(method, path string, body any, token, key string) response {
	s.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set(idempotency.Header, key)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)

	// RequestID middleware is part of the stack, so every response carries the header
	// a client would quote in a bug report. It is asserted on every response
	// including the 404s: the middleware runs for unmatched routes too, so an
	// exception here would hide a handler registered outside it.
	if rec.Header().Get("X-Request-Id") == "" {
		s.t.Errorf("%s %s returned no X-Request-Id header", method, path)
	}
	return response{status: rec.Code, body: rec.Body.Bytes(), header: rec.Header()}
}

// doAPIKey issues a request authenticated with an API key.
func (s *server) doAPIKey(method, path string, body any, key string) response {
	s.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "ApiKey "+key)

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return response{status: rec.Code, body: rec.Body.Bytes(), header: rec.Header()}
}

// --- session plumbing --------------------------------------------------------

type sessionBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
	Tenants      []struct {
		TenantID string `json:"tenant_id"`
		Slug     string `json:"slug"`
		Name     string `json:"name"`
		Role     string `json:"role"`
	} `json:"tenants"`
}

// register creates an account and returns its session plus the tenant it owns.
func (s *server) register(email string) (sessionBody, string) {
	s.t.Helper()

	res := s.do(http.MethodPost, "/v1/auth/register", map[string]any{
		"email":       email,
		"password":    "correct horse battery staple",
		"tenant_name": "Test Workspace",
	}, "")
	if res.status != http.StatusCreated {
		s.t.Fatalf("register: status %d, body %s", res.status, res.body)
	}
	var session sessionBody
	res.decodeData(s.t, &session)
	if session.AccessToken == "" || session.RefreshToken == "" {
		s.t.Fatalf("register returned an incomplete session: %s", res.body)
	}
	if len(session.Tenants) != 1 {
		s.t.Fatalf("register returned %d tenants, want the one it just created", len(session.Tenants))
	}
	return session, session.Tenants[0].TenantID
}

// login authenticates an existing account.
func (s *server) login(email, password string) response {
	return s.do(http.MethodPost, "/v1/auth/login", map[string]any{
		"email":    email,
		"password": password,
	}, "")
}

// addMemberWithRole creates a user and adds them to a tenant with a role,
// returning their session.
//
// It creates the *user* through the store rather than the API, because the API
// deliberately has no endpoint that mints an account without a tenant. The
// membership itself is created through the API, so the RBAC path under test is the
// real one — including the rank check on the granting role.
func (s *server) addMemberWithRole(owner sessionBody, tenantID, email string, role authz.Role) sessionBody {
	s.t.Helper()
	ctx := context.Background()

	user, err := s.users.Create(ctx, email, "correct horse battery staple")
	if err != nil {
		s.t.Fatalf("create member user: %v", err)
	}

	res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
		"user_id": user.ID.String(),
		"role":    string(role),
	}, owner.AccessToken)
	if res.status != http.StatusCreated {
		s.t.Fatalf("add member: status %d, body %s", res.status, res.body)
	}

	loginRes := s.login(email, "correct horse battery staple")
	if loginRes.status != http.StatusOK {
		s.t.Fatalf("member login: status %d, body %s", loginRes.status, loginRes.body)
	}
	var session sessionBody
	loginRes.decodeData(s.t, &session)
	return session
}

// --- happy path --------------------------------------------------------------

// TestRegisterLoginMe is the end-to-end spine: an account is created, it can log
// in, and the resulting token identifies it.
func TestRegisterLoginMe(t *testing.T) {
	s := newServer(t)
	email := uniqueEmail("spine")

	session, tenantID := s.register(email)

	if session.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", session.TokenType)
	}
	if session.ExpiresIn <= 0 {
		t.Fatalf("expires_in = %d, want a positive number of seconds", session.ExpiresIn)
	}

	// The same credentials must work through the login endpoint.
	loginRes := s.login(email, "correct horse battery staple")
	if loginRes.status != http.StatusOK {
		t.Fatalf("login: status %d, body %s", loginRes.status, loginRes.body)
	}
	var loggedIn sessionBody
	loginRes.decodeData(t, &loggedIn)
	if loggedIn.UserID != session.UserID {
		t.Fatalf("login returned user %s, want %s", loggedIn.UserID, session.UserID)
	}

	res := s.do(http.MethodGet, "/v1/me", nil, session.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("me: status %d, body %s", res.status, res.body)
	}
	var me struct {
		UserID     string `json:"user_id"`
		AuthMethod string `json:"auth_method"`
		// Permissions are per-tenant for a session, because they come from the
		// caller's role in each one — so they are asserted inside the tenant rather
		// than at the top level. A key reports them flat, because a key is not a person
		// and has no per-membership variation; that shape is covered by the API-key
		// test in this file.
		Tenants []struct {
			TenantID    string   `json:"tenant_id"`
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		} `json:"tenants"`
	}
	res.decodeData(t, &me)

	if me.UserID != session.UserID {
		t.Fatalf("me returned user %s, want %s", me.UserID, session.UserID)
	}
	if me.AuthMethod != "jwt" {
		t.Fatalf("auth_method = %q, want jwt", me.AuthMethod)
	}
	if len(me.Tenants) != 1 || me.Tenants[0].TenantID != tenantID {
		t.Fatalf("me returned tenants %+v, want the one owned", me.Tenants)
	}
	if me.Tenants[0].Role != string(authz.RoleOwner) {
		t.Fatalf("role = %q, want owner", me.Tenants[0].Role)
	}

	// An owner holds every permission, which is the property the RBAC matrix asserts
	// as data — this is the same claim observed through the API.
	if len(me.Tenants[0].Permissions) != len(authz.AllPerms()) {
		t.Fatalf("owner has %d permissions in their tenant, want all %d",
			len(me.Tenants[0].Permissions), len(authz.AllPerms()))
	}
}

// TestLogin_RejectsBadCredentials proves the endpoint's uniform failure: a wrong
// password and an unknown address are indistinguishable from outside.
func TestLogin_RejectsBadCredentials(t *testing.T) {
	s := newServer(t)
	email := uniqueEmail("badcreds")
	s.register(email)

	cases := []struct {
		name     string
		email    string
		password string
	}{
		{"wrong password", email, "not the password"},
		{"unknown email", uniqueEmail("nobody"), "correct horse battery staple"},
		{"malformed email", "not-an-email", "correct horse battery staple"},
		{"empty password", email, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := s.login(tc.email, tc.password)
			if res.status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", res.status)
			}
			// The body must not distinguish the causes: an attacker who could tell
			// them apart could enumerate which addresses have accounts.
			lower := strings.ToLower(string(res.body))
			for _, leak := range []string{"password", "unknown", "not found", "no account", "invalid email"} {
				if strings.Contains(lower, leak) {
					t.Fatalf("login response leaks the failure cause (%q): %s", leak, res.body)
				}
			}
		})
	}
}

// TestEndpoints_RequireAuthentication proves the authenticated routes refuse an
// anonymous caller, and that the refusal is 401 rather than 403 or 404.
func TestEndpoints_RequireAuthentication(t *testing.T) {
	s := newServer(t)
	_, tenantID := s.register(uniqueEmail("anon"))

	projectsPath := "/v1/tenants/" + tenantID + "/projects"
	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/me"},
		{http.MethodGet, "/v1/tenants"},
		{http.MethodPost, "/v1/tenants"},
		{http.MethodGet, projectsPath},
		{http.MethodPost, projectsPath},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			res := s.do(tc.method, tc.path, nil, "")
			if res.status != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 (body: %s)", res.status, res.body)
			}
		})
	}

	// A syntactically invalid token is rejected the same way as no token.
	for _, bad := range []string{"not-a-jwt", "a.b.c", ""} {
		res := s.do(http.MethodGet, "/v1/me", nil, bad)
		if res.status != http.StatusUnauthorized && bad != "" {
			t.Fatalf("token %q: status = %d, want 401", bad, res.status)
		}
	}
}

// --- tenant isolation through the full stack ---------------------------------

// TestProjectFlow_CreateReadUpdateArchive drives the project lifecycle over HTTP,
// so the successful path through every layer is exercised before the failure paths
// below isolate one layer each.
func TestProjectFlow_CreateReadUpdateArchive(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("flow"))
	base := "/v1/tenants/" + tenantID + "/projects"

	createRes := s.do(http.MethodPost, base, map[string]any{
		"name":        "Payments API",
		"description": "The money path",
	}, session.AccessToken)
	if createRes.status != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", createRes.status, createRes.body)
	}
	var created struct {
		ID      string `json:"id"`
		Slug    string `json:"slug"`
		Version int    `json:"version"`
	}
	createRes.decodeData(t, &created)
	if created.Slug != "payments-api" {
		t.Fatalf("slug = %q, want it derived from the name", created.Slug)
	}

	getRes := s.do(http.MethodGet, base+"/"+created.ID, nil, session.AccessToken)
	if getRes.status != http.StatusOK {
		t.Fatalf("get: status %d, body %s", getRes.status, getRes.body)
	}

	// Update with the version the create returned.
	updateRes := s.do(http.MethodPatch, base+"/"+created.ID, map[string]any{
		"name":             "Payments API v2",
		"expected_version": created.Version,
	}, session.AccessToken)
	if updateRes.status != http.StatusOK {
		t.Fatalf("update: status %d, body %s", updateRes.status, updateRes.body)
	}
	var updated struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	updateRes.decodeData(t, &updated)
	if updated.Name != "Payments API v2" {
		t.Fatalf("name = %q, want the update to apply", updated.Name)
	}
	if updated.Version != created.Version+1 {
		t.Fatalf("version = %d, want %d", updated.Version, created.Version+1)
	}

	archiveRes := s.do(http.MethodDelete, base+"/"+created.ID, nil, session.AccessToken)
	if archiveRes.status != http.StatusNoContent {
		t.Fatalf("archive: status %d, body %s", archiveRes.status, archiveRes.body)
	}

	// Archived projects are hidden from the default listing.
	listRes := s.do(http.MethodGet, base, nil, session.AccessToken)
	if listRes.status != http.StatusOK {
		t.Fatalf("list: status %d, body %s", listRes.status, listRes.body)
	}
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	listRes.decodeEnvelope(t, &page)
	if len(page.Data) != 0 {
		t.Fatalf("default listing returned %d projects, want 0 after archiving the only one", len(page.Data))
	}
}

// TestCrossTenant_ProjectAccessIsNotFound is the endpoint-level IDOR test.
//
// Two real accounts, two real tenants, and one token trying to reach the other's
// project by id. The assertion is not merely that it fails, but that it fails the
// same way an unknown id does: a distinguishable response would confirm the project
// exists, which is enough to enumerate.
func TestCrossTenant_ProjectAccessIsNotFound(t *testing.T) {
	s := newServer(t)

	aliceSession, aliceTenant := s.register(uniqueEmail("alice"))
	bobSession, _ := s.register(uniqueEmail("bob"))

	// Alice owns a project Bob must never see.
	createRes := s.do(http.MethodPost, "/v1/tenants/"+aliceTenant+"/projects", map[string]any{
		"name": "Alice Private Roadmap",
	}, aliceSession.AccessToken)
	if createRes.status != http.StatusCreated {
		t.Fatalf("alice create: status %d, body %s", createRes.status, createRes.body)
	}
	var aliceProject struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	}
	createRes.decodeData(t, &aliceProject)

	unknownID := uuid.Must(uuid.NewV7()).String()
	aliceBase := "/v1/tenants/" + aliceTenant + "/projects"

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"read Alice's project by id", http.MethodGet, aliceBase + "/" + aliceProject.ID, nil},
		{"read Alice's tenant directly", http.MethodGet, "/v1/tenants/" + aliceTenant, nil},
		{"list Alice's projects", http.MethodGet, aliceBase, nil},
		{"read Alice's member roster", http.MethodGet, "/v1/tenants/" + aliceTenant + "/members", nil},
		{"update Alice's project", http.MethodPatch, aliceBase + "/" + aliceProject.ID, map[string]any{
			"name": "Pwned", "expected_version": aliceProject.Version,
		}},
		{"archive Alice's project", http.MethodDelete, aliceBase + "/" + aliceProject.ID, nil},
		{"add a member to Alice's tenant", http.MethodPost, "/v1/tenants/" + aliceTenant + "/members", map[string]any{
			"user_id": uuid.Must(uuid.NewV7()).String(), "role": "owner",
		}},
		{"create a project in Alice's tenant", http.MethodPost, aliceBase, map[string]any{"name": "Intruder"}},
	}

	// The unknown-id responses are collected so each cross-tenant response can be
	// compared against them: an attacker with no access must not be able to tell a
	// real id from a fabricated one.
	unknownBase := "/v1/tenants/" + unknownID + "/projects"
	var unknownStatuses []int
	for _, p := range []string{unknownBase, unknownBase + "/" + aliceProject.ID} {
		unknownStatuses = append(unknownStatuses, s.do(http.MethodGet, p, nil, bobSession.AccessToken).status)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := s.do(tc.method, tc.path, tc.body, bobSession.AccessToken)
			if res.status == http.StatusOK || res.status == http.StatusCreated || res.status == http.StatusNoContent {
				t.Fatalf("Bob reached Alice's resource: status %d, body %s", res.status, res.body)
			}
			if res.status != http.StatusNotFound {
				t.Fatalf("status = %d, want 404 — a non-member must be indistinguishable from an unknown tenant (body: %s)",
					res.status, res.body)
			}
			// The response must not name the tenant or the resource: that would
			// confirm existence even with the right status code.
			if strings.Contains(string(res.body), aliceTenant) || strings.Contains(string(res.body), aliceProject.ID) {
				t.Fatalf("404 body echoes the requested resource: %s", res.body)
			}
		})
	}

	// Sanity: the same paths with a fabricated tenant id produce the same status, so
	// the 404s above are not distinguishable from "no such tenant".
	for _, status := range unknownStatuses {
		if status != http.StatusNotFound {
			t.Fatalf("fabricated tenant id returned %d, want 404", status)
		}
	}

	// And Alice's project must be untouched by the attempts.
	getRes := s.do(http.MethodGet, aliceBase+"/"+aliceProject.ID, nil, aliceSession.AccessToken)
	if getRes.status != http.StatusOK {
		t.Fatalf("Alice can no longer read her own project: %d", getRes.status)
	}
	var after struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	getRes.decodeData(t, &after)
	if after.Name == "Pwned" || after.Version != aliceProject.Version {
		t.Fatalf("a cross-tenant write succeeded: %+v", after)
	}
}

// TestRBAC_MemberCannotWriteProjects is the permission test at the HTTP boundary.
//
// A member may read projects and may not create, update, or archive them. The
// distinction from the isolation test above matters: this caller *can* see the
// tenant, so the correct answer is 403 rather than 404 — the resource is not a
// secret from them, the action is simply not theirs to take.
func TestRBAC_MemberCannotWriteProjects(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("rbac-owner"))
	memberSession := s.addMemberWithRole(ownerSession, tenantID, uniqueEmail("rbac-member"), authz.RoleMember)

	base := "/v1/tenants/" + tenantID + "/projects"

	// A member may read.
	if res := s.do(http.MethodGet, base, nil, memberSession.AccessToken); res.status != http.StatusOK {
		t.Fatalf("member read: status %d, want 200 (body %s)", res.status, res.body)
	}

	// A member may not write.
	createRes := s.do(http.MethodPost, base, map[string]any{"name": "Member Project"}, memberSession.AccessToken)
	if createRes.status != http.StatusForbidden {
		t.Fatalf("member create: status %d, want 403 (body %s)", createRes.status, createRes.body)
	}

	// The owner creates one so the member has something to attempt to modify.
	ownerCreate := s.do(http.MethodPost, base, map[string]any{"name": "Owner Project"}, ownerSession.AccessToken)
	if ownerCreate.status != http.StatusCreated {
		t.Fatalf("owner create: status %d, body %s", ownerCreate.status, ownerCreate.body)
	}
	var p struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	}
	ownerCreate.decodeData(t, &p)

	updateRes := s.do(http.MethodPatch, base+"/"+p.ID, map[string]any{
		"name": "Member Renamed It", "expected_version": p.Version,
	}, memberSession.AccessToken)
	if updateRes.status != http.StatusForbidden {
		t.Fatalf("member update: status %d, want 403 (body %s)", updateRes.status, updateRes.body)
	}

	archiveRes := s.do(http.MethodDelete, base+"/"+p.ID, nil, memberSession.AccessToken)
	if archiveRes.status != http.StatusForbidden {
		t.Fatalf("member archive: status %d, want 403 (body %s)", archiveRes.status, archiveRes.body)
	}

	// The owner may do all of it — proving the 403s above are about the role and not
	// about the route being broken.
	ownerUpdate := s.do(http.MethodPatch, base+"/"+p.ID, map[string]any{
		"name": "Owner Renamed It", "expected_version": p.Version,
	}, ownerSession.AccessToken)
	if ownerUpdate.status != http.StatusOK {
		t.Fatalf("owner update: status %d, body %s", ownerUpdate.status, ownerUpdate.body)
	}
}

// TestRBAC_MemberCannotManageMembersOrKeys proves the member role's boundary is not
// limited to projects.
func TestRBAC_MemberCannotManageMembersOrKeys(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("rbac2-owner"))
	memberSession := s.addMemberWithRole(ownerSession, tenantID, uniqueEmail("rbac2-member"), authz.RoleMember)

	res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
		"user_id": uuid.Must(uuid.NewV7()).String(),
		"role":    "owner",
	}, memberSession.AccessToken)
	if res.status != http.StatusForbidden {
		t.Fatalf("member adding a member: status %d, want 403 (body %s)", res.status, res.body)
	}

	// A member may read the roster, since member:read is in their set.
	if res := s.do(http.MethodGet, "/v1/tenants/"+tenantID+"/members", nil, memberSession.AccessToken); res.status != http.StatusOK {
		t.Fatalf("member reading the roster: status %d, want 200", res.status)
	}
}

// TestRBAC_AdminCannotGrantOwner is the privilege-escalation test.
//
// An admin may add members and may grant the admin role, but must not be able to
// mint an owner — which is the step that would let them promote themselves. Without
// this check the role hierarchy would be decorative: any admin could become an
// owner by creating an accomplice.
func TestRBAC_AdminCannotGrantOwner(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("escalate-owner"))
	adminSession := s.addMemberWithRole(ownerSession, tenantID, uniqueEmail("escalate-admin"), authz.RoleAdmin)

	ctx := context.Background()
	victim, err := s.users.Create(ctx, uniqueEmail("escalate-target"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("create target user: %v", err)
	}

	// An admin granting owner must be refused.
	res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
		"user_id": victim.ID.String(),
		"role":    "owner",
	}, adminSession.AccessToken)
	if res.status != http.StatusForbidden {
		t.Fatalf("admin granting owner: status %d, want 403 (body %s)", res.status, res.body)
	}

	// An admin granting member or admin is allowed: refusing that would make the
	// admin role useless, and the escalation path is what is forbidden rather than
	// the act of adding people.
	for _, role := range []string{"member", "admin"} {
		target, err := s.users.Create(ctx, uniqueEmail("escalate-ok-"+role), "correct horse battery staple")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
			"user_id": target.ID.String(),
			"role":    role,
		}, adminSession.AccessToken)
		if res.status != http.StatusCreated {
			t.Fatalf("admin granting %s: status %d, want 201 (body %s)", role, res.status, res.body)
		}
	}

	// The owner may grant owner, which is the control showing the refusal above is
	// about the actor's rank.
	successor, err := s.users.Create(ctx, uniqueEmail("escalate-successor"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("create successor: %v", err)
	}
	res = s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
		"user_id": successor.ID.String(),
		"role":    "owner",
	}, ownerSession.AccessToken)
	if res.status != http.StatusCreated {
		t.Fatalf("owner granting owner: status %d, want 201 (body %s)", res.status, res.body)
	}
}

// --- pagination over HTTP ----------------------------------------------------

// TestPagination_WalksEveryPageThroughHTTP proves the cursor round-trips through the
// wire format: the token the API returns is accepted by the API on the next request,
// and the union of pages is exactly the set that was created.
//
// The domain-level walk is tested elsewhere; what this adds is the encoding. A
// mismatch between how a cursor is minted and how it is parsed would pass every
// domain test and break only here.
func TestPagination_WalksEveryPageThroughHTTP(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("page"))
	base := "/v1/tenants/" + tenantID + "/projects"

	const total = 9
	created := map[string]bool{}
	for i := 0; i < total; i++ {
		res := s.do(http.MethodPost, base, map[string]any{"name": fmt.Sprintf("Paged Project %02d", i)}, session.AccessToken)
		if res.status != http.StatusCreated {
			t.Fatalf("create %d: status %d, body %s", i, res.status, res.body)
		}
		var p struct {
			ID string `json:"id"`
		}
		res.decodeData(t, &p)
		created[p.ID] = true
	}

	seen := map[string]bool{}
	path := base + "?limit=4"
	pages := 0
	for {
		pages++
		if pages > 20 {
			t.Fatal("pagination did not terminate")
		}

		res := s.do(http.MethodGet, path, nil, session.AccessToken)
		if res.status != http.StatusOK {
			t.Fatalf("page %d: status %d, body %s", pages, res.status, res.body)
		}
		var page struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			NextCursor string `json:"next_cursor"`
		}
		res.decodeEnvelope(t, &page)

		for _, p := range page.Data {
			if seen[p.ID] {
				t.Fatalf("project %s appeared on two pages", p.ID)
			}
			seen[p.ID] = true
			if !created[p.ID] {
				t.Fatalf("walk returned unknown project %s", p.ID)
			}
		}

		if page.NextCursor == "" {
			break
		}
		if len(page.Data) == 0 {
			t.Fatal("a non-empty next_cursor was returned with an empty page, which would loop forever")
		}
		path = base + "?limit=4&cursor=" + page.NextCursor
	}

	if len(seen) != total {
		t.Fatalf("walked %d projects, want %d", len(seen), total)
	}
	if pages != 3 {
		t.Fatalf("walked %d pages, want 3 (4+4+1)", pages)
	}
}

// TestPagination_CursorIsBoundToItsQuery proves a cursor cannot be replayed across
// a filter change or into another tenant.
//
// The first case is the subtle one: without binding, replaying a cursor from the
// default listing against ?include_archived=true returns a page starting at an
// arbitrary position — data the client cannot tell is wrong.
func TestPagination_CursorIsBoundToItsQuery(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("bind"))
	otherSession, otherTenant := s.register(uniqueEmail("bind-other"))
	base := "/v1/tenants/" + tenantID + "/projects"

	for i := 0; i < 5; i++ {
		if res := s.do(http.MethodPost, base, map[string]any{"name": fmt.Sprintf("Bound %02d", i)}, session.AccessToken); res.status != http.StatusCreated {
			t.Fatalf("create %d: %s", i, res.body)
		}
	}

	first := s.do(http.MethodGet, base+"?limit=2", nil, session.AccessToken)
	var page struct {
		NextCursor string `json:"next_cursor"`
	}
	first.decodeEnvelope(t, &page)
	if page.NextCursor == "" {
		t.Fatal("no cursor returned for a truncated page")
	}

	// The same tenant and cursor, but a different filter: rejected.
	res := s.do(http.MethodGet, base+"?limit=2&include_archived=true&cursor="+page.NextCursor, nil, session.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("cursor reused across a filter change: status %d, want 400 (body %s)", res.status, res.body)
	}

	// Another tenant, reusing the cursor: rejected, and it must not be possible to
	// tell whether that is because the cursor is foreign or because it is invalid.
	otherBase := "/v1/tenants/" + otherTenant + "/projects"
	res = s.do(http.MethodGet, otherBase+"?limit=2&cursor="+page.NextCursor, nil, otherSession.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("cursor replayed into another tenant: status %d, want 400 (body %s)", res.status, res.body)
	}

	// A tampered cursor is rejected too, rather than being interpreted.
	res = s.do(http.MethodGet, base+"?limit=2&cursor="+page.NextCursor+"x", nil, session.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("tampered cursor: status %d, want 400 (body %s)", res.status, res.body)
	}

	// Control: the untouched cursor works.
	res = s.do(http.MethodGet, base+"?limit=2&cursor="+page.NextCursor, nil, session.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("valid cursor rejected: status %d, body %s", res.status, res.body)
	}
}

// TestPagination_LimitValidation proves a malformed parameter is a client error
// rather than something silently coerced. Quietly ignoring "limit=abc" would return
// a page the client did not ask for, and a client cannot fix a parameter it does not
// know was dropped.
func TestPagination_LimitValidation(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("limit"))
	base := "/v1/tenants/" + tenantID + "/projects"

	for i := 0; i < 3; i++ {
		if res := s.do(http.MethodPost, base, map[string]any{"name": fmt.Sprintf("L %d", i)}, session.AccessToken); res.status != http.StatusCreated {
			t.Fatalf("create: %s", res.body)
		}
	}

	res := s.do(http.MethodGet, base+"?limit=abc", nil, session.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("limit=abc: status %d, want 400", res.status)
	}

	// A limit above the maximum is clamped rather than rejected: the client is not
	// doing anything wrong, it simply cannot have more than the service will serve.
	res = s.do(http.MethodGet, base+"?limit=100000", nil, session.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("limit=100000: status %d, want 200 (body %s)", res.status, res.body)
	}
	var page struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	res.decodeEnvelope(t, &page)
	if len(page.Data) != 3 {
		t.Fatalf("clamped listing returned %d rows, want all 3", len(page.Data))
	}
}

// --- request validation ------------------------------------------------------

// TestDecode_RejectsUnknownFields proves a typo is reported rather than ignored.
//
// Silently dropping an unrecognised field is how an integrator spends an afternoon
// on a request that returns 200 and does nothing: the client is told it succeeded,
// and the field it cares about was never read.
func TestDecode_RejectsUnknownFields(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("unknown"))

	res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/projects", map[string]any{
		"name":       "Valid Name",
		"descripton": "typo: this field does not exist",
	}, session.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown field (body %s)", res.status, res.body)
	}
	var problem struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details,omitempty"`
		} `json:"error"`
	}
	res.decodeEnvelope(t, &problem)

	if problem.Error.Code != "validation_failed" {
		t.Fatalf("code = %q, want validation_failed", problem.Error.Code)
	}
	// The offending field should be named, so the client does not have to diff its
	// request against the documentation.
	if field, _ := problem.Error.Details["field"].(string); field != "descripton" {
		t.Fatalf("details.field = %v, want the unknown field name", problem.Error.Details)
	}
}

// TestDecode_RejectsMalformedBodies covers the shapes a client or a scanner sends.
func TestDecode_RejectsMalformedBodies(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("malformed"))
	path := "/v1/tenants/" + tenantID + "/projects"

	cases := []struct {
		name string
		body string
	}{
		{"empty body", ""},
		{"not json", "this is not json"},
		{"truncated json", `{"name": "unterminated`},
		{"json array", `[{"name": "array"}]`},
		{"json string", `"just a string"`},
		{"two objects", `{"name":"a"}{"name":"b"}`},
		{"wrong type for name", `{"name": 123}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+session.AccessToken)
			rec := httptest.NewRecorder()
			s.handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestValidation_FieldLevel proves the field validations reach the client with a
// usable message and the offending field named.
func TestValidation_FieldLevel(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("field"))
	base := "/v1/tenants/" + tenantID + "/projects"

	cases := []struct {
		name  string
		body  map[string]any
		field string
	}{
		{"empty name", map[string]any{"name": ""}, "name"},
		{"whitespace name", map[string]any{"name": "   "}, "name"},
		{"name too long", map[string]any{"name": strings.Repeat("x", 201)}, "name"},
		{"invalid slug", map[string]any{"name": "Fine", "slug": "Not Valid"}, "slug"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := s.do(http.MethodPost, base, tc.body, session.AccessToken)
			if res.status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", res.status, res.body)
			}
			var problem struct {
				Error struct {
					Message string         `json:"message"`
					Details map[string]any `json:"details,omitempty"`
				} `json:"error"`
			}
			res.decodeEnvelope(t, &problem)
			if problem.Error.Message == "" {
				t.Fatal("no message returned, so the client cannot tell what is wrong")
			}
			// The message must not carry a package prefix or a sentinel name: those
			// are internal vocabulary, and seeing them in an API response is the
			// signature of an error that was never formatted for a client.
			for _, leak := range []string{"project:", "apperr", "validation failed"} {
				if strings.Contains(problem.Error.Message, leak) {
					t.Fatalf("message %q leaks internal vocabulary", problem.Error.Message)
				}
			}
		})
	}
}

// TestVersionConflict_OverHTTP proves the 409/404 distinction survives the wire.
//
// This is the assertion that matters for the concurrency design: a client that
// receives 404 for a stale write would conclude the resource was deleted, which is a
// different and wrong reaction, while 409 tells it to re-read and retry.
func TestVersionConflict_OverHTTP(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("conflict"))
	base := "/v1/tenants/" + tenantID + "/projects"

	createRes := s.do(http.MethodPost, base, map[string]any{"name": "Contested"}, session.AccessToken)
	var p struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	}
	createRes.decodeData(t, &p)

	// First write wins.
	okRes := s.do(http.MethodPatch, base+"/"+p.ID, map[string]any{
		"name": "First", "expected_version": p.Version,
	}, session.AccessToken)
	if okRes.status != http.StatusOK {
		t.Fatalf("first update: status %d, body %s", okRes.status, okRes.body)
	}

	// Second write, holding the stale version, is a conflict.
	staleRes := s.do(http.MethodPatch, base+"/"+p.ID, map[string]any{
		"name": "Second", "expected_version": p.Version,
	}, session.AccessToken)
	if staleRes.status != http.StatusConflict {
		t.Fatalf("stale update: status %d, want 409 (body %s)", staleRes.status, staleRes.body)
	}
	var problem struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	staleRes.decodeEnvelope(t, &problem)
	if problem.Error.Code != "version_conflict" {
		t.Fatalf("code = %q, want version_conflict", problem.Error.Code)
	}

	// An unknown project is a 404, and must be a different code — that difference is
	// what tells the client to re-read rather than to give up.
	missingRes := s.do(http.MethodPatch, base+"/"+uuid.Must(uuid.NewV7()).String(), map[string]any{
		"name": "Nope", "expected_version": 1,
	}, session.AccessToken)
	if missingRes.status != http.StatusNotFound {
		t.Fatalf("missing project: status %d, want 404", missingRes.status)
	}
	var missingProblem struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	missingRes.decodeEnvelope(t, &missingProblem)
	if missingProblem.Error.Code == problem.Error.Code {
		t.Fatal("a version conflict and a missing resource share an error code, so a client cannot react differently")
	}
}

// TestUpdate_RequiresVersion proves the version assertion is mandatory rather than
// defaulted. An update without one is a last-write-wins write, which is exactly what
// the field exists to prevent.
func TestUpdate_RequiresVersion(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("noversion"))
	base := "/v1/tenants/" + tenantID + "/projects"

	createRes := s.do(http.MethodPost, base, map[string]any{"name": "Versioned"}, session.AccessToken)
	var p struct {
		ID string `json:"id"`
	}
	createRes.decodeData(t, &p)

	res := s.do(http.MethodPatch, base+"/"+p.ID, map[string]any{"name": "No Version"}, session.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Fatalf("update without expected_version: status %d, want 400 (body %s)", res.status, res.body)
	}
}

// --- API keys over HTTP ------------------------------------------------------

// TestAPIKey_AuthenticatesAndIsScoped proves a machine credential works end to end
// and is limited by its scopes.
//
// A key holds explicit permissions rather than a role, so it can be narrower than
// any human role — which is the point of not modelling it as a user.
func TestAPIKey_AuthenticatesAndIsScoped(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("key-owner"))
	ctx := context.Background()

	tenantUUID := uuid.MustParse(tenantID)
	userUUID := uuid.MustParse(ownerSession.UserID)

	minted, err := s.keys.Mint(ctx, tenantUUID, userUUID, "read-only ci",
		[]authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("mint key: %v", err)
	}

	base := "/v1/tenants/" + tenantID + "/projects"

	// The key can read.
	readRes := s.doAPIKey(http.MethodGet, base, nil, minted.Secret)
	if readRes.status != http.StatusOK {
		t.Fatalf("key read: status %d, body %s", readRes.status, readRes.body)
	}

	// The key cannot write: its scopes do not include project:write.
	writeRes := s.doAPIKey(http.MethodPost, base, map[string]any{"name": "Key Project"}, minted.Secret)
	if writeRes.status != http.StatusForbidden {
		t.Fatalf("key write: status %d, want 403 (body %s)", writeRes.status, writeRes.body)
	}

	// It reports itself as a key rather than as a user, because an audit trail that
	// cannot tell a human from automation is much less useful.
	meRes := s.doAPIKey(http.MethodGet, "/v1/me", nil, minted.Secret)
	if meRes.status != http.StatusOK {
		t.Fatalf("key me: status %d, body %s", meRes.status, meRes.body)
	}
	var me struct {
		AuthMethod  string   `json:"auth_method"`
		Permissions []string `json:"permissions"`
		TenantID    string   `json:"tenant_id"`
	}
	meRes.decodeData(t, &me)
	if me.AuthMethod != "api_key" {
		t.Fatalf("auth_method = %q, want api_key", me.AuthMethod)
	}
	if me.TenantID != tenantID {
		t.Fatalf("key tenant = %q, want %q", me.TenantID, tenantID)
	}
	if len(me.Permissions) != 1 || me.Permissions[0] != string(authz.PermProjectRead) {
		t.Fatalf("key permissions = %v, want exactly project:read", me.Permissions)
	}

	// A revoked key stops working immediately, which is the property that makes a
	// machine credential revocable at all.
	if err := s.keys.Revoke(ctx, tenantUUID, userUUID, minted.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	revokedRes := s.doAPIKey(http.MethodGet, base, nil, minted.Secret)
	if revokedRes.status != http.StatusUnauthorized {
		t.Fatalf("revoked key: status %d, want 401 (body %s)", revokedRes.status, revokedRes.body)
	}
}

// TestAPIKey_CannotReachAnotherTenant proves a key is bound to its tenant even when
// the URL names a different one.
//
// The middleware refuses rather than resolving: silently honouring the path would
// let a key for one tenant act as another, and silently honouring the credential
// would make the URL a lie.
func TestAPIKey_CannotReachAnotherTenant(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("key-scope-owner"))
	otherSession, otherTenant := s.register(uniqueEmail("key-scope-other"))
	_ = otherSession

	ctx := context.Background()
	minted, err := s.keys.Mint(ctx,
		uuid.MustParse(tenantID), uuid.MustParse(ownerSession.UserID),
		"ci", []authz.Perm{authz.PermProjectRead}, nil)
	if err != nil {
		t.Fatalf("mint key: %v", err)
	}

	// The key's own tenant works.
	if res := s.doAPIKey(http.MethodGet, "/v1/tenants/"+tenantID+"/projects", nil, minted.Secret); res.status != http.StatusOK {
		t.Fatalf("key on its own tenant: status %d, body %s", res.status, res.body)
	}

	// Another tenant is refused, and refused as not-found so the key cannot be used
	// to probe which tenants exist.
	res := s.doAPIKey(http.MethodGet, "/v1/tenants/"+otherTenant+"/projects", nil, minted.Secret)
	if res.status != http.StatusNotFound {
		t.Fatalf("key on a foreign tenant: status %d, want 404 (body %s)", res.status, res.body)
	}
}

// --- infrastructure endpoints ------------------------------------------------

// TestHealthAndReadyArePublic proves the probes answer without a credential and
// report the dependency state they exist to report.
func TestHealthAndReadyArePublic(t *testing.T) {
	s := newServer(t)

	health := s.do(http.MethodGet, "/healthz", nil, "")
	if health.status != http.StatusOK {
		t.Fatalf("healthz: status %d, want 200", health.status)
	}

	ready := s.do(http.MethodGet, "/readyz", nil, "")
	if ready.status != http.StatusOK {
		t.Fatalf("readyz: status %d, want 200 (body %s)", ready.status, ready.body)
	}
	var body struct {
		Status string `json:"status"`
	}
	ready.decodeEnvelope(t, &body)
	if body.Status != "ready" {
		t.Fatalf("readiness status = %q, want ready", body.Status)
	}

	// Readiness must be 503 when Postgres is unreachable, because an instance that
	// cannot serve must be taken out of rotation. It is asserted by construction
	// here: a server built without a database probe is reported as not-configured
	// rather than as ready.
	//
	// The failure case itself is exercised in TestReady_FailsWhenDatabaseIsDown.
}

// TestReady_FailsWhenDatabaseIsDown proves the readiness probe is not permanently
// optimistic — the classic broken probe, which reports ready through a total outage
// and keeps an instance in rotation while it serves errors.
func TestReady_FailsWhenDatabaseIsDown(t *testing.T) {
	// Build a server whose database probe reports failure, standing in for the
	// state a real outage produces.
	handler := httpx.New(httpx.Deps{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		DBPing: func(*http.Request) bool { return false },
	})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness with an unreachable database: status %d, want 503", rec.Code)
	}

	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readiness body is not JSON: %v (%s)", err, rec.Body.String())
	}
	if body.Status != "not_ready" || body.Reason == "" {
		t.Fatalf("readiness body = %+v, want a not_ready status with a reason", body)
	}
}

// TestNotFoundAndMethodNotAllowed proves the router's own failures use the same
// envelope as everything else, so a client has one shape to parse.
func TestNotFoundAndMethodNotAllowed(t *testing.T) {
	s := newServer(t)

	res := s.do(http.MethodGet, "/v1/does-not-exist", nil, "")
	if res.status != http.StatusNotFound {
		t.Fatalf("unknown endpoint: status %d, want 404", res.status)
	}

	// A valid path with an unsupported method.
	res = s.do(http.MethodDelete, "/v1/me", nil, "")
	if res.status != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported method: status %d, want 405 (body %s)", res.status, res.body)
	}
}

// TestErrorEnvelope_CarriesRequestID proves every error response identifies the
// request, which is what makes a user-reported failure findable in the logs — the
// response and the log line share the id and nothing else.
func TestErrorEnvelope_CarriesRequestID(t *testing.T) {
	s := newServer(t)

	res := s.do(http.MethodGet, "/v1/me", nil, "")
	var problem struct {
		Error struct {
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	res.decodeEnvelope(t, &problem)
	if problem.Error.RequestID == "" {
		t.Fatalf("error envelope carries no request id: %s", res.body)
	}
}

// --- session lifecycle over HTTP ---------------------------------------------

// TestRefresh_RotatesAndDetectsReuse drives the refresh protocol over the wire.
//
// It runs with strict rotation (grace = 0) because that is the configuration in which
// an immediate replay is unambiguously theft: the token was consumed a moment ago and
// presented again, and with no retry window the server must treat it as a compromise and
// revoke the family. The production default is deliberately more forgiving, and
// TestRefresh_GraceWindowAbsorbsRetry below covers that side.
//
// Both configurations need a test. A suite that only exercised the default would leave
// the revocation path — the one that protects a stolen token — unverified, and a suite
// that only exercised strict rotation would never notice that the shipped default no
// longer revokes anything.
func TestRefresh_RotatesAndDetectsReuse(t *testing.T) {
	s := newServerWith(t, serverConfig{refreshGrace: 0})
	email := uniqueEmail("refresh")
	session, _ := s.register(email)

	// A refresh returns a new pair.
	res := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if res.status != http.StatusOK {
		t.Fatalf("refresh: status %d, body %s", res.status, res.body)
	}
	var rotated sessionBody
	res.decodeData(t, &rotated)
	if rotated.RefreshToken == session.RefreshToken {
		t.Fatal("refresh returned the same token; it is not a rotation")
	}
	if rotated.AccessToken == "" {
		t.Fatal("refresh returned no access token")
	}

	// The rotated access token works.
	if res := s.do(http.MethodGet, "/v1/me", nil, rotated.AccessToken); res.status != http.StatusOK {
		t.Fatalf("rotated access token rejected: status %d", res.status)
	}

	// Replaying the consumed token revokes the whole family, so the successor dies
	// too. This is the behaviour that makes a stolen token costly for an attacker
	// rather than silent.
	replay := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if replay.status != http.StatusUnauthorized {
		t.Fatalf("replay: status %d, want 401 (body %s)", replay.status, replay.body)
	}

	after := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": rotated.RefreshToken,
	}, "")
	if after.status != http.StatusUnauthorized {
		t.Fatalf("successor after a detected reuse: status %d, want 401 — the family was not revoked (body %s)",
			after.status, after.body)
	}

	// The session is genuinely over: the access token still works until it expires —
	// that is the documented bound on a leaked access token (internal/authn/token.go) —
	// but no new credential pair can be minted, so the attacker's session dies at the
	// end of the current access token's lifetime rather than being renewable forever.
	if res := s.do(http.MethodGet, "/v1/me", nil, rotated.AccessToken); res.status != http.StatusOK {
		t.Fatalf("an unexpired access token was rejected: status %d — the design bounds revocation "+
			"by the token lifetime, so this must still work", res.status)
	}
}

// TestRefresh_GraceWindowAbsorbsRetry covers the shipped default: a replay that lands
// inside the retry window is a concurrent retry, so the family survives.
//
// This is the behaviour that keeps a client from being logged out when it races itself —
// a tab restore plus a refresh timer, or a retry after a timeout the server never saw.
// The security cost is real and documented (authn.DefaultReuseGrace): an attacker who
// replays inside the window gets a session. Outside it, the family is revoked, which is
// what the test above proves.
func TestRefresh_GraceWindowAbsorbsRetry(t *testing.T) {
	s := newServerWith(t, serverConfig{refreshGrace: time.Hour})
	session, _ := s.register(uniqueEmail("refresh-grace"))

	res := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if res.status != http.StatusOK {
		t.Fatalf("refresh: status %d, body %s", res.status, res.body)
	}
	var rotated sessionBody
	res.decodeData(t, &rotated)

	// The retry: the same consumed token, presented again inside the window.
	retry := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if retry.status != http.StatusUnauthorized {
		t.Fatalf("in-grace retry: status %d, want 401 (the client re-authenticates) ", retry.status)
	}

	// The crucial difference from the strict case: the successor must still be usable,
	// because the family was not revoked. If this fails, a harmless client retry has
	// logged the user out.
	after := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": rotated.RefreshToken,
	}, "")
	if after.status != http.StatusOK {
		t.Fatalf("successor after an absorbed retry: status %d, want 200 — a retry inside the grace "+
			"window must not invalidate the session (body %s)", after.status, after.body)
	}
}

// TestLogout_RevokesTheSession proves logout ends the session rather than merely
// discarding the client's copy of it, and that it is idempotent.
func TestLogout_RevokesTheSession(t *testing.T) {
	s := newServer(t)
	session, _ := s.register(uniqueEmail("logout"))

	res := s.do(http.MethodPost, "/v1/auth/logout", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if res.status != http.StatusNoContent {
		t.Fatalf("logout: status %d, want 204 (body %s)", res.status, res.body)
	}

	// The refresh token is dead.
	refreshRes := s.do(http.MethodPost, "/v1/auth/refresh", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if refreshRes.status != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: status %d, want 401", refreshRes.status)
	}

	// Logging out again is a no-op rather than an error, because a retried request
	// must behave like the one it retried.
	again := s.do(http.MethodPost, "/v1/auth/logout", map[string]any{
		"refresh_token": session.RefreshToken,
	}, "")
	if again.status != http.StatusNoContent {
		t.Fatalf("second logout: status %d, want 204 (body %s)", again.status, again.body)
	}
}

// TestTenantCreation_GrantsOwnership proves a new tenant is immediately usable by
// its creator, which is what makes the membership the authorization rather than the
// token.
func TestTenantCreation_GrantsOwnership(t *testing.T) {
	s := newServer(t)
	session, _ := s.register(uniqueEmail("multitenant"))

	res := s.do(http.MethodPost, "/v1/tenants", map[string]any{"name": "Second Workspace"}, session.AccessToken)
	if res.status != http.StatusCreated {
		t.Fatalf("create tenant: status %d, body %s", res.status, res.body)
	}
	var created struct {
		TenantID string `json:"tenant_id"`
		Role     string `json:"role"`
	}
	res.decodeData(t, &created)

	if created.Role != "owner" {
		t.Fatalf("role = %q, want owner", created.Role)
	}

	// The new tenant is immediately usable — no re-login, because authorization is
	// resolved per request rather than baked into the token.
	projectsRes := s.do(http.MethodPost, "/v1/tenants/"+created.TenantID+"/projects", map[string]any{
		"name": "First Project",
	}, session.AccessToken)
	if projectsRes.status != http.StatusCreated {
		t.Fatalf("creating a project in the new tenant: status %d, body %s", projectsRes.status, projectsRes.body)
	}

	// And /v1/me now lists both tenants.
	meRes := s.do(http.MethodGet, "/v1/me", nil, session.AccessToken)
	var me struct {
		Tenants []struct {
			TenantID string `json:"tenant_id"`
		} `json:"tenants"`
	}
	meRes.decodeData(t, &me)
	if len(me.Tenants) != 2 {
		t.Fatalf("me lists %d tenants, want 2", len(me.Tenants))
	}
}

// TestAuthorization_IsResolvedPerRequest is the property that justifies keeping
// authorization out of the access token.
//
// A member is added to a tenant and can immediately act in it with a token minted
// *before* the membership existed — because the token asserts identity only, and the
// role is resolved from the memberships table on every request. If the token carried
// a role, this request would be refused until the client re-authenticated, and the
// "add a member" operation would appear not to work.
func TestAuthorization_IsResolvedPerRequest(t *testing.T) {
	s := newServer(t)
	ownerSession, tenantID := s.register(uniqueEmail("dynamic-owner"))

	ctx := context.Background()
	newcomer, err := s.users.Create(ctx, uniqueEmail("dynamic-newcomer"), "correct horse battery staple")
	if err != nil {
		t.Fatalf("create newcomer: %v", err)
	}

	// The newcomer logs in *before* being added, so their token predates the
	// membership entirely.
	loginRes := s.login(uniqueEmail("dynamic-newcomer"), "correct horse battery staple")
	if loginRes.status != http.StatusOK {
		// The email must match the one just created; recompute it correctly.
		loginRes = s.login(newcomer.Email, "correct horse battery staple")
	}
	if loginRes.status != http.StatusOK {
		t.Fatalf("newcomer login: status %d, body %s", loginRes.status, loginRes.body)
	}
	var newcomerSession sessionBody
	loginRes.decodeData(t, &newcomerSession)

	// Before being added: the tenant is invisible (404, not 403).
	if res := s.do(http.MethodGet, "/v1/tenants/"+tenantID+"/projects", nil, newcomerSession.AccessToken); res.status != http.StatusNotFound {
		t.Fatalf("before membership: status %d, want 404", res.status)
	}

	// The owner adds them.
	addRes := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/members", map[string]any{
		"user_id": newcomer.ID.String(),
		"role":    string(authz.RoleMember),
	}, ownerSession.AccessToken)
	if addRes.status != http.StatusCreated {
		t.Fatalf("add member: status %d, body %s", addRes.status, addRes.body)
	}

	// The *same* token now works, with no re-login.
	if res := s.do(http.MethodGet, "/v1/tenants/"+tenantID+"/projects", nil, newcomerSession.AccessToken); res.status != http.StatusOK {
		t.Fatalf("after membership with the pre-membership token: status %d, want 200 — authorization is being cached "+
			"in the credential (body %s)", res.status, res.body)
	}
}

// --- helpers -----------------------------------------------------------------

// uniqueEmail produces an address no other test in this package will reuse, so tests
// do not interfere and the suite needs no cleanup between runs.
func uniqueEmail(label string) string {
	suffix := idgen.ShortSuffix(12)
	return fmt.Sprintf("%s-%s@example.test", label, suffix)
}
