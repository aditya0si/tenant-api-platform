package httpx_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/httpx"
	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
	"github.com/aditya0si/tenant-api-platform/internal/ratelimit"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// limitsConfig builds a server whose routes are limited, using test-sized policies.
//
// The production middleware is used unchanged — only the policy numbers differ — so what is
// exercised here is the code that runs in production. A policy with a unique name keeps each
// test's counters isolated in the shared Redis, for the same reason the fixtures use unique
// slugs: the bucket key includes the policy name, so two tests sharing one would interfere
// through a mechanism nobody reading either test could see.
func limitsConfig(t *testing.T) (*httpx.RateLimits, testPolicySet) {
	t.Helper()
	rdb := testsupport.RequireRedis(t)

	set := testPolicySet{
		login:    ratelimit.Policy{Name: "t-login-" + idgen.ShortSuffix(8), Limit: 3, Window: time.Minute},
		register: ratelimit.Policy{Name: "t-reg-" + idgen.ShortSuffix(8), Limit: 2, Window: time.Minute},
		refresh:  ratelimit.Policy{Name: "t-ref-" + idgen.ShortSuffix(8), Limit: 2, Window: time.Minute},
		api:      ratelimit.Policy{Name: "t-api-" + idgen.ShortSuffix(8), Limit: 3, Window: time.Minute},
	}

	return &httpx.RateLimits{
		Login:    ratelimit.New(rdb, set.login, nil),
		Register: ratelimit.New(rdb, set.register, nil),
		Refresh:  ratelimit.New(rdb, set.refresh, nil),
		API:      ratelimit.New(rdb, set.api, nil),
	}, set
}

// testPolicySet holds the policies a test configured, so assertions can name the limit
// rather than restate it.
type testPolicySet struct {
	login, register, refresh, api ratelimit.Policy
}

// doFrom issues a request from a given address.
//
// The address matters because the unauthenticated limits are keyed on it: without controlling
// RemoteAddr every test would share the harness's default and could not show that one caller's
// exhaustion leaves another's budget intact.
func (s *server) doFrom(addr, method, path string, body any, token string) response {
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
	req.RemoteAddr = addr
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return response{status: rec.Code, body: rec.Body.Bytes(), header: rec.Header()}
}

// loginBody is a syntactically valid login attempt that cannot succeed.
//
// The limit is deliberately independent of authentication: it has to reject a
// credential-stuffing run, which by definition never succeeds, so a successful login is not a
// precondition for the limiter to fire.
func loginBody(email string) map[string]any {
	return map[string]any{"email": email, "password": "not-the-password"}
}

// TestRateLimit_LoginIsLimitedPerAddress is the security assertion for the endpoint that
// matters most.
//
// Login is the credential-stuffing surface: an attacker with a password list makes unlimited
// attempts, and there is no credential to key on because the attempts are the attack. Volume
// is the only available signal, so this is what stops it.
func TestRateLimit_LoginIsLimitedPerAddress(t *testing.T) {
	limits, set := limitsConfig(t)
	s := newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace, rateLimits: limits})

	const addr = "198.51.100.10:5000"
	email := uniqueEmail("rl-login")

	for i := 0; i < set.login.Limit; i++ {
		res := s.doFrom(addr, http.MethodPost, "/v1/auth/login", loginBody(email), "")
		if res.status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d of %d was already throttled", i+1, set.login.Limit)
		}
		if got := res.header.Get("X-RateLimit-Limit"); got != strconv.Itoa(set.login.Limit) {
			t.Fatalf("attempt %d: X-RateLimit-Limit = %q, want %d; a client cannot pace itself "+
				"without knowing the limit", i+1, got, set.login.Limit)
		}
	}

	// The attempt past the limit must be refused, and refused cheaply.
	res := s.doFrom(addr, http.MethodPost, "/v1/auth/login", loginBody(email), "")
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("attempt %d returned %d, want 429; a limit that does not refuse is not a limit",
			set.login.Limit+1, res.status)
	}
	if res.header.Get("Retry-After") == "" {
		t.Error("429 carried no Retry-After, so an automated client has to guess when to retry")
	}
	if !strings.Contains(string(res.body), "rate_limited") {
		t.Errorf("429 body did not identify the failure: %s", res.body)
	}

	// A different address is untouched, so the limit is per-caller rather than global.
	other := s.doFrom("203.0.113.20:5000", http.MethodPost, "/v1/auth/login", loginBody(email), "")
	if other.status == http.StatusTooManyRequests {
		t.Fatal("a second address was throttled by the first address's attempts; the limit is " +
			"keyed globally instead of per-caller, which turns the protection into an outage")
	}
}

// TestRateLimit_RegisterIsLimitedPerAddress covers the other unauthenticated write.
//
// Registration is a once-per-user event, so automated signup is unambiguous abuse, and the
// limit can be far tighter than login's without affecting a legitimate user.
func TestRateLimit_RegisterIsLimitedPerAddress(t *testing.T) {
	limits, set := limitsConfig(t)
	s := newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace, rateLimits: limits})

	const addr = "198.51.100.30:5000"

	for i := 0; i < set.register.Limit; i++ {
		res := s.doFrom(addr, http.MethodPost, "/v1/auth/register", map[string]any{
			"email":       uniqueEmail("rl-reg"),
			"password":    "correct horse battery staple",
			"tenant_name": "Rate Limited",
		}, "")
		if res.status == http.StatusTooManyRequests {
			t.Fatalf("registration %d of %d was already throttled", i+1, set.register.Limit)
		}
	}

	res := s.doFrom(addr, http.MethodPost, "/v1/auth/register", map[string]any{
		"email":       uniqueEmail("rl-reg"),
		"password":    "correct horse battery staple",
		"tenant_name": "Rate Limited",
	}, "")
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("registration past the limit returned %d, want 429", res.status)
	}
}

// TestRateLimit_PoliciesHaveIndependentBudgets is the isolation check between policies.
//
// Each endpoint has its own policy and its own budget. If they shared a counter, exhausting
// login attempts would lock a caller out of registration and everything else — the protection
// becoming the outage, and locking out exactly the user who is trying to recover.
//
// Login is genuinely exhausted here, and that is asserted before the isolation claim is made.
// An earlier version of this test hammered an endpoint whose requests were rejected by
// authentication before the limiter ran, so nothing was consumed and the assertion could not
// fail. A test that cannot fail is not a control.
func TestRateLimit_PoliciesHaveIndependentBudgets(t *testing.T) {
	limits, set := limitsConfig(t)
	s := newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace, rateLimits: limits})

	const addr = "198.51.100.40:5000"
	email := uniqueEmail("rl-iso")

	// Exhaust login for this address with requests the limiter actually sees.
	for i := 0; i < set.login.Limit; i++ {
		s.doFrom(addr, http.MethodPost, "/v1/auth/login", loginBody(email), "")
	}
	// Prove the setup worked before asserting on it; otherwise a test that silently consumed
	// nothing would pass while proving nothing.
	if res := s.doFrom(addr, http.MethodPost, "/v1/auth/login", loginBody(email), ""); res.status != http.StatusTooManyRequests {
		t.Fatalf("login was not exhausted by the setup (status %d), so this test cannot show "+
			"that another policy is unaffected", res.status)
	}

	// Registration from the same address must still work: it has its own policy.
	res := s.doFrom(addr, http.MethodPost, "/v1/auth/register", map[string]any{
		"email":       uniqueEmail("rl-iso-reg"),
		"password":    "correct horse battery staple",
		"tenant_name": "Isolation Check",
	}, "")
	if res.status == http.StatusTooManyRequests {
		t.Fatal("registration was refused once the login limit was exhausted; the endpoints " +
			"share a counter instead of having independent budgets, so a throttled caller cannot " +
			"recover through any other route")
	}
}

// TestRateLimit_FailsOpenWhenRedisIsUnreachable is the end-to-end failure-mode test.
//
// It is the one that matters operationally: Redis going down must degrade the protection, not
// the service. The degradation has to be visible in the response, or a client cannot tell an
// unenforced limit from an enforced one.
func TestRateLimit_FailsOpenWhenRedisIsUnreachable(t *testing.T) {
	broken := testsupport.BrokenRedis(t)
	policy := ratelimit.Policy{Name: "t-broken-" + idgen.ShortSuffix(8), Limit: 1, Window: time.Minute}
	limits := &httpx.RateLimits{Login: ratelimit.New(broken, policy, nil)}
	s := newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace, rateLimits: limits})

	const addr = "198.51.100.50:5000"
	email := uniqueEmail("rl-degraded")

	before := testutil.ToFloat64(metrics.RateLimitDegraded)

	// Far past a limit of 1: with Redis unreachable every one must be allowed.
	for i := 0; i < 5; i++ {
		res := s.doFrom(addr, http.MethodPost, "/v1/auth/login", loginBody(email), "")

		if res.status == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was refused while Redis was unreachable; that converts a cache "+
				"outage into a total outage", i+1)
		}
		if res.status >= 500 {
			t.Fatalf("attempt %d returned %d: an unreachable Redis reached the error handler "+
				"instead of being absorbed by the limiter", i+1, res.status)
		}
		if res.header.Get("X-RateLimit-Degraded") != "true" {
			t.Fatalf("attempt %d did not report degradation, so a client believes its requests "+
				"are being counted when they are not", i+1)
		}
	}

	if after := testutil.ToFloat64(metrics.RateLimitDegraded); after <= before {
		t.Fatal("no fail-open decision was counted; a limiter that is silently not limiting is " +
			"indistinguishable from one that is working")
	}
}

// TestRateLimit_APILimitIsKeyedOnTenant checks the authenticated limit's key.
//
// The limit exists to bound what one tenant can cost the others, so the tenant is the unit
// that must be bounded. Keying it per user would let a tenant multiply its share by adding
// members — the noisy-neighbour case the limit is for.
func TestRateLimit_APILimitIsKeyedOnTenant(t *testing.T) {
	limits, set := limitsConfig(t)
	s := newServerWith(t, serverConfig{refreshGrace: authn.DefaultReuseGrace, rateLimits: limits})

	session, tenantID := s.register(uniqueEmail("rl-tenant"))
	path := "/v1/tenants/" + tenantID + "/projects"

	for i := 0; i < set.api.Limit; i++ {
		res := s.do(http.MethodGet, path, nil, session.AccessToken)
		if res.status == http.StatusTooManyRequests {
			t.Fatalf("request %d of %d was already throttled", i+1, set.api.Limit)
		}
	}

	res := s.do(http.MethodGet, path, nil, session.AccessToken)
	if res.status != http.StatusTooManyRequests {
		t.Fatalf("request past the API limit returned %d, want 429", res.status)
	}

	// A different tenant has its own budget — the point of keying on the tenant.
	other := newServerWith(t, serverConfig{
		refreshGrace: authn.DefaultReuseGrace,
		// Deliberately the same limits, so the second tenant shares Redis but must not share
		// the first tenant's counter.
		rateLimits: limits,
	})
	otherSession, otherTenant := other.register(uniqueEmail("rl-tenant2"))

	otherRes := other.do(http.MethodGet, "/v1/tenants/"+otherTenant+"/projects", nil, otherSession.AccessToken)
	if otherRes.status == http.StatusTooManyRequests {
		t.Fatal("a second tenant was throttled by the first tenant's traffic; the limit is not " +
			"keyed on the tenant, so one noisy tenant degrades every other")
	}
}
