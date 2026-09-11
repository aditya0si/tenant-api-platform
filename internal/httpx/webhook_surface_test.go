package httpx_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
)

// The webhook registration surface, exercised through the real router.
//
// There were no HTTP tests over these routes, and the gap was not theoretical: a full-stack smoke
// test against the compose stack found that a blocked delivery target — 169.254.169.254, the cloud
// metadata service — was answered with 500 internal_error. The guard refused the address correctly
// and then the refusal was reported as a failure of this service, which tells a client to retry
// something that can never succeed and withholds the one part the tenant can act on.

func whBase(tenantID string) string { return "/v1/tenants/" + tenantID + "/webhooks" }

// whEndpoint is the wire shape, including the secret so a test can assert when it is absent.
type whEndpoint struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description"`
	Active      bool     `json:"active"`
	Secret      string   `json:"secret"`
	CreatedAt   string   `json:"created_at"`
}

// errProblem is the error envelope, decoded.
type errProblem struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Details map[string]any `json:"details"`
	} `json:"error"`
}

// TestWebhook_RefusedTargetIsAClientError is the regression test for the defect the smoke test
// found.
//
// A tenant-supplied URL that resolves into private space is the tenant's input, not a fault in this
// service. The distinction is not cosmetic: 500 says "try again", 400 with a reason says "fix your
// URL", and only the second is actionable. It also keeps the error budget honest — a dashboard
// counting 5xx would page someone for a tenant's typo.
func TestWebhook_RefusedTargetIsAClientError(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("webhook-ssrf"))

	// Literal addresses, so no DNS is involved and the cases cannot flake on a resolver. Loopback is
	// deliberately absent: the harness builds the guard with ssrf.NewForTests, which permits
	// loopback so a test can point an endpoint at an httptest server. Link-local, RFC1918, and the
	// unspecified address are refused by both constructors, which is what makes them the right
	// cases here.
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://10.0.0.1/internal",
		"http://192.168.1.1/admin",
		"http://[fd00::1]/internal",
		"http://0.0.0.0/",
	} {
		res := s.do(http.MethodPost, whBase(tenantID), map[string]any{
			"url":    target,
			"events": []string{"invoice.created"},
		}, owner.AccessToken)

		if res.status == http.StatusInternalServerError {
			t.Errorf("%s was answered with 500 internal_error; a refused tenant-supplied URL is a "+
				"client error, and a 500 tells the client to retry a request that cannot succeed",
				target)
			continue
		}
		if res.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", target, res.status, res.body)
			continue
		}

		var problem errProblem
		res.decodeEnvelope(t, &problem)

		if problem.Error.Code != "validation_failed" {
			t.Errorf("%s: code = %q, want validation_failed", target, problem.Error.Code)
		}
		// The message must say why. "invalid url" would be true and useless.
		if !strings.Contains(problem.Error.Message, "not publicly routable") {
			t.Errorf("%s: message %q does not explain the refusal", target, problem.Error.Message)
		}
		// It must not leak the internal package prefix: this text is addressed to a tenant.
		if strings.HasPrefix(problem.Error.Message, "ssrf:") {
			t.Errorf("%s: message %q leaks the internal package prefix", target, problem.Error.Message)
		}
		// The failing field is named, so a client can attach the error to the input it came from.
		//
		// The shape is {"field": "url"} — fieldDetails builds it that way centrally, so a client
		// parses one convention rather than one per endpoint. Asserting a bare "url" key here
		// failed against correct code, which is what the first version of this test did.
		if got, ok := problem.Error.Details["field"]; !ok || got != "url" {
			t.Errorf("%s: details = %v, want {\"field\": \"url\"}", target, problem.Error.Details)
		}
	}
}

// TestWebhook_ValidRegistrationReturnsTheSecretOnce is the positive control.
//
// Without it, a handler that refused every registration would satisfy the test above. It also pins
// the one-time-display contract: the signing secret is in the creation response and absent from
// every read, which is the same shape as an API key and for the same reason.
func TestWebhook_ValidRegistrationReturnsTheSecretOnce(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("webhook-valid"))

	// Loopback is permitted by the test guard, so this exercises the whole path including successful
	// SSRF validation rather than stubbing the guard out and testing less than it appears to.
	res := s.do(http.MethodPost, whBase(tenantID), map[string]any{
		"url":         "http://127.0.0.1:9999/hooks/invoice",
		"events":      []string{"invoice.created", "invoice.paid"},
		"description": "test receiver",
	}, owner.AccessToken)

	if res.status != http.StatusCreated {
		t.Fatalf("registration: status %d, body %s", res.status, res.body)
	}
	var created whEndpoint
	res.decodeData(t, &created)

	if !strings.HasPrefix(created.Secret, "whsec_") {
		t.Errorf("secret %q lacks the whsec_ prefix, so a leaked one would not be identifiable as a "+
			"secret at a glance", created.Secret)
	}
	if len(created.Events) != 2 {
		t.Errorf("events = %v, want the two that were subscribed", created.Events)
	}
	if !created.Active {
		t.Error("a new endpoint is inactive, so it would silently never deliver")
	}
	if loc := res.header.Get("Location"); !strings.HasSuffix(loc, "/webhooks/"+created.ID) {
		t.Errorf("Location = %q, want it to end with /webhooks/%s", loc, created.ID)
	}

	// Read it back: the secret must be gone, the configuration must not be.
	got := s.do(http.MethodGet, whBase(tenantID)+"/"+created.ID, nil, owner.AccessToken)
	if got.status != http.StatusOK {
		t.Fatalf("read back: status %d, body %s", got.status, got.body)
	}
	var fetched whEndpoint
	got.decodeData(t, &fetched)

	if fetched.Secret != "" {
		t.Errorf("the read returned a secret (%d chars); a signing key must exist only in the "+
			"creation response", len(fetched.Secret))
	}
	if fetched.URL != created.URL {
		t.Errorf("url = %q, want %q", fetched.URL, created.URL)
	}

	// The listing must hide it too — the likelier leak of the two, since a tenant reads it far more
	// often than it reads any single endpoint.
	list := s.do(http.MethodGet, whBase(tenantID), nil, owner.AccessToken)
	if list.status != http.StatusOK {
		t.Fatalf("list: status %d, body %s", list.status, list.body)
	}
	if strings.Contains(string(list.body), "whsec_") {
		t.Error("the listing response contains a signing secret")
	}
}

// TestWebhook_UnknownEventIsRefused covers the subscription vocabulary.
//
// An endpoint subscribed to a typo would register successfully, look correct, and never fire. That
// is the worst shape of integration bug: nothing errors, and the tenant discovers it as a missing
// webhook days later.
func TestWebhook_UnknownEventIsRefused(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("webhook-events"))

	for _, tc := range []struct {
		name   string
		events []any
	}{
		{"unknown event", []any{"invoice.refunded"}},
		{"wrong case", []any{"Invoice.Paid"}},
		{"empty list", []any{}},
		{"empty entry", []any{""}},
	} {
		res := s.do(http.MethodPost, whBase(tenantID), map[string]any{
			"url":    "http://127.0.0.1:9999/hooks",
			"events": tc.events,
		}, owner.AccessToken)

		if res.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, res.status, res.body)
			continue
		}
		var problem errProblem
		res.decodeEnvelope(t, &problem)
		if problem.Error.Code != "validation_failed" {
			t.Errorf("%s: code = %q, want validation_failed", tc.name, problem.Error.Code)
		}
	}
}

// TestWebhook_MemberCanNeitherReadNorManageEndpoints is the authorization boundary.
//
// A member holds neither webhook:read nor webhook:manage. Registering an endpoint is what
// redirects a tenant's event stream, so it is an exfiltration primitive rather than an
// administrative convenience — and the read is withheld too, because a credential that cannot
// change where data goes has no need to enumerate where it currently goes.
func TestWebhook_MemberCanNeitherReadNorManageEndpoints(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("webhook-member"))
	member := s.addMemberWithRole(owner, tenantID, uniqueEmail("webhook-member-sub"), authz.RoleMember)

	read := s.do(http.MethodGet, whBase(tenantID), nil, member.AccessToken)
	if read.status != http.StatusForbidden {
		t.Errorf("a member read the endpoint list: status %d, want 403 (body %s)", read.status, read.body)
	}

	write := s.do(http.MethodPost, whBase(tenantID), map[string]any{
		"url":    "http://127.0.0.1:9999/hooks",
		"events": []string{"invoice.created"},
	}, member.AccessToken)
	if write.status != http.StatusForbidden {
		t.Errorf("a member registered an endpoint: status %d, want 403 — this is the act that "+
			"redirects a tenant's event stream (body %s)", write.status, write.body)
	}

	// Nothing was created by the refused write.
	if list := s.do(http.MethodGet, whBase(tenantID), nil, owner.AccessToken); !strings.Contains(string(list.body), `"data":[]`) {
		t.Errorf("an endpoint exists after a member's registration was refused: %s", list.body)
	}
}

// TestSession_TenantEntriesCarryPermissions is the regression test for the second defect the smoke
// test found.
//
// The spec, /v1/me, and the session response all describe per-tenant permissions. Only /v1/me
// populated them, so a client reading its capabilities from the login or registration response —
// the natural place, since that is the body it has just parsed — saw an empty list and would
// conclude it may do nothing.
//
// The two responses are compared against each other rather than each against a literal, because the
// failure being prevented is precisely that they drift.
func TestSession_TenantEntriesCarryPermissions(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("session-perms"))

	if len(owner.Tenants) != 1 {
		t.Fatalf("register returned %d tenants, want the one it created", len(owner.Tenants))
	}
	entry := owner.Tenants[0]

	if len(entry.Permissions) == 0 {
		t.Fatalf("a %s's tenant entry in the session carries no permissions, so a client reading its "+
			"capabilities from the registration response would conclude it may do nothing", entry.Role)
	}

	// Every permission the role map grants an owner must be present, checked by name so a truncated
	// list fails here rather than in production.
	got := map[string]bool{}
	for _, p := range entry.Permissions {
		got[p] = true
	}
	for _, p := range authz.Perms(authz.RoleOwner) {
		if !got[string(p)] {
			t.Errorf("the session's permissions omit %q, which an owner holds", p)
		}
	}

	// /v1/me must report the same set for the same tenant: the two endpoints describe one fact.
	meRes := s.do(http.MethodGet, "/v1/me", nil, owner.AccessToken)
	if meRes.status != http.StatusOK {
		t.Fatalf("/v1/me: status %d, body %s", meRes.status, meRes.body)
	}
	var me struct {
		Tenants []struct {
			TenantID    string   `json:"tenant_id"`
			Permissions []string `json:"permissions"`
		} `json:"tenants"`
	}
	meRes.decodeData(t, &me)

	var mePerms []string
	for _, tn := range me.Tenants {
		if tn.TenantID == tenantID {
			mePerms = tn.Permissions
		}
	}
	if len(mePerms) == 0 {
		t.Fatalf("/v1/me reported no permissions for the tenant the session names: %s", meRes.body)
	}

	viaMe := map[string]bool{}
	for _, p := range mePerms {
		viaMe[p] = true
	}
	for p := range got {
		if !viaMe[p] {
			t.Errorf("/v1/me omits %q, which the session reports; the two describe one fact and must "+
				"not drift", p)
		}
	}
	for p := range viaMe {
		if !got[p] {
			t.Errorf("the session omits %q, which /v1/me reports", p)
		}
	}
}
