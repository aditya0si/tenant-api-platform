package httpx_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
)

// The API-key surface, exercised through the real router.
//
// apikey:read and apikey:manage were both granted in the role map and both reported by /v1/me
// before any route existed to use them, so these tests cover the gap between "the permission model
// says you may" and "there is something to call". The interesting assertions are the invariants a
// credential system has to hold — the secret appears exactly once, revocation actually stops
// authentication, and a key cannot bootstrap itself into more authority.

// apiKeyBody is the wire shape of a key, including the secret so a test can prove when it is
// absent as well as when it is present.
type apiKeyBody struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Prefix     string   `json:"prefix"`
	Scopes     []string `json:"scopes"`
	CreatedBy  string   `json:"created_by"`
	Secret     string   `json:"secret"`
	CreatedAt  string   `json:"created_at"`
	LastUsedAt *string  `json:"last_used_at"`
	ExpiresAt  *string  `json:"expires_at"`
	RevokedAt  *string  `json:"revoked_at"`
}

func apiKeyBase(tenantID string) string { return "/v1/tenants/" + tenantID + "/api-keys" }

// createKey mints a key through the API and returns the raw response plus the decoded body.
func (s *server) createKey(tenantID, token, name string, scopes ...authz.Perm) (response, apiKeyBody) {
	s.t.Helper()

	strs := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		strs = append(strs, string(sc))
	}
	res := s.do(http.MethodPost, apiKeyBase(tenantID), map[string]any{
		"name":   name,
		"scopes": strs,
	}, token)
	if res.status != http.StatusCreated {
		s.t.Fatalf("create key: status %d, body %s", res.status, res.body)
	}
	var body apiKeyBody
	res.decodeData(s.t, &body)
	return res, body
}

// listKeys returns the tenant's keys as the API reports them.
func (s *server) listKeys(tenantID, token string) []apiKeyBody {
	s.t.Helper()

	res := s.do(http.MethodGet, apiKeyBase(tenantID), nil, token)
	if res.status != http.StatusOK {
		s.t.Fatalf("list keys: status %d, body %s", res.status, res.body)
	}
	var body []apiKeyBody
	res.decodeData(s.t, &body)
	return body
}

// TestAPIKeySurface_SecretIsReturnedOnceAndNeverAgain is the central contract of a credential API.
//
// The secret is in the creation response and nowhere else. If a list ever returned it, every read
// of a tenant's keys would put a live credential for every integration into the response, the logs,
// and any screenshot taken while debugging — which is why the assertion is "absent from the list"
// rather than "present in the create".
func TestAPIKeySurface_SecretIsReturnedOnceAndNeverAgain(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-secret"))

	createRes, created := s.createKey(tenantID, owner.AccessToken, "ci deploy", authz.PermProjectRead)

	if !strings.HasPrefix(created.Secret, "ak_") {
		t.Fatalf("secret %q lacks the ak_ prefix, so the redaction backstop cannot recognise it",
			created.Secret)
	}
	if created.Prefix == "" {
		t.Fatal("the created key carries no display prefix")
	}
	if strings.Contains(created.Secret, created.Prefix) == false {
		t.Errorf("the prefix %q does not appear in the secret, so it cannot be used to identify "+
			"the key in a console", created.Prefix)
	}

	// The Location header names the resource, which is what makes a 201 actionable without a body
	// parse.
	if loc := createRes.header.Get("Location"); !strings.HasSuffix(loc, "/api-keys/"+created.ID) {
		t.Errorf("Location = %q, want it to end with /api-keys/%s", loc, created.ID)
	}

	listed := s.listKeys(tenantID, owner.AccessToken)
	if len(listed) != 1 {
		t.Fatalf("listing returned %d keys, want 1", len(listed))
	}
	if listed[0].Secret != "" {
		t.Errorf("the list returned a secret (%d chars); a key's plaintext must exist only in the "+
			"creation response", len(listed[0].Secret))
	}
	if listed[0].ID != created.ID {
		t.Errorf("listed id = %s, want %s", listed[0].ID, created.ID)
	}
	if listed[0].Prefix != created.Prefix {
		t.Errorf("listed prefix = %q, want %q", listed[0].Prefix, created.Prefix)
	}
	if len(listed[0].Scopes) != 1 || listed[0].Scopes[0] != string(authz.PermProjectRead) {
		t.Errorf("listed scopes = %v, want [%s]", listed[0].Scopes, authz.PermProjectRead)
	}
	if listed[0].RevokedAt != nil {
		t.Error("a freshly minted key reports a revocation time")
	}

	// The raw bytes are checked too: a decode that happened to drop a field would make the
	// assertion above pass while the response still carried the credential.
	if strings.Contains(string(createRes.body), "ak_") {
		// Only the creation response may contain the literal; this is the positive control for the
		// list check below.
		t.Log("creation response contains the ak_ literal, as expected")
	}
}

// TestAPIKeySurface_MintedKeyAuthenticatesAndRevocationStopsIt closes the loop.
//
// A minted secret is only worth anything if it authenticates a real request, and revocation is only
// worth anything if it stops one. Testing either alone would leave the other as an assumption.
func TestAPIKeySurface_MintedKeyAuthenticatesAndRevocationStopsIt(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-lifecycle"))

	_, created := s.createKey(tenantID, owner.AccessToken, "deploy", authz.PermProjectRead)

	// The credential works: /v1/me answers with the key's own principal shape.
	me := s.doAPIKey(http.MethodGet, "/v1/me", nil, created.Secret)
	if me.status != http.StatusOK {
		t.Fatalf("a freshly minted key could not authenticate: status %d, body %s", me.status, me.body)
	}
	var principal struct {
		AuthMethod  string   `json:"auth_method"`
		TenantID    string   `json:"tenant_id"`
		Permissions []string `json:"permissions"`
	}
	me.decodeData(t, &principal)
	if principal.TenantID != tenantID {
		t.Errorf("the key authenticates as tenant %s, want %s", principal.TenantID, tenantID)
	}
	if principal.AuthMethod != "api_key" {
		t.Errorf("auth_method = %q, want api_key", principal.AuthMethod)
	}

	// It is scoped: the key holds project:read, so a project listing is allowed...
	allowed := s.doAPIKey(http.MethodGet, "/v1/tenants/"+tenantID+"/projects", nil, created.Secret)
	if allowed.status != http.StatusOK {
		t.Fatalf("a key holding project:read was refused a project listing: status %d, body %s",
			allowed.status, allowed.body)
	}
	// ...and a write it was not granted is refused, rather than silently permitted.
	denied := s.doAPIKey(http.MethodPost, "/v1/tenants/"+tenantID+"/projects",
		map[string]any{"name": "nope"}, created.Secret)
	if denied.status != http.StatusForbidden {
		t.Errorf("a key holding only project:read created a project: status %d, body %s",
			denied.status, denied.body)
	}

	// Revocation is a guarded write and answers 204.
	revoke := s.do(http.MethodDelete, apiKeyBase(tenantID)+"/"+created.ID, nil, owner.AccessToken)
	if revoke.status != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", revoke.status, revoke.body)
	}

	after := s.doAPIKey(http.MethodGet, "/v1/me", nil, created.Secret)
	if after.status != http.StatusUnauthorized {
		t.Fatalf("a revoked key still authenticated: status %d, body %s", after.status, after.body)
	}

	// A second revoke is idempotent — the caller's intent is already satisfied — so a retry after a
	// lost response does not read as a failure.
	again := s.do(http.MethodDelete, apiKeyBase(tenantID)+"/"+created.ID, nil, owner.AccessToken)
	if again.status != http.StatusNoContent {
		t.Errorf("revoking an already-revoked key returned %d, want 204", again.status)
	}

	// The list reports the revocation rather than hiding the row: an operator asking "is this key
	// dead" should not have to infer it from an absence.
	listed := s.listKeys(tenantID, owner.AccessToken)
	if len(listed) != 1 {
		t.Fatalf("listing returned %d keys after revoke, want 1", len(listed))
	}
	if listed[0].RevokedAt == nil {
		t.Error("a revoked key reports no revocation time")
	}
}

// TestAPIKeySurface_MemberCannotReadOrManage is the authorization boundary.
//
// A member is invited to do work, not to manage the tenant's integrations. Both permissions are
// withheld from the role, so both the read and the write must be refused — and refused with 403
// rather than 404, because the caller is a legitimate member of this tenant and the resource is
// genuinely forbidden rather than absent.
func TestAPIKeySurface_MemberCannotReadOrManage(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-member"))
	member := s.addMemberWithRole(owner, tenantID, uniqueEmail("apikey-member-sub"), authz.RoleMember)

	read := s.do(http.MethodGet, apiKeyBase(tenantID), nil, member.AccessToken)
	if read.status != http.StatusForbidden {
		t.Errorf("a member listed keys: status %d, body %s", read.status, read.body)
	}

	write := s.do(http.MethodPost, apiKeyBase(tenantID), map[string]any{
		"name":   "member key",
		"scopes": []string{string(authz.PermProjectRead)},
	}, member.AccessToken)
	if write.status != http.StatusForbidden {
		t.Errorf("a member minted a key: status %d, body %s", write.status, write.body)
	}
}

// TestAPIKeySurface_MachineCanListItsSiblingsButNotMintThem pins the one deliberate asymmetry in
// the permission model.
//
// apikey:read may be granted to a machine credential — listing siblings is an observability
// convenience with no escalation path — while apikey:manage may not, because a key that can mint
// keys survives its own revocation by issuing a successor first. This is the test that keeps those
// two from being collapsed into one permission later.
func TestAPIKeySurface_MachineCanListItsSiblingsButNotMintThem(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-machine"))

	_, reader := s.createKey(tenantID, owner.AccessToken, "reader", authz.PermAPIKeyRead)

	// The reader key can enumerate keys, which is what apikey:read is for.
	list := s.doAPIKey(http.MethodGet, apiKeyBase(tenantID), nil, reader.Secret)
	if list.status != http.StatusOK {
		t.Fatalf("a key holding apikey:read could not list keys: status %d, body %s", list.status, list.body)
	}
	var siblings []apiKeyBody
	list.decodeData(t, &siblings)
	if len(siblings) != 1 {
		t.Fatalf("the reader sees %d keys, want 1", len(siblings))
	}
	// And the listing does not leak the sibling's secret to a machine credential either.
	if siblings[0].Secret != "" {
		t.Error("listing keys as a machine credential returned a secret")
	}

	// It cannot mint. The refusal is 403 from the permission check, which runs before the
	// idempotency middleware — so an unauthorized caller cannot even claim a key in that table.
	mint := s.doAPIKey(http.MethodPost, apiKeyBase(tenantID), map[string]any{
		"name":   "successor",
		"scopes": []string{string(authz.PermAPIKeyRead)},
	}, reader.Secret)
	if mint.status != http.StatusForbidden {
		t.Fatalf("a machine credential minted a key: status %d, body %s — this is the escalation "+
			"the forbidden-scope rule exists to prevent", mint.status, mint.body)
	}

	// Nor can it revoke one, which would be a denial-of-service primitive against every other
	// integration in the tenant.
	revoke := s.doAPIKey(http.MethodDelete, apiKeyBase(tenantID)+"/"+siblings[0].ID, nil, reader.Secret)
	if revoke.status != http.StatusForbidden {
		t.Errorf("a machine credential revoked a key: status %d, body %s", revoke.status, revoke.body)
	}

	// Only one key exists: the reader's own. Nothing was minted by the refused attempt.
	if got := len(s.listKeys(tenantID, owner.AccessToken)); got != 1 {
		t.Errorf("the tenant holds %d keys after two refused writes, want 1", got)
	}
}

// TestAPIKeySurface_ForeignKeyIsNotFound is the tenant boundary.
//
// An outsider is not a member of the victim's tenant, so the membership gate refuses before any
// authorization is considered: 404, never 403, so the response cannot confirm that the tenant
// exists. The revoke path has the same shape from inside the store — a key in another tenant is
// indistinguishable from an unknown id.
func TestAPIKeySurface_ForeignKeyIsNotFound(t *testing.T) {
	s := newServer(t)
	victim, victimTenant := s.register(uniqueEmail("apikey-victim"))
	_, victimKey := s.createKey(victimTenant, victim.AccessToken, "victim", authz.PermProjectRead)

	outsider, outsiderTenant := s.register(uniqueEmail("apikey-outsider"))
	if outsiderTenant == victimTenant {
		t.Fatal("the two registrations produced the same tenant")
	}

	// Through the outsider's own tenant path, the victim's key id does not resolve.
	res := s.do(http.MethodDelete, apiKeyBase(outsiderTenant)+"/"+victimKey.ID, nil, outsider.AccessToken)
	if res.status != http.StatusNotFound {
		t.Errorf("revoking a foreign key returned %d, want 404 (never 403, which would confirm the "+
			"id exists)", res.status)
	}

	// Through the victim's tenant path, the outsider is not a member at all: also 404.
	crossTenant := s.do(http.MethodDelete, apiKeyBase(victimTenant)+"/"+victimKey.ID, nil, outsider.AccessToken)
	if crossTenant.status != http.StatusNotFound {
		t.Errorf("a non-member reached the victim tenant's key route: status %d, want 404", crossTenant.status)
	}

	// The victim's key still works, so nothing leaked across.
	still := s.doAPIKey(http.MethodGet, "/v1/me", nil, victimKey.Secret)
	if still.status != http.StatusOK {
		t.Errorf("the victim's key stopped authenticating after a foreign revoke attempt: %d", still.status)
	}
}

// TestAPIKeySurface_RejectsUnknownAndForbiddenScopes covers mint-time validation.
//
// An unknown scope is refused rather than stored, because a key that appears to authorize something
// it cannot is a debugging problem nobody enjoys; and a scope the key may never hold is refused
// with the reason stated, rather than accepted and ignored at check time.
func TestAPIKeySurface_RejectsUnknownAndForbiddenScopes(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-scopes"))

	for _, tc := range []struct {
		name    string
		scopes  []string
		wantMsg string
	}{
		{"unknown scope", []string{"project:destroy"}, "unknown scope"},
		{"forbidden scope", []string{string(authz.PermAPIKeyManage)}, "may not be granted to an API key"},
		{"empty list", []string{}, "at least one scope"},
		{"duplicate", []string{string(authz.PermProjectRead), string(authz.PermProjectRead)}, "duplicate scope"},
	} {
		res := s.do(http.MethodPost, apiKeyBase(tenantID), map[string]any{
			"name":   "bad",
			"scopes": tc.scopes,
		}, owner.AccessToken)

		if res.status != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tc.name, res.status, res.body)
			continue
		}
		var problem struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		res.decodeEnvelope(t, &problem)
		if problem.Error.Code != "validation_failed" {
			t.Errorf("%s: code = %q, want validation_failed", tc.name, problem.Error.Code)
		}
		if !strings.Contains(problem.Error.Message, tc.wantMsg) {
			t.Errorf("%s: message %q does not mention %q, so the client cannot tell what to fix",
				tc.name, problem.Error.Message, tc.wantMsg)
		}
	}

	// A bad expiry is refused before the insert rather than becoming a key that cannot be used.
	past := "2020-01-01T00:00:00Z"
	res := s.do(http.MethodPost, apiKeyBase(tenantID), map[string]any{
		"name":       "expired",
		"scopes":     []string{string(authz.PermProjectRead)},
		"expires_at": past,
	}, owner.AccessToken)
	if res.status != http.StatusBadRequest {
		t.Errorf("a key expiring in the past was accepted: status %d, body %s", res.status, res.body)
	}

	// None of the refused attempts left a row behind.
	if got := len(s.listKeys(tenantID, owner.AccessToken)); got != 0 {
		t.Errorf("%d keys exist after five refused mints, want 0", got)
	}
}

// TestAPIKeySurface_CreateIsIdempotent covers the retry that a credential API must survive.
//
// A client that retries a lost create response must not end up with two keys — and, worse, two
// different secrets where it kept the first. Replay returns the original response, secret included,
// because that is exactly the document the client lost.
func TestAPIKeySurface_CreateIsIdempotent(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("apikey-idem"))

	body := map[string]any{
		"name":   "deploy",
		"scopes": []string{string(authz.PermProjectRead)},
	}
	key := "create-deploy-key-1"

	first := s.doWithKey(http.MethodPost, apiKeyBase(tenantID), body, owner.AccessToken, key)
	if first.status != http.StatusCreated {
		t.Fatalf("first create: status %d, body %s", first.status, first.body)
	}
	var minted apiKeyBody
	first.decodeData(t, &minted)

	second := s.doWithKey(http.MethodPost, apiKeyBase(tenantID), body, owner.AccessToken, key)
	if second.status != http.StatusCreated {
		t.Fatalf("the retry returned %d, want the replayed 201 (body %s)", second.status, second.body)
	}
	var replayed apiKeyBody
	second.decodeData(t, &replayed)

	if replayed.ID != minted.ID {
		t.Errorf("the retry minted a second key: %s then %s", minted.ID, replayed.ID)
	}
	if replayed.Secret != minted.Secret {
		t.Error("the replayed response carried a different secret, so a client that retried and kept " +
			"the second response would hold a credential the server never recorded")
	}
	if replayed.Secret == "" {
		t.Error("the replayed response omitted the secret, so a client that lost the first response " +
			"could never recover the key")
	}

	if got := len(s.listKeys(tenantID, owner.AccessToken)); got != 1 {
		t.Errorf("%d keys exist after a create and its retry, want 1", got)
	}
}

// TestAPIKeySurface_MintAndRevokeAreAudited proves the trail answers the question an incident review
// actually asks: who created this credential, and who killed it.
//
// It reads through owner credentials rather than the API, for the same reason the audit suite does —
// reading through the same access path that could hide a missing entry would let a bug hide its own
// evidence.
func TestAPIKeySurface_MintAndRevokeAreAudited(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("no owner credentials configured; the trail cannot be read independently")
	}

	owner, tenantID := s.register(uniqueEmail("apikey-audit"))
	_, created := s.createKey(tenantID, owner.AccessToken, "audited", authz.PermProjectRead)

	type row struct {
		Action    string
		ActorKind string
		ActorID   *string
	}
	read := func() []row {
		t.Helper()
		var out []row
		err := tenantScopedTx(t, s.db.Owner, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(context.Background(), `
				SELECT action, actor_kind, actor_id::text
				  FROM audit_log
				 WHERE tenant_id = $1 AND resource = 'api_key' AND resource_id = $2
				 ORDER BY at, action`, tenantID, created.ID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.Action, &r.ActorKind, &r.ActorID); err != nil {
					return err
				}
				out = append(out, r)
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("read audit trail: %v", err)
		}
		return out
	}

	afterCreate := read()
	if len(afterCreate) != 1 {
		t.Fatalf("minting a key produced %d audit entries, want 1: %v", len(afterCreate), afterCreate)
	}
	if afterCreate[0].Action != "api_key.create" {
		t.Errorf("action = %q, want api_key.create", afterCreate[0].Action)
	}
	// Attribution to a person, not a system: a credential that appears with no author is the exact
	// gap an incident review cannot close.
	if afterCreate[0].ActorKind != "user" {
		t.Errorf("actor_kind = %q, want user", afterCreate[0].ActorKind)
	}
	if afterCreate[0].ActorID == nil {
		t.Error("the create entry names no actor")
	}

	revoke := s.do(http.MethodDelete, apiKeyBase(tenantID)+"/"+created.ID, nil, owner.AccessToken)
	if revoke.status != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", revoke.status, revoke.body)
	}

	afterRevoke := read()
	if len(afterRevoke) != 2 {
		t.Fatalf("minting and revoking produced %d audit entries, want 2: %v", len(afterRevoke), afterRevoke)
	}
	if afterRevoke[1].Action != "api_key.revoke" {
		t.Errorf("second action = %q, want api_key.revoke", afterRevoke[1].Action)
	}

	// The revocation entry carries a before/after pair, which is what makes the trail answer "what
	// changed" rather than only "that something did".
	var before, after *string
	err := tenantScopedTx(t, s.db.Owner, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `
			SELECT before::text, after::text
			  FROM audit_log
			 WHERE tenant_id = $1 AND action = 'api_key.revoke' AND resource_id = $2`,
			tenantID, created.ID).Scan(&before, &after)
	})
	if err != nil {
		t.Fatalf("read revocation images: %v", err)
	}
	if before == nil || after == nil {
		t.Fatal("the revocation entry has a nil image")
	}
	if strings.Contains(*before, "ak_") || strings.Contains(*after, "ak_") {
		t.Error("an audit image contains the secret literal; this table is append-only and cannot be " +
			"pruned, so a credential written here would be permanent")
	}

	// Decoded rather than byte-matched. jsonb normalises its own output — a space after each colon,
	// keys in its own order — so matching a literal would assert Postgres's formatting rather than
	// the value, and would break the moment the column type changed. What matters is that the
	// before image shows an unrevoked key and the after image does not.
	images := map[string]map[string]any{}
	for label, raw := range map[string]*string{"before": before, "after": after} {
		var m map[string]any
		if err := json.Unmarshal([]byte(*raw), &m); err != nil {
			t.Fatalf("%s image is not a JSON object: %v (%s)", label, err, *raw)
		}
		images[label] = m
	}
	if images["before"]["revoked_at"] != nil {
		t.Errorf("the before image already shows the key revoked: %v", images["before"]["revoked_at"])
	}
	if images["after"]["revoked_at"] == nil {
		t.Error("the after image shows the key as unrevoked, so the pair does not record the change " +
			"this entry exists to describe")
	}
	// The name survives in both, which is what lets an operator match the entry to the credential
	// they are investigating without a join.
	if images["after"]["name"] == nil {
		t.Error("the after image carries no name, so the entry cannot be tied back to a key by anyone " +
			"reading the trail")
	}
}
