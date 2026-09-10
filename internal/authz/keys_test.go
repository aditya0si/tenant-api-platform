package authz

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestValidateKeyScopes_AcceptsGrantable proves a key may hold the operational
// permissions it exists for. A validation rule that rejected these would be
// discovered as "keys cannot be created at all", which is a worse failure than it
// sounds because it stops every downstream test.
func TestValidateKeyScopes_AcceptsGrantable(t *testing.T) {
	cases := [][]Perm{
		{PermProjectRead},
		{PermProjectRead, PermProjectWrite},
		{PermInvoiceRead},
		{PermProjectRead, PermInvoiceRead, PermAuditRead},
		{PermAPIKeyRead}, // reading sibling keys is allowed; managing them is not
	}
	for _, scopes := range cases {
		if err := ValidateKeyScopes(scopes); err != nil {
			t.Errorf("ValidateKeyScopes(%v) rejected a grantable set: %v", scopes, err)
		}
	}
}

// TestValidateKeyScopes_RejectsIdentityPermissions is the escalation test.
//
// Each of these is an identity operation. A key holding member:manage can add an
// accomplice; one holding apikey:manage can mint a successor and outlive its own
// revocation; one holding tenant:manage can rewrite the tenant it belongs to.
// None is a capability unattended automation should have, and all are strictly
// worse when the key leaks — which is the event a key's existence assumes will
// eventually happen.
func TestValidateKeyScopes_RejectsIdentityPermissions(t *testing.T) {
	for _, perm := range []Perm{PermMemberManage, PermAPIKeyManage, PermTenantManage} {
		err := ValidateKeyScopes([]Perm{PermProjectRead, perm})
		if err == nil {
			t.Errorf("scope %q was accepted; identity permissions must not be grantable to a key", perm)
			continue
		}
		if !strings.Contains(err.Error(), string(perm)) {
			t.Errorf("error for %q does not name the offending scope: %v", perm, err)
		}
	}
}

// TestValidateKeyScopes_RejectsJunk covers the input-validation arms, each of
// which corresponds to a distinct mistake at a call site.
func TestValidateKeyScopes_RejectsJunk(t *testing.T) {
	cases := []struct {
		name   string
		scopes []Perm
	}{
		// An empty list is rejected rather than accepted as "no permissions": a
		// key that can do nothing is almost always a mistake in the request, and
		// failing at creation beats handing back a credential that 403s on every
		// call it is ever used for.
		{"empty", nil},
		{"empty slice", []Perm{}},
		{"unknown permission", []Perm{Perm("project:destroy")}},
		{"typo", []Perm{Perm("project:reed")}},
		{"duplicate", []Perm{PermProjectRead, PermProjectRead}},
		{"empty string", []Perm{Perm("")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateKeyScopes(tc.scopes); err == nil {
				t.Fatalf("ValidateKeyScopes(%v) accepted invalid input", tc.scopes)
			}
		})
	}
}

// TestKeyGrantablePerms_PartitionsTheModel proves the forbid-list and the
// permission model stay in sync: every permission is either grantable to a key or
// forbidden, never both and never neither.
//
// Without this, adding a permission to the model and forgetting the key policy is
// invisible — the new permission silently becomes grantable, which is how a
// deny-list quietly stops denying.
func TestKeyGrantablePerms_PartitionsTheModel(t *testing.T) {
	grantable := map[Perm]bool{}
	for _, p := range KeyGrantablePerms() {
		if grantable[p] {
			t.Errorf("%s appears twice in the grantable set", p)
		}
		grantable[p] = true
	}

	all := AllPerms()
	if len(grantable)+3 != len(all) {
		// Three forbidden permissions today. If this fires, a permission was added
		// or removed without deciding whether a key may hold it.
		t.Fatalf("grantable=%d, all=%d, forbidden=3: the partition is broken — every permission needs an explicit decision",
			len(grantable), len(all))
	}

	for _, p := range all {
		_, forbidden := KeyForbiddenReason(p)
		if forbidden && grantable[p] {
			t.Errorf("%s is both forbidden and grantable", p)
		}
		if !forbidden && !grantable[p] {
			t.Errorf("%s is neither forbidden nor grantable", p)
		}
	}
}

// TestKeyForbiddenReason_Explains thinks about the maintainer. A deny-list entry
// whose reason is empty gives the next reader no way to judge whether it still
// applies, and the safe-looking move is to leave it forever.
func TestKeyForbiddenReason_Explains(t *testing.T) {
	for _, p := range AllPerms() {
		reason, forbidden := KeyForbiddenReason(p)
		if !forbidden {
			continue
		}
		if len(strings.TrimSpace(reason)) < 20 {
			t.Errorf("forbidden permission %q has no substantive reason: %q", p, reason)
		}
	}
}

// TestPrincipal_Allows covers the two authorization shapes.
func TestPrincipal_Allows(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	session := Principal{
		UserID:   userID,
		TenantID: tenantID,
		Role:     RoleAdmin,
		Method:   MethodJWT,
	}
	key := Principal{
		TenantID: tenantID,
		Scopes:   []Perm{PermProjectRead, PermInvoiceRead},
		Method:   MethodAPIKey,
	}

	cases := []struct {
		name      string
		principal Principal
		perm      Perm
		want      bool
	}{
		{"session admin writes projects", session, PermProjectWrite, true},
		{"session admin cannot manage tenant", session, PermTenantManage, false},
		{"key reads projects", key, PermProjectRead, true},
		{"key cannot write projects", key, PermProjectWrite, false},
		{"key cannot manage members", key, PermMemberManage, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.principal.Allows(tc.perm); got != tc.want {
				t.Fatalf("Allows(%s) = %v, want %v", tc.perm, got, tc.want)
			}
		})
	}

	// An unenriched session principal — what authentication alone produces — must
	// deny everything, because a permission cannot be evaluated without a role.
	unenriched := Principal{UserID: userID, Method: MethodJWT}
	for _, p := range AllPerms() {
		if unenriched.Allows(p) {
			t.Fatalf("an unenriched session principal allowed %s; authentication alone must not authorize", p)
		}
	}
	if unenriched.Resolved() {
		t.Fatal("an unenriched session principal reports itself resolved")
	}

	// An unrecognised method denies even with a role and scopes present, which is
	// the fail-closed arm for a future code path that forgets to set one.
	unknown := Principal{
		TenantID: tenantID,
		Role:     RoleOwner,
		Scopes:   []Perm{PermTenantManage},
		Method:   AuthMethod("magic"),
	}
	for _, p := range AllPerms() {
		if unknown.Allows(p) {
			t.Fatalf("principal with an unknown auth method allowed %s", p)
		}
	}
}

// TestPrincipal_WithResolvedTenant covers the enrichment seam and the two rules
// that make it safe.
func TestPrincipal_WithResolvedTenant(t *testing.T) {
	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())

	session := Principal{UserID: userID, Method: MethodJWT}
	enriched := session.WithResolvedTenant(tenantA, RoleMember)

	if enriched.TenantID != tenantA {
		t.Fatalf("tenant = %s, want %s", enriched.TenantID, tenantA)
	}
	if enriched.Role != RoleMember {
		t.Fatalf("role = %s, want member", enriched.Role)
	}
	if !enriched.Resolved() {
		t.Fatal("an enriched principal does not report itself resolved")
	}
	if enriched.UserID != userID {
		t.Fatal("enrichment lost the identity")
	}

	// Enrichment must not mutate the original: the pre-resolution principal is
	// still the value that was authenticated, and a later request must not inherit
	// a tenant from an earlier one.
	if session.TenantID != uuid.Nil || session.Role != "" {
		t.Fatal("WithResolvedTenant mutated its receiver")
	}

	// A key is already tenant-bound by its credential, so enrichment must refuse to
	// move it. Allowing it would turn any tenant-resolution bug into full
	// cross-tenant access for every machine credential in the system.
	key := Principal{
		TenantID: tenantA,
		Scopes:   []Perm{PermProjectRead},
		Method:   MethodAPIKey,
	}
	moved := key.WithResolvedTenant(tenantB, RoleOwner)
	if moved.TenantID != tenantA {
		t.Fatalf("an API key was re-scoped to %s; a key must act only as its own tenant", moved.TenantID)
	}
	if moved.Role == RoleOwner {
		t.Fatal("an API key was given a role; keys carry explicit scopes, never roles")
	}
	if !moved.Allows(PermProjectRead) {
		t.Fatal("refusing the re-scope also dropped the key's scopes")
	}
	if moved.Allows(PermProjectWrite) {
		t.Fatal("the refused re-scope leaked a permission")
	}
}
