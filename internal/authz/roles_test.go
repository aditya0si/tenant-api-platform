package authz

import "testing"

// TestRoleHierarchy locks the authorization model down as data.
//
// The property that matters is monotonicity — owner ⊇ admin ⊇ member — because
// it is the assumption every future permission check rests on. Asserting it as a
// property rather than a hand-written table means adding a permission to member
// without adding it to admin and owner fails here, loudly, instead of shipping a
// model where promotion removes a capability.
func TestRoleHierarchy(t *testing.T) {
	ordered := []Role{RoleMember, RoleAdmin, RoleOwner}

	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			lower, higher := ordered[i], ordered[j]
			for _, p := range Perms(lower) {
				if !Can(higher, p) {
					t.Errorf("hierarchy broken: %s holds %s but %s does not", lower, p, higher)
				}
			}
		}
	}
}

// TestCan_UnknownRoleDenies proves an unrecognised role fails closed. A stale
// JWT claim or a hand-edited membership row must never default to access.
func TestCan_UnknownRoleDenies(t *testing.T) {
	unknown := Role("superuser")
	for _, p := range AllPerms() {
		if Can(unknown, p) {
			t.Fatalf("unknown role granted %s; authorization must fail closed", p)
		}
	}
	if Perms(unknown) != nil {
		t.Fatal("unknown role must not resolve to a permission set")
	}
}

// TestCan_SpecificCapabilities pins the decisions that carry product meaning, so
// a refactor cannot quietly hand a member the ability to manage API keys or
// settle invoices.
func TestCan_SpecificCapabilities(t *testing.T) {
	cases := []struct {
		name string
		role Role
		perm Perm
		want bool
	}{
		{"member reads projects", RoleMember, PermProjectRead, true},
		{"member cannot write projects", RoleMember, PermProjectWrite, false},
		{"member cannot manage keys", RoleMember, PermAPIKeyManage, false},
		{"member cannot settle invoices", RoleMember, PermInvoiceSettle, false},
		{"member cannot read audit", RoleMember, PermAuditRead, false},

		{"admin writes projects", RoleAdmin, PermProjectWrite, true},
		{"admin manages members", RoleAdmin, PermMemberManage, true},
		{"admin settles invoices", RoleAdmin, PermInvoiceSettle, true},
		{"admin cannot manage the tenant", RoleAdmin, PermTenantManage, false},

		{"owner manages the tenant", RoleOwner, PermTenantManage, true},
		{"owner reads audit", RoleOwner, PermAuditRead, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Can(tc.role, tc.perm); got != tc.want {
				t.Fatalf("Can(%s, %s) = %v, want %v", tc.role, tc.perm, got, tc.want)
			}
		})
	}
}

// TestValidRole rejects anything outside the CHECK constraint's vocabulary, so
// role values cannot drift between Go and the database.
func TestValidRole(t *testing.T) {
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleMember} {
		if !r.Valid() {
			t.Errorf("%s should be valid", r)
		}
	}
	for _, r := range []Role{"", "Owner", "root", "superuser"} {
		if Role(r).Valid() {
			t.Errorf("%q should not be valid", r)
		}
	}
}

// TestPermsSorted keeps the /v1/me payload and docs stable across runs — map
// iteration order is random in Go, and an unsorted permission list would make
// API responses and golden files flap.
func TestPermsSorted(t *testing.T) {
	perms := Perms(RoleOwner)
	for i := 1; i < len(perms); i++ {
		if perms[i-1] >= perms[i] {
			t.Fatalf("permissions not sorted: %v", perms)
		}
	}
	if len(perms) != len(AllPerms()) {
		t.Fatalf("owner should hold every permission: owner=%d all=%d", len(perms), len(AllPerms()))
	}
}

// TestEveryRoleHasTenantRead guards a foot-gun: a principal who cannot read the
// tenant they are acting in cannot be served by most read paths, so this
// permission is effectively mandatory for all three roles.
func TestEveryRoleHasTenantRead(t *testing.T) {
	for _, r := range Roles() {
		if !Can(r, PermTenantRead) {
			t.Errorf("%s lacks %s", r, PermTenantRead)
		}
	}
}
