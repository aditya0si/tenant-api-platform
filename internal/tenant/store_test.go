package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// validHash is a well-formed PHC string long enough to satisfy the CHECK
// constraint on users.pw_hash. Fixtures use it because these tests never
// authenticate, and hashing at the production argon2 cost per fixture would make
// the suite slow enough that people stop running it.
const validHash = "$argon2id$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// TestCreateTenantWithOwner_PersistsEverything is the happy path, and it also
// asserts the resulting role and that the gate hands back an Authorized — the
// only value scoped methods accept.
func TestCreateTenantWithOwner_PersistsEverything(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantID, userID := testsupport.NewTenant(t, d.App, "acme")

	auth, err := store.Resolve(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if auth.Role() != authz.RoleOwner {
		t.Fatalf("role = %s, want owner", auth.Role())
	}
	if auth.UserID() != userID {
		t.Fatalf("authorized user = %s, want %s", auth.UserID(), userID)
	}

	got, err := store.Get(ctx, auth)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != tenantID {
		t.Fatalf("tenant id = %s, want %s", got.ID, tenantID)
	}
	if got.Slug == "" || got.Name == "" {
		t.Fatalf("tenant fields not returned: %+v", got)
	}

	memberships, err := store.ListForUser(ctx, userID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if len(memberships) != 1 || memberships[0].TenantID != tenantID {
		t.Fatalf("memberships = %+v, want exactly the created tenant", memberships)
	}
	if memberships[0].Role != authz.RoleOwner {
		t.Fatalf("listed role = %s, want owner", memberships[0].Role)
	}
}

// TestCreateTenantWithOwner_RollsBackOnConflict proves atomicity: when the owner
// email collides, the tenant row must not survive. A partially created tenant —
// a row nobody owns and nobody can administer — is unreachable through the API
// and would only ever be found by an operator.
//
// The fixture hash must be long enough to pass the CHECK constraint, otherwise
// the insert fails validation before it reaches the unique index and this test
// would pass for the wrong reason.
func TestCreateTenantWithOwner_RollsBackOnConflict(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	firstTenant, firstUser := testsupport.NewTenant(t, d.App, "alpha")

	var existingEmail string
	if err := d.App.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, firstUser).Scan(&existingEmail); err != nil {
		t.Fatalf("read fixture email: %v", err)
	}

	secondTenant := uuid.Must(uuid.NewV7())
	err := store.CreateTenantWithOwner(ctx, tenant.Tenant{
		ID:   secondTenant,
		Slug: "dupe-" + secondTenant.String()[:8],
		Name: "Should Not Exist",
	}, tenant.Owner{
		ID:     uuid.Must(uuid.NewV7()),
		Email:  existingEmail,
		PWHash: validHash,
	}, authz.RoleOwner)

	if !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}

	// The second tenant must be invisible: the insert rolled back, so no row
	// exists for a policy to expose. Verified through the owner connection so
	// the read itself is not subject to the policies under test.
	if d.Owner != nil {
		var count int
		if err := d.Owner.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, secondTenant).Scan(&count); err != nil {
			t.Fatalf("owner-side verification: %v", err)
		}
		if count != 0 {
			t.Fatal("orphan tenant row exists: the failed insert did not roll back")
		}
	}

	// And the first tenant is intact.
	auth, err := store.Resolve(ctx, firstTenant, firstUser)
	if err != nil {
		t.Fatalf("first tenant damaged by the failed insert: %v", err)
	}
	if _, err := store.Get(ctx, auth); err != nil {
		t.Fatalf("first tenant unreadable after the failed insert: %v", err)
	}
}

// TestCreateTenantWithOwner_RejectsBadInput covers the validation that happens
// before any SQL runs, so a malformed request never reaches the database.
func TestCreateTenantWithOwner_RejectsBadInput(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	good := tenant.Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "valid-slug", Name: "Valid"}
	goodOwner := tenant.Owner{ID: uuid.Must(uuid.NewV7()), Email: "owner@valid.test", PWHash: validHash}

	cases := []struct {
		name  string
		t     tenant.Tenant
		owner tenant.Owner
		role  authz.Role
	}{
		{"nil tenant id", tenant.Tenant{Slug: "x-y", Name: "X"}, goodOwner, authz.RoleOwner},
		{"invalid slug", tenant.Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "Bad Slug", Name: "X"}, goodOwner, authz.RoleOwner},
		{"nil owner id", good, tenant.Owner{Email: "a@b.test", PWHash: validHash}, authz.RoleOwner},
		{"malformed email", good, tenant.Owner{ID: uuid.Must(uuid.NewV7()), Email: "not-an-email", PWHash: validHash}, authz.RoleOwner},
		{"unknown role", good, goodOwner, authz.Role("root")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.CreateTenantWithOwner(ctx, tc.t, tc.owner, tc.role)
			if !errors.Is(err, apperr.ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}
		})
	}
}

// TestResolve_NonMemberIsNotFound is the IDOR regression test at the store layer.
//
// A user who exists but holds no membership in the target tenant must receive
// ErrNotFound — never ErrForbidden. The distinction is the whole point: 403 would
// confirm the tenant exists, turning the endpoint into an existence oracle an
// attacker can walk to enumerate other tenants' ids.
func TestResolve_NonMemberIsNotFound(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	victimTenant, _ := testsupport.NewTenant(t, d.App, "victim")
	outsider := testsupport.AddUser(t, d.App, "outsider")

	if _, err := store.Resolve(ctx, victimTenant, outsider); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("outsider resolved a foreign tenant (error = %v, want ErrNotFound)", err)
	}
}

// TestAuthorize_NonMemberIsNotFound covers the same boundary on the gate method
// itself, since Authorize is what Resolve delegates to.
func TestAuthorize_NonMemberIsNotFound(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	victimTenant, _ := testsupport.NewTenant(t, d.App, "victim")
	outsider := testsupport.AddUser(t, d.App, "outsider")

	scope, err := tenant.NewScope(victimTenant)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	if _, err := store.Authorize(ctx, scope, outsider); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// TestAddMember_GrantsAccess proves the membership edge works: a user with no
// access gains it once added, at the role they were granted.
func TestAddMember_GrantsAccess(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantID, ownerID := testsupport.NewTenant(t, d.App, "team")
	newcomer := testsupport.AddUser(t, d.App, "newcomer")

	auth, err := store.Resolve(ctx, tenantID, ownerID)
	if err != nil {
		t.Fatalf("Resolve owner: %v", err)
	}

	if _, err := store.Authorize(ctx, auth.Scope(), newcomer); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("newcomer already had access (error = %v)", err)
	}

	if err := store.AddMember(ctx, auth, newcomer, authz.RoleMember); err != nil {
		t.Fatalf("AddMember: %v", err)
	}

	role, err := store.Authorize(ctx, auth.Scope(), newcomer)
	if err != nil {
		t.Fatalf("Authorize after add: %v", err)
	}
	if role != authz.RoleMember {
		t.Fatalf("role = %s, want member", role)
	}

	members, err := store.ListMembers(ctx, auth)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("roster size = %d, want 2", len(members))
	}
}

// TestAddMember_UnknownUserIsNotFound proves a foreign-key violation is reported
// as not-found rather than a distinct "unknown user" code, so the endpoint cannot
// be used to probe which user ids exist.
func TestAddMember_UnknownUserIsNotFound(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantID, ownerID := testsupport.NewTenant(t, d.App, "team")

	auth, err := store.Resolve(ctx, tenantID, ownerID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := store.AddMember(ctx, auth, uuid.Must(uuid.NewV7()), authz.RoleMember); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

// TestListMembers_ScopedToOwnTenant is the store-level isolation assertion: a
// roster read authorized for tenant A must never contain tenant B's members, in
// either direction.
func TestListMembers_ScopedToOwnTenant(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "alpha")
	tenantB, ownerB := testsupport.NewTenant(t, d.App, "bravo")

	authA, err := store.Resolve(ctx, tenantA, ownerA)
	if err != nil {
		t.Fatalf("Resolve A: %v", err)
	}
	rosterA, err := store.ListMembers(ctx, authA)
	if err != nil {
		t.Fatalf("ListMembers A: %v", err)
	}
	if len(rosterA) != 1 || rosterA[0].UserID != ownerA {
		t.Fatalf("tenant A roster wrong: %+v", rosterA)
	}
	for _, m := range rosterA {
		if m.UserID == ownerB {
			t.Fatalf("tenant A roster contains tenant B's owner: %+v", m)
		}
	}

	authB, err := store.Resolve(ctx, tenantB, ownerB)
	if err != nil {
		t.Fatalf("Resolve B: %v", err)
	}
	rosterB, err := store.ListMembers(ctx, authB)
	if err != nil {
		t.Fatalf("ListMembers B: %v", err)
	}
	for _, m := range rosterB {
		if m.UserID == ownerA {
			t.Fatalf("tenant B roster contains tenant A's owner: %+v", m)
		}
	}
}

// TestGet_ReturnsOnlyAuthorizedTenant is the read-side counterpart: the tenant
// returned must be the one the authorization was issued for, never a neighbour.
func TestGet_ReturnsOnlyAuthorizedTenant(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "read-a")
	tenantB, ownerB := testsupport.NewTenant(t, d.App, "read-b")

	authA, err := store.Resolve(ctx, tenantA, ownerA)
	if err != nil {
		t.Fatalf("Resolve A: %v", err)
	}
	gotA, err := store.Get(ctx, authA)
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	if gotA.ID != tenantA {
		t.Fatalf("authorized for %s but read %s", tenantA, gotA.ID)
	}

	authB, err := store.Resolve(ctx, tenantB, ownerB)
	if err != nil {
		t.Fatalf("Resolve B: %v", err)
	}
	gotB, err := store.Get(ctx, authB)
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if gotB.ID != tenantB {
		t.Fatalf("authorized for %s but read %s", tenantB, gotB.ID)
	}
	if gotA.Slug == gotB.Slug {
		t.Fatalf("two tenants returned the same slug %q", gotA.Slug)
	}
}

// TestListForUser_OnlyOwnMemberships proves the pre-tenant query is bounded to
// the principal: a user must not see tenants they do not belong to.
//
// This is the query the memberships policy's user arm exists for, and it runs
// before any tenant is selected — so it is the clearest demonstration of why the
// policy cannot be keyed on tenant alone.
func TestListForUser_OnlyOwnMemberships(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := tenant.NewStore(d.App)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "list-a")
	tenantB, _ := testsupport.NewTenant(t, d.App, "list-b")

	memberships, err := store.ListForUser(ctx, ownerA)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	for _, m := range memberships {
		if m.TenantID == tenantB {
			t.Fatalf("user sees a tenant they do not belong to: %+v", m)
		}
	}
	if len(memberships) != 1 || memberships[0].TenantID != tenantA {
		t.Fatalf("memberships = %+v, want exactly tenant A", memberships)
	}
}
