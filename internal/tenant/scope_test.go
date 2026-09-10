package tenant

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// TestNewScope_RejectsNil proves the constructor refuses the zero UUID. A nil
// tenant is a call-site bug, and failing loudly beats issuing a query that
// silently matches nothing.
func TestNewScope_RejectsNil(t *testing.T) {
	if _, err := NewScope(uuid.Nil); !errors.Is(err, apperr.ErrNoScope) {
		t.Fatalf("NewScope(uuid.Nil) error = %v, want ErrNoScope", err)
	}
}

func TestNewScope_AcceptsRealTenant(t *testing.T) {
	id := uuid.Must(uuid.NewV7())
	scope, err := NewScope(id)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	if scope.ID() != id {
		t.Fatalf("scope id = %s, want %s", scope.ID(), id)
	}
	if !scope.Valid() {
		t.Fatal("scope from a real tenant should be valid")
	}
	if scope.String() != id.String() {
		t.Fatalf("scope String() = %q, want the tenant id", scope.String())
	}
}

// TestZeroScope_IsInvalid documents the deliberate limit of the Scope type: the
// zero value is still constructible from any package, so every repository method
// must call Valid(). This test pins that the zero value fails that check rather
// than passing as a usable scope.
//
// If this test ever fails, the type-level guarantee has been lost and the
// remaining defence is row-level security alone — which is not sufficient,
// because RLS cannot answer "is this principal entitled to this tenant".
func TestZeroScope_IsInvalid(t *testing.T) {
	var zero Scope
	if zero.Valid() {
		t.Fatal("zero Scope must be invalid")
	}
	if zero.ID() != uuid.Nil {
		t.Fatalf("zero Scope id = %s, want nil UUID", zero.ID())
	}
}

// TestZeroAuthorized_IsInvalid is the same assertion one level up. Authorized is
// what repository methods actually accept, so its zero value failing Valid() is
// the check that keeps an unauthorized request out of the data layer.
func TestZeroAuthorized_IsInvalid(t *testing.T) {
	var zero Authorized
	if zero.Valid() {
		t.Fatal("zero Authorized must be invalid")
	}
	if zero.Scope().Valid() {
		t.Fatal("zero Authorized must not yield a valid scope")
	}
	if zero.UserID() != uuid.Nil {
		t.Fatal("zero Authorized must not yield a user id")
	}
	if zero.Role() != "" {
		t.Fatalf("zero Authorized role = %q, want empty", zero.Role())
	}
}

// TestNewAuthorized_RejectsIncompleteInputs proves the constructor refuses to
// build a half-formed authorization. Each arm corresponds to a real bug:
// no scope, no principal, or a role that is not in the model (which would
// authorize nothing, since Can() fails closed on unknown roles).
func TestNewAuthorized_RejectsIncompleteInputs(t *testing.T) {
	realScope, err := NewScope(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	realUser := uuid.Must(uuid.NewV7())

	cases := []struct {
		name  string
		scope Scope
		user  uuid.UUID
		role  authz.Role
		want  error
	}{
		{"no scope", Scope{}, realUser, authz.RoleOwner, apperr.ErrNoScope},
		{"no principal", realScope, uuid.Nil, authz.RoleOwner, apperr.ErrUnauthorized},
		{"unknown role", realScope, realUser, authz.Role("superuser"), apperr.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newAuthorized(tc.scope, tc.user, tc.role); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	got, err := newAuthorized(realScope, realUser, authz.RoleAdmin)
	if err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if !got.Valid() {
		t.Fatal("valid Authorized reported invalid")
	}
	if got.Role() != authz.RoleAdmin || got.UserID() != realUser || got.Scope().ID() != realScope.ID() {
		t.Fatalf("Authorized round-trip mismatch: %s", got)
	}
}

// TestAuthorizedMethods_RejectZeroAuthorized proves the repository refuses an
// unresolved authorization before touching the database. Each call must fail with
// ErrNoScope rather than reaching Postgres with no identity — and under the
// policies, a nil identity would return zero rows, which is the failure mode
// least likely to be noticed in review.
func TestAuthorizedMethods_RejectZeroAuthorized(t *testing.T) {
	// A Store with a nil pool is safe here precisely because the validation
	// happens before any query: if a method ever reached the pool, this test
	// would panic instead of returning an error, which is the failure we want.
	store := NewStore(nil)
	var zero Authorized
	ctx := t.Context()

	t.Run("Get", func(t *testing.T) {
		if _, err := store.Get(ctx, zero); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("ListMembers", func(t *testing.T) {
		if _, err := store.ListMembers(ctx, zero); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("AddMember", func(t *testing.T) {
		if err := store.AddMember(ctx, zero, uuid.Must(uuid.NewV7()), authz.RoleMember); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
}

// TestResolve_RejectsNilTenantAndUser covers the gate's input validation.
//
// A nil tenant is reported as not-found so the caller cannot distinguish "no
// such tenant" from "not your tenant". A nil user is unauthorized rather than
// not-found, because there is no principal at all — that is an authentication
// problem, not an authorization one, and the two produce different responses.
func TestResolve_RejectsNilTenantAndUser(t *testing.T) {
	store := NewStore(nil)
	ctx := t.Context()

	if _, err := store.Resolve(ctx, uuid.Nil, uuid.Must(uuid.NewV7())); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("nil tenant: error = %v, want ErrNotFound", err)
	}
	if _, err := store.Resolve(ctx, uuid.Must(uuid.NewV7()), uuid.Nil); !errors.Is(err, apperr.ErrUnauthorized) {
		t.Fatalf("nil user: error = %v, want ErrUnauthorized", err)
	}
}

// TestAuthorize_RejectsZeroScopeAndUser covers the same boundary on the gate
// method itself, since Authorize is what Resolve delegates to.
func TestAuthorize_RejectsZeroScopeAndUser(t *testing.T) {
	store := NewStore(nil)
	ctx := t.Context()

	if _, err := store.Authorize(ctx, Scope{}, uuid.Must(uuid.NewV7())); !errors.Is(err, apperr.ErrNoScope) {
		t.Fatalf("zero scope: error = %v, want ErrNoScope", err)
	}
	scope, err := NewScope(uuid.Must(uuid.NewV7()))
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	if _, err := store.Authorize(ctx, scope, uuid.Nil); !errors.Is(err, apperr.ErrUnauthorized) {
		t.Fatalf("nil user: error = %v, want ErrUnauthorized", err)
	}
}

// TestValidateNewTenant covers the application-side mirror of the slug and name
// CHECK constraints. The database remains the authority; this exists so a bad
// slug produces a 400 with a usable message rather than a 500 wrapping a
// constraint violation.
func TestValidateNewTenant(t *testing.T) {
	valid := Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "acme-corp", Name: "Acme Corp"}
	if err := validateNewTenant(valid); err != nil {
		t.Fatalf("valid tenant rejected: %v", err)
	}

	cases := []struct {
		name string
		t    Tenant
	}{
		{"nil id", Tenant{Slug: "acme", Name: "Acme"}},
		{"uppercase slug", Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "Acme", Name: "Acme"}},
		{"slug with underscore", Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "acme_corp", Name: "Acme"}},
		{"slug starting with hyphen", Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "-acme", Name: "Acme"}},
		{"single character slug", Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "a", Name: "Acme"}},
		{"empty name", Tenant{ID: uuid.Must(uuid.NewV7()), Slug: "acme", Name: ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateNewTenant(tc.t); !errors.Is(err, apperr.ErrValidation) {
				t.Fatalf("error = %v, want ErrValidation", err)
			}
		})
	}
}

// TestNormalizeEmail pins the normalization the database CHECK constraint also
// enforces (email = lower(email)), plus the shape checks that keep malformed
// addresses out of the unique index.
func TestNormalizeEmail(t *testing.T) {
	got, err := normalizeEmail("  Owner@ACME.Test  ")
	if err != nil {
		t.Fatalf("normalizeEmail: %v", err)
	}
	if got != "owner@acme.test" {
		t.Fatalf("normalized = %q, want owner@acme.test", got)
	}

	for _, bad := range []string{"", "no-at-sign", "@acme.test", "owner@", "owner@localhost", "a@b"} {
		if _, err := normalizeEmail(bad); !errors.Is(err, apperr.ErrValidation) {
			t.Errorf("normalizeEmail(%q) error = %v, want ErrValidation", bad, err)
		}
	}
}
