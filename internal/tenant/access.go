package tenant

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

// Kind distinguishes the two sorts of principal that can hold a tenant scope.
//
// They are genuinely different, not cosmetic: a human is authorized by a
// membership and holds a role, while a machine credential *is* the tenant and holds
// an explicit permission list. Collapsing them would force a role onto a key (which
// is how a key ends up able to manage members) or a nil user id onto a human path
// (which is how a membership check silently passes).
type Kind uint8

const (
	// kindUnset is the zero value, and it is invalid. A scope carrying it is a
	// construction bug and is rejected by Valid.
	kindUnset Kind = iota
	// KindHuman is a user acting through a membership.
	KindHuman
	// KindMachine is a tenant-scoped API key.
	KindMachine
)

func (k Kind) String() string {
	switch k {
	case KindHuman:
		return "human"
	case KindMachine:
		return "machine"
	default:
		return "unset"
	}
}

// Authorized is the result of a successful authorization: a resolved tenant scope
// paired with the principal it was authorized for.
//
// # Why the principal travels with the scope
//
// The obvious shape for this type is just the tenant id. That shape does not work,
// and the way it fails is instructive. The `tenants` policy is keyed on membership —
// a tenant is visible to principals who hold a membership in it — so every query
// against `tenants` needs `app.current_user_id` set. A method that carried only the
// tenant would set only the tenant GUC, the policy's EXISTS subquery would evaluate
// against a NULL user, and the row would be filtered for the legitimate owner. The
// bug presents as "the owner cannot read their own tenant", which looks like a policy
// bug and is really a missing parameter.
//
// Threading the principal through a single value is what stops that from being a
// parameter somebody forgets at one call site. The row-level-security identity is then
// derived from this one value (see Identity), so a scoped query cannot be issued with
// a tenant and a principal that were authorized separately — or with one of them
// missing.
//
// # Constructible only by the two authorization paths
//
// Fields are unexported. A human authorization comes from Store.Resolve, which checks
// a membership. A machine authorization comes from NewMachineAuthorized, whose
// contract is described on that function. As with Scope, be honest about the limit:
// the zero value is still constructible everywhere, so every repository method calls
// Valid() and returns ErrNoScope. That residual gap is why row-level security is still
// doing real work — see the package doc.
type Authorized struct {
	scope Scope
	kind  Kind

	// Human principals.
	userID uuid.UUID
	role   authz.Role

	// Machine principals: the key that was verified. Carried for attribution and
	// auditing, since "which key did this" is the only useful answer for an
	// unattended action.
	keyID uuid.UUID
}

// newAuthorized builds a human authorization. Unexported: Store.Resolve is the only
// caller, and it always authorizes before constructing one.
func newAuthorized(scope Scope, userID uuid.UUID, role authz.Role) (Authorized, error) {
	switch {
	case !scope.Valid():
		return Authorized{}, fmt.Errorf("tenant: authorize with no scope: %w", apperr.ErrNoScope)
	case userID == uuid.Nil:
		return Authorized{}, fmt.Errorf("tenant: authorize with no principal: %w", apperr.ErrUnauthorized)
	case !role.Valid():
		return Authorized{}, fmt.Errorf("tenant: authorize with unknown role %q: %w", role, apperr.ErrValidation)
	}
	return Authorized{scope: scope, kind: KindHuman, userID: userID, role: role}, nil
}

// NewMachineAuthorized builds an authorization for a verified API key.
//
// # The trust this function requires, stated plainly
//
// A key is not authorized by a membership: the credential *is* the tenant, and
// nothing about the caller needs to be looked up in `memberships`. So this
// constructor cannot check anything, and the type system cannot prove the caller
// verified a key — which makes this the one place where construction is trusted.
//
// The trust is bounded and documented rather than hidden:
//
//   - The only caller is the HTTP tenant middleware, and only on the branch that
//     already observed authz.MethodAPIKey, a value that only
//     authn.Service.PrincipalForAPIKey produces — and that method reaches the
//     database, checks revocation and expiry, and reads the tenant from the key's own
//     row. There is no code path that mints a machine principal from a client-supplied
//     value.
//   - Row-level security still bounds every query to the scope named here, so a
//     mistakenly-constructed authorization grants nothing beyond its own tenant.
//   - A machine authorization carries no role, and Principal.Allows checks a key
//     against its explicit scopes, so machine authorization can never confer a
//     permission the key was not minted with.
//
// The alternative — re-reading the key inside the tenant package — would put a third
// query on every machine request to re-establish a fact the request already
// established, and would not remove the trust, only move it.
func NewMachineAuthorized(scope Scope, keyID uuid.UUID) (Authorized, error) {
	switch {
	case !scope.Valid():
		return Authorized{}, fmt.Errorf("tenant: machine authorize with no scope: %w", apperr.ErrNoScope)
	case keyID == uuid.Nil:
		return Authorized{}, fmt.Errorf("tenant: machine authorize with no key: %w", apperr.ErrUnauthorized)
	}
	return Authorized{scope: scope, kind: KindMachine, keyID: keyID}, nil
}

// Scope returns the resolved tenant.
func (a Authorized) Scope() Scope { return a.scope }

// Kind reports how the principal was authorized.
func (a Authorized) Kind() Kind { return a.kind }

// IsMachine reports whether this is a machine credential rather than a user session.
func (a Authorized) IsMachine() bool { return a.kind == KindMachine }

// UserID returns the authorized user, or the nil UUID for a machine principal.
//
// A machine has no user, and returning a zero value rather than an error is
// deliberate: callers that need a human must check IsMachine first, and a zero value
// fails a NOT NULL column or a foreign key loudly instead of attributing an
// unattended action to nobody.
func (a Authorized) UserID() uuid.UUID { return a.userID }

// KeyID returns the verified key id for a machine principal, or the nil UUID for a
// human one.
func (a Authorized) KeyID() uuid.UUID { return a.keyID }

// Role returns the principal's role, or the empty role for a machine principal.
//
// A key holds permissions, never a role — see internal/authz/keys.go for why. Callers
// that branch on a role must therefore treat the empty value as "not a human" rather
// than as "a human with no permissions".
func (a Authorized) Role() authz.Role { return a.role }

// Identity derives the row-level-security identity for this authorized principal.
//
// Both components come from the same value, so a scoped query cannot be issued with a
// tenant and a principal that were authorized separately — or with one of them
// missing, which is the failure mode described at the top of this file.
//
// A machine principal sets only the tenant: there is no user to name, and inventing
// one would be a lie the policies then act on.
func (a Authorized) Identity() db.Identity {
	id := db.Identity{TenantID: a.scope.ID()}
	if a.kind == KindHuman {
		id.UserID = a.userID
	}
	return id
}

// Valid reports whether this carries a resolved, authorized principal.
func (a Authorized) Valid() bool {
	if !a.scope.Valid() {
		return false
	}
	switch a.kind {
	case KindHuman:
		return a.userID != uuid.Nil && a.role.Valid()
	case KindMachine:
		return a.keyID != uuid.Nil
	default:
		return false
	}
}

// String satisfies fmt.Stringer. Ids and kind only: authorization state is not a
// secret, and logging it is what makes authorization bugs diagnosable.
func (a Authorized) String() string {
	switch a.kind {
	case KindHuman:
		return fmt.Sprintf("tenant=%s kind=human user=%s role=%s", a.scope, a.userID, a.role)
	case KindMachine:
		return fmt.Sprintf("tenant=%s kind=machine key=%s", a.scope, a.keyID)
	default:
		return "tenant=<unset> kind=unset"
	}
}
