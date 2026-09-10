// Package authz holds the authorization model: roles, permissions, and the
// static role -> permission matrix.
//
// It depends on nothing inside this repository (it is the bottom of the import
// graph) so that both the domain packages and the HTTP layer can use it without
// a cycle.
package authz

import "sort"

// Role is a principal's role within one tenant.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

// Perm is a single permission. Permissions are grouped by resource with
// "resource:action" naming so they read the same way in code, logs, and docs.
type Perm string

const (
	PermTenantRead   Perm = "tenant:read"
	PermTenantManage Perm = "tenant:manage"

	PermMemberRead   Perm = "member:read"
	PermMemberManage Perm = "member:manage"

	PermProjectRead  Perm = "project:read"
	PermProjectWrite Perm = "project:write"

	PermInvoiceRead   Perm = "invoice:read"
	PermInvoiceWrite  Perm = "invoice:write"
	PermInvoiceSettle Perm = "invoice:settle"

	PermAPIKeyRead   Perm = "apikey:read"
	PermAPIKeyManage Perm = "apikey:manage"

	PermWebhookRead   Perm = "webhook:read"
	PermWebhookManage Perm = "webhook:manage"

	PermAuditRead Perm = "audit:read"
)

// rolePerms is the authorization model. It is a deliberately static map rather
// than a database-backed policy engine (ADR-009): the hierarchy owner ⊇ admin ⊇
// member is a property of the product, not tenant data, and keeping it in code
// means it is reviewed, versioned, and unit-tested rather than mutated at
// runtime by whoever can write to a table.
var rolePerms = map[Role]map[Perm]bool{
	RoleMember: set(
		PermTenantRead,
		PermMemberRead,
		PermProjectRead,
		PermInvoiceRead,
	),
	RoleAdmin: set(
		PermTenantRead,
		PermMemberRead, PermMemberManage,
		PermProjectRead, PermProjectWrite,
		PermInvoiceRead, PermInvoiceWrite, PermInvoiceSettle,
		PermAPIKeyRead, PermAPIKeyManage,
		PermWebhookRead, PermWebhookManage,
		PermAuditRead,
	),
	RoleOwner: set(
		PermTenantRead, PermTenantManage,
		PermMemberRead, PermMemberManage,
		PermProjectRead, PermProjectWrite,
		PermInvoiceRead, PermInvoiceWrite, PermInvoiceSettle,
		PermAPIKeyRead, PermAPIKeyManage,
		PermWebhookRead, PermWebhookManage,
		PermAuditRead,
	),
}

func set(perms ...Perm) map[Perm]bool {
	m := make(map[Perm]bool, len(perms))
	for _, p := range perms {
		m[p] = true
	}
	return m
}

// ValidRole reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := rolePerms[r]
	return ok
}

// String satisfies fmt.Stringer so roles log cleanly.
func (r Role) String() string { return string(r) }

// Can reports whether a principal with role r holds permission p.
//
// An unknown role holds nothing: an unrecognised value (a stale JWT claim, a
// row edited by hand) fails closed rather than defaulting to access.
func Can(r Role, p Perm) bool {
	perms, ok := rolePerms[r]
	if !ok {
		return false
	}
	return perms[p]
}

// Perms returns role r's permissions in sorted order — used by docs, tests, and
// the /v1/me payload.
func Perms(r Role) []Perm {
	perms, ok := rolePerms[r]
	if !ok {
		return nil
	}
	out := make([]Perm, 0, len(perms))
	for p := range perms {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// AllPerms returns every permission the system defines, sorted.
func AllPerms() []Perm {
	seen := map[Perm]bool{}
	for _, perms := range rolePerms {
		for p := range perms {
			seen[p] = true
		}
	}
	out := make([]Perm, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Roles returns every known role, ordered from least to most privileged.
func Roles() []Role { return []Role{RoleMember, RoleAdmin, RoleOwner} }
