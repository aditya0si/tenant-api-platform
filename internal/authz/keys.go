package authz

import "fmt"

// keyForbiddenPerms are permissions an API key may never hold, regardless of
// what the caller requests.
//
// # Why a deny-list rather than a ceiling
//
// The alternative shape — "a key may hold any permission a member role holds" —
// reads as simpler but gets the important case wrong: managing members and
// minting further keys are *identity* operations. A key that can add members can
// add itself an accomplice; a key that can mint keys can outlive its own
// revocation by issuing a successor first. Neither is something unattended
// automation should be able to do, and both are strictly worse when the key
// leaks.
//
// These are denied at mint time with a clear error, rather than accepted and then
// silently ignored at check time, because a key that appears to have a permission
// it does not have is a debugging problem nobody enjoys.
//
// The one deliberate exception is apikey:read, which lets a key list its sibling
// keys. That is an observability convenience with no escalation path; revocation
// and management remain human-only.
var keyForbiddenPerms = map[Perm]string{
	PermTenantManage: "tenant management changes the tenant's own identity",
	PermMemberManage: "membership changes are identity operations and must be attributable to a person",
	PermAPIKeyManage: "a key that can mint keys can survive its own revocation by issuing a successor first",
}

// KeyForbiddenReason reports why perm may not be granted to an API key, and
// whether it is forbidden at all.
func KeyForbiddenReason(p Perm) (string, bool) {
	reason, ok := keyForbiddenPerms[p]
	return reason, ok
}

// ValidateKeyScopes checks a proposed permission list for an API key.
//
// It rejects unknown permissions, duplicates, an empty list, and the forbidden
// set above. An empty list is rejected rather than accepted as "no permissions":
// a key that can do nothing is nearly always a mistake in the request, and
// failing at creation is kinder than handing back a credential that 403s on
// every call.
func ValidateKeyScopes(scopes []Perm) error {
	if len(scopes) == 0 {
		return fmt.Errorf("authz: at least one scope is required")
	}
	known := map[Perm]bool{}
	for _, p := range AllPerms() {
		known[p] = true
	}
	seen := map[Perm]bool{}
	for _, p := range scopes {
		if !known[p] {
			return fmt.Errorf("authz: unknown scope %q", p)
		}
		if _, forbidden := keyForbiddenPerms[p]; forbidden {
			reason, _ := KeyForbiddenReason(p)
			return fmt.Errorf("authz: scope %q may not be granted to an API key: %s", p, reason)
		}
		if seen[p] {
			return fmt.Errorf("authz: duplicate scope %q", p)
		}
		seen[p] = true
	}
	return nil
}

// KeyGrantablePerms returns the permissions an API key may hold, sorted. Used by
// the key-creation endpoint to advertise what is legal and by tests to prove the
// forbid-list and the permission model stay in sync.
func KeyGrantablePerms() []Perm {
	var out []Perm
	for _, p := range AllPerms() {
		if _, forbidden := keyForbiddenPerms[p]; !forbidden {
			out = append(out, p)
		}
	}
	return out
}
