package httpx

import (
	"context"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// MembershipLister adapts the tenant store to the authentication service's
// tenant-listing need.
//
// # Why an adapter rather than a method
//
// Both operations answer "which tenants does this principal belong to", but they
// answer it for different purposes and belong to different packages: the tenant
// store reads the authoritative rows, and the auth service wants them rendered as
// session presentation data. The two packages deliberately do not import each
// other — tenant owns the policy-guarded query, authn owns sessions — so the wiring
// happens here, in the one layer that is allowed to know both.
//
// The adapter is a type rather than a closure so its behaviour is nameable in a
// test: a silent failure to wire it produces a session with an empty tenant list,
// which a client experiences as "I logged in and can see nothing".
type MembershipLister struct {
	Tenants *tenant.Store
}

// ListForUser implements authn.MembershipLister.
func (l MembershipLister) ListForUser(ctx context.Context, userID uuid.UUID) ([]authn.TenantSummary, error) {
	memberships, err := l.Tenants.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]authn.TenantSummary, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, authn.TenantSummary{
			TenantID: m.TenantID,
			Slug:     m.TenantSlug,
			Name:     m.TenantName,
			Role:     m.Role,
		})
	}
	return out, nil
}

var _ authn.MembershipLister = MembershipLister{}
