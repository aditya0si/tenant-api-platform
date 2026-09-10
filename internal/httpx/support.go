package httpx

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// setGauge sets a gauge from a boolean probe.
func setGauge(g prometheus.Gauge, ok bool) {
	if ok {
		g.Set(1)
		return
	}
	g.Set(0)
}

// authorizedFrom reads the resolved tenant from the request context.
//
// It panics on absence rather than returning an error. Every handler that calls it
// is registered inside the tenant-scoped group, where RequireAuthorized already
// guarantees the value — so a missing one means a route was registered in the wrong
// place, which is a programming error that should be loud at the first request
// rather than presenting as a puzzling 404 for every call.
func authorizedFrom(r *http.Request) tenant.Authorized {
	auth, ok := tenant.AuthorizedFrom(r.Context())
	if !ok {
		panic("httpx: handler reached without a resolved tenant; it is not registered under the tenant-scoped group")
	}
	if !auth.Valid() {
		panic("httpx: handler reached with an invalid tenant authorization")
	}
	return auth
}

// permissionInfo describes a principal's effective permissions, so a client can render
// what it may do without duplicating the model.
func permissionInfo(p authz.Principal) []string {
	switch p.Method {
	case authz.MethodJWT:
		return rolePermStrings(p.Role)
	case authz.MethodAPIKey:
		return permStrings(p.Scopes)
	default:
		return nil
	}
}

// rolePermStrings renders a role's permissions in sorted order.
//
// Sorted because Go's map iteration order is random: an unsorted list would make the
// response — and any golden file or client that caches it — flap between calls.
func rolePermStrings(r authz.Role) []string { return permStrings(authz.Perms(r)) }

func permStrings(perms []authz.Perm) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}

// timestamp renders a time as RFC 3339 in UTC, which is what the API documents.
//
// Times are normalised to UTC rather than sent in the server's local zone: a client
// parsing "2026-09-11T02:19:00+05:30" and one parsing "...T20:49:00Z" are the same
// instant, but a log line or a diff that mixes zones is not comparable by eye, and
// the API contract is easier to state one way.
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// timestampPtr renders an optional time, omitting it when unset.
func timestampPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := timestamp(*t)
	return &s
}
