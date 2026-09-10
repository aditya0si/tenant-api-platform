package tenant_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// These tests target layer 2 of tenant safety: row-level security enforced by
// Postgres itself. They are deliberately separate from store_test.go, which
// exercises the application-level membership gate. Neither layer substitutes for
// the other, so neither set of tests substitutes for the other.
//
// Everything here runs through the application pool, which authenticates as
// app_rw — a role that is neither superuser nor BYPASSRLS. That detail is the
// difference between measuring RLS and measuring nothing: a superuser, a
// BYPASSRLS role, and a table owner (absent FORCE) all ignore policies entirely.
// TestRLS_AppRoleIsSubjectToPolicies asserts that precondition directly, so if
// someone later points the test pool at the owner role, the suite says so
// instead of quietly passing.

// TestRLS_AppRoleIsSubjectToPolicies asserts the precondition every other test in
// this file depends on: the role the application connects as is actually subject
// to row-level security.
func TestRLS_AppRoleIsSubjectToPolicies(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	var (
		currentUser string
		isSuper     bool
		bypassRLS   bool
		ownsTable   bool
	)
	err := d.App.QueryRow(ctx, `
		SELECT current_user,
		       (SELECT rolsuper     FROM pg_roles WHERE rolname = current_user),
		       (SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user),
		       (SELECT pg_get_userbyid(relowner) = current_user
		          FROM pg_class WHERE relname = 'memberships')`).
		Scan(&currentUser, &isSuper, &bypassRLS, &ownsTable)
	if err != nil {
		t.Fatalf("inspect current role: %v", err)
	}

	if isSuper {
		t.Fatalf("app pool connects as %q, which is a SUPERUSER: all RLS policies are bypassed. "+
			"Point TEST_DATABASE_URL at the application role (app_rw).", currentUser)
	}
	if bypassRLS {
		t.Fatalf("app pool connects as %q, which has BYPASSRLS: all RLS policies are bypassed", currentUser)
	}
	if ownsTable {
		t.Fatalf("app pool connects as %q, which owns memberships: FORCE ROW LEVEL SECURITY is the only "+
			"thing keeping the policies active, and the production role is expected to be unprivileged", currentUser)
	}

	// FORCE must be on: the table owner bypasses policies without it, and a role
	// that owns the table would then read every tenant's rows.
	var forced bool
	if err := d.App.QueryRow(ctx, `
		SELECT relforcerowsecurity FROM pg_class WHERE relname = 'memberships'`).Scan(&forced); err != nil {
		t.Fatalf("inspect FORCE RLS: %v", err)
	}
	if !forced {
		t.Fatal("memberships does not have FORCE ROW LEVEL SECURITY")
	}

	// Memberships must also be subject to policies at all.
	var enabled bool
	if err := d.App.QueryRow(ctx, `
		SELECT relrowsecurity FROM pg_class WHERE relname = 'memberships'`).Scan(&enabled); err != nil {
		t.Fatalf("inspect ENABLE RLS: %v", err)
	}
	if !enabled {
		t.Fatal("memberships does not have ROW LEVEL SECURITY enabled")
	}
}

// TestRLS_UnsetContextReturnsZeroRows is the fail-closed assertion.
//
// With no identity GUC set, the policies must hide every row — not error, and
// certainly not return data. A bare current_setting(name) raises an error when
// the setting is missing, and a naive implementation would surface that as a 500;
// the NULLIF(..., ”) form used in migration 0001 yields NULL, and `x = NULL` is
// NULL, so the row is filtered. That is the difference between "unauthenticated
// request sees nothing" and "unauthenticated request crashes the endpoint".
//
// This query deliberately bypasses db.WithIdentityTx — that helper refuses to run
// without an identity — because the point is to observe the raw, unscoped
// behaviour a buggy call path would produce.
func TestRLS_UnsetContextReturnsZeroRows(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	// Seed real rows so an empty result cannot be explained by an empty table.
	testsupport.NewTenant(t, d.App, "rls-unset")

	var count int
	if err := d.App.QueryRow(ctx, `SELECT count(*) FROM memberships`).Scan(&count); err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if count != 0 {
		t.Fatalf("unscoped SELECT returned %d rows; policies are not fail-closed", count)
	}

	if err := d.App.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&count); err != nil {
		t.Fatalf("unscoped tenant count: %v", err)
	}
	if count != 0 {
		t.Fatalf("unscoped SELECT on tenants returned %d rows", count)
	}
}

// TestRLS_CrossTenantReadIsEmptyDropsPredicate is the strongest statement in the
// suite: it removes the application's own WHERE clause and shows that the database
// still refuses to hand over another tenant's rows.
//
// The query is `SELECT ... FROM memberships` with no tenant predicate at all,
// scoped only by the GUC for tenant A. If RLS were absent, misconfigured, or
// bypassed by the connecting role, tenant B's rows would appear here. This is the
// test that fails when someone points the app at a superuser connection — exactly
// the failure mode an unprivileged role exists to prevent.
func TestRLS_CrossTenantReadIsEmptyDropsPredicate(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "rls-a")
	tenantB, ownerB := testsupport.NewTenant(t, d.App, "rls-b")

	seen := map[uuid.UUID]bool{}
	err := db.WithIdentityTx(ctx, d.App, db.Identity{TenantID: tenantA, UserID: ownerA}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT user_id FROM memberships`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			seen[id] = true
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("scoped unfiltered read: %v", err)
	}

	if seen[ownerB] {
		t.Fatal("tenant B's membership is visible from tenant A's scope with no WHERE clause: RLS is not enforcing")
	}
	if !seen[ownerA] {
		t.Fatal("tenant A's own membership is not visible from tenant A's scope: policy is over-restrictive")
	}

	// The tenants table gets the same treatment: reading it from tenant A's
	// scope must not reveal tenant B, even though the query names no tenant and
	// presents B's id nowhere.
	var visibleTenants []uuid.UUID
	err = db.WithIdentityTx(ctx, d.App, db.Identity{TenantID: tenantA, UserID: ownerA}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenants`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			visibleTenants = append(visibleTenants, id)
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("scoped unfiltered tenants read: %v", err)
	}
	for _, id := range visibleTenants {
		if id == tenantB {
			t.Fatal("tenant B is visible from tenant A's scope: the tenants policy is not keyed on membership")
		}
	}
}

// TestRLS_ConcurrentScopesDoNotLeak is the regression test for the classic
// multi-tenant bug: a tenant identifier stored on a pooled connection and handed
// to the next request.
//
// It is constructed to make that bug reproducible rather than theoretical. The
// pool is capped at two connections while 32 goroutines run concurrently, so
// connection reuse is guaranteed and any session-scoped setting would surface.
// Each goroutine alternates between two tenants and asserts it only ever observes
// its own tenant's row.
//
// A bug in db.WithIdentityTx — using set_config(..., false), a plain SET, or a
// session-level connection — fails this test. Run it under -race.
func TestRLS_ConcurrentScopesDoNotLeak(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "concurrent-a")
	tenantB, ownerB := testsupport.NewTenant(t, d.App, "concurrent-b")

	// Two connections, many goroutines: reuse is the point, not a side effect.
	pool := d.AppPoolWithConns(t, 2)

	type probe struct {
		tenantID  uuid.UUID
		ownerID   uuid.UUID
		foreignID uuid.UUID
	}
	probes := []probe{
		{tenantID: tenantA, ownerID: ownerA, foreignID: ownerB},
		{tenantID: tenantB, ownerID: ownerB, foreignID: ownerA},
	}

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		p := probes[i%len(probes)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < 8; attempt++ {
				var ids []uuid.UUID
				err := db.WithIdentityTx(ctx, pool, db.Identity{TenantID: p.tenantID, UserID: p.ownerID}, func(tx pgx.Tx) error {
					rows, err := tx.Query(ctx, `SELECT user_id FROM memberships`)
					if err != nil {
						return err
					}
					defer rows.Close()
					for rows.Next() {
						var id uuid.UUID
						if err := rows.Scan(&id); err != nil {
							return err
						}
						ids = append(ids, id)
					}
					return rows.Err()
				})
				if err != nil {
					errs <- fmt.Errorf("scoped read: %w", err)
					return
				}
				for _, id := range ids {
					if id == p.foreignID {
						errs <- fmt.Errorf("tenant %s observed foreign membership %s: GUC leaked across a pooled connection", p.tenantID, id)
						return
					}
				}
				if len(ids) == 0 {
					errs <- fmt.Errorf("tenant %s observed zero rows: scope was lost", p.tenantID)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestRLS_WriteCannotCrossTenants proves the WITH CHECK arm of the policies: a
// request scoped to tenant A cannot insert a membership into tenant B, even
// though the insert is otherwise well-formed.
//
// This is the write-side counterpart to the read test above, and it is what stops
// a scoped request from minting itself access elsewhere.
func TestRLS_WriteCannotCrossTenants(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	tenantA, ownerA := testsupport.NewTenant(t, d.App, "write-a")
	tenantB, _ := testsupport.NewTenant(t, d.App, "write-b")
	newcomer := testsupport.AddUser(t, d.App, "write-newcomer")

	err := db.WithIdentityTx(ctx, d.App, db.Identity{TenantID: tenantA, UserID: ownerA}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO memberships (tenant_id, user_id, role) VALUES ($1, $2, $3)`,
			tenantB, newcomer, "member")
		return err
	})
	if err == nil {
		t.Fatal("inserted a membership into tenant B from a tenant A scope: WITH CHECK is not enforcing")
	}

	// The row must not exist. Verify with the owner connection so the read is not
	// itself subject to policies.
	if d.Owner != nil {
		var count int
		if err := d.Owner.QueryRow(ctx,
			`SELECT count(*) FROM memberships WHERE tenant_id = $1 AND user_id = $2`,
			tenantB, newcomer).Scan(&count); err != nil {
			t.Fatalf("owner-side verification: %v", err)
		}
		if count != 0 {
			t.Fatal("cross-tenant membership row exists despite the failed insert")
		}
	}
}

// TestRLS_TenantVisibleOnlyToMembers covers the tenants policy, which is keyed on
// membership rather than on the presented tenant id.
//
// The design point: reading a tenant does not depend on the caller claiming that
// tenant, it depends on holding a membership in it. So an outsider who presents a
// tenant id still sees nothing — there is no "prove it by knowing the id" path.
func TestRLS_TenantVisibleOnlyToMembers(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	tenantID, ownerID := testsupport.NewTenant(t, d.App, "visible")
	outsider := testsupport.AddUser(t, d.App, "visible-outsider")

	// The member sees it.
	var visible int
	err := db.WithIdentityTx(ctx, d.App, db.Identity{TenantID: tenantID, UserID: ownerID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, tenantID).Scan(&visible)
	})
	if err != nil {
		t.Fatalf("member read: %v", err)
	}
	if visible != 1 {
		t.Fatalf("member cannot see their own tenant (count = %d)", visible)
	}

	// The outsider presenting the very same id sees nothing, even scoped to it.
	var leaked int
	err = db.WithIdentityTx(ctx, d.App, db.Identity{TenantID: tenantID, UserID: outsider}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, tenantID).Scan(&leaked)
	})
	if err != nil {
		t.Fatalf("outsider read: %v", err)
	}
	if leaked != 0 {
		t.Fatalf("non-member observed tenant %s (count = %d): the tenants policy is keyed on the wrong thing", tenantID, leaked)
	}
}
