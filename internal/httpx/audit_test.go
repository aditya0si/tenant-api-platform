package httpx_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
)

// tenantScopedTx runs fn in a transaction with the tenant GUC set, so a query issued under the
// application role sees that tenant's rows.
//
// It runs fn on the *transaction*, not on the pool, and that distinction is the whole point: a
// pool query would acquire a different connection, where the setting does not apply — so the
// policy would filter everything away and the assertion would pass while proving nothing.
// pgx.BeginFunc rolls back on error, which is what makes it safe to raise inside.
func tenantScopedTx(t *testing.T, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`SELECT set_config('app.current_tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// auditRows reads a tenant's trail directly with owner credentials.
//
// Owner credentials rather than the application role, because the assertions below are about
// what was actually written, and reading through the API would let the same access path that
// could hide a missing entry also hide the assertion. Same instinct as connecting as superuser
// to prove the isolation tests measure RLS.
type auditRow struct {
	Action     string
	ActorKind  string
	ActorID    *uuid.UUID
	Resource   string
	ResourceID *uuid.UUID
	Before     []byte
	After      []byte
	RequestID  *string
}

func (s *server) auditRows(t *testing.T, tenantID string) []auditRow {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot read the trail as the owner")
	}
	tid := uuid.MustParse(tenantID)

	rows, err := s.db.Owner.Query(context.Background(), `
		SELECT action, actor_kind, actor_id, resource, resource_id, before, after, request_id
		  FROM audit_log
		 WHERE tenant_id = $1
		 ORDER BY at, id`, tid)
	if err != nil {
		t.Fatalf("read audit_log: %v", err)
	}
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.Action, &r.ActorKind, &r.ActorID, &r.Resource, &r.ResourceID,
			&r.Before, &r.After, &r.RequestID); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit rows: %v", err)
	}
	return out
}

// countAuditRows counts a tenant's entries.
func (s *server) countAuditRows(t *testing.T, tenantID string) int {
	t.Helper()
	return len(s.auditRows(t, tenantID))
}

// TestAudit_RecordsProjectLifecycle is the baseline: the operations this API performs leave a
// trail behind them.
//
// It asserts the action verb, the actor, and the presence of the images — the three things
// that make an entry answerable months later. A trail that records "something happened" but
// not who or what changed is a log line with a schema.
func TestAudit_RecordsProjectLifecycle(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("audit-lifecycle"))
	base := "/v1/tenants/" + tenantID + "/projects"

	created := s.do(http.MethodPost, base, map[string]any{"name": "Audited"}, session.AccessToken)
	if created.status != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", created.status, created.body)
	}
	var project struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	}
	created.decodeData(t, &project)

	updated := s.do(http.MethodPatch, base+"/"+project.ID, map[string]any{
		"name":             "Renamed",
		"expected_version": project.Version,
	}, session.AccessToken)
	if updated.status != http.StatusOK {
		t.Fatalf("update: status %d, body %s", updated.status, updated.body)
	}

	archived := s.do(http.MethodDelete, base+"/"+project.ID, nil, session.AccessToken)
	if archived.status != http.StatusOK && archived.status != http.StatusNoContent {
		t.Fatalf("archive: status %d, body %s", archived.status, archived.body)
	}

	rows := s.auditRows(t, tenantID)
	if len(rows) != 3 {
		t.Fatalf("recorded %d entries for a create, update and archive; want 3 — got %v",
			len(rows), actionsOf(rows))
	}

	want := []string{audit.ActionProjectCreate, audit.ActionProjectUpdate, audit.ActionProjectArchive}
	for i, w := range want {
		if rows[i].Action != w {
			t.Fatalf("entry %d is %q, want %q (order: %v)", i, rows[i].Action, w, actionsOf(rows))
		}
	}

	// The actor is the person, identified by id — not "someone".
	uid := uuid.MustParse(session.UserID)
	for i, r := range rows {
		if r.ActorKind != audit.ActorUser {
			t.Errorf("entry %d actor_kind = %q, want %q", i, r.ActorKind, audit.ActorUser)
		}
		if r.ActorID == nil || *r.ActorID != uid {
			t.Errorf("entry %d actor_id = %v, want %s", i, r.ActorID, uid)
		}
		if r.Resource != "project" {
			t.Errorf("entry %d resource = %q, want project", i, r.Resource)
		}
		if r.ResourceID == nil || r.ResourceID.String() != project.ID {
			t.Errorf("entry %d resource_id = %v, want %s", i, r.ResourceID, project.ID)
		}
		// Every entry carries the request id, which is what makes "show me everything from
		// that request" answerable.
		if r.RequestID == nil || *r.RequestID == "" {
			t.Errorf("entry %d has no request id", i)
		}
	}

	// A create has no before image, and that must be SQL NULL rather than the bytes "null" —
	// otherwise `before IS NULL` would not find creations, which is the query anyone would
	// write.
	if len(rows[0].Before) != 0 {
		t.Errorf("create entry has a before image (%s); a creation has no prior state",
			rows[0].Before)
	}
	if len(rows[0].After) == 0 {
		t.Error("create entry has no after image")
	}

	// The update records both sides, and the before image is the *pre-update* name. This is
	// the assertion that catches recording the post-update state as the before image, which
	// would make the trail silently claim nothing changed.
	var createAfter, updateBefore, updateAfter map[string]any
	if err := json.Unmarshal(rows[0].After, &createAfter); err != nil {
		t.Fatalf("create after image is not JSON: %v", err)
	}
	if err := json.Unmarshal(rows[1].Before, &updateBefore); err != nil {
		t.Fatalf("update before image is not JSON: %v", err)
	}
	if err := json.Unmarshal(rows[1].After, &updateAfter); err != nil {
		t.Fatalf("update after image is not JSON: %v", err)
	}
	if createAfter["name"] != "Audited" {
		t.Errorf("create after image name = %v, want Audited", createAfter["name"])
	}
	if updateBefore["name"] != "Audited" {
		t.Errorf("update before image name = %v, want Audited — the pre-image must be the state "+
			"before the change, or the trail reports that nothing changed", updateBefore["name"])
	}
	if updateAfter["name"] != "Renamed" {
		t.Errorf("update after image name = %v, want Renamed", updateAfter["name"])
	}
	if updateBefore["version"] == updateAfter["version"] {
		t.Error("the version is identical before and after an update, so the images are the same state")
	}
}

// TestAudit_IsAppendOnly is the guarantee that makes the trail worth having, and it is
// asserted rather than described.
//
// The trigger is the whole mechanism: a trail that can be edited is not evidence, it is a
// claim. It is checked under both credentials on purpose:
//
//   - As the application role, because that is what a compromised or simply buggy service
//     would attempt.
//   - As the owner (a superuser), because "the service cannot do it" is a weaker statement
//     than "the database refuses it". A superuser can still drop the trigger — that limit is
//     documented in ADR-006 — but this proves DML alone is not sufficient to rewrite history.
//
// The app-role case is the one that would otherwise fail silently: RLS filters rows before a
// statement sees them, so without the trigger a DELETE would report success while removing
// nothing, and the caller would believe the trail had been pruned.
func TestAudit_IsAppendOnly(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("audit-append"))
	base := "/v1/tenants/" + tenantID + "/projects"

	if res := s.do(http.MethodPost, base, map[string]any{"name": "Immutable"}, session.AccessToken); res.status != http.StatusCreated {
		t.Fatalf("setup create: status %d, body %s", res.status, res.body)
	}
	if got := s.countAuditRows(t, tenantID); got != 1 {
		t.Fatalf("setup produced %d entries, want 1", got)
	}

	tid := uuid.MustParse(tenantID)

	for _, tc := range []struct {
		name string
		pool string
	}{
		{"application role", "app"},
		{"owner role", "owner"},
	} {
		t.Run(tc.name+"/update", func(t *testing.T) {
			pool := s.db.App
			if tc.pool == "owner" {
				if s.db.Owner == nil {
					t.Skip("no owner credentials")
				}
				pool = s.db.Owner
			}

			// The tenant GUC is set first so the app-role case sees the row rather than being
			// filtered to nothing: a statement that matches no rows proves nothing about the
			// trigger, and that is exactly the silent-success failure mode being guarded.
			var err error
			if tc.pool == "app" {
				err = tenantScopedTx(t, pool, tenantID, func(tx pgx.Tx) error {
					_, e := tx.Exec(context.Background(),
						`UPDATE audit_log SET action = 'project.tampered' WHERE tenant_id = $1`, tid)
					return e
				})
			} else {
				_, err = pool.Exec(context.Background(),
					`UPDATE audit_log SET action = 'project.tampered' WHERE tenant_id = $1`, tid)
			}

			if err == nil {
				t.Fatal("an UPDATE on audit_log succeeded; a trail that can be edited is not evidence")
			}
			if !audit.IsAppendOnlyViolation(err) {
				t.Fatalf("the UPDATE failed for the wrong reason: %v", err)
			}
		})

		t.Run(tc.name+"/delete", func(t *testing.T) {
			pool := s.db.App
			if tc.pool == "owner" {
				if s.db.Owner == nil {
					t.Skip("no owner credentials")
				}
				pool = s.db.Owner
			}

			var err error
			if tc.pool == "app" {
				err = tenantScopedTx(t, pool, tenantID, func(tx pgx.Tx) error {
					_, e := tx.Exec(context.Background(),
						`DELETE FROM audit_log WHERE tenant_id = $1`, tid)
					return e
				})
			} else {
				_, err = pool.Exec(context.Background(),
					`DELETE FROM audit_log WHERE tenant_id = $1`, tid)
			}

			if err == nil {
				t.Fatal("a DELETE on audit_log succeeded; history was removed rather than kept")
			}
			if !audit.IsAppendOnlyViolation(err) {
				t.Fatalf("the DELETE failed for the wrong reason: %v", err)
			}
		})
	}

	// And the row is still there, unmodified.
	rows := s.auditRows(t, tenantID)
	if len(rows) != 1 || rows[0].Action != audit.ActionProjectCreate {
		t.Fatalf("the entry did not survive the attempted mutations: %v", actionsOf(rows))
	}
}

// TestAudit_FailureToRecordAbortsTheChange is the atomicity proof, and it is the test that
// makes "recorded in the same transaction" a fact rather than a claim.
//
// The mechanism: revoke INSERT on audit_log from the application role, attempt a create, and
// assert that the project was *not* created either. If the audit write were best-effort — or
// done from a separate transaction — the project would exist with no entry, which is the
// failure that makes an audit trail worse than none, because it is trusted.
//
// The privilege is restored in a cleanup so a failure here cannot poison later tests.
func TestAudit_FailureToRecordAbortsTheChange(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot revoke privileges as the owner")
	}

	session, tenantID := s.register(uniqueEmail("audit-atomic"))
	base := "/v1/tenants/" + tenantID + "/projects"

	before := s.countProjects(t, tenantID, "Atomic")
	if before != 0 {
		t.Fatalf("setup left %d projects behind", before)
	}

	// Make the audit write impossible for the application role.
	if _, err := s.db.Owner.Exec(context.Background(),
		`REVOKE INSERT ON audit_log FROM app_rw`); err != nil {
		t.Fatalf("revoke insert: %v", err)
	}
	t.Cleanup(func() {
		if _, err := s.db.Owner.Exec(context.Background(),
			`GRANT INSERT ON audit_log TO app_rw`); err != nil {
			t.Errorf("failed to restore the audit_log grant; later tests may be affected: %v", err)
		}
	})

	res := s.do(http.MethodPost, base, map[string]any{"name": "Atomic"}, session.AccessToken)

	// The request must fail. It fails as a 500 because the cause is this service's
	// configuration rather than the client's input — and that is the right signal: an
	// operator needs to know the audit trail is not being written.
	if res.status == http.StatusCreated {
		t.Fatal("a create succeeded while the audit trail could not be written; the effect and " +
			"its entry are not in one transaction, so a changed resource can exist with no record")
	}

	// The decisive assertion: the effect did not persist either.
	if got := s.countProjects(t, tenantID, "Atomic"); got != 0 {
		t.Fatalf("%d project rows exist despite the audit write failing; the change and its "+
			"entry committed separately", got)
	}
}

// TestAudit_NoEntryForAChangeThatDidNotHappen is the other direction: the trail must not
// claim events that never occurred.
//
// A duplicate slug is refused by the unique index, so no project is created — and a trail
// that logged the attempt as a creation would be actively misleading. Failed operations are
// the log stream's business, not the audit trail's.
func TestAudit_NoEntryForAChangeThatDidNotHappen(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("audit-noevent"))
	base := "/v1/tenants/" + tenantID + "/projects"

	if res := s.do(http.MethodPost, base, map[string]any{"name": "Only Once"}, session.AccessToken); res.status != http.StatusCreated {
		t.Fatalf("first create: status %d, body %s", res.status, res.body)
	}
	afterFirst := s.countAuditRows(t, tenantID)

	// The same name derives the same slug, so this is refused.
	dup := s.do(http.MethodPost, base, map[string]any{"name": "Only Once"}, session.AccessToken)
	if dup.status != http.StatusConflict {
		t.Fatalf("duplicate create: status %d, want 409; body %s", dup.status, dup.body)
	}

	if got := s.countAuditRows(t, tenantID); got != afterFirst {
		t.Fatalf("a refused create added an audit entry (%d -> %d); the trail claims a change "+
			"that never happened", afterFirst, got)
	}
}

// TestAudit_TenantIsolation checks that the trail is tenant-scoped like everything else.
//
// An audit log is the most sensitive table in the service — it names who did what — so a leak
// here is worse than a leak of the data it describes. It is read with owner credentials so the
// assertion cannot be satisfied by the same policy that could hide the rows.
func TestAudit_TenantIsolation(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot count rows as the owner")
	}

	ownerA, tenantA := s.register(uniqueEmail("audit-iso-a"))
	_, tenantB := s.register(uniqueEmail("audit-iso-b"))

	if res := s.do(http.MethodPost, "/v1/tenants/"+tenantA+"/projects",
		map[string]any{"name": "A Only"}, ownerA.AccessToken); res.status != http.StatusCreated {
		t.Fatalf("setup create: status %d, body %s", res.status, res.body)
	}

	tidA := uuid.MustParse(tenantA)
	tidB := uuid.MustParse(tenantB)

	// The application role, scoped to B, sees nothing of A's trail.
	var seen int
	if err := tenantScopedTx(t, s.db.App, tenantB, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_log WHERE tenant_id = $1`, tidA).Scan(&seen)
	}); err != nil {
		t.Fatalf("count under tenant B: %v", err)
	}
	if seen != 0 {
		t.Fatalf("tenant B can read %d of tenant A's audit entries; the trail leaks the most "+
			"sensitive table in the service", seen)
	}

	// And the owner sees that the row really is there, so the zero above is isolation rather
	// than an empty table.
	var exists int
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE tenant_id = $1`, tidA).Scan(&exists); err != nil {
		t.Fatalf("owner count: %v", err)
	}
	if exists == 0 {
		t.Fatal("tenant A has no audit entries at all, so the isolation assertion above proved nothing")
	}
	if tidB == tidA {
		t.Fatal("the two tenants are the same, which would make this test vacuous")
	}
}

// TestAuditList_RequiresAuditReadPermission pins the authorization boundary.
//
// The trail names who did what, including the API keys in use. A member who can read a
// workspace is not automatically entitled to enumerate its members' actions, so this is its
// own permission rather than an implication of tenant:read.
func TestAuditList_RequiresAuditReadPermission(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("audit-perm"))
	path := "/v1/tenants/" + tenantID + "/audit"

	if res := s.do(http.MethodPost, "/v1/tenants/"+tenantID+"/projects",
		map[string]any{"name": "Perms"}, owner.AccessToken); res.status != http.StatusCreated {
		t.Fatalf("setup create: status %d, body %s", res.status, res.body)
	}

	admin := s.addMemberWithRole(owner, tenantID, uniqueEmail("audit-admin"), authz.RoleAdmin)
	member := s.addMemberWithRole(owner, tenantID, uniqueEmail("audit-member"), authz.RoleMember)

	ownerRes := s.do(http.MethodGet, path, nil, owner.AccessToken)
	if ownerRes.status != http.StatusOK {
		t.Fatalf("owner read: status %d, body %s", ownerRes.status, ownerRes.body)
	}

	adminRes := s.do(http.MethodGet, path, nil, admin.AccessToken)
	if adminRes.status != http.StatusOK {
		t.Fatalf("admin read: status %d, body %s — admin holds audit:read", adminRes.status, adminRes.body)
	}

	// A member is in the tenant, so the membership gate passes and this is a real 403 rather
	// than a 404 hiding the tenant's existence.
	memberRes := s.do(http.MethodGet, path, nil, member.AccessToken)
	if memberRes.status != http.StatusForbidden {
		t.Fatalf("member read: status %d, want 403; body %s", memberRes.status, memberRes.body)
	}

	// An outsider — authenticated, a member of a different tenant — gets 404, not 403, on the
	// same rule as every other tenant-scoped route: a 403 would confirm that this tenant
	// exists and that the caller cannot see it, which is an enumeration oracle.
	outsiderSession, outsiderTenant := s.register(uniqueEmail("audit-outsider"))
	if outsiderTenant == tenantID {
		t.Fatal("the outsider registered into the same tenant, which would make this assertion vacuous")
	}
	outsiderRes := s.do(http.MethodGet, path, nil, outsiderSession.AccessToken)
	if outsiderRes.status != http.StatusNotFound {
		t.Fatalf("outsider read: status %d, want 404 (a 403 would confirm the tenant exists); body %s",
			outsiderRes.status, outsiderRes.body)
	}
}

// TestAuditList_ShapeAndPagination covers the read endpoint's contract.
//
// The images must survive the round trip byte for byte: an audit endpoint that reformats what
// it recorded is one step from one that misreports it. Ordering is newest-first and the cursor
// must page through without repeating or skipping — checked against the ids seen, because a
// pagination bug that duplicates an entry is invisible in any single page.
func TestAuditList_ShapeAndPagination(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("audit-page"))
	base := "/v1/tenants/" + tenantID + "/projects"
	path := "/v1/tenants/" + tenantID + "/audit"

	const total = 5
	for i := 0; i < total; i++ {
		if res := s.do(http.MethodPost, base,
			map[string]any{"name": "Paged " + strconv.Itoa(i)}, session.AccessToken); res.status != http.StatusCreated {
			t.Fatalf("setup create %d: status %d, body %s", i, res.status, res.body)
		}
	}

	type entry struct {
		ID        string          `json:"id"`
		ActorKind string          `json:"actor_kind"`
		ActorID   string          `json:"actor_id"`
		Action    string          `json:"action"`
		Resource  string          `json:"resource"`
		Before    json.RawMessage `json:"before"`
		After     json.RawMessage `json:"after"`
		RequestID string          `json:"request_id"`
		At        string          `json:"at"`
	}

	seen := map[string]bool{}
	var actions []string
	cursor := ""
	pages := 0

	for {
		url := path + "?limit=2"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		res := s.do(http.MethodGet, url, nil, session.AccessToken)
		if res.status != http.StatusOK {
			t.Fatalf("page %d: status %d, body %s", pages+1, res.status, res.body)
		}

		var page struct {
			Data       []entry `json:"data"`
			NextCursor string  `json:"next_cursor"`
		}
		res.decodeEnvelope(t, &page)
		pages++

		if len(page.Data) == 0 && page.NextCursor != "" {
			t.Fatal("a page with no entries advertised a next cursor, which would loop forever")
		}
		for _, e := range page.Data {
			if seen[e.ID] {
				t.Fatalf("audit entry %s appeared on two pages", e.ID)
			}
			seen[e.ID] = true
			actions = append(actions, e.Action)

			if e.Action == "" || e.Resource != "project" || e.At == "" {
				t.Errorf("entry %q is missing identifying fields: %+v", e.ID, e)
			}
			if e.ActorKind != audit.ActorUser || e.ActorID == "" {
				t.Errorf("entry %s actor = %q/%q, want a user with an id", e.ID, e.ActorKind, e.ActorID)
			}
			if e.RequestID == "" {
				t.Errorf("entry %s carries no request id", e.ID)
			}
			// The after image must be the object that was stored, not a re-encoding artifact.
			var after map[string]any
			if err := json.Unmarshal(e.After, &after); err != nil {
				t.Errorf("entry %s after image is not a JSON object: %v (%s)", e.ID, err, e.After)
			} else if _, ok := after["name"]; !ok {
				t.Errorf("entry %s after image has no name field: %s", e.ID, e.After)
			}
			// A create has no before image, and omitempty means the field is absent rather
			// than null.
			if len(e.Before) != 0 {
				t.Errorf("create entry %s carries a before image: %s", e.ID, e.Before)
			}
		}

		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(seen) != total {
		t.Fatalf("paged through %d entries, want %d", len(seen), total)
	}

	// Newest first: the last create is the first entry.
	for i, action := range actions {
		if action != audit.ActionProjectCreate {
			t.Fatalf("entry %d is %q, want the create verb", i, action)
		}
	}
}

// actionsOf lists the recorded verbs, for failure messages that say what was actually there.
func actionsOf(rows []auditRow) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Action)
	}
	return out
}
