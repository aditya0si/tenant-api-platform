package project_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/project"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// fixture wires the two stores a project test needs and resolves an authorized
// caller for a fresh tenant.
type fixture struct {
	projects *project.Store
	tenants  *tenant.Store
	auth     tenant.Authorized
	tenantID uuid.UUID
	userID   uuid.UUID
}

func newFixture(t *testing.T, label string) fixture {
	t.Helper()
	d := testsupport.RequireDB(t)

	tenantID, userID := testsupport.NewTenant(t, d.App, label)
	tenants := tenant.NewStore(d.App)

	auth, err := tenants.Resolve(context.Background(), tenantID, userID)
	if err != nil {
		t.Fatalf("resolve tenant %s: %v", label, err)
	}

	return fixture{
		projects: project.NewStore(d.App),
		tenants:  tenants,
		auth:     auth,
		tenantID: tenantID,
		userID:   userID,
	}
}

// TestCreate_RoundTrip covers the happy path and asserts that attribution comes
// from the authorized principal rather than from the request.
func TestCreate_RoundTrip(t *testing.T) {
	f := newFixture(t, "proj-create")
	ctx := context.Background()

	created, err := f.projects.Create(ctx, f.auth, project.CreateInput{
		Name:        "Payments API",
		Description: "The money path",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if created.ID == uuid.Nil {
		t.Fatal("created project has a nil id")
	}
	if created.TenantID != f.tenantID {
		t.Fatalf("tenant = %s, want %s", created.TenantID, f.tenantID)
	}
	if created.Slug != "payments-api" {
		t.Fatalf("slug = %q, want payments-api (derived from the name)", created.Slug)
	}
	if created.Version != 1 {
		t.Fatalf("version = %d, want 1 for a new project", created.Version)
	}
	if created.CreatedBy == nil {
		t.Fatal("created_by is nil: a human-created project must name its creator")
	}
	if *created.CreatedBy != f.userID {
		t.Fatalf("created_by = %s, want the authorized principal %s", *created.CreatedBy, f.userID)
	}
	if created.CreatedByKey != nil {
		t.Fatal("created_by_key is set on a human-created project; exactly one attribution column may be populated")
	}
	if !created.CreatedByHuman() {
		t.Fatal("CreatedByHuman reports false for a user-created project")
	}
	if created.Archived() {
		t.Fatal("a new project is already archived")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatal("timestamps were not populated by the database")
	}

	got, err := f.projects.Get(ctx, f.auth, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID || got.Name != created.Name {
		t.Fatalf("Get returned %+v, want the created project", got)
	}
}

// TestCreate_DuplicateSlugIsConflict proves the partial unique index is what
// enforces slug uniqueness, and that the error surfaces as a conflict rather than
// a driver-specific failure.
func TestCreate_DuplicateSlugIsConflict(t *testing.T) {
	f := newFixture(t, "proj-dupe")
	ctx := context.Background()

	if _, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Payments API"}); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	_, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Payments API"})
	if !errors.Is(err, apperr.ErrConflict) {
		t.Fatalf("error = %v, want ErrConflict", err)
	}
}

// TestCreate_SlugIsScopedToTenant proves the uniqueness constraint is
// per-tenant: two tenants may each have a "payments-api", which is the whole
// point of slugging rather than exposing ids.
func TestCreate_SlugIsScopedToTenant(t *testing.T) {
	a := newFixture(t, "slug-a")
	b := newFixture(t, "slug-b")
	ctx := context.Background()

	if _, err := a.projects.Create(ctx, a.auth, project.CreateInput{Name: "Payments API"}); err != nil {
		t.Fatalf("tenant A Create: %v", err)
	}
	if _, err := b.projects.Create(ctx, b.auth, project.CreateInput{Name: "Payments API"}); err != nil {
		t.Fatalf("tenant B could not reuse a slug that is unique in its own tenant: %v", err)
	}
}

// TestArchive_FreesTheSlug proves the partial index behaves as designed: archiving
// releases the name so a tenant can reuse it, which a full unique index would
// forbid forever.
func TestArchive_FreesTheSlug(t *testing.T) {
	f := newFixture(t, "proj-slug-reuse")
	ctx := context.Background()

	first, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Payments API"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.projects.Archive(ctx, f.auth, first.ID); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	second, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Payments API"})
	if err != nil {
		t.Fatalf("could not reuse the slug of an archived project: %v", err)
	}
	if second.ID == first.ID {
		t.Fatal("reusing a slug returned the archived project")
	}

	// Both rows exist; the archived one is simply not listed by default.
	all, err := f.projects.List(ctx, f.auth, project.ListFilter{IncludeArchived: true}, nil, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all.Projects) != 2 {
		t.Fatalf("include_archived listing returned %d projects, want 2", len(all.Projects))
	}

	live, err := f.projects.List(ctx, f.auth, project.ListFilter{}, nil, 50)
	if err != nil {
		t.Fatalf("List (live): %v", err)
	}
	if len(live.Projects) != 1 || live.Projects[0].ID != second.ID {
		t.Fatalf("live listing returned %+v, want only the new project", live.Projects)
	}
}

// TestGet_CrossTenantIsNotFound is the IDOR assertion at the project layer.
//
// A project that exists but belongs to another tenant must be reported exactly as
// an unknown id is: not-found, never forbidden. A distinguishable error would
// confirm the id exists and turn the endpoint into an enumeration oracle.
func TestGet_CrossTenantIsNotFound(t *testing.T) {
	victim := newFixture(t, "proj-victim")
	attacker := newFixture(t, "proj-attacker")
	ctx := context.Background()

	secret, err := victim.projects.Create(ctx, victim.auth, project.CreateInput{Name: "Secret Roadmap"})
	if err != nil {
		t.Fatalf("victim Create: %v", err)
	}

	_, err = attacker.projects.Get(ctx, attacker.auth, secret.ID)
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("cross-tenant Get error = %v, want ErrNotFound", err)
	}

	// An id that exists nowhere must produce the identical error, or the two cases
	// are distinguishable from outside.
	_, err = attacker.projects.Get(ctx, attacker.auth, uuid.Must(uuid.NewV7()))
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("unknown-id Get error = %v, want ErrNotFound", err)
	}
}

// TestUpdate_CrossTenantIsNotFound is the write-side counterpart. It must also
// leave the victim's row untouched, which a naive implementation that checked
// visibility after writing would fail.
func TestUpdate_CrossTenantIsNotFound(t *testing.T) {
	victim := newFixture(t, "upd-victim")
	attacker := newFixture(t, "upd-attacker")
	ctx := context.Background()

	secret, err := victim.projects.Create(ctx, victim.auth, project.CreateInput{Name: "Secret Roadmap"})
	if err != nil {
		t.Fatalf("victim Create: %v", err)
	}

	name := "Pwned"
	_, err = attacker.projects.Update(ctx, attacker.auth, secret.ID, project.UpdateInput{
		Name:            &name,
		ExpectedVersion: secret.Version,
	})
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("cross-tenant Update error = %v, want ErrNotFound", err)
	}

	// The victim's project must be unchanged.
	after, err := victim.projects.Get(ctx, victim.auth, secret.ID)
	if err != nil {
		t.Fatalf("victim Get after attack: %v", err)
	}
	if after.Name != secret.Name {
		t.Fatalf("cross-tenant update modified the row: name is now %q", after.Name)
	}
	if after.Version != secret.Version {
		t.Fatalf("cross-tenant update bumped the version: %d", after.Version)
	}
}

// TestArchive_CrossTenantIsNotFound proves archiving cannot be used to disable
// another tenant's project — the highest-impact version of the same bug.
func TestArchive_CrossTenantIsNotFound(t *testing.T) {
	victim := newFixture(t, "arc-victim")
	attacker := newFixture(t, "arc-attacker")
	ctx := context.Background()

	secret, err := victim.projects.Create(ctx, victim.auth, project.CreateInput{Name: "Secret Roadmap"})
	if err != nil {
		t.Fatalf("victim Create: %v", err)
	}

	if err := attacker.projects.Archive(ctx, attacker.auth, secret.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("cross-tenant Archive error = %v, want ErrNotFound", err)
	}

	after, err := victim.projects.Get(ctx, victim.auth, secret.ID)
	if err != nil {
		t.Fatalf("victim Get after attack: %v", err)
	}
	if after.Archived() {
		t.Fatal("a foreign tenant archived the victim's project")
	}
}

// TestUpdate_OptimisticConcurrency is the lost-update assertion.
//
// Two clients read version 1 and both try to write. The first must succeed and the
// second must be told its copy is stale — not silently overwrite the first. The
// failure this prevents is invisible without the version predicate: both writes
// succeed, the later one wins, and the first client's change is gone with no error
// anywhere.
func TestUpdate_OptimisticConcurrency(t *testing.T) {
	f := newFixture(t, "proj-oc")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Shared Doc"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	staleVersion := p.Version

	// Client one wins.
	first := "Client One's title"
	updated, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
		Name:            &first,
		ExpectedVersion: staleVersion,
	})
	if err != nil {
		t.Fatalf("first Update: %v", err)
	}
	if updated.Version != staleVersion+1 {
		t.Fatalf("version = %d, want %d", updated.Version, staleVersion+1)
	}

	// Client two, still holding the stale version, must be rejected.
	second := "Client Two's title"
	_, err = f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
		Name:            &second,
		ExpectedVersion: staleVersion,
	})
	if !errors.Is(err, apperr.ErrVersionConflict) {
		t.Fatalf("stale Update error = %v, want ErrVersionConflict", err)
	}

	// Client one's change must have survived, and the version must not have moved.
	after, err := f.projects.Get(ctx, f.auth, p.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.Name != first {
		t.Fatalf("name = %q, want the winning write %q — the lost update happened", after.Name, first)
	}
	if after.Version != staleVersion+1 {
		t.Fatalf("version = %d, want %d: a rejected update must not bump it", after.Version, staleVersion+1)
	}

	// Client two re-reads and retries successfully.
	third := "Client Two's title, retried"
	retried, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
		Name:            &third,
		ExpectedVersion: after.Version,
	})
	if err != nil {
		t.Fatalf("retry after re-read failed: %v", err)
	}
	if retried.Name != third {
		t.Fatalf("name = %q, want %q", retried.Name, third)
	}
}

// TestUpdate_PartialSemantics proves the pointer fields distinguish "not supplied"
// from "set to empty". Collapsing the two would make it impossible to clear a
// description, and would silently wipe fields on every update.
func TestUpdate_PartialSemantics(t *testing.T) {
	f := newFixture(t, "proj-partial")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{
		Name:        "Original Name",
		Description: "Original description",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("omitted fields are preserved", func(t *testing.T) {
		name := "Renamed"
		got, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
			Name:            &name,
			ExpectedVersion: p.Version,
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got.Name != "Renamed" {
			t.Fatalf("name = %q, want Renamed", got.Name)
		}
		if got.Description != "Original description" {
			t.Fatalf("description = %q, want it preserved — a nil field must mean unchanged", got.Description)
		}
		p = got
	})

	t.Run("an empty string clears a field", func(t *testing.T) {
		empty := ""
		got, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
			Description:     &empty,
			ExpectedVersion: p.Version,
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got.Description != "" {
			t.Fatalf("description = %q, want it cleared — a pointer to empty must mean set-to-empty", got.Description)
		}
		if got.Name != "Renamed" {
			t.Fatalf("name = %q, want it preserved", got.Name)
		}
		p = got
	})

	t.Run("leading and trailing whitespace is trimmed", func(t *testing.T) {
		padded := "  Padded Name  "
		got, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
			Name:            &padded,
			ExpectedVersion: p.Version,
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if got.Name != "Padded Name" {
			t.Fatalf("name = %q, want it trimmed", got.Name)
		}
		p = got
	})
}

// TestUpdate_ArchivedIsNotFound proves an archived project is not editable, and
// that the refusal is indistinguishable from "no such project" — so a client
// cannot use the update endpoint to learn that a project was retired.
func TestUpdate_ArchivedIsNotFound(t *testing.T) {
	f := newFixture(t, "proj-upd-archived")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Doomed"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.projects.Archive(ctx, f.auth, p.ID); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	name := "Resurrected"
	_, err = f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
		Name:            &name,
		ExpectedVersion: p.Version,
	})
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("update of an archived project = %v, want ErrNotFound", err)
	}
}

// TestUpdate_SeparatesStaleFromMissing is the mistake this code was written to
// avoid.
//
// A conditional UPDATE returns zero rows for three different reasons — no such
// project, wrong tenant, or a stale version — and answering 404 for all of them
// would make the version conflict invisible to the client, which is exactly the
// case that needs a 409 so the client knows to re-read and retry.
func TestUpdate_SeparatesStaleFromMissing(t *testing.T) {
	f := newFixture(t, "proj-upd-classify")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Subject"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	name := "New"
	t.Run("stale version is a conflict", func(t *testing.T) {
		_, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{
			Name:            &name,
			ExpectedVersion: p.Version + 99,
		})
		if !errors.Is(err, apperr.ErrVersionConflict) {
			t.Fatalf("error = %v, want ErrVersionConflict", err)
		}
	})

	t.Run("unknown id is not-found", func(t *testing.T) {
		_, err := f.projects.Update(ctx, f.auth, uuid.Must(uuid.NewV7()), project.UpdateInput{
			Name:            &name,
			ExpectedVersion: 1,
		})
		if !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})

	t.Run("version conflict and not-found are different errors", func(t *testing.T) {
		if errors.Is(apperr.ErrVersionConflict, apperr.ErrNotFound) {
			t.Fatal("the two sentinels are indistinguishable, so the API cannot answer 409 and 404 differently")
		}
	})
}

// TestUpdate_RejectsInvalidInput covers validation that must run before any SQL.
func TestUpdate_RejectsInvalidInput(t *testing.T) {
	f := newFixture(t, "proj-upd-validate")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Subject"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("zero expected version", func(t *testing.T) {
		name := "New"
		if _, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{Name: &name}); !errors.Is(err, apperr.ErrValidation) {
			t.Fatalf("error = %v, want ErrValidation — an update without a version assertion is a lost-write", err)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		empty := "   "
		_, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{Name: &empty, ExpectedVersion: p.Version})
		if !errors.Is(err, apperr.ErrValidation) {
			t.Fatalf("error = %v, want ErrValidation", err)
		}
	})

	t.Run("oversized description", func(t *testing.T) {
		big := make([]byte, 2001)
		for i := range big {
			big[i] = 'x'
		}
		s := string(big)
		_, err := f.projects.Update(ctx, f.auth, p.ID, project.UpdateInput{Description: &s, ExpectedVersion: p.Version})
		if !errors.Is(err, apperr.ErrValidation) {
			t.Fatalf("error = %v, want ErrValidation", err)
		}
	})

	t.Run("nil id", func(t *testing.T) {
		name := "New"
		_, err := f.projects.Update(ctx, f.auth, uuid.Nil, project.UpdateInput{Name: &name, ExpectedVersion: 1})
		if !errors.Is(err, apperr.ErrNotFound) {
			t.Fatalf("error = %v, want ErrNotFound", err)
		}
	})
}

// TestArchive_IsIdempotent covers retry behaviour: archiving twice must succeed,
// because the caller's intent is satisfied either way and a retried request must
// behave like the one it retried.
func TestArchive_IsIdempotent(t *testing.T) {
	f := newFixture(t, "proj-arch-idem")
	ctx := context.Background()

	p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Retire Me"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := f.projects.Archive(ctx, f.auth, p.ID); err != nil {
		t.Fatalf("first Archive: %v", err)
	}
	first, err := f.projects.Get(ctx, f.auth, p.ID)
	if err != nil {
		t.Fatalf("Get after archive: %v", err)
	}

	if err := f.projects.Archive(ctx, f.auth, p.ID); err != nil {
		t.Fatalf("second Archive returned an error, so a retry is not idempotent: %v", err)
	}

	second, err := f.projects.Get(ctx, f.auth, p.ID)
	if err != nil {
		t.Fatalf("Get after second archive: %v", err)
	}

	// The retirement time must be the first one, not the most recent retry: a
	// re-archive that moved the timestamp would corrupt the audit record.
	if first.ArchivedAt == nil || second.ArchivedAt == nil {
		t.Fatal("archived_at was not set")
	}
	if !first.ArchivedAt.Equal(*second.ArchivedAt) {
		t.Fatalf("archived_at moved on retry: %s then %s", first.ArchivedAt, second.ArchivedAt)
	}
}

// TestList_EmptyTenant proves a listing with no rows is an empty page rather than
// an error, and that it reports no next page.
func TestList_EmptyTenant(t *testing.T) {
	f := newFixture(t, "proj-empty")

	res, err := f.projects.List(context.Background(), f.auth, project.ListFilter{}, nil, 20)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(res.Projects) != 0 {
		t.Fatalf("empty tenant returned %d projects", len(res.Projects))
	}
	if res.Next != nil {
		t.Fatal("an empty page reported a next page")
	}
}

// TestList_KeysetWalkIsCompleteAndUnique is the core pagination property.
//
// It walks a collection in small pages and asserts the union is exactly the set
// that was inserted, with no duplicates and no omissions. A page boundary that was
// off by one — the classic bug when a cursor is exclusive where it should be
// inclusive, or vice versa — shows up here as a repeated or missing row.
func TestList_KeysetWalkIsCompleteAndUnique(t *testing.T) {
	f := newFixture(t, "proj-walk")
	ctx := context.Background()

	const total = 25
	created := map[uuid.UUID]bool{}
	for i := 0; i < total; i++ {
		p, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: projectName(i)})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		created[p.ID] = true
	}

	var (
		seen      []uuid.UUID
		after     *cursor.Position
		page      int
		pageSizes []int
	)
	for {
		page++
		if page > 50 {
			t.Fatal("pagination did not terminate: a cursor is being issued that never advances")
		}
		res, err := f.projects.List(ctx, f.auth, project.ListFilter{}, after, 7)
		if err != nil {
			t.Fatalf("List page %d: %v", page, err)
		}
		pageSizes = append(pageSizes, len(res.Projects))
		for _, p := range res.Projects {
			seen = append(seen, p.ID)
		}
		if res.Next == nil {
			break
		}
		after = res.Next
	}

	if len(seen) != total {
		t.Fatalf("walked %d rows, want %d (page sizes: %v)", len(seen), total, pageSizes)
	}

	unique := map[uuid.UUID]bool{}
	for _, id := range seen {
		if unique[id] {
			t.Fatalf("row %s appeared on more than one page", id)
		}
		unique[id] = true
		if !created[id] {
			t.Fatalf("walk returned unknown row %s", id)
		}
	}
	for id := range created {
		if !unique[id] {
			t.Fatalf("row %s was never returned", id)
		}
	}

	// Every page except the last must be full, which is what proves the extra row
	// fetched to detect "more" is not being leaked into the response.
	for i, size := range pageSizes[:len(pageSizes)-1] {
		if size != 7 {
			t.Fatalf("page %d has %d rows, want a full page of 7", i+1, size)
		}
	}
}

// TestList_InsertsDuringWalkDoNotCorruptPages is the property that offset
// pagination cannot provide, and the reason keyset was chosen.
//
// A row is inserted between two page requests. Because it sorts before the cursor
// position (newest first), it must not appear on a later page — it would only ever
// have appeared on page one. With OFFSET, that same insert would shift every
// subsequent window by one and silently push a not-yet-read row off the end.
func TestList_InsertsDuringWalkDoNotCorruptPages(t *testing.T) {
	f := newFixture(t, "proj-walk-insert")
	ctx := context.Background()

	for i := 0; i < 12; i++ {
		if _, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: projectName(i)}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	first, err := f.projects.List(ctx, f.auth, project.ListFilter{}, nil, 5)
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Projects) != 5 || first.Next == nil {
		t.Fatalf("first page returned %d rows with next=%v", len(first.Projects), first.Next != nil)
	}

	// Insert a row that is newer than everything already read. It sorts before the
	// cursor, so it belongs to the pages already consumed.
	intruder, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Inserted Mid-Walk"})
	if err != nil {
		t.Fatalf("intruder Create: %v", err)
	}

	// Continue the walk from where the client left off.
	seen := map[uuid.UUID]bool{}
	for _, p := range first.Projects {
		seen[p.ID] = true
	}
	after := first.Next
	for page := 0; page < 20; page++ {
		res, err := f.projects.List(ctx, f.auth, project.ListFilter{}, after, 5)
		if err != nil {
			t.Fatalf("continuation page: %v", err)
		}
		for _, p := range res.Projects {
			if seen[p.ID] {
				t.Fatalf("row %s (%q) was returned twice across the walk", p.ID, p.Name)
			}
			seen[p.ID] = true
		}
		if res.Next == nil {
			break
		}
		after = res.Next
	}

	if seen[intruder.ID] {
		t.Fatal("a row inserted mid-walk appeared in a later page; the cursor is not a stable position")
	}

	// The original twelve must all have been returned exactly once.
	if len(seen) != 12 {
		t.Fatalf("walk returned %d rows, want the 12 that existed when it started", len(seen))
	}
}

// TestList_BindingRejectsCursorFromAnotherQuery proves a cursor cannot be carried
// across a filter change.
//
// Without binding, replaying a cursor minted for the default listing against
// ?include_archived=true would start at an arbitrary position and return a page the
// client cannot recognise as wrong. The binding turns that silent corruption into a
// clean rejection.
func TestList_BindingRejectsCursorFromAnotherQuery(t *testing.T) {
	f := newFixture(t, "proj-binding")
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		if _, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: projectName(i)}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
	}

	live := project.ListFilter{}
	all := project.ListFilter{IncludeArchived: true}

	// The bindings must differ, or a cursor could be replayed across the two.
	if project.Binding(f.auth, live) == project.Binding(f.auth, all) {
		t.Fatal("the two filters produce the same cursor binding")
	}

	// The same holds across tenants.
	other := newFixture(t, "proj-binding-other")
	if project.Binding(f.auth, live) == project.Binding(other.auth, live) {
		t.Fatal("two different tenants produce the same cursor binding")
	}
}

// TestList_IncludeArchivedFilter proves the filter is honoured in both directions,
// including that an archived row is hidden by default rather than merely deprioritized.
func TestList_IncludeArchivedFilter(t *testing.T) {
	f := newFixture(t, "proj-filter")
	ctx := context.Background()

	liveProject, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Live"})
	if err != nil {
		t.Fatalf("Create live: %v", err)
	}
	archivedProject, err := f.projects.Create(ctx, f.auth, project.CreateInput{Name: "Archived"})
	if err != nil {
		t.Fatalf("Create archived: %v", err)
	}
	if err := f.projects.Archive(ctx, f.auth, archivedProject.ID); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	live, err := f.projects.List(ctx, f.auth, project.ListFilter{}, nil, 50)
	if err != nil {
		t.Fatalf("List live: %v", err)
	}
	if len(live.Projects) != 1 || live.Projects[0].ID != liveProject.ID {
		t.Fatalf("default listing = %+v, want only the live project", live.Projects)
	}

	allRes, err := f.projects.List(ctx, f.auth, project.ListFilter{IncludeArchived: true}, nil, 50)
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if len(allRes.Projects) != 2 {
		t.Fatalf("include_archived listing returned %d rows, want 2", len(allRes.Projects))
	}

	// The archived row must still carry its timestamp, so a client can tell the two
	// apart without a second request.
	var sawArchived bool
	for _, p := range allRes.Projects {
		if p.ID == archivedProject.ID {
			sawArchived = true
			if !p.Archived() {
				t.Fatal("an archived project was returned without its archived_at timestamp")
			}
		}
	}
	if !sawArchived {
		t.Fatal("the archived project is missing from the include_archived listing")
	}
}

// TestList_ScopedToTenant is the isolation assertion for the listing path.
func TestList_ScopedToTenant(t *testing.T) {
	a := newFixture(t, "list-scope-a")
	b := newFixture(t, "list-scope-b")
	ctx := context.Background()

	mine, err := a.projects.Create(ctx, a.auth, project.CreateInput{Name: "Mine"})
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	theirs, err := b.projects.Create(ctx, b.auth, project.CreateInput{Name: "Theirs"})
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}

	res, err := a.projects.List(ctx, a.auth, project.ListFilter{IncludeArchived: true}, nil, 50)
	if err != nil {
		t.Fatalf("List A: %v", err)
	}
	if len(res.Projects) != 1 {
		t.Fatalf("tenant A's listing returned %d rows, want 1", len(res.Projects))
	}
	if res.Projects[0].ID != mine.ID {
		t.Fatalf("tenant A's listing returned %s, want %s", res.Projects[0].ID, mine.ID)
	}
	for _, p := range res.Projects {
		if p.ID == theirs.ID {
			t.Fatal("tenant A's listing contains tenant B's project")
		}
	}
}

// TestStore_MethodsRejectZeroAuthorized proves an unauthorized value cannot reach
// the database. A Store with a nil pool is safe here precisely because validation
// happens first: if any method reached the pool, this test would panic instead of
// returning an error, which is the failure worth catching.
func TestStore_MethodsRejectZeroAuthorized(t *testing.T) {
	store := project.NewStore(nil)
	var zero tenant.Authorized
	ctx := context.Background()
	id := uuid.Must(uuid.NewV7())

	t.Run("Create", func(t *testing.T) {
		if _, err := store.Create(ctx, zero, project.CreateInput{Name: "Nope"}); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("Get", func(t *testing.T) {
		if _, err := store.Get(ctx, zero, id); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("Update", func(t *testing.T) {
		name := "Nope"
		_, err := store.Update(ctx, zero, id, project.UpdateInput{Name: &name, ExpectedVersion: 1})
		if !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("Archive", func(t *testing.T) {
		if err := store.Archive(ctx, zero, id); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
	t.Run("List", func(t *testing.T) {
		if _, err := store.List(ctx, zero, project.ListFilter{}, nil, 20); !errors.Is(err, apperr.ErrNoScope) {
			t.Fatalf("error = %v, want ErrNoScope", err)
		}
	})
}

func projectName(i int) string {
	// Distinct names so the derived slugs differ; a shared name would collide on the
	// unique index and the walk would be over fewer rows than expected.
	return "Project " + string(rune('A'+i%26)) + "-" + itoa(i)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}
