package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aditya0si/tenant-api-platform/internal/platform/migrations"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// TestLoad_IsSortedAndUnique guards the invariants the runner relies on. A
// duplicate version would make apply order ambiguous; an unsorted list would make
// it non-deterministic, which is only visible as a production incident.
func TestLoad_IsSortedAndUnique(t *testing.T) {
	migs, err := migrations.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("no migrations embedded; the //go:embed directive is not matching *.sql")
	}

	seen := map[string]string{}
	for i, m := range migs {
		if m.Version == "" || m.Name == "" || m.Checksum == "" {
			t.Fatalf("migration %d is incomplete: %+v", i, m)
		}
		if prev, dup := seen[m.Version]; dup {
			t.Fatalf("duplicate version %s in %s and %s", m.Version, prev, m.Name)
		}
		seen[m.Version] = m.Name

		if i > 0 && migs[i-1].Name >= m.Name {
			t.Fatalf("migrations not sorted: %s before %s", migs[i-1].Name, m.Name)
		}
		if !strings.HasSuffix(m.Name, ".sql") {
			t.Fatalf("migration %s is not a .sql file", m.Name)
		}
	}
}

// TestUp_IsIdempotent proves re-running migrations is safe: the second run
// applies nothing and reports the first run's work as already current. Deploys
// restart, and a migration runner that is not idempotent turns a restart into an
// outage.
func TestUp_IsIdempotent(t *testing.T) {
	d := testsupport.RequireDB(t)
	if d.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set; cannot exercise the migration runner")
	}
	ctx := context.Background()

	first, err := migrations.Up(ctx, d.Owner)
	if err != nil {
		t.Fatalf("first Up: %v", err)
	}
	_ = first

	second, err := migrations.Up(ctx, d.Owner)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if len(second.Applied) != 0 {
		t.Fatalf("second run applied %v; migrations are not idempotent", second.Applied)
	}
	if second.AlreadyCurrent == 0 {
		t.Fatal("second run reported no current migrations; the history table is not being read")
	}
}

// TestApplied_RecordsChecksums proves history is recorded with a checksum, which
// is what makes the immutability check in Up meaningful. Without a recorded
// checksum, editing an applied migration would silently diverge environments.
func TestApplied_RecordsChecksums(t *testing.T) {
	d := testsupport.RequireDB(t)
	if d.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set; cannot exercise the migration runner")
	}
	ctx := context.Background()

	if _, err := migrations.Up(ctx, d.Owner); err != nil {
		t.Fatalf("Up: %v", err)
	}
	applied, err := migrations.Applied(ctx, d.Owner)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("no applied migrations recorded")
	}

	embedded, err := migrations.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	byVersion := map[string]string{}
	for _, m := range embedded {
		byVersion[m.Version] = m.Checksum
	}
	for _, a := range applied {
		want, ok := byVersion[a.Version]
		if !ok {
			t.Fatalf("recorded migration %s is not present in the embedded set", a.Version)
		}
		if a.Checksum != want {
			t.Fatalf("checksum mismatch for %s: recorded %s, embedded %s", a.Version, a.Checksum, want)
		}
	}
}

// TestUp_ConcurrentRunsAreSerialised proves the advisory lock does its job:
// several deployers starting at once must not race, and none of them may error.
// The second and later runners should observe the work as already done.
func TestUp_ConcurrentRunsAreSerialised(t *testing.T) {
	d := testsupport.RequireDB(t)
	if d.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set; cannot exercise the migration runner")
	}
	ctx := context.Background()

	if _, err := migrations.Up(ctx, d.Owner); err != nil {
		t.Fatalf("prime migrations: %v", err)
	}

	const runners = 4
	errs := make(chan error, runners)
	for i := 0; i < runners; i++ {
		go func() {
			_, err := migrations.Up(ctx, d.Owner)
			errs <- err
		}()
	}
	for i := 0; i < runners; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Up failed: %v", err)
		}
	}
}
