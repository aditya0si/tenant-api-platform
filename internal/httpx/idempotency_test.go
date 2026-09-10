package httpx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/httpx"
	"github.com/aditya0si/tenant-api-platform/internal/idempotency"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// rawResult is one HTTP response, returned without touching *testing.T.
type rawResult struct {
	status int
	body   []byte
	header http.Header
}

// doRaw issues a request without touching *testing.T.
//
// The concurrency test issues requests from goroutines, and t.Fatalf is illegal there: it
// calls runtime.Goexit, which only unwinds the goroutine that called it — so a helper that
// fails the test would abandon the request and leave the test asserting on a zero value.
// Returning the result moves every judgement back to the test goroutine.
func (s *server) doRaw(method, path string, body any, token, key string) (rawResult, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return rawResult{}, err
		}
		reader = bytes.NewReader(raw)
	}

	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set(idempotency.Header, key)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rawResult{status: rec.Code, body: rec.Body.Bytes(), header: rec.Header()}, nil
}

// doRawBody issues a request with an already-encoded body.
//
// The oversize case cannot go through doRaw: encoding a 1 MiB body is fine, but the point
// of that test is to send bytes the JSON encoder would happily produce, so the request is
// built from raw bytes and the size is exact rather than approximate.
func (s *server) doRawBody(method, path string, raw []byte, token, key string) (rawResult, error) {
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set(idempotency.Header, key)
	}

	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rawResult{status: rec.Code, body: rec.Body.Bytes(), header: rec.Header()}, nil
}

// countProjects counts rows in projects directly, with owner credentials.
//
// Reading through the API would let the same filter that could hide a duplicate also hide
// the assertion; a superuser reads the table itself. This is the same negative-control
// instinct as connecting as superuser to prove the RLS tests measure RLS.
func (s *server) countProjects(t *testing.T, tenantID, name string) int {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot count rows as the owner")
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatalf("tenant id %q is not a uuid: %v", tenantID, err)
	}
	var n int
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM projects WHERE tenant_id = $1 AND name = $2`, tid, name).Scan(&n); err != nil {
		t.Fatalf("count projects: %v", err)
	}
	return n
}

// countIdempotencyRows counts stored keys, again with owner credentials.
func (s *server) countIdempotencyRows(t *testing.T, tenantID, key string) int {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot count rows as the owner")
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatalf("tenant id %q is not a uuid: %v", tenantID, err)
	}
	var n int
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT count(*) FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, tid, key).Scan(&n); err != nil {
		t.Fatalf("count idempotency rows: %v", err)
	}
	return n
}

// idemState reads a stored key's state, fingerprint and age.
func (s *server) idemState(t *testing.T, tenantID, key string) (state, fingerprint string, age time.Duration) {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot read rows as the owner")
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatalf("tenant id %q is not a uuid: %v", tenantID, err)
	}
	var createdAt time.Time
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT state, fingerprint, created_at FROM idempotency_keys
		  WHERE tenant_id = $1 AND key = $2`, tid, key).Scan(&state, &fingerprint, &createdAt); err != nil {
		t.Fatalf("read idempotency row: %v", err)
	}
	return state, fingerprint, time.Since(createdAt)
}

// setClaimState rewrites a stored key so a test can drive lease expiry without sleeping.
//
// The alternative — constructing the store with a tiny lease — would exercise different SQL
// from the SQL production runs. Backdating the row keeps the statement under test identical
// and makes the assertion about the real lease constant.
//
// Rewinding to in_progress has to clear the recorded response as well as the state, because
// the schema enforces that pairing: idempotency_completed_has_response requires a completed
// row to carry a status and a completion time, and an in_progress row to carry neither. A
// helper that changed only the state would produce a row the schema forbids — which is what
// happens when a test writes a shape its own database would reject.
func (s *server) setClaimState(t *testing.T, tenantID, key, state string, age time.Duration) {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot rewrite rows as the owner")
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatalf("tenant id %q is not a uuid: %v", tenantID, err)
	}

	// The two shapes are written explicitly rather than sharing one statement, so the
	// invariant is visible here exactly as the CHECK states it.
	var sql string
	switch state {
	case "in_progress":
		sql = `UPDATE idempotency_keys
		          SET state = 'in_progress',
		              status_code = NULL,
		              response_headers = NULL,
		              response_body = NULL,
		              completed_at = NULL,
		              created_at = now() - make_interval(secs => $3::double precision)
		        WHERE tenant_id = $1 AND key = $2`
	case "completed":
		sql = `UPDATE idempotency_keys
		          SET state = 'completed', created_at = now() - make_interval(secs => $3::double precision)
		        WHERE tenant_id = $1 AND key = $2`
	default:
		t.Fatalf("setClaimState: unknown state %q", state)
	}

	if _, err := s.db.Owner.Exec(context.Background(), sql, tid, key, age.Seconds()); err != nil {
		t.Fatalf("set claim state: %v", err)
	}
}

// seedStaleClaim inserts a claim directly, as a process killed mid-handler would have left
// it: claimed, no response recorded, older than the lease.
//
// The scenario it reproduces cannot be produced from inside the test process — no test can
// kill itself between two statements — so the row is written rather than raced. The
// fingerprint is the genuine value captured from a real request of the same shape, which is
// what makes the middleware classify this row exactly as it would a real leftover.
func (s *server) seedStaleClaim(t *testing.T, tenantID, key, fingerprint string, age time.Duration) {
	t.Helper()
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot insert rows as the owner")
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatalf("tenant id %q is not a uuid: %v", tenantID, err)
	}
	if _, err := s.db.Owner.Exec(context.Background(),
		`INSERT INTO idempotency_keys (tenant_id, key, fingerprint, state, created_at, expires_at)
		 VALUES ($1, $2, $3, 'in_progress',
		         now() - make_interval(secs => $4::double precision),
		         now() + interval '24 hours')`,
		tid, key, fingerprint, age.Seconds()); err != nil {
		t.Fatalf("seed stale claim: %v", err)
	}
}

// --- the test that is the feature --------------------------------------------

// TestCreateProject_ConcurrentDuplicateAppliesExactlyOnce fires identical requests with the
// same idempotency key, concurrently, and asserts the effect happened once.
//
// # Why this is the whole feature
//
// Idempotency is a claim about a race: that two requests carrying the same key cannot both
// execute the write. Nothing but a concurrent test against the real router and the real
// database can substantiate it — a sequential test passes against an implementation that
// has no protection at all, and a mock would prove only that the mock was called twice.
//
// # The two phases, and why both are needed
//
// Phase one releases every goroutine at once and asserts the invariant that must hold no
// matter how the race resolves: exactly one row. Some requests will legitimately be told
// 409 while the winner is still running, because refusing a duplicate that is in flight is
// the correct answer at that instant.
//
// Phase two then retries sequentially and requires every request to be answered with the
// recorded response. That is only guaranteed once the winner has finished — and it has,
// because it is one of the goroutines wg.Wait() joined, and Complete runs inline before the
// handler returns. So a 409 here is not a race, it is a lost response, and it fails.
func TestCreateProject_ConcurrentDuplicateAppliesExactlyOnce(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-race"))

	const workers = 8
	const key = "race-create-0001"
	const name = "Concurrent Copy"

	path := "/v1/tenants/" + tenantID + "/projects"
	payload := map[string]any{"name": name, "description": "must exist exactly once"}

	// --- phase one: race -----------------------------------------------------
	results := make([]rawResult, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // held closed until every goroutine is parked, to widen the window
			results[i], errs[i] = s.doRaw(http.MethodPost, path, payload, session.AccessToken, key)
		}(i)
	}
	close(start)
	wg.Wait()

	var proceeded, replayed, refused int
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		switch {
		case res.status >= 500:
			t.Fatalf("worker %d got a %d, which means the protocol failed rather than serialised:\n%s",
				i, res.status, res.body)
		case res.status == http.StatusConflict:
			refused++
		case res.header.Get("Idempotent-Replay") == "true":
			replayed++
		case res.status == http.StatusCreated:
			proceeded++
		default:
			t.Fatalf("worker %d: unexpected status %d, body %s", i, res.status, res.body)
		}
	}

	if proceeded != 1 {
		t.Fatalf("%d requests executed the handler, want exactly 1 (replayed %d, refused %d)",
			proceeded, replayed, refused)
	}
	if replayed+refused != workers-1 {
		t.Fatalf("accounting is wrong: %d replayed + %d refused != %d", replayed, refused, workers-1)
	}

	// The invariant, read from the table rather than from a response.
	if got := s.countProjects(t, tenantID, name); got != 1 {
		t.Fatalf("%d project rows exist for %q, want 1: the concurrent duplicates were not deduplicated",
			got, name)
	}

	// --- phase two: every request now converges on the recorded response -----
	var canonical []byte
	for i := 0; i < workers; i++ {
		res, err := s.doRaw(http.MethodPost, path, payload, session.AccessToken, key)
		if err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
		if res.status != http.StatusCreated {
			t.Fatalf("retry %d: status %d, want the recorded 201; body %s", i, res.status, res.body)
		}
		if res.header.Get("Idempotent-Replay") != "true" {
			t.Fatalf("retry %d: completed request was not marked as a replay", i)
		}
		if canonical == nil {
			canonical = res.body
			continue
		}
		if !bytes.Equal(canonical, res.body) {
			t.Fatalf("retry %d replayed a different body:\nfirst: %s\nlater: %s", i, canonical, res.body)
		}
	}

	// And still exactly one effect, after all those retries.
	if got := s.countProjects(t, tenantID, name); got != 1 {
		t.Fatalf("%d project rows exist after retries, want 1", got)
	}
}

// TestIdempotency_KeyReusedForDifferentBodyIsRejected covers the one outcome that indicates
// a client bug rather than a retry.
//
// It must not replay: the recorded response describes a different request, so replaying it
// would tell the client something happened that did not.
func TestIdempotency_KeyReusedForDifferentBodyIsRejected(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-mismatch"))

	const key = "reuse-different-body"
	path := "/v1/tenants/" + tenantID + "/projects"

	first := s.doWithKey(http.MethodPost, path,
		map[string]any{"name": "Original"}, session.AccessToken, key)
	if first.status != http.StatusCreated {
		t.Fatalf("first request: status %d, body %s", first.status, first.body)
	}

	second := s.doWithKey(http.MethodPost, path,
		map[string]any{"name": "Different"}, session.AccessToken, key)
	if second.status != http.StatusUnprocessableEntity {
		t.Fatalf("reused key with a different body: status %d, want 422; body %s", second.status, second.body)
	}
	if !strings.Contains(string(second.body), "idempotency_key_reused") {
		t.Fatalf("422 did not carry the reuse code: %s", second.body)
	}

	// The distinguishing failure: the second request must not have executed.
	if got := s.countProjects(t, tenantID, "Different"); got != 0 {
		t.Fatalf("%d rows for the second body, want 0: a reused key must not execute", got)
	}
}

// TestIdempotency_InFlightDuplicateIsRefused drives the 409 path deterministically.
//
// The claim is written by the real protocol first, then aged to sit inside the lease, so
// the middleware classifies a genuine in_progress row rather than a fabricated one. Racing
// two HTTP requests cannot test this reliably: whoever wins, the loser may arrive after the
// winner completed, and the test would assert on a race rather than on the state machine.
func TestIdempotency_InFlightDuplicateIsRefused(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-inflight"))

	const key = "inflight-0001"
	path := "/v1/tenants/" + tenantID + "/projects"
	payload := map[string]any{"name": "In Flight"}

	// A completed request, so the stored fingerprint is the one the middleware computes for
	// this exact request shape.
	first := s.doWithKey(http.MethodPost, path, payload, session.AccessToken, key)
	if first.status != http.StatusCreated {
		t.Fatalf("first request: status %d, body %s", first.status, first.body)
	}

	_, fingerprint, _ := s.idemState(t, tenantID, key)

	// Rewind it to a live claim held by a process that has not finished. Fingerprint is
	// preserved so this is classified as the same request, and the age is inside the lease.
	s.setClaimState(t, tenantID, key, "in_progress", 5*time.Second)

	if state, _, age := s.idemState(t, tenantID, key); state != "in_progress" || age > 30*time.Second {
		t.Fatalf("setup did not produce a live in_progress claim: state=%s age=%s", state, age)
	}
	_ = fingerprint

	second := s.doWithKey(http.MethodPost, path, payload, session.AccessToken, key)
	if second.status != http.StatusConflict {
		t.Fatalf("duplicate against a live claim: status %d, want 409; body %s", second.status, second.body)
	}
	if second.header.Get("Retry-After") == "" {
		t.Error("409 did not carry Retry-After, so an automated client has to guess when to retry")
	}
	if got := s.countProjects(t, tenantID, "In Flight"); got != 1 {
		t.Fatalf("%d rows, want 1: the refused duplicate must not have executed", got)
	}
}

// TestIdempotency_ExpiredClaimIsTakenOver covers the crash path.
//
// A process that dies between claiming a key and recording a response would otherwise wedge
// that key permanently, and an interrupted client could never make its request. The lease
// exists to make that self-healing, and this is the assertion that it actually heals.
//
// The claim is seeded rather than raced, because the scenario — a process killed
// mid-handler — cannot be produced by the test process itself. Its fingerprint is captured
// from a real request of the same shape, so the middleware classifies it exactly as it would
// a genuine leftover, and the effect of that first request is removed so the re-execution is
// the first time the work actually happens.
func TestIdempotency_ExpiredClaimIsTakenOver(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-takeover"))

	const warmupKey = "takeover-warmup"
	const key = "takeover-0001"
	path := "/v1/tenants/" + tenantID + "/projects"
	payload := map[string]any{"name": "After Restart"}

	warmup := s.doWithKey(http.MethodPost, path, payload, session.AccessToken, warmupKey)
	if warmup.status != http.StatusCreated {
		t.Fatalf("warmup request: status %d, body %s", warmup.status, warmup.body)
	}
	_, fingerprint, _ := s.idemState(t, tenantID, warmupKey)

	// Undo the warmup so the takeover's execution is the first time the effect happens.
	tid := uuid.MustParse(tenantID)
	if _, err := s.db.Owner.Exec(context.Background(),
		`DELETE FROM projects WHERE tenant_id = $1 AND name = $2`, tid, "After Restart"); err != nil {
		t.Fatalf("remove the warmup effect: %v", err)
	}
	if _, err := s.db.Owner.Exec(context.Background(),
		`DELETE FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, tid, warmupKey); err != nil {
		t.Fatalf("remove the warmup claim: %v", err)
	}

	// A claim left behind by a process that died, older than the 60s lease.
	s.seedStaleClaim(t, tenantID, key, fingerprint, 2*time.Minute)

	// The retry must proceed rather than being refused forever.
	second := s.doWithKey(http.MethodPost, path, payload, session.AccessToken, key)
	if second.status != http.StatusCreated {
		t.Fatalf("request after the lease lapsed: status %d, want the handler to run; body %s",
			second.status, second.body)
	}
	if second.header.Get("Idempotent-Replay") == "true" {
		t.Fatal("a taken-over claim was reported as a replay, but no response was ever recorded")
	}

	// The effect genuinely happened, exactly once, and the key is live again for the next
	// retry.
	if got := s.countProjects(t, tenantID, "After Restart"); got != 1 {
		t.Fatalf("%d rows after takeover, want 1", got)
	}
	if state, _, _ := s.idemState(t, tenantID, key); state != "completed" {
		t.Fatalf("state after takeover = %q, want completed", state)
	}
}

// TestIdempotency_UnauthorizedRequestDoesNotClaimKey is the ordering test.
//
// Authorization must precede idempotency, and the reason is not tidiness: with the reverse
// order every 403 an attacker probes with claims a row, which makes idempotency_keys
// attacker-writable storage. The order is invisible in a diff — both orders produce
// correct-looking responses — so it needs an assertion.
func TestIdempotency_UnauthorizedRequestDoesNotClaimKey(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("idem-authz"))

	// A member can read projects but not write them, so this request is authorized to
	// authenticate and forbidden to proceed.
	member := s.addMemberWithRole(owner, tenantID, uniqueEmail("idem-member"), authz.RoleMember)

	const key = "unauthorized-0001"
	path := "/v1/tenants/" + tenantID + "/projects"

	res := s.doWithKey(http.MethodPost, path,
		map[string]any{"name": "Should Not Exist"}, member.AccessToken, key)
	if res.status != http.StatusForbidden {
		t.Fatalf("member write: status %d, want 403; body %s", res.status, res.body)
	}

	if got := s.countIdempotencyRows(t, tenantID, key); got != 0 {
		t.Fatalf("%d idempotency rows were claimed by a request that was never authorized; "+
			"authorization must run before idempotency so an unauthorized caller cannot write to the table", got)
	}
	if got := s.countProjects(t, tenantID, "Should Not Exist"); got != 0 {
		t.Fatalf("%d project rows were created by a forbidden request", got)
	}
}

// TestIdempotency_OversizeBodyIsRejectedAsTooLarge pins the status code.
//
// Falling through to the generic error handler would answer 500, which tells a client the
// server broke — and a well-behaved client retries a 500, forever, with a body that can
// never succeed. 413 is terminal and names the side that has to change.
func TestIdempotency_OversizeBodyIsRejectedAsTooLarge(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-oversize"))
	path := "/v1/tenants/" + tenantID + "/projects"

	// Just past the 1 MiB cap the decoder and the middleware share.
	raw, err := json.Marshal(map[string]any{
		"name":        "Huge",
		"description": strings.Repeat("a", (1<<20)+1024),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	res, err := s.doRawBody(http.MethodPost, path, raw, session.AccessToken, "oversize-0001")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413; body %s", res.status, res.body)
	}
}

// TestSweep_RefusesWithoutPrivileges is the negative control for the reaper.
//
// Under FORCE row-level security a delete with no tenant identity is filtered to zero rows
// and reports success. A reaper that silently returns zero every night is indistinguishable
// from a healthy one until the disk fills, so the guard turns it into a loud error — and
// this proves both halves: it refuses on the application role, and it really deletes on the
// owner role.
func TestSweep_RefusesWithoutPrivileges(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-sweep"))

	const key = "sweep-0001"
	path := "/v1/tenants/" + tenantID + "/projects"
	if res := s.doWithKey(http.MethodPost, path,
		map[string]any{"name": "Sweepable"}, session.AccessToken, key); res.status != http.StatusCreated {
		t.Fatalf("setup create: status %d, body %s", res.status, res.body)
	}

	// Expire it by moving both timestamps together.
	//
	// expires_at cannot simply be pushed into the past: the schema enforces
	// idempotency_expiry_after_creation (expires_at > created_at), deliberately, because a
	// row whose expiry precedes its creation is not expired — it is corrupt. So the pair is
	// moved as a unit, which is what a real day-old record looks like.
	tid := uuid.MustParse(tenantID)
	if _, err := s.db.Owner.Exec(context.Background(),
		`UPDATE idempotency_keys
		    SET created_at = now() - interval '25 hours',
		        expires_at = now() - interval '1 hour'
		  WHERE tenant_id = $1 AND key = $2`, tid, key); err != nil {
		t.Fatalf("expire row: %v", err)
	}

	// Half one: the application role must refuse rather than report a false zero.
	appStore := idempotency.NewStore(s.db.App, 0, 0)
	if _, err := appStore.Sweep(context.Background(), 100); !errors.Is(err, idempotency.ErrSweepNeedsPrivilegedRole) {
		t.Fatalf("sweep on the application role returned %v; it must refuse, because the delete would be "+
			"silently filtered to zero rows while reporting success", err)
	}

	// Half two: the owner role actually deletes.
	ownerStore := idempotency.NewStore(s.db.Owner, 0, 0)
	removed, err := ownerStore.Sweep(context.Background(), 100)
	if err != nil {
		t.Fatalf("sweep on the owner role: %v", err)
	}
	if removed < 1 {
		t.Fatalf("owner sweep removed %d rows, want at least the expired one", removed)
	}
	if got := s.countIdempotencyRows(t, tenantID, key); got != 0 {
		t.Fatalf("the expired key still exists after a sweep that reported removing %d rows", removed)
	}
}

// TestSweep_NothingToCollectReportsZero is the regression test for the empty-table case.
//
// It is the half the privileged-path test above cannot see. With a row to collect, a
// QueryRow-based sweep returns 1 and looks correct; with nothing to collect it returns no
// rows at all, and Scan surfaces that as pgx.ErrNoRows — so a sweep of a quiet table failed
// instead of reporting zero. The test passed anyway because it always seeded an expired row
// first, which is how a real defect hides behind a green suite.
//
// The distinction matters operationally: zero from a role that can see every tenant is
// information, and it is the reading a scheduled reaper produces most nights. An error there
// trains whoever is on call to ignore the job.
func TestSweep_NothingToCollectReportsZero(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot sweep as the owner")
	}

	// Empty the table outright, so "nothing to collect" is certain rather than incidental.
	// The package's tests run sequentially and each builds its own state, so removing
	// another test's records cannot affect it — none of them expect a pre-existing row to
	// outlive the test that created it.
	if _, err := s.db.Owner.Exec(context.Background(), `DELETE FROM idempotency_keys`); err != nil {
		t.Fatalf("clear the table: %v", err)
	}

	ownerStore := idempotency.NewStore(s.db.Owner, 0, 0)
	removed, err := ownerStore.Sweep(context.Background(), 100)
	if err != nil {
		t.Fatalf("sweeping a table with nothing to collect returned an error: %v\n"+
			"a quiet sweep must report zero, which is the reading a scheduled reaper produces most nights", err)
	}
	if removed != 0 {
		t.Fatalf("removed %d rows from an empty table", removed)
	}
}

// TestIdempotency_OversizeResponseIsNotReplayed closes the one path that unit coverage
// cannot reach.
//
// The Overflow rule is unit-tested in the idempotency package, but a unit test only proves
// the flag is set. What matters operationally is the consequence: a retry of a request whose
// response was too large must be refused with an explanation rather than handed a truncated
// document. That path runs through the real middleware, the real store, and the real
// database, so it is tested the same way — by wiring the production middleware to a handler
// that returns more than the replay cap.
//
// A synthetic handler is used because no guarded write in this API can return 64 KiB: the
// largest is a project, capped at 2000 characters. That is a fact about the current surface,
// not a reason to leave the rule unverified end to end.
func TestIdempotency_OversizeResponseIsNotReplayed(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot inspect the stored row")
	}

	session, tenantID := s.register(uniqueEmail("idem-overflow"))
	tid := uuid.MustParse(tenantID)
	uid := uuid.MustParse(session.UserID)

	auth, err := s.tenants.Resolve(context.Background(), tid, uid)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}

	// Comfortably past the 64 KiB replay cap.
	big := strings.Repeat("x", 128<<10)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"data":"`+big+`"}`)
	})

	// The production middleware, wired to the production store, in the production order:
	// the tenant is resolved *before* idempotency runs, because a key is scoped to a tenant
	// and the middleware reads that identity from the context. Composing these the other way
	// round makes the middleware's no-tenant guard fire — which is that guard working, but it
	// means the test is measuring the wrong thing. Only tenant resolution is stood in for
	// here; it is not what this test is about.
	withTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(tenant.WithAuthorized(r.Context(), auth)))
		})
	}
	store := idempotency.NewStore(s.db.App, 0, 0)
	handler := withTenant(httpx.Idempotency(store, nil)(inner))

	const key = "overflow-0001"
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/big", nil)
		req.Header.Set(idempotency.Header, key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	first := call()
	if first.Code != http.StatusCreated {
		t.Fatalf("first request: status %d, want 201; body %s", first.Code, first.Body.String()[:min(200, first.Body.Len())])
	}
	// The client must receive every byte. Truncating the live response to protect the copy
	// would corrupt what the caller actually gets.
	if first.Body.Len() <= 64<<10 {
		t.Fatalf("first response was %d bytes, expected the full oversized body", first.Body.Len())
	}
	if strings.Contains(first.Header().Get("Idempotent-Replay"), "true") {
		t.Fatal("the first response was marked as a replay")
	}

	// It really was stored as non-replayable, read from the table rather than inferred.
	var replayable bool
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT replayable FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, tid, key).
		Scan(&replayable); err != nil {
		t.Fatalf("read the stored row: %v", err)
	}
	if replayable {
		t.Fatal("a response past the storage cap was recorded as replayable, so a retry would be " +
			"served a truncated body that still parses as JSON")
	}

	second := call()
	if second.Code != http.StatusConflict {
		t.Fatalf("retry of an unreplayable response: status %d, want 409; body %s",
			second.Code, second.Body.String())
	}
	if !strings.Contains(second.Body.String(), "idempotent_response_not_replayable") {
		t.Fatalf("409 did not explain that the response cannot be replayed: %s", second.Body.String())
	}
	if strings.Contains(second.Header().Get("Idempotent-Replay"), "true") {
		t.Fatal("an unreplayable response was marked as a replay")
	}
}

// TestIdempotency_SessionCookieIsNeverReplayed is the end-to-end assertion for the one
// place in this feature where being wrong is a vulnerability rather than a bug.
//
// A response can carry a Set-Cookie — a session, a CSRF token, anything scoped to one
// caller. If the replay path returned it, a second client sending the same idempotency key
// would be handed the first client's cookie. The unit test proves encodeHeaders drops it;
// this proves the whole stack does, through the real store and the real database, which is
// the claim that actually matters.
//
// X-Request-Id is asserted for the same reason and a different harm: replaying the
// original's request id would make a response claim to belong to a request it does not.
func TestIdempotency_SessionCookieIsNeverReplayed(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot inspect the stored row")
	}

	session, tenantID := s.register(uniqueEmail("idem-cookie"))
	tid := uuid.MustParse(tenantID)
	uid := uuid.MustParse(session.UserID)

	auth, err := s.tenants.Resolve(context.Background(), tid, uid)
	if err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}

	// A handler that sets a session cookie and a request id, as a real one might.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=super-secret; HttpOnly; Path=/")
		w.Header().Set("X-Request-Id", "original-request-id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"data":{"ok":true}}`)
	})

	withTenant := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(tenant.WithAuthorized(r.Context(), auth)))
		})
	}
	store := idempotency.NewStore(s.db.App, 0, 0)
	handler := withTenant(httpx.Idempotency(store, nil)(inner))

	const key = "cookie-0001"
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/cookie", nil)
		req.Header.Set(idempotency.Header, key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	first := call()
	if first.Code != http.StatusCreated {
		t.Fatalf("first request: status %d", first.Code)
	}
	if first.Header().Get("Set-Cookie") == "" {
		t.Fatal("the first response did not carry its cookie, so this test would prove nothing")
	}

	// The stored row must not contain it either — this is the check that catches persistence
	// rather than replay, which is where the filter actually lives.
	var storedHeaders []byte
	if err := s.db.Owner.QueryRow(context.Background(),
		`SELECT response_headers FROM idempotency_keys WHERE tenant_id = $1 AND key = $2`, tid, key).
		Scan(&storedHeaders); err != nil {
		t.Fatalf("read the stored row: %v", err)
	}
	if strings.Contains(string(storedHeaders), "super-secret") {
		t.Fatalf("the session cookie was persisted for replay: %s", storedHeaders)
	}

	second := call()
	if second.Code != http.StatusCreated {
		t.Fatalf("replay: status %d, want the recorded 201", second.Code)
	}
	if second.Header().Get("Idempotent-Replay") != "true" {
		t.Fatal("the response was not marked as a replay")
	}
	if got := second.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("a replayed response handed the second caller the first caller's cookie: %q", got)
	}
	if got := second.Header().Get("X-Request-Id"); got == "original-request-id" {
		t.Fatal("the replayed response echoed the original request id, claiming to belong to a different request")
	}
	// The headers that make the response usable must survive.
	if got := second.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type was lost on replay: %q", got)
	}
}

// TestIdempotency_BlankKeyIsRejected covers the header-present-but-empty case.
//
// It is the case a naive implementation gets wrong, because Header.Get reports "" both for
// an absent header and for a blank one. Treating them alike means a client that sends the
// header with a mistyped value runs unprotected while believing it is protected — no error,
// no replay, no signal — which is the worst available outcome.
//
// Only whitespace values appear here. A bare "" is the *absent* case, which is legitimately
// unprotected and is asserted separately in TestIdempotency_NoKeyRunsUnprotected.
func TestIdempotency_BlankKeyIsRejected(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-blank"))
	path := "/v1/tenants/" + tenantID + "/projects"
	body := []byte(`{"name":"Blank Key"}`)

	for _, blank := range []string{" ", "   ", "	"} {
		res, err := s.doRawBody(http.MethodPost, path, body, session.AccessToken, blank)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if res.status != http.StatusBadRequest {
			t.Fatalf("blank key %q: status %d, want 400; body %s", blank, res.status, res.body)
		}
	}

	// And crucially, none of them executed: a rejected key must not have claimed anything.
	if got := s.countProjects(t, tenantID, "Blank Key"); got != 0 {
		t.Fatalf("%d rows exist, want 0: a blank key must not run the handler at all", got)
	}
	if got := s.countIdempotencyRows(t, tenantID, " "); got != 0 {
		t.Fatalf("%d idempotency rows were claimed by a blank key", got)
	}
}

// TestIdempotency_OversizeKeyIsRejected pins the promise MaxKeyLength makes.
//
// Without validation at the middleware the key reaches the table and trips the CHECK
// constraint, which surfaces as a 500 — telling the client the server broke when the fault
// is a header they can fix.
func TestIdempotency_OversizeKeyIsRejected(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-longkey"))
	path := "/v1/tenants/" + tenantID + "/projects"

	res, err := s.doRawBody(http.MethodPost, path, []byte(`{"name":"Long Key"}`),
		session.AccessToken, strings.Repeat("k", idempotency.MaxKeyLength+1))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.status != http.StatusBadRequest {
		t.Fatalf("oversize key: status %d, want 400; body %s", res.status, res.body)
	}
	if got := s.countProjects(t, tenantID, "Long Key"); got != 0 {
		t.Fatalf("%d rows exist, want 0", got)
	}
}

// TestIdempotency_NoKeyRunsUnprotected documents the opt-in boundary.
//
// A request without the header is not deduplicated — that is the contract. The second
// identical request is refused, but the refusal comes from the domain and not from
// idempotency: projects.slug is unique per tenant, so re-creating "Unprotected" conflicts
// with or without a key. Keeping that distinction explicit is the point — a test that
// accepted any 4xx would pass against an implementation that had no idempotency at all.
func TestIdempotency_NoKeyRunsUnprotected(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("idem-nokey"))
	path := "/v1/tenants/" + tenantID + "/projects"

	first := s.do(http.MethodPost, path, map[string]any{"name": "Unprotected"}, session.AccessToken)
	if first.status != http.StatusCreated {
		t.Fatalf("first request: status %d, body %s", first.status, first.body)
	}

	second := s.do(http.MethodPost, path, map[string]any{"name": "Unprotected"}, session.AccessToken)
	if second.status != http.StatusConflict {
		t.Fatalf("duplicate unkeyed request: status %d, want 409 from the slug constraint; body %s",
			second.status, second.body)
	}
	if second.header.Get("Idempotent-Replay") == "true" {
		t.Fatal("an unkeyed request was answered with a replay: idempotency is opt-in")
	}

	// A distinct project still succeeds, so nothing is being deduplicated globally.
	third := s.do(http.MethodPost, path, map[string]any{"name": "Also Unprotected"}, session.AccessToken)
	if third.status != http.StatusCreated {
		t.Fatalf("distinct request: status %d, body %s", third.status, third.body)
	}

	if got := s.countProjects(t, tenantID, "Unprotected"); got != 1 {
		t.Fatalf("%d rows for the repeated name, want 1", got)
	}
	if got := s.countProjects(t, tenantID, "Also Unprotected"); got != 1 {
		t.Fatalf("%d rows for the distinct name, want 1", got)
	}
}
