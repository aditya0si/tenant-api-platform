package webhook

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// These tests target the three properties that make the outbox a delivery mechanism rather than a
// table of hopeful rows, and each fails *silently* in production if it is wrong:
//
//  1. **The worker can see a row another tenant's endpoint produced.** The claim query joins
//     webhook_endpoints to read the URL and secret, and a join is filtered by the joined table's
//     policy independently. If only webhook_outbox admitted the worker, the claim would return
//     zero rows while looking correct — the queue would fill forever and nothing would send.
//  2. **An enqueue commits with its caller's transaction.** Otherwise an invoice is written and
//     its notification is lost, or a notification is sent for a change that rolled back.
//  3. **Two holders cannot settle the same delivery.** Without the attempt-number fence, a
//     reclaimed delivery can be marked complete by a worker that had already lost its lease.
//
// Everything runs through the application pool, which authenticates as app_rw — neither superuser
// nor BYPASSRLS — so the policies are genuinely in force. As a superuser these tests would pass
// while measuring nothing.

// topJitter is the top of the jitter range, which makes the retry schedule the nominal one. The
// schedule itself is pinned by the unit tests; here the exact delay does not matter, only the
// state it produces.
func topJitter() float64 { return 1 }

func tenantAuth(t *testing.T, d *testsupport.DB, label string) tenant.Authorized {
	t.Helper()

	tenantID, userID := testsupport.NewTenant(t, d.App, label)
	auth, err := tenant.NewStore(d.App).Resolve(context.Background(), tenantID, userID)
	if err != nil {
		t.Fatalf("resolve %s: %v", label, err)
	}
	return auth
}

func registeredEndpoint(t *testing.T, d *testsupport.DB, store *Store, auth tenant.Authorized, url string, events ...string) Endpoint {
	t.Helper()

	validated, err := ValidateCreate(CreateInput{URL: url, Events: events})
	if err != nil {
		t.Fatalf("validate endpoint: %v", err)
	}
	e, _, err := store.CreateEndpoint(context.Background(), auth, validated)
	if err != nil {
		t.Fatalf("create endpoint: %v", err)
	}
	return e
}

// enqueueInTx mirrors what the invoice store does: the insert runs inside a transaction the caller
// owns, so it commits or rolls back with the caller's change.
func enqueueInTx(t *testing.T, d *testsupport.DB, store *Store, auth tenant.Authorized, event string, data any) int {
	t.Helper()

	var n int
	err := db.WithIdentityTx(context.Background(), d.App, auth.Identity(), func(tx pgx.Tx) error {
		var err error
		n, err = store.Enqueue(context.Background(), tx, auth.Scope().ID(), event, data)
		return err
	})
	if err != nil {
		t.Fatalf("enqueue %s: %v", event, err)
	}
	return n
}

// workerExec runs one statement under the worker's own policy, which is the only way the delivery
// process can see or change these rows.
func workerExec(t *testing.T, d *testsupport.DB, sql string, args ...any) {
	t.Helper()

	err := db.WithSettings(context.Background(), d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), sql, args...)
		return err
	})
	if err != nil {
		t.Fatalf("worker exec %q: %v", sql, err)
	}
}

// removeOutboxRows deletes this endpoint's rows when the test finishes.
//
// Not tidiness: a row left 'pending' survives into the next run of the suite, and enough of them
// would eventually crowd out a real claim's batch, turning a passing test into a flaky one. It
// deletes rather than settling because the pending row from the rollback test is deliberately
// never settled.
func removeOutboxRows(t *testing.T, d *testsupport.DB, endpointID uuid.UUID) {
	t.Cleanup(func() {
		_ = db.WithSettings(context.Background(), d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(),
				`DELETE FROM webhook_outbox WHERE endpoint_id = $1`, endpointID)
			return err
		})
	})
}

func outboxState(t *testing.T, d *testsupport.DB, id uuid.UUID) (string, int) {
	t.Helper()

	var (
		state    string
		attempts int
	)
	err := db.WithSettings(context.Background(), d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(),
			`SELECT state, attempts FROM webhook_outbox WHERE id = $1`, id).Scan(&state, &attempts)
	})
	if err != nil {
		t.Fatalf("read outbox row: %v", err)
	}
	return state, attempts
}

func outboxIDs(t *testing.T, d *testsupport.DB, endpointID uuid.UUID) []uuid.UUID {
	t.Helper()

	var ids []uuid.UUID
	err := db.WithSettings(context.Background(), d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(),
			`SELECT id FROM webhook_outbox WHERE endpoint_id = $1 ORDER BY created_at, id`, endpointID)
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
		t.Fatalf("list outbox rows: %v", err)
	}
	return ids
}

// findEndpointDue returns the claimed row for one endpoint, or fails.
//
// It filters rather than indexing because Claim works across every tenant by design: the batch may
// legitimately contain other rows, and a test that assumed index 0 would be asserting the order of
// an unordered result.
func findEndpointDue(t *testing.T, due []Due, endpointID uuid.UUID) Due {
	t.Helper()

	for _, d := range due {
		if d.EndpointID == endpointID {
			return d
		}
	}
	t.Fatalf("claim returned %d rows and none was for endpoint %s: the worker cannot see the "+
		"endpoint, which is the RLS join failing rather than the queue being empty", len(due), endpointID)
	return Due{}
}

// TestClaim_SeesARowTheTenantCreated is the RLS-join test.
//
// The claim query joins webhook_endpoints, and each table's policy is evaluated independently. A
// worker arm on webhook_outbox alone would leave the join returning nothing — a queue that fills
// and never drains, with no error anywhere.
func TestClaim_SeesARowTheTenantCreated(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "claim")
	e := registeredEndpoint(t, d, store, auth,
		"https://example.com/hooks/invoice", EventInvoicePaid)
	removeOutboxRows(t, d, e.ID)

	if n := enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 4200}); n != 1 {
		t.Fatalf("enqueue inserted %d rows, want 1", n)
	}

	due, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	got := findEndpointDue(t, due, e.ID)

	if got.URL != e.URL {
		t.Errorf("claimed URL = %q, want %q", got.URL, e.URL)
	}
	if got.Secret == "" {
		t.Error("the claimed row carries no secret, so the delivery could not be signed")
	}
	if got.Event != EventInvoicePaid {
		t.Errorf("claimed event = %q, want %q", got.Event, EventInvoicePaid)
	}
	if got.Attempt != 1 {
		t.Errorf("attempts = %d on the first claim, want 1", got.Attempt)
	}
	if got.EventID == uuid.Nil {
		t.Error("the claimed row has no event id, so a receiver has no key to deduplicate on")
	}
	if len(got.Payload) == 0 {
		t.Error("the claimed row has an empty payload; the frozen body is the point of the outbox")
	}

	state, attempts := outboxState(t, d, got.ID)
	if state != StateDelivering {
		t.Errorf("state = %q after a claim, want %q", state, StateDelivering)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d after one claim, want 1", attempts)
	}

	// Two policies, checked separately, because they fail in opposite directions. The tenant arm
	// is what lets the API list its own delivery history; the worker arm is what lets a delivery
	// process see work belonging to a tenant it has no membership in.
	var asTenant int
	if err := db.WithIdentityTx(ctx, d.App, auth.Identity(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM webhook_outbox WHERE endpoint_id = $1`, e.ID).Scan(&asTenant)
	}); err != nil {
		t.Fatalf("count as tenant: %v", err)
	}
	if asTenant != 1 {
		t.Errorf("the owning tenant sees %d of its own rows, want 1", asTenant)
	}

	// Fail-closed control: with no tenant and no worker setting, the same query sees nothing. A
	// policy that admitted rows on an unset GUC would be worse than none, because it would look
	// enforced. This is the assertion that distinguishes the two.
	var bare int
	if err := d.App.QueryRow(ctx,
		`SELECT count(*) FROM webhook_outbox WHERE endpoint_id = $1`, e.ID).Scan(&bare); err != nil {
		t.Fatalf("count with no identity: %v", err)
	}
	if bare != 0 {
		t.Fatalf("a query with no tenant and no worker setting saw %d rows; the policies are "+
			"fail-open, so a missing GUC exposes every tenant's deliveries", bare)
	}
}

// TestEnqueue_CommitsAndRollsBackWithItsCaller is the atomicity test.
//
// Both directions are asserted. Failure in one direction announces a change that never happened;
// failure in the other records the change and silently loses the notification. A test that only
// checked the rollback would also pass if Enqueue wrote nothing at all, so the commit direction is
// the positive control.
func TestEnqueue_CommitsAndRollsBackWithItsCaller(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "atomicity")
	e := registeredEndpoint(t, d, store, auth,
		"https://example.com/hooks/atomicity", EventInvoiceCreated)
	removeOutboxRows(t, d, e.ID)

	// The rollback: a transaction that enqueues and then fails, which is the shape of an invoice
	// mutation whose later step errors out.
	boom := errors.New("caller changed its mind")
	err := db.WithIdentityTx(ctx, d.App, auth.Identity(), func(tx pgx.Tx) error {
		if _, err := store.Enqueue(ctx, tx, auth.Scope().ID(), EventInvoiceCreated,
			map[string]any{"id": "rolled-back"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("transaction error = %v, want %v", err, boom)
	}

	if ids := outboxIDs(t, d, e.ID); len(ids) != 0 {
		t.Fatalf("a rolled-back transaction left %d outbox rows: the delivery would announce a "+
			"change that never happened", len(ids))
	}

	// The positive control: the same call inside a transaction that commits does leave a row.
	if n := enqueueInTx(t, d, store, auth, EventInvoiceCreated,
		map[string]any{"id": "committed"}); n != 1 {
		t.Fatalf("a committed enqueue inserted %d rows, want 1", n)
	}
	if ids := outboxIDs(t, d, e.ID); len(ids) != 1 {
		t.Fatalf("a committed enqueue left %d rows, want 1", len(ids))
	}
}

// TestEnqueue_FansOutToEverySubscribedEndpoint covers the count the caller acts on.
//
// The store returns how many deliveries it queued, and that number distinguishes "three receivers
// were notified" from "nobody is listening" — a distinction the API surfaces. It was originally
// read with QueryRow, which returns only the first row of an INSERT...SELECT fan-out and so
// reported 1 no matter how many endpoints matched.
func TestEnqueue_FansOutToEverySubscribedEndpoint(t *testing.T) {
	d := testsupport.RequireDB(t)

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "fanout")

	a := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/a", EventInvoicePaid)
	b := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/b", EventInvoicePaid)
	removeOutboxRows(t, d, a.ID)
	removeOutboxRows(t, d, b.ID)

	// Subscribed to a different event: matching must be on the event, not merely on the tenant.
	c := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/c", EventInvoiceVoided)
	removeOutboxRows(t, d, c.ID)

	n := enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 7})
	if n != 2 {
		t.Fatalf("enqueue reported %d deliveries, want 2 (two of three endpoints subscribe to %s)",
			n, EventInvoicePaid)
	}
	if got := len(outboxIDs(t, d, a.ID)); got != 1 {
		t.Errorf("endpoint a has %d rows, want 1", got)
	}
	if got := len(outboxIDs(t, d, b.ID)); got != 1 {
		t.Errorf("endpoint b has %d rows, want 1", got)
	}
	if got := len(outboxIDs(t, d, c.ID)); got != 0 {
		t.Errorf("endpoint c has %d rows, want 0: it subscribes to %s, not %s",
			got, EventInvoiceVoided, EventInvoicePaid)
	}
}

// TestSettle_StaleAttemptCannotSettleAReclaimedDelivery is the fencing test.
//
// The sequence is the one the lease exists for: a worker claims a delivery, stalls past its lease,
// and another worker reclaims it. The stalled worker then wakes up and settles. State and lease
// predicates alone do not refuse it — the row is 'delivering' again with a fresh future lease — so
// without the attempt-number fence the stale holder marks the delivery complete while the live
// owner is mid-attempt, and the attempt count that drives dead-lettering is overwritten.
func TestSettle_StaleAttemptCannotSettleAReclaimedDelivery(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "fence")
	e := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/fence", EventInvoicePaid)
	removeOutboxRows(t, d, e.ID)

	enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 1})

	first, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	stale := findEndpointDue(t, first, e.ID)

	// The stall: the lease lapses and the row becomes claimable again.
	workerExec(t, d, `UPDATE webhook_outbox SET lease_expires_at = now() - interval '1 minute' WHERE id = $1`, stale.ID)

	second, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	live := findEndpointDue(t, second, e.ID)
	if live.ID != stale.ID {
		t.Fatalf("the reclaim produced a different row (%s vs %s)", live.ID, stale.ID)
	}
	if live.Attempt != stale.Attempt+1 {
		t.Fatalf("attempt after a reclaim = %d, want %d", live.Attempt, stale.Attempt+1)
	}

	// The stale holder settles with the attempt number it was given. It must be refused.
	err = store.Settle(ctx, stale, Result{StatusCode: 200}, topJitter)
	var lost *LeaseLostError
	if !errors.As(err, &lost) {
		t.Fatalf("a stale settle returned %v, want LeaseLostError: without the fence it would "+
			"mark the delivery complete while the live owner is still attempting it", err)
	}

	state, _ := outboxState(t, d, live.ID)
	if state != StateDelivering {
		t.Fatalf("the stale settle changed the state to %q; the live owner's claim was overwritten", state)
	}

	// The live owner settles normally, and that one lands.
	if err := store.Settle(ctx, live, Result{StatusCode: 200}, topJitter); err != nil {
		t.Fatalf("the current owner could not settle: %v", err)
	}
	state, attempts := outboxState(t, d, live.ID)
	if state != StateDelivered {
		t.Errorf("state after the owner settled = %q, want %q", state, StateDelivered)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2 (one per claim)", attempts)
	}
}

// TestSettle_AtTheAttemptBudgetDeadLetters covers the transition into the DLQ.
//
// The attempt count is advanced directly rather than by driving four real attempts, because the
// branch under test is the decision made *at* the budget, not the retry loop that arrives there.
// The retry schedule itself is pinned by the unit tests, and the loop by the fence test above.
func TestSettle_AtTheAttemptBudgetDeadLetters(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "dead")
	e := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/dead", EventInvoicePaid)
	removeOutboxRows(t, d, e.ID)

	enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 2})

	claimed, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	due := findEndpointDue(t, claimed, e.ID)

	workerExec(t, d, `UPDATE webhook_outbox SET attempts = $2 WHERE id = $1`, due.ID, MaxAttempts)
	due.Attempt = MaxAttempts

	err = store.Settle(ctx, due, Result{StatusCode: 503}, topJitter)
	var dead *DeadLetterError
	if !errors.As(err, &dead) {
		t.Fatalf("settling at the budget returned %v, want DeadLetterError", err)
	}

	state, attempts := outboxState(t, d, due.ID)
	if state != StateDead {
		t.Errorf("state at the budget = %q, want %q", state, StateDead)
	}
	if attempts != MaxAttempts {
		t.Errorf("attempts = %d, want %d", attempts, MaxAttempts)
	}
}

// TestSettle_BelowTheBudgetSchedulesARetry covers the other half of the branch that dead-letters
// above it — and it is the test that found the bug the dead-letter test then confirmed.
//
// Both outcomes share one UPDATE, and that statement carried an argument no placeholder referred
// to. Postgres refuses to parse such a statement (42P18), so *no* failing delivery could persist
// its outcome: the row stayed 'delivering' until its lease lapsed, was reclaimed, and each reclaim
// incremented the attempt count toward a budget it could never reach. Dead rows were impossible,
// retries were never recorded, and a failing receiver was hit forever. A green build said nothing
// about any of it — the failure was in a query that only runs when a delivery fails.
func TestSettle_BelowTheBudgetSchedulesARetry(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "retry")
	e := registeredEndpoint(t, d, store, auth, "https://example.com/hooks/retry", EventInvoicePaid)
	removeOutboxRows(t, d, e.ID)

	enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 3})

	claimed, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	due := findEndpointDue(t, claimed, e.ID)

	// A 503 is the receiver saying "not now". Below the budget that is a retry rather than a dead
	// letter: the receiver may be restarting, and dead-lettering it would need a manual replay for
	// a transient cause.
	if err := store.Settle(ctx, due, Result{StatusCode: 503}, topJitter); err != nil {
		t.Fatalf("settling a retryable failure returned %v, want nil", err)
	}

	state, attempts := outboxState(t, d, due.ID)
	if state != StatePending {
		t.Fatalf("state = %q after a retryable failure, want %q", state, StatePending)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1: a retry records that an attempt happened, not that "+
			"another one is due", attempts)
	}

	// The failure itself is recorded. A retry with no last_error is a queue that keeps failing
	// and an operator with nothing to look at.
	var (
		lastErr    *string
		lastStatus *int
		nextAt     time.Time
	)
	err = db.WithSettings(ctx, d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT last_error, last_status, next_at FROM webhook_outbox WHERE id = $1`,
			due.ID).Scan(&lastErr, &lastStatus, &nextAt)
	})
	if err != nil {
		t.Fatalf("read retry outcome: %v", err)
	}
	if lastErr == nil || *lastErr != "receiver returned 503" {
		t.Errorf("last_error = %v, want %q", lastErr, "receiver returned 503")
	}
	if lastStatus == nil || *lastStatus != 503 {
		t.Errorf("last_status = %v, want 503", lastStatus)
	}

	// The backoff is real rather than a formality: an immediate re-claim must take nothing, or a
	// struggling receiver is retried as fast as the worker can loop.
	if !nextAt.After(time.Now()) {
		t.Errorf("next_at = %s, which is not in the future", nextAt)
	}
	again, err := store.Claim(ctx, 50)
	if err != nil {
		t.Fatalf("claim after a retry was scheduled: %v", err)
	}
	for _, row := range again {
		if row.EndpointID == e.ID {
			t.Fatal("the delivery was claimable immediately after a retry was scheduled: the " +
				"backoff did not delay it, so a failing receiver would be retried in a tight loop")
		}
	}
}

// TestClaim_SkipsRowsHeldByAnotherTransaction is the SKIP LOCKED test.
//
// This is the mechanism two workers depend on, tested directly rather than by racing two real
// claims: a race passes whether or not the clause is present, because the second claim usually
// runs after the first has committed and the rows are no longer eligible anyway. Holding a lock
// open across the claim is the only way to ask the question, and it is also the case that matters
// — one slow receiver must not stall the whole queue behind it.
func TestClaim_SkipsRowsHeldByAnotherTransaction(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	auth := tenantAuth(t, d, "skiplock")
	setup := NewStore(d.App)
	e := registeredEndpoint(t, d, setup, auth,
		"https://example.com/hooks/skip", EventInvoicePaid, EventInvoiceCreated)
	removeOutboxRows(t, d, e.ID)

	enqueueInTx(t, d, setup, auth, EventInvoicePaid, map[string]any{"n": 1})
	enqueueInTx(t, d, setup, auth, EventInvoiceCreated, map[string]any{"n": 2})

	ids := outboxIDs(t, d, e.ID)
	if len(ids) != 2 {
		t.Fatalf("setup produced %d rows, want 2", len(ids))
	}
	held := ids[0]

	// A separate pool, so the claiming store is guaranteed a different connection than the
	// transaction holding the lock — otherwise the test would deadlock on its own setup.
	claimStore := NewStore(d.AppPoolWithConns(t, 4))

	var claimed []Due
	err := db.WithSettings(ctx, d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		// Hold the row the way a worker mid-delivery holds it: a transaction that has begun and
		// has not committed.
		if _, err := tx.Exec(ctx,
			`SELECT id FROM webhook_outbox WHERE id = $1 FOR UPDATE`, held); err != nil {
			return err
		}
		var err error
		claimed, err = claimStore.Claim(ctx, 50)
		return err
	})
	if err != nil {
		t.Fatalf("claim while a row is held: %v", err)
	}

	var sawHeld, sawOther bool
	for _, d := range claimed {
		if d.EndpointID != e.ID {
			continue
		}
		switch d.ID {
		case held:
			sawHeld = true
		case ids[1]:
			sawOther = true
		}
	}

	if sawHeld {
		t.Fatal("claim returned a row another transaction holds locked: without SKIP LOCKED the " +
			"claim blocks behind one slow receiver, and every other tenant's deliveries stall with it")
	}
	if !sawOther {
		t.Fatal("claim returned neither row; it should step over the locked one and take the free one")
	}
}

// TestClaim_ConcurrentClaimsDoNotOverlap is the integration half of the previous test: two claims
// running together must partition the work rather than duplicate it. Delivering a webhook twice is
// not a correctness failure for the receiver — the event id exists for that — but it means two
// workers spent the same effort and the attempt counter is wrong.
func TestClaim_ConcurrentClaimsDoNotOverlap(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	auth := tenantAuth(t, d, "concurrent")
	setup := NewStore(d.App)
	e := registeredEndpoint(t, d, setup, auth, "https://example.com/hooks/concurrent",
		EventInvoicePaid, EventInvoiceCreated, EventInvoiceIssued, EventInvoiceVoided)
	removeOutboxRows(t, d, e.ID)

	for _, ev := range []string{EventInvoicePaid, EventInvoiceCreated, EventInvoiceIssued, EventInvoiceVoided} {
		enqueueInTx(t, d, setup, auth, ev, map[string]any{"n": ev})
	}
	if got := len(outboxIDs(t, d, e.ID)); got != 4 {
		t.Fatalf("setup produced %d rows, want 4", got)
	}

	store := NewStore(d.AppPoolWithConns(t, 4))

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results [][]Due
	)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			due, err := store.Claim(ctx, 50)
			if err != nil {
				// Recorded rather than fatal: t.Fatalf from a goroutine is not allowed.
				t.Errorf("concurrent claim: %v", err)
				return
			}
			mu.Lock()
			results = append(results, due)
			mu.Unlock()
		}()
	}
	wg.Wait()

	seen := map[uuid.UUID]int{}
	for _, due := range results {
		for _, row := range due {
			if row.EndpointID == e.ID {
				seen[row.ID]++
			}
		}
	}

	for id, n := range seen {
		if n > 1 {
			t.Errorf("row %s was claimed by %d workers; the same delivery would be attempted twice", id, n)
		}
	}
	if len(seen) != 4 {
		t.Errorf("the two claims covered %d of 4 rows: some work was left unclaimed", len(seen))
	}
}
