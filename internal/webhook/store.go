package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/reqid"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// SettingWorker is the GUC that widens the webhook policies to every tenant.
//
// It is applied in exactly one place — Claim and Settle, both of which run in the worker — and
// nowhere in the API. The name is exported so a test can assert that no other path sets it, which
// is the property that keeps the API as tenant-scoped as it was before the policy existed.
const SettingWorker = "app.worker"

// Store is the webhook repository.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Enqueue records an event for every active endpoint subscribed to it, inside the caller's
// transaction.
//
// # Why it takes a pgx.Tx
//
// The same guarantee as the audit trail: the event and the change that caused it commit together
// or neither does. Enqueuing after commit loses events to a crash in the gap; enqueuing before
// a commit that then rolls back announces changes that never happened. Neither is fixable in the
// transport layer, which is why the outbox exists at all (ADR-001).
//
// # Why one statement rather than select-then-insert
//
// The fan-out is a single INSERT ... SELECT, so an endpoint registered concurrently is either in
// or out — both correct — rather than the two statements disagreeing about which endpoints
// existed a moment apart. It also returns the count without a second query.
//
// # Why the ids are v4 here
//
// ADR-007 chose UUIDv7 for resource primary keys, for index locality and because creation order
// is worth preserving. An outbox row is not a resource: it is a queue entry, ordered by
// (next_at, id), and its id is a tiebreaker rather than an ordering key. Generating them in the
// database means the fan-out stays one statement, and the cost — a random v4 in a table whose
// ordering comes from another column — is nothing. Resource ids remain v7 in the application.
//
// # Why an unknown event is not an error
//
// An event with no subscribers is the common case: most tenants subscribe to nothing. Enqueuing
// nothing is the right answer, and the returned count lets a caller distinguish "delivered to 3
// endpoints" from "no one is listening" without treating the second as a failure.
func (s *Store) Enqueue(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, event string, data any) (int, error) {
	if _, ok := Events[event]; !ok {
		return 0, fmt.Errorf("webhook: %q is not a known event", event)
	}

	eventID := uuid.Must(uuid.NewV7())
	env := Envelope{
		// The id is generated once and stored with the frozen payload. A fresh id per attempt would
		// be wrong: a retry must carry the same one for the receiver's deduplication to work.
		ID:        eventID.String(),
		Event:     event,
		CreatedAt: time.Now().UTC(),
		TenantID:  tenantID.String(),
		Data:      data,
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("webhook: encode %s payload: %w", event, err)
	}
	if len(payload) > MaxPayloadBytes {
		// Refused rather than truncated: a receiver acting on half an event is worse than a
		// receiver that never saw it, and the failure surfaces here rather than at delivery.
		return 0, fmt.Errorf("webhook: %s payload is %d bytes, over the %d limit",
			event, len(payload), MaxPayloadBytes)
	}

	traceparent := nullIfEmpty(reqid.TraceparentFrom(ctx))

	var enqueued int
	tag, err := tx.Exec(ctx, `
		INSERT INTO webhook_outbox (id, tenant_id, endpoint_id, event, event_id, payload, traceparent)
		SELECT gen_random_uuid(), $1, e.id, $2, $5, $3, $4
		  FROM webhook_endpoints e
		 WHERE e.tenant_id = $1
		   AND e.active
		   AND $2 = ANY(e.events)`,
		tenantID, event, payload, traceparent, eventID)
	if err != nil {
		return 0, fmt.Errorf("webhook: enqueue %s: %w", event, err)
	}
	enqueued = int(tag.RowsAffected())

	// Exec and RowsAffected, not QueryRow.
	//
	// The fan-out inserts one row per subscribed endpoint, and QueryRow returns only the first —
	// so a tenant with three subscribed endpoints would be told one delivery was queued. The
	// count is what the caller uses to distinguish "delivered to 3 endpoints" from "nobody is
	// listening", and a silently wrong version of it makes the second case indistinguishable
	// from the first.
	return enqueued, nil
}

// Due is a claimed delivery, ready to send. It carries the endpoint's URL and secret because the
// delivery happens outside any transaction — see Claim.
type Due struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	EndpointID uuid.UUID

	// EventID is the identity a receiver deduplicates on, in the body and in a header. It is a
	// column rather than something read back out of the payload, so the header and the body cannot
	// disagree — see migration 0012 for why that matters.
	EventID uuid.UUID

	Event       string
	Payload     []byte
	Traceparent *string

	// Attempt is the 1-based count including this one, already incremented by Claim.
	Attempt int

	URL    string
	Secret string
}

// Claim leases up to batchSize due deliveries.
//
// # SKIP LOCKED, and why it is not an optimisation
//
// Without it, a second worker on the same row blocks until the first commits — so the workers
// serialise, and throughput collapses to the slowest delivery rather than scaling with the
// worker count. With SKIP LOCKED the second worker moves on to a different row, which is what
// makes running more than one worker mean anything.
//
// # The lease, and why the delivery happens outside this transaction
//
// A delivery is an HTTP request with a ten-second timeout, so holding a transaction open across
// it would pin a connection and a snapshot for that whole time — and a receiver that hangs would
// hold it until the request timeout. Instead: claim (commit), deliver, mark (new transaction).
// The lease covers the gap, and a worker that dies mid-delivery leaves a lease that expires, at
// which point the row is claimable again. Delayed, never lost.
//
// # Why a reclaiming worker also takes expired leases
//
// The second branch of the predicate — `state = 'delivering' AND lease_expires_at < now()` — is
// what makes a crash recoverable. A worker that only claimed pending rows would leave anything
// its predecessor was holding stranded forever.
func (s *Store) Claim(ctx context.Context, batchSize int) ([]Due, error) {
	if batchSize <= 0 {
		batchSize = 10
	}

	// The only place the worker GUC is set. It is transaction-scoped, so it reverts at commit and
	// a pooled connection cannot carry the widened policy into an API request — which is the
	// property that makes the second policy safe to have.
	var out []Due
	err := db.WithSettings(ctx, s.pool, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH due AS (
				SELECT id FROM webhook_outbox
				 WHERE (state = 'pending' AND next_at <= now())
				    OR (state = 'delivering' AND lease_expires_at < now())
				 ORDER BY next_at, id
				 LIMIT $1
				 FOR UPDATE SKIP LOCKED
			)
			UPDATE webhook_outbox o
			   SET state            = 'delivering',
			       lease_expires_at = now() + make_interval(secs => $2::double precision),
			       attempts         = o.attempts + 1
			  FROM due, webhook_endpoints e
			 WHERE o.id = due.id
			   AND e.id = o.endpoint_id
			RETURNING o.id, o.tenant_id, o.endpoint_id, o.event, o.event_id, o.payload, o.traceparent,
			          o.attempts, e.url, e.secret`,
			batchSize, LeaseDuration.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var d Due
			if err := rows.Scan(&d.ID, &d.TenantID, &d.EndpointID, &d.Event, &d.EventID, &d.Payload,
				&d.Traceparent, &d.Attempt, &d.URL, &d.Secret); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("webhook: claim deliveries: %w", err)
	}
	return out, nil
}

// Result is the outcome of one delivery attempt.
type Result struct {
	// StatusCode is the receiver's status, or 0 when the request never got a response.
	StatusCode int

	// Err is a transport failure: DNS, connection, timeout. A non-nil Err means the status is
	// meaningless, which is why the two are separate rather than folded into one code.
	Err error
}

// Succeeded reports whether the receiver acknowledged the delivery.
//
// Only 2xx. A 3xx is a failure rather than a redirect to follow: the client refuses redirects
// (see ssrf.Guard.Client), because following one would resend a signed body to a destination the
// tenant never registered. A 4xx is a failure too, and deliberately not treated as permanent — a
// receiver returning 401 while an operator rotates its secret will work again in a minute, and
// dead-lettering it immediately would need a manual replay for a transient cause.
func (r Result) Succeeded() bool {
	return r.Err == nil && r.StatusCode >= 200 && r.StatusCode < 300
}

// Settle records the outcome of an attempt and schedules the next one.
//
// # The state transition is where the lease is enforced, and the attempt number is the fence
//
// Every branch carries `state = 'delivering' AND lease_expires_at > now() AND attempts = $N`.
// The first two predicates refuse a settle whose lease lapsed and was not renewed. They are not
// sufficient on their own: after another worker reclaims the row, it is `delivering` again with a
// *future* lease, so a stale worker's update would still match and could mark the delivery
// complete while the new owner is mid-attempt — overwriting the attempt count that decides
// dead-lettering.
//
// The attempt number closes that window. Claim increments it, so the value a worker holds is a
// fencing token: a stale settle carries the previous number and matches nothing, while the
// current owner's settle carries the live one. Without it, two workers that both delivered would
// both settle and the attempts column would undercount.
func (s *Store) Settle(ctx context.Context, d Due, res Result, jitter func() float64) error {
	if d.Attempt <= 0 {
		return errors.New("webhook: settle called with no attempt recorded")
	}

	var (
		state    string
		nextAt   time.Time
		dead     bool
		lastErr  *string
		lastCode *int
	)
	if res.Err != nil {
		msg := res.Err.Error()
		lastErr = &msg
	} else {
		code := res.StatusCode
		lastCode = &code
		if !res.Succeeded() {
			msg := fmt.Sprintf("receiver returned %d", res.StatusCode)
			lastErr = &msg
		}
	}

	if res.Succeeded() {
		state = StateDelivered
		nextAt = time.Now()
	} else {
		delay, retry := NextDelay(d.Attempt, jitter())
		if !retry {
			state = StateDead
			nextAt = time.Now()
			dead = true
		} else {
			state = StatePending
			nextAt = time.Now().Add(delay)
		}
	}

	// deadLetter is recorded rather than returned from inside the transaction.
	//
	// WithSettings wraps this closure in pgx.BeginFunc, which rolls back on any error, so
	// returning the dead-letter result from in there would undo the very write it describes: the
	// row would stay 'delivering' until its lease lapsed, be reclaimed, and dead-letter again on
	// the next reclaim, forever. The DLQ would be empty by construction, the outbox depth would
	// never clear, and Replay — which requires state='dead' — could never find a row to requeue.
	//
	// The caller still receives the error. It is returned after the write it describes commits,
	// which is the difference between reporting a dead letter and being unable to create one.
	var deadLetter *DeadLetterError

	if err := db.WithSettings(ctx, s.pool, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		var (
			query string
			args  []any
		)
		if state == StateDelivered {
			query = `
				UPDATE webhook_outbox
				   SET state            = 'delivered',
				       delivered_at     = now(),
				       lease_expires_at = NULL,
				       next_at          = $2,
				       last_error       = NULL,
				       last_status      = $3
				 WHERE id = $1
				   AND state = 'delivering'
				   AND lease_expires_at > now()
				   AND attempts = $4`
			args = []any{d.ID, nextAt, lastCode, d.Attempt}
		} else {
			// Placeholders are contiguous, and that is not cosmetic: an argument no placeholder
			// references has no type context, so Postgres refuses to parse the statement at all
			// (42P18, "could not determine data type of parameter $3"). A stray argument here
			// meant every retry and every dead-letter settle failed — the row stayed
			// 'delivering', the lease lapsed, and each reclaim incremented the attempt count
			// toward a budget that could never dead-letter it. The delivery retried forever
			// against a receiver that was already failing.
			query = `
				UPDATE webhook_outbox
				   SET state            = $3,
				       lease_expires_at = NULL,
				       next_at          = $2,
				       last_error       = $4,
				       last_status      = $5
				 WHERE id = $1
				   AND state = 'delivering'
				   AND lease_expires_at > now()
				   AND attempts = $6`
			args = []any{d.ID, nextAt, state, lastErr, lastCode, d.Attempt}
		}

		tag, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("webhook: settle delivery: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return &LeaseLostError{ID: d.ID}
		}
		if dead {
			// Recorded, not returned — see the note on deadLetter above. The worker still learns
			// about it, because a delivery reaching the DLQ is the point at which the tenant may
			// need to be told; it is told after this transaction commits.
			deadLetter = &DeadLetterError{ID: d.ID, Event: d.Event, EndpointID: d.EndpointID}
		}
		return nil
	}); err != nil {
		return err
	}

	// An explicit nil check rather than `return deadLetter`. Returning a typed nil pointer as an
	// error yields a non-nil interface, so every successful settle would report a failure.
	if deadLetter != nil {
		return deadLetter
	}
	return nil
}

// LeaseLostError reports that a delivery was reclaimed while it was being attempted.
//
// It is an error rather than a silent no-op because the cause matters: it means the delivery took
// longer than the lease, which is a configuration problem — LeaseDuration must exceed
// DeliveryTimeout plus the receiver's real latency — and a pattern of these means the receiver is
// slower than the lease assumes, not that something is broken.
type LeaseLostError struct{ ID uuid.UUID }

func (e *LeaseLostError) Error() string {
	return fmt.Sprintf("webhook: delivery %s was reclaimed by another worker before it settled; "+
		"the lease is shorter than this receiver takes to respond", e.ID)
}

// DeadLetterError reports that a delivery exhausted its attempts and entered the DLQ.
type DeadLetterError struct {
	ID         uuid.UUID
	Event      string
	EndpointID uuid.UUID
}

func (e *DeadLetterError) Error() string {
	return fmt.Sprintf("webhook: delivery %s (%s) exhausted its attempts and is now dead; "+
		"replay it after fixing the receiver", e.ID, e.Event)
}

// Replay re-queues a dead delivery.
//
// # Why only a dead one
//
// Re-queuing a pending row would duplicate an in-flight delivery, and re-queuing a delivered one
// would resend an event the receiver already acknowledged. Both are worse than refusing, and the
// caller cannot always tell which state a row is in — so this checks, rather than trusting.
//
// # Why the attempt count is reset but the replay count is not
//
// attempts drives the DLQ decision, so it must start over for the retry schedule to apply again.
// replays is history, and a row that needed five replays is a fact an operator wants; resetting it
// would hide the pattern that matters.
//
// # Why the payload is not rebuilt
//
// The stored payload is what would have been sent. Rebuilding it from current state would send the
// resource's *new* contents under the old event's name — a receiver would be told invoice.paid and
// handed a body reflecting a later edit. The frozen payload is the reason replay is meaningful.
func (s *Store) Replay(ctx context.Context, auth tenant.Authorized, id uuid.UUID) (Delivery, error) {
	if !auth.Valid() {
		return Delivery{}, apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return Delivery{}, ErrNotFound
	}

	var d Delivery
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var (
			nextAt   time.Time
			lastErr  *string
			lastCode *int
		)
		err := tx.QueryRow(ctx, `
			UPDATE webhook_outbox
			   SET state = 'pending',
			       attempts = 0,
			       replays = replays + 1,
			       next_at = now(),
			       lease_expires_at = NULL
			 WHERE id = $1 AND tenant_id = $2 AND state = 'dead'
			RETURNING id, tenant_id, endpoint_id, event, state, attempts, replays,
			          next_at, last_error, last_status, delivered_at, created_at`,
			id, auth.Scope().ID()).Scan(&d.ID, &d.TenantID, &d.EndpointID, &d.Event, &d.State,
			&d.Attempts, &d.Replays, &nextAt, &lastErr, &lastCode, &d.DeliveredAt, &d.CreatedAt)
		switch {
		case err == nil:
			d.NextAt = nextAt
			if lastErr != nil {
				d.LastError = *lastErr
			}
			if lastCode != nil {
				d.LastStatus = *lastCode
			}
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("webhook: replay delivery: %w", err)
		}

		// Zero rows: either no such delivery in this tenant, or one that is not dead. The two need
		// different answers — an id typo versus a caller that misunderstood the state — so the
		// state is read to tell them apart, inside the same transaction so it cannot race.
		var state string
		err = tx.QueryRow(ctx,
			`SELECT state FROM webhook_outbox WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()).Scan(&state)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("webhook: classify replay failure: %w", err)
		case state != StateDead:
			return fmt.Errorf("%w (this delivery is %s)", ErrNotDead, state)
		default:
			// Unreachable: a dead row would have matched the UPDATE. Kept explicit so a future
			// change to the predicate cannot silently turn this into a success.
			return ErrNotFound
		}
	})
	if err != nil {
		return Delivery{}, err
	}
	return d, nil
}

// Depth counts deliveries that are not yet delivered, per state.
//
// It is the gauge an operator watches: a rising pending count means receivers are failing or the
// worker is not keeping up, and the two are distinguished by the dead count rising separately.
func (s *Store) Depth(ctx context.Context) (map[string]int, error) {
	out := map[string]int{}
	err := db.WithSettings(ctx, s.pool, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT state, count(*) FROM webhook_outbox WHERE state <> 'delivered' GROUP BY state`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				state string
				n     int
			)
			if err := rows.Scan(&state, &n); err != nil {
				return err
			}
			out[state] = n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("webhook: count depth: %w", err)
	}
	return out, nil
}

// ListFilter narrows a delivery listing.
type ListFilter struct {
	EndpointID string
	State      string
}

// ListResult is one page of deliveries.
type ListResult struct {
	Deliveries []Delivery
	Next       *cursor.Position
}

// List returns one page of a tenant's deliveries, newest first.
//
// Keyset on (created_at, id) for the same reason as projects and invoices: an offset page shifts
// under the writes a queue generates continuously, so page 2 can repeat or skip rows.
//
// The payload is not returned. A delivery listing is for an operator triaging failures, and the
// bodies of hundreds of events are a large response for data the summary does not need — the
// last_error and last_status are what they are reading.
func (s *Store) List(ctx context.Context, auth tenant.Authorized, filter ListFilter, after *cursor.Position, limit int) (ListResult, error) {
	if !auth.Valid() {
		return ListResult{}, apperr.ErrNoScope
	}
	state, err := NormalizeState(filter.State)
	if err != nil {
		return ListResult{}, err
	}
	limit = NormalizePageSize(limit)

	var endpointID *uuid.UUID
	if filter.EndpointID != "" {
		parsed, err := uuid.Parse(filter.EndpointID)
		if err != nil {
			return ListResult{}, apperr.Invalid("endpoint_id", "is not a valid id")
		}
		endpointID = &parsed
	}

	var out []Delivery
	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var afterTime *time.Time
		var afterID uuid.UUID
		if after != nil {
			t := after.Time
			afterTime = &t
			afterID = after.ID
		}

		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, endpoint_id, event, state, attempts, replays,
			       next_at, last_error, last_status, delivered_at, created_at
			  FROM webhook_outbox
			 WHERE tenant_id = $1
			   AND ($2::text IS NULL OR state = $2::text)
			   AND ($3::uuid IS NULL OR endpoint_id = $3::uuid)
			   AND ($4::timestamptz IS NULL OR (created_at, id) < ($4::timestamptz, $5::uuid))
			 ORDER BY created_at DESC, id DESC
			 LIMIT $6`,
			auth.Scope().ID(), nullIfEmpty(state), endpointID, afterTime, afterID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var (
				d        Delivery
				lastErr  *string
				lastCode *int
			)
			if err := rows.Scan(&d.ID, &d.TenantID, &d.EndpointID, &d.Event, &d.State, &d.Attempts,
				&d.Replays, &d.NextAt, &lastErr, &lastCode, &d.DeliveredAt, &d.CreatedAt); err != nil {
				return err
			}
			if lastErr != nil {
				d.LastError = *lastErr
			}
			if lastCode != nil {
				d.LastStatus = *lastCode
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("webhook: list deliveries: %w", err)
	}

	res := ListResult{Deliveries: out}
	if len(out) > limit {
		res.Deliveries = out[:limit]
		last := out[limit-1]
		res.Next = &cursor.Position{Time: last.CreatedAt, ID: last.ID}
	}
	return res, nil
}

// nullIfEmpty maps "" to a SQL NULL so a filter can be absent.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// DeliveryBinding describes the query a delivery cursor belongs to.
func DeliveryBinding(auth tenant.Authorized, filter ListFilter) cursor.Binding {
	state, _ := NormalizeState(filter.State)
	if state == "" {
		state = "any"
	}
	endpoint := filter.EndpointID
	if endpoint == "" {
		endpoint = "all"
	}
	return cursor.Binding{
		TenantID: auth.Scope().ID(),
		Resource: "webhook_deliveries",
		Filter:   state + ":" + endpoint,
	}
}

// actorFor builds an audit actor from an authorized caller, for endpoint registration.
func actorFor(auth tenant.Authorized) (*uuid.UUID, string, error) {
	return audit.ActorFromAuthorized(auth)
}
