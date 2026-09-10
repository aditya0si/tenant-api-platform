package idempotency

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

const (
	// DefaultLease is how long a claim may be held before another request may take it
	// over.
	//
	// It exists because a process can die between claiming a key and recording a
	// response — a deploy, an OOM kill, a panic — and without a lease that key would be
	// stuck in_progress forever, refusing every retry. The value must exceed the request
	// timeout (15s) by enough that a slow-but-alive handler is never taken over
	// mid-flight; a minute is comfortably longer than any handler here runs and short
	// enough that an interrupted client can retry promptly.
	DefaultLease = 60 * time.Second

	// maxStoredBody bounds the response body kept for replay.
	//
	// Beyond it the record is marked not replayable rather than truncated: a truncated
	// body would be served to a retrying client as a complete response, and a client
	// cannot detect that its JSON was cut in half. Refusing to replay is loud; a
	// half-response is silent.
	maxStoredBody = 64 << 10
)

// Outcome is the result of beginning an idempotent request.
type Outcome uint8

const (
	// OutcomeProceed means this request owns the key and must run the handler.
	OutcomeProceed Outcome = iota
	// OutcomeReplay means the key is complete and its recorded response must be returned
	// instead of running the handler.
	OutcomeReplay
)

// BeginResult reports what Begin decided.
type BeginResult struct {
	Outcome Outcome
	// Record is populated when Outcome is OutcomeReplay.
	Record Record
}

// Store persists idempotency records.
//
// # One clock, and it is the database's
//
// The store deliberately holds no clock. Every time comparison here — lease expiry and
// retention expiry — is evaluated by Postgres in SQL, against timestamps Postgres wrote.
//
// The alternative, comparing a database-written timestamp against the application's clock,
// is wrong by whatever skew the two hosts disagree by, in whichever direction, and it
// produces no symptom except wrong answers: a record that expires early, or a lease that
// never lapses. That bug was fixed once already in the refresh store
// (internal/authn/refresh.go); this is the same decision applied consistently, and it is
// also why there is no SetClock here — there is no clock to substitute.
//
// Tests exercise expiry by constructing a store with a tiny retention or lease and
// sleeping past it, which is slower than injecting a clock and tests the real path.
type Store struct {
	pool      *pgxpool.Pool
	retention time.Duration
	lease     time.Duration
}

// NewStore builds a store. retention is how long a key is honoured; zero selects
// DefaultRetention. lease is the claim timeout; zero selects DefaultLease.
func NewStore(pool *pgxpool.Pool, retention, lease time.Duration) *Store {
	if retention <= 0 {
		retention = DefaultRetention
	}
	if lease <= 0 {
		lease = DefaultLease
	}
	return &Store{pool: pool, retention: retention, lease: lease}
}

// Begin claims a key or reports why it cannot be claimed.
//
// # Why the claim commits before the handler runs
//
// The claim is its own committed transaction, and that is deliberate. If the in_progress
// row were still uncommitted while the handler ran, a concurrent duplicate would block
// inside its own INSERT — Postgres waits to see whether the conflicting row commits — for
// as long as the first request takes. Committing the claim immediately means the duplicate
// sees a *committed* conflict, reads in_progress, and is answered with 409 straight away.
//
// # Why the record and the effect are not in one transaction
//
// Ideally the claim, the side effect, and the recorded response would share a single
// transaction, which would close every interleaving. That is not available here: the
// handlers own their transactions (each repository call opens one through
// db.WithIdentityTx, and a create may span several), and a transport-level middleware
// cannot join a transaction it did not open.
//
// What that costs is stated precisely in the package doc, and it is mitigated where it
// matters: every state transition in this service is compare-and-set, so a duplicated
// call is refused by the data layer even when it reaches a handler.
//
// # The five ways a key can already exist
//
//	completed, unexpired, same fingerprint   -> replay
//	completed, unexpired, different request  -> ErrFingerprintMismatch (422)
//	completed but past its retention         -> treated as unused; claim it
//	in_progress, within the lease            -> ErrInProgress (409)
//	in_progress, past the lease              -> take it over; the holder died
//
// The fingerprint comparison comes before the state check on purpose. A key reused for a
// different request is a client bug regardless of what the original request is doing, and
// answering 409-with-retry would tell the client to retry a request that can never succeed
// under that key.
func (s *Store) Begin(ctx context.Context, auth tenant.Authorized, key, fingerprint string) (BeginResult, error) {
	if !auth.Valid() {
		return BeginResult{}, apperr.ErrNoScope
	}
	if err := ValidateKey(key); err != nil {
		return BeginResult{}, fmt.Errorf("%w: %v", apperr.ErrValidation, err)
	}

	tenantID := auth.Scope().ID()

	// Two attempts at the whole claim-and-classify sequence, not just the insert, because a
	// record can disappear between reading it and acting on it: a racing request that found
	// the same expired row may have cleared it first. Without the outer retry that
	// interleaving surfaces as "read idempotency key: no rows in result set" — an internal
	// error for what is an ordinary concurrent retry.
	for attempt := 0; attempt < 2; attempt++ {
		// Step one: try to claim. A conflict here does not block, because any conflicting
		// row is already committed by the time we get here.
		claimed, err := s.tryClaim(ctx, auth, tenantID, key, fingerprint)
		if err != nil {
			return BeginResult{}, err
		}
		if claimed {
			return BeginResult{Outcome: OutcomeProceed}, nil
		}

		// Step two: somebody holds it. Read and classify.
		rec, found, err := s.read(ctx, auth, tenantID, key)
		if err != nil {
			return BeginResult{}, err
		}
		if !found {
			continue // it vanished; try to claim it again
		}

		if !FingerprintsMatch(rec.Fingerprint, fingerprint) {
			return BeginResult{}, fmt.Errorf("%w (this key is in state %s)", ErrFingerprintMismatch, rec.State)
		}

		switch {
		case rec.State == StateCompleted:
			if !rec.Replayable {
				return BeginResult{}, ErrNotReplayable
			}
			return BeginResult{Outcome: OutcomeReplay, Record: rec}, nil

		case rec.LeaseExpired:
			// The holder is gone — a deploy, an OOM kill — and the lease has passed. Taking it
			// over is what stops a crashed process from wedging a key permanently.
			took, err := s.takeOver(ctx, auth, tenantID, key, fingerprint)
			if err != nil {
				return BeginResult{}, err
			}
			if took {
				return BeginResult{Outcome: OutcomeProceed}, nil
			}
			// Somebody else took it between the read and the update. Reported as a concurrent
			// duplicate rather than retried in a loop: the client's correct move is to back off
			// either way.
			return BeginResult{}, ErrInProgress

		default:
			return BeginResult{}, ErrInProgress
		}
	}

	// Both attempts lost the race to a competing claim. Reported as a concurrent duplicate,
	// which is what the client should treat it as: back off and retry.
	return BeginResult{}, ErrInProgress
}

// tryClaim attempts the initial insert and reports whether this caller owns the key.
//
// The insert is retried once after clearing an *expired completed* row, because
// ON CONFLICT DO NOTHING cannot distinguish "somebody is using this key" from "this key
// was used a week ago and has expired". Without the retry a key would be permanently
// blocked the first time it aged out, which is the opposite of what retention means.
func (s *Store) tryClaim(ctx context.Context, auth tenant.Authorized, tenantID uuid.UUID, key, fingerprint string) (bool, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var claimed uuid.UUID
		err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
			// expires_at is computed by the database from the database's clock, so the
			// value that retention is later compared against was written by the same clock
			// doing the comparing.
			return tx.QueryRow(ctx, `
				INSERT INTO idempotency_keys (tenant_id, key, fingerprint, state, expires_at, actor_id)
				VALUES ($1, $2, $3, 'in_progress',
				        now() + make_interval(secs => $4::double precision), $5)
				ON CONFLICT (tenant_id, key) DO NOTHING
				RETURNING tenant_id`,
				tenantID, key, fingerprint, s.retention.Seconds(), actorID(auth)).Scan(&claimed)
		})
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, pgx.ErrNoRows):
			// Conflicted: the key exists.
		case err != nil:
			return false, fmt.Errorf("claim idempotency key: %w", err)
		}

		if attempt == 0 {
			cleared, err := s.clearExpired(ctx, auth, tenantID, key)
			if err != nil {
				return false, err
			}
			if !cleared {
				return false, nil // a live record exists; the caller classifies it
			}
			continue
		}
	}
	return false, nil
}

// clearExpired deletes a completed record whose retention has passed, reporting whether it
// removed one.
//
// Deleting rather than updating is safe because a completed record's only job is to be
// replayed, and past its retention it has no job. The WHERE clause makes the deletion
// conditional, so a record that is still live — including one a concurrent request just
// completed — cannot be clobbered.
func (s *Store) clearExpired(ctx context.Context, auth tenant.Authorized, tenantID uuid.UUID, key string) (bool, error) {
	var cleared bool
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			DELETE FROM idempotency_keys
			 WHERE tenant_id = $1 AND key = $2
			   AND state = 'completed'
			   AND expires_at <= now()`, tenantID, key)
		if err != nil {
			return err
		}
		cleared = tag.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("clear expired idempotency key: %w", err)
	}
	return cleared, nil
}

// takeOver re-claims an in_progress record whose lease has passed.
//
// The UPDATE is conditional on the record still being in_progress and still stale, so two
// requests racing to take over the same dead claim cannot both succeed — one sees a row
// affected and proceeds, the other sees zero and is told a request is in progress.
func (s *Store) takeOver(ctx context.Context, auth tenant.Authorized, tenantID uuid.UUID, key, fingerprint string) (bool, error) {
	var took bool
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var claimed uuid.UUID
		err := tx.QueryRow(ctx, `
			UPDATE idempotency_keys
			   SET fingerprint = $3,
			       actor_id    = $4,
			       created_at  = now(),
			       expires_at  = now() + make_interval(secs => $5::double precision)
			 WHERE tenant_id = $1
			   AND key = $2
			   AND state = 'in_progress'
			   AND created_at < now() - make_interval(secs => $6::double precision)
			RETURNING tenant_id`,
			tenantID, key, fingerprint, actorID(auth),
			s.retention.Seconds(), s.lease.Seconds()).Scan(&claimed)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		took = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("take over idempotency key: %w", err)
	}
	return took, nil
}

// read loads an existing record, asking the database to evaluate lease staleness.
//
// Lease staleness is a returned column rather than something the caller computes, for the
// reason given on Store: comparing a database-written created_at against the application's
// clock is wrong by the skew between them, and expresses itself as a lease that never
// lapses (a key wedged forever) or one that lapses instantly (a live handler taken over).
func (s *Store) read(ctx context.Context, auth tenant.Authorized, tenantID uuid.UUID, key string) (Record, bool, error) {
	var (
		rec   Record
		found bool
	)
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var (
			statusCode  *int
			headers     []byte
			body        []byte
			completedAt *time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT key, fingerprint, state, status_code, response_headers, response_body,
			       replayable, created_at, completed_at,
			       (state = 'in_progress'
			        AND created_at < now() - make_interval(secs => $3::double precision)) AS lease_expired
			FROM idempotency_keys
			WHERE tenant_id = $1 AND key = $2`, tenantID, key, s.lease.Seconds()).
			Scan(&rec.Key, &rec.Fingerprint, &rec.State, &statusCode, &headers, &body,
				&rec.Replayable, &rec.CreatedAt, &completedAt, &rec.LeaseExpired)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Somebody cleared an expired row between the claim attempt and this read. That
			// is a race, not a failure, so it is reported as "not found" and the caller
			// retries rather than surfacing an internal error.
			return nil
		case err != nil:
			return err
		}
		found = true

		if statusCode != nil {
			rec.StatusCode = *statusCode
		}
		rec.CompletedAt = completedAt
		rec.Body = body
		if len(headers) > 0 {
			if err := decodeHeaders(headers, &rec.Headers); err != nil {
				return fmt.Errorf("decode stored headers: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return Record{}, false, fmt.Errorf("read idempotency key: %w", err)
	}
	return rec, found, nil
}

// Complete records the response for a claimed key.
//
// It runs in its own transaction, after the handler's own transaction has committed — the
// gap described on Begin. The ordering is deliberate: recording the response *before* the
// effect committed would let a crash replay a response for an effect that never happened,
// which is a lie the client then acts on.
func (s *Store) Complete(ctx context.Context, auth tenant.Authorized, key string, res CapturedResponse) error {
	if !auth.Valid() {
		return apperr.ErrNoScope
	}

	replayable := res.Replayable()
	body := res.Body
	if !replayable {
		// The status is kept and the body is dropped, so a retry can be told what happened
		// (a 201 that cannot be replayed) rather than handed a truncated document that
		// parses as valid JSON. Whether the response overflowed travels on the response
		// itself: inferring it from len(body) would be wrong, because the buffer stops
		// exactly at the cap and so a truncated body is *shorter* than the limit.
		body = nil
	}

	headers, err := encodeHeaders(res.Headers)
	if err != nil {
		return fmt.Errorf("encode response headers: %w", err)
	}

	return db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE idempotency_keys
			   SET state            = 'completed',
			       status_code      = $3,
			       response_headers = $4,
			       response_body    = $5,
			       replayable       = $6,
			       completed_at     = now()
			 WHERE tenant_id = $1 AND key = $2 AND state = 'in_progress'`,
			auth.Scope().ID(), key, res.Status, headers, body, replayable)
		if err != nil {
			return fmt.Errorf("complete idempotency key: %w", err)
		}
		if tag.RowsAffected() == 0 {
			// The claim was taken over while this handler ran, which means the request
			// outlived its lease. The work is done and its effect stands; only the replay
			// record is lost, so a retry re-executes. Reported rather than swallowed,
			// because a pattern of these means the lease is too short for this handler.
			return fmt.Errorf("idempotency claim for key %q was taken over before it completed: %w",
				key, ErrInProgress)
		}
		return nil
	})
}

// Sweep deletes expired records and reports how many were removed.
//
// # Why this refuses to run on the application role
//
// A sweep spans tenants by definition, but idempotency_keys carries a FORCE row-level
// security policy keyed on app.current_tenant_id. Run with no tenant identity — which is
// what the application pool has — the policy filters every row away, the candidate set is
// empty, and the statement deletes nothing *while reporting success*.
//
// That failure mode is the worst available: a scheduled reaper would log "0 removed" every
// night, an operator would read it as "nothing to do", and the table would grow without
// bound until a disk alert. So the guard below turns it into a loud error instead. It is
// deliberately a runtime check and not a comment, because a comment cannot fail.
//
// # Calling it
//
// The expected caller is a maintenance entry point holding owner credentials — the same
// role that applies migrations — because that role bypasses row-level security. See
// cmd/migrate's `sweep` command and docs/OPERATIONS.md.
func (s *Store) Sweep(ctx context.Context, limit int) (int64, error) {
	if limit <= 0 {
		limit = 1000
	}

	// Does row-level security apply to this connection's role? If it does, the DELETE
	// below cannot see another tenant's rows and would report a misleading zero.
	var subjectToRLS bool
	if err := s.pool.QueryRow(ctx, `
		SELECT NOT (r.rolsuper OR r.rolbypassrls)
		  FROM pg_roles r
		 WHERE r.rolname = current_user`).Scan(&subjectToRLS); err != nil {
		return 0, fmt.Errorf("sweep: identify the connected role: %w", err)
	}
	if subjectToRLS {
		return 0, fmt.Errorf(
			"sweep: the connected role is subject to row-level security, so the delete would be "+
				"silently filtered to zero rows. Run this with owner credentials (the same role that "+
				"applies migrations). Refusing rather than reporting a false success: %w",
			ErrSweepNeedsPrivilegedRole)
	}

	// Exec, not QueryRow, and the count comes from the command tag.
	//
	// QueryRow is wrong here and the failure is quiet: `DELETE ... RETURNING 1` produces no
	// rows when nothing is expired, so Scan returns pgx.ErrNoRows — and a sweep of an empty
	// table *errors* instead of reporting zero. That inverts what the privilege guard above
	// is for. "swept 0" is only meaningful because the role can see every tenant, so a zero
	// has to be returned as a zero; turning it into an error means the first quiet night
	// pages someone, and the natural fix under pressure is to stop alerting on it.
	//
	// The command tag reports the number of deleted rows and is 0 when the CTE matched
	// nothing, which is the answer the caller actually wants.
	tag, err := s.pool.Exec(ctx, `
		WITH expired AS (
			SELECT tenant_id, key FROM idempotency_keys
			 WHERE expires_at <= now() OR
			       (state = 'in_progress' AND created_at < now() - make_interval(secs => $2::double precision))
			 ORDER BY expires_at
			 LIMIT $1
		)
		DELETE FROM idempotency_keys k
		 USING expired e
		 WHERE k.tenant_id = e.tenant_id AND k.key = e.key`, limit, s.lease.Seconds())
	if err != nil {
		return 0, fmt.Errorf("sweep idempotency keys: %w", err)
	}
	return tag.RowsAffected(), nil
}

// actorID records who claimed a key, for attribution. A machine principal has no user, so
// its key id is recorded instead — the same reasoning as project attribution.
func actorID(auth tenant.Authorized) *uuid.UUID {
	if auth.IsMachine() {
		id := auth.KeyID()
		return &id
	}
	id := auth.UserID()
	return &id
}
