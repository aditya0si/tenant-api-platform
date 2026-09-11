package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
	"github.com/aditya0si/tenant-api-platform/internal/platform/ssrf"
)

// Deliverer performs delivery attempts.
//
// It holds no state between attempts: each one re-resolves the URL, because a tenant can repoint
// DNS at any time and the registration-time check is deliberately not treated as a standing
// permission. That is also why the guard is here rather than only at registration.
type Deliverer struct {
	guard *ssrf.Guard
	log   *slog.Logger

	// now is injectable so a test can assert on the signature's timestamp without sleeping.
	now func() time.Time
}

// NewDeliverer builds a deliverer.
func NewDeliverer(guard *ssrf.Guard, log *slog.Logger) *Deliverer {
	if log == nil {
		log = slog.Default()
	}
	return &Deliverer{guard: guard, log: log, now: time.Now}
}

// Deliver performs one attempt and reports what happened.
//
// It never returns an error: a failed delivery is a Result, not an exception, because the caller's
// job is to record the outcome and schedule the next attempt. Returning an error would tempt a
// caller into treating a receiver's 500 as a bug in this service, and the two need opposite
// responses — one is retried, the other is fixed.
//
// # Why the URL is re-validated on every attempt
//
// Validating once at registration is a time-of-check to time-of-use bug waiting for a slow clock:
// a tenant registers a public hostname, then repoints it at 169.254.169.254. The registration check
// passed and means nothing now. Since the guard also returns the addresses to dial, re-validating
// is not extra work — it is how the client is built at all.
func (d *Deliverer) Deliver(ctx context.Context, due Due) Result {
	started := d.now()

	// A per-attempt deadline. The parent context bounds the whole poll cycle; this bounds one
	// receiver, so a single slow endpoint cannot hold up the batch.
	attemptCtx, cancel := context.WithTimeout(ctx, DeliveryTimeout)
	defer cancel()

	target, err := d.guard.Validate(attemptCtx, due.URL)
	if err != nil {
		// A refusal is a failed attempt, not a crash. It is recorded like any other failure so it
		// reaches the DLQ and is visible through the delivery history — a silently dropped
		// delivery would mean a tenant whose URL was blocked never learns their integration
		// cannot work.
		return Result{Err: fmt.Errorf("target refused: %w", err)}
	}

	req, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, due.URL, bytes.NewReader(due.Payload))
	if err != nil {
		return Result{Err: fmt.Errorf("build request: %w", err)}
	}

	// The signature covers the frozen body with the current time, so a redelivery is a fresh,
	// valid signature over the same bytes rather than a replay of an old header. That distinction
	// is the point: the timestamp is what a receiver's tolerance window checks, and reusing the
	// original timestamp would make every retry look stale and be rejected.
	signedAt := d.now()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, Sign(due.Secret, signedAt, due.Payload))
	req.Header.Set(EventHeader, due.Event)
	req.Header.Set(IDHeader, due.EventID.String())
	req.Header.Set(AttemptHeader, fmt.Sprintf("%d", due.Attempt))
	// The caller's context travels with the delivery so a receiver can join its own traces to the
	// request that caused the event. A retry reuses the original traceparent, which is correct:
	// this is still the same logical event.
	if due.Traceparent != nil && *due.Traceparent != "" {
		req.Header.Set("traceparent", *due.Traceparent)
	}

	client := d.guard.Client(attemptCtx, target, DeliveryTimeout)
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, ssrf.ErrBlocked) {
			// Specifically distinguished because it is a policy refusal rather than a network
			// failure, and an operator reading the delivery history needs to tell them apart.
			return Result{Err: fmt.Errorf("redirect refused: %w", err)}
		}
		return Result{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	// The body is read and discarded rather than left unread. A receiver's error page is worth
	// logging in outline, but it is attacker-controlled text from the tenant's own endpoint, so
	// only the first bytes are kept and they go to the log, never to the API response.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

	metrics.WebhookAttemptDuration.WithLabelValues(due.Event).Observe(d.now().Sub(started).Seconds())

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(body) > 0 {
			d.log.Debug("webhook receiver returned a non-2xx",
				"event", due.Event, "status", resp.StatusCode, "attempt", due.Attempt,
				"endpoint_id", due.EndpointID, "body_prefix", truncate(string(body), 256))
		}
	}

	// The status is returned even for a 3xx: the client refuses redirects, so a 302 arrives here and
	// is recorded as the failure it is. Treating it as success would mark a delivery delivered that
	// the receiver never processed.
	return Result{StatusCode: resp.StatusCode}
}

// truncate bounds a log field.
//
// It is byte-oriented and may split a multi-byte rune at the boundary. That is acceptable for a log
// prefix and is called out so nobody later "fixes" it by reading the whole body into a string to
// trim rune-safely — which would undo the bound.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Worker drains the outbox.
type Worker struct {
	store     *Store
	deliverer *Deliverer
	log       *slog.Logger

	// batchSize bounds one poll. A large batch holds connections for as long as the batch takes,
	// so this is a memory and lock-hold decision rather than a throughput one; the poll repeats.
	batchSize int

	// interval is the idle delay between polls. It is not a busy loop: a queue with nothing due
	// should cost one indexed query per interval, and the interval is the latency floor for a new
	// event.
	interval time.Duration
}

// NewWorker builds a worker.
func NewWorker(store *Store, deliverer *Deliverer, log *slog.Logger, batchSize int, interval time.Duration) *Worker {
	if log == nil {
		log = slog.Default()
	}
	if batchSize <= 0 {
		batchSize = 10
	}
	if interval <= 0 {
		interval = time.Second
	}
	return &Worker{store: store, deliverer: deliverer, log: log, batchSize: batchSize, interval: interval}
}

// Run polls until the context is cancelled, then returns.
//
// # Shutdown
//
// An in-flight delivery is allowed to finish: cancelling it mid-request would leave the receiver
// possibly having processed the event while this worker records nothing, which is exactly the
// ambiguity the lease exists to resolve — but resolving it by death is worse than resolving it by
// waiting a bounded few seconds. The lease means a worker killed outright is still recoverable, so
// this is a graceful path and not the safety mechanism.
//
// A poll that finds nothing sleeps for the interval. A poll that found work repeats immediately,
// because a non-empty batch means there may be more and sleeping would stack the interval onto
// every batch.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("webhook worker started", "batch_size", w.batchSize, "interval", w.interval.String())

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.log.Info("webhook worker stopping", "reason", ctx.Err())
			return nil
		default:
		}

		n, err := w.poll(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// A database blip must not kill the worker: it retries on the next tick, and the
			// outbox is durable so nothing is lost by waiting.
			w.log.Error("webhook poll failed; retrying", "err", err)
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
			continue
		}

		w.recordDepth(ctx)

		if n == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
			}
		}
	}
}

// WorkOnce performs a single poll, for tests and for a one-shot invocation.
func (w *Worker) WorkOnce(ctx context.Context) (int, error) { return w.poll(ctx) }

// poll claims a batch and attempts each delivery, returning how many were attempted.
func (w *Worker) poll(ctx context.Context) (int, error) {
	due, err := w.store.Claim(ctx, w.batchSize)
	if err != nil {
		return 0, err
	}
	if len(due) == 0 {
		return 0, nil
	}

	for _, d := range due {
		// Serial within a poll. Delivering a batch concurrently would be faster and is deliberately
		// not done here: the concurrency control is the number of worker processes, which an
		// operator can reason about from the deployment, rather than a goroutine count buried in
		// this loop.
		w.attempt(ctx, d)
	}
	return len(due), nil
}

// attempt delivers once and settles the row.
func (w *Worker) attempt(ctx context.Context, d Due) {
	res := w.deliverer.Deliver(ctx, d)

	// Jitter from math/rand/v2 rather than a crypto source: the value is used to spread retry
	// timing, and an unpredictable one would be no better. Drawing it per attempt here keeps the
	// backoff schedule itself a pure function of (attempt, fraction), which is what makes it
	// testable without seeding anything — see NextDelay.
	err := w.store.Settle(ctx, d, res, rand.Float64)

	switch {
	case err == nil:
		if res.Succeeded() {
			metrics.WebhookAttempts.WithLabelValues(d.Event, "delivered").Inc()
			w.log.Info("webhook delivered",
				"event", d.Event, "endpoint_id", d.EndpointID, "delivery_id", d.ID,
				"attempt", d.Attempt, "status", res.StatusCode)
		} else {
			metrics.WebhookAttempts.WithLabelValues(d.Event, "retry").Inc()
			w.log.Warn("webhook delivery failed; scheduled a retry",
				"event", d.Event, "endpoint_id", d.EndpointID, "delivery_id", d.ID,
				"attempt", d.Attempt, "status", res.StatusCode, "err", res.Err)
		}

	case isLeaseLost(err):
		// Not a failure of the receiver: the delivery outlived its lease and another worker now owns
		// the row. Counted separately because the fix is a longer lease or a faster receiver, not a
		// look at the endpoint.
		metrics.WebhookAttempts.WithLabelValues(d.Event, "lease_lost").Inc()
		w.log.Warn("webhook delivery outlived its lease and was reclaimed; "+
			"LeaseDuration must exceed the receiver's response time plus the delivery timeout",
			"event", d.Event, "delivery_id", d.ID, "attempt", d.Attempt)

	case isDeadLetter(err):
		// The one outcome that a tenant may need to be told about: their receiver has been broken
		// long enough that deliveries have stopped retrying.
		metrics.WebhookAttempts.WithLabelValues(d.Event, "dead").Inc()
		w.log.Error("webhook delivery exhausted its attempts and is now dead; replay it after "+
			"fixing the receiver",
			"event", d.Event, "endpoint_id", d.EndpointID, "delivery_id", d.ID,
			"attempts", d.Attempt, "status", res.StatusCode, "err", res.Err)

	default:
		metrics.WebhookAttempts.WithLabelValues(d.Event, "retry").Inc()
		w.log.Error("failed to settle a webhook delivery; the row keeps its lease until it expires",
			"err", err, "delivery_id", d.ID, "event", d.Event)
	}
}

// recordDepth publishes the queue depth.
//
// It is the only health signal a worker has: the process serves no HTTP, so there is no endpoint to
// probe, and "is it keeping up" is answered by whether pending falls rather than by a liveness code.
// A failure to read the depth is logged at debug rather than error — it means the metric is stale,
// which is worth knowing but is not a delivery problem.
func (w *Worker) recordDepth(ctx context.Context) {
	depth, err := w.store.Depth(ctx)
	if err != nil {
		w.log.Debug("could not read the outbox depth", "err", err)
		return
	}
	for state, n := range depth {
		metrics.WebhookOutboxDepth.WithLabelValues(state).Set(float64(n))
	}
}

// isLeaseLost reports whether err is a reclaimed-lease error.
func isLeaseLost(err error) bool {
	var target *LeaseLostError
	return errors.As(err, &target)
}

// isDeadLetter reports whether err is a delivery that exhausted its attempts.
func isDeadLetter(err error) bool {
	var target *DeadLetterError
	return errors.As(err, &target)
}
