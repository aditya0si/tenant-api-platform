package webhook

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
	"github.com/aditya0si/tenant-api-platform/internal/platform/ssrf"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// TestWorker_RecordsDeliveryMetrics covers the one part of the worker no other test reaches: its
// metrics.
//
// # Why the assertion lives here and not in the end-to-end smoke test
//
// A deployed compose network offers no address the production SSRF guard will deliver to — every
// address a container can offer is private, and refusing those is the feature, not a gap. So no
// delivery can occur there, and `webhook_delivery_attempts_total` correctly has no series to
// report. The smoke test asserted its presence anyway and failed against correct code; the honest
// fix was to move the check to a place where a delivery can actually happen.
//
// # Why attempt() is called directly instead of through WorkOnce
//
// WorkOnce claims rows from a database shared with every other package's tests. A claim would also
// pick up whatever the invoice and webhook suites have queued — deliveries to example.com among
// them — making this test slow, network-dependent, and fundamentally about someone else's row. The
// row is therefore placed in the exact state a claim would have left it in, and one attempt is
// driven against it.
func TestWorker_RecordsDeliveryMetrics(t *testing.T) {
	d := testsupport.RequireDB(t)
	ctx := context.Background()

	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := NewStore(d.App)
	auth := tenantAuth(t, d, "metrics")
	e := registeredEndpoint(t, d, store, auth, srv.URL+"/hook", EventInvoicePaid)
	removeOutboxRows(t, d, e.ID)

	enqueueInTx(t, d, store, auth, EventInvoicePaid, map[string]any{"total_minor": 1})
	ids := outboxIDs(t, d, e.ID)
	if len(ids) != 1 {
		t.Fatalf("setup produced %d outbox rows, want 1", len(ids))
	}
	id := ids[0]

	workerExec(t, d, `
		UPDATE webhook_outbox
		   SET state = 'delivering',
		       attempts = 1,
		       lease_expires_at = now() + interval '1 minute'
		 WHERE id = $1`, id)

	var payload []byte
	if err := db.WithSettings(ctx, d.App, map[string]string{SettingWorker: "true"}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT payload FROM webhook_outbox WHERE id = $1`, id).Scan(&payload)
	}); err != nil {
		t.Fatalf("read the queued payload: %v", err)
	}

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}

	due := Due{
		ID:         id,
		TenantID:   auth.Scope().ID(),
		EndpointID: e.ID,
		EventID:    uuid.Must(uuid.NewV7()),
		Event:      EventInvoicePaid,
		Payload:    payload,
		Attempt:    1,
		URL:        srv.URL + "/hook",
		Secret:     secret,
	}

	// The loopback-permitting guard, which is the only way a delivery can be driven in a test.
	log := discardLogger()
	worker := NewWorker(store, NewDeliverer(ssrf.NewForTests(nil), log), log, 10, time.Second)

	before := testutil.ToFloat64(metrics.WebhookAttempts.WithLabelValues(EventInvoicePaid, "delivered"))

	worker.attempt(ctx, due)

	after := testutil.ToFloat64(metrics.WebhookAttempts.WithLabelValues(EventInvoicePaid, "delivered"))
	if after != before+1 {
		t.Fatalf("webhook_delivery_attempts_total{outcome=delivered} moved from %v to %v, want +1. "+
			"This counter is the only signal that deliveries are happening at all: the worker serves "+
			"no API, and the outbox depth says how much is queued, not whether any of it moved.",
			before, after)
	}

	// The receiver was actually called, so the metric is not counting a failed attempt as a
	// delivered one.
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("the test receiver was never called, so the delivery did not happen")
	}

	// And the row was settled, so the metric and the database agree.
	state, attempts := outboxState(t, d, id)
	if state != StateDelivered {
		t.Errorf("state = %q after a successful attempt, want %q", state, StateDelivered)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}
