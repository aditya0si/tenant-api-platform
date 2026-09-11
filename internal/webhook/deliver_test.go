package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/ssrf"
)

// These tests drive one real HTTP delivery against a real listener. Everything else in this
// package tests the pieces — the signature arithmetic, the claim query, the retry schedule — and
// none of it proves the assembled request is one a receiver can verify. That gap is where a
// delivery system fails in the most annoying way possible: every internal assertion passes, the
// queue drains, the logs say "delivered", and the tenant's endpoint rejects every request because
// a header name or a covered byte is wrong.
//
// The guard is the tests-only constructor with loopback permitted, so a test can point an endpoint
// at an httptest server. It is deliberately a named constructor rather than a flag: production
// calls ssrf.New(), and the difference is visible at the call site rather than buried in a bool.

// recordedRequest is what the receiver actually saw.
type recordedRequest struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

// recorder is a receiver that remembers every request it was sent.
type recorder struct {
	mu       sync.Mutex
	requests []recordedRequest
}

// handler answers with status and records the request.
func (r *recorder) handler(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, 0)
		if req.Body != nil {
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(req.Body)
			body = buf.Bytes()
		}

		r.mu.Lock()
		r.requests = append(r.requests, recordedRequest{
			method:  req.Method,
			path:    req.URL.Path,
			headers: req.Header.Clone(),
			body:    body,
		})
		r.mu.Unlock()

		w.WriteHeader(status)
	}
}

func (r *recorder) all() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest(nil), r.requests...)
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// forPath returns the requests that hit one path, so a redirect test can assert on the hop that
// was or was not taken.
func (r *recorder) forPath(path string) []recordedRequest {
	var out []recordedRequest
	for _, req := range r.all() {
		if req.path == path {
			out = append(out, req)
		}
	}
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// newDelivererWithClock builds a deliverer whose clock is fixed, so a signature's timestamp is
// assertable without sleeping.
func newDelivererWithClock(at time.Time) *Deliverer {
	d := NewDeliverer(ssrf.NewForTests(nil), discardLogger())
	d.now = func() time.Time { return at }
	return d
}

// dueFor builds the claimed row a delivery attempt receives.
//
// The event id is generated once and used for both the envelope body and the row's event_id,
// mirroring what Enqueue does. That is the property under test — a receiver deduplicates on the
// id in the body, and the header must carry the same value — so a fixture that generated them
// independently would make the assertion untestable rather than the code wrong.
func dueFor(t *testing.T, url, event, secret string) Due {
	t.Helper()

	eventID := uuid.Must(uuid.NewV7())

	payload, err := json.Marshal(Envelope{
		ID:        eventID.String(),
		Event:     event,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		TenantID:  uuid.Must(uuid.NewV7()).String(),
		Data:      map[string]any{"total_minor": 1234},
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	return Due{
		ID:         uuid.Must(uuid.NewV7()),
		TenantID:   uuid.Must(uuid.NewV7()),
		EndpointID: uuid.Must(uuid.NewV7()),
		EventID:    eventID,
		Event:      event,
		Payload:    payload,
		Attempt:    1,
		URL:        url,
		Secret:     secret,
	}
}

// TestDeliver_SendsAVerifiableSignedRequest is the wire-contract test.
//
// It asserts the request a receiver has to accept: the right method, the headers a receiver reads,
// and — the part that cannot be checked from inside this process — that a receiver following the
// documented scheme verifies the signature over the bytes it actually received.
func TestDeliver_SendsAVerifiableSignedRequest(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK))
	defer srv.Close()

	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	at := time.Now()
	d := newDelivererWithClock(at)
	due := dueFor(t, srv.URL+"/hook", EventInvoicePaid, secret)

	res := d.Deliver(context.Background(), due)

	if !res.Succeeded() {
		t.Fatalf("delivery failed: status %d, err %v", res.StatusCode, res.Err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}

	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("the receiver saw %d requests, want exactly 1", len(got))
	}
	req := got[0]

	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST: a receiver routing on method would drop this", req.method)
	}
	if ct := req.headers.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// The body must be the frozen payload byte for byte. Re-marshalling it here would send
	// different bytes than the ones the signature covers the moment a struct tag changes.
	if !bytes.Equal(req.body, due.Payload) {
		t.Errorf("body differs from the stored payload:\n got %s\nwant %s", req.body, due.Payload)
	}

	if got, want := req.headers.Get(EventHeader), EventInvoicePaid; got != want {
		t.Errorf("%s = %q, want %q", EventHeader, got, want)
	}
	if got, want := req.headers.Get(IDHeader), due.EventID.String(); got != want {
		t.Errorf("%s = %q, want %q: this is the key a receiver deduplicates on", IDHeader, got, want)
	}
	if got, want := req.headers.Get(AttemptHeader), "1"; got != want {
		t.Errorf("%s = %q, want %q", AttemptHeader, got, want)
	}

	// The assertion that matters: verify the transmitted signature against the transmitted body,
	// exactly as a receiver would, using only what arrived on the wire.
	header := req.headers.Get(SignatureHeader)
	if header == "" {
		t.Fatalf("no %s header was sent, so nothing can authenticate the delivery", SignatureHeader)
	}
	if err := Verify(secret, header, req.body, at, SignatureTolerance); err != nil {
		t.Fatalf("a receiver following the documented scheme cannot verify this delivery: %v", err)
	}

	// The signature is over the body, so flipping one byte must break it — the receiver-side
	// property, asserted from the same captured request rather than from a second synthetic one.
	tampered := append([]byte(nil), req.body...)
	tampered[len(tampered)-2] ^= 0x01
	if err := Verify(secret, header, tampered, at, SignatureTolerance); err == nil {
		t.Fatal("a one-byte change to the delivered body still verified")
	}

	// The envelope's deduplication key is in the body as well as the header: a receiver that logs
	// payloads and not headers — most of them — needs it there, and the two must agree.
	var env Envelope
	if err := json.Unmarshal(req.body, &env); err != nil {
		t.Fatalf("the delivered body is not a valid envelope: %v", err)
	}
	if env.ID != due.EventID.String() {
		t.Errorf("the body's id is %q but %s was %q; a receiver keying on one and logging the "+
			"other would deduplicate the wrong event", env.ID, IDHeader, due.EventID)
	}
	if env.Event != EventInvoicePaid {
		t.Errorf("the body's event is %q, want %q", env.Event, EventInvoicePaid)
	}
}

// TestDeliver_CarriesTheTraceparentWhenPresentAndOmitsItOtherwise covers the correlation header.
//
// An empty traceparent is omitted rather than sent blank: a receiver that parses the header would
// see an unusable value and either error or record a bogus trace id, and a retry reusing the
// original one is deliberate — this is still the same logical event.
func TestDeliver_CarriesTheTraceparentWhenPresentAndOmitsItOtherwise(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK))
	defer srv.Close()

	secret, _ := GenerateSecret()
	d := newDelivererWithClock(time.Now())

	traceparent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	due := dueFor(t, srv.URL+"/hooked", EventInvoicePaid, secret)
	due.Traceparent = &traceparent

	if res := d.Deliver(context.Background(), due); !res.Succeeded() {
		t.Fatalf("delivery with a traceparent failed: %v", res.Err)
	}
	if got := rec.forPath("/hooked")[0].headers.Get("traceparent"); got != traceparent {
		t.Errorf("traceparent = %q, want %q", got, traceparent)
	}

	empty := ""
	due2 := dueFor(t, srv.URL+"/untraced", EventInvoiceCreated, secret)
	due2.Traceparent = &empty
	if res := d.Deliver(context.Background(), due2); !res.Succeeded() {
		t.Fatalf("delivery with an empty traceparent failed: %v", res.Err)
	}
	if got := rec.forPath("/untraced")[0].headers.Get("traceparent"); got != "" {
		t.Errorf("an empty traceparent was sent as %q, want the header omitted", got)
	}
}

// TestDeliver_RefusesANonPublicTarget is the guard's presence in the delivery path, as opposed to
// the registration path.
//
// It has to be here and not only at registration: a tenant registers a public hostname, the check
// passes, and then the name is repointed at the metadata service. Validating once would be a
// time-of-check to time-of-use bug with a slow clock, which is the bug that made this a
// re-validation on every attempt.
func TestDeliver_RefusesANonPublicTarget(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec.handler(http.StatusOK))
	defer srv.Close()

	secret, _ := GenerateSecret()
	d := newDelivererWithClock(time.Now())

	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://10.0.0.1/internal",
		"http://192.168.1.1/admin",
		"http://[fd00::1]/internal",
	} {
		due := dueFor(t, target, EventInvoicePaid, secret)

		res := d.Deliver(context.Background(), due)

		if res.Succeeded() {
			t.Errorf("%s was delivered; a tenant-supplied URL reaching private space is the SSRF "+
				"the guard exists to prevent", target)
		}
		if res.Err == nil {
			t.Errorf("%s produced no error, so the refusal is indistinguishable from a transport "+
				"failure in the delivery history", target)
		} else if !errors.Is(res.Err, ssrf.ErrBlocked) {
			t.Errorf("%s failed with %v, want a wrapped ssrf.ErrBlocked", target, res.Err)
		}
	}

	if n := rec.count(); n != 0 {
		t.Errorf("the receiver saw %d requests, want 0", n)
	}
}

// TestDeliver_Non2xxIsAFailure covers the status classification, including the 3xx case.
//
// A 3xx is a failure rather than a redirect to follow: the client refuses redirects, so a 302
// arrives here and is recorded as what it is. Treating it as success would mark a delivery
// delivered that the receiver never processed — the exact silent loss the outbox exists to
// prevent.
func TestDeliver_Non2xxIsAFailure(t *testing.T) {
	secret, _ := GenerateSecret()

	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusFound, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		rec := &recorder{}
		srv := httptest.NewServer(rec.handler(status))

		due := dueFor(t, srv.URL+"/status", EventInvoicePaid, secret)
		res := newDelivererWithClock(time.Now()).Deliver(context.Background(), due)

		if res.Succeeded() {
			t.Errorf("a %d was treated as delivered", status)
		}
		if res.StatusCode != status {
			t.Errorf("status = %d, want %d: the delivery history records this for an operator", res.StatusCode, status)
		}
		// A non-2xx response is not a transport error, and conflating them would make the retry
		// logic unable to distinguish "the receiver said no" from "we never reached it".
		if res.Err != nil {
			t.Errorf("a %d produced a transport error (%v); the status is the meaningful field here", status, res.Err)
		}

		srv.Close()
	}
}

// TestDeliver_DoesNotFollowARedirectEvenToAnAllowedTarget separates two behaviours that are easy
// to conflate.
//
// The redirect destination here is loopback and the tests-only guard permits loopback, so the
// guard raises no objection — and the delivery still must not follow. The signature covers the
// body and the timestamp, not the destination, so following a redirect resends a validly signed
// payload to a host the tenant never registered. The refusal is the client's, and it is what the
// 302 status in the delivery history represents.
func TestDeliver_DoesNotFollowARedirectEvenToAnAllowedTarget(t *testing.T) {
	rec := &recorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/destination", http.StatusFound)
	})
	mux.HandleFunc("/destination", rec.handler(http.StatusOK))

	srv := httptest.NewServer(mux)
	defer srv.Close()

	secret, _ := GenerateSecret()
	due := dueFor(t, srv.URL+"/start", EventInvoicePaid, secret)

	res := newDelivererWithClock(time.Now()).Deliver(context.Background(), due)

	if res.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302: the redirect must be reported, not silently resolved", res.StatusCode)
	}
	if res.Succeeded() {
		t.Error("a redirect was treated as a successful delivery, so the receiver never saw the event")
	}
	if n := len(rec.forPath("/destination")); n != 0 {
		t.Fatalf("the redirect was followed: the signed payload was resent to %d hop(s) the tenant "+
			"never registered", n)
	}
}

// TestDeliver_RefusesARedirectIntoPrivateSpace is the redirect half of the guard.
//
// A public host that answers with a redirect to the metadata service is the bypass the
// per-redirect re-validation exists for: the initial URL was legitimately public, so a check
// performed only before the first request would permit it.
func TestDeliver_RefusesARedirectIntoPrivateSpace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	secret, _ := GenerateSecret()
	due := dueFor(t, srv.URL+"/public", EventInvoicePaid, secret)

	res := newDelivererWithClock(time.Now()).Deliver(context.Background(), due)

	if res.Succeeded() {
		t.Fatal("a redirect into the metadata range was treated as a successful delivery")
	}
	if res.Err == nil || !errors.Is(res.Err, ssrf.ErrBlocked) {
		t.Fatalf("the refusal carried %v, want a wrapped ssrf.ErrBlocked so an operator can tell "+
			"a policy refusal from a network failure", res.Err)
	}
}

// TestDeliver_APerAttemptDeadlineBoundsOneReceiver covers the timeout that keeps one slow endpoint
// from holding a whole batch.
//
// The parent context bounds the poll cycle; this bounds a single receiver, and the distinction is
// what stops a hung endpoint from consuming the worker's entire interval while every other
// tenant's deliveries wait behind it.
func TestDeliver_APerAttemptDeadlineBoundsOneReceiver(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Held open past the delivery timeout. The handler unblocks when the test ends, so the
		// server can still shut down cleanly.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	secret, _ := GenerateSecret()
	due := dueFor(t, srv.URL+"/slow", EventInvoicePaid, secret)

	// A context with less headroom than the delivery timeout, so the test does not take
	// DeliveryTimeout to complete. The deadline under test is the per-attempt one, and it is
	// derived from this parent.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	started := time.Now()
	res := newDelivererWithClock(time.Now()).Deliver(ctx, due)
	elapsed := time.Since(started)

	if res.Succeeded() {
		t.Fatal("a receiver that never responded was treated as a successful delivery")
	}
	if res.Err == nil {
		t.Fatal("a hung receiver produced no error")
	}
	if elapsed > DeliveryTimeout {
		t.Errorf("the attempt took %s, longer than the %s delivery timeout", elapsed, DeliveryTimeout)
	}
	// The deadline is the parent's here, so assert it actually took effect rather than returning
	// instantly for some unrelated reason.
	if elapsed < 200*time.Millisecond {
		t.Errorf("the attempt returned after only %s; it did not wait for the deadline it was "+
			"given, so a hung receiver would be retried in a tight loop", elapsed)
	}
}
