package webhook

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestSign_VerifyRoundTrip is the baseline, and it asserts both directions because a signature
// scheme that signs and verifies with the same wrong assumption passes a one-way test.
func TestSign_VerifyRoundTrip(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	body := []byte(`{"id":"01a08de1-0000-7000-8000-000000000001","event":"invoice.paid"}`)
	now := time.Now()

	header := Sign(secret, now, body)

	if err := Verify(secret, header, body, now, SignatureTolerance); err != nil {
		t.Fatalf("a signature this package produced failed to verify: %v", err)
	}

	// The header carries the timestamp, which is what lets a receiver window it for replay.
	timestamp, digest, err := ParseSignature(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if timestamp != now.Unix() {
		t.Errorf("timestamp = %d, want %d", timestamp, now.Unix())
	}
	if len(digest) != 64 {
		t.Errorf("digest is %d hex characters, want 64 (sha256)", len(digest))
	}
}

// TestVerify_RejectsATamperedBody is the forgery check.
func TestVerify_RejectsATamperedBody(t *testing.T) {
	secret, _ := GenerateSecret()
	body := []byte(`{"total_minor":100}`)
	now := time.Now()
	header := Sign(secret, now, body)

	// One character changed: a receiver that accepted this would act on an amount nobody sent.
	tampered := []byte(`{"total_minor":900}`)
	if err := Verify(secret, header, tampered, now, SignatureTolerance); err == nil {
		t.Fatal("a tampered body verified against a signature for the original")
	}
}

// TestVerify_RejectsAnOldSignature is the replay check, and it is the reason the timestamp is
// inside the MAC rather than merely alongside it.
//
// A signature over the body alone proves authorship but not freshness: an attacker who captures
// one delivery resends it forever and every copy verifies. Because the timestamp is signed, an old
// header cannot be reused with a fresh one — and a receiver's tolerance window is what makes that
// refusal possible.
func TestVerify_RejectsAnOldSignature(t *testing.T) {
	secret, _ := GenerateSecret()
	body := []byte(`{"event":"invoice.paid"}`)
	signedAt := time.Now().Add(-time.Hour)

	header := Sign(secret, signedAt, body)

	// Within the window it is valid.
	if err := Verify(secret, header, body, signedAt, SignatureTolerance); err != nil {
		t.Fatalf("a fresh signature failed: %v", err)
	}

	// An hour later, the same header must be refused. This is the replay.
	if err := Verify(secret, header, body, time.Now(), SignatureTolerance); err == nil {
		t.Fatal("a signature an hour old was accepted; a captured delivery could be replayed forever")
	}

	// Skew in the other direction is refused too, or a client whose clock is ahead could mint
	// signatures that are valid long into the future.
	future := time.Now().Add(time.Hour)
	futureHeader := Sign(secret, future, body)
	if err := Verify(secret, futureHeader, body, time.Now(), SignatureTolerance); err == nil {
		t.Fatal("a signature from the future was accepted; it would be valid for as long as the skew")
	}
}

// TestVerify_RejectsAWrongSecret covers the case a receiver actually hits: a secret rotated on one
// side and not the other.
func TestVerify_RejectsAWrongSecret(t *testing.T) {
	right, _ := GenerateSecret()
	wrong, _ := GenerateSecret()
	body := []byte(`{"event":"invoice.paid"}`)
	now := time.Now()

	header := Sign(right, now, body)
	if err := Verify(wrong, header, body, now, SignatureTolerance); err == nil {
		t.Fatal("a signature verified against the wrong secret")
	}
}

// TestParseSignature_RejectsANonIntegerTimestamp is the regression test for a bug that made this
// path accept more than it should.
//
// The first version appended "s" and called time.ParseDuration, which parses far more than an
// integer: "1h30m" became "1h30ms" and yielded 3600.03 seconds, truncated to 3600 — a malformed
// timestamp silently accepted as a valid one. On a path whose failure mode is a forged delivery,
// accepting more than intended is the wrong direction to be wrong in.
func TestParseSignature_RejectsANonIntegerTimestamp(t *testing.T) {
	valid := "4bf92f3577b34da6a3ce929d0e0e4736"

	for _, bad := range []string{
		"t=1h30m,v1=" + valid,
		"t=1s,v1=" + valid,
		"t=1.5,v1=" + valid,
		"t=,v1=" + valid,
		"t=9999999999999999999999,v1=" + valid, // past int64
		"t=0x10,v1=" + valid,
		"t= 10 ,v1=" + valid,
	} {
		if _, _, err := ParseSignature(bad); err == nil {
			t.Errorf("a non-integer timestamp was accepted: %q", bad)
		}
	}

	// The valid form still parses, and negative values are the caller's problem rather than a
	// parse error — a negative unix time is representable, and Verify's skew check refuses it.
	if _, _, err := ParseSignature("t=1700000000,v1=" + valid); err != nil {
		t.Errorf("a valid timestamp was refused: %v", err)
	}
}

// TestParseSignature_RequiresBothParts covers a partially-formed header.
func TestParseSignature_RequiresBothParts(t *testing.T) {
	digest := strings.Repeat("a", 64)

	for _, bad := range []string{
		"",                  // empty
		"garbage",           // not a header
		"v1=" + digest,      // no timestamp
		"t=1700000000",      // no digest
		"t=1700000000,v2=x", // unknown version only
		"t1700000000,v1=x",  // malformed parts
	} {
		if _, _, err := ParseSignature(bad); err == nil {
			t.Errorf("%q was accepted as a signature", bad)
		}
	}
}

// TestVerify_RejectsAMalformedHeader keeps the error path exercised rather than only the happy one.
func TestVerify_RejectsAMalformedHeader(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()

	for _, bad := range []string{"", "t=abc,v1=zz", "t=1700000000,v1=not-hex"} {
		if err := Verify(secret, bad, []byte("{}"), now, SignatureTolerance); err == nil {
			t.Errorf("a malformed signature header was accepted: %q", bad)
		}
	}
}

// TestNextDelay_BacksOffAndStops pins the retry schedule, including where it stops.
//
// The last entry is repeated rather than indexing past the end, so raising MaxAttempts without
// extending the schedule produces an hour between attempts rather than a panic or a zero delay.
func TestNextDelay_BacksOffAndStops(t *testing.T) {
	want := []time.Duration{time.Second, 5 * time.Second, 30 * time.Second, 5 * time.Minute, time.Hour}

	for i, expected := range want {
		// jitterFraction = 1 selects the top of the range, which is the nominal value.
		got, retry := NextDelay(i+1, 1)
		if !retry {
			t.Fatalf("attempt %d should still retry (MaxAttempts is %d)", i+1, MaxAttempts)
		}
		if got != expected {
			t.Errorf("attempt %d delay = %s, want %s at the top of the jitter range", i+1, got, expected)
		}
	}

	// Attempts at or past the budget are terminal, which is what puts a row in the DLQ.
	if _, retry := NextDelay(MaxAttempts, 0.5); retry {
		t.Fatalf("attempt %d was allowed to retry, so a delivery would never reach the DLQ", MaxAttempts)
	}
	if _, retry := NextDelay(MaxAttempts+1, 0.5); retry {
		t.Fatal("an attempt past the budget was allowed to retry")
	}
	if _, retry := NextDelay(0, 0.5); !retry {
		t.Fatal("attempt 0 was treated as exhausted")
	}
}

// TestNextDelay_JitterStaysInRange is the anti-thundering-herd check.
//
// Jitter exists so that a receiver which briefly failed does not have every tenant's webhooks
// retried at the same instant — the retry mechanism would otherwise amplify the failure it exists
// to survive. Too little spread defeats that; going past the nominal value would make the
// documented schedule a lie, so the range is bounded to 50-100% rather than full jitter.
func TestNextDelay_JitterStaysInRange(t *testing.T) {
	const attempt = 3
	nominal := NominalBackoff(attempt)

	for _, f := range []float64{-1, 0, 0.25, 0.5, 0.75, 1, 2} {
		got, retry := NextDelay(attempt, f)
		if !retry {
			t.Fatalf("attempt %d stopped retrying early", attempt)
		}
		if got < nominal/2 || got > nominal {
			t.Errorf("jitter fraction %v produced %s, outside [%s, %s]",
				f, got, nominal/2, nominal)
		}
	}

	// Out-of-range fractions are clamped rather than trusted. A NaN or a negative from a caller
	// would otherwise produce a delay of zero, which is a busy retry loop against a struggling
	// receiver — the worst possible timing.
	if got, _ := NextDelay(attempt, -5); got < nominal/2 {
		t.Errorf("a negative jitter fraction produced %s, below half the nominal delay", got)
	}
	if got, _ := NextDelay(attempt, 5); got > nominal {
		t.Errorf("an oversized jitter fraction produced %s, above the nominal delay", got)
	}
}

// TestNominalBackoff_RepeatsTheLastEntry documents the behaviour the comment claims.
func TestNominalBackoff_RepeatsTheLastEntry(t *testing.T) {
	last := backoffSchedule[len(backoffSchedule)-1]

	for i := len(backoffSchedule) + 1; i < len(backoffSchedule)+5; i++ {
		if got := NominalBackoff(i); got != last {
			t.Errorf("NominalBackoff(%d) = %s, want the last schedule entry %s", i, got, last)
		}
	}
	if got := NominalBackoff(0); got != 0 {
		t.Errorf("NominalBackoff(0) = %s, want 0 (no prior failure)", got)
	}
}

// TestValidateEvents covers the subscription rules, including the one that matters: an unknown
// event is refused rather than accepted.
//
// An endpoint subscribed to a typo would look correctly registered and never fire. That is the
// worst kind of integration bug — nothing errors, and the tenant discovers it as a missing
// webhook days later.
func TestValidateEvents(t *testing.T) {
	got, err := ValidateEvents([]string{EventInvoicePaid, EventInvoiceCreated})
	if err != nil {
		t.Fatalf("valid events were refused: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2", len(got))
	}

	// Duplicates are removed rather than refused: a client that lists one twice means it once, and
	// failing the request would be pedantry. The stored array is what fan-out matches on, so a
	// duplicate would otherwise deliver the event twice.
	deduped, err := ValidateEvents([]string{EventInvoicePaid, EventInvoicePaid, EventInvoicePaid})
	if err != nil {
		t.Fatalf("duplicates were refused: %v", err)
	}
	if len(deduped) != 1 {
		t.Fatalf("duplicates were not removed: %v", deduped)
	}

	// Whitespace is trimmed rather than refused: the vocabulary is fixed, so trimming cannot
	// silently change which event a subscriber ends up receiving. A wrong *case* is a different
	// matter and is refused below, because the vocabulary lookup is exact.
	padded, err := ValidateEvents([]string{"  invoice.paid  "})
	if err != nil {
		t.Fatalf("a padded event name was refused rather than trimmed: %v", err)
	}
	if len(padded) != 1 || padded[0] != EventInvoicePaid {
		t.Fatalf("a padded event name normalized to %v, want [%s]", padded, EventInvoicePaid)
	}

	for _, bad := range []struct {
		name   string
		events []string
	}{
		{"empty", nil},
		{"empty slice", []string{}},
		{"unknown event", []string{"invoice.refunded"}},
		{"wrong case", []string{"Invoice.Paid"}},
		{"empty entry", []string{""}},
		{"too many", make([]string, 33)},
	} {
		if _, err := ValidateEvents(bad.events); err == nil {
			t.Errorf("%s was accepted", bad.name)
		}
	}
}

// TestValidateURLSyntax covers the shape checks that need no DNS.
func TestValidateURLSyntax(t *testing.T) {
	for _, good := range []string{
		"https://example.com/hook",
		"http://example.com:8080/hook?token=abc",
		"https://93.184.216.34/hook",
	} {
		if err := ValidateURLSyntax(good); err != nil {
			t.Errorf("%s was refused: %v", good, err)
		}
	}

	for _, bad := range []struct{ name, url string }{
		{"empty", ""},
		{"no scheme", "example.com/hook"},
		{"file scheme", "file:///etc/passwd"},
		{"gopher scheme", "gopher://example.com:70/"},
		{"no host", "https:///hook"},
		{"fragment", "https://example.com/hook#section"},
		{"embedded credentials", "https://user:pass@example.com/hook"},
		{"too long", "https://example.com/" + strings.Repeat("a", 2100)},
	} {
		if err := ValidateURLSyntax(bad.url); err == nil {
			t.Errorf("%s was accepted: %s", bad.name, bad.url)
		}
	}
}

// TestGenerateSecret_Shape covers the prefix a scanner keys on and the length the column requires.
func TestGenerateSecret_Shape(t *testing.T) {
	seen := map[string]bool{}

	for i := 0; i < 8; i++ {
		s, err := GenerateSecret()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if !strings.HasPrefix(s, "whsec_") {
			t.Fatalf("secret %q has no whsec_ prefix; a leaked secret is only recognisable as one "+
				"if it is identifiable at a glance", s)
		}
		if seen[s] {
			t.Fatal("two generated secrets are identical")
		}
		seen[s] = true

		if err := ValidateSecret(s); err != nil {
			t.Errorf("a generated secret failed its own validation: %v", err)
		}
	}

	for _, bad := range []string{"", "secret", "whsec_", "whsec_short", "sk_" + strings.Repeat("a", 43)} {
		if err := ValidateSecret(bad); err == nil {
			t.Errorf("%q was accepted as a secret", bad)
		}
	}
}

// TestValidateCreate_NormalisesInput covers the trimming and the event normalisation together.
func TestValidateCreate_NormalisesInput(t *testing.T) {
	got, err := ValidateCreate(CreateInput{
		URL:         "  https://example.com/hook  ",
		Events:      []string{EventInvoicePaid},
		Description: "  Billing integration  ",
	})
	if err != nil {
		t.Fatalf("a valid registration was refused: %v", err)
	}
	if got.URL != "https://example.com/hook" {
		t.Errorf("url was not trimmed: %q", got.URL)
	}
	if got.Description != "Billing integration" {
		t.Errorf("description was not trimmed: %q", got.Description)
	}

	if _, err := ValidateCreate(CreateInput{
		URL:         "https://example.com/hook",
		Events:      []string{EventInvoicePaid},
		Description: strings.Repeat("x", 501),
	}); err == nil {
		t.Error("an over-long description was accepted")
	}
}

// TestNormalizePageSize and TestNormalizeState cover the listing parameters.
func TestNormalizePageSize(t *testing.T) {
	cases := map[int]int{
		0: DefaultPageSize, -1: DefaultPageSize, 1: 1,
		MaxPageSize: MaxPageSize, MaxPageSize + 1: MaxPageSize, 99999: MaxPageSize,
	}
	for in, want := range cases {
		if got := NormalizePageSize(in); got != want {
			t.Errorf("NormalizePageSize(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNormalizeState(t *testing.T) {
	for _, s := range []string{StatePending, StateDelivering, StateDelivered, StateDead} {
		if got, err := NormalizeState(s); err != nil || got != s {
			t.Errorf("NormalizeState(%q) = %q, %v", s, got, err)
		}
	}
	if got, err := NormalizeState(""); err != nil || got != "" {
		t.Errorf("an empty state filter should mean any: %q, %v", got, err)
	}
	for _, bad := range []string{"dead ", "DEAD", "failed", "1"} {
		if _, err := NormalizeState(bad); err == nil {
			t.Errorf("NormalizeState(%q) was accepted; an unknown state filters to nothing and "+
				"reads as an empty queue", bad)
		}
	}
}

// TestEnvelope_SerializesTheReceiverContract pins what actually reaches a receiver, which is the
// part a receiver integrates against.
//
// It asserts on the serialized bytes rather than on the struct: a struct test passes even if a
// field is mistagged `json:"-"`, and a receiver only ever sees bytes.
func TestEnvelope_SerializesTheReceiverContract(t *testing.T) {
	enqueuedAt := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	env := Envelope{
		ID:        "01a08de1-0000-7000-8000-000000000001",
		Event:     EventInvoicePaid,
		CreatedAt: enqueuedAt,
		TenantID:  "01a08de1-0000-7000-8000-000000000002",
		Data:      map[string]any{"total_minor": 1234},
	}

	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// The id must survive serialization: it is the key a receiver deduplicates on, and a
	// mistagged field would leave every retry looking like a new event.
	if got["id"] != env.ID {
		t.Errorf("serialized id = %v, want %s", got["id"], env.ID)
	}
	if got["event"] != EventInvoicePaid {
		t.Errorf("serialized event = %v, want %s", got["event"], EventInvoicePaid)
	}
	if got["tenant_id"] != env.TenantID {
		t.Errorf("serialized tenant_id = %v, want %s", got["tenant_id"], env.TenantID)
	}
	data, ok := got["data"].(map[string]any)
	if !ok {
		t.Fatalf("serialized data is %T, want an object", got["data"])
	}
	if data["total_minor"] != float64(1234) {
		t.Errorf("serialized total_minor = %v, want 1234", data["total_minor"])
	}

	// created_at is present, and this assertion replaces one I wrote from an assumption rather
	// than from the struct: my first version asserted the field's absence and failed. It records
	// when the event was enqueued, which is a different instant from the signature header's t=,
	// set when the delivery was signed. A receiver ordering events uses this one; a receiver
	// deciding whether a delivery is a replay must still use the signed header, because that is
	// the value inside the MAC alongside the body.
	raw, ok := got["created_at"].(string)
	if !ok {
		t.Fatalf("serialized created_at is %T, want a string", got["created_at"])
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatalf("serialized created_at %q is not a parseable timestamp: %v", raw, err)
	}
	if !parsed.Equal(env.CreatedAt) {
		t.Errorf("serialized created_at = %s, want %s", parsed, env.CreatedAt)
	}
}
