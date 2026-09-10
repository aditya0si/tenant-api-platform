package idempotency

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEncodeHeaders_PersistsOnlyReplayableHeaders is the security test for the replay
// cache.
//
// The replay path is only as safe as what was persisted, and what gets persisted is
// decided here. A stored Set-Cookie handed to a different client is one session served to
// another, and a stored X-Request-Id makes a replayed response claim to be a different
// request than it is. Asserting on the persisted form is the point: a comment claiming a
// whitelist exists cannot fail, and this can.
func TestEncodeHeaders_PersistsOnlyReplayableHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Location", "/v1/tenants/t/projects/p")
	h.Set("ETag", `"v1"`)
	h.Set("Set-Cookie", "session=secret; HttpOnly")
	h.Set("X-Request-Id", "01a08d79-478a-7931-a6f2-380c33a99353")
	h.Set("Content-Length", "42")
	h.Set("Date", "Mon, 01 Jan 2026 00:00:00 GMT")
	h.Set("Connection", "keep-alive")

	raw, err := encodeHeaders(h)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	var stored map[string][]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("stored headers are not a JSON object: %v", err)
	}

	for _, drop := range []string{"Set-Cookie", "X-Request-Id", "Content-Length", "Date", "Connection"} {
		if _, ok := stored[drop]; ok {
			t.Errorf("%q was persisted for replay; it is per-response or per-connection state "+
				"and recording it is how a replay cache becomes a vulnerability", drop)
		}
	}
	for _, keep := range []string{"Content-Type", "Location", "ETag"} {
		if _, ok := stored[keep]; !ok {
			t.Errorf("%q was dropped but is needed to replay the response faithfully", keep)
		}
	}
}

// TestCapture_OverflowIsNotReplayable pins the overflow rule.
//
// It is the regression test for the bug this field exists to prevent: replayability was
// once inferred from len(Body), and because the buffer stops accumulating *at* the cap, a
// truncated body is smaller than the cap. That inference therefore marked exactly the
// responses that must not be replayed as safe — and the retrying client would receive half
// a JSON document that still parsed.
func TestCapture_OverflowIsNotReplayable(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewCapture(rec)

	first := bytes.Repeat([]byte("a"), 128)
	rest := bytes.Repeat([]byte("b"), maxStoredBody)
	if _, err := c.Write(first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := c.Write(rest); err != nil {
		t.Fatalf("second write: %v", err)
	}

	got := c.Captured()
	if got.Replayable() {
		t.Fatal("a capture that overflowed reports itself replayable; a retry would be served a truncated body")
	}

	// The client must receive every byte. Dropping bytes from the live response to keep the
	// copy intact would corrupt what the caller actually gets, which is strictly worse than
	// a record that cannot be replayed.
	if rec.Body.Len() != len(first)+len(rest) {
		t.Fatalf("client received %d bytes, want %d: the capture must not truncate the live response",
			rec.Body.Len(), len(first)+len(rest))
	}
	if !bytes.Equal(rec.Body.Bytes(), append(append([]byte{}, first...), rest...)) {
		t.Fatal("the bytes sent to the client are not the bytes the handler wrote")
	}

	// And the stored copy really is short — which is why the length cannot be the signal.
	if len(got.Body) >= len(first)+len(rest) {
		t.Fatalf("stored %d bytes, which is not truncated", len(got.Body))
	}
}

// TestCapture_WithinCapIsReplayable is the other half: the rule must not be so eager that
// ordinary responses stop being replayable.
func TestCapture_WithinCapIsReplayable(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewCapture(rec)

	body := []byte(`{"data":{"id":"01a08d79-478a-7931-a6f2-380c33a99353"}}`)
	c.WriteHeader(http.StatusCreated)
	if _, err := c.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := c.Captured()
	if !got.Replayable() {
		t.Fatal("a response well under the cap reports itself unreplayable")
	}
	if got.Status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", got.Status)
	}
	if !bytes.Equal(got.Body, body) {
		t.Fatalf("stored body = %q, want %q", got.Body, body)
	}
}

// TestCapture_FlushReachesTheUnderlyingWriter guards the passthrough that streaming
// depends on.
//
// A wrapper that does not forward Flush makes a streaming handler believe it flushed while
// the client sees nothing until the response completes. The symptom is "streaming does not
// work through some routes", which is expensive to diagnose, and it costs one method to
// prevent.
func TestCapture_FlushReachesTheUnderlyingWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	c := NewCapture(rec)

	c.WriteHeader(http.StatusOK)
	c.Write([]byte("chunk"))
	c.Flush()

	if !rec.Flushed {
		t.Fatal("Flush did not reach the wrapped ResponseWriter")
	}
	if got, want := rec.Body.String(), "chunk"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestDecodeHeaders_RejectsResponseSplitting covers the read side.
//
// Stored headers come from this service today, so they are not attacker-controlled — but a
// database row is not a trusted source of header *names*, and a value containing CRLF is
// how a response-splitting attack injects a second response. Re-validating on the way out
// costs nothing and removes the question.
func TestDecodeHeaders_RejectsResponseSplitting(t *testing.T) {
	raw := []byte(`{
		"Content-Type": ["application/json"],
		"X-Evil": ["a\r\nSet-Cookie: pwned=1"],
		"Bad Name": ["x"],
		"X-Empty": [""]
	}`)

	var h http.Header
	if err := decodeHeaders(raw, &h); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if h.Get("X-Evil") != "" {
		t.Error("a header value containing CRLF was accepted; that is a response-splitting vector")
	}
	if h.Get("Bad Name") != "" {
		t.Error("an invalid field name was accepted")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("a valid header was dropped along with the invalid ones")
	}
}

// TestFingerprint_SeparatesCollidingInputs covers the delimiter choice.
//
// Without separators between the components, ("ab", "c") and ("a", "bc") hash identically,
// so two different requests could share a fingerprint and one would replay the other's
// response — silently, and only for particular pairs of paths.
func TestFingerprint_SeparatesCollidingInputs(t *testing.T) {
	a := Fingerprint("POST", "/ab", "", []byte("c"))
	b := Fingerprint("POST", "/a", "", []byte("bc"))
	if a == b {
		t.Fatal("distinct requests share a fingerprint; a replay could return the wrong response")
	}

	same := Fingerprint("POST", "/ab", "", []byte("c"))
	if a != same {
		t.Fatal("the same request produced two fingerprints; retries would be treated as different requests")
	}

	diffBody := Fingerprint("POST", "/ab", "", []byte("d"))
	if a == diffBody {
		t.Fatal("a different body produced the same fingerprint")
	}

	diffQuery := Fingerprint("POST", "/ab", "x=1", []byte("c"))
	if a == diffQuery {
		t.Fatal("a different query string produced the same fingerprint")
	}
}

// TestValidateKey_RejectsEmptyAndOversize pins the key contract, since a key that is only
// whitespace would be stored and then never match the header a client retries with.
func TestValidateKey_RejectsEmptyAndOversize(t *testing.T) {
	if err := ValidateKey(""); err == nil {
		t.Error("an empty key was accepted")
	}
	if err := ValidateKey("   "); err == nil {
		t.Error("a whitespace-only key was accepted")
	}
	if err := ValidateKey(string(bytes.Repeat([]byte("k"), MaxKeyLength+1))); err == nil {
		t.Error("an oversize key was accepted")
	}
	if err := ValidateKey("order-12345"); err != nil {
		t.Errorf("a valid key was rejected: %v", err)
	}
}
