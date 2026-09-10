package idempotency

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// CapturedResponse is a handler's response, retained so it can be recorded and replayed.
type CapturedResponse struct {
	Status  int
	Headers http.Header
	Body    []byte

	// Overflow reports that the response exceeded maxStoredBody, so Body is incomplete.
	//
	// It is a field rather than something callers infer from len(Body), and that
	// distinction is the whole point: the buffer stops accumulating at the cap, so an
	// oversized response has a Body *shorter* than the limit. Inferring replayability from
	// the length therefore marks precisely the responses that must not be replayed as safe
	// to replay — and the retrying client would receive a truncated document that parses
	// as valid JSON.
	Overflow bool
}

// Replayable reports whether this response may be stored and replayed verbatim.
func (r CapturedResponse) Replayable() bool { return !r.Overflow }

// replayableHeaders are the response headers worth storing.
//
// A whitelist rather than everything, and that is the safety property that matters: the
// Date and Content-Length of the original response would be wrong when replayed, hop-by-hop
// headers are meaningless outside their connection, and a replayed Set-Cookie would hand one
// client another's session. Recording a header this service did not put there is how a
// replay cache turns into a vulnerability.
var replayableHeaders = []string{
	"Content-Type",
	"Location",
	"ETag",
}

// encodeHeaders renders the whitelisted subset as JSON.
func encodeHeaders(h http.Header) ([]byte, error) {
	if len(h) == 0 {
		return nil, nil
	}
	out := map[string][]string{}
	for _, name := range replayableHeaders {
		if vs := h.Values(name); len(vs) > 0 {
			out[name] = vs
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return json.Marshal(out)
}

// decodeHeaders restores headers from storage.
//
// A stored header name and value are re-validated rather than trusted. They came from this
// service, so they are not attacker-controlled today — but a database written to by anything
// else is not a trusted source of header *names*, and a name or value containing a colon or a
// newline is a response-splitting vector. The check costs nothing and removes the question.
func decodeHeaders(raw []byte, dst *http.Header) error {
	var stored map[string][]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	h := http.Header{}
	for name, values := range stored {
		if !validHeaderName(name) {
			continue
		}
		for _, v := range values {
			if !validHeaderValue(v) {
				// Skip rather than fail: a stored value that cannot be sent safely should
				// not take down the replay of an otherwise valid response.
				continue
			}
			h.Add(name, v)
		}
	}
	*dst = h
	return nil
}

// validHeaderName reports whether name is a syntactically valid HTTP header field name.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// validHeaderValue rejects values carrying CR or LF, which is how a response-splitting
// attack injects a second response.
func validHeaderValue(v string) bool {
	for _, r := range v {
		if r == '\r' || r == '\n' || r == 0 {
			return false
		}
	}
	return true
}

// Capture buffers a handler's response for recording while passing it through.
//
// It is exported because the HTTP layer owns the middleware that wraps a handler, and a
// second implementation of "capture while forwarding" would be a second place for the
// overflow rule to be got wrong.
//
// It passes bytes to the client as they are written and keeps a copy, rather than buffering
// the whole response before sending anything: buffering first would add latency to every
// write and would break streaming outright if this ever fronts a streaming endpoint.
type Capture struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
	overflow    bool
}

// NewCapture wraps w.
func NewCapture(w http.ResponseWriter) *Capture {
	return &Capture{ResponseWriter: w, status: http.StatusOK}
}

func (c *Capture) WriteHeader(status int) {
	if !c.wroteHeader {
		c.status = status
		c.wroteHeader = true
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *Capture) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.wroteHeader = true
	}

	// Stop accumulating past the cap, but keep writing to the client. Dropping bytes from
	// the live response to save room for the copy would corrupt what the client actually
	// receives, which is far worse than a record that cannot be replayed.
	if !c.overflow {
		if c.body.Len()+len(b) > maxStoredBody {
			c.overflow = true
		} else {
			c.body.Write(b)
		}
	}
	return c.ResponseWriter.Write(b)
}

// Flush forwards to the wrapped writer when it supports flushing.
//
// This passthrough is load-bearing rather than tidy. Wrapping a ResponseWriter without
// forwarding Flush silently breaks server-sent events and any streaming handler behind this
// middleware: the handler believes it is flushing, the interface assertion fails, and the
// client receives nothing until the response completes. The failure appears as "streaming
// does not work through some routes", which is a miserable thing to diagnose.
func (c *Capture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController, which is how the standard
// library reaches Flush, Hijack, and deadlines through a wrapper. Without it, a handler using
// ResponseController gets "feature not supported" for capabilities the real writer has.
func (c *Capture) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Captured returns the recorded response.
func (c *Capture) Captured() CapturedResponse {
	return CapturedResponse{
		Status:   c.status,
		Headers:  c.ResponseWriter.Header(),
		Body:     c.body.Bytes(),
		Overflow: c.overflow,
	}
}
