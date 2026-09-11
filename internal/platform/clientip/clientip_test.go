package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNoTrustedProxies_IgnoresForwardedHeaders is the security assertion this package
// exists for.
//
// An attacker being rate-limited varies X-Forwarded-For per request; if that header were
// believed, every request would look like a new caller and the limiter would report success
// while enforcing nothing. With no trusted proxies configured the header must be ignored
// entirely — including when it is well-formed and plausible.
func TestNoTrustedProxies_IgnoresForwardedHeaders(t *testing.T) {
	r, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.Trusts() {
		t.Fatal("a resolver built with no ranges reports that it trusts proxies")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:41234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("Forwarded", "for=203.0.113.98")

	if got := r.ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want the socket peer 198.51.100.7\n"+
			"honouring a client-supplied header here makes every header-keyed limit bypassable", got)
	}
}

// TestUntrustedPeer_IgnoresForwardedHeaders covers the same rule when *some* proxy is
// trusted but the peer is not one of them.
//
// It is the case that matters in a real deployment: the service does sit behind a proxy, so
// the operator has configured a range, and an attacker connects directly — or through a
// different proxy — and supplies the header themselves.
func TestUntrustedPeer_IgnoresForwardedHeaders(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:41234" // not in 10/8
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	if got := r.ClientIP(req); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want the socket peer; the peer is not a trusted proxy, so the "+
			"header must not be believed", got)
	}
}

// TestTrustedPeer_UsesForwardedClient covers the configured case.
//
// With a trusted peer the header is the only way to see the real client: every request
// arrives from the proxy's address, so without this every client behind it would share one
// rate-limit bucket and throttle each other.
func TestTrustedPeer_UsesForwardedClient(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:41234"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	if got := r.ClientIP(req); got != "203.0.113.99" {
		t.Fatalf("ClientIP = %q, want 203.0.113.99", got)
	}
}

// TestTrustedChain_WalksRightToLeft is the spoofing test for the multi-proxy case.
//
// X-Forwarded-For is appended to by each proxy, so the leftmost entry is whatever the
// original client supplied and the rightmost is what the closest proxy appended. Reading the
// leftmost value — the intuitive implementation — returns an attacker-chosen address and
// makes the limit bypassable again. The chain here is:
//
//	client-supplied (203.0.113.1, a lie) , real client (203.0.113.50) , our proxy (10.1.2.3)
//
// Walking from the right, 10.1.2.3 is trusted so the walk continues, 203.0.113.50 is not and
// is returned. Reading from the left would return the attacker's 203.0.113.1.
func TestTrustedChain_WalksRightToLeft(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:41234"
	req.Header.Set("X-Forwarded-For", "203.0.113.1, 203.0.113.50, 10.1.2.3")

	if got := r.ClientIP(req); got != "203.0.113.50" {
		t.Fatalf("ClientIP = %q, want 203.0.113.50 (the rightmost untrusted address)\n"+
			"returning 203.0.113.1 would hand the attacker control of their own bucket", got)
	}
}

// TestFullyTrustedChain_FallsBackToPeer covers a chain in which every hop is a trusted
// proxy — an internal service calling through the mesh.
//
// There is no client address to report, so the peer is the honest answer. Returning the last
// trusted hop would invent a client that does not exist.
func TestFullyTrustedChain_FallsBackToPeer(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:41234"
	req.Header.Set("X-Forwarded-For", "10.9.9.9, 10.8.8.8")

	if got := r.ClientIP(req); got != "10.1.2.3" {
		t.Fatalf("ClientIP = %q, want the socket peer 10.1.2.3", got)
	}
}

// TestPortStripping covers the easiest bypass an IP-keyed limiter can have.
//
// Source ports are free and change per connection, so a limiter that keys on addr:port
// gives an attacker a fresh bucket per request by doing nothing at all.
func TestPortStripping(t *testing.T) {
	cases := []struct {
		name string
		peer string
		want string
	}{
		{"ipv4 with port", "198.51.100.7:41234", "198.51.100.7"},
		{"ipv4 without port", "198.51.100.7", "198.51.100.7"},
		{"ipv6 with port", "[2001:db8::1]:41234", "2001:db8::1"},
		{"ipv6 without port", "2001:db8::1", "2001:db8::1"},
		{"ipv6 loopback with port", "[::1]:8080", "::1"},
	}

	r, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			if got := r.ClientIP(req); got != tc.want {
				t.Fatalf("ClientIP(%q) = %q, want %q", tc.peer, got, tc.want)
			}
		})
	}
}

// TestForwardedHeader covers RFC 7239, which a proxy may emit instead of X-Forwarded-For.
//
// "for=" is required by the spec and may be quoted, so both forms are accepted; a proxy that
// emits it and is silently ignored would make every client behind it share one bucket.
func TestForwardedHeader(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"bare", "for=203.0.113.5", "203.0.113.5"},
		{"quoted", `for="203.0.113.5"`, "203.0.113.5"},
		{"with proto", "for=203.0.113.5;proto=https", "203.0.113.5"},
		{"ipv6 quoted", `for="[2001:db8::1]:4711"`, "2001:db8::1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = "10.1.2.3:41234"
			req.Header.Set("Forwarded", tc.value)
			if got := r.ClientIP(req); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnreadableEntry_FallsBackToPeer is the security assertion for malformed input.
//
// An entry that does not parse as an address must never be adopted as a bucket key. If it
// were, a caller would control their own bucket by varying the garbage — one request per
// bucket, which is no limit at all. The peer is the honest fallback: it over-attributes
// every client behind the proxy to a shared bucket, which is a degradation rather than a
// bypass, and this project prefers the degradation.
func TestUnreadableEntry_FallsBackToPeer(t *testing.T) {
	r, err := New([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, junk := range []string{
		"not-an-address",
		"999.999.999.999",
		"203.0.113.5;proto=https", // the parameter must be stripped, and the rest is valid
		"for=",
		"::::",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.1.2.3:41234"
		req.Header.Set("X-Forwarded-For", junk)

		got := r.ClientIP(req)
		if got == junk {
			t.Fatalf("ClientIP returned the raw entry %q; a value that is not an address must not "+
				"become a bucket key, or a caller chooses its own bucket", junk)
		}
		if junk == "999.999.999.999" && got != "10.1.2.3" {
			t.Fatalf("ClientIP = %q, want the peer", got)
		}
	}
}

// TestNew_AcceptsBareAddressAndRejectsGarbage pins configuration parsing.
//
// A bare address is a common way to write "this one proxy", so it is read as a single-host
// prefix rather than rejected. Garbage is rejected at construction, because the alternative
// is a service that starts and then attributes every request to the wrong thing.
func TestNew_AcceptsBareAddressAndRejectsGarbage(t *testing.T) {
	r, err := New([]string{"10.1.2.3"})
	if err != nil {
		t.Fatalf("a bare address was rejected: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := r.ClientIP(req); got != "203.0.113.9" {
		t.Fatalf("a bare address was not treated as trustable: got %q", got)
	}

	if _, err := New([]string{"not-an-address"}); err == nil {
		t.Fatal("garbage was accepted as a trusted proxy range")
	}
}
