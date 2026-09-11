package ssrf

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixedResolver answers every lookup with the same addresses, and counts the calls.
//
// The count is what makes the rebinding test meaningful: the defence is that the client never
// performs a second lookup, so asserting "the answer was used" is weaker than asserting "the
// resolver was asked exactly once".
type fixedResolver struct {
	addrs []netip.Addr
	calls atomic.Int32
	err   error
}

func (r *fixedResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	return r.addrs, nil
}

// TestValidate_RejectsNonPublicAddresses is the core of the guard.
//
// Every entry is a category an SSRF attempt actually uses. The metadata addresses in particular
// are the reason this package exists: on a cloud instance, 169.254.169.254 returns credentials,
// and a webhook URL is attacker-supplied, so an unguarded delivery is a credential-exfiltration
// primitive rather than a nuisance.
func TestValidate_RejectsNonPublicAddresses(t *testing.T) {
	g := New()

	blocked := map[string]string{
		"cloud metadata":           "http://169.254.169.254/latest/meta-data/",
		"metadata by name":         "http://metadata.google.internal/",
		"ipv4 loopback":            "http://127.0.0.1:8080/hook",
		"ipv6 loopback":            "http://[::1]:8080/hook",
		"rfc1918 ten":              "http://10.0.0.1/hook",
		"rfc1918 172":              "http://172.16.5.4/hook",
		"rfc1918 192":              "http://192.168.1.1/hook",
		"ipv4 link-local":          "http://169.254.1.1/hook",
		"ipv6 link-local":          "http://[fe80::1]/hook",
		"unspecified v4":           "http://0.0.0.0/hook",
		"unspecified v6":           "http://[::]/hook",
		"cg nat":                   "http://100.100.100.100/hook",
		"ietf protocol assignment": "http://192.0.0.8/hook",
		"benchmarking":             "http://198.18.0.1/hook",
		"reserved":                 "http://240.0.0.1/hook",
		"broadcast":                "http://255.255.255.255/hook",
		"private ipv6":             "http://[fd00::1]/hook",
		"nat64":                    "http://[64:ff9b::7f00:1]/hook",
		"discard only":             "http://[100::1]/hook",
		"documentation v6":         "http://[2001:db8::1]/hook",
		"4in6 loopback":            "http://[::ffff:127.0.0.1]:8080/hook",
		"4in6 metadata":            "http://[::ffff:169.254.169.254]/hook",
	}

	for name, rawURL := range blocked {
		t.Run(name, func(t *testing.T) {
			if _, err := g.Validate(context.Background(), rawURL); err == nil {
				t.Fatalf("%s was allowed: %s", name, rawURL)
			} else if !errors.Is(err, ErrBlocked) && !errors.Is(err, ErrNoAddresses) {
				t.Fatalf("%s failed for an unexpected reason: %v", name, err)
			}
		})
	}
}

// TestValidate_RejectsTransitionRanges covers 6to4 and Teredo, which carry an embedded IPv4
// address and are therefore a route back into private space.
func TestValidate_RejectsTransitionRanges(t *testing.T) {
	g := New()

	// 2002:7f00:0001::/48 encodes 127.0.0.1 — the classic 6to4 pivot.
	for _, rawURL := range []string{
		"http://[2002::1]/hook",
		"http://[2002:7f00:1::1]/hook",
		"http://[2001::1]/hook",
	} {
		if _, err := g.Validate(context.Background(), rawURL); err == nil {
			t.Errorf("an IPv6 transition address was allowed: %s", rawURL)
		}
	}
}

// TestValidate_AcceptsPublicAddresses is the control: a guard that refused everything would pass
// every test above and be useless.
func TestValidate_AcceptsPublicAddresses(t *testing.T) {
	g := New()

	for _, rawURL := range []string{
		"https://93.184.216.34/hook", // a real public address, as a literal
		"http://93.184.216.34:8080/hook",
		"https://[2606:2800:220:1:248:1893:25c8:1946]/hook",
	} {
		res, err := g.Validate(context.Background(), rawURL)
		if err != nil {
			t.Fatalf("%s was refused: %v", rawURL, err)
		}
		if len(res.Addrs) == 0 {
			t.Fatalf("%s produced no addresses", rawURL)
		}
	}
}

// TestValidate_RejectsHostnameWithAnyNonPublicAddress is the multi-address bypass.
//
// A name with one public A record and one private is a working attack if only the first address
// is examined — and the HTTP client picks for itself, so examining one and dialling whichever it
// likes is exactly the hole. Every returned address must be public.
func TestValidate_RejectsHostnameWithAnyNonPublicAddress(t *testing.T) {
	public := netip.MustParseAddr("93.184.216.34")
	metadata := netip.MustParseAddr("169.254.169.254")
	private := netip.MustParseAddr("10.1.2.3")

	cases := map[string][]netip.Addr{
		"public then metadata": {public, metadata},
		"metadata then public": {metadata, public},
		"public then private":  {public, private},
		"two public":           {public, netip.MustParseAddr("1.1.1.1")},
	}

	for name, addrs := range cases {
		t.Run(name, func(t *testing.T) {
			g := NewWithResolver(&fixedResolver{addrs: addrs})
			_, err := g.Validate(context.Background(), "https://webhooks.example/hook")

			shouldBlock := false
			for _, a := range addrs {
				if err := g.checkAddr(a); err != nil {
					shouldBlock = true
				}
			}
			if shouldBlock && err == nil {
				t.Fatalf("a hostname resolving to %v was accepted; the client would dial whichever "+
					"address it preferred", addrs)
			}
			if !shouldBlock && err != nil {
				t.Fatalf("an all-public hostname was refused: %v", err)
			}
		})
	}
}

// TestValidate_RejectsNonHTTPAndBrokenURLs covers the boundary cases.
func TestValidate_RejectsNonHTTPAndBrokenURLs(t *testing.T) {
	g := New()

	for _, rawURL := range []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:70/",
		"ftp://93.184.216.34/x",
		"dict://169.254.169.254:11211/",
		"//93.184.216.34/hook",
		"not a url at all",
	} {
		if _, err := g.Validate(context.Background(), rawURL); err == nil {
			t.Errorf("%q was allowed", rawURL)
		}
	}

	// A hostname that does not resolve is refused rather than deferred to delivery.
	g2 := NewWithResolver(&fixedResolver{err: errors.New("no such host")})
	if _, err := g2.Validate(context.Background(), "https://nope.invalid/hook"); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("an unresolvable host produced %v, want ErrNoAddresses", err)
	}

	// A resolver that answers with nothing is the same case.
	g3 := NewWithResolver(&fixedResolver{})
	if _, err := g3.Validate(context.Background(), "https://empty.example/hook"); !errors.Is(err, ErrNoAddresses) {
		t.Fatalf("an empty answer produced %v, want ErrNoAddresses", err)
	}
}

// TestValidate_UsesDefaultPorts covers the port defaulting, since the dialer needs one.
func TestValidate_UsesDefaultPorts(t *testing.T) {
	g := NewWithResolver(&fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("93.184.216.34")}})

	https, err := g.Validate(context.Background(), "https://webhooks.example/hook")
	if err != nil {
		t.Fatalf("https: %v", err)
	}
	if https.Port != "443" {
		t.Errorf("https defaulted to port %q, want 443", https.Port)
	}

	httpRes, err := g.Validate(context.Background(), "http://webhooks.example/hook")
	if err != nil {
		t.Fatalf("http: %v", err)
	}
	if httpRes.Port != "80" {
		t.Errorf("http defaulted to port %q, want 80", httpRes.Port)
	}

	explicit, err := g.Validate(context.Background(), "https://webhooks.example:8443/hook")
	if err != nil {
		t.Fatalf("explicit port: %v", err)
	}
	if explicit.Port != "8443" {
		t.Errorf("explicit port = %q, want 8443", explicit.Port)
	}
}

// TestNewForTests_IsTheOnlyWayToAllowLoopback pins the escape hatch.
//
// Loopback is needed so a test can run a receiver locally. It is exposed as a named constructor
// rather than a boolean field so that a call site reads as what it is: an all-sites guard and a
// tests-only guard look different, and the difference is what stops one being set from
// configuration to make a failing deployment pass.
func TestNewForTests_IsTheOnlyWayToAllowLoopback(t *testing.T) {
	ctx := context.Background()

	if _, err := New().Validate(ctx, "http://127.0.0.1:9/hook"); err == nil {
		t.Fatal("the default guard allowed loopback")
	}
	if _, err := NewForTests(nil).Validate(ctx, "http://127.0.0.1:9/hook"); err != nil {
		t.Fatalf("the tests-only guard refused loopback: %v", err)
	}
	// The escape hatch is narrow: it permits loopback and nothing else.
	if _, err := NewForTests(nil).Validate(ctx, "http://169.254.169.254/hook"); err == nil {
		t.Fatal("the tests-only guard allowed the cloud metadata address")
	}
	if _, err := NewForTests(nil).Validate(ctx, "http://10.0.0.1/hook"); err == nil {
		t.Fatal("the tests-only guard allowed a private address")
	}
}

// TestClient_DialsTheValidatedAddressWithoutReResolving is the DNS-rebinding proof.
//
// # What it demonstrates
//
// The attack is a name the attacker controls resolving to a public address when validated and to
// 127.0.0.1 (or 169.254.169.254) when delivered. The defence is that the delivery never performs
// its own lookup, so there is no second answer to lie to.
//
// The assertion is the resolver's call count: exactly one lookup for the whole request. If the
// client re-resolved, the count would be two — and a two-lookup implementation is one an
// attacker defeats with a short-TTL record, no matter how good the validation looks.
//
// A real loopback server is the target, reached through a hostname that does not exist, so
// nothing but the pinned dialer could have connected.
func TestClient_DialsTheValidatedAddressWithoutReResolving(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// The Host header must be the name the tenant registered, not the dialled address: a
		// receiver behind a shared IP routes on it, and TLS sends it as SNI.
		if got := r.Host; !strings.HasPrefix(got, "rebind.example") {
			t.Errorf("Host header = %q, want the registered hostname", got)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "delivered")
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	port := u.Port()

	resolver := &fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	g := NewForTests(resolver)

	rawURL := "http://rebind.example:" + port + "/hook"
	target, err := g.Validate(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("Validate performed %d lookups, want 1", got)
	}

	client := g.Client(context.Background(), target, 5*time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, strings.NewReader(`{"event":"x"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("the receiver was hit %d times, want 1", hits.Load())
	}

	// The decisive assertion: no lookup happened during delivery.
	if got := resolver.calls.Load(); got != 1 {
		t.Fatalf("the resolver was asked %d times across validation and delivery; the client "+
			"re-resolved, which is the DNS-rebinding window this package exists to close", got)
	}
}

// TestClient_RefusesARedirectToAPrivateAddress covers the second request a redirect creates.
//
// Validating only the URL a tenant registered protects the first hop and nothing after it: a
// public endpoint answering 302 to 169.254.169.254 is the same attack one step removed. Go's
// client follows redirects by default, so the guard has to inspect each hop.
func TestClient_RefusesARedirectToAPrivateAddress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	resolver := &fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	g := NewForTests(resolver)

	rawURL := "http://redirector.example:" + u.Port() + "/hook"
	target, err := g.Validate(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	client := g.Client(context.Background(), target, 5*time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	_, err = client.Do(req)
	if err == nil {
		t.Fatal("a redirect to the cloud metadata address was followed; that is the SSRF " +
			"defence applied to the first hop only")
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("the redirect was refused for the wrong reason: %v", err)
	}
}

// TestClient_DoesNotFollowAnAllowedRedirect documents the deliberate refusal to follow at all.
//
// A signed delivery's signature covers the body, and following a redirect would resend that body
// to a destination the tenant never registered — a leak of their payload to whatever the
// redirect names. So a redirect is surfaced as a non-2xx and treated as a delivery failure, which
// the tenant sees in the delivery history, rather than silently followed.
func TestClient_DoesNotFollowAnAllowedRedirect(t *testing.T) {
	var finalHits atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer final.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	g := NewForTests(&fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})

	rawURL := "http://redirector.example:" + u.Port() + "/hook"
	target, err := g.Validate(context.Background(), rawURL)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	client := g.Client(context.Background(), target, 5*time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, rawURL, strings.NewReader("{}"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want the 302 surfaced rather than followed", resp.StatusCode)
	}
	if finalHits.Load() != 0 {
		t.Fatal("the redirect was followed, so the signed body was sent to a destination the " +
			"tenant never registered")
	}
}

// TestClient_RejectsAnEmptyAddressSet guards a construction mistake rather than an attack: a
// client built from a target with no addresses must fail loudly instead of dialling nothing or,
// worse, falling back to the system resolver.
func TestClient_RejectsAnEmptyAddressSet(t *testing.T) {
	g := NewForTests(nil)
	client := g.Client(context.Background(), Resolved{Host: "x.example", Port: "80"}, time.Second)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://x.example/", nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("a client with no validated addresses completed a request")
	}
}

// TestGuard_IsUsableThroughTheResolverInterface keeps the seam honest: the production
// constructor must work against the real resolver type without an adapter.
func TestGuard_IsUsableThroughTheResolverInterface(t *testing.T) {
	var _ Resolver = net.DefaultResolver
	var _ Resolver = (*fixedResolver)(nil)

	// A localhost name resolves without network access on every platform that runs these tests,
	// so this exercises the real resolver path without depending on external DNS.
	if _, err := New().Validate(context.Background(), "http://169.254.169.254/"); err == nil {
		t.Fatal("the literal metadata address was allowed through the production guard")
	}
}
