// Package ssrf guards outbound webhook delivery against server-side request forgery.
//
// # Why this is not a hostname check
//
// A webhook URL is supplied by the tenant, so it is attacker-controlled by construction. The
// obvious defence — parse the URL, reject "localhost", 127.0.0.1, and 169.254.169.254 — is
// defeated by a DNS name the attacker controls:
//
//	their-domain.example  A  93.184.216.34     (looks public, passes the check)
//	                       A  169.254.169.254  (what the client resolves at delivery time)
//
// The check on the name and the resolution at delivery are two separate lookups, so an
// attacker who controls the zone can answer them differently. That is a time-of-check to
// time-of-use bug, and it is why "the URL looked fine when we validated it" is not a defence.
//
// # What this does instead
//
// Resolve once, here. Reject if *any* returned address is not public. Then hand the HTTP
// client a dialer that connects to one of the already-validated IPs directly, with the original
// Host header preserved. The client never performs its own lookup, so there is no second answer
// to be lied to.
//
// Checking every address rather than the first matters: a name with one public A record and one
// private is a working bypass if only the first is examined.
//
// # Redirects
//
// A redirect is a second request to a URL this package has never seen, and Go's client follows
// them by default — so a public endpoint can bounce the delivery to 169.254.169.254, and the
// guard would have been applied only to the first hop. Redirects are therefore re-validated
// per hop, with the same rules, by the CheckRedirect hook in Client.
//
// # What it does not claim
//
// This is an outbound-request guard, not a network policy. A deployment that can also restrict
// egress at the firewall should — defence in depth is the right posture for SSRF, and this
// package is the layer that knows the tenant supplied the URL.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Errors, so a caller can distinguish "the URL is not allowed" from "the URL is broken".
// The distinction reaches the client: the first is a 400 at registration time, the second is
// a delivery failure the operator sees.
var (
	// ErrBlocked is returned for an address that is not publicly routable.
	ErrBlocked = errors.New("ssrf: the address is not publicly routable")

	// ErrScheme is returned for a scheme this service will not call.
	ErrScheme = errors.New("ssrf: only http and https are permitted")

	// ErrNoAddresses is returned when a hostname resolves to nothing.
	ErrNoAddresses = errors.New("ssrf: the host did not resolve")
)

// Resolver resolves a hostname, and is an interface so tests can supply answers without DNS.
//
// The seam exists because the interesting cases — a name with a public and a private address, a
// name that resolves differently on the second call — cannot be produced against real DNS.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Guard validates outbound targets and builds clients that cannot be redirected into a private
// network.
type Guard struct {
	resolver Resolver

	// allowLoopback exists for tests and local development, and is deliberately not reachable
	// from configuration: a deployment that could set it would be one where an operator turns
	// SSRF protection off to make something work, and then forgets. See the note on Options.
	allowLoopback bool
}

// New builds a guard using the system resolver.
func New() *Guard { return &Guard{resolver: net.DefaultResolver} }

// NewWithResolver builds a guard with an explicit resolver, for tests.
func NewWithResolver(r Resolver) *Guard { return &Guard{resolver: r} }

// NewForTests permits loopback, so a test can stand up a local receiver.
//
// It is named for its purpose rather than taking a boolean, because "guard with a flag" at a
// call site is indistinguishable from "guard" in review, and the flag would be set from
// configuration by whoever was trying to make a failing deployment pass.
func NewForTests(r Resolver) *Guard { return &Guard{resolver: r, allowLoopback: true} }

// Resolved is a validated target: the addresses that may be connected to.
type Resolved struct {
	// Host is the hostname from the URL, used for the Host header and for TLS SNI so
	// certificate validation still checks the name the tenant registered.
	Host string

	// Addrs are the validated addresses, in resolution order.
	Addrs []netip.Addr

	// Port is the effective port, defaulted from the scheme.
	Port string
}

// nonPublicPrefixes are ranges that are not publicly routable but which the netip helpers do
// not classify as private, link-local, or loopback.
//
// This list exists because IsPrivate and IsGlobalUnicast together are not sufficient:
//
//   - IsPrivate() covers RFC 1918 and fc00::/7 only.
//   - IsGlobalUnicast() returns *true* for 100.64.0.0/10 and 240.0.0.0/4 — the comment in the
//     standard library says so explicitly, because "global unicast" is an address-type
//     classification, not a reachability claim.
//
// So a request to 100.100.100.100 (carrier-grade NAT, which reaches carrier interior
// infrastructure) or 240.0.0.1 would pass every check above and be dialled. Each entry below is
// a range where a delivery is either impossible or is an SSRF attempt.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737 TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737 TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737 TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112 reserved, includes the broadcast address

	netip.MustParsePrefix("64:ff9b::/96"),   // RFC 6052 NAT64 — embeds an IPv4 destination
	netip.MustParsePrefix("64:ff9b:1::/48"), // RFC 8215 local-use NAT64
	netip.MustParsePrefix("100::/64"),       // RFC 6666 discard-only
	netip.MustParsePrefix("2001:db8::/32"),  // RFC 3849 documentation
}

// Validate resolves a URL and checks every address it returns.
//
// It returns the addresses so the caller can connect to one directly; the caller must not
// re-resolve, which is the whole point. See Client.
func (g *Guard) Validate(ctx context.Context, rawURL string) (Resolved, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Resolved{}, fmt.Errorf("ssrf: parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Resolved{}, fmt.Errorf("%w (got %q)", ErrScheme, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Resolved{}, errors.New("ssrf: the url has no host")
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// A literal IP needs no lookup but does need the same validation: https://169.254.169.254/
	// is the classic cloud-metadata probe and it never touches DNS.
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := g.checkAddr(addr); err != nil {
			return Resolved{}, err
		}
		return Resolved{Host: host, Addrs: []netip.Addr{addr}, Port: port}, nil
	}

	addrs, err := g.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return Resolved{}, fmt.Errorf("%w (%s: %v)", ErrNoAddresses, host, err)
	}
	if len(addrs) == 0 {
		return Resolved{}, fmt.Errorf("%w (%s)", ErrNoAddresses, host)
	}

	// Every address, not the first. A name with one public A record and one private is a
	// working bypass if only the first is examined, and the client picks for itself.
	for _, addr := range addrs {
		if err := g.checkAddr(addr); err != nil {
			return Resolved{}, fmt.Errorf("%s resolves to %s: %w", host, addr, err)
		}
	}
	return Resolved{Host: host, Addrs: addrs, Port: port}, nil
}

// checkAddr rejects any address that is not globally routable.
//
// The categories are named in the error so an operator reading a refusal knows which rule fired
// rather than only that one did.
func (g *Guard) checkAddr(addr netip.Addr) error {
	// Unmap 4-in-6 so ::ffff:127.0.0.1 is judged as 127.0.0.1 rather than slipping through the
	// IPv6 checks. This is a real bypass if omitted: the address is loopback but its family is
	// IPv6, and every v6-specific check passes it.
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback():
		if g.allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: %s is loopback", ErrBlocked, addr)
	case addr.IsPrivate():
		return fmt.Errorf("%w: %s is private", ErrBlocked, addr)
	case addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast():
		// 169.254.0.0/16 and fe80::/10. The metadata services live in the v4 range.
		return fmt.Errorf("%w: %s is link-local (cloud metadata lives here)", ErrBlocked, addr)
	case addr.IsUnspecified():
		return fmt.Errorf("%w: %s is the unspecified address", ErrBlocked, addr)
	case addr.IsMulticast():
		return fmt.Errorf("%w: %s is multicast", ErrBlocked, addr)
	case !addr.IsGlobalUnicast():
		return fmt.Errorf("%w: %s is not globally routable", ErrBlocked, addr)
	}

	// IPv6 transition ranges route to an embedded v4 address and are therefore a way back into
	// private space: 2002::/16 (6to4) and 2001::/32 (Teredo) both carry one.
	if addr.Is6() {
		if addr.Is4In6() {
			return fmt.Errorf("%w: %s is an IPv4 address in IPv6 form", ErrBlocked, addr)
		}
		if isTransitionRange(addr) {
			return fmt.Errorf("%w: %s is in an IPv6 transition range, which can embed a private address",
				ErrBlocked, addr)
		}
	}

	// The ranges the helpers above miss. Checked last so the more specific messages win, which
	// is what an operator reading a refusal benefits from.
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: %s is in %s, which is not publicly routable",
				ErrBlocked, addr, prefix)
		}
	}
	return nil
}

// isTransitionRange reports whether addr is in 6to4 or Teredo.
//
// Both embed an IPv4 address, so a request to one is resolved by the receiver into a request to
// whatever v4 address it carries — including 169.254.169.254.
func isTransitionRange(addr netip.Addr) bool {
	b := addr.As16()
	// 2002::/16
	if b[0] == 0x20 && b[1] == 0x02 {
		return true
	}
	// 2001:0000::/32, checked on the first four bytes.
	return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00
}

// Client builds an HTTP client that can only reach the addresses Validate approved.
//
// # Why the dialer ignores the address it is given
//
// http.Transport resolves the hostname itself before dialing, so a client built on the default
// transport would perform a *second* lookup — the one an attacker with a short-TTL record
// answers differently. Pinning the dialer to the validated addresses removes that lookup
// entirely: whichever address the transport asks for, the connection goes to one this package
// already checked.
//
// The Host header and the TLS server name are still the original hostname, so certificate
// validation is unchanged and a receiver behind a shared IP still routes correctly.
//
// # Redirects
//
// Each hop is re-validated. Following a redirect without checking it is the same TOCTOU as
// re-resolving: the first hop is public, the Location points at 169.254.169.254, and the guard
// never saw the second URL.
func (g *Guard) Client(ctx context.Context, target Resolved, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

	// Round-robin across the validated addresses so one dead address does not fail every
	// delivery, while never leaving the validated set.
	var next int

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if len(target.Addrs) == 0 {
				return nil, errors.New("ssrf: no validated address to dial")
			}
			chosen := target.Addrs[next%len(target.Addrs)]
			next++
			return dialer.DialContext(ctx, network, net.JoinHostPort(chosen.String(), target.Port))
		},
		// A redirect to another host must not carry our headers — and for a signed webhook the
		// signature covers the body, not the destination, so sending it onward is a leak of the
		// tenant's payload to whatever the redirect names.
		DisableKeepAlives:   true,
		MaxIdleConnsPerHost: 1,
		ForceAttemptHTTP2:   false,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return errors.New("ssrf: too many redirects")
		}
		// Re-validate the destination. The body cannot be resent safely anyway once it has been
		// read, and a signed delivery whose signature covers the original URL must not silently
		// follow a redirect — so this is a refusal rather than a follow.
		if _, err := g.Validate(req.Context(), req.URL.String()); err != nil {
			return fmt.Errorf("ssrf: redirect target refused: %w", err)
		}
		return http.ErrUseLastResponse
	}
	return client
}

// ValidateEndpointURL is the registration-time check.
//
// It resolves the URL as it stands, which means a name that is unresolvable *at registration*
// is refused — a real limitation worth stating: a tenant whose DNS is not yet live cannot
// register a webhook. The alternative is accepting an unvalidated URL and checking only at
// delivery, which moves the failure to a place the tenant cannot see it.
//
// Delivery re-validates regardless, because a name can be repointed after registration. So this
// is an early, helpful check and never the only one.
func (g *Guard) ValidateEndpointURL(rawURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := g.Validate(ctx, rawURL); err != nil {
		return err
	}
	return nil
}

// SchemeOf reports the lower-cased scheme, for normalising a stored URL.
func SchemeOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Scheme)
}
