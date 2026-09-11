// Package clientip derives a caller's address in a way that can actually be believed.
//
// # Why this is not a one-liner
//
// The obvious implementation is to read X-Forwarded-For and trust it. That is a security
// hole, not a convenience: the header is client-controlled, so an attacker who is being
// rate-limited varies it per request and every request looks like a new caller. The limiter
// then reports that it is enforcing a limit while enforcing nothing.
//
// The same applies to chi's middleware.RealIP, which rewrites RemoteAddr from the header
// unconditionally. It is only correct when the service is unreachable except through a proxy
// that overwrites the header — an assumption that holds in some deployments and silently
// fails in others, which is the worst property a security assumption can have.
//
// # What this package does instead
//
// The header is honoured only when the immediate peer is a proxy the operator has declared
// trustworthy, and only for hops that are themselves trusted. Absent that configuration, the
// socket peer is the answer: a caller cannot forge a TCP connection's source address.
//
// The default is therefore "trust nothing", which fails closed. A deployment behind a proxy
// that wants per-client limits must say so, and saying so is a security decision someone
// makes on purpose rather than one that happens by default.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// Resolver derives client addresses, honouring forwarding headers only from trusted peers.
type Resolver struct {
	trusted []*net.IPNet
}

// New builds a resolver. An empty list trusts no forwarding header, which is the safe
// default: every request is attributed to its socket peer.
func New(trustedProxyCIDRs []string) (*Resolver, error) {
	r := &Resolver{}
	for _, cidr := range trustedProxyCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// A bare address is a common mistake and an obvious intent, so it is accepted
			// and read as a single-host prefix rather than rejected. Guessing wrong here
			// would mean a misconfigured proxy range silently stops being trusted, which
			// degrades to the safe default but surprises the operator.
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, &net.ParseError{Type: "trusted proxy CIDR", Text: cidr}
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		r.trusted = append(r.trusted, network)
	}
	return r, nil
}

// Trusts reports whether any peer is trusted. Callers use it to describe the deployment's
// behaviour without re-parsing configuration.
func (r *Resolver) Trusts() bool { return len(r.trusted) > 0 }

// ClientIP returns the caller's address.
//
// When the socket peer is not a trusted proxy, the peer is returned and the forwarding
// header is ignored entirely — including when it is present, which is the case that matters.
func (r *Resolver) ClientIP(req *http.Request) string {
	peer := hostOnly(req.RemoteAddr)
	if !r.isTrusted(peer) {
		return peer
	}

	// The peer is a trusted proxy, so walk the chain right to left: each hop is either
	// another trusted proxy or the client itself, and the first untrusted address is the
	// closest thing to an attributable origin.
	//
	// Walking from the left instead would return the leftmost value, which the original
	// client supplied and can therefore be anything — the classic spoofing bug that makes a
	// header-aware limiter weaker than an IP-only one.
	for _, raw := range xffChain(req) {
		ip, ok := parseForwardedAddress(raw)
		if !ok {
			// An entry that cannot be read as an address means the chain stops being
			// trustworthy at this hop. Falling back to the peer over-attributes every client
			// behind this proxy to one bucket, which is a degradation; adopting an
			// unparseable value as a bucket key would let a caller choose its own bucket by
			// varying the garbage, which is a bypass. Degrade, never bypass.
			return peer
		}
		if !r.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

// isTrusted reports whether ip falls inside a declared proxy range.
func (r *Resolver) isTrusted(ip string) bool {
	if ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range r.trusted {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

// xffChain returns the forwarding entries nearest-to-farthest, still unparsed.
//
// Splitting and parsing are deliberately separate, with parsing in exactly one place
// (parseForwardedAddress). Two parsers that disagree is how a header-keyed limiter ends up
// with a bucket an attacker controls: one reads the value, the other validates a different
// substring, and only the difference between them matters.
func xffChain(req *http.Request) []string {
	var chain []string
	for _, header := range []string{"X-Forwarded-For", "Forwarded"} {
		for _, value := range req.Header.Values(header) {
			for _, part := range strings.Split(value, ",") {
				if part = strings.TrimSpace(part); part != "" {
					chain = append(chain, part)
				}
			}
		}
	}

	// Reverse so index 0 is the hop nearest us, which is the order the caller wants.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// parseForwardedAddress reads one forwarding entry as a bare IP, reporting whether it was
// readable at all.
//
// Both header formats land here, which is the reason this is a function rather than inline
// trimming. X-Forwarded-For carries a bare address; Forwarded (RFC 7239) carries
// for=<addr> with optional semicolon-separated parameters such as ";proto=https", and the
// address may be quoted. An earlier version cut at "for=" but left ";proto=https" attached,
// so the "address" returned was 203.0.113.5;proto=https — not an IP, and therefore a string a
// caller could vary to change their own bucket.
//
// A value that does not parse as an address is reported unreadable rather than returned
// as-is: it has not been shown to be an address, so it must not become a bucket key.
func parseForwardedAddress(entry string) (string, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", false
	}

	// Semicolons introduce Forwarded parameters. Truncating first means the address is taken
	// from the front of the entry in both formats, and a parameter can never be mistaken for
	// part of it.
	if i := strings.IndexByte(entry, ';'); i >= 0 {
		entry = entry[:i]
	}
	if _, after, found := strings.Cut(entry, "for="); found {
		entry = after
	}

	host := hostOnly(strings.Trim(strings.TrimSpace(entry), `"`))
	if net.ParseIP(host) == nil {
		return "", false
	}
	return host, true
}

// hostOnly strips a port from an address, and brackets from an IPv6 literal.
//
// net.SplitHostPort is the correct tool but errors on a bare address, so both forms are
// handled. A port in a rate-limit key would otherwise split one caller into many — an
// attacker's easiest bypass, since source ports are free.
func hostOnly(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// A bare address, or an IPv6 literal without a port. Brackets only appear in the
	// bracketed form that SplitHostPort already handled.
	return strings.Trim(addr, "[]")
}
