# ADR-013: Webhook delivery — SSRF guard, timestamped signatures, traceparent

Status: accepted

## Context

Webhook delivery is the one feature where a tenant supplies a URL that this service then makes an
HTTP request to. That single sentence is the source of every decision below: the destination is
attacker-controlled, the request originates from inside the network boundary, and the body carries
another tenant's billing data.

Three separate problems, which are easy to conflate because they share a code path:

1. **The destination is hostile input.** A registered URL can name `169.254.169.254`, an RFC1918
   address, or a public hostname that resolves to one.
2. **The receiver must authenticate the sender.** An endpoint that trusts a POST to `/hooks` is an
   endpoint anyone can post to.
3. **A delivery must be attributable to the request that caused it.** Without a correlation
   identifier, "why did this invoice appear in my system twice" is unanswerable.

## Decision

### 1. Resolve and validate every address, on every attempt

`ssrf.Guard.Validate` resolves the hostname and checks **every** returned address, then returns the
validated set. `Guard.Client` dials only addresses from that set, so the request cannot reach an
address the check never saw.

Refused: loopback, RFC1918, link-local (`169.254.0.0/16` holds the cloud metadata endpoints),
unspecified, multicast, anything not globally unicast, IPv4-mapped IPv6 (`::ffff:127.0.0.1`), the
6to4 and Teredo transition ranges, and the ranges `netip` classifies as global unicast but which are
not publicly routable — CGNAT `100.64.0.0/10`, `192.0.0.0/24`, benchmarking `198.18.0.0/15`,
reserved `240.0.0.0/4`, and NAT64 `64:ff9b::/96`.

**Redirects are refused, not followed.** `CheckRedirect` re-validates the target and then returns
`http.ErrUseLastResponse`, so a 302 is reported as the failed delivery it is. Following one would
resend a validly signed payload to a host the tenant never registered — the signature covers the
body and the timestamp, not the destination.

**Validation happens per attempt, not only at registration.** A check performed once is a
time-of-check to time-of-use bug with a slow clock: register a public hostname, pass the check,
repoint DNS at the metadata service. `Deliverer.Deliver` re-resolves on every attempt, which is not
extra work because the guard also produces the addresses the client dials.

### 2. Sign the body *and* the timestamp

The header is `t=<unix seconds>,v1=<hex hmac-sha256>`, and the signed message is `<t>.<body>`.

Signing the body alone proves authorship but not freshness: a captured delivery verifies forever and
can be replayed without limit. Putting the timestamp inside the MAC means a receiver enforces a
tolerance window on a value it can trust, which is what makes replay refusal possible.
`SignatureTolerance` is 5 minutes.

The timestamp is parsed as an integer, not with `time.ParseDuration`. The first implementation
appended `"s"` and called the duration parser, which accepts `"1h30m"` — a malformed timestamp that
silently parsed as valid. On a path whose failure mode is a forged delivery, accepting more than
intended is the wrong direction to be wrong in.

### 3. Carry the caller's trace context in the outbox row

`traceparent` is stored with the delivery, not read at send time. A retry reuses the original value,
which is correct: it is the same logical event, caused by the same request. A receiver can therefore
join its own traces to the request that caused the event, and the correlation survives the worker
restart that a re-read would lose.

## Alternatives rejected

- **Validate at registration only.** Cheaper, and wrong for the DNS-rebinding reason above.
- **Allow redirects but re-validate.** The body cannot be resent safely once read, and a signed
  payload must not follow a URL the tenant did not register. Refusal is the honest outcome.
- **Sign the body only (no timestamp).** Cannot refuse a replay.
- **Full body jitter / no jitter in retries.** Full jitter makes the documented schedule
  meaningless; no jitter makes a briefly-failing receiver's retries arrive simultaneously from every
  worker. The retry delay is 50–100% of the nominal value.
- **A denylist of known-bad hosts.** Enumerating bad destinations loses to an attacker who
  registers a new name; the check is on the resolved address, which is what the socket actually
  connects to.

## Consequences

- **A refused target is a failed delivery, not a dropped one.** `Deliver` returns a `Result` with an
  error wrapping `ssrf.ErrBlocked`, so the refusal is recorded, retried on the normal schedule, and
  reaches the DLQ — where an operator can see it. A silently dropped delivery would mean a tenant
  whose URL is blocked never learns their integration cannot work.
- **`ssrf.New()` permits no loopback exception, and there is no flag to add one.**
  `ssrf.NewForTests` exists as a separate named constructor for the test suite, so the difference is
  visible at the call site rather than buried in a boolean, and the permissive constructor is not
  reachable from either binary.
- **A 3xx is a failure in the delivery history.** An operator sees `last_status: 302` and a note
  that redirects are refused, rather than a delivery marked complete that the receiver never
  processed.
