# ADR-005: Rate limiting is a Redis Lua sliding window, keyed per caller, and fails open

Status: accepted

## Context

Two different problems need bounding, and conflating them produces a limit that is wrong for
both:

- **Abuse.** Login and registration are reachable without credentials. Credential stuffing
  submits a password list; automated signup creates accounts in bulk. There is no credential
  to key on, because the volume *is* the attack, so the only available signal is how many
  requests arrive from one address.
- **Fairness.** Authenticated traffic needs a runaway-client guard: one tenant with a retry
  loop should not be able to consume capacity that the others need. This is not abuse; it is
  a noisy neighbour, and the limit should be generous enough that a legitimate batch job is
  never throttled.

Redis is already in the stack for caching. Postgres could enforce both with a counter table,
and that was considered.

## Decision

One Lua script per check, evaluated by Redis, over a sorted set scored by arrival time.

- Keyed on the client address for unauthenticated endpoints, and on the tenant for
  authenticated ones.
- Policy per endpoint, not per route group: login is 10/min, registration 5/h, refresh
  20/min, authenticated traffic 600/min.
- Fail **open** when Redis is unreachable; fail **loudly** at startup if the script itself is
  broken.
- Forwarding headers are believed only from operator-declared proxy ranges.

## Alternatives rejected

**Fixed-window counter (INCR + EXPIRE).** Rejected because it allows double the limit across
a boundary: 100 requests at 11:59:59 and 100 more at 12:00:00 are 200 requests in one second
against a limit of 100 per minute. The window has to slide for the limit to mean what it says.
A sliding window costs memory proportional to the admitted rate rather than one integer per
key, which is the trade this makes deliberately — the members are bounded by the limit and
expire with the key.

**Postgres-backed counters.** Rejected: it puts the limiter on the same resource it is
protecting. A credential-stuffing flood would then consume database connections and write
load, so the protection would compete with the traffic it exists to bound. It also adds a
round trip to every request on the hot path, for a check that must be cheap by definition.

**Application-side read-then-write.** Rejected outright: two concurrent requests can read the
same count and both proceed, exceeding the limit by exactly the concurrency. The read and the
write have to be one atomic operation, which is what the script provides.

**Keying login by the submitted email.** Rejected: an attacker picks a new address per
attempt, so the limit would be trivially bypassed by the very party it exists to stop. The
source address is the one thing the caller cannot choose freely.

**A group-wide limit on `/v1/auth`.** Rejected: a group can only carry the loosest policy in
it, so a limit loose enough to allow ordinary logins leaves credential stuffing effectively
unbounded. The tight limit has to sit on the endpoint that needs it.

**Trusting `X-Forwarded-For` (and chi's `middleware.RealIP`).** Rejected as a security hole
rather than a convenience. The header is client-controlled, so an attacker being
rate-limited varies it per request and every request looks like a new caller — a limiter that
reports it is enforcing a limit while enforcing nothing. `middleware.RealIP` rewrites
`RemoteAddr` from the header unconditionally, which is correct only when the service is
unreachable except through a proxy that overwrites it; that assumption holds in some
deployments and fails silently in others.

## Consequences

**The clock is Redis's, not the application's.** "Now" is read inside the script from Redis
`TIME`. Several instances with skewed clocks would otherwise disagree about where the window
starts, and since each instance holds its own view, a limit of N would be enforced N times
over — once per instance. This is the same decision as the idempotency store's, for the same
reason: there is one clock per system and it belongs to the shared component.

**Fail-open, and the failure is visible.** When Redis is unreachable the request is allowed,
because the limit protects against abuse rather than correctness and refusing all traffic
would turn a cache outage into a total outage. What must not happen is a *silent* allow:
every degraded decision increments `ratelimit_degraded_total`, is logged (rate-limited to one
line a minute so an outage cannot flood the log — the metric carries the volume), and the
response carries `X-RateLimit-Degraded: true`. A client cannot tell an unenforced limit from
an enforced one otherwise. `Remaining` is deliberately not advertised in that state: room
that is not known to exist must not be claimed.

**A broken script fails startup; an unreachable Redis does not.** The two are opposite cases
and are handled oppositely. Redis answering with a server-side error means the script is
wrong — a bug in this package — and a service that starts with an unusable limiter enforces
nothing while reporting healthy, so validation treats it as fatal. The script is loaded once
at boot to make that check possible. Because the shipped script is correct, no test could
reach that branch; `validateScript` takes the script as a parameter so a deliberately broken
one can be loaded in a test, rather than leaving the branch to a comment.

**Forwarding headers are trusted only from declared ranges, and the default is to trust
nothing.** An empty `TRUSTED_PROXY_CIDRS` attributes every request to its socket address,
which a caller cannot forge. Both ways of getting this wrong are silent, which is why the
default is the safe one and setting it is an operator's explicit assertion:

- Unset behind a proxy: every client shares one bucket and throttles each other.
- Set when the peer is not a proxy: a limiter anyone bypasses with one extra header.

Within a trusted chain the header is walked **right to left**, because `X-Forwarded-For` is
appended to by each proxy: the leftmost entry is whatever the original client supplied and is
therefore attacker-chosen. An entry that does not parse as an address is never adopted as a
bucket key — it stops the walk and the peer is used, which over-attributes every client
behind that proxy to one bucket. That is a degradation; adopting the garbage would be a
bypass, and a degradation is preferred.

**Ports are stripped.** Source ports are free and change per connection, so a key containing
one would give a caller a fresh bucket per request while doing nothing at all.

**Transaction-shaped keys, not per-user ones, for authenticated traffic.** The limit bounds
what one tenant can cost the others, so the tenant is the unit that must be bounded. Keying
it per user would let a tenant multiply its share by adding members — precisely the
noisy-neighbour case the limit exists for. A machine credential is charged to its tenant like
any other caller, because the tenant is still what it consumes.

**`/v1/auth/logout` is deliberately unlimited.** It carries a token in the body and performs
one indexed delete, so its cost is bounded and it is not a guessing surface: a wrong token is
refused without revealing whether it ever existed. Limiting it would add a failure mode to
the one endpoint a client calls when it is already in trouble.

**The limiter runs before the handler, and after authentication where authentication
applies.** An IP-keyed check cannot depend on a parsed credential, so it necessarily precedes
it; a tenant-keyed check necessarily follows it, because the tenant is not known until the
membership gate has resolved it. Both orderings follow from what the key is, rather than from
preference.

## Not covered

- **Distributed coordination.** Each instance reads the shared counter, so the limit is global
  rather than per-instance, but nothing coordinates which instance serves which caller. That
  is the intended design and needs no further work.
- **Adaptive or cost-weighted limits.** Every request costs one unit. Weighting by
  expensive-versus-cheap endpoints would require knowing the cost before the handler runs.
- **`POST /v1/tenants/{tenantID}/members`** carries the authenticated policy like its
  siblings; there is nothing to key it on beyond the tenant, so it needs no policy of its own.
