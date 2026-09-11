# ADR-012: Short-lived access tokens and refresh-family revocation, no denylist

Status: accepted

## Context

A signature cannot be un-signed. Once an access token is minted, anything holding the verification
key accepts it until it expires — so a service has exactly two levers over a leaked credential:
shorten the window, or keep server-side state recording which tokens are still valid.

## Decision

- Access tokens are short-lived (`DefaultAccessTTL` = 10 minutes) and assert **identity only** —
  who the caller is, never what they may do.
- Authorization is resolved per request from the database, so a permission or membership change
  takes effect on the next request without invalidating anything.
- Refresh tokens are opaque, stored hashed, and grouped into a **family** per login. Presenting a
  consumed refresh token is treated as theft: the whole family is revoked, and the event is
  recorded as an audit entry and a metric.
- **No access-token denylist and no introspection endpoint.**

## Why no denylist

A denylist is a lookup on every authenticated request. The request path already queries Postgres for
the membership gate; adding a second remote dependency in front of it turns a rate-limiting-tier
failure (Redis) into an authentication outage — the exact failure mode the Redis usage was designed
to avoid, since the rate limiter fails open (ADR-005) and a denylist could not.

More fundamentally, the denylist solves a problem this design does not have. It is needed when the
access token is the unit of revocation. Here the token grants nothing that can be revoked: it
asserts identity, and every authorization decision re-reads current state. A stolen token therefore
buys its holder identity for at most one TTL — not standing access to any resource.

## Why refresh-family revocation instead

Refresh tokens live for days, so expiry does not bound them meaningfully. Rotation makes theft
*detectable*: if a stolen refresh token is presented while the legitimate client also holds one, one
of the two presentations is necessarily a replay of a consumed token. Both holders lose the session
— the correct outcome for a suspected compromise, and the only mechanism here that converts a silent
theft into a visible event.

A grace window (`DefaultReuseGrace`) lets a client retry a refresh whose response was lost without
being treated as a thief. It is bounded, not a general allowance: outside it, a replay revokes the
family. The tests configure it to zero to assert the strict-rotation semantic directly.

## Consequences

- Revocation of a fully compromised session lags by up to one access-token TTL. Accepted and stated:
  the alternative is a per-request remote lookup, and the lag bounds identity only, because the
  token carries no permission.
- The refresh path must be transactional. Consumption and the family decision happen in one
  guarded transaction, because a replay check racing a legitimate consume is precisely the
  interleaving that must not mint two sessions.
- **Any future change that adds an authorization claim to the access token invalidates this ADR.**
  The denylist is affordable only while the token grants nothing.
