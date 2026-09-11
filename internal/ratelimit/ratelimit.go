// Package ratelimit bounds how many requests a caller may make in a window.
//
// # Where the limit sits, and why it is the boundary that matters
//
// The limit is enforced at the HTTP boundary, before the handler, so a throttled request
// costs one Redis round trip rather than a database query. That matters most on the
// endpoints that have no authentication: a credential-stuffing run against /v1/auth/login
// cannot be stopped by requiring a credential, so the volume itself is the only signal
// available, and rejecting it cheaply is the difference between an outage and an
// inconvenience.
//
// # Fail open, and why that is a decision rather than an oversight
//
// When Redis is unreachable the limiter allows the request. The alternative — refusing every
// request because the thing that counts them is down — converts a cache outage into a total
// outage, which is strictly worse: the limit protects against abuse, not against
// correctness, and the service is still correct without it. Every fail-open decision is
// counted and logged, because a limiter that is silently not limiting is indistinguishable
// from one that is working.
//
// # The one failure that must not fail open silently
//
// A request that Redis *answers* with a server-side error means Redis is reachable and the
// script is wrong — a compile error, a bad command, a type error. That is a bug in this
// package, not an outage, and it would disable the limit while the process looked healthy.
// Script validity is therefore checked once at construction via SCRIPT LOAD, where a broken
// script is a startup failure. At request time the two are indistinguishable without
// inspecting the error type, so the check is moved to a moment when the process can refuse
// to start.
package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
)

// Policy is a limit: at most Limit requests in any Window.
//
// The Name identifies the policy in the Redis key, in metrics, and in logs, so a throttled
// caller and an operator are talking about the same thing.
type Policy struct {
	Name   string
	Limit  int
	Window time.Duration
}

// Decision is the outcome of one check.
type Decision struct {
	Allowed bool
	Limit   int

	// Remaining is the number of further requests permitted in this window.
	Remaining int

	// ResetAfter is how long until a slot frees.
	ResetAfter time.Duration

	// Degraded reports that the decision was made without Redis and is therefore
	// "allowed because we cannot tell", not "allowed because the caller is within the
	// limit". Callers surface it and operators chart it; a degraded allow is not the same
	// claim as a real one.
	Degraded bool
}

// slidingWindow is the limit as a single atomic Redis operation.
//
// # Why a Lua script rather than INCR plus EXPIRE
//
// INCR-then-EXPIRE on a fixed bucket allows twice the limit across a boundary: 100 requests
// at 11:59:59 and 100 more at 12:00:00 are 200 requests in one second against a limit of 100
// per minute. Sliding the window removes that, and doing it in one script keeps the read and
// the write atomic — an application-side read-then-write has a race in which two concurrent
// requests both see the same count and both proceed, exceeding the limit by exactly the
// concurrency.
//
// # Why the clock is Redis's
//
// "Now" is read inside the script from Redis TIME. Several app instances with skewed clocks
// would otherwise disagree about where the window starts, and since each instance holds its
// own view, a limit of N would be enforced N times over — once per instance. The same
// reasoning put the idempotency store on the database's clock; there is one clock per system
// and it belongs to the shared component.
//
// # Why a sorted set
//
// Each admitted request is a member scored by its arrival in milliseconds, so the window is
// an exact range query rather than an approximation. The cost is memory proportional to the
// admitted rate — one small member per request, bounded by the limit and expired with the
// key — which is why the comment on Policy notes the trade-off below.
var slidingWindow = redis.NewScript(`
local key      = KEYS[1]
local limit    = tonumber(ARGV[1])
local windowms = tonumber(ARGV[2])
local member   = ARGV[3]

local t   = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)

-- Evict everything that has left the window. This is what turns "at most N per aligned
-- bucket" into "at most N in any window ending now".
redis.call('ZREMRANGEBYSCORE', key, 0, now - windowms)

local count = redis.call('ZCARD', key)

-- A slot frees when the oldest surviving entry leaves the window.
local reset = windowms
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if oldest[2] then
  reset = windowms - (now - tonumber(oldest[2]))
  if reset < 0 then reset = 0 end
end

if count < limit then
  redis.call('ZADD', key, now, member)
  -- The key must not outlive its window: without an expiry, one key per caller
  -- accumulates until Redis runs out of memory.
  redis.call('PEXPIRE', key, windowms)
  return {1, limit - count - 1, reset}
end

return {0, 0, reset}
`)

// Script is exposed for the startup validation in cmd/api, which loads it once so a broken
// script is a failed boot rather than a limiter that silently allows everything.
var Script = slidingWindow

// Limiter enforces one Policy.
type Limiter struct {
	rdb    redis.Cmdable
	policy Policy
	log    *slog.Logger

	// lastComplaint guards the degraded log line so an outage does not produce one line per
	// request. During a Redis outage that is the difference between a log and a flood, and a
	// flood is how the line that matters gets missed.
	mu            sync.Mutex
	lastComplaint time.Time
}

// New builds a limiter for one policy.
func New(rdb redis.Cmdable, policy Policy, log *slog.Logger) *Limiter {
	if log == nil {
		log = slog.Default()
	}
	return &Limiter{rdb: rdb, policy: policy, log: log}
}

// Policy returns the policy being enforced, for reporting.
func (l *Limiter) Policy() Policy { return l.policy }

// Validate loads the script into Redis, returning an error only for a *server-side* failure.
//
// This is the distinction the package comment describes, made concrete. If Redis is
// unreachable, that is the expected degraded condition and validation reports no error —
// the service is meant to run without Redis. If Redis answers with an error, the script
// itself is wrong, and starting a service whose rate limiter cannot run would mean enforcing
// no limit at all while reporting healthy.
func (l *Limiter) Validate(ctx context.Context) error {
	return validateScript(ctx, l.rdb, slidingWindow, l.policy.Name, l.log)
}

// validateScript is Validate's body, taking the script as a parameter so it can be tested
// with a deliberately broken one.
//
// Without that seam the "a broken script fails startup" claim would be a comment nobody can
// falsify: the real script is correct, so no test could ever reach the error branch. The
// branch that matters is the one that only fires when something is wrong, which is exactly
// the branch that goes unexercised.
func validateScript(ctx context.Context, rdb redis.Cmdable, script *redis.Script, policy string, log *slog.Logger) error {
	err := script.Load(ctx, rdb).Err()
	if err == nil {
		return nil
	}

	var serverErr redis.Error
	if errors.As(err, &serverErr) {
		return err
	}

	if log != nil {
		log.Warn("rate limiter script could not be preloaded; running degraded until redis is reachable",
			"err", err, "policy", policy)
	}
	return nil
}

// Allow reports whether one more request is permitted for bucket.
//
// It never returns an error: an unanswerable question is answered "allow", and the caller
// learns that from Decision.Degraded rather than from an error it would have to handle on
// every request.
func (l *Limiter) Allow(ctx context.Context, bucket string) Decision {
	key := l.keyFor(bucket)
	member := uuid.Must(uuid.NewV7()).String()

	res, err := slidingWindow.Run(ctx, l.rdb, []string{key},
		l.policy.Limit, l.policy.Window.Milliseconds(), member).Slice()
	if err != nil {
		return l.degrade(err, bucket)
	}

	allowed, remaining, resetMillis, ok := parseDecision(res)
	if !ok {
		// A reply this package cannot read means the script and the parser disagree, which
		// is a bug rather than an outage. Treated as degraded so traffic keeps flowing, and
		// logged loudly so it is found.
		return l.degrade(errors.New("rate limiter reply did not match the expected shape"), bucket)
	}

	d := Decision{
		Allowed:    allowed,
		Limit:      l.policy.Limit,
		Remaining:  int(remaining),
		ResetAfter: time.Duration(resetMillis) * time.Millisecond,
	}
	if !d.Allowed {
		metrics.RateLimitLimited.WithLabelValues(l.policy.Name).Inc()
	}
	return d
}

// keyFor namespaces the bucket so two policies cannot share a counter, and so a bucket value
// containing a colon cannot be read as another policy's key.
//
// The braces are redis cluster hash tags: everything inside them is the hash slot, so one
// policy's keys stay together if this is ever pointed at a cluster. The script touches a
// single key so this changes nothing today — it is here so that adding a second key later
// does not silently need a topology change.
func (l *Limiter) keyFor(bucket string) string {
	return "rl:{" + l.policy.Name + "}:" + bucket
}

// degrade records a fail-open decision.
func (l *Limiter) degrade(err error, bucket string) Decision {
	metrics.RateLimitDegraded.Inc()

	l.mu.Lock()
	quiet := time.Since(l.lastComplaint) < degradedLogInterval
	if !quiet {
		l.lastComplaint = time.Now()
	}
	l.mu.Unlock()

	if !quiet {
		l.log.Warn("rate limit check failed; allowing request (fail-open) — this service is "+
			"currently not limiting anything in this policy",
			"err", err, "policy", l.policy.Name, "bucket", bucket)
	}

	return Decision{
		Allowed: true,
		Limit:   l.policy.Limit,
		// Remaining and ResetAfter are unknown rather than reported as the full limit: a
		// degraded allow that advertised room would let a client believe it is being
		// limited when it is not.
		ResetAfter: l.policy.Window,
		Degraded:   true,
	}
}

// degradedLogInterval bounds how often a sustained outage may write to the log.
const degradedLogInterval = time.Minute

// parseDecision reads the script's {allowed, remaining, reset} reply.
func parseDecision(res []any) (allowed bool, remaining, resetMillis int64, ok bool) {
	if len(res) != 3 {
		return false, 0, 0, false
	}
	flag, ok1 := res[0].(int64)
	rem, ok2 := res[1].(int64)
	reset, ok3 := res[2].(int64)
	if !ok1 || !ok2 || !ok3 {
		return false, 0, 0, false
	}
	return flag == 1, rem, reset, true
}
