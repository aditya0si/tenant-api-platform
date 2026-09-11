package ratelimit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// testPolicy builds a policy whose name is unique per test.
//
// The bucket key includes the policy name, so two tests sharing a name would share a counter
// against the same Redis. That failure mode is invisible — both tests pass or fail depending
// on execution order — and it is the same class as the slug collision that made every
// registration after the first fail. A unique name per test is how isolation is guaranteed
// rather than hoped for.
func testPolicy(t *testing.T, limit int, window time.Duration) Policy {
	t.Helper()
	return Policy{Name: "test-" + idgen.ShortSuffix(10), Limit: limit, Window: window}
}

// TestAllow_EnforcesTheLimit is the baseline: the limit is a limit.
func TestAllow_EnforcesTheLimit(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	policy := testPolicy(t, 3, time.Minute)
	l := New(rdb, policy, nil)
	bucket := "caller-a"

	for i := 0; i < 3; i++ {
		d := l.Allow(context.Background(), bucket)
		if !d.Allowed {
			t.Fatalf("request %d of 3 was refused; the limit is %d", i+1, policy.Limit)
		}
		if d.Degraded {
			t.Fatalf("request %d reported degraded against a reachable Redis", i+1)
		}
		// Remaining must count down, because a client paces itself on it.
		if want := policy.Limit - i - 1; d.Remaining != want {
			t.Fatalf("request %d: Remaining = %d, want %d", i+1, d.Remaining, want)
		}
	}

	fourth := l.Allow(context.Background(), bucket)
	if fourth.Allowed {
		t.Fatalf("a %d-th request was allowed past a limit of %d", policy.Limit+1, policy.Limit)
	}
	if fourth.Remaining != 0 {
		t.Fatalf("Refused decision reported Remaining = %d, want 0", fourth.Remaining)
	}
	if fourth.ResetAfter <= 0 {
		t.Fatal("a refusal reported no reset time, so a client cannot know when to retry")
	}
}

// TestAllow_IsolatesBuckets is the correctness check that makes the limit per-caller rather
// than global.
//
// A limiter that shares one counter across callers refuses everyone once any one caller is
// busy — an outage caused by the protection. This is the assertion that it does not.
func TestAllow_IsolatesBuckets(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	policy := testPolicy(t, 2, time.Minute)
	l := New(rdb, policy, nil)

	for i := 0; i < 2; i++ {
		if d := l.Allow(context.Background(), "caller-a"); !d.Allowed {
			t.Fatalf("caller-a request %d was refused", i+1)
		}
	}
	if d := l.Allow(context.Background(), "caller-a"); d.Allowed {
		t.Fatal("caller-a exceeded its limit and was allowed")
	}

	// A different caller is unaffected.
	if d := l.Allow(context.Background(), "caller-b"); !d.Allowed {
		t.Fatal("caller-b was refused because caller-a had exhausted its own limit; " +
			"the buckets are not isolated")
	}
}

// TestAllow_WindowSlides is what distinguishes a sliding window from a fixed bucket.
//
// With a fixed window aligned to the clock, a caller can make a full limit's worth of
// requests at the end of one window and another full limit at the start of the next —
// double the intended rate across the boundary. A sliding window has no such seam, and this
// test pins the behaviour it is supposed to provide: consumption ages out, so the limiter
// recovers on its own without any reset job.
func TestAllow_WindowSlides(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	policy := testPolicy(t, 1, 300*time.Millisecond)
	l := New(rdb, policy, nil)
	ctx := context.Background()

	if d := l.Allow(ctx, "caller"); !d.Allowed {
		t.Fatal("first request was refused")
	}
	if d := l.Allow(ctx, "caller"); d.Allowed {
		t.Fatal("second request inside the window was allowed past a limit of 1")
	}

	time.Sleep(400 * time.Millisecond)

	if d := l.Allow(ctx, "caller"); !d.Allowed {
		t.Fatal("a request after the window elapsed was still refused; entries are not " +
			"aging out, so the limiter never recovers from a burst")
	}
}

// TestAllow_FailsOpenWhenRedisIsUnreachable is the failure-mode guarantee.
//
// Redis being down must not take the service down with it: the limiter protects against
// abuse, not correctness, so an unanswerable question is answered "allow". What must not
// happen is a silent allow — the caller and the operator both have to be able to tell the
// difference, which is what Degraded is for.
func TestAllow_FailsOpenWhenRedisIsUnreachable(t *testing.T) {
	rdb := testsupport.BrokenRedis(t)
	policy := testPolicy(t, 1, time.Minute)
	l := New(rdb, policy, nil)

	before := degradedCount(t)

	d := l.Allow(context.Background(), "caller")

	if !d.Allowed {
		t.Fatal("a request was refused because Redis was unreachable; that turns a cache " +
			"outage into a total outage")
	}
	if !d.Degraded {
		t.Fatal("the decision was not marked Degraded, so a client cannot tell an unenforced " +
			"limit from an enforced one")
	}
	if d.Remaining != 0 {
		t.Fatalf("a degraded decision reported Remaining = %d; room that is not known to exist "+
			"must not be advertised", d.Remaining)
	}

	if after := degradedCount(t); after <= before {
		t.Fatal("no degraded decision was counted; a limiter that is silently not limiting is " +
			"indistinguishable from one that is working")
	}
}

// TestAllow_FailsOpenButCountsRepeatedly guards the metric under sustained failure.
//
// The log line is rate-limited to one a minute so an outage cannot flood the log, but the
// *metric* must not be — an operator charting degradation needs the volume, not a sample.
func TestAllow_FailsOpenButCountsRepeatedly(t *testing.T) {
	rdb := testsupport.BrokenRedis(t)
	l := New(rdb, testPolicy(t, 5, time.Minute), nil)

	before := degradedCount(t)

	const attempts = 5
	for i := 0; i < attempts; i++ {
		if d := l.Allow(context.Background(), "caller"); !d.Allowed {
			t.Fatalf("attempt %d was refused while degraded", i+1)
		}
	}

	if got := degradedCount(t) - before; got != attempts {
		t.Fatalf("counted %.0f degraded decisions for %d requests; every fail-open decision must "+
			"be counted, even though the log is rate-limited", got, attempts)
	}
}

// TestValidate_UnreachableRedisIsNotAnError pins the half of the contract that keeps Redis
// optional.
//
// If an unreachable Redis failed validation, the service could not start without it, which
// makes an optional dependency a hard requirement by accident — and the fail-open path
// could never run in production because the process would never have started.
func TestValidate_UnreachableRedisIsNotAnError(t *testing.T) {
	l := New(testsupport.BrokenRedis(t), testPolicy(t, 1, time.Minute), nil)

	if err := l.Validate(context.Background()); err != nil {
		t.Fatalf("Validate returned %v for an unreachable Redis; Redis is optional and the "+
			"service is designed to run without it", err)
	}
}

// TestValidate_GoodScriptLoads is the positive control for the startup check.
func TestValidate_GoodScriptLoads(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	l := New(rdb, testPolicy(t, 1, time.Minute), nil)

	if err := l.Validate(context.Background()); err != nil {
		t.Fatalf("Validate rejected the real script: %v", err)
	}
}

// TestValidateScript_RejectsABrokenScript is the test that makes the startup claim real.
//
// The script shipped in this package is correct, so no test could otherwise reach the error
// branch — and an unexercised branch is a comment, not a guarantee. The consequence of
// missing it is specific: a limiter whose script cannot compile answers every request with an
// error, and if that were treated as degradation the service would start and enforce nothing
// while reporting healthy.
func TestValidateScript_RejectsABrokenScript(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	broken := redis.NewScript("this is not lua (((")

	err := validateScript(context.Background(), rdb, broken, "broken", nil)
	if err == nil {
		t.Fatal("a script Redis cannot compile was accepted; a service that starts with an " +
			"unusable limiter enforces nothing while reporting healthy")
	}
	// It must be reported as a *server-side* error, since that is what distinguishes "this
	// script is broken" from "Redis is unreachable" — the two are handled oppositely.
	var serverErr redis.Error
	if !errors.As(err, &serverErr) {
		t.Fatalf("the failure was not recognised as a server-side error: %v", err)
	}
}

// TestKeyFor_NamespacesByPolicyAndEscapesAmbiguity covers key construction.
//
// Two properties matter. The policy name must be in the key, or two policies sharing a
// bucket value would share a counter and a login limit would consume an API limit. And the
// bucket must not be able to impersonate another policy's key: a bucket value containing the
// separator would otherwise land in a different policy's namespace, which is the kind of
// forgery a caller controls.
func TestKeyFor_NamespacesByPolicyAndEscapesAmbiguity(t *testing.T) {
	l := New(nil, Policy{Name: "login", Limit: 1, Window: time.Minute}, nil)

	key := l.keyFor("1.2.3.4")
	if !strings.Contains(key, "login") {
		t.Fatalf("key %q does not name its policy, so two policies can share a counter", key)
	}

	other := New(nil, Policy{Name: "api", Limit: 1, Window: time.Minute}, nil)
	if l.keyFor("x") == other.keyFor("x") {
		t.Fatal("two policies with the same bucket produced the same key")
	}

	// The bucket is caller-influenced (it can be an address), so a bucket crafted to look
	// like another policy's key must not collide with it.
	if l.keyFor("api}1.2.3.4") == other.keyFor("1.2.3.4") {
		t.Fatal("a crafted bucket collided with another policy's key; the caller controls part " +
			"of the key, so this is a namespace escape")
	}
}

// TestPolicy_ReportsItself keeps the reporting honest: metrics and logs label by policy, so
// a limiter that reported the wrong one would attribute throttling to the wrong endpoint.
func TestPolicy_ReportsItself(t *testing.T) {
	policy := Policy{Name: "unit", Limit: 7, Window: 2 * time.Minute}
	l := New(nil, policy, nil)

	got := l.Policy()
	if got.Name != policy.Name || got.Limit != policy.Limit || got.Window != policy.Window {
		t.Fatalf("Policy() = %+v, want %+v", got, policy)
	}
}

// TestAllow_ConcurrentDuplicatesDoNotExceedTheLimit is the concurrency check for the
// counting itself.
//
// INCR-then-read would have a race in which two callers read the same count and both
// proceed, exceeding a limit by exactly the concurrency. Doing it in one Lua script is what
// prevents that, and this is the assertion that the script actually serialises — run with
// -race, because a concurrent test without the detector is theatre.
func TestAllow_ConcurrentDuplicatesDoNotExceedTheLimit(t *testing.T) {
	rdb := testsupport.RequireRedis(t)
	const limit = 10
	policy := testPolicy(t, limit, time.Minute)
	l := New(rdb, policy, nil)

	const callers = 40
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)

	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // released together, to widen the window for a race
			if l.Allow(context.Background(), "shared").Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if allowed != limit {
		t.Fatalf("%d of %d concurrent requests were allowed against a limit of %d; "+
			"exactly %d must be, or the count is not atomic", allowed, callers, limit, limit)
	}
}
