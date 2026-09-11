package testsupport

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aditya0si/tenant-api-platform/internal/platform/cache"
)

// RequireRedis returns a client for the test Redis or fails the test.
//
// It fails rather than skips for the same reason RequireDB does: a limiter whose tests were
// skipped proves nothing, and the fail-open path in particular is the one that has to be
// exercised deliberately. SKIP_DB_TESTS=1 opts out of the whole dependency-backed subset
// during development.
//
// It deliberately does not FLUSH the database. Tests isolate themselves by using unique
// bucket names, which is the same discipline the database fixtures use with unique slugs —
// flushing would make two tests running against a shared Redis interfere through a mechanism
// nobody reading either test could see.
func RequireRedis(t *testing.T) *redis.Client {
	t.Helper()

	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		if os.Getenv("SKIP_DB_TESTS") == "1" {
			t.Skip("SKIP_DB_TESTS=1: skipping dependency-backed test")
		}
		t.Fatalf(`TEST_REDIS_URL is not set.

The rate limiter's behaviour is defined by what it does when Redis answers, when Redis is
unreachable, and when a window slides — none of which a fake can reproduce faithfully.

  docker compose up -d redis
  make test            # sets TEST_REDIS_URL and runs everything

Set SKIP_DB_TESTS=1 only to run the pure-unit subset locally.`)
	}

	client, err := cache.NewClient(url)
	if err != nil {
		t.Fatalf("testsupport: parse TEST_REDIS_URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("testsupport: ping redis (%s): %v", url, err)
	}

	t.Cleanup(func() { _ = client.Close() })
	return client
}

// BrokenRedis returns a client pointed at an address nothing is listening on.
//
// This is how the fail-open path is tested against a *real* failure rather than a stubbed
// one. A mock that returns an error proves the error branch is reachable; a client whose
// connection is actually refused proves the limiter survives the thing that will actually
// happen in production. It is the same instinct as connecting as superuser to prove the
// isolation tests measure row-level security.
//
// Retries are disabled and the dial timeout is short, so a test that makes several degraded
// calls does not spend its time waiting on a refusal it already expects. The production client
// keeps its generous timeouts: this is a property of the test double, not of the behaviour
// under test.
func BrokenRedis(t *testing.T) *redis.Client {
	t.Helper()

	// Port 1 is reserved and nothing listens on it, so the dial fails immediately rather
	// than hanging.
	client, err := cache.NewClient("redis://127.0.0.1:1/0")
	if err != nil {
		t.Fatalf("testsupport: build broken redis client: %v", err)
	}

	// -1 disables retries in go-redis v9. Without it every call burns several dial timeouts
	// before reporting the failure the test is deliberately causing.
	client.Options().MaxRetries = -1
	client.Options().DialTimeout = 200 * time.Millisecond

	t.Cleanup(func() { _ = client.Close() })
	return client
}
