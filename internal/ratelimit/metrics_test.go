package ratelimit

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
)

// degradedCount reads the fail-open counter.
//
// It is a helper rather than an inline call because every test that asserts on it must take
// a *delta*: the metric is process-global and shared across tests in this package, so an
// absolute value is meaningless. Reading the delta is also the honest assertion — it states
// "this request counted one", which is the claim, rather than "the total happens to be N",
// which would pass or fail depending on what ran before it.
func degradedCount(t *testing.T) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.RateLimitDegraded)
}
