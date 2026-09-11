package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "HTTP requests by method, route, status.",
	}, []string{"method", "route", "status"})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP latency by route.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	}, []string{"route"})

	DBUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "db_up",
		Help: "1 if postgres reachable from readyz, else 0.",
	})

	RedisUp = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "redis_up",
		Help: "1 if redis reachable from readyz, else 0.",
	})

	RateLimitDegraded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ratelimit_degraded_total",
		Help: "Requests allowed fail-open because Redis was unavailable.",
	})

	// RateLimitLimited counts requests refused by the limiter, per policy.
	//
	// A 429 that nobody counts is a support ticket with no data behind it: the first question
	// about a throttled client is "is this the limit working or the limit set wrongly", and
	// that cannot be answered from request logs alone.
	RateLimitLimited = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ratelimit_limited_total",
		Help: "Requests refused by the rate limiter, by policy.",
	}, []string{"policy"})
)
