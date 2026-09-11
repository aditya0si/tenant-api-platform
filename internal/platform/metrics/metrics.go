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

	// WebhookAttempts counts delivery attempts by outcome.
	//
	// The three outcomes need different responses: "delivered" is health, "retry" is a receiver
	// having a bad minute, and "dead" is a receiver that has been broken for an hour and whose
	// tenant may need to be told. Collapsing them into one counter would hide the third behind
	// the second, which is the only one that ever needs a human.
	WebhookAttempts = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "webhook_delivery_attempts_total",
		Help: "Webhook delivery attempts, by event and outcome (delivered, retry, dead, lease_lost).",
	}, []string{"event", "outcome"})

	// WebhookAttemptDuration observes how long a receiver takes.
	//
	// This is the number that explains most delivery failures: a receiver whose p99 approaches
	// the delivery timeout produces timeouts rather than rejections, and the timeout is
	// indistinguishable from an outage without the latency distribution.
	WebhookAttemptDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "webhook_delivery_duration_seconds",
		Help:    "Webhook delivery attempt latency, by event.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"event"})

	// WebhookOutboxDepth is how much is queued, by state.
	//
	// A rising pending count means receivers are failing or the worker is not keeping up, and
	// the two are distinguished by whether dead rises with it. This is the gauge the worker's
	// own health is read from — the worker serving no HTTP cannot be probed any other way.
	WebhookOutboxDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "webhook_outbox_depth",
		Help: "Undelivered webhook events, by state.",
	}, []string{"state"})
)
