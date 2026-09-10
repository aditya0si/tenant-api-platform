package httpserver

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aditya0si/tenant-api-platform/internal/platform/metrics"
)

// Deps are the runtime dependencies. DB/Redis may be nil in degraded mode;
// readiness reflects that instead of crashing.
type Deps struct {
	DBPing    func(r *http.Request) bool
	RedisPing func(r *http.Request) bool
}

// New builds the router. Routes: /healthz (liveness), /readyz (readiness), /metrics.
func New(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(15 * time.Second))
	r.Use(instrument)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		dbOK, redisOK := true, true
		if d.DBPing != nil {
			dbOK = d.DBPing(req)
		}
		if d.RedisPing != nil {
			redisOK = d.RedisPing(req)
		}
		if dbOK {
			metrics.DBUp.Set(1)
		} else {
			metrics.DBUp.Set(0)
		}
		if redisOK {
			metrics.RedisUp.Set(1)
		} else {
			metrics.RedisUp.Set(0)
		}
		w.Header().Set("Content-Type", "application/json")
		if !dbOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not_ready","reason":"db_unreachable"}`))
			return
		}
		// Redis down is degraded, not unready (fail-open rate limiter).
		w.WriteHeader(http.StatusOK)
		if !redisOK {
			_, _ = w.Write([]byte(`{"status":"ok","redis":"degraded"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Handle("/metrics", promhttp.Handler())
	r.Get("/v1/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"pong"}`))
	})
	return r
}
