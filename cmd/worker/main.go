// Command worker delivers webhook events from the transactional outbox.
//
// # Why this is a separate binary rather than a goroutine in the API
//
// Three reasons, in order of weight.
//
//  1. **Scale independently.** Delivery throughput is bounded by how fast tenants' receivers
//     respond, which has nothing to do with how many API requests arrive. Embedded, the two would
//     have to be scaled together and an operator could not add delivery capacity without also
//     adding a fourth API replica.
//
//  2. **Fail independently.** A burst of slow receivers makes this process spend its time in HTTP
//     timeouts. That is its job. In the API it would be competing for the same event loop and the
//     same connection pool as request handling, so a tenant's broken endpoint would degrade
//     everyone's API latency.
//
//  3. **Survive a deploy.** Restarting the API to ship a handler change should not interrupt
//     delivery, and vice versa. The lease makes either safe, but not needing the lease is better
//     than relying on it.
//
// # What it does not do
//
// It serves no API. Its only HTTP surface is a metrics and health endpoint on a separate port,
// because a process with no ports cannot be probed and "is delivery keeping up" would then be
// answerable only by querying the database by hand.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aditya0si/tenant-api-platform/internal/platform/config"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/logging"
	"github.com/aditya0si/tenant-api-platform/internal/platform/ssrf"
	"github.com/aditya0si/tenant-api-platform/internal/webhook"
)

// shutdownGrace bounds how long an in-flight delivery may take to finish.
//
// It deliberately exceeds webhook.DeliveryTimeout: the worker waits for a delivery that is already
// in progress, and cutting it off sooner would abandon an attempt the receiver may be midway
// through — leaving this worker recording nothing while the receiver acts on the event, which is
// the ambiguity the lease exists to resolve. Waiting the delivery timeout out is the cheaper
// resolution.
const shutdownGrace = 15 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("worker stopped with an error", "err", err)
		// A non-zero exit is what a supervisor notices. Exiting zero on a fatal error would make a
		// crash-looping worker look like a cleanly stopped one.
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	log := logging.New(cfg.LogLevel)
	log = log.With("component", "webhook-worker")

	startupCtx, cancelStartup := context.WithTimeout(ctx, 30*time.Second)
	defer cancelStartup()

	pool, err := db.NewPool(startupCtx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()

	// The same check the API makes, for a subtler reason: this process reaches across every tenant
	// by policy (app.worker, migration 0011), so running it privileged would still deliver
	// everything while bypassing the mechanism that bounds it. The constraint would look satisfied
	// and would not be.
	if err := db.AssertUnprivilegedRole(startupCtx, pool, log); err != nil {
		return err
	}

	// The guard is constructed rather than reused from configuration: SSRF protection is not a
	// setting an operator can weaken. The loopback exception does not exist here — a tenant's
	// webhook URL is never allowed to reach this process's own host, and the test constructor is
	// not reachable from a binary.
	guard := ssrf.New()
	store := webhook.NewStore(pool)
	deliverer := webhook.NewDeliverer(guard, log)

	worker := webhook.NewWorker(store, deliverer, log, cfg.WorkerBatchSize, cfg.WorkerInterval)

	// --- metrics and health ---------------------------------------------------
	//
	// A separate listener on a separate port, and deliberately not exposed on a public interface
	// by default: the depth gauge is operational data about every tenant's delivery backlog.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// Liveness only. It checks the process is able to answer, not that the database is
		// reachable: a worker that cannot reach Postgres should keep retrying rather than be
		// restarted, because a restart does not fix a database outage and the outbox is durable.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Readiness does check the database, because a worker whose connection is gone is not
		// usefully running — it cannot claim or settle anything. Reported flat rather than in the
		// API's data envelope, for the same reason the API's probes are: an orchestrator reads a
		// top-level field.
		pingCtx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()

		w.Header().Set("Content-Type", "application/json")
		if err := pool.Ping(pingCtx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "not_ready", "reason": "database_unreachable",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ready"})
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.WorkerMetricsPort),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	srvErr := make(chan error, 1)
	go func() {
		log.Info("worker metrics listening", "port", cfg.WorkerMetricsPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- err
		}
		close(srvErr)
	}()

	// The poll loop runs in the foreground so its exit is the process's exit. ctx is cancelled by
	// SIGTERM, at which point an in-flight attempt finishes before Run returns — see shutdownGrace.
	runErr := make(chan error, 1)
	go func() {
		runErr <- worker.Run(ctx)
	}()

	select {
	case err := <-runErr:
		if err != nil {
			return fmt.Errorf("worker: %w", err)
		}
	case err := <-srvErr:
		if err != nil {
			return fmt.Errorf("metrics server: %w", err)
		}
	case <-ctx.Done():
		log.Info("shutdown signal received; waiting for the in-flight delivery to settle")
		if err := <-runErr; err != nil {
			return fmt.Errorf("worker: %w", err)
		}
	}

	// The context is not derived from the cancelled one: that would abort the drain immediately,
	// which is the opposite of the intent.
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancelDrain()
	if err := srv.Shutdown(drainCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	log.Info("worker stopped cleanly")
	return nil
}
