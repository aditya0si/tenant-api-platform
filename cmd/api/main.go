// Command api runs the tenant API Platform HTTP service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aditya0si/tenant-api-platform/internal/platform/cache"
	"github.com/aditya0si/tenant-api-platform/internal/platform/config"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httpserver"
	"github.com/aditya0si/tenant-api-platform/internal/platform/logging"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	log := logging.New(cfg.LogLevel)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var pingDB func(r *http.Request) bool
	var pingRedis func(r *http.Request) bool

	if cfg.DatabaseURL != "" {
		pool, err := db.NewPool(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("postgres pool: %w", err)
		}
		defer pool.Close()
		pingDB = func(r *http.Request) bool {
			c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			return pool.Ping(c) == nil
		}
		log.Info("postgres pool ready")
	} else {
		log.Warn("DATABASE_URL empty, readiness will report db_unreachable")
		pingDB = func(_ *http.Request) bool { return false }
	}

	rdb, err := cache.NewClient(cfg.RedisURL)
	if err != nil {
		log.Warn("redis config invalid, degraded mode", "err", err)
		pingRedis = func(_ *http.Request) bool { return false }
	} else {
		defer func() { _ = rdb.Close() }()
		pingRedis = func(r *http.Request) bool {
			c, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			return rdb.Ping(c).Err() == nil
		}
	}

	handler := httpserver.New(httpserver.Deps{DBPing: pingDB, RedisPing: pingRedis})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("api listening", "port", cfg.Port, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	}

	shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}
