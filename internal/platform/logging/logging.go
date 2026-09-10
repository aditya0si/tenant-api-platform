package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// redactedKeys are never emitted in values.
var redactedKeys = []string{"authorization", "token", "api_key", "apikey", "password", "secret", "cookie", "set-cookie"}

// New returns a JSON slog logger. Level from LOG_LEVEL.
func New(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l})
	return slog.New(&redactHandler{Handler: h})
}

// redactHandler strips sensitive headers/values before emission.
type redactHandler struct{ slog.Handler }

func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	var attrs []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		k := strings.ToLower(a.Key)
		for _, rk := range redactedKeys {
			if strings.Contains(k, rk) {
				a.Value = slog.StringValue("[redacted]")
				break
			}
		}
		attrs = append(attrs, a)
		return true
	})
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r2.AddAttrs(attrs...)
	return h.Handler.Handle(ctx, r2)
}
