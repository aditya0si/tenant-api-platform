package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// redactedKeys are matched case-insensitively as substrings of an attribute key.
// Key matching is the primary defence; it is deliberately broad because the cost
// of an over-redacted key is a slightly less useful log line, and the cost of a
// missed one is a credential in a log aggregator.
var redactedKeys = []string{
	"authorization", "token", "api_key", "apikey", "password", "secret", "cookie",
	"set-cookie", "credential", "private_key", "session",
}

// redactedValuePrefixes catch credentials that arrive inside a generically named
// attribute, where key matching cannot help — e.g. a raw header dump logged as
// {"header": "Bearer eyJ..."} or a key echoed back as {"value": "ak_live_..."}.
//
// This is a backstop, not a guarantee: it recognises the credential formats this
// service issues. The rule the codebase follows is stricter and simpler — never
// log a raw header map or request body; log named fields.
var redactedValuePrefixes = []string{"bearer ", "basic ", "ak_", "rt_"}

// New returns a JSON slog logger. Level comes from LOG_LEVEL.
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

// redactHandler strips credentials from records before they are emitted.
//
// It wraps rather than replaces the inner handler, which means all three
// construction paths matter: Handle (the record itself), WithAttrs (attributes
// bound to a child logger, as in log.With("password", x)), and WithGroup. A
// wrapper that only implements Handle inherits the inner handler's WithAttrs,
// which returns an unwrapped handler — so redaction silently stops applying the
// moment anyone uses a child logger. TestRedaction_SurvivesChildLogger covers
// exactly that regression.
type redactHandler struct{ slog.Handler }

// Enabled defers to the inner handler's level filter.
func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.Handler.Enabled(ctx, l)
}

// Handle redacts the record's own attributes, then passes it on.
func (h *redactHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r2.AddAttrs(redactAttrs(collectAttrs(r))...)
	return h.Handler.Handle(ctx, r2)
}

// WithAttrs redacts bound attributes and re-wraps, so a child logger keeps the
// redaction behaviour of its parent.
func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &redactHandler{Handler: h.Handler.WithAttrs(redactAttrs(attrs))}
}

// WithGroup re-wraps the grouped child. Attributes added after the group are
// nested by the inner handler but still pass through Handle/WithAttrs here, so
// key matching continues to apply.
func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{Handler: h.Handler.WithGroup(name)}
}

func collectAttrs(r slog.Record) []slog.Attr {
	out := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		out = append(out, a)
		return true
	})
	return out
}

// redactAttrs replaces sensitive values in place, recursing into groups so a
// nested {"auth": {"token": ...}} is caught too.
func redactAttrs(attrs []slog.Attr) []slog.Attr {
	for i := range attrs {
		a := &attrs[i]
		if len(a.Value.Group()) > 0 {
			grouped := a.Value.Group()
			a.Value = slog.GroupValue(redactAttrs(grouped)...)
			continue
		}
		if isSensitiveKey(a.Key) || hasSensitiveValue(a.Value) {
			a.Value = slog.StringValue("[redacted]")
		}
	}
	return attrs
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, rk := range redactedKeys {
		if strings.Contains(k, rk) {
			return true
		}
	}
	return false
}

func hasSensitiveValue(v slog.Value) bool {
	if v.Kind() != slog.KindString {
		return false
	}
	s := strings.ToLower(v.String())
	for _, p := range redactedValuePrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
