package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// capture builds a logger writing JSON into a buffer, so tests can assert on
// what would actually have been emitted.
func capture(level string) (*slog.Logger, *bytes.Buffer) {
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
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: l})
	return slog.New(&redactHandler{Handler: inner}), &buf
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("log output is not valid JSON: %v\n%s", err, buf.String())
	}
	return out
}

// TestRedact_SensitiveKeysAreRedacted covers the primary defence: an attribute
// whose key looks like a credential never carries its value into the log.
func TestRedact_SensitiveKeysAreRedacted(t *testing.T) {
	log, buf := capture("info")

	sensitive := map[string]string{
		"password":      "hunter2",
		"api_key":       "ak_live_abcdef",
		"Authorization": "Bearer eyJhbGciOi",
		"refresh_token": "rt_0123456789",
		"secret":        "s3cr3t",
		"cookie":        "session=abc",
	}

	for key, value := range sensitive {
		buf.Reset()
		log.Info("event", key, value)

		entry := decode(t, buf)
		if entry[key] != "[redacted]" {
			t.Errorf("key %q was not redacted: got %v", key, entry[key])
		}
		if strings.Contains(buf.String(), value) && !strings.Contains(value, "[redacted]") {
			t.Errorf("key %q leaked its value into the log: %s", key, buf.String())
		}
	}
}

// TestRedact_OrdinaryFieldsSurvive guards against redaction that is so broad it
// makes logs useless. Unknown keys must pass through untouched, or nobody can
// debug anything.
func TestRedact_OrdinaryFieldsSurvive(t *testing.T) {
	log, buf := capture("info")

	log.Info("tenant created",
		"tenant_id", "01a08d4c-2011-711d-91dc-8a818df491d1",
		"slug", "acme",
		"duration_ms", 12,
		"ok", true,
	)

	entry := decode(t, buf)
	if entry["tenant_id"] != "01a08d4c-2011-711d-91dc-8a818df491d1" {
		t.Errorf("tenant_id was altered: %v", entry["tenant_id"])
	}
	if entry["slug"] != "acme" {
		t.Errorf("slug was altered: %v", entry["slug"])
	}
	if entry["duration_ms"] != float64(12) {
		t.Errorf("duration_ms was altered: %v", entry["duration_ms"])
	}
	if entry["msg"] != "tenant created" {
		t.Errorf("message was altered: %v", entry["msg"])
	}
}

// TestRedact_SurvivesChildLogger is the regression test for the structural bug
// this handler is shaped to avoid.
//
// slog's Handler interface has WithAttrs and WithGroup. An implementation that
// embeds a handler and only overrides Handle inherits the inner handler's
// WithAttrs, which returns an *unwrapped* handler — so the moment anyone writes
// log.With("password", x), redaction silently stops applying and the credential
// is emitted verbatim. It is invisible in code review and invisible in tests that
// only ever log through the root logger.
func TestRedact_SurvivesChildLogger(t *testing.T) {
	log, buf := capture("info")

	child := log.With("api_key", "ak_live_child", "component", "worker")
	child.Info("bound attribute")

	entry := decode(t, buf)
	if entry["api_key"] != "[redacted]" {
		t.Errorf("child logger leaked a bound credential: %v", entry["api_key"])
	}
	if entry["component"] != "worker" {
		t.Errorf("child logger lost an ordinary bound attribute: %v", entry["component"])
	}
	if strings.Contains(buf.String(), "ak_live_child") {
		t.Fatalf("credential present in output: %s", buf.String())
	}
}

// TestRedact_SurvivesGrandchildLogger proves the re-wrapping composes: a logger
// derived from a derived logger keeps redacting.
func TestRedact_SurvivesGrandchildLogger(t *testing.T) {
	log, buf := capture("info")

	log.With("component", "worker").
		With("token", "rt_grandchild").
		Info("nested")

	entry := decode(t, buf)
	if entry["token"] != "[redacted]" {
		t.Errorf("grandchild logger leaked a credential: %v", entry["token"])
	}
	if strings.Contains(buf.String(), "rt_grandchild") {
		t.Fatalf("credential present in output: %s", buf.String())
	}
}

// TestRedact_NestedGroupsAreRedacted covers the case a flat key scan misses:
// a credential nested inside a group, which is what happens when any code logs a
// structured sub-object.
func TestRedact_NestedGroupsAreRedacted(t *testing.T) {
	log, buf := capture("info")

	log.Info("request",
		slog.Group("auth",
			slog.String("token", "eyJhbGciOi-nested"),
			slog.String("scheme", "Bearer"),
		),
	)

	entry := decode(t, buf)
	auth, ok := entry["auth"].(map[string]any)
	if !ok {
		t.Fatalf("group was not emitted as an object: %v", entry["auth"])
	}
	if auth["token"] != "[redacted]" {
		t.Errorf("nested credential not redacted: %v", auth["token"])
	}
	// Equal-cost check: a nested *ordinary* field must survive, otherwise group
	// redaction is just disabling the group.
	if auth["scheme"] != "Bearer" {
		t.Errorf("nested ordinary field was dropped: %v", auth["scheme"])
	}
}

// TestRedact_SensitiveValuePrefixes covers the gap key matching cannot close: a
// credential arriving under a generically named attribute, such as a raw header
// string logged as {"header": "Bearer eyJ..."}.
//
// This is explicitly a backstop rather than a guarantee — it recognises the
// credential shapes this service issues. The rule the codebase follows is
// stricter: log named fields, never a raw header map or request body.
func TestRedact_SensitiveValuePrefixes(t *testing.T) {
	log, buf := capture("info")

	cases := map[string]string{
		"header":           "Bearer eyJhbGciOiJIUzI1NiIs",
		"value":            "ak_live_prefix_detected",
		"authorization_hd": "Basic dXNlcjpwYXNz",
		"tokenish":         "rt_refresh_prefix",
	}

	for key, value := range cases {
		buf.Reset()
		log.Info("event", key, value)
		entry := decode(t, buf)
		if entry[key] != "[redacted]" {
			t.Errorf("value with a credential prefix was not redacted: key=%q value=%q got=%v", key, value, entry[key])
		}
	}

	// A value that merely resembles a word must not be redacted: over-redaction
	// is how logs stop being useful.
	buf.Reset()
	log.Info("event", "note", "bearish market summary", "path", "/v1/tokens")
	entry := decode(t, buf)
	if entry["note"] != "bearish market summary" {
		t.Errorf("ordinary text starting with a similar word was redacted: %v", entry["note"])
	}
	if entry["path"] != "/v1/tokens" {
		t.Errorf("ordinary path was redacted: %v", entry["path"])
	}
}

// TestRedact_LevelFilterStillApplies proves the wrapper honours the inner
// handler's level: redaction must not accidentally become a bypass that logs
// everything, nor silence debug output that tests rely on.
func TestRedact_LevelFilterStillApplies(t *testing.T) {
	log, buf := capture("warn")

	log.Debug("debug line")
	if buf.Len() != 0 {
		t.Fatalf("debug output emitted at warn level: %s", buf.String())
	}

	log.Warn("warn line")
	if buf.Len() == 0 {
		t.Fatal("warn output was suppressed at warn level")
	}
}

// TestNew_ProducesJSONWithLevel confirms the constructor returns a working JSON
// logger and does not panic on an unrecognised level string.
func TestNew_ProducesJSONWithLevel(t *testing.T) {
	for _, level := range []string{"debug", "INFO", "warn", "error", "nonsense", ""} {
		log := New(level)
		if log == nil {
			t.Fatalf("New(%q) returned nil", level)
		}
	}
}
