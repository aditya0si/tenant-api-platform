package httpx_test

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"gopkg.in/yaml.v3"
)

// TestOpenAPI_MatchesTheRouter is the contract test ADR-010 promises, and the reason
// docs/openapi.yaml cannot quietly become documentation of a service that no longer exists.
//
// It compares two sets in both directions, because the two failures are different:
//
//   - A route the router serves but the spec omits means a client generated from the spec cannot
//     call something that exists.
//   - An operation the spec documents but the router does not serve means an integrator writes
//     code against an endpoint that 404s.
//
// Only the second is visible from reading the spec alone, which is why both are asserted. This is
// also the gate that makes a hand-written spec maintainable: adding a route without documenting it
// fails the build, so the spec tracks the code by default rather than by diligence.
//
// It builds the full router through the test harness, so it needs the database — the same
// requirement as every other test in this package, and for the same reason: a router assembled
// without its stores registers fewer routes, and comparing the spec against that would pass while
// measuring nothing.
func TestOpenAPI_MatchesTheRouter(t *testing.T) {
	s := newServer(t)

	mux, ok := s.handler.(*chi.Mux)
	if !ok {
		t.Fatalf("the router is a %T, not a *chi.Mux", s.handler)
	}

	served := map[string]bool{}
	err := chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// /metrics is mounted with Handle(), so chi reports every method for it. It belongs to
		// Prometheus rather than to the API — scraped, never called by a client — and it is
		// deliberately absent from the spec. Excluding it here rather than documenting nine
		// meaningless operations keeps both sides honest about what this test covers.
		if normalizeOpenAPIPath(route) == "/metrics" {
			return nil
		}
		served[method+" "+normalizeOpenAPIPath(route)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk the router: %v", err)
	}
	if len(served) == 0 {
		t.Fatal("the router reported no routes, so this test would pass against any spec")
	}

	specPath := filepath.Join("..", "..", "docs", "openapi.yaml")
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read %s: %v — the spec is part of the contract, not an optional extra", specPath, err)
	}

	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid YAML: %v", specPath, err)
	}
	if len(doc.Paths) == 0 {
		t.Fatalf("%s declares no paths", specPath)
	}

	declared := map[string]bool{}
	for path, item := range doc.Paths {
		for key, node := range item {
			method := strings.ToUpper(key)
			switch method {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
				http.MethodDelete, http.MethodHead, http.MethodOptions:
				// An operation.
			default:
				// Path-level keys that are not operations: parameters, summary, description.
				continue
			}

			// A documented operation with no responses is a stub. It would satisfy the path
			// comparison while telling an integrator nothing about what comes back, so it fails
			// here instead of passing as documentation.
			var op struct {
				Responses map[string]yaml.Node `yaml:"responses"`
			}
			if err := node.Decode(&op); err != nil {
				t.Errorf("%s %s: cannot decode the operation: %v", method, path, err)
				continue
			}
			if len(op.Responses) == 0 {
				t.Errorf("%s %s documents no responses", method, path)
			}

			key := method + " " + normalizeOpenAPIPath(path)
			if declared[key] {
				t.Errorf("%s is documented twice", key)
			}
			declared[key] = true
		}
	}

	var undocumentedInSpec, notServed []string
	for key := range served {
		if !declared[key] {
			undocumentedInSpec = append(undocumentedInSpec, key)
		}
	}
	for key := range declared {
		if !served[key] {
			notServed = append(notServed, key)
		}
	}
	sort.Strings(undocumentedInSpec)
	sort.Strings(notServed)

	if len(undocumentedInSpec) > 0 {
		t.Errorf("the router serves %d operation(s) the spec does not document:\n  %s",
			len(undocumentedInSpec), strings.Join(undocumentedInSpec, "\n  "))
	}
	if len(notServed) > 0 {
		t.Errorf("the spec documents %d operation(s) the router does not serve:\n  %s",
			len(notServed), strings.Join(notServed, "\n  "))
	}
	if t.Failed() {
		t.Fatalf("spec and router disagree: %d served, %d declared", len(served), len(declared))
	}

	t.Logf("contract holds in both directions: %d operations", len(served))
}

// normalizeOpenAPIPath makes a chi route pattern and a spec path comparable.
//
// chi reports a sub-router's index route with a trailing slash —
// "/v1/tenants/{tenantID}/projects/" — while the spec follows the convention of no trailing slash.
// Trimming both sides is the whole normalisation. The brace style is not normalised, deliberately:
// the spec copies chi's parameter names ({tenantID}, {projectID}), so a mistyped one is a visible
// mismatch rather than an invisible one.
func normalizeOpenAPIPath(p string) string {
	if len(p) > 1 {
		return strings.TrimSuffix(p, "/")
	}
	return p
}
