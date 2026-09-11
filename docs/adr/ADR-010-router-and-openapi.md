# ADR-010: chi as the router, and a hand-written OpenAPI spec with a contract test

Status: accepted. Both parts are implemented: `docs/openapi.yaml` (26 paths, 35 operations) and the
contract test in `internal/httpx/openapi_test.go`.

## Context

Two decisions that arrive together, because both concern what the HTTP surface *is*: which router
owns the request path, and where the API's contract is written down.

Handlers must compose cross-cutting middleware in a specific order — request id, trace context,
authentication, tenant resolution, authorization, rate limit, idempotency, handler — and the order
is load-bearing. Idempotency must run after authorization (an unauthorized caller must not be able
to reserve an idempotency key by probing), and the rate limiter must key on the resolved tenant for
authenticated routes but on the client address for unauthenticated ones.

The contract question follows from the router choice: chi derives no schema from anything, so the
spec is not a by-product and has to be decided on explicitly.

## Decision

- **chi v5** as the router, with hand-composed middleware groups.
- **OpenAPI 3.1 written by hand** in `docs/openapi.yaml`, plus a contract test that drives the real
  router and checks the spec against actual responses.
- **Rejected: huma** and annotation-driven spec generation generally.

## Why chi

- **stdlib-first.** Handlers are `http.HandlerFunc`s and middleware is `func(http.Handler) http.Handler`.
  There is no framework vocabulary between a reviewer and the routing tree.
- **Group-scoped middleware matches the layout exactly.** The unauthenticated group carries
  address-keyed rate limits; the tenant group carries tenant-keyed ones applied after tenant
  resolution; write routes carry idempotency. These are three chi groups, not conditional branches
  inside one middleware — which is what makes "the limiter keys on the tenant" a property of the
  route tree rather than of a runtime check.
- **Composable, individually testable middleware.** Each piece here is small and unit-testable
  alone: request-id propagation, trusted-proxy address resolution, the idempotency middleware, the
  rate limiter.

## Why a hand-written spec

- **The wire format is designed in the spec, not extracted from structs.** The response envelope,
  the cursor pagination parameters, and the error shape are decisions. A generated spec documents
  whatever the Go types happened to be, including fields that are not part of the contract.
- **Generators that annotate handlers cannot see middleware.** The error envelope is written by the
  error-handling layer, not by the handler, so a handler-level annotation would describe a response
  shape the service does not actually send.
- **Spec authorship is reviewable.** The spec is a design artifact someone can read and disagree
  with, which is the point for this project.

## Why a contract test rather than generated clients

A client generated from the spec and used by nobody proves nothing. A test that drives the real
router and asserts status codes, envelope shape, and required fields against the spec's own route
list is the version that catches drift — the failure it catches is "the handler changed and the spec
now lies."

## What the contract test checks, and what it does not

It compares the spec and the router in **both** directions, because the two failures differ in who
notices:

- A route the router serves that the spec omits means a client generated from the spec cannot call
  something that exists.
- An operation the spec documents that the router does not serve means an integrator writes code
  against an endpoint that 404s.

Only the second is visible from reading the spec, which is why both are asserted. Every documented
operation must also declare at least one response — a path with no responses would satisfy the
comparison while telling an integrator nothing.

**It does not check response shapes.** It does not assert that `GET /v1/me` returns the fields the
spec says it does, nor that a 409 carries the documented error code. Those are real properties and
they are not verified by this test; the handler-level tests in `internal/httpx` assert them for the
endpoints that have them. A shape-checking contract test would mean driving a real request per
operation, which is a larger piece of work than this milestone, and claiming the narrower test proves
more than it does would be the exact failure this ADR exists to prevent.

Only route/method agreement and response presence are guaranteed here. Stating the boundary is
deliberate: a reviewer who knows what the test does not cover can decide whether to rely on it.

## Consequences

- Adding an endpoint means adding its spec entry, and the build fails if it is forgotten — the
  discipline is now enforced by a test rather than by review.
- **No runtime validation from the spec.** Request validation lives in the stores and handlers where
  it can produce the service's error envelope. The spec describes; it does not enforce.
- The spec is a second artifact to keep correct. At roughly thirty endpoints hand-maintenance wins;
  past roughly a hundred the trade-off inverts and this decision should be revisited.
- The test builds the full router through the test harness, so it needs the database — the same
  requirement as every other test in that package. A router assembled without its stores registers
  fewer routes, and comparing the spec against that would pass while measuring nothing.
