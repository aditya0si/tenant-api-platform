// Package idempotency implements the idempotency-key protocol for unsafe requests.
//
// # The protocol, stated precisely
//
// A client that may retry a write sends an Idempotency-Key header. The server records
// the key on first use and replays the recorded response on every later use, so a retry
// cannot cause a second effect.
//
// The server's behaviour:
//
//	no key                        -> the request runs normally, unprotected
//	key, never seen               -> claim it, run the handler, record the response
//	key, completed, same request  -> replay the recorded response verbatim
//	key, completed, different body-> 422; the client reused a key for a different request
//	key, in_progress              -> 409 with Retry-After; a duplicate is already running
//	key, in_progress, stale       -> take it over; the original process died
//
// # Which requests this covers, and which it does not
//
// Supported: POST, PATCH, and DELETE on tenant-scoped resources. Safe methods (GET,
// HEAD, OPTIONS) are skipped — they have no effect to duplicate, and recording them
// would fill the table with replays of no consequence.
//
// Not supported: requests with no resolved tenant. A key is scoped to (tenant, key), so
// a request that cannot name a tenant cannot participate. That is not a limitation to
// work around: the endpoints without a tenant are registration and login, and treating
// a duplicate login as replayable would mean caching a credential response.
//
// # The window this does not close, stated plainly
//
// A handler's effect commits in its own transaction, and the idempotency record is
// updated after it returns. A process that dies in between leaves an in_progress row
// whose effect has already been applied, and a takeover after the lease expires would
// run the handler a second time.
//
// The window is small — one UPDATE wide — and it is not closed by making the record and
// the effect share a transaction, because the handlers own their transactions and a
// generic transport-level middleware cannot join one it did not open. So the mitigation
// is at the operations that matter: every state transition in this service is
// compare-and-set (an invoice moves draft -> open only from draft; a project create is
// guarded by a unique slug), which means a duplicated call is refused by the data layer
// even when it reaches a handler. See docs/IDEMPOTENCY.md for the full account and for
// what would be required to close it properly.
package idempotency

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// Header is the request header carrying a client's idempotency key.
	//
	// It is the de facto standard name (Stripe, Square, and the IETF draft all use
	// it), which matters more than aesthetics: a client library that already knows how
	// to send it works against this service without configuration.
	Header = "Idempotency-Key"

	// MaxKeyLength mirrors the CHECK constraint. It is enforced in Go as well so an
	// over-long key produces a 400 naming the header rather than a 500 wrapping a
	// constraint violation.
	MaxKeyLength = 255

	// DefaultRetention is how long a key is honoured.
	//
	// It has to exceed any realistic client retry schedule, because a retry that lands
	// after the key expires is a fresh request — causing exactly the second effect the
	// protocol exists to prevent. Twenty-four hours covers an offline client
	// reconnecting, a manual retry the next morning, and a queued job that failed
	// overnight; longer than that and the table grows faster than the value it provides.
	DefaultRetention = 24 * time.Hour
)

// Errors. Each maps to a distinct client response, because each needs a different client
// action: reload, re-read, wait, or fix a bug.
var (
	// ErrKeyBlank is a malformed request: the header was present but carried no usable
	// value.
	//
	// It is deliberately distinct from "no header at all", which is not an error — that is
	// a client declining to opt in. Collapsing the two is the bug this sentinel exists to
	// prevent: a blank header would run unprotected while the client believed otherwise.
	ErrKeyBlank = errors.New("idempotency: the key must not be blank")

	// ErrKeyTooLong is a malformed request, not a conflict.
	ErrKeyTooLong = errors.New("idempotency: key exceeds the maximum length")

	// ErrFingerprintMismatch means the key was reused for a different request. It is the
	// one outcome that indicates a client bug rather than a retry, so it is reported
	// distinctly.
	ErrFingerprintMismatch = errors.New("idempotency: this key was already used for a different request")

	// ErrInProgress means a request with this key is running right now.
	ErrInProgress = errors.New("idempotency: a request with this key is currently in progress")

	// ErrNotReplayable means the original request completed but its response was too large
	// to store, so it cannot be replayed.
	ErrNotReplayable = errors.New("idempotency: the original response was too large to replay")

	// ErrSweepNeedsPrivilegedRole means an attempt was made to reap expired records with a
	// connection that row-level security applies to, where the delete would be silently
	// filtered to zero rows. It is an operational error rather than a client one, and it is
	// not listed as client-safe — its message names a role and belongs in a log.
	ErrSweepNeedsPrivilegedRole = errors.New("idempotency: sweeping requires a role that bypasses row-level security")
)

// State is a record's position in the protocol.
type State string

const (
	StateInProgress State = "in_progress"
	StateCompleted  State = "completed"
)

// Record is a stored idempotency key and, once completed, the response it replays.
type Record struct {
	Key         string
	Fingerprint string
	State       State
	StatusCode  int
	Headers     http.Header
	Body        []byte
	Replayable  bool
	CreatedAt   time.Time
	CompletedAt *time.Time

	// LeaseExpired reports that this is an in_progress record whose holder has died.
	//
	// It is evaluated by the database rather than computed here, for the reason given on
	// Store: comparing a database-written created_at against the application's clock is
	// wrong by the skew between them, and the symptom is either a key wedged forever or a
	// live handler taken over mid-flight.
	LeaseExpired bool
}

// Completed reports whether the record carries a replayable response.
func (r Record) Completed() bool { return r.State == StateCompleted }

// Fingerprint derives the comparison hash for a request.
//
// # What is covered, and why only this
//
// Method, path, query string, and a hash of the body. Together they answer "is this the
// same request?" — which is the only question the protocol needs to answer.
//
// The tenant is deliberately *not* included: it is already the leading column of the
// primary key, so a key can only ever be compared against records in its own tenant.
// Including it would be redundant rather than wrong, and redundancy in a hash is a
// place for the two copies to disagree.
//
// The body is hashed rather than stored, so a credential in a request body never lands
// in this table. Only the digest reaches the database, and a digest is not reversible.
//
// # Why the body must be included at all
//
// Without it, a client that reuses a key for a genuinely different request — the same
// key sent for two different invoices — would receive the first invoice's response for
// the second request. That is worse than an error: the client is told its second
// request succeeded, with data describing the first, and nothing anywhere reports a
// problem.
func Fingerprint(method, path, query string, body []byte) string {
	h := sha256.New()
	// NUL separators, so a method or path containing a delimiter cannot be crafted to
	// collide with a different request. Without them, ("ab","c") and ("a","bc") hash
	// identically.
	h.Write([]byte(strings.ToUpper(method)))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(query))
	h.Write([]byte{0})
	bodySum := sha256.Sum256(body)
	h.Write(bodySum[:])
	return hex.EncodeToString(h.Sum(nil))
}

// FingerprintsMatch compares two fingerprints in constant time.
//
// The values are not secrets, so a timing attack is not the threat. The reason to use a
// constant-time comparison anyway is that it removes the question: a reviewer reading
// `a == b` on two hashes has to reason about whether the values are secret, and a
// reviewer reading this does not. The cost is a few nanoseconds on a path that already
// touched the database.
func FingerprintsMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ValidateKey checks a client-supplied key.
//
// Empty is rejected rather than treated as "no idempotency": a client that sends the
// header at all is asking for protection, and silently providing none would be the
// worst outcome. A client that does not want it omits the header.
func ValidateKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return ErrKeyBlank
	}
	if len(key) > MaxKeyLength {
		return fmt.Errorf("idempotency: key is %d characters, the maximum is %d: %w",
			len(key), MaxKeyLength, ErrKeyTooLong)
	}
	return nil
}
