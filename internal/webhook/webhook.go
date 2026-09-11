// Package webhook delivers tenant-configured events over HTTP, at least once.
//
// # The three properties, and what each rules out
//
// **Durability.** An event is written in the same transaction as the change that caused it, so
// the two commit together or neither does. Enqueuing after commit loses events to a crash
// between the two; enqueuing before it announces changes that then roll back. Neither is
// acceptable, and neither is fixable in the transport layer — see ADR-001.
//
// **At-least-once, stated honestly.** A worker that dies after the receiver processed a delivery
// but before recording it will redeliver, because on the network there is no way to tell
// "processed" from "never arrived". So every delivery carries a stable event id in the body and
// in a header, and the receiver deduplicates on it. Claiming exactly-once would be a lie the
// receiver discovers in production, usually twice.
//
// **Authenticity.** Every delivery is signed with a timestamped HMAC, so a receiver can prove
// the request came from this service and that it is not a replay of an old body. A bare HMAC
// over the body proves authorship but not freshness: an attacker who captures one delivery can
// resend it forever, and a receiver that only checks the signature accepts every copy.
//
// # What a receiver needs to do, in full
//
//  1. Verify the signature over `timestamp + "." + body` with the endpoint's secret.
//  2. Reject a timestamp outside the tolerance window, which is what makes replay fail.
//  3. Deduplicate on the event id, because redelivery is expected rather than exceptional.
//
// Step 3 is not optional and is documented here rather than only in the delivery semantics,
// because a receiver that skips it will process a duplicate payment notification the first time
// a worker restarts mid-delivery.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// Events this service can emit.
//
// The set is closed and enumerated so registration can be validated against it: an endpoint
// subscribed to a typo would look correct and silently never fire, and the tenant would
// discover it as a missing integration rather than as an error.
const (
	EventInvoiceCreated = "invoice.created"
	EventInvoiceIssued  = "invoice.issued"
	EventInvoicePaid    = "invoice.paid"
	EventInvoiceVoided  = "invoice.voided"
)

// Events is the catalogue, with a description for each so a registration endpoint can tell a
// tenant what they are subscribing to.
var Events = map[string]string{
	EventInvoiceCreated: "An invoice was created as a draft.",
	EventInvoiceIssued:  "A draft invoice was issued and its amounts froze.",
	EventInvoicePaid:    "An invoice was settled.",
	EventInvoiceVoided:  "An invoice was voided.",
}

// SignatureHeader, EventHeader, and IDHeader are the headers a receiver reads.
//
// They are constants because a receiver hard-codes them, and a rename would be a breaking change
// for every integration — so the names belong somewhere a rename is visible in a diff.
const (
	SignatureHeader = "Webhook-Signature"
	EventHeader     = "Webhook-Event"
	IDHeader        = "Webhook-Id"

	// AttemptHeader is informational: a receiver seeing attempt 4 knows the delivery has been
	// failing and can drop it rather than process it late. It is not a security control.
	AttemptHeader = "Webhook-Attempt"
)

// Delivery limits.
const (
	// MaxAttempts is one initial delivery plus five retries, matching the schedule below.
	MaxAttempts = 6

	// DeliveryTimeout bounds one attempt. A receiver that has not acknowledged in ten seconds
	// is treated as failed: the retry exists precisely because that receiver may be healthy
	// again in a minute, and waiting longer only delays the retry that would succeed.
	DeliveryTimeout = 10 * time.Second

	// LeaseDuration is how long a worker owns a row it has claimed.
	//
	// It must exceed DeliveryTimeout by a margin, or a slow-but-alive worker has its row
	// reclaimed underneath it and the receiver gets the delivery twice — turning a timing
	// decision into a duplicate.
	LeaseDuration = 60 * time.Second

	// SignatureTolerance is how far from now a signature timestamp may be.
	//
	// Five minutes is the usual compromise: long enough for clock skew between hosts, short
	// enough that a captured request is useless within the hour. This is what makes a signature
	// resistant to replay rather than merely to forgery.
	SignatureTolerance = 5 * time.Minute

	// MaxPayloadBytes bounds a stored event body.
	MaxPayloadBytes = 64 << 10

	// DefaultPageSize and MaxPageSize bound a delivery listing.
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// backoffSchedule is the nominal delay before each retry, indexed by the number of failures so
// far. The last entry is repeated if MaxAttempts is ever raised without extending the schedule,
// which is a deliberate choice: repeating an hour beats indexing past the end.
var backoffSchedule = []time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	5 * time.Minute,
	1 * time.Hour,
}

// NominalBackoff is the delay before retry number failedAttempt, without jitter.
func NominalBackoff(failedAttempt int) time.Duration {
	if failedAttempt <= 0 {
		return 0
	}
	i := failedAttempt - 1
	if i >= len(backoffSchedule) {
		i = len(backoffSchedule) - 1
	}
	return backoffSchedule[i]
}

// NextDelay returns the delay before the next attempt, with jitter, and whether attempts remain.
//
// # Why jitter is not optional
//
// A fixed schedule synchronises retries. A receiver that briefly fails takes every webhook from
// every tenant down with it, and they all come back at exactly 1s, then exactly 5s, then exactly
// 30s — a thundering herd that arrives precisely when the receiver is trying to recover. The
// retry mechanism then amplifies the failure it exists to survive.
//
// # Why the jitter is fractional rather than full
//
// jitterFraction ∈ [0,1] is supplied by the caller rather than drawn here, so the schedule is
// testable without seeding a generator, and the randomness lives where the clock does. The delay
// is between 50% and 100% of the nominal value: enough spread to break synchronisation, while
// keeping the schedule's shape — an operator reading "retries back off to an hour" is not
// surprised by a retry at 4 minutes.
func NextDelay(failedAttempt int, jitterFraction float64) (time.Duration, bool) {
	if failedAttempt >= MaxAttempts {
		return 0, false
	}
	nominal := NominalBackoff(failedAttempt)
	if nominal == 0 {
		return 0, true
	}
	if jitterFraction < 0 {
		jitterFraction = 0
	}
	if jitterFraction > 1 {
		jitterFraction = 1
	}
	// 0.5 + 0.5f, so the result is in [50%, 100%] of nominal.
	scaled := float64(nominal) * (0.5 + 0.5*jitterFraction)
	return time.Duration(math.Round(scaled)), true
}

// Endpoint is a tenant's registered receiver.
type Endpoint struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	URL         string
	Events      []string
	Description string
	Active      bool

	// Attribution, exactly one of which is set — enforced by the database rather than by
	// convention. A human registration records the user, a machine registration records the
	// key, and the column pair exists so an endpoint cannot exist with no identifiable author.
	//
	// This matters more here than for most resources: a webhook endpoint is an outbound request
	// to a URL the tenant chooses, which is the shape of an exfiltration channel. When one is
	// found pointing at a host it should not, "which credential registered this?" is the first
	// question asked, and it is unanswerable if the column is null.
	CreatedBy    *uuid.UUID
	CreatedByKey *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Delivery is one queued event, as the API reports it.
//
// Payload is the frozen body. Secret and URL belong to the endpoint, not the delivery, and are
// deliberately absent — an operator reading a delivery history does not need the signing key,
// and returning it would put it in every log and screenshot of the list endpoint.
//
// The ids are uuid.UUID rather than string, matching every other domain type here. Conversion
// happens at the wire boundary; a string id inside the domain is how a lookup starts comparing
// text to a uuid column and a pagination cursor silently stops matching.
type Delivery struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	EndpointID  uuid.UUID
	Event       string
	State       string
	Attempts    int
	Replays     int
	NextAt      time.Time
	LastError   string
	LastStatus  int
	DeliveredAt *time.Time
	CreatedAt   time.Time
}

// States.
const (
	StatePending    = "pending"
	StateDelivering = "delivering"
	StateDelivered  = "delivered"
	StateDead       = "dead"
)

// CreateInput is a registration request.
type CreateInput struct {
	URL         string
	Events      []string
	Description string
}

// UpdateInput changes a registration. Both fields are optional, and a nil pointer means "leave
// unchanged" — the same convention as the project update, where the distinction between an
// omitted field and an empty one matters.
type UpdateInput struct {
	Events      *[]string
	Description *string
	Active      *bool
}

// ValidateCreate checks a registration and normalises it.
//
// It does not resolve the URL: that needs the SSRF guard and a context, so the caller does it.
// Keeping DNS out of a pure validation function is what makes this testable without a network.
func ValidateCreate(in CreateInput) (CreateInput, error) {
	in.URL = strings.TrimSpace(in.URL)
	if err := ValidateURLSyntax(in.URL); err != nil {
		return CreateInput{}, err
	}

	events, err := ValidateEvents(in.Events)
	if err != nil {
		return CreateInput{}, err
	}
	in.Events = events

	in.Description = strings.TrimSpace(in.Description)
	if len(in.Description) > 500 {
		return CreateInput{}, apperr.Invalid("description", "must be at most 500 characters")
	}
	return in, nil
}

// ValidateURLSyntax checks the shape of a webhook URL.
//
// Shape only — reachability is the SSRF guard's job and needs a resolver. This function exists
// so an obviously malformed URL is refused without a DNS lookup, and so the two checks are
// separable in tests.
func ValidateURLSyntax(rawURL string) error {
	if rawURL == "" {
		return apperr.Invalid("url", "is required")
	}
	if len(rawURL) > 2048 {
		return apperr.Invalid("url", "must be at most 2048 characters")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return apperr.Invalid("url", "is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return apperr.Invalid("url", "must use http or https")
	}
	if u.Hostname() == "" {
		return apperr.Invalid("url", "must include a host")
	}
	if u.Fragment != "" {
		// A fragment is never sent to a server, so a URL containing one is a sign the tenant
		// pasted something that does not mean what they think.
		return apperr.Invalid("url", "must not include a fragment")
	}
	if u.User != nil {
		// Credentials in a URL would be stored in plaintext and sent in the clear on every
		// delivery; a receiver that authenticates should do it on the signature, not on a
		// userinfo component.
		return apperr.Invalid("url", "must not embed credentials")
	}
	return nil
}

// ValidateEvents checks and normalises an event subscription.
//
// Duplicates are removed rather than refused: a client that lists an event twice means it once,
// and failing the request would be pedantry. An *unknown* event is refused, because that one is
// a silent failure — the endpoint would look registered and never fire.
func ValidateEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, apperr.Invalid("events", "must name at least one event")
	}
	if len(events) > 32 {
		return nil, apperr.Invalid("events", "must name at most 32 events")
	}

	seen := make(map[string]bool, len(events))
	out := make([]string, 0, len(events))
	for _, e := range events {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, apperr.Invalid("events", "must not contain an empty entry")
		}
		if _, ok := Events[e]; !ok {
			return nil, apperr.Invalid("events", fmt.Sprintf("unknown event %q", e))
		}
		if seen[e] {
			continue
		}
		seen[e] = true
		out = append(out, e)
	}
	return out, nil
}

// GenerateSecret returns a new signing secret.
//
// The whsec_ prefix is not decoration: a secret that leaks into a log, a screenshot, or a commit
// is only recognisable as one if it is identifiable at a glance. Every secret scanning tool in
// use keys on exactly this kind of prefix.
//
// 32 bytes of crypto/rand, base64url-encoded so it survives being pasted into a config file or a
// URL without escaping.
func GenerateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("webhook: generate secret: %w", err)
	}
	return "whsec_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// ValidateSecret checks a stored secret's shape, so a mangled one is caught at registration
// rather than as a signature mismatch nobody can explain.
func ValidateSecret(secret string) error {
	if !strings.HasPrefix(secret, "whsec_") {
		return errors.New("webhook: secret must start with whsec_")
	}
	raw := strings.TrimPrefix(secret, "whsec_")
	if len(raw) < 32 || len(raw) > 128 {
		return errors.New("webhook: secret body must be between 32 and 128 characters")
	}
	if _, err := base64.RawURLEncoding.DecodeString(raw); err != nil {
		return errors.New("webhook: secret body is not valid base64url")
	}
	return nil
}

// digestFor computes the hex HMAC over `<timestamp>.<body>`.
//
// The timestamp is inside the MAC, and that is the whole design: signing the body alone proves
// authorship but not freshness, so a captured delivery could be replayed forever and every copy
// would verify. Including it means a replay outside the tolerance window fails its own check.
//
// Sign, Verify, and the tests all go through this one function, so there is a single
// implementation of the scheme — two would be two chances for a receiver's independent
// implementation to agree with one and not the other.
func digestFor(secret string, unixTimestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(mac, "%d.", unixTimestamp)
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Sign produces the value of the signature header.
//
// The format is `t=<unix seconds>,v1=<hex hmac>`. The version prefix leaves room to rotate the
// algorithm without a flag day: a receiver switches on `v1` and ignores versions it does not
// implement, and both can be sent during a migration.
func Sign(secret string, timestamp time.Time, body []byte) string {
	return fmt.Sprintf("t=%d,v1=%s", timestamp.Unix(), digestFor(secret, timestamp.Unix(), body))
}

// ParseSignature reads a signature header into its timestamp and digest.
//
// It is exported because a receiver implementing the same scheme needs the shape, and because
// the tests assert against the parse rather than against string formatting.
func ParseSignature(header string) (timestamp int64, digest string, err error) {
	var haveT, haveV1 bool
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "t="):
			raw := strings.TrimPrefix(part, "t=")
			// ParseInt, not ParseDuration.
			//
			// The first version of this appended "s" and called time.ParseDuration, which accepts
			// far more than an integer: "t=1h30m" becomes the string "1h30ms", parses as 3600.03
			// seconds, and truncates to 3600 — so a malformed timestamp was silently accepted as
			// a valid one. On a path whose failure mode is a forged delivery, "accepts more than
			// it should" is the wrong direction to be wrong in.
			parsed, convErr := strconv.ParseInt(raw, 10, 64)
			if convErr != nil {
				return 0, "", errors.New("webhook: signature timestamp is not an integer")
			}
			timestamp = parsed
			haveT = true
		case strings.HasPrefix(part, "v1="):
			digest = strings.TrimPrefix(part, "v1=")
			haveV1 = true
		}
	}
	if !haveT {
		return 0, "", errors.New("webhook: signature has no timestamp")
	}
	if !haveV1 {
		return 0, "", errors.New("webhook: signature has no v1 digest")
	}
	return timestamp, digest, nil
}

// Verify checks a signature header against a body.
//
// It exists in the library — rather than only in the test — because delivery semantics documented
// in prose and implemented nowhere are how a receiver ends up checking the signature but not the
// timestamp. The test suite uses it, so the verification path is exercised rather than described.
//
// The comparison is hmac.Equal, which is constant-time: a byte-by-byte compare leaks the digest a
// prefix at a time, and an attacker with enough attempts can forge a signature without the key.
func Verify(secret, header string, body []byte, now time.Time, tolerance time.Duration) error {
	timestamp, gotHex, err := ParseSignature(header)
	if err != nil {
		return err
	}

	skew := now.Sub(time.Unix(timestamp, 0))
	if skew < 0 {
		skew = -skew
	}
	if skew > tolerance {
		return fmt.Errorf("webhook: signature is %s old, outside the %s tolerance",
			skew.Round(time.Second), tolerance)
	}

	// The digest is computed directly rather than recovered by re-parsing a generated header.
	// The first version did the latter, which added a second parse of a string this code had
	// just built — extra machinery on the one path where being wrong means accepting a forgery.
	got, err := hex.DecodeString(gotHex)
	if err != nil {
		return errors.New("webhook: signature digest is not hex")
	}
	want, err := hex.DecodeString(digestFor(secret, timestamp, body))
	if err != nil {
		return errors.New("webhook: computed digest is not hex")
	}
	if !hmac.Equal(got, want) {
		return errors.New("webhook: signature does not match")
	}
	return nil
}

// Envelope is the JSON body a receiver receives.
//
// The event id is in the body as well as in a header, because a receiver that logs the payload
// and not the headers — which is most of them — would otherwise have no key to deduplicate on.
type Envelope struct {
	ID        string    `json:"id"`
	Event     string    `json:"event"`
	CreatedAt time.Time `json:"created_at"`
	TenantID  string    `json:"tenant_id"`
	Data      any       `json:"data"`
}

// NormalizePageSize clamps a requested page size into range.
func NormalizePageSize(requested int) int {
	switch {
	case requested <= 0:
		return DefaultPageSize
	case requested > MaxPageSize:
		return MaxPageSize
	default:
		return requested
	}
}

// NormalizeState validates a delivery-state filter, returning "" for "any".
func NormalizeState(raw string) (string, error) {
	switch raw {
	case "":
		return "", nil
	case StatePending, StateDelivering, StateDelivered, StateDead:
		return raw, nil
	default:
		return "", apperr.Invalid("state", "must be one of pending, delivering, delivered, dead")
	}
}

// ErrNotFound is returned when a delivery or endpoint does not exist or is not visible to the
// caller. The two are never distinguished: doing so would turn an id guess into an existence
// oracle, the same rule as every other tenant-scoped resource.
var ErrNotFound = errors.New("webhook: not found")

// ErrNotDead is returned when replay is attempted on a delivery that is not in the DLQ.
//
// It is distinct from ErrNotFound because the client's action differs: not-found means the id is
// wrong, while this means the delivery exists and does not need replaying. Re-queuing a pending
// or delivered row would either duplicate an in-flight delivery or resend one the receiver
// already acknowledged.
var ErrNotDead = errors.New("webhook: only a dead delivery can be replayed")
