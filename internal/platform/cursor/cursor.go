// Package cursor implements the keyset pagination tokens used by list endpoints.
//
// # Why keyset rather than offset
//
// OFFSET n makes the database walk and discard n rows to return the next page, so
// deep pages cost proportionally more for the same amount of useful work. Worse,
// it is not correct: rows inserted or deleted between two requests shift the
// window, so a client paging through a live table can see the same row twice or
// miss one entirely, with no way to detect it.
//
// A keyset cursor instead asks for "rows strictly older than this specific row",
// which is a predicate the index can seek to and which does not move when other
// rows are inserted. New rows sort after the cursor position, so they appear on a
// later page or not at all — never in the middle of a page the client already read.
//
// # What the signature is for, and what it is not for
//
// A cursor is signed with HMAC-SHA256 and bound to the query that produced it.
// That buys two things, and deliberately not a third:
//
//   - Integrity. A truncated or hand-edited cursor fails loudly with a specific
//     error, instead of silently returning a differently-shaped page that looks
//     like data loss to the client.
//   - Query binding. A cursor minted for one tenant's project list cannot be
//     replayed against another tenant's list, or against the same tenant with
//     different filters, because the binding is covered by the signature. The
//     resulting page would otherwise be subtly wrong rather than obviously
//     rejected.
//
// It is *not* an authorization mechanism. A cursor grants no access; it only
// names a position in a listing that the caller is independently authorized to
// read, and row-level security plus the tenant gate still decide what rows exist
// for that caller. Treating a signed cursor as a capability would be a category
// error — which is why cursors carry no expiry: a stale cursor from last week is
// simply a position, and re-reading from it is harmless.
package cursor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The three ways a cursor can be rejected. They are kept distinct because they
// need different reactions from whoever is writing the client: a malformed token
// is a bug in how it was stored, a signature failure means it was altered in
// transit or by hand, and a binding mismatch usually means it was carried across
// a filter change — which is a client-side state bug, not an attack.
var (
	ErrMalformed = errors.New("cursor: malformed")
	ErrSignature = errors.New("cursor: signature does not verify")
	ErrBinding   = errors.New("cursor: does not belong to this query")
)

// minKeyLen is the HMAC key length floor. Keys shorter than the hash output add
// no strength, and HMAC accepts them silently, so a too-short key would produce
// tokens that verify correctly and are forgeable.
const minKeyLen = 32

// DeriveKey derives a cursor-signing key from a base secret.
//
// It exists so a deployment can have one secret to manage while the cursor key
// remains independent of the access-token key. Reusing the token secret directly
// would mean a signature from one mechanism is a valid signature for the other —
// key separation by domain, using HMAC itself as the KDF, which is the standard
// construction for this (HKDF-expand without extract, since the base secret is
// already high-entropy).
func DeriveKey(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("tenant-api-platform/cursor/v1"))
	return mac.Sum(nil)
}

// Binding identifies the query a cursor belongs to.
//
// It is hashed into the signed payload rather than stored in clear, so the token
// does not reveal a tenant id to anyone who sees it — a cursor ends up in URLs, and
// URLs end up in logs and browser history.
type Binding struct {
	TenantID uuid.UUID
	Resource string
	// Filter is a canonical, stable rendering of the query's filter set. It must
	// not vary with parameter order or formatting, or valid cursors will be
	// rejected as mismatched.
	Filter string
}

func (b Binding) fingerprint() string {
	h := sha256.New()
	fmt.Fprintf(h, "v1\x00%s\x00%s\x00%s", b.TenantID, b.Resource, b.Filter)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Position is a place in a listing, ordered by (created_at, id).
//
// The id is part of the key rather than a tiebreaker convenience: two rows can
// share a timestamp (bulk inserts, coarse clocks), and without the id the page
// boundary would be ambiguous and could skip or repeat a row.
type Position struct {
	Time time.Time
	ID   uuid.UUID
}

// String renders a position for logs.
func (p Position) String() string {
	return fmt.Sprintf("%s/%s", p.Time.UTC().Format(time.RFC3339Nano), p.ID)
}

// Codec encodes and decodes cursors under one key.
type Codec struct{ key []byte }

// NewCodec builds a codec. key must be at least minKeyLen bytes; see DeriveKey.
func NewCodec(key []byte) (*Codec, error) {
	if len(key) < minKeyLen {
		return nil, fmt.Errorf("cursor: key must be at least %d bytes, got %d", minKeyLen, len(key))
	}
	return &Codec{key: append([]byte(nil), key...)}, nil
}

// encoded is the wire shape of a cursor payload.
//
// Field names are one character each to keep tokens short — they travel in query
// strings on every page request.
type encoded struct {
	T int64     `json:"t"` // timestamp, microseconds since the Unix epoch
	I uuid.UUID `json:"i"`
	B string    `json:"b"` // binding fingerprint
}

// Encode renders a signed cursor for a position within a bound query.
func (c *Codec) Encode(b Binding, p Position) (string, error) {
	if p.ID == uuid.Nil {
		return "", fmt.Errorf("cursor: refusing to encode a nil position id: %w", ErrMalformed)
	}
	raw, err := json.Marshal(encoded{T: p.Time.UTC().UnixMicro(), I: p.ID, B: b.fingerprint()})
	if err != nil {
		return "", fmt.Errorf("cursor: marshal payload: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + c.sign(body), nil
}

// Decode verifies a token and returns the position it names.
//
// The signature is checked before the payload is parsed. That order matters: it
// means a malformed payload can only be reported as malformed after the signature
// has proven the payload was produced by this service, so error messages never
// describe attacker-supplied bytes.
func (c *Codec) Decode(b Binding, token string) (Position, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok || body == "" || sig == "" {
		return Position{}, ErrMalformed
	}

	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Position{}, ErrMalformed
	}
	// Reject non-canonical encodings before comparing. base64 has several valid
	// spellings of the same bytes (padding, and for RawURLEncoding trailing bits),
	// so without this check a token with a re-encoded signature would compare
	// equal to a freshly signed one — which is a forgery vector, because the
	// re-encoding is not covered by the MAC.
	if base64.RawURLEncoding.EncodeToString(want) != sig {
		return Position{}, ErrMalformed
	}

	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(body))
	// hmac.Equal is constant-time. A byte-wise comparison would leak, through
	// timing, how much of a forged signature is correct — which is enough to
	// recover a valid one a byte at a time.
	if !hmac.Equal(mac.Sum(nil), want) {
		return Position{}, ErrSignature
	}

	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Position{}, ErrMalformed
	}
	var p encoded
	if err := json.Unmarshal(raw, &p); err != nil {
		return Position{}, ErrMalformed
	}
	if p.I == uuid.Nil {
		return Position{}, ErrMalformed
	}
	if p.B != b.fingerprint() {
		return Position{}, ErrBinding
	}

	return Position{Time: time.UnixMicro(p.T).UTC(), ID: p.I}, nil
}

// sign returns the base64url HMAC of a payload body.
func (c *Codec) sign(body string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
