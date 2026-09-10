package cursor

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testCodec(t *testing.T) *Codec {
	t.Helper()
	key := DeriveKey([]byte("0123456789abcdef0123456789abcdef"))
	c, err := NewCodec(key)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

func testBinding() Binding {
	return Binding{
		TenantID: uuid.Must(uuid.NewV7()),
		Resource: "projects",
		Filter:   "archived=false",
	}
}

// TestDeriveKey_IsSeparatedFromTheBaseSecret proves the cursor key is not the
// secret it was derived from.
//
// If DeriveKey returned the input, a cursor signature and an access-token
// signature would be signatures under the same key — so a token minted by one
// mechanism would verify in the other, and a leak of either would compromise both.
// Domain separation by HMAC is the reason this function exists at all.
func TestDeriveKey_IsSeparatedFromTheBaseSecret(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	derived := DeriveKey(secret)

	if string(derived) == string(secret) {
		t.Fatal("DeriveKey returned its input; the cursor key is not separated from the base secret")
	}
	if len(derived) != 32 {
		t.Fatalf("derived key is %d bytes, want 32", len(derived))
	}

	// Deterministic, so a restart does not invalidate every in-flight cursor.
	if string(DeriveKey(secret)) != string(derived) {
		t.Fatal("DeriveKey is not deterministic; cursors would break on restart")
	}

	// Different base secrets must produce different derived keys.
	if string(DeriveKey([]byte("ffffffffffffffffffffffffffffffff"))) == string(derived) {
		t.Fatal("two different base secrets produced the same cursor key")
	}
}

// TestNewCodec_RejectsShortKey proves the key length floor. HMAC accepts any key
// length, so a short key would produce cursors that verify correctly and are
// forgeable — the worst combination, because nothing looks wrong.
func TestNewCodec_RejectsShortKey(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31} {
		if _, err := NewCodec(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte key was accepted, want rejection (minimum is %d)", n, minKeyLen)
		}
	}
	if _, err := NewCodec(make([]byte, 32)); err != nil {
		t.Fatalf("a 32-byte key was rejected: %v", err)
	}
}

// TestEncodeDecode_RoundTrip is the basic contract.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	c := testCodec(t)
	b := testBinding()

	original := Position{Time: time.Now().UTC().Truncate(time.Microsecond), ID: uuid.Must(uuid.NewV7())}
	token, err := c.Encode(b, original)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	got, err := c.Decode(b, token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Time.Equal(original.Time) {
		t.Fatalf("time = %s, want %s", got.Time, original.Time)
	}
	if got.ID != original.ID {
		t.Fatalf("id = %s, want %s", got.ID, original.ID)
	}
}

// TestEncode_IsDeterministic documents that a cursor is a value, not a nonce.
// Two encodes of the same position produce the same token, which is what lets a
// client safely retry a page request.
func TestEncode_IsDeterministic(t *testing.T) {
	c := testCodec(t)
	b := testBinding()
	p := Position{Time: time.Unix(1_700_000_000, 0).UTC(), ID: uuid.Must(uuid.NewV7())}

	first, err := c.Encode(b, p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	second, err := c.Encode(b, p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if first != second {
		t.Fatalf("encoding the same position twice produced different cursors:\n%s\n%s", first, second)
	}
}

// TestEncode_RejectsNilPosition stops a cursor that names no row from existing.
// Paginating from a nil id would compare against NULL and silently return the
// first page again, which presents as an infinite loop rather than an error.
func TestEncode_RejectsNilPosition(t *testing.T) {
	c := testCodec(t)
	if _, err := c.Encode(testBinding(), Position{Time: time.Now(), ID: uuid.Nil}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("error = %v, want ErrMalformed", err)
	}
}

// TestDecode_RejectsTamperedPayload proves the signature covers the payload.
//
// The mutation is applied to the decoded JSON and then re-encoded, so the token
// is structurally valid base64 and would parse successfully if the signature were
// not checked. A test that corrupted the base64 instead would pass for the wrong
// reason.
func TestDecode_RejectsTamperedPayload(t *testing.T) {
	c := testCodec(t)
	b := testBinding()

	token, err := c.Encode(b, Position{Time: time.Now(), ID: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	body, sig, _ := strings.Cut(token, ".")

	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	// Swap the position id for a different one, keeping the JSON shape valid.
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload["i"] = uuid.Must(uuid.NewV7()).String()
	mutated, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	forged := base64.RawURLEncoding.EncodeToString(mutated) + "." + sig
	if _, err := c.Decode(b, forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("a payload swapped under a valid signature was accepted (err = %v)", err)
	}
}

// TestDecode_RejectsNonCanonicalSignature covers a forgery vector that a naive
// implementation misses.
//
// base64 has more than one spelling for the same bytes: in a 43-character
// encoding of a 32-byte MAC, the final character carries four bits of data and two
// unused bits, so several final characters decode to the identical MAC. A
// comparison that decodes first and compares bytes therefore accepts all of those
// spellings — and since the re-encoding is not covered by the MAC, an attacker can
// rewrite a signature's trailing character (or a capture/replay proxy can) without
// invalidating it.
//
// The codec guards this by re-encoding the decoded signature and requiring an
// exact match with what was presented.
func TestDecode_RejectsNonCanonicalSignature(t *testing.T) {
	c := testCodec(t)
	b := testBinding()

	token, err := c.Encode(b, Position{Time: time.Now(), ID: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	body, sig, _ := strings.Cut(token, ".")

	want, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	// Find a spelling of the same bytes that differs from the canonical one.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var variant string
	for i := 0; i < len(alphabet); i++ {
		candidate := sig[:len(sig)-1] + string(alphabet[i])
		if candidate == sig {
			continue
		}
		got, err := base64.RawURLEncoding.DecodeString(candidate)
		if err == nil && string(got) == string(want) {
			variant = candidate
			break
		}
	}
	if variant == "" {
		// Not every MAC has an alternate spelling; the two unused trailing bits
		// must be zero in a canonical encoding, and if they happen to be non-zero
		// Go's decoder rejects every variant. Regenerating a token until the
		// condition holds is possible but would make this test flaky, so it is
		// skipped honestly rather than randomised.
		t.Skip("this signature has no non-canonical spelling to test against")
	}

	if _, err := c.Decode(b, body+"."+variant); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a non-canonical signature encoding was accepted (err = %v): the MAC is being compared "+
			"after decoding, so any spelling of the same bytes verifies", err)
	}
}

// TestDecode_RejectsWrongBinding covers query binding, which is what stops a
// cursor from being carried across a filter change or a tenant switch.
//
// The failure this prevents is silent rather than loud: without binding, a cursor
// minted for "all projects" replayed against "archived only" would return a page
// starting at an arbitrary position, and the client would see a gap it cannot
// detect.
func TestDecode_RejectsWrongBinding(t *testing.T) {
	c := testCodec(t)
	original := testBinding()

	token, err := c.Encode(original, Position{Time: time.Now(), ID: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	cases := []struct {
		name string
		b    Binding
	}{
		{"different tenant", Binding{TenantID: uuid.Must(uuid.NewV7()), Resource: original.Resource, Filter: original.Filter}},
		{"different resource", Binding{TenantID: original.TenantID, Resource: "invoices", Filter: original.Filter}},
		{"different filter", Binding{TenantID: original.TenantID, Resource: original.Resource, Filter: "archived=true"}},
		{"empty binding", Binding{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.Decode(tc.b, token); !errors.Is(err, ErrBinding) {
				t.Fatalf("error = %v, want ErrBinding", err)
			}
		})
	}

	// Control: the original binding must still work, so the rejections above are
	// attributable to the binding rather than to a broken token.
	if _, err := c.Decode(original, token); err != nil {
		t.Fatalf("the cursor was rejected under its own binding: %v", err)
	}
}

// TestDecode_RejectsMalformed covers the scanner-shaped inputs. Each must be an
// ordinary rejection, and none may panic.
func TestDecode_RejectsMalformed(t *testing.T) {
	c := testCodec(t)
	b := testBinding()

	valid, err := c.Encode(b, Position{Time: time.Now(), ID: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	body, _, _ := strings.Cut(valid, ".")

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformed},
		{"single segment", "abcdef", ErrMalformed},
		{"empty body", "." + "sig", ErrMalformed},
		{"empty signature", body + ".", ErrMalformed},
		{"dot only", ".", ErrMalformed},
		{"body is not base64", "!!!not-base64!!!." + "sig", ErrMalformed},
		{"body is not json", base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + "sig", ErrSignature},
		{"truncated body", body[:len(body)-4] + "." + "sig", ErrSignature},
		{"signature is not base64", body + ".!!!!", ErrMalformed},
		{"nil position in payload", base64.RawURLEncoding.EncodeToString([]byte(`{"t":1,"i":"00000000-0000-0000-0000-000000000000","b":"x"}`)) + ".sig", ErrSignature},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The signature is verified before the payload is parsed, so most of
			// these fail as ErrSignature rather than ErrMalformed. What matters is
			// that each is rejected with one of the two, never accepted and never
			// a panic.
			_, err := c.Decode(b, tc.token)
			if err == nil {
				t.Fatal("malformed cursor was accepted")
			}
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrSignature) {
				t.Fatalf("error = %v, want ErrMalformed or ErrSignature", err)
			}
		})
	}
}

// TestDecode_RejectsCursorFromAnotherKey proves key separation between
// deployments: a cursor minted under a different secret must not verify, so a
// staging cursor replayed against production is a clean rejection rather than a
// silent page starting at an arbitrary row.
func TestDecode_RejectsCursorFromAnotherKey(t *testing.T) {
	other, err := NewCodec(DeriveKey([]byte("ffffffffffffffffffffffffffffffff")))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	mine := testCodec(t)
	b := testBinding()

	token, err := other.Encode(b, Position{Time: time.Now(), ID: uuid.Must(uuid.NewV7())})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if _, err := mine.Decode(b, token); !errors.Is(err, ErrSignature) {
		t.Fatalf("a cursor signed with a different key was accepted (err = %v)", err)
	}
}

// TestDecode_IsIndependentOfCodecInstance proves a cursor survives a restart of
// the service, which matters because a client may be paginating across a deploy.
func TestDecode_IsIndependentOfCodecInstance(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	first, err := NewCodec(DeriveKey(secret))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	second, err := NewCodec(DeriveKey(secret))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	b := testBinding()
	p := Position{Time: time.Unix(1_700_000_000, 0).UTC(), ID: uuid.Must(uuid.NewV7())}

	token, err := first.Encode(b, p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := second.Decode(b, token)
	if err != nil {
		t.Fatalf("a cursor did not survive a new codec instance: %v", err)
	}
	if got.ID != p.ID || !got.Time.Equal(p.Time) {
		t.Fatal("the decoded position differs from the encoded one")
	}
}

// TestFingerprint_IsStableAndDistinct guards the binding's canonical form. The
// fingerprint is computed from fields rather than from a concatenation, so a
// tenant id containing the separator byte cannot forge another tenant's binding.
func TestFingerprint_IsStableAndDistinct(t *testing.T) {
	tenantA := uuid.Must(uuid.NewV7())
	tenantB := uuid.Must(uuid.NewV7())

	base := Binding{TenantID: tenantA, Resource: "projects", Filter: "archived=false"}
	if base.fingerprint() != base.fingerprint() {
		t.Fatal("fingerprint is not stable")
	}
	if base.fingerprint() == "" {
		t.Fatal("fingerprint is empty")
	}

	distinct := []Binding{
		{TenantID: tenantB, Resource: "projects", Filter: "archived=false"},
		{TenantID: tenantA, Resource: "projects2", Filter: "archived=false"},
		{TenantID: tenantA, Resource: "projects", Filter: "archived=false "},
		{TenantID: tenantA, Resource: "projects", Filter: ""},
	}
	for _, other := range distinct {
		if other.fingerprint() == base.fingerprint() {
			t.Errorf("bindings collided: %+v and %+v", base, other)
		}
	}
}
