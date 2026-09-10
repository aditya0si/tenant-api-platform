package authn

import (
	"errors"
	"strings"
	"testing"
)

// withCheapParams lowers the argon2 cost for the duration of a test and
// restores it afterwards.
//
// The production parameters (64 MiB, so ~50-100 ms per derivation) are the point
// of argon2, but paying that in every case would make this file slow enough to
// discourage running it — and an untested password path is far worse than a
// slightly unreduced one. These tests are about correctness of encoding,
// comparison, and error handling, none of which depend on the cost.
func withCheapParams(t *testing.T) {
	t.Helper()
	original := Params
	Params = Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	t.Cleanup(func() { Params = original })
}

// TestHashPassword_VerifyRoundTrip is the basic contract: a password verifies
// against its own hash, and a different password does not.
func TestHashPassword_VerifyRoundTrip(t *testing.T) {
	withCheapParams(t)

	const password = "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword(hash, password)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("correct password did not verify")
	}

	for _, wrong := range []string{
		"correct horse battery stapl",  // truncated
		"Correct horse battery staple", // case differs
		"",
		"correct horse battery staple ", // trailing space
	} {
		ok, err := VerifyPassword(hash, wrong)
		if err != nil {
			t.Fatalf("VerifyPassword(%q): %v", wrong, err)
		}
		if ok {
			t.Fatalf("wrong password %q verified", wrong)
		}
	}
}

// TestHashPassword_SaltsAreUnique proves two hashes of the same password differ.
// Without a per-hash random salt, identical passwords produce identical digests,
// which turns a database leak into a rainbow-table lookup and reveals which users
// share a password.
func TestHashPassword_SaltsAreUnique(t *testing.T) {
	withCheapParams(t)

	const password = "same password both times"

	first, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if first == second {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}

	// Both must still verify — uniqueness of the encoding must not come at the
	// cost of correctness.
	for i, hash := range []string{first, second} {
		ok, err := VerifyPassword(hash, password)
		if err != nil {
			t.Fatalf("VerifyPassword(hash %d): %v", i, err)
		}
		if !ok {
			t.Fatalf("hash %d did not verify", i)
		}
	}
}

// TestHashPassword_Encoding pins the PHC format, because the format is a
// compatibility contract: hashes written by an older version of this code must
// keep verifying after the parameters change.
func TestHashPassword_Encoding(t *testing.T) {
	withCheapParams(t)

	hash, err := HashPassword("a-password-long-enough")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash does not start with the argon2id identifier: %q", hash)
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("hash has %d $-separated parts, want 6: %q", len(parts), hash)
	}
	if parts[2] != "v=19" {
		t.Fatalf("version field = %q, want v=19", parts[2])
	}
	if !strings.Contains(parts[3], "m=") || !strings.Contains(parts[3], "t=") || !strings.Contains(parts[3], "p=") {
		t.Fatalf("parameter field is missing a cost component: %q", parts[3])
	}
}

// TestVerifyPassword_UsesParamsFromHash is the property that makes cost
// migration possible without a flag day.
//
// The hash carries its own parameters, so raising the global cost does not lock
// out existing users: their old hashes keep verifying at the cost they were
// created with. If verification used the current process defaults instead, every
// stored password would break the moment the parameters were raised.
func TestVerifyPassword_UsesParamsFromHash(t *testing.T) {
	const password = "param migration is not a flag day"

	// Hash at a deliberately weak cost.
	original := Params
	Params = Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	oldHash, err := HashPassword(password)
	if err != nil {
		Params = original
		t.Fatalf("HashPassword: %v", err)
	}

	// Raise the cost, as a deployment would.
	Params = Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 16, KeyLength: 32}
	defer func() { Params = original }()

	ok, err := VerifyPassword(oldHash, password)
	if err != nil {
		t.Fatalf("VerifyPassword with raised params: %v", err)
	}
	if !ok {
		t.Fatal("a hash created at a lower cost stopped verifying after the cost was raised")
	}

	ok, err = VerifyPassword(oldHash, "not the password")
	if err != nil {
		t.Fatalf("VerifyPassword (wrong password): %v", err)
	}
	if ok {
		t.Fatal("wrong password verified against a lower-cost hash")
	}
}

// TestVerifyPassword_RejectsMalformedHashes covers the corruption path.
//
// A malformed stored hash is data corruption, not a wrong password: the two must
// be distinguishable by the caller, because one is a 500 with an operator
// alert and the other is a 401. Note in particular that an empty or garbage
// hash must not verify anything — a naive implementation that treats a parse
// failure as "no match" would also silently accept a truncated row.
func TestVerifyPassword_RejectsMalformedHashes(t *testing.T) {
	withCheapParams(t)

	cases := []struct {
		name string
		hash string
	}{
		{"empty", ""},
		{"not a phc string", "hunter2"},
		{"wrong algorithm", "$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$a2V5"},
		{"missing version", "$argon2id$m=8192,t=1,p=1$c2FsdA$a2V5"},
		{"unparseable params", "$argon2id$v=19$garbage$c2FsdA$a2V5"},
		{"zero cost parameters", "$argon2id$v=19$m=0,t=0,p=0$c2FsdA$a2V5"},
		{"bad base64 salt", "$argon2id$v=19$m=8192,t=1,p=1$!!!!$a2V5"},
		{"empty salt", "$argon2id$v=19$m=8192,t=1,p=1$$a2V5"},
		{"empty key", "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$"},
		{"truncated", "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA"},
		{"too many parts", "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$a2V5$extra"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyPassword(tc.hash, "any password")
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("error = %v, want ErrInvalidHash", err)
			}
			if ok {
				t.Fatal("a malformed hash verified; corruption must never authenticate")
			}
		})
	}
}

// TestValidatePasswordStrength pins the policy: length is the requirement,
// bounded at both ends.
//
// The upper bound is not arbitrary. argon2 hashes the whole input, so an
// unbounded password field is a cheap way to make the server do arbitrary work
// per request — a denial-of-service vector that costs the attacker nothing.
func TestValidatePasswordStrength(t *testing.T) {
	if err := ValidatePasswordStrength("twelve chars"); err != nil {
		t.Fatalf("12-character password rejected: %v", err)
	}
	if err := ValidatePasswordStrength(strings.Repeat("a", 1024)); err != nil {
		t.Fatalf("1024-character password rejected: %v", err)
	}

	for _, bad := range []string{"", "short", strings.Repeat("a", 11)} {
		if err := ValidatePasswordStrength(bad); err == nil {
			t.Fatalf("password of length %d accepted, want rejection", len(bad))
		}
	}
	if err := ValidatePasswordStrength(strings.Repeat("a", 1025)); err == nil {
		t.Fatal("oversized password accepted: unbounded hashing input is a DoS vector")
	}
}

// TestNormalizeEmail pins the normalization and the shape checks. The database
// enforces the same lowercase rule with a CHECK constraint; this exists so a bad
// address produces a clean validation error rather than a constraint violation
// surfaced as a 500.
func TestNormalizeEmail(t *testing.T) {
	got, err := NormalizeEmail("  Owner@ACME.Test  ")
	if err != nil {
		t.Fatalf("NormalizeEmail: %v", err)
	}
	if got != "owner@acme.test" {
		t.Fatalf("normalized = %q, want owner@acme.test", got)
	}

	for _, bad := range []string{
		"",
		"no-at-sign",
		"@acme.test",
		"owner@",
		"owner@localhost", // no dot in the domain: not fully qualified
		"a@b",
	} {
		if _, err := NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q) accepted, want rejection", bad)
		}
	}

	// A plus-addressed address is legal and must survive normalization: the local
	// part is not ours to rewrite.
	got, err = NormalizeEmail("Owner+Receipts@ACME.Test")
	if err != nil {
		t.Fatalf("plus-addressed email rejected: %v", err)
	}
	if got != "owner+receipts@acme.test" {
		t.Fatalf("normalized = %q, want owner+receipts@acme.test", got)
	}
}
