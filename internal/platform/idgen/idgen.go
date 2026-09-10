// Package idgen produces the short random tokens used in slugs and fixtures.
//
// # Why this package exists at all
//
// The obvious way to get a random suffix is to slice a UUID:
//
//	strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", "")[:6]
//
// That is wrong, and wrong in the worst way — it looks random and is not. A UUIDv7
// is not uniformly random: its first 48 bits (the first 12 hex characters) are a
// millisecond timestamp, and its 13th character is the constant version nibble. So
// every UUIDv7 minted inside the same millisecond shares those leading characters,
// and taking a prefix produces an identifier that repeats across calls instead of
// being unique.
//
// The failure mode is not a crash. It is a uniqueness constraint that starts
// rejecting valid requests a few seconds into a burst, which reads as "the retry
// logic is broken" and sends you looking in the wrong place. It also silently
// poisons test fixtures, whose "unique" addresses collide and make unrelated tests
// interfere.
//
// These functions take bytes from crypto/rand instead, so the output is uniform and
// the property they promise — that repeated calls do not repeat — actually holds.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// ShortSuffix returns n lowercase hex characters of cryptographic randomness.
//
// n is clamped to the range [1, 32] rather than trusted. A caller asking for 0 would
// receive an empty suffix, which silently turns "unique name" into "the same name
// every time" — the exact failure this package exists to prevent — and a caller
// asking for 100 would be given a truncated value whose length no longer matches
// what the call site assumed.
//
// The entropy is 4 bits per character: 6 characters is 24 bits, which is ample for
// disambiguating a human-readable slug, since a collision only matters against names
// already in use. It is not sufficient for a secret, and this function is not for
// that — credentials come from the dedicated generators in internal/authn, which use
// 256 bits and a distinct prefix.
func ShortSuffix(n int) string {
	if n < 1 {
		n = 1
	}
	if n > 32 {
		n = 32
	}

	// Reading ceil(n/2) bytes and hex-encoding yields exactly n characters: each
	// byte becomes two hex digits, so an odd n simply discards the final nibble.
	buf := make([]byte, (n+1)/2)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read only fails if the OS entropy source is unavailable, which
		// is not a condition any caller of this package could handle meaningfully.
		// The alternative — returning a timestamp-derived value — is precisely the
		// bug this package was written to remove, so a panic is the honest outcome:
		// it fails loudly at the first call rather than producing collisions under
		// load.
		panic("idgen: the system entropy source is unavailable: " + err.Error())
	}
	return hex.EncodeToString(buf)[:n]
}
