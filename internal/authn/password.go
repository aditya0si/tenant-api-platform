// Package authn covers credential handling: password hashing and verification,
// and the user store.
//
// It deliberately contains no HTTP and no session logic; JWT issuance and
// refresh-family rotation arrive in M2 and live beside this code rather than
// inside it.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the cost parameters for password hashing.
//
// Defaults follow the OWASP recommendation for argon2id (64 MiB, t=1, p=4) and
// are a package variable rather than constants so tests can lower the cost: a
// suite that spends a second per fixture on key derivation is a suite people
// stop running. Production code never mutates it.
type Argon2Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// Params is the active cost configuration.
var Params = Argon2Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  1,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// ErrInvalidHash is returned when a stored hash is not a well-formed argon2id
// PHC string. It signals data corruption, not a bad password.
var ErrInvalidHash = errors.New("authn: malformed password hash")

// HashPassword derives an argon2id hash and returns it in PHC string format:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<base64 salt>$<base64 key>
//
// Encoding the parameters alongside the digest means cost can be raised later
// without invalidating existing hashes, and verification always uses the
// parameters the hash was created with (see VerifyPassword).
func HashPassword(password string) (string, error) {
	salt := make([]byte, Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("authn: read salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, Params.Iterations, Params.Memory, Params.Parallelism, Params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, Params.Memory, Params.Iterations, Params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// VerifyPassword reports whether password matches the PHC-encoded hash.
//
// The comparison is constant-time. Its cost parameters come from the stored
// hash, not from the current process defaults, so raising Params does not lock
// out existing users.
func VerifyPassword(encodedHash, password string) (bool, error) {
	params, salt, want, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func decodeHash(encodedHash string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}

	var p Argon2Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return Argon2Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))
	p.KeyLength = uint32(len(key))
	return p, salt, key, nil
}
