package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
)

const (
	// DefaultRefreshTTL is how long a session can be renewed without logging in
	// again. This is the real session lifetime; the access token's ten minutes
	// only bound how long a leaked access token stays usable.
	DefaultRefreshTTL = 30 * 24 * time.Hour

	// DefaultReuseGrace is the window in which re-presenting a just-consumed
	// refresh token is treated as a concurrent retry rather than theft.
	//
	// # The trade-off, stated plainly
	//
	// Strict rotation (grace = 0) is the most secure reading: a consumed token is
	// never accepted again, so replaying a stolen one revokes the family. It also
	// logs out any client that fires two refreshes at once — a tab restore plus a
	// timer, a retry after a timeout the server never saw — and users experience
	// that as "the app randomly signs me out".
	//
	// A short grace window accepts that same replay if it lands inside the
	// window, which is a genuine, if narrow, weakening: an attacker who steals a
	// token and replays it within seconds gets a working session. Outside the
	// window, replay still revokes the family.
	//
	// The window is a knob because the right value depends on the client fleet.
	// Ten seconds absorbs network retries without meaningfully widening the
	// replay opportunity, which is why it is the default here rather than
	// compiled in.
	DefaultReuseGrace = 10 * time.Second
)

// Refresh errors. All map to the same 401 for the client; they are distinguished
// internally because they mean different things operationally. ErrRefreshReused
// in particular is a security event worth alerting on, while ErrRefreshUnknown is
// usually just a stale client.
var (
	ErrRefreshUnknown   = errors.New("authn: refresh token not recognised")
	ErrRefreshExpired   = errors.New("authn: refresh token expired")
	ErrRefreshRevoked   = errors.New("authn: refresh family revoked")
	ErrRefreshReused    = errors.New("authn: refresh token replayed")
	ErrRefreshRetryRace = errors.New("authn: concurrent refresh retry")
)

// ReuseError reports that a consumed refresh token was presented again outside
// the retry grace window.
//
// It carries identity — which user, which family — because the moment this error
// is produced is the moment an operator needs those facts, and the ordinary
// return value is an empty TokenPair by then. A bare sentinel would force the
// caller either to give up the detail or to re-query for it in the middle of a
// security event; neither is acceptable.
type ReuseError struct {
	UserID   uuid.UUID
	FamilyID uuid.UUID

	// RevocationFailed is non-nil when the family could not be revoked after the
	// replay was detected. That is a strictly worse outcome than the replay
	// itself — the attacker's session is still live — so it is surfaced rather
	// than logged and swallowed.
	RevocationFailed error
}

func (e *ReuseError) Error() string {
	msg := fmt.Sprintf("refresh token replayed for user %s (family %s)", e.UserID, e.FamilyID)
	if e.RevocationFailed != nil {
		msg += fmt.Sprintf("; FAMILY REVOCATION FAILED: %v", e.RevocationFailed)
	}
	return msg
}

// Is makes errors.Is(err, ErrRefreshReused) true for a ReuseError, so ordinary
// callers can treat it as the sentinel while security-aware callers can recover
// the detail with errors.As.
func (e *ReuseError) Is(target error) bool { return target == ErrRefreshReused }

// Unwrap exposes the revocation failure to errors.Is/As chains.
func (e *ReuseError) Unwrap() error { return e.RevocationFailed }

// TokenPair is a freshly rotated refresh credential.
type TokenPair struct {
	// RefreshToken is the plaintext successor. It is returned to the client
	// exactly once, here; only its hash is stored, so it can never be recovered
	// from the database and can never be logged from a row.
	RefreshToken string
	UserID       uuid.UUID
	ExpiresAt    time.Time
}

// RefreshStore owns refresh-family persistence and rotation.
type RefreshStore struct {
	pool  *pgxpool.Pool
	grace time.Duration
	now   func() time.Time
}

// NewRefreshStore builds a store. grace is the reuse window described on
// DefaultReuseGrace; pass 0 for strict rotation.
func NewRefreshStore(pool *pgxpool.Pool, grace time.Duration) *RefreshStore {
	return &RefreshStore{pool: pool, grace: grace, now: time.Now}
}

// SetClock overrides the store's clock. It exists for tests, which need a token
// that expired an hour ago without waiting an hour; there is no production
// caller.
func (s *RefreshStore) SetClock(fn func() time.Time) { s.now = fn }

// StartSession begins a new refresh family and returns its first token. Called at
// login, after the password has been verified.
func (s *RefreshStore) StartSession(ctx context.Context, userID uuid.UUID, ttl time.Duration) (TokenPair, error) {
	if userID == uuid.Nil {
		return TokenPair{}, apperr.ErrUnauthorized
	}
	if ttl <= 0 {
		return TokenPair{}, fmt.Errorf("authn: refresh TTL must be positive: %w", apperr.ErrValidation)
	}

	plaintext, hash, err := newRefreshSecret()
	if err != nil {
		return TokenPair{}, err
	}
	familyID := uuid.Must(uuid.NewV7())
	expiresAt := s.now().Add(ttl)

	err = db.WithIdentityTx(ctx, s.pool, db.Identity{UserID: userID}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO refresh_families (id, user_id) VALUES ($1, $2)`,
			familyID, userID); err != nil {
			return fmt.Errorf("create family: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO refresh_tokens (token_hash, family_id, user_id, expires_at)
			 VALUES ($1, $2, $3, $4)`,
			hash, familyID, userID, expiresAt); err != nil {
			return fmt.Errorf("create refresh token: %w", err)
		}
		return nil
	})
	if err != nil {
		return TokenPair{}, err
	}
	return TokenPair{RefreshToken: plaintext, UserID: userID, ExpiresAt: expiresAt}, nil
}

// Rotate consumes a presented refresh token and returns its successor.
//
// # The rotation protocol, and why it is one transaction
//
// A refresh token is single-use. Consuming it and issuing its successor must
// happen atomically, because the interesting failure is two requests arriving
// with the same token at the same instant — a client retry, or an attacker racing
// the legitimate client. If the consume were a read followed by a write, both
// requests would read "unconsumed" and both would mint successors, and the family
// would silently fork with no way to tell which branch was legitimate.
//
// So the consume is a single conditional UPDATE ... WHERE consumed_at IS NULL
// RETURNING. Postgres serialises the two statements on the row: exactly one
// returns a row, and the loser sees zero rows and falls into the retry path.
//
// # The statement order inside the transaction is load-bearing
//
// replaced_by is a self-referencing foreign key checked immediately, so the
// successor row must exist before anything points at it. Inserting first and
// claiming second is also wrong, for a subtler reason: if the claim then loses
// the race, the transaction has already written a live successor for a token
// nobody consumed, and that orphan is a usable credential. So the order is
// claim, then insert, then link.
//
// # The outcomes
//
//	token unknown           -> ErrRefreshUnknown   (401; usually a stale client)
//	family revoked          -> ErrRefreshRevoked   (401)
//	expired                 -> ErrRefreshExpired   (401)
//	unconsumed              -> consume, mint successor (200)
//	consumed, inside grace  -> ErrRefreshRetryRace (401; client retries; family kept)
//	consumed, outside grace -> *ReuseError, family revoked
//
// The last case is the point of the whole mechanism. A token that has already
// been used is being presented again after the retry window has closed, which
// means either the client lost the successor or someone else has it. The server
// cannot tell which, so it assumes the worse and revokes every token in the
// family — forcing a fresh login, which is recoverable, rather than leaving a
// possibly-attacker-held session live, which is not.
func (s *RefreshStore) Rotate(ctx context.Context, presented string, ttl time.Duration) (TokenPair, error) {
	if presented == "" {
		return TokenPair{}, ErrRefreshUnknown
	}
	if ttl <= 0 {
		return TokenPair{}, fmt.Errorf("authn: refresh TTL must be positive: %w", apperr.ErrValidation)
	}

	hash := HashRefreshToken(presented)

	var (
		out         TokenPair
		failure     error
		reuseUserID uuid.UUID
		reuseFamID  uuid.UUID
		reused      bool
	)

	// The presented hash is the only credential available: the caller is not yet
	// authenticated, so the request carries no user id. The policy's hash arm
	// (migration 0003) admits exactly this row.
	//
	// # Why identity is established in two steps, not one
	//
	// The obvious implementation reads the token and its family in a single JOIN.
	// That fails, and the failure is instructive: refresh_families carries its own
	// policy keyed on app.current_user_id, so a JOIN evaluated while only the
	// token-hash setting is in force filters the family side away — and every
	// refresh in the system is reported as an unknown token while the row sits
	// there untouched.
	//
	// So identity is established progressively inside one transaction: the
	// presented secret admits the token row, and the user id that row carries is
	// then set as a second setting, which is what makes the family visible. Both
	// settings are transaction-scoped, so nothing outlives the request, and the
	// elevation is narrow by construction: the secret unlocks exactly one token,
	// and that token names exactly one user.
	err := db.WithPresentedSecret(ctx, s.pool, db.SettingRefreshTokenHash, hash, func(tx pgx.Tx) error {
		var (
			tokenUserID      uuid.UUID
			familyID         uuid.UUID
			expiresAt        time.Time
			consumedAt       *time.Time
			consumedRecently bool
		)

		// consumed_recently is computed by the database, not by Go, and that is
		// deliberate. consumed_at is written with now() — the *database's* clock —
		// so comparing it against the application's clock would make the grace
		// window wrong by whatever skew the two hosts disagree by, in whichever
		// direction, with no symptom except occasional spurious reuse alarms.
		// Computing both sides in one place removes the class of bug entirely.
		//
		// The expiry comparison below still uses the application clock, and that
		// is consistent rather than inconsistent: expires_at is written from the
		// application clock in StartSession, so it is compared against the clock
		// that wrote it.
		err := tx.QueryRow(ctx, `
			SELECT user_id, family_id, expires_at, consumed_at,
			       (consumed_at IS NOT NULL
			        AND now() - consumed_at <= make_interval(secs => $2::double precision))
			FROM refresh_tokens
			WHERE token_hash = $1`, hash, s.grace.Seconds()).
			Scan(&tokenUserID, &familyID, &expiresAt, &consumedAt, &consumedRecently)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			failure = ErrRefreshUnknown
			return nil
		case err != nil:
			return fmt.Errorf("look up refresh token: %w", err)
		}

		// Step two: the token named its owner, so the family can now be read under
		// that owner's identity.
		if err := db.SetLocal(ctx, tx, db.SettingUserID, tokenUserID.String()); err != nil {
			return err
		}

		var familyRevoked *time.Time
		switch err := tx.QueryRow(ctx,
			`SELECT revoked_at FROM refresh_families WHERE id = $1`, familyID).Scan(&familyRevoked); {
		case errors.Is(err, pgx.ErrNoRows):
			// The token exists but its family does not. The foreign key makes this
			// unreachable, so it indicates corruption rather than a client problem;
			// treating it as an unknown token is the safe reading.
			failure = ErrRefreshUnknown
			return nil
		case err != nil:
			return fmt.Errorf("look up refresh family: %w", err)
		}

		switch {
		case familyRevoked != nil:
			failure = ErrRefreshRevoked
			return nil
		case !expiresAt.After(s.now()):
			failure = ErrRefreshExpired
			return nil
		}

		if consumedAt != nil {
			// Already used. Inside the grace window this is most likely a
			// concurrent retry, so the family survives and the client can simply
			// try again. Outside it, treat the second presentation as theft.
			if consumedRecently {
				failure = ErrRefreshRetryRace
				return nil
			}
			reused, reuseUserID, reuseFamID = true, tokenUserID, familyID
			return nil
		}

		plaintext, newHash, err := newRefreshSecret()
		if err != nil {
			return err
		}
		newExpiry := s.now().Add(ttl)

		var claimed string
		err = tx.QueryRow(ctx, `
			UPDATE refresh_tokens
			   SET consumed_at = now()
			 WHERE token_hash = $1 AND consumed_at IS NULL
			 RETURNING token_hash`, hash).Scan(&claimed)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Lost the race between the SELECT above and this UPDATE.
			failure = ErrRefreshRetryRace
			return nil
		case err != nil:
			return fmt.Errorf("consume refresh token: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO refresh_tokens (token_hash, family_id, user_id, expires_at)
			 VALUES ($1, $2, $3, $4)`,
			newHash, familyID, tokenUserID, newExpiry); err != nil {
			return fmt.Errorf("insert successor: %w", err)
		}

		if _, err := tx.Exec(ctx,
			`UPDATE refresh_tokens SET replaced_by = $2 WHERE token_hash = $1`,
			hash, newHash); err != nil {
			return fmt.Errorf("link successor: %w", err)
		}

		out = TokenPair{RefreshToken: plaintext, UserID: tokenUserID, ExpiresAt: newExpiry}
		return nil
	})
	if err != nil {
		return TokenPair{}, err
	}

	if reused {
		// Revocation runs in its own transaction, after the detection has
		// committed. Doing it inside would risk the detection being rolled back
		// by a failure in the revocation — and a detected replay that leaves the
		// family live is the worst possible outcome, so the two effects are
		// ordered so the detection survives regardless of what the revocation
		// does.
		revokeErr := s.RevokeFamily(ctx, reuseUserID, reuseFamID, "refresh token reused outside grace window")
		return TokenPair{}, &ReuseError{
			UserID:           reuseUserID,
			FamilyID:         reuseFamID,
			RevocationFailed: revokeErr,
		}
	}
	if failure != nil {
		return TokenPair{}, failure
	}
	return out, nil
}

// RevokeFamily revokes one family.
//
// The UPDATE carries no user_id predicate on purpose: the refresh_families
// policy is keyed on app.current_user_id, so a row belonging to anyone else is
// invisible to this statement and simply does not match. That is the policy doing
// the work, and relying on it here means a future caller who forgets to pass the
// right user still cannot revoke a stranger's session.
func (s *RefreshStore) RevokeFamily(ctx context.Context, userID, familyID uuid.UUID, reason string) error {
	if userID == uuid.Nil || familyID == uuid.Nil {
		return apperr.ErrUnauthorized
	}
	return db.WithIdentityTx(ctx, s.pool, db.Identity{UserID: userID}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE refresh_families
			   SET revoked_at = now(), revoked_reason = $2
			 WHERE id = $1 AND revoked_at IS NULL`, familyID, reason)
		if err != nil {
			return fmt.Errorf("revoke family: %w", err)
		}
		return nil
	})
}

// RevokeByPresentedToken revokes the family that owns a presented token.
//
// This is the logout path, and it demonstrates progressive identity
// establishment: the request arrives holding nothing but a secret, so it starts
// with only the presented-hash setting (which admits exactly that one token row).
// Once the row is read, the user id it carries is layered on as a second setting,
// which is what makes the refresh_families policy permit the UPDATE.
//
// Both settings are transaction-scoped, so the second one applies from the moment
// it is set and neither outlives the transaction.
func (s *RefreshStore) RevokeByPresentedToken(ctx context.Context, presented, reason string) error {
	if presented == "" {
		return ErrRefreshUnknown
	}
	hash := HashRefreshToken(presented)

	return db.WithPresentedSecret(ctx, s.pool, db.SettingRefreshTokenHash, hash, func(tx pgx.Tx) error {
		var (
			userID   uuid.UUID
			familyID uuid.UUID
		)
		err := tx.QueryRow(ctx,
			`SELECT user_id, family_id FROM refresh_tokens WHERE token_hash = $1`, hash).
			Scan(&userID, &familyID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrRefreshUnknown
		case err != nil:
			return fmt.Errorf("find refresh token: %w", err)
		}

		if err := db.SetLocal(ctx, tx, db.SettingUserID, userID.String()); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			UPDATE refresh_families
			   SET revoked_at = now(), revoked_reason = $2
			 WHERE id = $1 AND revoked_at IS NULL`, familyID, reason); err != nil {
			return fmt.Errorf("revoke family: %w", err)
		}
		return nil
	})
}

// RevokeAllForUser revokes every live session for a user, and reports how many.
//
// This is the password-change and "I think I was compromised" path, and it is the
// reason sessions are modelled as families rather than as individual tokens: a
// bulk revoke is one UPDATE against refresh_families, not a scan of every token.
func (s *RefreshStore) RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) (int64, error) {
	if userID == uuid.Nil {
		return 0, apperr.ErrUnauthorized
	}
	var revoked int64
	err := db.WithIdentityTx(ctx, s.pool, db.Identity{UserID: userID}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE refresh_families
			   SET revoked_at = now(), revoked_reason = $2
			 WHERE user_id = $1 AND revoked_at IS NULL`, userID, reason)
		if err != nil {
			return fmt.Errorf("revoke all sessions: %w", err)
		}
		revoked = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// CountLiveSessions reports how many unrevoked families a user has. Used by the
// tests and by the session list on /v1/me.
func (s *RefreshStore) CountLiveSessions(ctx context.Context, userID uuid.UUID) (int, error) {
	if userID == uuid.Nil {
		return 0, apperr.ErrUnauthorized
	}
	var n int
	err := db.WithIdentityTx(ctx, s.pool, db.Identity{UserID: userID}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM refresh_families WHERE user_id = $1 AND revoked_at IS NULL`,
			userID).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("count live sessions: %w", err)
	}
	return n, nil
}

// newRefreshSecret returns a fresh token and its storage hash.
//
// 32 bytes from crypto/rand, base64url-encoded. The rt_ prefix is a debugging
// aid: it makes the credential recognisable in a log or a support ticket without
// the value being usable, and the redaction backstop in the logging package keys
// on exactly that prefix.
func newRefreshSecret() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("authn: read random bytes: %w", err)
	}
	plaintext = "rt_" + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, HashRefreshToken(plaintext), nil
}

// HashRefreshToken returns the hex SHA-256 of a refresh token.
//
// A fast hash is correct here and a slow one would be wrong. The input is 256
// bits of CSPRNG output, so there is no dictionary to attack and no benefit to
// making each guess expensive; argon2 would only add latency to every refresh.
// Passwords are the opposite case — low entropy, so they need a slow KDF (see
// password.go).
func HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}
