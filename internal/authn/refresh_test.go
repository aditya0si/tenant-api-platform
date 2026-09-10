package authn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/testsupport"
)

// These tests exercise the refresh protocol against a real Postgres, because the
// properties under test are database properties: a conditional UPDATE that
// exactly one caller can win, a self-referencing foreign key, and a policy that
// admits a row by its hash. A fake would prove none of them.

// TestStartSession_IssuesUsableToken covers the login path's persistence and
// asserts the two things that matter afterwards: the token hashes to a stored row,
// and only the hash is stored.
func TestStartSession_IssuesUsableToken(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "sess")

	pair, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	if pair.RefreshToken == "" {
		t.Fatal("no refresh token issued")
	}
	if pair.UserID != userID {
		t.Fatalf("session user = %s, want %s", pair.UserID, userID)
	}
	if !pair.ExpiresAt.After(time.Now()) {
		t.Fatalf("session expires in the past: %s", pair.ExpiresAt)
	}
	if len(pair.RefreshToken) < 40 {
		t.Fatalf("refresh token looks too short to be 256 bits: %q", pair.RefreshToken)
	}

	// The plaintext must not be recoverable from storage. Checking through the
	// owner connection is deliberate: it bypasses the policies, so this asserts the
	// storage format rather than what the app role happens to be allowed to see.
	if d.Owner != nil {
		var count int
		if err := d.Owner.QueryRow(ctx,
			`SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`,
			pair.RefreshToken).Scan(&count); err != nil {
			t.Fatalf("owner-side lookup: %v", err)
		}
		if count != 0 {
			t.Fatal("the plaintext refresh token is stored verbatim; only its hash may be persisted")
		}

		if err := d.Owner.QueryRow(ctx,
			`SELECT count(*) FROM refresh_tokens WHERE token_hash = $1`,
			HashRefreshToken(pair.RefreshToken)).Scan(&count); err != nil {
			t.Fatalf("owner-side hash lookup: %v", err)
		}
		if count != 1 {
			t.Fatalf("stored rows matching the token hash = %d, want 1", count)
		}
	}

	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 1 {
		t.Fatalf("live sessions = %d (err %v), want 1", n, err)
	}
}

// TestRotate_HappyPath proves rotation issues a working successor and consumes the
// predecessor, and that the chain is recorded — the link is what makes a reuse
// investigation possible after the fact.
func TestRotate_HappyPath(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "rotate")

	first, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	second, err := store.Rotate(ctx, first.RefreshToken, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("rotation returned the same token; it is not a rotation")
	}
	if second.UserID != userID {
		t.Fatalf("successor user = %s, want %s", second.UserID, userID)
	}

	// The family is unchanged: rotation extends a session, it does not start one.
	// A new family per rotation would mean one live session per refresh, and a
	// "revoke all sessions" that leaves hundreds of rows live.
	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 1 {
		t.Fatalf("live sessions after rotation = %d (err %v), want 1 (same family)", n, err)
	}

	// The predecessor is consumed and linked to its successor.
	if d.Owner != nil {
		var (
			consumed   bool
			replacedBy *string
		)
		if err := d.Owner.QueryRow(ctx,
			`SELECT consumed_at IS NOT NULL, replaced_by FROM refresh_tokens WHERE token_hash = $1`,
			HashRefreshToken(first.RefreshToken)).Scan(&consumed, &replacedBy); err != nil {
			t.Fatalf("inspect predecessor: %v", err)
		}
		if !consumed {
			t.Fatal("predecessor was not marked consumed")
		}
		if replacedBy == nil || *replacedBy != HashRefreshToken(second.RefreshToken) {
			t.Fatalf("predecessor does not link to its successor (replaced_by = %v)", replacedBy)
		}
	}

	// The successor must itself be rotatable, or the session cannot outlive one
	// refresh.
	if _, err := store.Rotate(ctx, second.RefreshToken, DefaultRefreshTTL); err != nil {
		t.Fatalf("rotating the successor failed: %v", err)
	}
}

// TestRotate_ReuseRevokesFamily is the security-critical assertion.
//
// A consumed token presented again after the retry window means either the client
// lost its successor or somebody else has it, and the server cannot tell which. It
// must assume the worse: revoke every token in the family, and report the event
// with enough detail to investigate.
func TestRotate_ReuseRevokesFamily(t *testing.T) {
	d := testsupport.RequireDB(t)
	// Strict rotation: grace 0 makes an immediate replay count as theft, which is
	// the behaviour under test. The production default is more forgiving (see
	// DefaultReuseGrace), and TestRotate_GraceWindowAbsorbsRetry covers that path.
	store := NewRefreshStore(d.App, 0)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "reuse")

	first, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	second, err := store.Rotate(ctx, first.RefreshToken, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	// Replay the consumed token.
	_, err = store.Rotate(ctx, first.RefreshToken, DefaultRefreshTTL)
	if !errors.Is(err, ErrRefreshReused) {
		t.Fatalf("replayed token error = %v, want ErrRefreshReused", err)
	}

	// The error must carry identity: this is the moment an operator needs it, and
	// the ordinary return value is empty by then.
	var reuse *ReuseError
	if !errors.As(err, &reuse) {
		t.Fatalf("error is %T, want *ReuseError carrying the affected identity", err)
	}
	if reuse.UserID != userID {
		t.Errorf("ReuseError user = %s, want %s", reuse.UserID, userID)
	}
	if reuse.FamilyID == uuid.Nil {
		t.Error("ReuseError carries no family id, so the revoked family cannot be identified")
	}
	if reuse.RevocationFailed != nil {
		t.Errorf("revocation failed: %v", reuse.RevocationFailed)
	}

	// The successor must be dead: the whole point is that a possibly
	// attacker-held session does not survive the detection.
	if _, err := store.Rotate(ctx, second.RefreshToken, DefaultRefreshTTL); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("successor after family revocation error = %v, want ErrRefreshRevoked", err)
	}

	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 0 {
		t.Fatalf("live sessions after reuse detection = %d (err %v), want 0", n, err)
	}
}

// TestRotate_GraceWindowAbsorbsRetry covers the other side of the trade-off: a
// second presentation inside the grace window is a concurrent retry, so the family
// survives and the client simply re-authenticates.
//
// Both this and the reuse test must pass for the design to be defensible. A system
// that only revoked on replay would log users out whenever a client retried; one
// that only absorbed retries would never notice theft.
func TestRotate_GraceWindowAbsorbsRetry(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, time.Hour) // generous window: the retry is inside it
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "grace")

	first, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}
	second, err := store.Rotate(ctx, first.RefreshToken, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("first Rotate: %v", err)
	}

	_, err = store.Rotate(ctx, first.RefreshToken, DefaultRefreshTTL)
	if !errors.Is(err, ErrRefreshRetryRace) {
		t.Fatalf("in-grace replay error = %v, want ErrRefreshRetryRace", err)
	}

	// The family must be intact, and the successor must still work.
	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 1 {
		t.Fatalf("live sessions after an absorbed retry = %d (err %v), want 1", n, err)
	}
	if _, err := store.Rotate(ctx, second.RefreshToken, DefaultRefreshTTL); err != nil {
		t.Fatalf("successor was invalidated by an absorbed retry: %v", err)
	}
}

// TestRotate_UnknownAndEmptyTokens covers the malformed-input path. These are the
// requests a scanner sends, and they must be ordinary rejections rather than
// database errors.
func TestRotate_UnknownAndEmptyTokens(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	if _, err := store.Rotate(ctx, "", DefaultRefreshTTL); !errors.Is(err, ErrRefreshUnknown) {
		t.Fatalf("empty token error = %v, want ErrRefreshUnknown", err)
	}
	if _, err := store.Rotate(ctx, "rt_totally-made-up-but-well-formed-looking", DefaultRefreshTTL); !errors.Is(err, ErrRefreshUnknown) {
		t.Fatalf("unknown token error = %v, want ErrRefreshUnknown", err)
	}
}

// TestRotate_Expired proves expiry is enforced, using an injected clock rather
// than a sleep.
func TestRotate_Expired(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "expiry")

	pair, err := store.StartSession(ctx, userID, time.Hour)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	// Advance the store's clock past the session's expiry.
	store.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })

	if _, err := store.Rotate(ctx, pair.RefreshToken, time.Hour); !errors.Is(err, ErrRefreshExpired) {
		t.Fatalf("expired token error = %v, want ErrRefreshExpired", err)
	}
}

// TestRotate_ConcurrentOnlyOneWinner is the race test.
//
// Eight goroutines present the same valid token at once. Exactly one must win: if
// two could succeed, the family would fork into two independent live sessions with
// no way to tell which branch was legitimate, and the "single-use token" property
// would be a fiction.
//
// This runs against a small pool so connection reuse is forced, which is also what
// makes it a regression test for transaction-scoped settings: if the GUCs were
// session-scoped, one goroutine's identity would leak into another's transaction
// and this test would see cross-tenant rows.
func TestRotate_ConcurrentOnlyOneWinner(t *testing.T) {
	d := testsupport.RequireDB(t)
	pool := d.AppPoolWithConns(t, 4)
	store := NewRefreshStore(pool, DefaultReuseGrace)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "concurrent")

	start, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	const racers = 8
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		winners    []string
		losers     []error
		unexpected []error
	)

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pair, err := store.Rotate(ctx, start.RefreshToken, DefaultRefreshTTL)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, pair.RefreshToken)
			case errors.Is(err, ErrRefreshRetryRace), errors.Is(err, ErrRefreshReused):
				losers = append(losers, err)
			default:
				unexpected = append(unexpected, err)
			}
		}()
	}
	wg.Wait()

	if len(unexpected) > 0 {
		t.Fatalf("unexpected errors from concurrent rotation: %v", unexpected)
	}
	if len(winners) != 1 {
		t.Fatalf("%d goroutines succeeded in rotating one single-use token, want exactly 1", len(winners))
	}
	if len(losers) != racers-1 {
		t.Fatalf("%d losers, want %d", len(losers), racers-1)
	}

	// With a grace window in force, the losers must all have been retry-class
	// rejections, which means the family survived and the winner's session is
	// still usable. A reuse classification here would mean concurrent requests
	// revoke the session they are racing to extend.
	for _, err := range losers {
		if !errors.Is(err, ErrRefreshRetryRace) {
			t.Fatalf("a concurrent loser was classified as %v; inside the grace window this must be a retry", err)
		}
	}
	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 1 {
		t.Fatalf("live sessions after concurrent rotation = %d (err %v), want 1", n, err)
	}
	if _, err := store.Rotate(ctx, winners[0], DefaultRefreshTTL); err != nil {
		t.Fatalf("the winning successor is not usable: %v", err)
	}
}

// TestRevokeByPresentedToken covers the logout path, including its progressive
// identity establishment: the request starts holding nothing but a secret and
// layers the user id on once the row is read.
func TestRevokeByPresentedToken(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, userID := testsupport.NewTenant(t, d.App, "logout")

	pair, err := store.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("StartSession: %v", err)
	}

	if err := store.RevokeByPresentedToken(ctx, pair.RefreshToken, "logout"); err != nil {
		t.Fatalf("RevokeByPresentedToken: %v", err)
	}
	if n, err := store.CountLiveSessions(ctx, userID); err != nil || n != 0 {
		t.Fatalf("live sessions after logout = %d (err %v), want 0", n, err)
	}

	// The revoked token must not work.
	if _, err := store.Rotate(ctx, pair.RefreshToken, DefaultRefreshTTL); !errors.Is(err, ErrRefreshRevoked) {
		t.Fatalf("revoked token error = %v, want ErrRefreshRevoked", err)
	}

	// An unknown token is reported as unknown rather than silently succeeding, so
	// the service layer can decide that logout is idempotent while still logging
	// the distinction.
	if err := store.RevokeByPresentedToken(ctx, "rt_never-issued", "logout"); !errors.Is(err, ErrRefreshUnknown) {
		t.Fatalf("unknown token error = %v, want ErrRefreshUnknown", err)
	}
}

// TestRevokeAllForUser proves a bulk revocation touches every session and no
// other user's, which is what makes "change password, sign out everywhere"
// truthful.
func TestRevokeAllForUser(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, victim := testsupport.NewTenant(t, d.App, "bulk-victim")
	_, bystander := testsupport.NewTenant(t, d.App, "bulk-bystander")

	// Three sessions for the victim, one for somebody else.
	for i := 0; i < 3; i++ {
		if _, err := store.StartSession(ctx, victim, DefaultRefreshTTL); err != nil {
			t.Fatalf("StartSession %d: %v", i, err)
		}
	}
	if _, err := store.StartSession(ctx, bystander, DefaultRefreshTTL); err != nil {
		t.Fatalf("bystander StartSession: %v", err)
	}

	revoked, err := store.RevokeAllForUser(ctx, victim, "password changed")
	if err != nil {
		t.Fatalf("RevokeAllForUser: %v", err)
	}
	if revoked != 3 {
		t.Fatalf("revoked %d sessions, want 3", revoked)
	}

	if n, err := store.CountLiveSessions(ctx, victim); err != nil || n != 0 {
		t.Fatalf("victim live sessions = %d (err %v), want 0", n, err)
	}
	if n, err := store.CountLiveSessions(ctx, bystander); err != nil || n != 1 {
		t.Fatalf("bystander live sessions = %d (err %v), want 1 — a bulk revoke must not reach another user's sessions", n, err)
	}
}

// TestRotate_DoesNotLeakAcrossUsers proves the presented-hash policy arm admits
// exactly one row: a token belonging to another user is simply not found, so a
// stolen secret can never be used to enumerate or affect anyone else's sessions.
func TestRotate_DoesNotLeakAcrossUsers(t *testing.T) {
	d := testsupport.RequireDB(t)
	store := NewRefreshStore(d.App, DefaultReuseGrace)
	ctx := context.Background()

	_, alice := testsupport.NewTenant(t, d.App, "alice")
	_, bob := testsupport.NewTenant(t, d.App, "bob")

	aliceSession, err := store.StartSession(ctx, alice, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("alice StartSession: %v", err)
	}
	if _, err := store.StartSession(ctx, bob, DefaultRefreshTTL); err != nil {
		t.Fatalf("bob StartSession: %v", err)
	}

	// Alice's token, rotated once, yields Alice's successor only.
	next, err := store.Rotate(ctx, aliceSession.RefreshToken, DefaultRefreshTTL)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next.UserID != alice {
		t.Fatalf("rotated session belongs to %s, want %s", next.UserID, alice)
	}

	// And Bob's live session count is untouched by Alice's rotation.
	if n, err := store.CountLiveSessions(ctx, bob); err != nil || n != 1 {
		t.Fatalf("bob live sessions = %d (err %v), want 1", n, err)
	}
}
