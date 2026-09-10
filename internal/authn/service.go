package authn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// TenantSummary names a tenant a user may act as.
type TenantSummary struct {
	TenantID uuid.UUID
	Slug     string
	Name     string
	Role     authz.Role
}

// MembershipLister lists the tenants a user may act as.
//
// It is an interface because authn must not import tenant: tenant owns the
// policy-guarded query, authn owns the session, and main is the only package
// that is allowed to know both. Passing the dependency in keeps that direction
// intact instead of creating an import cycle, and it lets the session tests run
// without a tenant store.
type MembershipLister interface {
	ListForUser(ctx context.Context, userID uuid.UUID) ([]TenantSummary, error)
}

// Service is the authentication use case: it owns the stores, the token issuer,
// and the small amount of policy that ties them together — what a login returns,
// when a session is revoked, how a credential becomes a principal.
//
// # Why this is a layer rather than handler code
//
// The alternative is handlers calling the password verifier, then the token
// issuer, then the refresh store, which spreads the login protocol across the
// HTTP layer where it can only be tested through a router and where the ordering
// of those three steps is implicit. Here the ordering is one function a test can
// call directly, and a handler's job shrinks to parsing input and writing a
// response.
type Service struct {
	users       *UserStore
	tokens      *TokenIssuer
	refresh     *RefreshStore
	keys        *APIKeyStore
	memberships MembershipLister
	log         *slog.Logger

	// dummyHash is a valid argon2id digest of an unknowable password.
	//
	// It exists so the unknown-email path costs the same as the wrong-password
	// path. Without it, POST /login returns measurably faster for an address with
	// no account than for a wrong password, and that timing difference is a
	// reliable account-enumeration oracle: an attacker learns which addresses are
	// registered without guessing a single password.
	//
	// The cost is one wasted key derivation per failed login — the same cost a
	// successful login already pays.
	dummyHash string
}

// NewService builds the authentication service. memberships may be nil, in which
// case a session still authenticates but carries no tenant list; that is a
// degraded login rather than a failed one, and it is reported as such at startup
// by the caller that wired it.
func NewService(
	users *UserStore,
	tokens *TokenIssuer,
	refresh *RefreshStore,
	keys *APIKeyStore,
	memberships MembershipLister,
	log *slog.Logger,
) (*Service, error) {
	if users == nil || tokens == nil || refresh == nil || keys == nil {
		return nil, errors.New("authn: NewService requires users, tokens, refresh, and keys stores")
	}
	if log == nil {
		log = slog.Default()
	}

	// Built once at startup rather than per request: deriving it inline would be
	// the same cost as a real verification, which is the point, but paying it
	// here keeps the per-request path to a single derivation.
	dummy, err := HashPassword("no account has this password; this digest exists only to burn CPU")
	if err != nil {
		return nil, fmt.Errorf("authn: build dummy hash: %w", err)
	}

	return &Service{
		users:       users,
		tokens:      tokens,
		refresh:     refresh,
		keys:        keys,
		memberships: memberships,
		log:         log,
		dummyHash:   dummy,
	}, nil
}

// Session is a successful authentication: an access token plus the refresh
// credential that continues the session.
type Session struct {
	AccessToken  string
	RefreshToken string
	UserID       uuid.UUID
	ExpiresIn    time.Duration
	// Tenants lists the tenants this user may act as, so a client can pick one
	// without a second round trip. It is presentation data, not authorization:
	// every scoped request re-resolves the membership server-side, which is what
	// makes a revoked membership take effect immediately rather than at the next
	// login.
	Tenants []TenantSummary
}

// Login verifies a password and starts a session.
//
// # Uniform failure
//
// Wrong password, unknown email, and malformed email all return the same error
// and take the same time. A caller cannot distinguish them from the response or
// from the latency, which is what stops this endpoint from being an account
// oracle. The distinction survives only in the logs, where an operator needs it.
func (s *Service) Login(ctx context.Context, email, password string) (Session, error) {
	user, err := s.users.ByEmail(ctx, email)
	switch {
	case errors.Is(err, apperr.ErrNotFound):
		// Burn the CPU a real verification would. The result is discarded: this
		// branch can only fail.
		if _, vErr := VerifyPassword(s.dummyHash, password); vErr != nil {
			s.log.Error("dummy hash is malformed; the login timing defence is not working", "err", vErr)
		}
		s.log.Info("login rejected", "reason", "unknown_email")
		return Session{}, apperr.ErrUnauthorized
	case err != nil:
		return Session{}, fmt.Errorf("login: %w", err)
	}

	ok, err := VerifyPassword(user.PWHash, password)
	if err != nil {
		// A malformed stored hash is corruption, not a bad password. It must not
		// authenticate, and it must be visible to an operator rather than
		// presenting as a wrong password forever.
		s.log.Error("stored password hash is malformed", "user_id", user.ID, "err", err)
		return Session{}, apperr.ErrUnauthorized
	}
	if !ok {
		s.log.Info("login rejected", "reason", "bad_password", "user_id", user.ID)
		return Session{}, apperr.ErrUnauthorized
	}

	session, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return Session{}, err
	}
	s.log.Info("login succeeded", "user_id", user.ID)
	return session, nil
}

// Refresh exchanges a refresh token for a new credential pair.
//
// The interesting behaviour lives in RefreshStore.Rotate — rotation, reuse
// detection, family revocation. What this adds is the interpretation: a reused
// token is a security event and is logged as one here, at the layer that knows it
// was a refresh rather than an API-key attempt.
func (s *Service) Refresh(ctx context.Context, presented string) (Session, error) {
	rotated, err := s.refresh.Rotate(ctx, presented, DefaultRefreshTTL)
	switch {
	case errors.Is(err, ErrRefreshReused):
		// The error carries identity precisely because this is the moment an
		// operator needs it and the return value is empty by now. A revocation
		// failure is escalated rather than folded into the warning: the replay
		// itself is survivable, but a replay whose family is still live is not.
		var reuse *ReuseError
		if errors.As(err, &reuse) {
			if reuse.RevocationFailed != nil {
				s.log.Error("SECURITY: refresh token replayed and the session family could NOT be revoked",
					"user_id", reuse.UserID,
					"family_id", reuse.FamilyID,
					"err", reuse.RevocationFailed)
			} else {
				s.log.Warn("refresh token replayed after the retry window: session family revoked",
					"user_id", reuse.UserID,
					"family_id", reuse.FamilyID,
					"note", "possible token theft, or a client that lost its successor")
			}
		}
		return Session{}, apperr.ErrUnauthorized
	case errors.Is(err, ErrRefreshRetryRace):
		// Benign and recoverable: a concurrent retry inside the grace window. The
		// family is intact, so re-authenticating is safe and the client simply
		// retries.
		s.log.Info("concurrent refresh retry inside the grace window")
		return Session{}, apperr.ErrUnauthorized
	case err != nil:
		s.log.Info("refresh rejected", "reason", err)
		return Session{}, apperr.ErrUnauthorized
	}

	access, _, err := s.tokens.Mint(rotated.UserID)
	if err != nil {
		return Session{}, fmt.Errorf("refresh: mint access token: %w", err)
	}

	tenants, err := s.tenantsFor(ctx, rotated.UserID)
	if err != nil {
		return Session{}, err
	}

	return Session{
		AccessToken:  access,
		RefreshToken: rotated.RefreshToken,
		UserID:       rotated.UserID,
		ExpiresIn:    s.tokens.TTL(),
		Tenants:      tenants,
	}, nil
}

// Logout ends the session that a refresh token belongs to.
//
// It revokes the whole family rather than deleting the presented token, because
// the point of logging out is that no descendant of this session remains usable.
// Deleting one row would leave its successor live, which is a logout that logs
// nobody out.
//
// It is idempotent: an unknown or already-revoked token is treated as success,
// because in every one of those cases the caller's intent — this session is over
// — is already satisfied. Returning an error would make a harmless retry look
// like a failure.
func (s *Service) Logout(ctx context.Context, presented string) error {
	if presented == "" {
		return apperr.ErrUnauthorized
	}

	err := s.refresh.RevokeByPresentedToken(ctx, presented, "logout")
	switch {
	case err == nil, errors.Is(err, ErrRefreshUnknown), errors.Is(err, ErrRefreshRevoked):
		return nil
	default:
		return fmt.Errorf("logout: %w", err)
	}
}

// LogoutAll revokes every live session for a user and reports how many. This is
// the password-change and suspected-compromise path.
func (s *Service) LogoutAll(ctx context.Context, userID uuid.UUID, reason string) (int64, error) {
	if userID == uuid.Nil {
		return 0, apperr.ErrUnauthorized
	}
	return s.refresh.RevokeAllForUser(ctx, userID, reason)
}

// PrincipalForAccessToken implements SessionStore.
//
// The returned principal carries identity only: no tenant, no role. That is the
// design (see internal/authn/token.go), and the consequence is visible right
// here — a session request must name the tenant it is acting on, because the
// token deliberately does not remember one and because a person may belong to
// several.
//
// # The one check this does not make
//
// It does not confirm the user still exists, so a deleted account keeps its
// access token working until the token expires — at most DefaultAccessTTL. The
// blast radius is bounded by where such a token is useful: every tenant-scoped
// operation goes through the membership gate, and deleting a user cascades their
// memberships, so a deleted user can reach only the pre-tenant endpoints
// (GET /v1/me, GET /v1/tenants), which return their own row and an empty list.
//
// The alternative — a database round trip on the hottest path purely to
// re-confirm existence — buys a window of at most ten minutes on endpoints that
// leak nothing. If that trade ever stops being right, the fix is a denylist keyed
// on the token's jti, not a per-request lookup.
func (s *Service) PrincipalForAccessToken(_ context.Context, raw string) (authz.Principal, error) {
	claims, err := s.tokens.Parse(raw)
	if err != nil {
		return authz.Principal{}, err
	}
	return authz.Principal{
		UserID: claims.UserID,
		Method: authz.MethodJWT,
	}, nil
}

// PrincipalForAPIKey implements SessionStore.
//
// Unlike a session, a key *does* determine its tenant: the credential is
// tenant-scoped, so there is no membership to check and no tenant to resolve. The
// principal carries the key's explicit scopes rather than a role, because a key
// is deliberately not a user — see internal/authz/keys.go for why a key may not
// hold identity-management permissions.
func (s *Service) PrincipalForAPIKey(ctx context.Context, raw string) (authz.Principal, error) {
	key, err := s.keys.Authenticate(ctx, raw)
	if err != nil {
		return authz.Principal{}, err
	}
	return authz.Principal{
		TenantID: key.TenantID,
		Scopes:   key.Scopes,
		Method:   authz.MethodAPIKey,
	}, nil
}

// issueSession mints the access token and starts a refresh family.
//
// Order matters: the access token is minted first and the family second, so a
// failure to persist the refresh credential cannot leave a live access token
// whose session was never recorded. The reverse order produces exactly that — a
// usable token with no way to revoke it.
func (s *Service) issueSession(ctx context.Context, userID uuid.UUID) (Session, error) {
	access, _, err := s.tokens.Mint(userID)
	if err != nil {
		return Session{}, fmt.Errorf("issue session: %w", err)
	}

	refresh, err := s.refresh.StartSession(ctx, userID, DefaultRefreshTTL)
	if err != nil {
		return Session{}, fmt.Errorf("issue session: %w", err)
	}

	tenants, err := s.tenantsFor(ctx, userID)
	if err != nil {
		return Session{}, err
	}

	return Session{
		AccessToken:  access,
		RefreshToken: refresh.RefreshToken,
		UserID:       userID,
		ExpiresIn:    s.tokens.TTL(),
		Tenants:      tenants,
	}, nil
}

// tenantsFor lists the tenants a user may act as, or nil when no lister is wired.
//
// Returning nil rather than an error is deliberate: an unwired lister means the
// tenant list is unavailable, not that the login failed. The client can still
// fetch it from GET /v1/tenants with the token it just received, so failing the
// login over a missing convenience field would be the wrong call.
func (s *Service) tenantsFor(ctx context.Context, userID uuid.UUID) ([]TenantSummary, error) {
	if s.memberships == nil {
		return nil, nil
	}
	return s.memberships.ListForUser(ctx, userID)
}
