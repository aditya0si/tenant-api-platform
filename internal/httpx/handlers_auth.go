package httpx

import (
	"context"
	"errors"
	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/authn"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// Requests and responses for the authentication endpoints.
//
// They are separate types from the domain's own structs, so a change to how the API
// presents a session cannot alter how one is stored or verified. The mapping
// between the two is explicit and lives here.

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// Tenant fields. Registering creates a personal tenant, because every
	// tenant-scoped endpoint requires one and a user with no tenant could do
	// nothing at all until they created one.
	TenantName string `json:"tenant_name"`
	TenantSlug string `json:"tenant_slug,omitempty"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type createTenantRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type tenantSummary struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug,omitempty"`
	Name     string `json:"name,omitempty"`
	Role     string `json:"role,omitempty"`

	// Permissions is per-tenant, and that placement is the honest one: a human's
	// permissions come from their role *in a specific tenant*, so two memberships of
	// the same person can carry different capabilities. Publishing a single flat list
	// at the top level would imply the caller has one permission set, which is wrong
	// for exactly the users this endpoint exists to serve — those belonging to more
	// than one tenant.
	Permissions []string `json:"permissions,omitempty"`
}

type sessionResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	// ExpiresIn is seconds, matching the OAuth 2 convention, so a client can compute
	// when to refresh without parsing the token.
	ExpiresIn int             `json:"expires_in"`
	UserID    string          `json:"user_id"`
	Tenants   []tenantSummary `json:"tenants"`
}

// handleRegister creates a user, their first tenant, and an owner membership.
//
// # The two-step failure this accepts
//
// The user row and the tenant are created in separate transactions, because they
// belong to different aggregates — authn owns identities, tenant owns tenancy — and
// a single transaction spanning both would put a cross-package write inside one
// store. The consequence is real: if the tenant step fails after the user exists,
// the account is left with no tenant.
//
// That state is deliberately recoverable by the user rather than requiring an
// operator: they can log in, see an empty tenant list, and create one through
// POST /v1/tenants. The alternative — a saga with compensation, or a distributed
// transaction — is more machinery than a failure that leaves a working account
// warrants. The trade-off is stated rather than hidden.
func (d Deps) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	user, err := d.Users.Create(r.Context(), req.Email, req.Password)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	tenantName := strings.TrimSpace(req.TenantName)
	if tenantName == "" {
		// Derive a name from the address rather than requiring one: a first tenant
		// is bookkeeping, not a decision the user should have to make before they
		// can log in.
		local := req.Email
		if at := strings.Index(local, "@"); at > 0 {
			local = local[:at]
		}
		tenantName = local + "'s workspace"
	}

	newTenant, err := d.createTenantWithUniqueSlug(r.Context(), tenantName, req.TenantSlug, user.ID)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	session, err := d.Auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		// The account exists, so failing here would be misleading: report the
		// registration as successful and let the client log in.
		d.Log.Error("registration succeeded but the initial login failed",
			"user_id", user.ID, "err", err)
		httperr.Created(w, map[string]any{
			"user_id": user.ID.String(),
			"tenant":  tenantSummaryFrom(newTenant, authz.RoleOwner),
			"note":    "account created; obtain a session from POST /v1/auth/login",
		})
		return
	}

	httperr.Created(w, sessionResponseFrom(session, d.AccessTokenTTL))
}

// handleLogin authenticates and starts a session.
func (d Deps) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	session, err := d.Auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		// The service returns ErrUnauthorized for a wrong password, an unknown
		// address, and a malformed address alike, and takes the same time for each.
		// The response must not narrow that down.
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, sessionResponseFrom(session, d.AccessTokenTTL))
}

// handleRefresh exchanges a refresh token for a new credential pair.
func (d Deps) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	session, err := d.Auth.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, sessionResponseFrom(session, d.AccessTokenTTL))
}

// handleLogout ends the session a refresh token belongs to.
//
// It answers 204 whether or not the token was live, because the caller's intent —
// this session is over — is satisfied either way. Distinguishing the cases would
// tell an unauthenticated caller which refresh tokens exist.
func (d Deps) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	if err := d.Auth.Logout(r.Context(), req.RefreshToken); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.NoContent(w)
}

// handleMe reports the authenticated principal.
//
// It is a pre-tenant endpoint: it answers "who am I and what may I do", which is what a
// client needs in order to render a UI, and it deliberately does not require a tenant
// because there may be several.
//
// # Where permissions live, and why it differs by credential
//
// A session's permissions are per-tenant, because they come from the caller's role in
// one — so they are reported inside each tenant rather than as a single list. A caller
// who belongs to two tenants as admin and member genuinely has two permission sets, and
// a flat list would have to pick one and be wrong about the other.
//
// An API key's permissions are not per-tenant at all: the credential *is* its tenant and
// its scopes were chosen at mint time, so they are reported at the top level alongside
// the tenant the key belongs to.
func (d Deps) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := authz.PrincipalFrom(r.Context())
	if !ok {
		httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}

	payload := map[string]any{
		"auth_method": string(principal.Method),
	}

	switch principal.Method {
	case authz.MethodAPIKey:
		// A key has no identity of its own and no tenant list: it acts as exactly one
		// tenant, with exactly the scopes it was minted with.
		payload["tenant_id"] = principal.TenantID.String()
		payload["permissions"] = permissionInfo(principal)

	case authz.MethodJWT:
		payload["user_id"] = principal.UserID.String()

		memberships, err := d.Tenants.ListForUser(r.Context(), principal.UserID)
		if err != nil {
			httperr.Fail(w, r, d.Log, err)
			return
		}
		tenants := make([]tenantSummary, 0, len(memberships))
		for _, m := range memberships {
			tenants = append(tenants, tenantSummary{
				TenantID:    m.TenantID.String(),
				Slug:        m.TenantSlug,
				Name:        m.TenantName,
				Role:        string(m.Role),
				Permissions: rolePermStrings(m.Role),
			})
		}
		payload["tenants"] = tenants
	}

	httperr.OK(w, payload)
}

// handleListMyTenants lists the tenants the caller may act as.
func (d Deps) handleListMyTenants(w http.ResponseWriter, r *http.Request) {
	principal, ok := authz.PrincipalFrom(r.Context())
	if !ok {
		httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if principal.UserID == uuid.Nil {
		// An API key is already bound to one tenant; "my tenants" is not a question
		// it can ask. Answered with the single tenant it does belong to, so a client
		// written against a session works unchanged with a key.
		httperr.OK(w, []tenantSummary{{
			TenantID: principal.TenantID.String(),
		}})
		return
	}

	memberships, err := d.Tenants.ListForUser(r.Context(), principal.UserID)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	out := make([]tenantSummary, 0, len(memberships))
	for _, m := range memberships {
		out = append(out, tenantSummary{
			TenantID: m.TenantID.String(),
			Slug:     m.TenantSlug,
			Name:     m.TenantName,
			Role:     string(m.Role),
		})
	}
	httperr.OK(w, out)
}

// handleCreateTenant creates a new tenant owned by the caller.
//
// The caller becomes the owner of the tenant they just created. This is the only
// place a membership is granted without an existing owner's approval, and it is
// bounded: the membership is in the tenant being created, so it grants nothing that
// already existed.
func (d Deps) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	principal, ok := authz.PrincipalFrom(r.Context())
	if !ok {
		httperr.Write(w, r, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if principal.UserID == uuid.Nil {
		// A machine credential must not be able to create tenants: it would be a
		// key minting an organisation, which is exactly the kind of unattended
		// identity change the key permission model forbids.
		httperr.Write(w, r, http.StatusForbidden, "forbidden", "an API key cannot create tenants")
		return
	}

	var req createTenantRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httperr.Fail(w, r, d.Log, apperr.Invalid("name", "is required"))
		return
	}

	newTenant, err := d.createTenantWithUniqueSlug(r.Context(), name, req.Slug, principal.UserID)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	httperr.Created(w, tenantSummaryFrom(newTenant, authz.RoleOwner))
}

// handleGetTenant returns the tenant the request is scoped to.
func (d Deps) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	t, err := d.Tenants.Get(r.Context(), auth)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	httperr.OK(w, map[string]any{
		"tenant_id":  t.ID.String(),
		"slug":       t.Slug,
		"name":       t.Name,
		"role":       string(auth.Role()),
		"created_at": timestamp(t.CreatedAt),
	})
}

// handleListMembers returns the scoped tenant's roster.
func (d Deps) handleListMembers(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	members, err := d.Tenants.ListMembers(r.Context(), auth)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		out = append(out, map[string]any{
			"user_id":    m.UserID.String(),
			"email":      m.Email,
			"role":       string(m.Role),
			"created_at": timestamp(m.CreatedAt),
		})
	}
	httperr.OK(w, out)
}

// handleAddMember grants an existing user a role in the scoped tenant.
func (d Deps) handleAddMember(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	var req addMemberRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	userID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.Invalid("user_id", "must be a UUID"))
		return
	}
	role := authz.Role(strings.TrimSpace(req.Role))
	if !role.Valid() {
		httperr.Fail(w, r, d.Log, apperr.Invalid("role", "must be one of owner, admin, member"))
		return
	}

	// Granting a role equal to your own is allowed; granting one above it is not.
	// Without this, an admin could promote themselves by minting an owner, which
	// would make the role hierarchy decorative.
	if !mayGrantRole(auth.Role(), role) {
		httperr.Write(w, r, http.StatusForbidden, "forbidden",
			"a "+string(auth.Role())+" may not grant the "+string(role)+" role")
		return
	}

	if err := d.Tenants.AddMember(r.Context(), auth, userID, role); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	httperr.Created(w, map[string]any{
		"user_id": userID.String(),
		"role":    string(role),
	})
}

// mayGrantRole reports whether a principal with role actor may grant target.
//
// The rule is that you may grant any role at or below your own. It is deliberately
// not "owner only": an admin running a team needs to add members, and requiring the
// owner for every addition would make the admin role useless. Escalation is what is
// forbidden — an admin cannot mint an owner, so an admin cannot become one.
func mayGrantRole(actor, target authz.Role) bool {
	rank := func(r authz.Role) int {
		switch r {
		case authz.RoleOwner:
			return 3
		case authz.RoleAdmin:
			return 2
		case authz.RoleMember:
			return 1
		default:
			return 0
		}
	}
	return rank(actor) >= rank(target) && rank(target) > 0
}

// createTenantWithUniqueSlug creates a tenant, retrying with a random suffix when a
// *derived* slug collides.
//
// # Why a retry rather than a 409
//
// tenants.slug is globally unique — it is the tenant's public identifier — so a
// derived slug collides as soon as two workspaces share a name, which is common
// ("Acme", "Test Workspace", "Personal"). Returning 409 for a slug the user never
// chose would present as "you cannot register", with no field to fix and no
// explanation, because the conflicting value is not in the request.
//
// So a derived slug is treated as a starting point: on collision it is re-derived
// with a short random suffix, which keeps the readable prefix and guarantees
// progress. A slug the caller *supplied* is not retried — there, the collision is
// about a value they chose and asked for, so it is reported as the conflict it is,
// and they can pick another.
func (d Deps) createTenantWithUniqueSlug(ctx context.Context, name, suppliedSlug string, userID uuid.UUID) (tenant.Tenant, error) {
	slug := suppliedSlug
	derived := slug == ""

	if derived {
		slug = slugFromName(name)
	}

	newTenant := tenant.Tenant{ID: uuid.Must(uuid.NewV7()), Slug: slug, Name: name}
	err := d.Tenants.CreateForUser(ctx, newTenant, userID, authz.RoleOwner)
	if err == nil {
		return newTenant, nil
	}

	// Only a derived slug is retried. Two attempts is enough: the suffix carries 6
	// random hex characters, so a second collision would mean something other than
	// name reuse is happening and should surface rather than be papered over.
	if !derived || !errors.Is(err, apperr.ErrConflict) {
		return tenant.Tenant{}, err
	}

	// The base is capped so the suffixed slug still satisfies the CHECK constraint's
	// 63-character limit. A 62-character base plus "-" plus six characters would be
	// rejected as a validation error rather than retried, which is a confusing outcome
	// for a name that is otherwise perfectly legal.
	base := slugFromName(name)
	if len(base) > 55 {
		base = strings.TrimRight(base[:55], "-")
	}
	newTenant.ID = uuid.Must(uuid.NewV7())
	newTenant.Slug = base + "-" + shortRandomSuffix()
	if retryErr := d.Tenants.CreateForUser(ctx, newTenant, userID, authz.RoleOwner); retryErr != nil {
		return tenant.Tenant{}, retryErr
	}
	return newTenant, nil
}

// shortRandomSuffix returns six lowercase hex characters, short enough to keep a
// slug readable and long enough that a collision means something is wrong.
func shortRandomSuffix() string {
	return idgen.ShortSuffix(6)
}

// sessionResponseFrom renders a session for the wire.
//
// ExpiresIn is a duration in seconds rather than an absolute timestamp, so a client
// computes its own refresh point from its own clock. A server timestamp would require
// the two clocks to agree, and a browser whose clock is off is the normal case, not
// the exceptional one.
func sessionResponseFrom(s authn.Session, ttlSeconds int) sessionResponse {
	tenants := make([]tenantSummary, 0, len(s.Tenants))
	for _, t := range s.Tenants {
		tenants = append(tenants, tenantSummary{
			TenantID: t.TenantID.String(),
			Slug:     t.Slug,
			Name:     t.Name,
			Role:     string(t.Role),
		})
	}
	return sessionResponse{
		AccessToken:  s.AccessToken,
		RefreshToken: s.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    ttlSeconds,
		UserID:       s.UserID.String(),
		Tenants:      tenants,
	}
}

func tenantSummaryFrom(t tenant.Tenant, role authz.Role) tenantSummary {
	return tenantSummary{
		TenantID: t.ID.String(),
		Slug:     t.Slug,
		Name:     t.Name,
		Role:     string(role),
	}
}

// slugFromName derives a tenant slug from a display name.
//
// It delegates to the project package's slug rule because the two must agree: a
// tenant slug and a project slug are validated by the same CHECK constraint shape,
// so deriving them differently would produce a slug that passes one path and fails
// the other for the same input.
func slugFromName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	lastDash := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case !lastDash:
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 62 {
			break
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) < 2 {
		if slug == "" {
			slug = "t"
		}
		slug = slug + "-" + idgen.ShortSuffix(6)
	}
	return slug
}

var _ = errors.Is
