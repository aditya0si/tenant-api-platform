// Package project owns projects: the resource tenants organise work under.
//
// Every method takes a tenant.Authorized, which only an authorization path can
// construct, so a project can never be reached without a resolved, authorized tenant.
// That is the first bound; row-level security is the second, and it holds even for a
// query that forgets its tenant predicate.
package project

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/idgen"
)

// Pagination bounds.
//
// The default is deliberately small: a list endpoint's job is to let a client walk a
// collection, and a large default turns a careless client into load. The maximum
// exists so a caller cannot ask for the whole tenant in one request and get a response
// whose size is a function of someone else's data volume.
const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// Project is a unit of work belonging to exactly one tenant.
type Project struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Slug        string
	Description string

	// Version supports optimistic concurrency: it is asserted on every update and
	// incremented, so two clients editing the same project cannot silently overwrite
	// each other.
	Version int

	// Attribution. Exactly one of these is set, which the database enforces with a
	// CHECK constraint rather than leaving to the application.
	//
	// Both are pointers because both columns are nullable, and the pair is what makes
	// "who created this" answerable for a human and for a machine. A key is not a user,
	// so recording a machine-created project against a user column would be a lie the
	// audit trail then repeats.
	CreatedBy    *uuid.UUID
	CreatedByKey *uuid.UUID

	CreatedAt time.Time
	UpdatedAt time.Time

	// ArchivedAt is set when a project is retired. Archive rather than delete, because
	// "this project existed and was retired" is almost always the fact worth keeping,
	// and a hard delete would cascade or orphan whatever will later reference it.
	ArchivedAt *time.Time
}

// Archived reports whether the project has been retired.
func (p Project) Archived() bool { return p.ArchivedAt != nil }

// CreatedByHuman reports whether a user created this project.
func (p Project) CreatedByHuman() bool { return p.CreatedBy != nil }

// CreatedByMachine reports whether an API key created this project.
func (p Project) CreatedByMachine() bool { return p.CreatedByKey != nil }

// CreateInput is the caller-supplied part of a new project.
type CreateInput struct {
	Name        string
	Description string

	// Slug may be empty, in which case it is derived from Name. Supplying one is how a
	// client asks for a vanity URL; it is validated either way, because a derived slug
	// and a supplied one must be indistinguishable afterwards.
	Slug string
}

// UpdateInput is a partial update. A nil field means "leave unchanged", which is
// distinct from a pointer to the zero value ("set to empty").
//
// Pointers rather than a struct with a "fields present" mask because the mask is then
// implicit in the type: a caller cannot forget to set it, and a reviewer can see at a
// glance which fields the update can touch.
type UpdateInput struct {
	Name        *string
	Description *string

	// ExpectedVersion is required. An update without a version assertion is a
	// last-write-wins write, which is exactly the behaviour version exists to prevent —
	// so it is not offered as an option.
	ExpectedVersion int
}

// ListFilter selects which projects a listing covers, and is hashed into the pagination
// cursor's binding.
//
// It must be canonical: the same logical query must always render to the same
// fingerprint, or valid cursors will be rejected as belonging to a different query.
// Adding a field here means adding it to bindingFilter below.
type ListFilter struct {
	IncludeArchived bool
}

// bindingFilter renders a filter canonically for cursor binding.
//
// It is a single function so the encode and decode paths cannot disagree — a divergence
// would present as "the cursor we just handed you is invalid".
func bindingFilter(f ListFilter) string {
	return fmt.Sprintf("archived=%t", f.IncludeArchived)
}

// ListResult is one page of projects plus the position of the last row returned.
//
// Next is nil when the page is the last one, which is how a client knows to stop without
// an extra request. It is a cursor.Position rather than an encoded token because
// encoding needs the signing key, which belongs to the HTTP layer: the domain package
// has no business knowing how a position is serialised.
type ListResult struct {
	Projects []Project
	Next     *cursor.Position
}

// NormalizePageSize clamps a requested page size into the supported range.
//
// It returns the effective size rather than an error: a client asking for 1000 items is
// not doing anything wrong, it just cannot have them, and failing the request would be
// less useful than answering with as much as the service is willing to serve.
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

// slugPattern mirrors the CHECK constraint on projects.slug. The database is the
// authority; this copy exists so a bad slug produces a 400 with a usable message rather
// than a 500 wrapping a constraint violation.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// validateCreate checks a create request before any SQL runs.
//
// Every failure is an apperr.Invalid, which is a distinct type precisely so its message
// reaches the client verbatim: the message names the field and says what is wrong with
// it, because the client is who has to fix it. A wrapped sentinel would append
// "validation failed" to the sentence and prefix it with a package name — internal
// vocabulary leaking into an API response, which is the signature of an error that was
// never formatted for a consumer.
func validateCreate(in CreateInput) (CreateInput, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 200 {
		return in, apperr.Invalid("name", "must be between 1 and 200 characters")
	}
	if len(in.Description) > 2000 {
		return in, apperr.Invalid("description", "must be at most 2000 characters")
	}

	slug := in.Slug
	if slug == "" {
		slug = Slugify(name)
	}
	if !slugPattern.MatchString(slug) {
		return in, apperr.Invalid("slug",
			"must be 2-63 characters of lowercase letters, digits, and single hyphens, and must not start with a hyphen")
	}

	in.Name = name
	in.Slug = slug
	return in, nil
}

// Slugify derives a URL-safe slug from a name.
//
// The result is guaranteed to satisfy slugPattern, because a derived slug that failed
// validation would make creation fail for a name the user is entitled to use — a
// confusing error about a field they never filled in. Names that reduce to fewer than two
// characters (all punctuation, or a single letter) get a short random suffix rather than
// being rejected, since the pattern's two-character minimum exists to avoid degenerate
// URLs, not to constrain what a user may call their project.
func Slugify(name string) string {
	var b strings.Builder
	lastDash := true // a leading dash is not allowed by the pattern
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
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
			slug = "p"
		}
		// idgen, not a UUID slice: a UUIDv7's leading characters are a timestamp, so
		// slicing them yields the same "random" suffix for every call in a millisecond —
		// see internal/platform/idgen for the full account of that bug.
		slug = slug + "-" + idgen.ShortSuffix(6)
	}
	return slug
}

// SlugifyForCollision derives a slug with a random suffix appended, for use when a
// derived slug is already taken.
//
// The base is capped so the result still satisfies the constraint's 63-character limit: a
// 62-character base plus a hyphen and six characters would be rejected as a validation
// error rather than retried, which is a confusing outcome for an otherwise legal name.
func SlugifyForCollision(name string) string {
	base := Slugify(name)
	const maxBase = 55 // 55 + 1 + 6 = 62, inside the pattern's 63-character ceiling
	if len(base) > maxBase {
		base = strings.TrimRight(base[:maxBase], "-")
	}
	return base + "-" + idgen.ShortSuffix(6)
}
