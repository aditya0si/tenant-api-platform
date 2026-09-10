package project

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// Store is the project repository.
//
// Every method takes a tenant.Authorized, which only an authorization path can
// construct. There is no method that accepts a bare tenant id or a raw scope, so a
// handler cannot reach project data without having authorized first — and the queries
// are additionally bounded by row-level security, which holds even if a future query
// forgets its tenant predicate.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by pool. As everywhere else, the pool must
// authenticate as a role that row-level security applies to (app_rw); a superuser pool
// makes the policies decorative.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// selectColumns is the column list every read uses, in one place so a scan and a
// RETURNING clause cannot drift apart.
const selectColumns = `id, tenant_id, name, slug, description, version, created_by, created_by_key, created_at, updated_at, archived_at`

// scanProject reads one row into a Project. It exists because the column list above
// appears in four statements, and a scan written out four times is a scan that will
// eventually be updated three times.
func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Slug, &p.Description, &p.Version,
		&p.CreatedBy, &p.CreatedByKey, &p.CreatedAt, &p.UpdatedAt, &p.ArchivedAt)
	return p, err
}

// Create inserts a project in the caller's tenant.
//
// # Attribution comes from the authorization, not the request
//
// Which column records the creator depends on the kind of principal: a human goes in
// created_by, a machine credential in created_by_key. The database enforces that exactly
// one is set (projects_creator_exactly_one), so a bug here surfaces as a constraint
// violation rather than as a project with no identifiable author.
//
// Crucially, the value comes from the authorized principal rather than from the request
// body. Attribution a client supplies is not attribution.
func (s *Store) Create(ctx context.Context, auth tenant.Authorized, in CreateInput) (Project, error) {
	if !auth.Valid() {
		return Project{}, apperr.ErrNoScope
	}
	validated, err := validateCreate(in)
	if err != nil {
		return Project{}, err
	}

	p := Project{
		ID:          uuid.Must(uuid.NewV7()),
		TenantID:    auth.Scope().ID(),
		Name:        validated.Name,
		Slug:        validated.Slug,
		Description: validated.Description,
		Version:     1,
	}
	if auth.IsMachine() {
		keyID := auth.KeyID()
		p.CreatedByKey = &keyID
	} else {
		userID := auth.UserID()
		p.CreatedBy = &userID
	}

	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var scanErr error
		p, scanErr = scanProject(tx.QueryRow(ctx, `
			INSERT INTO projects (id, tenant_id, name, slug, description, version, created_by, created_by_key)
			VALUES ($1, $2, $3, $4, $5, 1, $6, $7)
			RETURNING `+selectColumns,
			p.ID, p.TenantID, p.Name, p.Slug, p.Description, p.CreatedBy, p.CreatedByKey))
		return scanErr
	})
	if err != nil {
		// The partial unique index is on (tenant_id, slug) WHERE archived_at IS NULL, so
		// this fires only against a live project — reusing the slug of an archived one is
		// allowed, which is what archiving is for.
		if db.IsUniqueViolation(err) {
			return Project{}, fmt.Errorf("a project with the slug %q already exists in this tenant: %w", p.Slug, apperr.ErrConflict)
		}
		return Project{}, fmt.Errorf("create project: %w", err)
	}
	return p, nil
}

// Get returns one project in the caller's tenant, or ErrNotFound.
//
// The tenant predicate and the row-level-security policy overlap deliberately: the
// predicate is what the index can use, and the policy is what holds if the predicate is
// ever dropped in a refactor. A project belonging to another tenant is reported as
// not-found rather than forbidden, so the endpoint cannot be used to probe which ids
// exist.
func (s *Store) Get(ctx context.Context, auth tenant.Authorized, id uuid.UUID) (Project, error) {
	if !auth.Valid() {
		return Project{}, apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return Project{}, apperr.ErrNotFound
	}

	var p Project
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var scanErr error
		p, scanErr = scanProject(tx.QueryRow(ctx,
			`SELECT `+selectColumns+` FROM projects WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		return scanErr
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Project{}, apperr.ErrNotFound
	case err != nil:
		return Project{}, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

// Update applies a partial update with optimistic concurrency.
//
// # Why the version predicate is in the WHERE clause
//
// The check is a single conditional UPDATE rather than a read followed by a write.
// Between a read and a write, another client can commit, and the second writer would then
// overwrite a change it never saw — the classic lost update. Making the expected version
// part of the predicate means Postgres decides the winner: exactly one of two concurrent
// writers matches, and the loser sees zero rows.
//
// A zero-row result is then disambiguated by reading the current state, because "somebody
// else changed this" and "there is no such project" need different responses: the first
// is a 409 the client resolves by re-reading, the second is a 404.
func (s *Store) Update(ctx context.Context, auth tenant.Authorized, id uuid.UUID, in UpdateInput) (Project, error) {
	if !auth.Valid() {
		return Project{}, apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return Project{}, apperr.ErrNotFound
	}
	if in.ExpectedVersion <= 0 {
		return Project{}, apperr.Invalid("expected_version", "must be a positive integer")
	}
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" || len(name) > 200 {
			return Project{}, apperr.Invalid("name", "must be between 1 and 200 characters")
		}
		in.Name = &name
	}
	if in.Description != nil && len(*in.Description) > 2000 {
		return Project{}, apperr.Invalid("description", "must be at most 2000 characters")
	}

	var (
		p       Project
		outcome error
		got     bool
	)
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		// COALESCE keeps an omitted field unchanged: a nil pointer means "not supplied",
		// which is deliberately distinct from a pointer to the empty string, which means
		// "set it to empty".
		updated, err := scanProject(tx.QueryRow(ctx, `
			UPDATE projects
			   SET name        = COALESCE($3, name),
			       description = COALESCE($4, description),
			       version     = version + 1,
			       updated_at  = now()
			 WHERE id = $1
			   AND tenant_id = $2
			   AND version = $5
			   AND archived_at IS NULL
			RETURNING `+selectColumns,
			id, auth.Scope().ID(), in.Name, in.Description, in.ExpectedVersion))
		switch {
		case err == nil:
			p, got = updated, true
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("update project: %w", err)
		}

		// Zero rows. Distinguish the three causes with one read, inside the same
		// transaction so the classification cannot itself race.
		var (
			currentVersion int
			archivedAt     *time.Time
		)
		err = tx.QueryRow(ctx,
			`SELECT version, archived_at FROM projects WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()).Scan(&currentVersion, &archivedAt)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			outcome = apperr.ErrNotFound
			return nil
		case err != nil:
			return fmt.Errorf("classify update failure: %w", err)
		case archivedAt != nil:
			// An archived project is not editable. Reported as not-found rather than as a
			// distinct state so the API's visible surface stays the same size; the audit
			// log records the archive event for anyone who needs it.
			outcome = apperr.ErrNotFound
			return nil
		default:
			outcome = fmt.Errorf(
				"this project was modified by someone else (expected version %d, current version %d); re-read it and retry: %w",
				in.ExpectedVersion, currentVersion, apperr.ErrVersionConflict)
			return nil
		}
	})
	switch {
	case err != nil:
		return Project{}, err
	case outcome != nil:
		return Project{}, outcome
	case !got:
		// Unreachable: every branch above either returns an error or sets outcome.
		return Project{}, fmt.Errorf("update project: no outcome for %s", id)
	}
	return p, nil
}

// Archive retires a project.
//
// It is idempotent: archiving an already-archived project succeeds, because the caller's
// intent is satisfied either way and a retry should not look like a failure. A project
// that does not exist — or belongs to another tenant — is not-found, which keeps the two
// indistinguishable from outside.
//
// The archived_at timestamp is only written once (WHERE archived_at IS NULL), so the
// recorded retirement time is the first one, not the time of the most recent retry.
func (s *Store) Archive(ctx context.Context, auth tenant.Authorized, id uuid.UUID) error {
	if !auth.Valid() {
		return apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return apperr.ErrNotFound
	}

	return db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE projects
			   SET archived_at = now(), updated_at = now(), version = version + 1
			 WHERE id = $1 AND tenant_id = $2 AND archived_at IS NULL`,
			id, auth.Scope().ID())
		if err != nil {
			return fmt.Errorf("archive project: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}

		var archivedAt *time.Time
		err = tx.QueryRow(ctx,
			`SELECT archived_at FROM projects WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()).Scan(&archivedAt)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return apperr.ErrNotFound
		case err != nil:
			return fmt.Errorf("classify archive failure: %w", err)
		case archivedAt != nil:
			return nil // already archived: the caller's intent is satisfied
		default:
			// Unreachable: a live row in this tenant would have matched the UPDATE. Kept
			// explicit so a future change to the predicate cannot silently turn this into
			// a success.
			return apperr.ErrNotFound
		}
	})
}

// List returns one page of projects, newest first, using keyset pagination.
//
// # The keyset predicate
//
// `(created_at, id) < (after.Time, after.ID)` is a row comparison, which Postgres
// evaluates against the composite index `(tenant_id, created_at DESC, id DESC)` by
// seeking straight to the position rather than scanning and discarding. That is what
// keeps page 500 the same cost as page 1.
//
// It is also what makes the page correct under concurrent writes. Rows inserted between
// two requests sort *after* the cursor, so they appear on a later page or not at all —
// never duplicated into, or skipped from, a page the client has already read. OFFSET has
// neither property.
//
// # Why limit+1
//
// One extra row is fetched to decide whether a next page exists, and then dropped. The
// alternative — treating "returned exactly limit rows" as "there is more" — produces a
// spurious empty final page on every complete listing.
func (s *Store) List(ctx context.Context, auth tenant.Authorized, filter ListFilter, after *cursor.Position, limit int) (ListResult, error) {
	if !auth.Valid() {
		return ListResult{}, apperr.ErrNoScope
	}
	limit = NormalizePageSize(limit)

	var out []Project
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		// afterTime is *time.Time rather than a pointer-to-interface: pgx encodes
		// *time.Time natively for a nullable timestamptz, whereas a *interface{} has no
		// registered codec and would fail at encode time. The nil case is the "first page"
		// request, which the predicate reads as "no cursor".
		var afterTime *time.Time
		var afterID uuid.UUID
		if after != nil {
			t := after.Time
			afterTime = &t
			afterID = after.ID
		}

		rows, err := tx.Query(ctx, `
			SELECT `+selectColumns+`
			FROM projects
			WHERE tenant_id = $1
			  AND ($2::boolean OR archived_at IS NULL)
			  AND ($3::timestamptz IS NULL OR (created_at, id) < ($3::timestamptz, $4::uuid))
			ORDER BY created_at DESC, id DESC
			LIMIT $5`,
			auth.Scope().ID(), filter.IncludeArchived, afterTime, afterID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProject(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list projects: %w", err)
	}

	res := ListResult{Projects: out}
	if len(out) > limit {
		// There is at least one more row. Report the position of the last row the client
		// actually received, so the next request resumes from exactly there and the extra
		// row is simply fetched again.
		res.Projects = out[:limit]
		last := out[limit-1]
		res.Next = &cursor.Position{Time: last.CreatedAt, ID: last.ID}
	}
	return res, nil
}

// Binding describes the query a pagination cursor belongs to, so a cursor minted for
// one listing cannot be replayed against another.
func Binding(auth tenant.Authorized, filter ListFilter) cursor.Binding {
	return cursor.Binding{
		TenantID: auth.Scope().ID(),
		Resource: "projects",
		Filter:   bindingFilter(filter),
	}
}
