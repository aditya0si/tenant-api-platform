package httpx

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/project"
)

// Requests and responses for the project endpoints.
//
// Separate types from the domain's own, so the wire format can change without
// touching how a project is stored — and so that a field the domain gains is not
// published by accident. Publishing a field is a decision, and the compiler should
// not make it on our behalf.

type createProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
}

type updateProjectRequest struct {
	// Pointers so an omitted field is distinguishable from one set to empty. In a
	// PATCH that distinction is the whole semantic: sending {"name":"x"} must not
	// clear the description, and sending {"description":""} must.
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`

	// ExpectedVersion is required, and there is no default. An update without a
	// version assertion is a last-write-wins write, which is precisely the behaviour
	// version exists to prevent — so the type makes it mandatory rather than
	// optional-with-a-default, which a client would silently get wrong.
	ExpectedVersion int `json:"expected_version"`
}

type projectResponse struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	Version     int    `json:"version"`

	// Attribution. Exactly one of these is set, which the database enforces. Both are
	// omitted when unset rather than serialised as empty strings, so a client can test
	// for presence instead of comparing against "".
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedByKey string `json:"created_by_key,omitempty"`

	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
	ArchivedAt *string `json:"archived_at,omitempty"`
}

func projectResponseFrom(p project.Project) projectResponse {
	return projectResponse{
		ID:           p.ID.String(),
		TenantID:     p.TenantID.String(),
		Name:         p.Name,
		Slug:         p.Slug,
		Description:  p.Description,
		Version:      p.Version,
		CreatedBy:    uuidPtrString(p.CreatedBy),
		CreatedByKey: uuidPtrString(p.CreatedByKey),
		CreatedAt:    timestamp(p.CreatedAt),
		UpdatedAt:    timestamp(p.UpdatedAt),
		ArchivedAt:   timestampPtr(p.ArchivedAt),
	}
}

// uuidPtrString renders an optional id, or "" when unset.
func uuidPtrString(id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

// handleCreateProject creates a project in the scoped tenant.
func (d Deps) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	var req createProjectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	created, err := d.Projects.Create(r.Context(), auth, project.CreateInput{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
	})
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	// Location is set explicitly here rather than inside the Created helper, which
	// cannot know the resource's canonical path. A wrong Location is worse than
	// none: a client that follows it would be misled.
	w.Header().Set("Location", projectURL(auth.Scope().ID(), created.ID))
	httperr.Created(w, projectResponseFrom(created))
}

// handleListProjects returns one page of projects, newest first.
func (d Deps) handleListProjects(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	limit, rawCursor, err := pageParams(r)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	includeArchived, err := boolParam(r, "include_archived")
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	filter := project.ListFilter{IncludeArchived: includeArchived}

	// The binding ties this cursor to this tenant, this resource, and this filter.
	// It is computed before decoding so a cursor from a different query is rejected
	// as a mismatch rather than silently returning a page the client cannot
	// recognise as wrong.
	binding := project.Binding(auth, filter)

	var after *cursor.Position
	if rawCursor != "" {
		pos, err := d.Cursors.Decode(binding, rawCursor)
		if err != nil {
			// A cursor from a different query is a client state bug rather than a
			// malformed token, and saying so is far more useful than "invalid
			// cursor" — it points at the cause instead of the symptom.
			if errors.Is(err, cursor.ErrBinding) {
				httperr.Fail(w, r, d.Log, apperr.Invalid("cursor",
					"this cursor belongs to a different query; start from the first page"))
				return
			}
			httperr.Fail(w, r, d.Log, apperr.Invalid("cursor", "the cursor is not valid"))
			return
		}
		after = &pos
	}

	page, err := d.Projects.List(r.Context(), auth, filter, after, limit)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]projectResponse, 0, len(page.Projects))
	for _, p := range page.Projects {
		items = append(items, projectResponseFrom(p))
	}

	// The next cursor is minted from the position the domain reported, not from the
	// last item's fields read back here. Recomputing it at the transport layer would
	// be a second place the ordering rule lives, and the two would eventually
	// disagree about what "last" means.
	var nextToken string
	if page.Next != nil {
		nextToken, err = d.Cursors.Encode(binding, *page.Next)
		if err != nil {
			// Encoding failed, which means the codec is misconfigured rather than
			// that the request was bad. The page itself is valid, so it is returned
			// without a cursor rather than discarded — the client can still use the
			// data, and the operator sees the error.
			d.Log.Error("failed to encode a pagination cursor", "err", err)
		}
	}

	httperr.Page(w, items, nextToken)
}

// handleGetProject returns one project.
func (d Deps) handleGetProject(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "projectID"))
	if err != nil {
		// A malformed id cannot name a real project, so it is reported as not-found
		// rather than as a bad request: collapsing the two keeps the response
		// surface uniform, so nothing about id format can be learned from the
		// status code.
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	p, err := d.Projects.Get(r.Context(), auth, id)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, projectResponseFrom(p))
}

// handleUpdateProject applies a partial update.
func (d Deps) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "projectID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	var req updateProjectRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	if req.Name == nil && req.Description == nil {
		httperr.Fail(w, r, d.Log, apperr.Invalid("body", "supply at least one field to update"))
		return
	}

	updated, err := d.Projects.Update(r.Context(), auth, id, project.UpdateInput{
		Name:            req.Name,
		Description:     req.Description,
		ExpectedVersion: req.ExpectedVersion,
	})
	if err != nil {
		// A version conflict is answered by Map with 409 and a message telling the
		// client to re-read. That is the whole point of separating it from
		// not-found: a client that received 404 here would conclude the project was
		// deleted, which is a different and wrong action.
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, projectResponseFrom(updated))
}

// handleArchiveProject retires a project.
//
// DELETE archives rather than removing the row: a project is referenced by
// everything that will later hang off it, so the fact that it existed is worth
// keeping. The response is 204 either way, since the endpoint's effect is
// idempotent — archiving an archived project is not an error.
func (d Deps) handleArchiveProject(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "projectID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	if err := d.Projects.Archive(r.Context(), auth, id); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.NoContent(w)
}

// projectURL renders a project's canonical path.
func projectURL(tenantID, projectID uuid.UUID) string {
	return "/v1/tenants/" + tenantID.String() + "/projects/" + projectID.String()
}

// normalizeErrorText is a small helper used by tests to compare messages without
// depending on wrapping depth.
var _ = strings.TrimSpace
