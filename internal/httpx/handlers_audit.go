package httpx

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// auditEntryResponse is one entry as the wire sees it.
//
// before and after are json.RawMessage rather than map[string]any so the stored object is
// passed through byte for byte. Re-encoding would round-trip the value through Go's map
// ordering and number handling, and an audit trail that reformats what it recorded is one
// step away from one that misreports it.
type auditEntryResponse struct {
	ID        string `json:"id"`
	ActorKind string `json:"actor_kind"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	At        string `json:"at"`

	// actor_id is absent rather than null for a system actor, so a client can tell
	// "no actor" from "an actor it is not allowed to see".
	ActorID *string `json:"actor_id,omitempty"`

	ResourceID *string         `json:"resource_id,omitempty"`
	Before     json.RawMessage `json:"before,omitempty"`
	After      json.RawMessage `json:"after,omitempty"`
	RequestID  *string         `json:"request_id,omitempty"`
}

// auditEntryResponseFrom maps a stored record onto the wire shape.
//
// It does not trim or reinterpret the images. They are what was recorded, and the endpoint's
// whole job is to report that faithfully.
func auditEntryResponseFrom(rec audit.Record) auditEntryResponse {
	out := auditEntryResponse{
		ID:        rec.ID.String(),
		ActorKind: rec.ActorKind,
		Action:    rec.Action,
		Resource:  rec.Resource,
		RequestID: rec.RequestID,
		At:        timestamp(rec.At),
	}
	if rec.ActorID != nil {
		s := rec.ActorID.String()
		out.ActorID = &s
	}
	if rec.ResourceID != nil {
		s := rec.ResourceID.String()
		out.ResourceID = &s
	}
	if len(rec.Before) > 0 {
		out.Before = json.RawMessage(rec.Before)
	}
	if len(rec.After) > 0 {
		out.After = json.RawMessage(rec.After)
	}
	return out
}

// handleListAudit returns one page of a tenant's audit trail, newest first.
//
// # Why this is read-only, and stays that way
//
// There is no endpoint that creates, edits, or deletes an entry, and there should never be
// one. Entries are written by the operations they describe, inside those operations'
// transactions; a client that could write here could fabricate a history, which would make
// the whole trail worthless rather than merely incomplete.
//
// # Why the permission is separate from tenant:read
//
// The trail names who did what, including the API keys in use and the request ids to
// correlate. That is operational detail about a tenant's users, not tenant metadata, so it
// gets its own permission — an admin who can rename a workspace should not automatically be
// able to enumerate its members' actions.
func (d Deps) handleListAudit(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	if d.Audit == nil {
		// A router assembled without an audit reader has none to serve. Reported as
		// not-found rather than as a 500, because from the client's side the resource simply
		// does not exist on this deployment, and creating an error-alert on a
		// deliberately-absent feature is noise.
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	limit, rawCursor, err := pageParams(r)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	// The binding ties the cursor to this tenant and this resource, so a cursor minted for
	// another listing is rejected as a mismatch rather than silently returning a page the
	// client cannot recognise as wrong.
	binding := audit.Binding(auth)

	var after *cursor.Position
	if rawCursor != "" {
		pos, err := d.Cursors.Decode(binding, rawCursor)
		if err != nil {
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

	page, err := d.Audit.List(r.Context(), auth, after, limit)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]auditEntryResponse, 0, len(page.Entries))
	for _, rec := range page.Entries {
		items = append(items, auditEntryResponseFrom(rec))
	}

	// The next cursor is minted from the position the domain reported rather than being
	// recomputed here, so the ordering rule lives in one place.
	var nextToken string
	if page.Next != nil {
		token, encErr := d.Cursors.Encode(binding, *page.Next)
		if encErr != nil {
			// The codec is misconfigured rather than the request being bad. The page is
			// valid, so it is returned without a cursor rather than discarded.
			d.Log.Error("failed to encode a pagination cursor", "err", encErr)
		} else {
			nextToken = token
		}
	}

	httperr.Page(w, items, nextToken)
}
