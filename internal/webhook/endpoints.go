package webhook

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/reqid"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// endpointColumns is the projection every read uses, so a scan and its query cannot drift.
//
// The secret is deliberately absent: it is read only by Claim, which needs it to sign a delivery,
// and never by a handler. A list endpoint that selected it would put every tenant's signing key
// in every response.
const endpointColumns = `id, tenant_id, url, events, description, active, created_by, created_by_key, created_at, updated_at`

func scanEndpoint(row pgx.Row) (Endpoint, error) {
	var e Endpoint
	err := row.Scan(&e.ID, &e.TenantID, &e.URL, &e.Events, &e.Description, &e.Active,
		&e.CreatedBy, &e.CreatedByKey, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// auditImage is the audited form of an endpoint.
//
// The URL is included — it is the point of the record — and the secret is not. The audit table is
// append-only and cannot be pruned, so a signing key written there would be permanent, and it
// would sit in a table whose whole purpose is to be readable by anyone with audit:read.
//
// Attribution is included because this is the resource where it matters most. A webhook endpoint
// is an outbound request to a URL the tenant chooses — the shape of an exfiltration channel — so
// "which credential registered this?" is the first question asked when one is found pointing
// somewhere it should not. The creator_exactly_one column pair guarantees an answer exists in the
// table; without these two keys the audit trail could not supply it, and the trail is what an
// investigator actually reads. Omitting them would repeat the defect this milestone kept finding:
// a comment claiming a guarantee the code does not provide.
func auditImage(e Endpoint) map[string]any {
	return map[string]any{
		"id":             e.ID.String(),
		"url":            e.URL,
		"events":         e.Events,
		"description":    e.Description,
		"active":         e.Active,
		"created_by":     e.CreatedBy,
		"created_by_key": e.CreatedByKey,
	}
}

// CreateEndpoint registers a receiver.
//
// # The secret is returned exactly once
//
// It is generated here, stored on the row, and handed back to the caller in this response. No
// other read selects it, so if the tenant loses it they register a new endpoint — which is the
// same one-time-display shape as an API key, and for the same reason: a secret that can be read
// back is a secret that leaks from a list endpoint, a log, or a support screenshot.
//
// # The URL has already been resolved by the caller
//
// SSRF validation needs a DNS lookup and therefore a context, which is why it is not here — see
// ssrf.Guard.ValidateEndpointURL. Validating in the handler rather than the store keeps this
// method free of the network, which is what makes it testable.
func (s *Store) CreateEndpoint(ctx context.Context, auth tenant.Authorized, validated CreateInput) (Endpoint, string, error) {
	if !auth.Valid() {
		return Endpoint{}, "", apperr.ErrNoScope
	}

	secret, err := GenerateSecret()
	if err != nil {
		return Endpoint{}, "", err
	}

	e := Endpoint{
		ID:          uuid.Must(uuid.NewV7()),
		TenantID:    auth.Scope().ID(),
		URL:         validated.URL,
		Events:      validated.Events,
		Description: validated.Description,
		Active:      true,
	}

	// Attribution comes from the authorized principal, never from the request body. A client that
	// could name its own author would make the audit trail a record of what the caller claimed
	// rather than what the platform verified — the same argument as projects, and here the columns
	// are NOT NULL-enforced by webhook_endpoints_creator_exactly_one, so a bug in this block is a
	// constraint violation rather than a silently unattributed endpoint.
	if auth.IsMachine() {
		keyID := auth.KeyID()
		e.CreatedByKey = &keyID
	} else {
		userID := auth.UserID()
		e.CreatedBy = &userID
	}

	actorID, actorKind, err := audit.ActorFromAuthorized(auth)
	if err != nil {
		return Endpoint{}, "", err
	}

	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var scanErr error
		e, scanErr = scanEndpoint(tx.QueryRow(ctx, `
			INSERT INTO webhook_endpoints (id, tenant_id, url, secret, events, description, active, created_by, created_by_key)
			VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8)
			RETURNING `+endpointColumns,
			e.ID, e.TenantID, e.URL, secret, e.Events, e.Description, e.CreatedBy, e.CreatedByKey))
		if scanErr != nil {
			return fmt.Errorf("create webhook endpoint: %w", scanErr)
		}
		// Recorded inside the transaction, like every other audit entry: the registration and its
		// record commit together or neither does.
		return audit.Write(ctx, tx, audit.Entry{
			TenantID:   e.TenantID,
			ActorID:    actorID,
			ActorKind:  actorKind,
			Action:     audit.ActionWebhookEndpointCreate,
			Resource:   "webhook_endpoint",
			ResourceID: &e.ID,
			Before:     nil,
			After:      auditImage(e),
			RequestID:  reqid.From(ctx),
		})
	})
	if err != nil {
		return Endpoint{}, "", err
	}
	return e, secret, nil
}

// GetEndpoint returns one endpoint in the caller's tenant.
func (s *Store) GetEndpoint(ctx context.Context, auth tenant.Authorized, id uuid.UUID) (Endpoint, error) {
	if !auth.Valid() {
		return Endpoint{}, apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return Endpoint{}, ErrNotFound
	}

	var e Endpoint
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var scanErr error
		e, scanErr = scanEndpoint(tx.QueryRow(ctx,
			`SELECT `+endpointColumns+` FROM webhook_endpoints WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		return scanErr
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Endpoint{}, ErrNotFound
	case err != nil:
		return Endpoint{}, fmt.Errorf("get webhook endpoint: %w", err)
	}
	return e, nil
}

// ListEndpoints returns one page of endpoints, newest first.
//
// Keyset on (created_at, id) like every other listing. The count is small — a tenant has a
// handful of receivers — but the page shape is the same everywhere so a client does not have to
// learn two.
func (s *Store) ListEndpoints(ctx context.Context, auth tenant.Authorized, after *cursor.Position, limit int) ([]Endpoint, *cursor.Position, error) {
	if !auth.Valid() {
		return nil, nil, apperr.ErrNoScope
	}
	limit = NormalizePageSize(limit)

	var out []Endpoint
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var afterTime *time.Time
		var afterID uuid.UUID
		if after != nil {
			t := after.Time
			afterTime = &t
			afterID = after.ID
		}

		rows, err := tx.Query(ctx, `
			SELECT `+endpointColumns+`
			  FROM webhook_endpoints
			 WHERE tenant_id = $1
			   AND ($2::timestamptz IS NULL OR (created_at, id) < ($2::timestamptz, $3::uuid))
			 ORDER BY created_at DESC, id DESC
			 LIMIT $4`,
			auth.Scope().ID(), afterTime, afterID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanEndpoint(rows)
			if err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, nil, fmt.Errorf("list webhook endpoints: %w", err)
	}

	var next *cursor.Position
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = &cursor.Position{Time: last.CreatedAt, ID: last.ID}
	}
	return out, next, nil
}

// UpdateEndpoint changes an endpoint's subscription, description, or active flag.
//
// Deactivation rather than deletion is the retirement path, which is why there is no Delete: the
// outbox rows reference the endpoint, and removing it would cascade the delivery history away.
// "We sent that and it failed" is the fact an operator needs during an incident, and it would be
// destroyed by the tidiest-looking cleanup.
func (s *Store) UpdateEndpoint(ctx context.Context, auth tenant.Authorized, id uuid.UUID, in UpdateInput) (Endpoint, error) {
	if !auth.Valid() {
		return Endpoint{}, apperr.ErrNoScope
	}
	if id == uuid.Nil {
		return Endpoint{}, ErrNotFound
	}

	if in.Events != nil {
		normalized, err := ValidateEvents(*in.Events)
		if err != nil {
			return Endpoint{}, err
		}
		in.Events = &normalized
	}
	if in.Description != nil {
		desc := trimSpace(*in.Description)
		if len(desc) > 500 {
			return Endpoint{}, apperr.Invalid("description", "must be at most 500 characters")
		}
		in.Description = &desc
	}

	actorID, actorKind, err := audit.ActorFromAuthorized(auth)
	if err != nil {
		return Endpoint{}, err
	}

	var e Endpoint
	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		before, err := scanEndpoint(tx.QueryRow(ctx,
			`SELECT `+endpointColumns+` FROM webhook_endpoints WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("read endpoint before update: %w", err)
		}

		updated, err := scanEndpoint(tx.QueryRow(ctx, `
			UPDATE webhook_endpoints
			   SET events      = COALESCE($3, events),
			       description = COALESCE($4, description),
			       active      = COALESCE($5, active),
			       updated_at  = now()
			 WHERE id = $1 AND tenant_id = $2
			RETURNING `+endpointColumns,
			id, auth.Scope().ID(), in.Events, in.Description, in.Active))
		if err != nil {
			return fmt.Errorf("update webhook endpoint: %w", err)
		}
		e = updated

		return audit.Write(ctx, tx, audit.Entry{
			TenantID:   e.TenantID,
			ActorID:    actorID,
			ActorKind:  actorKind,
			Action:     audit.ActionWebhookEndpointUpdate,
			Resource:   "webhook_endpoint",
			ResourceID: &e.ID,
			Before:     auditImage(before),
			After:      auditImage(e),
			RequestID:  reqid.From(ctx),
		})
	})
	if err != nil {
		return Endpoint{}, err
	}
	return e, nil
}

// EndpointBinding describes the query an endpoint-listing cursor belongs to.
func EndpointBinding(auth tenant.Authorized) cursor.Binding {
	return cursor.Binding{
		TenantID: auth.Scope().ID(),
		Resource: "webhook_endpoints",
		Filter:   "all",
	}
}

// trimSpace is a local helper so this file does not import strings for one call.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
