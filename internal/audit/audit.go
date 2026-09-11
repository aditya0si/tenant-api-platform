// Package audit records who changed what, in the same transaction as the change.
//
// # The one property that makes an audit trail worth having
//
// An entry is written inside the transaction that performs the effect, and the transaction
// carries the policy's tenant settings, so the two commit together or neither does. This is
// the whole design:
//
//	A trail that can lose an entry while the effect persists is not an audit trail. It is a
//	best-effort log with a schema, and it is worse than nothing because it is trusted.
//
// The alternative — recording after the fact, or from a queue — fails precisely when it
// matters. A crash between the write and the record leaves a changed resource with no entry,
// and an attacker who can make the recorder fail gets to act unlogged. So Write takes a
// pgx.Tx rather than opening its own, and a failure to record fails the request.
//
// # Why this is not middleware
//
// A transport-level middleware cannot express it: it sees a request and a response, not the
// rows that changed, and it cannot join a transaction it did not open. The before/after
// images only exist inside the handler's own transaction, which is why recording happens
// there. The same constraint was documented for idempotency in ADR-004; here it is not a
// limitation to work around but the reason for the design.
//
// # What is recorded
//
// The fields the API exposes, never raw rows and never secrets. This table is append-only
// and cannot be pruned, so anything written into it is written permanently — a password
// hash or a session token stored here would be a permanent secret store by accident.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
)

// Actor kinds. Each names a different answer to "who did this", and collapsing them would
// make an unattended action indistinguishable from a person's.
const (
	ActorUser   = "user"
	ActorAPIKey = "api_key"
	ActorSystem = "system"
)

// Actions, as dotted verbs. They are constants rather than literals at each call site so a
// typo is a compile error, and so the set of things this system can do is enumerable by
// reading one file — which is what makes the trail queryable in a year.
const (
	ActionProjectCreate  = "project.create"
	ActionProjectUpdate  = "project.update"
	ActionProjectArchive = "project.archive"

	// Invoice actions. The lifecycle transitions are recorded as distinct verbs rather than
	// as one "invoice.update", because "when was this paid" is the question actually asked of
	// an invoice and it should not require diffing two images to answer.
	ActionInvoiceCreate      = "invoice.create"
	ActionInvoiceItemAdded   = "invoice.item_added"
	ActionInvoiceItemRemoved = "invoice.item_removed"
	ActionInvoiceIssued      = "invoice.issued"
	ActionInvoicePaid        = "invoice.paid"
	ActionInvoiceVoided      = "invoice.voided"

	// Webhook actions. Registration and its modification are recorded because they change where a
	// tenant's data is sent — which is a security-relevant fact, not an administrative one. A
	// replay is recorded for the same reason: re-sending an event the receiver already saw is an
	// action somebody should be able to account for.
	ActionWebhookEndpointCreate = "webhook_endpoint.create"
	ActionWebhookEndpointUpdate = "webhook_endpoint.update"
	ActionWebhookDeliveryReplay = "webhook_delivery.replay"
)

// Entry is one audit record.
type Entry struct {
	TenantID   uuid.UUID
	ActorID    *uuid.UUID
	ActorKind  string
	Action     string
	Resource   string
	ResourceID *uuid.UUID

	// Before and After are marshalled to JSON. They are `any` rather than json.RawMessage
	// so a caller passes the struct it already has instead of pre-encoding it — pre-encoding
	// at the call site is where a field gets forgotten.
	Before any
	After  any

	// RequestID ties the entry to the logs and the response that produced it.
	RequestID string
}

// Validate reports whether an entry is well-formed.
//
// It runs before the INSERT so a malformed entry is a clear error rather than a constraint
// violation, and it is exported because a caller assembling an entry is doing something the
// package cannot check — the fields come from a handler.
func (e Entry) Validate() error {
	if e.TenantID == uuid.Nil {
		return errors.New("audit: entry has no tenant")
	}
	switch e.ActorKind {
	case ActorUser, ActorAPIKey:
		if e.ActorID == nil {
			return fmt.Errorf("audit: actor_kind %q requires an actor id", e.ActorKind)
		}
	case ActorSystem:
		if e.ActorID != nil {
			return errors.New("audit: actor_kind system must not carry an actor id")
		}
	default:
		return fmt.Errorf("audit: unknown actor_kind %q", e.ActorKind)
	}
	if !strings.Contains(e.Action, ".") {
		return fmt.Errorf("audit: action %q is not a dotted verb", e.Action)
	}
	if e.Resource == "" {
		return errors.New("audit: entry names no resource")
	}
	if e.Before == nil && e.After == nil {
		return errors.New("audit: entry records neither before nor after, so it says nothing changed")
	}
	return nil
}

// Write records an entry using the caller's transaction.
//
// Taking a pgx.Tx is the design, not a convenience: it is what makes the entry and the effect
// atomic. A caller that cannot provide its transaction cannot provide this guarantee, and
// should not be recording an audit entry at all.
func Write(ctx context.Context, tx pgx.Tx, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}

	before, err := marshalImage(e.Before)
	if err != nil {
		return fmt.Errorf("audit: encode before image: %w", err)
	}
	after, err := marshalImage(e.After)
	if err != nil {
		return fmt.Errorf("audit: encode after image: %w", err)
	}

	var requestID *string
	if e.RequestID != "" {
		requestID = &e.RequestID
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log
			(id, tenant_id, actor_id, actor_kind, action, resource, resource_id,
			 before, after, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		uuid.Must(uuid.NewV7()), e.TenantID, e.ActorID, e.ActorKind, e.Action,
		e.Resource, e.ResourceID, before, after, requestID); err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Action, err)
	}
	return nil
}

// marshalImage encodes an image, mapping a nil interface to SQL NULL rather than JSON null.
//
// The distinction is load-bearing for the create case: a create has no before image, and
// storing the four bytes "null" would make `before IS NULL` — the query anyone would write to
// find creates — return nothing.
func marshalImage(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// ActorFromAuthorized builds the actor for a tenant-scoped caller.
//
// It lives here rather than on tenant.Authorized so that the tenant package stays unaware of
// auditing: attribution is this package's concern, and a method on Authorized returning an
// audit type would make tenant import audit for no reason but convenience.
func ActorFromAuthorized(auth tenant.Authorized) (*uuid.UUID, string, error) {
	if auth.IsMachine() {
		id := auth.KeyID()
		return &id, ActorAPIKey, nil
	}
	id := auth.UserID()
	if id == uuid.Nil {
		return nil, "", apperr.ErrNoScope
	}
	return &id, ActorUser, nil
}

// Record is the read model: what came back out of the table.
type Record struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	ActorID    *uuid.UUID
	ActorKind  string
	Action     string
	Resource   string
	ResourceID *uuid.UUID
	Before     []byte
	After      []byte
	RequestID  *string
	At         time.Time
}

// IsAppendOnlyViolation reports whether err is the trigger refusing a mutation.
//
// It checks the message as well as the SQLSTATE because the trigger deliberately raises
// 42501 — insufficient_privilege, which is the honest code for "not permitted" — and a
// row-level-security refusal uses the same code. Message matching is usually a smell; here
// the alternative is a shared code with two meanings, and the trigger's message is a
// constant this package controls.
func IsAppendOnlyViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "append-only")
}
