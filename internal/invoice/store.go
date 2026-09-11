package invoice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/db"
	"github.com/aditya0si/tenant-api-platform/internal/platform/reqid"
	"github.com/aditya0si/tenant-api-platform/internal/tenant"
	"github.com/aditya0si/tenant-api-platform/internal/webhook"
)

// Store is the invoice repository.
//
// Every method takes a tenant.Authorized, so a handler cannot reach invoice data without
// having authorized first, and the queries are additionally bounded by row-level security.
type Store struct {
	pool *pgxpool.Pool

	// events records what happened, for delivery to the tenant's webhook endpoints.
	//
	// It is enqueued *inside* the transaction that changes the invoice, which is the whole reason
	// the outbox exists: an event written after commit is lost to a crash in the gap, and one
	// written before a rollback announces a change that never happened. Neither is fixable in a
	// transport layer, which cannot join a transaction it did not open — the same argument as the
	// audit trail, and the reason both are called from here rather than from a middleware.
	//
	// Nil disables delivery and is what the pure unit tests use; production always supplies one.
	events *webhook.Store
}

// NewStore builds a store. events may be nil, which emits nothing.
func NewStore(pool *pgxpool.Pool, events *webhook.Store) *Store {
	return &Store{pool: pool, events: events}
}

// emit records a domain event for delivery, in the caller's transaction.
//
// A failure is returned rather than logged and swallowed. Swallowing it would commit the invoice
// while losing the notification, which is the half-delivered state the outbox is designed to make
// impossible — the tenant's receiver would never learn, and nothing would record that it should
// have. Failing the request is the honest outcome: the client retries, and if the retry carries an
// idempotency key the work is not duplicated.
func (s *Store) emit(ctx context.Context, tx pgx.Tx, auth tenant.Authorized, event string, inv Invoice) error {
	if s.events == nil {
		return nil
	}
	if _, err := s.events.Enqueue(ctx, tx, auth.Scope().ID(), event, eventPayload(inv)); err != nil {
		return fmt.Errorf("invoice: enqueue %s: %w", event, err)
	}
	return nil
}

// eventPayload is what a receiver receives as the event's data.
//
// It is not the same projection as auditImage: the audit trail records that a change happened and
// to which fields, while a receiver has to act on it — an invoice.paid delivery with no line items
// would leave the integration fetching the invoice back, which is a second request that the
// payload could have made unnecessary.
//
// Amounts stay integers in minor units, matching the API and the schema. A receiver that wants
// "$12.34" formats it; one that needs to add it up cannot use a formatted string.
func eventPayload(inv Invoice) map[string]any {
	items := make([]map[string]any, 0, len(inv.Items))
	for _, it := range inv.Items {
		items = append(items, map[string]any{
			"description":      it.Description,
			"quantity":         it.Quantity,
			"unit_price_minor": it.UnitPriceMinor,
			"line_total_minor": it.LineTotalMinor,
		})
	}
	return map[string]any{
		"id":             inv.ID.String(),
		"number":         inv.Number,
		"status":         inv.Status,
		"currency":       inv.Currency,
		"subtotal_minor": inv.SubtotalMinor,
		"tax_minor":      inv.TaxMinor,
		"total_minor":    inv.TotalMinor,
		"version":        inv.Version,
		"items":          items,
	}
}

// eventForTransition maps a lifecycle transition onto the event it emits.
//
// The mapping is exhaustive over the three transitions and returns "" for anything else, so a new
// transition added without an event fails the emit rather than silently notifying nobody — a
// webhook that never fires is indistinguishable from a receiver that never received, which is the
// hardest kind of integration bug to notice.
func eventForTransition(t Transition) string {
	switch t {
	case TransitionIssue:
		return webhook.EventInvoiceIssued
	case TransitionPay:
		return webhook.EventInvoicePaid
	case TransitionVoid:
		return webhook.EventInvoiceVoided
	default:
		return ""
	}
}

// invoiceColumns is the projection every read uses, so a scan and its query cannot drift.
const invoiceColumns = `id, tenant_id, number, status, currency,
	subtotal_minor, tax_minor, total_minor, version,
	created_by, created_by_key,
	issued_at, paid_at, voided_at, created_at, updated_at`

const itemColumns = `id, invoice_id, tenant_id, position, description,
	quantity, unit_price_minor, line_total_minor, created_at`

func scanInvoice(row pgx.Row) (Invoice, error) {
	var inv Invoice
	err := row.Scan(&inv.ID, &inv.TenantID, &inv.Number, &inv.Status, &inv.Currency,
		&inv.SubtotalMinor, &inv.TaxMinor, &inv.TotalMinor, &inv.Version,
		&inv.CreatedBy, &inv.CreatedByKey,
		&inv.IssuedAt, &inv.PaidAt, &inv.VoidedAt, &inv.CreatedAt, &inv.UpdatedAt)
	return inv, err
}

func scanItem(row pgx.Row) (Item, error) {
	var it Item
	err := row.Scan(&it.ID, &it.InvoiceID, &it.TenantID, &it.Position, &it.Description,
		&it.Quantity, &it.UnitPriceMinor, &it.LineTotalMinor, &it.CreatedAt)
	return it, err
}

// auditImage is the audited form of an invoice: the fields the API exposes.
//
// Built explicitly rather than by marshalling the struct, for the reason given in the project
// store — the audit table is append-only and cannot be pruned, so adding a field to Invoice
// should not silently start publishing it into a permanent record.
func auditImage(inv Invoice) map[string]any {
	return map[string]any{
		"id":             inv.ID.String(),
		"number":         inv.Number,
		"status":         inv.Status,
		"currency":       inv.Currency,
		"subtotal_minor": inv.SubtotalMinor,
		"tax_minor":      inv.TaxMinor,
		"total_minor":    inv.TotalMinor,
		"version":        inv.Version,
		"item_count":     len(inv.Items),
	}
}

// auditInvoice records one invoice action inside the caller's transaction.
//
// Same guarantee as the project store: the entry and the change commit together or neither
// does, so a changed invoice can never exist without its record.
func auditInvoice(ctx context.Context, tx pgx.Tx, auth tenant.Authorized, action string, inv Invoice, before, after any) error {
	actorID, actorKind, err := audit.ActorFromAuthorized(auth)
	if err != nil {
		return err
	}
	id := inv.ID
	return audit.Write(ctx, tx, audit.Entry{
		TenantID:   inv.TenantID,
		ActorID:    actorID,
		ActorKind:  actorKind,
		Action:     action,
		Resource:   "invoice",
		ResourceID: &id,
		Before:     before,
		After:      after,
		RequestID:  reqid.From(ctx),
	})
}

// writeEvent appends to the invoice's own event log, inside the same transaction.
//
// Two logs exist for two different questions. invoice_events replays this invoice's lifecycle
// — it is the invoice's story, readable by anyone who can read the invoice. audit_log answers
// "who did what" across a tenant. Recording the lifecycle in both is deliberate duplication:
// collapsing them would either make the lifecycle unreadable without audit permission, or make
// the audit trail reconstructable only by joining a table whose access is narrower.
func writeEvent(ctx context.Context, tx pgx.Tx, auth tenant.Authorized, inv Invoice, kind string, from, to *string) error {
	actorID, actorKind, err := audit.ActorFromAuthorized(auth)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO invoice_events
			(id, invoice_id, tenant_id, kind, from_status, to_status, actor_id, actor_kind)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.Must(uuid.NewV7()), inv.ID, inv.TenantID, kind, from, to, actorID, actorKind)
	if err != nil {
		return fmt.Errorf("invoice: record %s event: %w", kind, err)
	}
	return nil
}

// allocateNumber reserves the next number for a tenant, inside the caller's transaction.
//
// # Why a counter row and not max(number) + 1
//
// The obvious implementation reads the maximum and adds one, and it is wrong under
// concurrency: two creates read the same maximum and both insert it, so the loser gets a
// uniqueness violation on a request that should have succeeded. The counter row is
// incremented by a single statement that takes a row lock, so allocation serialises and the
// second caller waits rather than colliding.
//
// The INSERT ... ON CONFLICT form is one statement, so the very first invoice for a tenant
// needs no separate initialisation step — a read-then-branch would reintroduce exactly the
// race this avoids, in the one case that only ever happens once and therefore never gets
// tested in production.
//
// The number is consumed even if the transaction later rolls back, leaving gaps. That is
// deliberate: invoice numbers are referenced by documents that may already have been sent, so
// reusing one is worse than a gap. Tax authorities require unique and monotonic per issuer,
// not contiguous.
func allocateNumber(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (string, error) {
	var n int64
	err := tx.QueryRow(ctx, `
		INSERT INTO invoice_counters (tenant_id, next_number)
		VALUES ($1, 2)
		ON CONFLICT (tenant_id)
		DO UPDATE SET next_number = invoice_counters.next_number + 1
		RETURNING next_number - 1`, tenantID).Scan(&n)
	if err != nil {
		return "", fmt.Errorf("allocate invoice number: %w", err)
	}
	return fmt.Sprintf("INV-%06d", n), nil
}

// Create issues a new invoice in draft.
//
// # Everything is one transaction
//
// The number allocation, the invoice row, its items, its creation event, and its audit entry
// all commit together. A failure anywhere leaves nothing behind — which matters most for the
// number: a rolled-back create that had already consumed one would burn a number for an
// invoice that does not exist, and a client retrying would see the gap as a missing invoice.
//
// # The totals are computed here and verified there
//
// Subtotals and totals are summed in Go with overflow checks, and the database independently
// asserts line_total = unit_price * quantity and total = subtotal + tax. The Go check exists so
// a bad amount is a 400 naming the field; the constraint exists so a wrong amount cannot be
// stored even if this function is bypassed.
func (s *Store) Create(ctx context.Context, auth tenant.Authorized, in CreateInput) (Invoice, error) {
	if !auth.Valid() {
		return Invoice{}, apperr.ErrNoScope
	}
	validated, err := ValidateCreate(in)
	if err != nil {
		return Invoice{}, err
	}

	// Line totals and the subtotal, all checked. SumTotals is the one that matters: the
	// per-line limits permit 500 lines of 1e18 each, which is 5e20 and far past int64, so
	// checking each multiplication is not sufficient.
	lineTotals := make([]int64, 0, len(validated.Items))
	for _, it := range validated.Items {
		lt, err := LineTotal(it.Quantity, it.UnitPriceMinor)
		if err != nil {
			return Invoice{}, apperr.Invalid("unit_price_minor", err.Error())
		}
		lineTotals = append(lineTotals, lt)
	}
	subtotal, err := SumTotals(lineTotals)
	if err != nil {
		return Invoice{}, apperr.Invalid("items", err.Error())
	}
	total, err := InvoiceTotal(subtotal, validated.TaxMinor)
	if err != nil {
		return Invoice{}, apperr.Invalid("tax_minor", err.Error())
	}

	inv := Invoice{
		ID:            uuid.Must(uuid.NewV7()),
		TenantID:      auth.Scope().ID(),
		Status:        StatusDraft,
		Currency:      validated.Currency,
		SubtotalMinor: subtotal,
		TaxMinor:      validated.TaxMinor,
		TotalMinor:    total,
		Version:       1,
	}
	if auth.IsMachine() {
		keyID := auth.KeyID()
		inv.CreatedByKey = &keyID
	} else {
		userID := auth.UserID()
		inv.CreatedBy = &userID
	}

	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		number, err := allocateNumber(ctx, tx, inv.TenantID)
		if err != nil {
			return err
		}
		inv.Number = number

		if _, err := tx.Exec(ctx, `
			INSERT INTO invoices
				(id, tenant_id, number, status, currency,
				 subtotal_minor, tax_minor, total_minor, version,
				 created_by, created_by_key)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			inv.ID, inv.TenantID, inv.Number, inv.Status, inv.Currency,
			inv.SubtotalMinor, inv.TaxMinor, inv.TotalMinor, inv.Version,
			inv.CreatedBy, inv.CreatedByKey); err != nil {
			return fmt.Errorf("create invoice: %w", err)
		}

		for i, it := range validated.Items {
			item := Item{
				ID:             uuid.Must(uuid.NewV7()),
				InvoiceID:      inv.ID,
				TenantID:       inv.TenantID,
				Position:       i,
				Description:    it.Description,
				Quantity:       it.Quantity,
				UnitPriceMinor: it.UnitPriceMinor,
				LineTotalMinor: lineTotals[i],
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO invoice_items
					(id, invoice_id, tenant_id, position, description,
					 quantity, unit_price_minor, line_total_minor)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				item.ID, item.InvoiceID, item.TenantID, item.Position, item.Description,
				item.Quantity, item.UnitPriceMinor, item.LineTotalMinor); err != nil {
				return fmt.Errorf("create invoice item %d: %w", i, err)
			}
			inv.Items = append(inv.Items, item)
		}

		// from_status is NULL: an invoice that has just come into existence has no previous
		// state, and recording one would put a false value in an append-only log whose purpose
		// is to be replayable. Migration 0009 exists because 0008 required the opposite.
		draft := StatusDraft
		if err := writeEvent(ctx, tx, auth, inv, "created", nil, &draft); err != nil {
			return err
		}
		// Enqueued inside this transaction, so the invoice and its notification commit together.
		if err := s.emit(ctx, tx, auth, webhook.EventInvoiceCreated, inv); err != nil {
			return err
		}
		return auditInvoice(ctx, tx, auth, audit.ActionInvoiceCreate, inv, nil, auditImage(inv))
	})
	if err != nil {
		// A unique violation here can only be (tenant_id, number), which means the counter and
		// the invoices disagree — a bug in allocation rather than a client problem, so it is
		// not reported as a conflict the client could resolve by retrying with different input.
		if db.IsUniqueViolation(err) {
			return Invoice{}, fmt.Errorf("invoice number allocation collided: %w", err)
		}
		return Invoice{}, err
	}
	return inv, nil
}

// Get returns one invoice with its items.
func (s *Store) Get(ctx context.Context, auth tenant.Authorized, id uuid.UUID) (Invoice, error) {
	if !auth.Valid() {
		return Invoice{}, apperr.ErrNoScope
	}
	if err := ValidateUUID(id); err != nil {
		return Invoice{}, err
	}

	var inv Invoice
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var scanErr error
		inv, scanErr = scanInvoice(tx.QueryRow(ctx,
			`SELECT `+invoiceColumns+` FROM invoices WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		if scanErr != nil {
			return scanErr
		}
		inv.Items, scanErr = loadItems(ctx, tx, inv.ID, inv.TenantID)
		return scanErr
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Invoice{}, apperr.ErrNotFound
	case err != nil:
		return Invoice{}, fmt.Errorf("get invoice: %w", err)
	}
	return inv, nil
}

// loadItems reads an invoice's lines in position order.
func loadItems(ctx context.Context, tx pgx.Tx, invoiceID, tenantID uuid.UUID) ([]Item, error) {
	rows, err := tx.Query(ctx,
		`SELECT `+itemColumns+` FROM invoice_items
		  WHERE invoice_id = $1 AND tenant_id = $2 ORDER BY position`, invoiceID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Item, 0, 4)
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

// List returns one page of invoices, newest first.
//
// Keyset paginated on (created_at, id) for the same reason as projects: an offset page shifts
// under concurrent inserts, so page 2 can repeat or skip rows the client already saw.
//
// Items are deliberately not loaded — a listing of 100 invoices with their lines is a much
// larger response for data the caller usually does not need. Items is non-nil and empty, so a
// caller cannot mistake "not loaded" for "no lines".
func (s *Store) List(ctx context.Context, auth tenant.Authorized, filter ListFilter, after *cursor.Position, limit int) (ListResult, error) {
	if !auth.Valid() {
		return ListResult{}, apperr.ErrNoScope
	}
	status, err := NormalizeStatus(filter.Status)
	if err != nil {
		return ListResult{}, err
	}
	limit = NormalizePageSize(limit)

	var out []Invoice
	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		var afterTime *time.Time
		var afterID uuid.UUID
		if after != nil {
			t := after.Time
			afterTime = &t
			afterID = after.ID
		}

		rows, err := tx.Query(ctx, `
			SELECT `+invoiceColumns+`
			FROM invoices
			WHERE tenant_id = $1
			  AND ($2::text IS NULL OR status = $2::text)
			  AND ($3::timestamptz IS NULL OR (created_at, id) < ($3::timestamptz, $4::uuid))
			ORDER BY created_at DESC, id DESC
			LIMIT $5`,
			auth.Scope().ID(), nullIfEmpty(status), afterTime, afterID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			inv, err := scanInvoice(rows)
			if err != nil {
				return err
			}
			inv.Items = make([]Item, 0)
			out = append(out, inv)
		}
		return rows.Err()
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list invoices: %w", err)
	}

	res := ListResult{Invoices: out}
	if len(out) > limit {
		res.Invoices = out[:limit]
		last := out[limit-1]
		res.Next = &cursor.Position{Time: last.CreatedAt, ID: last.ID}
	}
	return res, nil
}

// nullIfEmpty maps "" to a SQL NULL so the status filter can be absent.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// AddItem appends a line to a draft invoice and recomputes its totals.
//
// Draft-only, and the database enforces it too: a trigger rejects any item write on an invoice
// that is not a draft. The application checks first so the client gets a readable 409 rather
// than a raw constraint violation, and a test asserts both layers agree.
func (s *Store) AddItem(ctx context.Context, auth tenant.Authorized, id uuid.UUID, in AddItemInput) (Invoice, error) {
	if !auth.Valid() {
		return Invoice{}, apperr.ErrNoScope
	}
	if err := ValidateUUID(id); err != nil {
		return Invoice{}, err
	}
	validated, err := ValidateItem(ItemInput(in))
	if err != nil {
		return Invoice{}, err
	}
	lineTotal, err := LineTotal(validated.Quantity, validated.UnitPriceMinor)
	if err != nil {
		return Invoice{}, apperr.Invalid("unit_price_minor", err.Error())
	}

	var inv Invoice
	err = db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		before, err := scanInvoice(tx.QueryRow(ctx,
			`SELECT `+invoiceColumns+` FROM invoices WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return apperr.ErrNotFound
		case err != nil:
			return fmt.Errorf("read invoice before adding an item: %w", err)
		}
		if before.Status != StatusDraft {
			return fmt.Errorf("invoice %s is %s, so its lines cannot be changed; only a draft may be edited: %w",
				before.Number, before.Status, apperr.ErrConflict)
		}

		// The next position is the current maximum plus one, read inside this transaction. A
		// unique constraint on (invoice_id, position) means a concurrent append cannot
		// silently interleave — the loser gets a conflict rather than two lines claiming the
		// same slot.
		var nextPos int
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(max(position) + 1, 0) FROM invoice_items WHERE invoice_id = $1`,
			id).Scan(&nextPos); err != nil {
			return fmt.Errorf("find the next item position: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO invoice_items
				(id, invoice_id, tenant_id, position, description,
				 quantity, unit_price_minor, line_total_minor)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.Must(uuid.NewV7()), id, before.TenantID, nextPos, validated.Description,
			validated.Quantity, validated.UnitPriceMinor, lineTotal); err != nil {
			return fmt.Errorf("add invoice item: %w", err)
		}

		inv, err = s.recomputeTotals(ctx, tx, before, auth,
			audit.ActionInvoiceItemAdded, "item_added")
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Invoice{}, err
	}
	return inv, nil
}

// RemoveItem deletes a line from a draft invoice and recomputes its totals.
func (s *Store) RemoveItem(ctx context.Context, auth tenant.Authorized, invoiceID, itemID uuid.UUID) (Invoice, error) {
	if !auth.Valid() {
		return Invoice{}, apperr.ErrNoScope
	}
	if err := ValidateUUID(invoiceID); err != nil {
		return Invoice{}, err
	}
	if err := ValidateUUID(itemID); err != nil {
		return Invoice{}, err
	}

	var inv Invoice
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		before, err := scanInvoice(tx.QueryRow(ctx,
			`SELECT `+invoiceColumns+` FROM invoices WHERE id = $1 AND tenant_id = $2`,
			invoiceID, auth.Scope().ID()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return apperr.ErrNotFound
		case err != nil:
			return fmt.Errorf("read invoice before removing an item: %w", err)
		}
		if before.Status != StatusDraft {
			return fmt.Errorf("invoice %s is %s, so its lines cannot be changed; only a draft may be edited: %w",
				before.Number, before.Status, apperr.ErrConflict)
		}

		tag, err := tx.Exec(ctx,
			`DELETE FROM invoice_items WHERE id = $1 AND invoice_id = $2 AND tenant_id = $3`,
			itemID, invoiceID, before.TenantID)
		if err != nil {
			return fmt.Errorf("remove invoice item: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return apperr.ErrNotFound
		}

		inv, err = s.recomputeTotals(ctx, tx, before, auth,
			audit.ActionInvoiceItemRemoved, "item_removed")
		return err
	})
	if err != nil {
		return Invoice{}, err
	}
	return inv, nil
}

// recomputeTotals rebuilds an invoice's subtotal and total from its lines, records the change,
// and returns the updated row.
//
// # Why the subtotal is recomputed rather than adjusted
//
// Incrementing the subtotal by the added line and decrementing on removal would work, and it
// accumulates any error forever — one bad arithmetic path and every subsequent total is wrong
// by that amount, with no way to notice. Rebuilding from the lines means the subtotal is a
// function of the rows that exist, so it is self-correcting and a mismatch is impossible rather
// than unlikely.
//
// The invoice's financial fields are frozen by a trigger once it leaves draft, so this runs
// only on drafts and the recomputation cannot rewrite a number a customer has already seen.
//
// action and eventKind come from the caller because only the caller knows which operation it
// performed; deriving them from the resulting numbers is wrong in a way that is easy to miss
// (see the note at the call site).
func (s *Store) recomputeTotals(ctx context.Context, tx pgx.Tx, before Invoice, auth tenant.Authorized, action, eventKind string) (Invoice, error) {
	var subtotal int64
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(sum(line_total_minor), 0) FROM invoice_items WHERE invoice_id = $1`,
		before.ID).Scan(&subtotal); err != nil {
		return Invoice{}, fmt.Errorf("recompute subtotal: %w", err)
	}
	total, err := InvoiceTotal(subtotal, before.TaxMinor)
	if err != nil {
		return Invoice{}, apperr.Invalid("tax_minor", err.Error())
	}

	after, err := scanInvoice(tx.QueryRow(ctx, `
		UPDATE invoices
		   SET subtotal_minor = $3,
		       total_minor    = $4,
		       version        = version + 1,
		       updated_at     = now()
		 WHERE id = $1 AND tenant_id = $2 AND status = 'draft'
		RETURNING `+invoiceColumns,
		before.ID, before.TenantID, subtotal, total))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The guard is `AND status = 'draft'`, so zero rows means the invoice left draft
		// between the read above and this write. Reported as the same conflict the caller
		// would have received a moment earlier.
		return Invoice{}, fmt.Errorf("invoice %s was issued while its lines were being edited: %w",
			before.Number, apperr.ErrConflict)
	case err != nil:
		return Invoice{}, fmt.Errorf("recompute totals: %w", err)
	}

	after.Items, err = loadItems(ctx, tx, after.ID, after.TenantID)
	if err != nil {
		return Invoice{}, err
	}
	// The action is passed in rather than inferred from the totals.
	//
	// Inferring it from `subtotal < before.SubtotalMinor` looks equivalent and is not: removing
	// a zero-priced line leaves the subtotal identical, so the change would be recorded as an
	// addition in an append-only log whose entire purpose is to be accurate. The caller knows
	// which operation it performed, so it says so.
	if err := writeEvent(ctx, tx, auth, after, eventKind, nil, nil); err != nil {
		return Invoice{}, err
	}
	if err := auditInvoice(ctx, tx, auth, action, after, auditImage(before), auditImage(after)); err != nil {
		return Invoice{}, err
	}
	return after, nil
}

// Transition moves an invoice through its lifecycle.
//
// # Two enforcement points, and a test that they agree
//
// The legal transitions are declared in CanTransition and enforced by a database trigger. The
// application check exists so the client gets a 409 naming the current and requested states; the
// trigger exists because a future endpoint, a migration, or a debugging session will not consult
// this function. A test drives an illegal transition through raw SQL and asserts the trigger
// refuses it, so the two cannot drift apart unnoticed.
//
// # Why the version is asserted
//
// Settling an invoice twice is the failure that costs money. The UPDATE carries
// `version = expected`, so of two concurrent pay requests exactly one matches and the other
// sees zero rows — the same compare-and-set that protects project updates, applied to the
// operation that most needs it.
func (s *Store) Transition(ctx context.Context, auth tenant.Authorized, id uuid.UUID, t Transition, expectedVersion int) (Invoice, error) {
	if !auth.Valid() {
		return Invoice{}, apperr.ErrNoScope
	}
	if err := ValidateUUID(id); err != nil {
		return Invoice{}, err
	}
	to := TransitionTo(t)
	if to == "" {
		return Invoice{}, apperr.Invalid("transition", "must be one of issue, pay, void")
	}
	if expectedVersion <= 0 {
		return Invoice{}, apperr.Invalid("expected_version", "must be a positive integer")
	}

	var inv Invoice
	err := db.WithIdentityTx(ctx, s.pool, auth.Identity(), func(tx pgx.Tx) error {
		before, err := scanInvoice(tx.QueryRow(ctx,
			`SELECT `+invoiceColumns+` FROM invoices WHERE id = $1 AND tenant_id = $2`,
			id, auth.Scope().ID()))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return apperr.ErrNotFound
		case err != nil:
			return fmt.Errorf("read invoice before %s: %w", t, err)
		}

		// Read first for the message, CAS second for the guarantee. The order matters: the
		// CAS alone would report "version conflict" for an illegal transition, which tells the
		// client to retry something that can never succeed.
		if !CanTransition(before.Status, to) {
			return fmt.Errorf("invoice %s is %s and cannot be %s: %w",
				before.Number, before.Status, to, apperr.ErrConflict)
		}

		var (
			updated Invoice
			scanErr error
		)
		updated, scanErr = scanInvoice(tx.QueryRow(ctx, `
			UPDATE invoices
			   SET status     = $3,
			       version    = version + 1,
			       updated_at = now(),
			       issued_at  = CASE WHEN $3 = 'open' THEN now() ELSE issued_at END,
			       paid_at    = CASE WHEN $3 = 'paid' THEN now() ELSE paid_at END,
			       voided_at  = CASE WHEN $3 = 'void' THEN now() ELSE voided_at END
			 WHERE id = $1
			   AND tenant_id = $2
			   AND version = $4
			   AND status  = $5
			RETURNING `+invoiceColumns,
			id, before.TenantID, to, expectedVersion, before.Status))
		switch {
		case errors.Is(scanErr, pgx.ErrNoRows):
			// The row is still there and the transition is legal, so zero rows means the
			// version moved: somebody changed this invoice between the read and the write.
			var current int
			if qErr := tx.QueryRow(ctx,
				`SELECT version FROM invoices WHERE id = $1 AND tenant_id = $2`,
				id, before.TenantID).Scan(&current); qErr != nil {
				return fmt.Errorf("classify %s failure: %w", t, qErr)
			}
			return fmt.Errorf(
				"this invoice changed while you were acting on it (expected version %d, current version %d); re-read it and retry: %w",
				expectedVersion, current, apperr.ErrVersionConflict)
		case scanErr != nil:
			return fmt.Errorf("%s invoice: %w", t, scanErr)
		}

		updated.Items, scanErr = loadItems(ctx, tx, updated.ID, updated.TenantID)
		if scanErr != nil {
			return scanErr
		}

		from := before.Status
		if err := writeEvent(ctx, tx, auth, updated, string(t), &from, &to); err != nil {
			return err
		}
		// The event and the transition commit together. A payment announced but rolled back is a
		// receiver shipping goods for an invoice that was never settled.
		event := eventForTransition(t)
		if event == "" {
			return fmt.Errorf("invoice: transition %q has no event mapped, so this change would "+
				"notify nobody", t)
		}
		if err := s.emit(ctx, tx, auth, event, updated); err != nil {
			return err
		}
		if err := auditInvoice(ctx, tx, auth, auditActionFor(t), updated, auditImage(before), auditImage(updated)); err != nil {
			return err
		}

		// Assigned only after everything above has succeeded. `inv` is what the caller
		// receives, and assigning it before the event and audit writes would return a
		// transition as complete that a later failure rolls back — the response would
		// describe a change that did not persist.
		inv = updated
		return nil
	})
	if err != nil {
		return Invoice{}, err
	}
	return inv, nil
}

// auditActionFor maps a transition onto its audit verb.
func auditActionFor(t Transition) string {
	switch t {
	case TransitionIssue:
		return audit.ActionInvoiceIssued
	case TransitionPay:
		return audit.ActionInvoicePaid
	case TransitionVoid:
		return audit.ActionInvoiceVoided
	default:
		return "invoice.unknown"
	}
}

// Binding describes the query a pagination cursor belongs to.
func Binding(auth tenant.Authorized, filter ListFilter) cursor.Binding {
	status, _ := NormalizeStatus(filter.Status)
	if status == "" {
		status = "any"
	}
	return cursor.Binding{
		TenantID: auth.Scope().ID(),
		Resource: "invoices",
		Filter:   status,
	}
}
