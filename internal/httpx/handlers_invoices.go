package httpx

import (
	"errors"
	"net/http"

	"github.com/aditya0si/tenant-api-platform/internal/invoice"
	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
)

// invoiceItemResponse is one line on the wire.
//
// Money is sent as an integer in minor units, never as a formatted string or a decimal.
// A client that wants "$12.34" formats it; a client that needs to do arithmetic on it
// cannot use the formatted form, and a float here would reintroduce the rounding the
// whole schema avoids (ADR-008).
type invoiceItemResponse struct {
	ID             string `json:"id"`
	Position       int    `json:"position"`
	Description    string `json:"description"`
	Quantity       int    `json:"quantity"`
	UnitPriceMinor int64  `json:"unit_price_minor"`
	LineTotalMinor int64  `json:"line_total_minor"`
}

// invoiceResponse is one invoice on the wire.
type invoiceResponse struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Number   string `json:"number"`
	Status   string `json:"status"`
	Currency string `json:"currency"`

	SubtotalMinor int64 `json:"subtotal_minor"`
	TaxMinor      int64 `json:"tax_minor"`
	TotalMinor    int64 `json:"total_minor"`

	Version int `json:"version"`

	CreatedBy    string `json:"created_by,omitempty"`
	CreatedByKey string `json:"created_by_key,omitempty"`

	IssuedAt *string `json:"issued_at,omitempty"`
	PaidAt   *string `json:"paid_at,omitempty"`
	VoidedAt *string `json:"voided_at,omitempty"`

	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// Items is omitted entirely for a listing, where lines are deliberately not loaded.
	// It is a pointer so that "not loaded" and "no lines" are different on the wire: a
	// client rendering an invoice needs to know whether an empty list means the invoice
	// has no lines or that it should fetch them.
	Items *[]invoiceItemResponse `json:"items,omitempty"`
}

// invoiceResponseFrom renders an invoice.
//
// includeItems controls whether lines are serialised. A listing passes false and the field
// is absent; a single-invoice read passes true and an empty invoice yields an empty array
// rather than a missing field.
func invoiceResponseFrom(inv invoice.Invoice, includeItems bool) invoiceResponse {
	out := invoiceResponse{
		ID:            inv.ID.String(),
		TenantID:      inv.TenantID.String(),
		Number:        inv.Number,
		Status:        inv.Status,
		Currency:      inv.Currency,
		SubtotalMinor: inv.SubtotalMinor,
		TaxMinor:      inv.TaxMinor,
		TotalMinor:    inv.TotalMinor,
		Version:       inv.Version,
		IssuedAt:      timestampPtr(inv.IssuedAt),
		PaidAt:        timestampPtr(inv.PaidAt),
		VoidedAt:      timestampPtr(inv.VoidedAt),
		CreatedAt:     timestamp(inv.CreatedAt),
		UpdatedAt:     timestamp(inv.UpdatedAt),
	}
	if inv.CreatedBy != nil {
		out.CreatedBy = inv.CreatedBy.String()
	}
	if inv.CreatedByKey != nil {
		out.CreatedByKey = inv.CreatedByKey.String()
	}
	if includeItems {
		items := make([]invoiceItemResponse, 0, len(inv.Items))
		for _, it := range inv.Items {
			items = append(items, invoiceItemResponse{
				ID:             it.ID.String(),
				Position:       it.Position,
				Description:    it.Description,
				Quantity:       it.Quantity,
				UnitPriceMinor: it.UnitPriceMinor,
				LineTotalMinor: it.LineTotalMinor,
			})
		}
		out.Items = &items
	}
	return out
}

// handleCreateInvoice issues a new draft invoice.
//
// It is one of the guarded writes, so it inherits authorization-then-idempotency from
// writeGuard. That ordering matters more here than on projects: a retried create consumes an
// invoice number, and a number that has been sent to a customer cannot be reused, so a
// duplicate is not merely untidy — it is a gap in a sequence an accountant will ask about.
func (d Deps) handleCreateInvoice(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	var req struct {
		Currency string `json:"currency"`
		TaxMinor int64  `json:"tax_minor"`
		Items    []struct {
			Description    string `json:"description"`
			Quantity       int    `json:"quantity"`
			UnitPriceMinor int64  `json:"unit_price_minor"`
		} `json:"items"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	in := invoice.CreateInput{
		Currency: req.Currency,
		TaxMinor: req.TaxMinor,
		Items:    make([]invoice.ItemInput, 0, len(req.Items)),
	}
	for _, it := range req.Items {
		in.Items = append(in.Items, invoice.ItemInput{
			Description:    it.Description,
			Quantity:       it.Quantity,
			UnitPriceMinor: it.UnitPriceMinor,
		})
	}

	created, err := d.Invoices.Create(r.Context(), auth, in)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.Created(w, invoiceResponseFrom(created, true))
}

// handleGetInvoice returns one invoice with its lines.
func (d Deps) handleGetInvoice(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "invoiceID"))
	if err != nil {
		// A malformed id cannot name a real invoice, so it is reported as not-found rather
		// than as a bad request — the same uniform surface as every other id in this API,
		// so nothing about id format is learnable from a status code.
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	inv, err := d.Invoices.Get(r.Context(), auth, id)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, invoiceResponseFrom(inv, true))
}

// handleListInvoices returns one page of invoices, newest first.
func (d Deps) handleListInvoices(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	limit, rawCursor, err := pageParams(r)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	filter := invoice.ListFilter{Status: r.URL.Query().Get("status")}
	if _, err := invoice.NormalizeStatus(filter.Status); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	binding := invoice.Binding(auth, filter)

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

	page, err := d.Invoices.List(r.Context(), auth, filter, after, limit)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]invoiceResponse, 0, len(page.Invoices))
	for _, inv := range page.Invoices {
		// Lines are not loaded for a listing, so they are not serialised and the field is
		// absent — which the client can distinguish from an empty invoice.
		items = append(items, invoiceResponseFrom(inv, false))
	}

	var nextToken string
	if page.Next != nil {
		token, encErr := d.Cursors.Encode(binding, *page.Next)
		if encErr != nil {
			d.Log.Error("failed to encode a pagination cursor", "err", encErr)
		} else {
			nextToken = token
		}
	}

	httperr.Page(w, items, nextToken)
}

// handleAddInvoiceItem appends a line to a draft.
func (d Deps) handleAddInvoiceItem(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	invoiceID, err := parseUUID(chiURLParam(r, "invoiceID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	var req struct {
		Description    string `json:"description"`
		Quantity       int    `json:"quantity"`
		UnitPriceMinor int64  `json:"unit_price_minor"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	updated, err := d.Invoices.AddItem(r.Context(), auth, invoiceID, invoice.AddItemInput{
		Description:    req.Description,
		Quantity:       req.Quantity,
		UnitPriceMinor: req.UnitPriceMinor,
	})
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	// The full invoice is returned, not just the new line, because adding a line changes the
	// subtotal and total — and a client that received only the item would have to guess the
	// new totals or re-read, which is exactly the re-read the response can save it.
	httperr.OK(w, invoiceResponseFrom(updated, true))
}

// handleRemoveInvoiceItem deletes a line from a draft.
func (d Deps) handleRemoveInvoiceItem(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	invoiceID, err := parseUUID(chiURLParam(r, "invoiceID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}
	itemID, err := parseUUID(chiURLParam(r, "itemID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	updated, err := d.Invoices.RemoveItem(r.Context(), auth, invoiceID, itemID)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, invoiceResponseFrom(updated, true))
}

// transitionRequest is the body for a lifecycle transition.
//
// expected_version is required and has no default, for the same reason it is required on a
// project update: an unguarded transition is a last-write-wins write, and for an invoice
// that means settling something that already changed — the failure that costs money.
type transitionRequest struct {
	ExpectedVersion int `json:"expected_version"`
}

// handleIssueInvoice moves a draft to open.
func (d Deps) handleIssueInvoice(w http.ResponseWriter, r *http.Request) {
	d.handleTransition(w, r, invoice.TransitionIssue)
}

// handlePayInvoice settles an open invoice.
//
// It requires invoice:settle rather than invoice:write — see the route registration. Marking
// an invoice paid is a stronger act than editing one, and the roles are split accordingly.
func (d Deps) handlePayInvoice(w http.ResponseWriter, r *http.Request) {
	d.handleTransition(w, r, invoice.TransitionPay)
}

// handleVoidInvoice cancels a draft or an open invoice.
func (d Deps) handleVoidInvoice(w http.ResponseWriter, r *http.Request) {
	d.handleTransition(w, r, invoice.TransitionVoid)
}

// handleTransition is the shared body of the three lifecycle endpoints.
func (d Deps) handleTransition(w http.ResponseWriter, r *http.Request, t invoice.Transition) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "invoiceID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	var req transitionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	updated, err := d.Invoices.Transition(r.Context(), auth, id, t, req.ExpectedVersion)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, invoiceResponseFrom(updated, true))
}
