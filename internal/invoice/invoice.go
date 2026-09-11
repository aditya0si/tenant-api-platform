// Package invoice owns invoices: their line items, their lifecycle, and their money.
//
// # Money is an integer and the arithmetic is checked
//
// Every amount is an int64 in the currency's smallest unit — cents, paise, yen. There is no
// float anywhere in this package. A float cannot represent 0.10 exactly, so summing line items
// drifts, and a total that is off by a hundredth is a total that does not reconcile; for a
// billing system that is the one bug that matters (ADR-008).
//
// Checked, not trusted. A line total is a multiplication and an invoice total is a sum, and
// both can overflow int64 — an overflowed total is not a rounding error, it is a negative
// number, and a negative invoice total is discovered by a customer rather than by a test. The
// limits below are chosen so a single line cannot overflow, and every accumulation is checked
// anyway because "cannot happen given the limits" is a claim that survives right up until
// somebody raises a limit.
//
// The database enforces the same arithmetic (line_total = unit_price * quantity, and
// total_minor = subtotal_minor + tax_minor), so a wrong number cannot be stored even if this
// package is bypassed. The checks here exist so the failure is a clear 400 naming the field
// rather than a constraint violation.
//
// # One currency per invoice, and it is structural
//
// Line items carry no currency field. They are in their invoice's currency by construction,
// because there is nowhere to put a different one — an invoice cannot be half in dollars and
// half in euros, and that is a property of the schema rather than a rule this package
// remembers to enforce.
//
// # The lifecycle
//
//	draft ──issue──> open ──pay──> paid
//	  │               │
//	  └────void───────┴────> void
//
// paid and void are terminal. The database trigger is the authority on what is legal; this
// package mirrors it so a client gets a 409 with a readable message instead of a raw
// constraint violation, and a test asserts the two agree rather than assuming it.
package invoice

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
)

// Statuses.
const (
	StatusDraft = "draft"
	StatusOpen  = "open"
	StatusPaid  = "paid"
	StatusVoid  = "void"
)

// Limits. Each exists to keep an amount inside int64, and each is enforced with a message
// naming the field rather than discovered as an overflow.
const (
	// MaxQuantity bounds one line's quantity. A million units of one item on a single
	// invoice line is already far past anything real.
	MaxQuantity = 1_000_000

	// MaxUnitPriceMinor bounds one line's unit price: 1e12 minor units, which is ten billion
	// dollars in cents. Chosen with MaxQuantity so that
	// MaxQuantity * MaxUnitPriceMinor = 1e18 stays comfortably under math.MaxInt64 (≈9.2e18).
	MaxUnitPriceMinor = 1_000_000_000_000

	// MaxItemsPerInvoice bounds how many lines one invoice may have.
	MaxItemsPerInvoice = 500

	// MaxTaxMinor bounds the tax component, which is supplied by the caller rather than
	// computed here (this service is not a tax engine, and pretending to be one is how
	// invoices end up subtly wrong).
	MaxTaxMinor = 1_000_000_000_000_000

	MaxDescriptionLen = 500
	MaxCurrencyLen    = 3

	// DefaultPageSize and MaxPageSize bound a listing.
	DefaultPageSize = 25
	MaxPageSize     = 100
)

// supportedCurrencies is the set this service will issue in.
//
// The database constrains only the shape ([A-Z]{3}), because a list in a CHECK constraint is a
// migration every time a market is added. The list lives here so it is a code change with a
// test, and it is deliberately short: a currency this service cannot compute with correctly is
// one it should refuse rather than accept and mishandle.
var supportedCurrencies = map[string]bool{
	"AUD": true, "CAD": true, "CHF": true, "EUR": true, "GBP": true,
	"INR": true, "JPY": true, "SGD": true, "USD": true,
}

// SupportedCurrency reports whether this service issues in cur.
func SupportedCurrency(cur string) bool { return supportedCurrencies[cur] }

// Item is one line on an invoice.
type Item struct {
	ID             uuid.UUID
	InvoiceID      uuid.UUID
	TenantID       uuid.UUID
	Position       int
	Description    string
	Quantity       int
	UnitPriceMinor int64
	LineTotalMinor int64
	CreatedAt      time.Time
}

// Invoice is one invoice, with its lines when they were loaded.
//
// Items is empty rather than nil for a listing row, which is deliberate: a listing does not
// fetch lines, and a caller that forgot that would otherwise read a nil slice as "this invoice
// has no lines" instead of "they were not loaded".
type Invoice struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	Number   string
	Status   string
	Currency string

	SubtotalMinor int64
	TaxMinor      int64
	TotalMinor    int64

	Version int

	CreatedBy    *uuid.UUID
	CreatedByKey *uuid.UUID

	IssuedAt *time.Time
	PaidAt   *time.Time
	VoidedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time

	Items []Item
}

// Terminal reports whether the invoice can no longer change.
func (i Invoice) Terminal() bool { return i.Status == StatusPaid || i.Status == StatusVoid }

// CreateInput is a new invoice.
type CreateInput struct {
	Currency string
	TaxMinor int64
	Items    []ItemInput
}

// ItemInput is one line supplied by a client.
type ItemInput struct {
	Description    string
	Quantity       int
	UnitPriceMinor int64
}

// AddItemInput is one line added to an existing draft.
type AddItemInput struct {
	Description    string
	Quantity       int
	UnitPriceMinor int64
}

// ListFilter narrows a listing.
type ListFilter struct {
	// Status is empty for "any status".
	Status string
}

// ListResult is one page.
//
// Next is a real position rather than `any`: the project store does the same thing with the
// same types and there is no cycle to avoid — cursor imports nothing from here. Typing it as
// `any` would push a type assertion onto every caller for no benefit, and the assertion is
// exactly where a pagination bug would hide.
type ListResult struct {
	Invoices []Invoice
	Next     *cursor.Position
}

// Transition is a requested state change.
type Transition string

const (
	TransitionIssue Transition = "issued"
	TransitionPay   Transition = "paid"
	TransitionVoid  Transition = "voided"
)

// ValidateCreate checks a create request and normalises it.
func ValidateCreate(in CreateInput) (CreateInput, error) {
	cur := strings.ToUpper(strings.TrimSpace(in.Currency))
	if len(cur) != MaxCurrencyLen {
		return CreateInput{}, apperr.Invalid("currency",
			fmt.Sprintf("must be a %d-letter ISO 4217 code", MaxCurrencyLen))
	}
	if !supportedCurrencies[cur] {
		return CreateInput{}, apperr.Invalid("currency",
			fmt.Sprintf("this service does not issue invoices in %q", cur))
	}
	in.Currency = cur

	if in.TaxMinor < 0 {
		return CreateInput{}, apperr.Invalid("tax_minor", "must not be negative")
	}
	if in.TaxMinor > MaxTaxMinor {
		return CreateInput{}, apperr.Invalid("tax_minor", "is implausibly large")
	}
	if len(in.Items) > MaxItemsPerInvoice {
		return CreateInput{}, apperr.Invalid("items",
			fmt.Sprintf("an invoice may have at most %d lines", MaxItemsPerInvoice))
	}
	for i, it := range in.Items {
		norm, err := ValidateItem(it)
		if err != nil {
			return CreateInput{}, fmt.Errorf("item %d: %w", i, err)
		}
		in.Items[i] = norm
	}
	return in, nil
}

// ValidateItem checks one line and normalises it.
func ValidateItem(in ItemInput) (ItemInput, error) {
	desc := strings.TrimSpace(in.Description)
	if desc == "" {
		return ItemInput{}, apperr.Invalid("description", "must not be empty")
	}
	if len(desc) > MaxDescriptionLen {
		return ItemInput{}, apperr.Invalid("description",
			fmt.Sprintf("must be at most %d characters", MaxDescriptionLen))
	}
	in.Description = desc

	if in.Quantity <= 0 {
		return ItemInput{}, apperr.Invalid("quantity", "must be a positive integer")
	}
	if in.Quantity > MaxQuantity {
		return ItemInput{}, apperr.Invalid("quantity",
			fmt.Sprintf("must be at most %d", MaxQuantity))
	}
	if in.UnitPriceMinor < 0 {
		return ItemInput{}, apperr.Invalid("unit_price_minor", "must not be negative")
	}
	if in.UnitPriceMinor > MaxUnitPriceMinor {
		return ItemInput{}, apperr.Invalid("unit_price_minor", "is implausibly large")
	}

	// The multiplication is checked even though the limits above make overflow impossible
	// today. The limits are the kind of thing that gets raised by somebody who has not read
	// this comment, and a silently negative line total is not something a test would catch
	// afterwards.
	if _, err := LineTotal(in.Quantity, in.UnitPriceMinor); err != nil {
		return ItemInput{}, apperr.Invalid("unit_price_minor", err.Error())
	}
	return in, nil
}

// LineTotal computes a line's total, refusing to overflow.
func LineTotal(quantity int, unitPriceMinor int64) (int64, error) {
	if quantity <= 0 {
		return 0, errors.New("quantity must be positive")
	}
	if unitPriceMinor < 0 {
		return 0, errors.New("unit price must not be negative")
	}
	// Checked by division rather than by comparing against a precomputed bound, so the check
	// stays correct if either limit changes.
	if unitPriceMinor != 0 && int64(quantity) > math.MaxInt64/unitPriceMinor {
		return 0, errors.New("this line's total would exceed the largest supported amount")
	}
	return int64(quantity) * unitPriceMinor, nil
}

// SumTotals adds line totals, refusing to overflow.
//
// The sum is where overflow actually becomes reachable: the per-line limits permit 500 lines
// of 1e18 each, which is 5e20 and well past int64. Checking each multiplication is not
// sufficient, which is exactly the sort of thing that is assumed rather than verified.
func SumTotals(lineTotals []int64) (int64, error) {
	var sum int64
	for _, lt := range lineTotals {
		if lt < 0 {
			return 0, errors.New("a line total is negative")
		}
		if sum > math.MaxInt64-lt {
			return 0, errors.New("the invoice total would exceed the largest supported amount")
		}
		sum += lt
	}
	return sum, nil
}

// InvoiceTotal combines a subtotal and tax, refusing to overflow.
func InvoiceTotal(subtotalMinor, taxMinor int64) (int64, error) {
	if subtotalMinor < 0 || taxMinor < 0 {
		return 0, errors.New("amounts must not be negative")
	}
	if subtotalMinor > math.MaxInt64-taxMinor {
		return 0, errors.New("the invoice total would exceed the largest supported amount")
	}
	return subtotalMinor + taxMinor, nil
}

// CanTransition reports whether the lifecycle permits from -> to.
//
// This mirrors the database trigger exactly, and the mirroring is tested: a test drives an
// illegal transition through raw SQL and asserts the trigger refuses it too. Two enforcement
// points that disagree would be worse than one, because the application would refuse
// operations the database would allow and the difference would be discovered from a support
// ticket.
func CanTransition(from, to string) bool {
	switch from {
	case StatusDraft:
		return to == StatusOpen || to == StatusVoid
	case StatusOpen:
		return to == StatusPaid || to == StatusVoid
	default:
		// paid and void are terminal.
		return false
	}
}

// TransitionTo is the status a named transition produces.
func TransitionTo(t Transition) string {
	switch t {
	case TransitionIssue:
		return StatusOpen
	case TransitionPay:
		return StatusPaid
	case TransitionVoid:
		return StatusVoid
	default:
		return ""
	}
}

// NormalizePageSize clamps a requested page size into range.
//
// It returns the effective size rather than an error: a client asking for 1000 items is not
// doing anything wrong, it just cannot have them.
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

// NormalizeStatus validates a status filter, returning "" for "any".
func NormalizeStatus(raw string) (string, error) {
	switch raw {
	case "":
		return "", nil
	case StatusDraft, StatusOpen, StatusPaid, StatusVoid:
		return raw, nil
	default:
		return "", apperr.Invalid("status",
			"must be one of draft, open, paid, void")
	}
}

// ValidateUUID reports a usable id, mapping the zero id to not-found.
//
// A caller that supplies uuid.Nil is asking for a resource that cannot exist, so it is the
// same answer as one that does not exist — and mapping it here keeps every method from
// repeating the check.
func ValidateUUID(id uuid.UUID) error {
	if id == uuid.Nil {
		return apperr.ErrNotFound
	}
	return nil
}
