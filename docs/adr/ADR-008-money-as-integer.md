# ADR-008: Money is an integer in minor units, with checked arithmetic

Status: accepted

## Context

An invoice has line items, a subtotal, tax, and a total. Every one of those is money, and the
service must compute with them: multiply quantity by unit price, sum the lines, add tax.

## Decision

Every amount is an `int64` in the currency's smallest unit — cents, paise, yen. There is no
float, no `numeric`, and no string amount anywhere in the schema or the Go packages.

The database independently enforces the arithmetic:

- `invoice_items.line_total_minor = unit_price_minor * quantity` (CHECK)
- `invoices.total_minor = subtotal_minor + tax_minor` (CHECK)
- all four amounts `>= 0` (CHECK)

Go enforces the same and checks for overflow, so the failure is a 400 naming the field rather
than a 500 wrapping a constraint violation.

## Alternatives rejected

**Floating point.** Rejected outright. A float cannot represent 0.10 exactly — it stores the
nearest binary fraction — so summing line items drifts, and a total that is off by a hundredth
is a total that does not reconcile. For a billing system that is the one bug that matters, and
it is the kind that appears only after enough invoices have accumulated to make the error
visible.

**Postgres `numeric`.** Rejected. It is exact, so it solves the representation problem, but it
moves the arithmetic into the database and out of the language the rest of the business logic
is written in. That means either every computation becomes a round trip, or the application
reads `numeric` into a float and reintroduces the original bug at the boundary. It also
serialises as a string in JSON, so every client has to parse money before it can add it up.

**A decimal library.** Rejected as unnecessary dependency weight. Integers in minor units are
exact for every operation this service performs, because none of them involve division. A
decimal type earns its place when you need exact fractional results — interest accrual, tax
apportionment, currency conversion — and none of those are here.

**Storing a formatted amount alongside the integer.** Rejected. Two representations of one
value are two things to keep in agreement, and the formatted one is the one that drifts. A
client that wants `"$12.34"` formats it from the integer.

## Consequences

**Overflow is checked, and the checks are separated deliberately.** Per-line limits alone are
not sufficient to bound the total: the limits permit 500 lines at 1e18 minor units each, which
is 5e20 — far past `MaxInt64` (about 9.2e18). An implementation that validated each line and
then summed without checking would wrap to a *negative* total for a batch of entirely legal
lines. `LineTotal`, `SumTotals`, and `InvoiceTotal` therefore each check, and
`TestSumTotals_CatchesWhatPerLineChecksCannot` exists specifically to prove the sum check is
load-bearing rather than redundant.

An overflowed amount is not a rounding error — it is a negative number, and a negative invoice
total is discovered by a customer rather than by a test. That asymmetry is why the limits are
chosen to make overflow unreachable *and* the checks are written anyway: "cannot happen given
the limits" survives right up until somebody raises a limit.

**One currency per invoice, and it is structural.** Line items carry no currency column. They
are in their invoice's currency because there is nowhere to put a different one, so an invoice
cannot be half in dollars and half in euros by construction rather than by a rule the code
remembers to enforce. The currency is validated against an allowlist in the application, and
the database constrains only its *shape* — a list in a CHECK constraint is a migration every
time a market is added.

**Totals are recomputed from the lines, never adjusted.** Adding a line recomputes the subtotal
as `sum(line_total_minor)` rather than incrementing it. Incremental adjustment works and
accumulates any error forever: one bad arithmetic path and every subsequent total is wrong by
that amount with no way to notice. Rebuilding makes the subtotal a function of the rows that
exist, so a mismatch is impossible rather than unlikely.

**Zero-priced lines are legal, and that has a consequence elsewhere.** A free item belongs on
the document, so `unit_price_minor = 0` is permitted. Removing such a line therefore leaves the
subtotal *unchanged* — which is why the audit action for an item change is passed in by the
caller rather than inferred from the totals. Inferring it recorded a removal as an addition in
an append-only log; `TestInvoice_ZeroPricedRemovalIsRecordedAsRemoval` is the regression test.

**The financial fields freeze when an invoice leaves draft.** A trigger rejects any change to
the number, currency, or amounts once the status is no longer `draft`, and item writes are
rejected outright. A correction is a void and a reissue, which is what accounting practice
requires and what an auditor assumes. A draft remains freely editable, and should be.

## Not covered

- **Rounding.** Nothing here divides, so nothing here rounds. Tax is supplied by the caller as
  an integer rather than computed, because this service is not a tax engine and pretending to
  be one is how invoices end up subtly wrong.
- **Currency conversion.** Out of scope; an invoice is in one currency for its whole life.
- **Aggregate reporting.** Summing across invoices for a total would need the same overflow
  discipline applied at the query level, and no endpoint does it yet.
