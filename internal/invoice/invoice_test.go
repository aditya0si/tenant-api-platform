package invoice

import (
	"errors"
	"testing"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
)

// TestCanTransition pins the lifecycle, including the terminal states.
//
// It enumerates the full matrix rather than sampling it: CanTransition mirrors a database
// trigger, and the two are only equivalent if every pair has been checked. A sampled test
// would leave the disagreement exactly where nobody looked — which is the transition that
// re-opens a settled invoice.
func TestCanTransition(t *testing.T) {
	legal := map[string][]string{
		StatusDraft: {StatusOpen, StatusVoid},
		StatusOpen:  {StatusPaid, StatusVoid},
		StatusPaid:  nil,
		StatusVoid:  nil,
	}
	all := []string{StatusDraft, StatusOpen, StatusPaid, StatusVoid}

	for from, allowed := range legal {
		for _, to := range all {
			want := false
			for _, a := range allowed {
				if a == to {
					want = true
				}
			}
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s, %s) = %v, want %v", from, to, got, want)
			}
		}
	}

	// The two that cost money if wrong, called out so a failure names the consequence.
	if CanTransition(StatusPaid, StatusOpen) {
		t.Error("a paid invoice can be re-opened; that is how an invoice is paid twice")
	}
	if CanTransition(StatusVoid, StatusOpen) {
		t.Error("a voided invoice can be re-opened; a voided document must stay void")
	}
	if CanTransition(StatusPaid, StatusPaid) {
		t.Error("paid -> paid is permitted, which would record a transition that changes nothing")
	}
	if CanTransition(StatusVoid, StatusPaid) {
		t.Error("a voided invoice can be paid; a cancelled document cannot be settled")
	}
}

// TestTransitionTo covers the verb-to-status mapping, including the unknown verb.
//
// The unknown case returns "" rather than a default status, so a caller that forgets to
// validate gets a refusal instead of silently issuing an invoice when it meant to pay one.
func TestTransitionTo(t *testing.T) {
	cases := map[Transition]string{
		TransitionIssue:        StatusOpen,
		TransitionPay:          StatusPaid,
		TransitionVoid:         StatusVoid,
		Transition("nonsense"): "",
	}
	for verb, want := range cases {
		if got := TransitionTo(verb); got != want {
			t.Errorf("TransitionTo(%q) = %q, want %q", verb, got, want)
		}
	}
}

// TestLineTotal_OverflowBoundary is the arithmetic check that a float would hide.
//
// int64 multiplication wraps silently, so an overflowed line total is not a rounding error —
// it is a negative number, and a negative amount on an invoice is discovered by a customer
// rather than by a test. Every other line-total test passes against an unchecked
// implementation; these are the ones that do not.
func TestLineTotal_OverflowBoundary(t *testing.T) {
	// The largest permitted pair, which must succeed.
	if _, err := LineTotal(MaxQuantity, MaxUnitPriceMinor); err != nil {
		t.Fatalf("the documented maximum line (quantity %d at %d) was refused: %v",
			MaxQuantity, MaxUnitPriceMinor, err)
	}

	// One past the int64 limit, which must not wrap. 2^62 * 2 = 2^63, which is past
	// MaxInt64, so an unchecked multiply returns a negative number here.
	big := int64(1) << 62
	if got, err := LineTotal(2, big); err == nil {
		t.Fatalf("2 x %d was accepted as %d; an unchecked multiply wraps to a negative total",
			big, got)
	}

	// Rejections that are about the inputs rather than overflow.
	if _, err := LineTotal(0, 100); err == nil {
		t.Error("a zero quantity was accepted")
	}
	if _, err := LineTotal(-1, 100); err == nil {
		t.Error("a negative quantity was accepted")
	}
	if _, err := LineTotal(1, -100); err == nil {
		t.Error("a negative unit price was accepted")
	}
	if got, err := LineTotal(3, 150); err != nil || got != 450 {
		t.Errorf("LineTotal(3, 150) = %d, %v; want 450, nil", got, err)
	}
}

// TestSumTotals_CatchesWhatPerLineChecksCannot is the test that justifies SumTotals existing.
//
// Each line is individually legal: the limits permit MaxItemsPerInvoice lines at the maximum
// line total. Their sum is 500 x 1e18 = 5e20, which is far past MaxInt64 (about 9.2e18). So
// checking every multiplication is *not* sufficient, and an implementation that only checked
// per-line would wrap here — producing a negative invoice total for a batch of entirely valid
// lines. This is the failure mode the two functions exist to separate.
func TestSumTotals_CatchesWhatPerLineChecksCannot(t *testing.T) {
	const perLine = int64(1_000_000_000_000_000_000) // 1e18, the maximum legal line total

	// One line is fine.
	if got, err := SumTotals([]int64{perLine}); err != nil || got != perLine {
		t.Fatalf("a single maximum line failed to sum: %d, %v", got, err)
	}

	// Ten is already past MaxInt64 (1e19 > 9.2e18).
	if got, err := SumTotals([]int64{perLine, perLine, perLine, perLine, perLine,
		perLine, perLine, perLine, perLine, perLine}); err == nil {
		t.Fatalf("ten maximum lines summed to %d without error; the sum wrapped", got)
	}

	// And the full invoice the limits allow.
	lines := make([]int64, MaxItemsPerInvoice)
	for i := range lines {
		lines[i] = perLine
	}
	if got, err := SumTotals(lines); err == nil {
		t.Fatalf("%d maximum lines summed to %d without error; every line was individually legal",
			MaxItemsPerInvoice, got)
	}

	// A negative line total is a corrupt row rather than an overflow, and it must not be
	// silently added to a subtotal.
	if _, err := SumTotals([]int64{100, -50}); err == nil {
		t.Error("a negative line total was summed into the subtotal")
	}

	// The ordinary case still works.
	if got, err := SumTotals([]int64{1250, 3400, 0, 999}); err != nil || got != 5649 {
		t.Errorf("SumTotals = %d, %v; want 5649, nil", got, err)
	}
}

// TestInvoiceTotal_Overflow covers the subtotal-plus-tax addition, which can also wrap.
func TestInvoiceTotal_Overflow(t *testing.T) {
	if got, err := InvoiceTotal(1000, 180); err != nil || got != 1180 {
		t.Errorf("InvoiceTotal(1000, 180) = %d, %v; want 1180, nil", got, err)
	}
	big := int64(1) << 62
	if got, err := InvoiceTotal(big, big); err == nil {
		t.Fatalf("subtotal %d plus tax %d was accepted as %d; the addition wrapped", big, big, got)
	}
	if _, err := InvoiceTotal(-1, 100); err == nil {
		t.Error("a negative subtotal was accepted")
	}
	if _, err := InvoiceTotal(100, -1); err == nil {
		t.Error("a negative tax was accepted")
	}
}

// TestValidateCreate covers the boundary rules, and specifically the currency allowlist.
//
// The database constrains only the shape of a currency code, because a list in a CHECK
// constraint is a migration per market. The allowlist lives here, so this is the only place
// the two can disagree — and a currency this service cannot compute in must be refused rather
// than accepted and mishandled.
func TestValidateCreate(t *testing.T) {
	ok := CreateInput{
		Currency: "usd",
		TaxMinor: 180,
		Items:    []ItemInput{{Description: "Consulting", Quantity: 2, UnitPriceMinor: 5000}},
	}
	norm, err := ValidateCreate(ok)
	if err != nil {
		t.Fatalf("a valid create was refused: %v", err)
	}
	if norm.Currency != "USD" {
		t.Errorf("currency was not normalised to upper case: %q", norm.Currency)
	}
	if norm.Items[0].Description != "Consulting" {
		t.Errorf("item description was altered: %q", norm.Items[0].Description)
	}

	bad := []struct {
		name string
		in   CreateInput
	}{
		{"empty currency", CreateInput{Currency: ""}},
		{"short currency", CreateInput{Currency: "US"}},
		{"unsupported currency", CreateInput{Currency: "XYZ"}},
		{"negative tax", CreateInput{Currency: "USD", TaxMinor: -1}},
		{"implausible tax", CreateInput{Currency: "USD", TaxMinor: MaxTaxMinor + 1}},
	}
	for _, tc := range bad {
		if _, err := ValidateCreate(tc.in); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}

	// No items is legal: an invoice can be drafted empty and filled in before issuing. The
	// totals are then zero, which the schema permits (CHECK >= 0).
	if _, err := ValidateCreate(CreateInput{Currency: "USD"}); err != nil {
		t.Errorf("an empty draft was refused: %v", err)
	}

	// Too many lines is refused, and the message names the limit rather than a count.
	many := CreateInput{Currency: "USD", Items: make([]ItemInput, MaxItemsPerInvoice+1)}
	for i := range many.Items {
		many.Items[i] = ItemInput{Description: "x", Quantity: 1, UnitPriceMinor: 1}
	}
	_, err = ValidateCreate(many)
	if err == nil {
		t.Fatal("an invoice past the line limit was accepted")
	}
	var ce *apperr.ClientError
	if !errors.As(err, &ce) {
		t.Fatalf("the line-limit failure is not a client error: %v", err)
	}
}

// TestValidateItem covers one line's rules, including the trimming that makes a
// whitespace-only description invalid rather than an empty-looking but non-empty string.
func TestValidateItem(t *testing.T) {
	norm, err := ValidateItem(ItemInput{Description: "  Design work  ", Quantity: 1, UnitPriceMinor: 100})
	if err != nil {
		t.Fatalf("a valid item was refused: %v", err)
	}
	if norm.Description != "Design work" {
		t.Errorf("description was not trimmed: %q", norm.Description)
	}

	bad := []struct {
		name string
		in   ItemInput
	}{
		{"empty description", ItemInput{Description: "", Quantity: 1}},
		{"whitespace description", ItemInput{Description: "   ", Quantity: 1}},
		{"long description", ItemInput{Description: string(make([]byte, MaxDescriptionLen+1)), Quantity: 1}},
		{"zero quantity", ItemInput{Description: "x", Quantity: 0}},
		{"negative quantity", ItemInput{Description: "x", Quantity: -1}},
		{"huge quantity", ItemInput{Description: "x", Quantity: MaxQuantity + 1}},
		{"negative price", ItemInput{Description: "x", Quantity: 1, UnitPriceMinor: -1}},
		{"huge price", ItemInput{Description: "x", Quantity: 1, UnitPriceMinor: MaxUnitPriceMinor + 1}},
	}
	for _, tc := range bad {
		if _, err := ValidateItem(tc.in); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}

	// A zero-priced line is legal and is not the same as an absent one: a free item still
	// belongs on the document. This matters because removing such a line leaves the subtotal
	// unchanged, which is why the item-removed action cannot be inferred from the totals.
	if _, err := ValidateItem(ItemInput{Description: "Free sample", Quantity: 1, UnitPriceMinor: 0}); err != nil {
		t.Errorf("a zero-priced line was refused: %v", err)
	}
}

// TestNormalizePageSize and TestNormalizeStatus cover the listing parameters.
func TestNormalizePageSize(t *testing.T) {
	cases := map[int]int{
		0:               DefaultPageSize,
		-5:              DefaultPageSize,
		DefaultPageSize: DefaultPageSize,
		1:               1,
		MaxPageSize:     MaxPageSize,
		MaxPageSize + 1: MaxPageSize,
		100000:          MaxPageSize,
	}
	for in, want := range cases {
		if got := NormalizePageSize(in); got != want {
			t.Errorf("NormalizePageSize(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	for _, s := range []string{StatusDraft, StatusOpen, StatusPaid, StatusVoid} {
		if got, err := NormalizeStatus(s); err != nil || got != s {
			t.Errorf("NormalizeStatus(%q) = %q, %v; want %q, nil", s, got, err, s)
		}
	}
	// Empty means "any", which is not an error — it is the default listing.
	if got, err := NormalizeStatus(""); err != nil || got != "" {
		t.Errorf("NormalizeStatus(\"\") = %q, %v; want \"\", nil", got, err)
	}
	for _, s := range []string{"cancelled", "DRAFT", "paid ", "1"} {
		if _, err := NormalizeStatus(s); err == nil {
			t.Errorf("NormalizeStatus(%q) was accepted; an unknown status would filter to nothing "+
				"and read as an empty account", s)
		}
	}
}

// TestSupportedCurrency pins the allowlist against the shape-only database constraint.
//
// The mismatch is deliberate and worth a test: the database accepts any three uppercase
// letters, so this function is the only thing standing between a request and an invoice in a
// currency this service cannot compute in.
func TestSupportedCurrency(t *testing.T) {
	for _, cur := range []string{"USD", "EUR", "GBP", "INR", "JPY"} {
		if !SupportedCurrency(cur) {
			t.Errorf("%s is not supported", cur)
		}
	}
	for _, cur := range []string{"XYZ", "usd", "AB", "ABCD", ""} {
		if SupportedCurrency(cur) {
			t.Errorf("%q is reported as supported; the check must be exact", cur)
		}
	}
}

// TestValidateUUID covers the nil-id mapping, which every repository method relies on to avoid
// repeating the check.
func TestValidateUUID(t *testing.T) {
	if err := ValidateUUID([16]byte{}); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("the zero id mapped to %v, want not-found", err)
	}
}
