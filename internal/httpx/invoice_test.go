package httpx_test

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/aditya0si/tenant-api-platform/internal/audit"
	"github.com/aditya0si/tenant-api-platform/internal/authz"
	"github.com/aditya0si/tenant-api-platform/internal/invoice"
)

// invoiceBody is the wire shape these tests decode.
type invoiceBody struct {
	ID       string `json:"id"`
	Number   string `json:"number"`
	Status   string `json:"status"`
	Currency string `json:"currency"`

	SubtotalMinor int64 `json:"subtotal_minor"`
	TaxMinor      int64 `json:"tax_minor"`
	TotalMinor    int64 `json:"total_minor"`
	Version       int   `json:"version"`

	IssuedAt *string `json:"issued_at"`
	PaidAt   *string `json:"paid_at"`
	VoidedAt *string `json:"voided_at"`

	// A pointer so a test can tell "the field was absent" from "it was an empty list" — the
	// distinction a listing relies on.
	Items *[]struct {
		ID             string `json:"id"`
		Position       int    `json:"position"`
		Description    string `json:"description"`
		Quantity       int    `json:"quantity"`
		UnitPriceMinor int64  `json:"unit_price_minor"`
		LineTotalMinor int64  `json:"line_total_minor"`
	} `json:"items"`
}

// invoiceBase is the collection path for a tenant.
func invoiceBase(tenantID string) string { return "/v1/tenants/" + tenantID + "/invoices" }

// createInvoice posts a create request and requires it to succeed.
func (s *server) createInvoice(token, tenantID string, body map[string]any) invoiceBody {
	s.t.Helper()
	res := s.do(http.MethodPost, invoiceBase(tenantID), body, token)
	if res.status != http.StatusCreated {
		s.t.Fatalf("create invoice: status %d, body %s", res.status, res.body)
	}
	var inv invoiceBody
	res.decodeData(s.t, &inv)
	return inv
}

// TestInvoice_TotalsAreComputedFromLines is the arithmetic baseline, and it checks the number
// the database independently asserts.
//
// A wrong total is the one bug in a billing system that a customer finds. The subtotal is
// summed from the lines and the total adds tax, and both invariants are CHECK constraints in
// the schema — so this test asserts the application agrees with the database rather than
// merely that the response looks plausible.
func TestInvoice_TotalsAreComputedFromLines(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-totals"))

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency":  "usd",
		"tax_minor": 1800,
		"items": []map[string]any{
			{"description": "Consulting", "quantity": 2, "unit_price_minor": 50000}, // 100000
			{"description": "Hosting", "quantity": 1, "unit_price_minor": 2500},     //   2500
			{"description": "Free sample", "quantity": 3, "unit_price_minor": 0},    //      0
		},
	})

	// 100000 + 2500 + 0
	if inv.SubtotalMinor != 102500 {
		t.Fatalf("subtotal_minor = %d, want 102500", inv.SubtotalMinor)
	}
	if inv.TotalMinor != 104300 {
		t.Fatalf("total_minor = %d, want 104300 (102500 + 1800 tax)", inv.TotalMinor)
	}
	if inv.TotalMinor != inv.SubtotalMinor+inv.TaxMinor {
		t.Fatalf("total %d is not subtotal %d plus tax %d; the schema's CHECK would have "+
			"rejected this write, so the response must be consistent",
			inv.TotalMinor, inv.SubtotalMinor, inv.TaxMinor)
	}
	if inv.Currency != "USD" {
		t.Fatalf("currency = %q, want USD (normalised from the lower-case input)", inv.Currency)
	}
	if inv.Status != invoice.StatusDraft {
		t.Fatalf("a new invoice is %q, want draft", inv.Status)
	}
	if inv.Number == "" {
		t.Fatal("the invoice has no number")
	}
	if inv.Items == nil || len(*inv.Items) != 3 {
		t.Fatalf("items = %v, want the three lines that were supplied", inv.Items)
	}

	// Line totals are computed, not echoed: the client sent no line total at all.
	want := []int64{100000, 2500, 0}
	for i, it := range *inv.Items {
		if it.LineTotalMinor != want[i] {
			t.Errorf("line %d total = %d, want %d", i, it.LineTotalMinor, want[i])
		}
		if it.Position != i {
			t.Errorf("line %d has position %d; positions must be the supplied order", i, it.Position)
		}
	}

	// The database's own check, read directly — the response could be consistent while the
	// stored row is not, and only a constraint makes that impossible.
	if s.db.Owner != nil {
		tid := uuid.MustParse(tenantID)
		var subtotal, total int64
		if err := s.db.Owner.QueryRow(context.Background(),
			`SELECT subtotal_minor, total_minor FROM invoices WHERE tenant_id = $1 AND id = $2`,
			tid, uuid.MustParse(inv.ID)).Scan(&subtotal, &total); err != nil {
			t.Fatalf("read the stored invoice: %v", err)
		}
		if subtotal != inv.SubtotalMinor || total != inv.TotalMinor {
			t.Fatalf("stored totals (%d, %d) differ from the response (%d, %d)",
				subtotal, total, inv.SubtotalMinor, inv.TotalMinor)
		}
	}
}

// TestInvoice_OverflowIsRefusedNotWrapped exercises the accumulation path that per-line checks
// cannot cover.
//
// Each line is individually legal: the limits permit quantity 1e6 at 1e12 minor units, which
// is 1e18 per line. Ten of those is 1e19 — past MaxInt64 — so an implementation that validated
// each line and then summed without checking would wrap to a negative total. The schema's
// CHECK (total_minor >= 0) would reject it too, which would surface as a 500; this asserts the
// application refuses it as a 400 first, naming the problem.
func TestInvoice_OverflowIsRefusedNotWrapped(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-overflow"))

	// 1e18 per line, ten lines: 1e19, comfortably past MaxInt64 (~9.2e18).
	huge := int64(invoice.MaxUnitPriceMinor)
	items := make([]map[string]any, 0, 10)
	for i := 0; i < 10; i++ {
		items = append(items, map[string]any{
			"description":      "Large line",
			"quantity":         invoice.MaxQuantity,
			"unit_price_minor": huge,
		})
	}

	res := s.do(http.MethodPost, invoiceBase(tenantID), map[string]any{
		"currency": "USD",
		"items":    items,
	}, session.AccessToken)

	if res.status == http.StatusCreated {
		t.Fatal("ten maximum lines were accepted; each is individually legal but their sum " +
			"exceeds int64, so an unchecked accumulation wrapped and the totals are nonsense")
	}
	if res.status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 — the amount is the client's input, so it is a request "+
			"error rather than a server fault; body %s", res.status, res.body)
	}
}

// TestInvoice_Lifecycle walks draft -> open -> paid and checks the state and its timestamps.
//
// The state timestamps are a schema CHECK: a paid invoice must carry paid_at and must not carry
// voided_at, so a bug that left one behind would be rejected by the database rather than
// silently reported as revenue by a report that reads paid_at.
func TestInvoice_Lifecycle(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-life"))
	base := invoiceBase(tenantID)

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "EUR",
		"items":    []map[string]any{{"description": "Work", "quantity": 1, "unit_price_minor": 10000}},
	})
	if inv.IssuedAt != nil || inv.PaidAt != nil || inv.VoidedAt != nil {
		t.Fatal("a draft invoice carries a state timestamp")
	}

	issue := s.do(http.MethodPost, base+"/"+inv.ID+"/issue",
		map[string]any{"expected_version": inv.Version}, session.AccessToken)
	if issue.status != http.StatusOK {
		t.Fatalf("issue: status %d, body %s", issue.status, issue.body)
	}
	var issued invoiceBody
	issue.decodeData(t, &issued)
	if issued.Status != invoice.StatusOpen {
		t.Fatalf("after issue the status is %q, want open", issued.Status)
	}
	if issued.IssuedAt == nil {
		t.Fatal("an open invoice has no issued_at")
	}
	if issued.Version != inv.Version+1 {
		t.Fatalf("version = %d, want %d — every transition must bump it, or a retry can "+
			"settle twice", issued.Version, inv.Version+1)
	}

	pay := s.do(http.MethodPost, base+"/"+inv.ID+"/pay",
		map[string]any{"expected_version": issued.Version}, session.AccessToken)
	if pay.status != http.StatusOK {
		t.Fatalf("pay: status %d, body %s", pay.status, pay.body)
	}
	var paid invoiceBody
	pay.decodeData(t, &paid)
	if paid.Status != invoice.StatusPaid {
		t.Fatalf("after pay the status is %q, want paid", paid.Status)
	}
	if paid.PaidAt == nil || paid.IssuedAt == nil {
		t.Fatal("a paid invoice must carry both issued_at and paid_at")
	}
	if paid.VoidedAt != nil {
		t.Fatal("a paid invoice carries voided_at; the schema forbids that combination")
	}
	// The response is a real invoice, not a zero value — the bug this test was written for
	// after Transition returned an unassigned struct.
	if paid.Number != inv.Number || paid.TotalMinor != inv.TotalMinor {
		t.Fatalf("the pay response does not describe the invoice that was paid: %+v", paid)
	}
}

// TestInvoice_IllegalTransitionsAreRefused covers the state machine from the client's side.
//
// Each refusal must be a 409 rather than a 400: the request is well-formed and the client is
// asking for something that the resource's current state forbids, which is a conflict they
// resolve by re-reading rather than by fixing their input.
func TestInvoice_IllegalTransitionsAreRefused(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-illegal"))
	base := invoiceBase(tenantID)

	mk := func() invoiceBody {
		return s.createInvoice(session.AccessToken, tenantID, map[string]any{"currency": "USD"})
	}

	// draft -> pay is not a transition: an invoice must be issued before it can be settled,
	// which is what stops an un-reviewed draft from being marked paid.
	draft := mk()
	if res := s.do(http.MethodPost, base+"/"+draft.ID+"/pay",
		map[string]any{"expected_version": draft.Version}, session.AccessToken); res.status != http.StatusConflict {
		t.Fatalf("paying a draft returned %d, want 409; body %s", res.status, res.body)
	}

	// A settled invoice is terminal.
	settled := mk()
	issued := s.do(http.MethodPost, base+"/"+settled.ID+"/issue",
		map[string]any{"expected_version": settled.Version}, session.AccessToken)
	var issuedBody invoiceBody
	issued.decodeData(t, &issuedBody)
	paid := s.do(http.MethodPost, base+"/"+settled.ID+"/pay",
		map[string]any{"expected_version": issuedBody.Version}, session.AccessToken)
	var paidBody invoiceBody
	paid.decodeData(t, &paidBody)

	for _, tc := range []struct{ verb, name string }{
		{"pay", "paying a paid invoice"},
		{"void", "voiding a paid invoice"},
		{"issue", "re-issuing a paid invoice"},
	} {
		res := s.do(http.MethodPost, base+"/"+settled.ID+"/"+tc.verb,
			map[string]any{"expected_version": paidBody.Version}, session.AccessToken)
		if res.status != http.StatusConflict {
			t.Errorf("%s returned %d, want 409; body %s", tc.name, res.status, res.body)
		}
	}

	// A voided invoice is terminal too.
	voided := mk()
	vres := s.do(http.MethodPost, base+"/"+voided.ID+"/void",
		map[string]any{"expected_version": voided.Version}, session.AccessToken)
	if vres.status != http.StatusOK {
		t.Fatalf("voiding a draft: status %d, body %s", vres.status, vres.body)
	}
	var voidedBody invoiceBody
	vres.decodeData(t, &voidedBody)
	if res := s.do(http.MethodPost, base+"/"+voided.ID+"/issue",
		map[string]any{"expected_version": voidedBody.Version}, session.AccessToken); res.status != http.StatusConflict {
		t.Fatalf("re-issuing a voided invoice returned %d, want 409; body %s", res.status, res.body)
	}
}

// TestInvoice_DoubleSettleIsRefusedByVersionCAS is the concurrency assertion for the operation
// that costs money.
//
// It fires identical pay requests at once with the same expected_version. The compare-and-set
// in the UPDATE means exactly one can match; the losers see zero rows and are told the invoice
// changed. Without that predicate, two callers would both read "open", both write "paid", and
// the invoice would be settled twice — with two paid_at writes and two ledger entries, and no
// way afterwards to tell which was real.
func TestInvoice_DoubleSettleIsRefusedByVersionCAS(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-race"))
	base := invoiceBase(tenantID)

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Race", "quantity": 1, "unit_price_minor": 5000}},
	})
	issue := s.do(http.MethodPost, base+"/"+inv.ID+"/issue",
		map[string]any{"expected_version": inv.Version}, session.AccessToken)
	var issued invoiceBody
	issue.decodeData(t, &issued)

	// Every worker uses the version read before the race, which is exactly what a client
	// retrying an unacknowledged request would send.
	const workers = 6
	results := make([]rawResult, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = s.doRaw(http.MethodPost, base+"/"+inv.ID+"/pay",
				map[string]any{"expected_version": issued.Version}, session.AccessToken, "")
		}(i)
	}
	close(start)
	wg.Wait()

	var settled int
	for i, res := range results {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		switch res.status {
		case http.StatusOK:
			settled++
		case http.StatusConflict:
			// The expected outcome: this caller's version was stale.
		case http.StatusInternalServerError:
			t.Fatalf("worker %d got a 500, which means the write failed rather than being "+
				"serialised:\n%s", i, res.body)
		default:
			t.Fatalf("worker %d: unexpected status %d, body %s", i, res.status, res.body)
		}
	}

	if settled != 1 {
		t.Fatalf("%d of %d concurrent pay requests succeeded, want exactly 1; the "+
			"compare-and-set is not serialising the settle", settled, workers)
	}

	// The row itself, read with owner credentials: paid once, and the version advanced by
	// exactly one transition rather than by every attempt.
	if s.db.Owner != nil {
		tid := uuid.MustParse(tenantID)
		var status string
		var version int
		if err := s.db.Owner.QueryRow(context.Background(),
			`SELECT status, version FROM invoices WHERE tenant_id = $1 AND id = $2`,
			tid, uuid.MustParse(inv.ID)).Scan(&status, &version); err != nil {
			t.Fatalf("read the settled invoice: %v", err)
		}
		if status != invoice.StatusPaid {
			t.Fatalf("status = %q, want paid", status)
		}
		if version != issued.Version+1 {
			t.Fatalf("version = %d, want %d: %d concurrent attempts advanced it %d times",
				version, issued.Version+1, workers, version-issued.Version)
		}
	}
}

// TestInvoice_ItemsAreFrozenOnceIssued covers the rule that protects a number a customer has
// already seen.
//
// Once an invoice is issued its money is immutable — a correction is a void and a reissue, not
// an edit. The database trigger enforces it, and this asserts a client gets a readable 409
// rather than a 500 wrapping a constraint violation.
func TestInvoice_ItemsAreFrozenOnceIssued(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-frozen"))
	base := invoiceBase(tenantID)

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Original", "quantity": 1, "unit_price_minor": 100}},
	})

	// A draft accepts a new line.
	add := s.do(http.MethodPost, base+"/"+inv.ID+"/items", map[string]any{
		"description": "Added", "quantity": 1, "unit_price_minor": 200,
	}, session.AccessToken)
	if add.status != http.StatusOK {
		t.Fatalf("adding to a draft: status %d, body %s", add.status, add.body)
	}
	var withItem invoiceBody
	add.decodeData(t, &withItem)
	if withItem.SubtotalMinor != 300 {
		t.Fatalf("subtotal after adding = %d, want 300", withItem.SubtotalMinor)
	}
	if withItem.Items == nil || len(*withItem.Items) != 2 {
		t.Fatalf("items = %v, want 2", withItem.Items)
	}

	// Issue it, then try to change the lines.
	if res := s.do(http.MethodPost, base+"/"+inv.ID+"/issue",
		map[string]any{"expected_version": withItem.Version}, session.AccessToken); res.status != http.StatusOK {
		t.Fatalf("issue: status %d, body %s", res.status, res.body)
	}

	res := s.do(http.MethodPost, base+"/"+inv.ID+"/items", map[string]any{
		"description": "Too late", "quantity": 1, "unit_price_minor": 999,
	}, session.AccessToken)
	if res.status != http.StatusConflict {
		t.Fatalf("adding a line to an issued invoice returned %d, want 409 — an issued "+
			"invoice's money is immutable; body %s", res.status, res.body)
	}

	// And the totals did not move.
	if s.db.Owner != nil {
		tid := uuid.MustParse(tenantID)
		var subtotal int64
		if err := s.db.Owner.QueryRow(context.Background(),
			`SELECT subtotal_minor FROM invoices WHERE tenant_id = $1 AND id = $2`,
			tid, uuid.MustParse(inv.ID)).Scan(&subtotal); err != nil {
			t.Fatalf("read the invoice: %v", err)
		}
		if subtotal != 300 {
			t.Fatalf("subtotal after the refused edit = %d, want 300", subtotal)
		}
	}
}

// TestInvoice_ZeroPricedRemovalIsRecordedAsRemoval is the regression test for a bug that
// arithmetic inference caused.
//
// The item event and audit action were once derived from `subtotal < before.SubtotalMinor`.
// Removing a zero-priced line leaves the subtotal identical, so the removal was recorded as an
// *addition* — a false entry in an append-only log whose only job is to be accurate. A free
// sample on an invoice is not a contrived case; it is exactly why a zero-priced line is legal.
func TestInvoice_ZeroPricedRemovalIsRecordedAsRemoval(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-zero"))
	base := invoiceBase(tenantID)

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items": []map[string]any{
			{"description": "Paid item", "quantity": 1, "unit_price_minor": 1000},
			{"description": "Free sample", "quantity": 1, "unit_price_minor": 0},
		},
	})
	if inv.Items == nil || len(*inv.Items) != 2 {
		t.Fatalf("setup: items = %v", inv.Items)
	}

	// Remove the zero-priced line, whose removal cannot be inferred from the subtotal.
	var freeID string
	for _, it := range *inv.Items {
		if it.UnitPriceMinor == 0 {
			freeID = it.ID
		}
	}
	if freeID == "" {
		t.Fatal("setup did not produce a zero-priced line")
	}

	res := s.do(http.MethodDelete, base+"/"+inv.ID+"/items/"+freeID, nil, session.AccessToken)
	if res.status != http.StatusOK {
		t.Fatalf("removing the free line: status %d, body %s", res.status, res.body)
	}
	var after invoiceBody
	res.decodeData(t, &after)
	if after.SubtotalMinor != 1000 {
		t.Fatalf("subtotal = %d, want 1000 — unchanged, which is why the action cannot be "+
			"inferred from the totals", after.SubtotalMinor)
	}

	// The audit trail must say "removed", not "added".
	var removed, added int
	for _, row := range s.auditRows(t, tenantID) {
		switch row.Action {
		case audit.ActionInvoiceItemRemoved:
			removed++
		case audit.ActionInvoiceItemAdded:
			added++
		}
	}
	if removed != 1 {
		t.Fatalf("recorded %d item_removed entries for one removal (%d item_added entries); "+
			"removing a zero-priced line must not be logged as an addition", removed, added)
	}
}

// TestInvoice_PermissionsAndIsolation covers who may do what, and that one tenant cannot see
// another's invoices.
//
// An invoice carries amounts and a customer name, so a leak here is a commercial disclosure
// rather than merely a bug. A member may read — an invoice is part of the work they were
// invited to do — but may not create or settle.
func TestInvoice_PermissionsAndIsolation(t *testing.T) {
	s := newServer(t)
	owner, tenantID := s.register(uniqueEmail("inv-perm"))
	base := invoiceBase(tenantID)

	created := s.createInvoice(owner.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Perm", "quantity": 1, "unit_price_minor": 100}},
	})

	admin := s.addMemberWithRole(owner, tenantID, uniqueEmail("inv-admin"), authz.RoleAdmin)
	member := s.addMemberWithRole(owner, tenantID, uniqueEmail("inv-member"), authz.RoleMember)

	// A member can read.
	if res := s.do(http.MethodGet, base+"/"+created.ID, nil, member.AccessToken); res.status != http.StatusOK {
		t.Fatalf("member read: status %d, want 200 — an invoice is part of the work a member "+
			"was invited to do; body %s", res.status, res.body)
	}

	// A member cannot create or settle: both are 403, not 404, because the member is in the
	// tenant and this is a permission decision rather than a visibility one.
	createRes := s.do(http.MethodPost, base, map[string]any{"currency": "USD"}, member.AccessToken)
	if createRes.status != http.StatusForbidden {
		t.Fatalf("member create: status %d, want 403; body %s", createRes.status, createRes.body)
	}
	payRes := s.do(http.MethodPost, base+"/"+created.ID+"/pay",
		map[string]any{"expected_version": created.Version}, member.AccessToken)
	if payRes.status != http.StatusForbidden {
		t.Fatalf("member settle: status %d, want 403; body %s", payRes.status, payRes.body)
	}

	// An admin can do both.
	if res := s.do(http.MethodPost, base, map[string]any{"currency": "USD"}, admin.AccessToken); res.status != http.StatusCreated {
		t.Fatalf("admin create: status %d, body %s", res.status, res.body)
	}

	// An outsider is not a member of this tenant, so the membership gate refuses before
	// authorization is even considered: 404, never 403, so the response cannot confirm that
	// the tenant exists. Listing is refused for the same reason as reading by id — the gate
	// runs on the route group, not per handler.
	outsider, outsiderTenant := s.register(uniqueEmail("inv-outsider"))
	if outsiderTenant == tenantID {
		t.Fatal("the outsider landed in the same tenant, which would make this vacuous")
	}
	if res := s.do(http.MethodGet, base+"/"+created.ID, nil, outsider.AccessToken); res.status != http.StatusNotFound {
		t.Fatalf("outsider read by id: status %d, want 404; body %s", res.status, res.body)
	}
	if res := s.do(http.MethodGet, base, nil, outsider.AccessToken); res.status != http.StatusNotFound {
		t.Fatalf("outsider list: status %d, want 404 — a 200 would confirm the tenant exists and "+
			"that the caller may not see it; body %s", res.status, res.body)
	}

	// The outsider's own tenant has no invoices, which is what an isolated listing looks like
	// from the inside: an empty page, not a refusal.
	ownRes := s.do(http.MethodGet, invoiceBase(outsiderTenant), nil, outsider.AccessToken)
	if ownRes.status != http.StatusOK {
		t.Fatalf("the outsider's own listing: status %d, body %s", ownRes.status, ownRes.body)
	}
	var ownPage struct {
		Data []invoiceBody `json:"data"`
	}
	ownRes.decodeEnvelope(t, &ownPage)
	if len(ownPage.Data) != 0 {
		t.Fatalf("the outsider's own tenant listed %d invoices, but none were created there; "+
			"the listing is not scoped to the caller's tenant", len(ownPage.Data))
	}
}

// TestInvoice_ListOmitsItemsButReadIncludesThem pins the response distinction a client relies
// on.
//
// A listing deliberately does not load lines, and the field is absent rather than an empty
// array so a client can tell "not loaded, fetch it" from "this invoice has no lines". Getting
// that wrong makes a rendered invoice look empty.
func TestInvoice_ListOmitsItemsButReadIncludesThem(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-list"))
	base := invoiceBase(tenantID)

	created := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Listed", "quantity": 1, "unit_price_minor": 700}},
	})

	listRes := s.do(http.MethodGet, base, nil, session.AccessToken)
	if listRes.status != http.StatusOK {
		t.Fatalf("list: status %d, body %s", listRes.status, listRes.body)
	}
	var page struct {
		Data []invoiceBody `json:"data"`
	}
	listRes.decodeEnvelope(t, &page)
	if len(page.Data) != 1 {
		t.Fatalf("listing returned %d invoices, want 1", len(page.Data))
	}
	if page.Data[0].Items != nil {
		t.Error("a listing included items; lines are deliberately not loaded, and sending an " +
			"empty array would make an invoice with lines look empty")
	}

	// A single read includes them, and carries the money.
	oneRes := s.do(http.MethodGet, base+"/"+created.ID, nil, session.AccessToken)
	var one invoiceBody
	oneRes.decodeData(t, &one)
	if one.Items == nil {
		t.Fatal("a single read omitted items")
	}
	if len(*one.Items) != 1 || (*one.Items)[0].LineTotalMinor != 700 {
		t.Fatalf("a single read returned %v, want the one line at 700", *one.Items)
	}

	// A filter that matches nothing is an empty page, not an error.
	empty := s.do(http.MethodGet, base+"?status=paid", nil, session.AccessToken)
	if empty.status != http.StatusOK {
		t.Fatalf("filtered list: status %d, body %s", empty.status, empty.body)
	}
	var emptyPage struct {
		Data []invoiceBody `json:"data"`
	}
	empty.decodeEnvelope(t, &emptyPage)
	if len(emptyPage.Data) != 0 {
		t.Fatalf("status=paid returned %d invoices, but everything here is a draft", len(emptyPage.Data))
	}

	// An unknown status is refused rather than silently returning everything: a filtered
	// listing that quietly ignores its filter reads as an empty account.
	if res := s.do(http.MethodGet, base+"?status=cancelled", nil, session.AccessToken); res.status != http.StatusBadRequest {
		t.Fatalf("unknown status filter: status %d, want 400; body %s", res.status, res.body)
	}
}

// TestInvoice_IdsAreOpaqueAcrossTenants is the id-guessing check.
//
// A malformed id is not-found rather than a bad request, so nothing about id format is
// learnable from a status code, and a well-formed id belonging to another tenant is
// indistinguishable from one that does not exist.
func TestInvoice_IdsAreOpaqueAcrossTenants(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-opaque"))
	base := invoiceBase(tenantID)

	for _, id := range []string{"not-a-uuid", uuid.Nil.String(), uuid.Must(uuid.NewV7()).String()} {
		res := s.do(http.MethodGet, base+"/"+id, nil, session.AccessToken)
		if res.status != http.StatusNotFound {
			t.Errorf("GET with id %q returned %d, want 404 for every one of them; body %s",
				id, res.status, res.body)
		}
	}

	// A transition on an unknown id is also not-found rather than a conflict.
	res := s.do(http.MethodPost, base+"/"+uuid.Must(uuid.NewV7()).String()+"/pay",
		map[string]any{"expected_version": 1}, session.AccessToken)
	if res.status != http.StatusNotFound {
		t.Fatalf("paying an unknown invoice returned %d, want 404; body %s", res.status, res.body)
	}
}

// TestInvoice_NumberSequenceIsPerTenantAndMonotonic checks allocation.
//
// Two tenants are different issuers, so neither should observe the other's numbering, and a
// sequence that repeats within a tenant is the one failure that matters: an invoice number is
// referenced by a document that may already have been sent.
func TestInvoice_NumberSequenceIsPerTenantAndMonotonic(t *testing.T) {
	s := newServer(t)
	first, tenantA := s.register(uniqueEmail("inv-seq-a"))
	second, tenantB := s.register(uniqueEmail("inv-seq-b"))

	a1 := s.createInvoice(first.AccessToken, tenantA, map[string]any{"currency": "USD"})
	a2 := s.createInvoice(first.AccessToken, tenantA, map[string]any{"currency": "USD"})
	b1 := s.createInvoice(second.AccessToken, tenantB, map[string]any{"currency": "USD"})

	if a1.Number == a2.Number {
		t.Fatalf("two invoices in one tenant share the number %q; a number identifies a "+
			"document and cannot repeat", a1.Number)
	}
	if a1.Number >= a2.Number {
		t.Fatalf("numbers are not increasing within a tenant: %q then %q", a1.Number, a2.Number)
	}
	// Tenant B's first invoice is its own first number, not a continuation of A's.
	if b1.Number != a1.Number {
		t.Fatalf("tenant B's first invoice is %q but tenant A's first was %q; numbering is "+
			"per-issuer, so both start at the same place", b1.Number, a1.Number)
	}
	if a1.ID == b1.ID {
		t.Fatal("two tenants produced the same invoice id")
	}
}

// TestInvoice_NumberAndIdAreStableAcrossReads guards against a read path that regenerates
// anything.
//
// A read that minted a new id or number would be invisible in a single-response test and
// catastrophic in practice: two reads of one invoice would describe two different documents.
func TestInvoice_NumberAndIdAreStableAcrossReads(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-stable"))
	base := invoiceBase(tenantID)

	created := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Stable", "quantity": 2, "unit_price_minor": 333}},
	})

	for i := 0; i < 3; i++ {
		res := s.do(http.MethodGet, base+"/"+created.ID, nil, session.AccessToken)
		if res.status != http.StatusOK {
			t.Fatalf("read %d: status %d, body %s", i, res.status, res.body)
		}
		var got invoiceBody
		res.decodeData(t, &got)
		if got.ID != created.ID || got.Number != created.Number {
			t.Fatalf("read %d returned id/number %s/%s, want %s/%s",
				i, got.ID, got.Number, created.ID, created.Number)
		}
		if got.SubtotalMinor != 666 || got.Version != created.Version {
			t.Fatalf("read %d returned subtotal %d version %d, want 666 and %d",
				i, got.SubtotalMinor, got.Version, created.Version)
		}
	}
}

// TestInvoice_RequestEchoIsNotTrusted covers the boundary between what a client supplies and
// what the server computes.
//
// A client that sends its own totals, status, number, or version must have them ignored rather
// than honoured: trusting any of them would let a caller issue themselves a zero-total invoice
// in a paid state.
func TestInvoice_RequestEchoIsNotTrusted(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-echo"))

	// Unknown fields are rejected outright by the decoder, which is the first line of defence
	// and the reason a client cannot smuggle a total in under a name the server ignores.
	body := []byte(`{"currency":"USD","total_minor":1,"status":"paid","number":"INV-999999","version":99,"subtotal_minor":0}`)
	res, err := s.doRawBody(http.MethodPost, invoiceBase(tenantID), body, session.AccessToken, "")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.status != http.StatusBadRequest {
		t.Fatalf("a body carrying server-computed fields returned %d, want 400 — silently "+
			"ignoring them would let a client believe it set them; body %s", res.status, res.body)
	}

	// And a legitimate body still produces server-computed values.
	created := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Honest", "quantity": 1, "unit_price_minor": 42}},
	})
	if created.TotalMinor != 42 || created.Status != invoice.StatusDraft || created.Version != 1 {
		t.Fatalf("server-computed fields came from the client: %+v", created)
	}
}

// TestInvoice_UnsupportedCurrencyIsRefused pins the application-side allowlist.
//
// The database constrains only the shape ([A-Z]{3}), so this check is the only thing between a
// request and an invoice in a currency the service cannot compute in.
func TestInvoice_UnsupportedCurrencyIsRefused(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-cur"))

	for _, cur := range []string{"XYZ", "us", "USDD", ""} {
		res := s.do(http.MethodPost, invoiceBase(tenantID), map[string]any{"currency": cur}, session.AccessToken)
		if res.status != http.StatusBadRequest {
			t.Errorf("currency %q returned %d, want 400; body %s", cur, res.status, res.body)
		}
	}

	// A supported one, in lower case, is accepted and normalised.
	res := s.do(http.MethodPost, invoiceBase(tenantID), map[string]any{"currency": "inr"}, session.AccessToken)
	if res.status != http.StatusCreated {
		t.Fatalf("INR was refused: status %d, body %s", res.status, res.body)
	}
	var got invoiceBody
	res.decodeData(t, &got)
	if got.Currency != "INR" {
		t.Fatalf("currency = %q, want INR", got.Currency)
	}
}

// TestInvoice_IdempotentCreateDoesNotBurnANumber is the interaction between the two guards.
//
// A retried create must replay rather than allocate again. A duplicate is not merely untidy
// here: each attempt consumes an invoice number, and a number that has been sent to a customer
// cannot be reused, so a duplicate leaves a gap an accountant will ask about.
func TestInvoice_IdempotentCreateDoesNotBurnANumber(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-idem"))
	base := invoiceBase(tenantID)

	const key = "invoice-create-0001"
	payload := map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Once", "quantity": 1, "unit_price_minor": 100}},
	}

	first := s.doWithKey(http.MethodPost, base, payload, session.AccessToken, key)
	if first.status != http.StatusCreated {
		t.Fatalf("first create: status %d, body %s", first.status, first.body)
	}
	var created invoiceBody
	first.decodeData(t, &created)

	second := s.doWithKey(http.MethodPost, base, payload, session.AccessToken, key)
	if second.status != http.StatusCreated {
		t.Fatalf("replay: status %d, body %s", second.status, second.body)
	}
	if second.header.Get("Idempotent-Replay") != "true" {
		t.Fatal("the retry was not marked as a replay")
	}
	var replayed invoiceBody
	second.decodeData(t, &replayed)
	if replayed.ID != created.ID || replayed.Number != created.Number {
		t.Fatalf("the replay describes a different invoice: %s/%s vs %s/%s",
			replayed.ID, replayed.Number, created.ID, created.Number)
	}

	// Exactly one invoice exists, so no number was burned by the retry.
	res := s.do(http.MethodGet, base, nil, session.AccessToken)
	var page struct {
		Data []invoiceBody `json:"data"`
	}
	res.decodeEnvelope(t, &page)
	if len(page.Data) != 1 {
		t.Fatalf("the retry created a second invoice (%d exist); each attempt consumes an "+
			"invoice number, so a duplicate leaves a gap in a sent sequence", len(page.Data))
	}

	// And the next genuinely new invoice continues the sequence rather than repeating.
	next := s.createInvoice(session.AccessToken, tenantID, map[string]any{"currency": "USD"})
	if next.Number <= created.Number {
		t.Fatalf("the invoice after a replayed create is numbered %q, which does not follow %q",
			next.Number, created.Number)
	}
}

// driveToState creates an invoice and moves it into a named status through the API.
//
// It goes through the real endpoints rather than raw SQL so the invoice it produces is a
// genuine one — the trigger-agreement test below then asks the *database* to change a row the
// application put there, which is the situation a migration, a script, or a debugging session
// would create.
func (s *server) driveToState(t *testing.T, session sessionBody, tenantID, want string) invoiceBody {
	t.Helper()
	base := invoiceBase(tenantID)

	inv := s.createInvoice(session.AccessToken, tenantID, map[string]any{
		"currency": "USD",
		"items":    []map[string]any{{"description": "Trigger", "quantity": 1, "unit_price_minor": 100}},
	})
	if want == invoice.StatusDraft {
		return inv
	}

	issue := s.do(http.MethodPost, base+"/"+inv.ID+"/issue",
		map[string]any{"expected_version": inv.Version}, session.AccessToken)
	if issue.status != http.StatusOK {
		t.Fatalf("driving to open: status %d, body %s", issue.status, issue.body)
	}
	var issued invoiceBody
	issue.decodeData(t, &issued)
	if want == invoice.StatusOpen {
		return issued
	}

	if want == invoice.StatusVoid {
		void := s.do(http.MethodPost, base+"/"+inv.ID+"/void",
			map[string]any{"expected_version": issued.Version}, session.AccessToken)
		if void.status != http.StatusOK {
			t.Fatalf("driving to void: status %d, body %s", void.status, void.body)
		}
		var voided invoiceBody
		void.decodeData(t, &voided)
		return voided
	}

	pay := s.do(http.MethodPost, base+"/"+inv.ID+"/pay",
		map[string]any{"expected_version": issued.Version}, session.AccessToken)
	if pay.status != http.StatusOK {
		t.Fatalf("driving to paid: status %d, body %s", pay.status, pay.body)
	}
	var paid invoiceBody
	pay.decodeData(t, &paid)
	return paid
}

// TestInvoice_TriggerAgreesWithCanTransition is the two-enforcement-points test.
//
// # Why this has to exist
//
// The legal transitions are declared twice: in CanTransition, so a client gets a readable 409,
// and in the invoices_guard trigger, because a future endpoint, a migration, or a debugging
// session will not consult the Go function. Two enforcement points that disagree are worse
// than one — the application would refuse operations the database permits, and the difference
// would surface as a support ticket rather than a failing test. The comment claiming they
// agree is not evidence; this drives every pair and compares the answers.
//
// # Why it uses raw SQL
//
// Every other invoice test goes through the API, which is right for testing the API. This one
// asks the *database* directly, because the trigger is only reachable that way — an
// application-level test can never distinguish "the trigger refused" from "the application
// refused", and it is the trigger's independent opinion that is under test.
//
// The UPDATE writes a timestamp set consistent with the target status as well as the status,
// so the schema's invoices_state_timestamps CHECK is satisfied on every target. Without that
// the test would pass for the wrong reason: an illegal transition would fail on the timestamp
// constraint rather than on the guard, and a legal one from a stale row would too.
func TestInvoice_TriggerAgreesWithCanTransition(t *testing.T) {
	s := newServer(t)
	if s.db.Owner == nil {
		t.Skip("TEST_MIGRATE_DATABASE_URL is not set: cannot drive raw SQL as the owner")
	}

	all := []string{invoice.StatusDraft, invoice.StatusOpen, invoice.StatusPaid, invoice.StatusVoid}
	ctx := context.Background()

	for _, from := range all {
		for _, to := range all {
			t.Run(from+"_to_"+to, func(t *testing.T) {
				session, tenantID := s.register(uniqueEmail("inv-trig"))
				live := s.driveToState(t, session, tenantID, from)

				if live.Status != from {
					t.Fatalf("setup produced a %s invoice, want %s", live.Status, from)
				}

				tid := uuid.MustParse(tenantID)
				_, err := s.db.Owner.Exec(ctx, `
					UPDATE invoices
					   SET status     = $3,
					       version    = version + 1,
					       issued_at  = CASE WHEN $3 IN ('open','paid') THEN COALESCE(issued_at, now()) ELSE NULL END,
					       paid_at    = CASE WHEN $3 = 'paid' THEN COALESCE(paid_at, now()) ELSE NULL END,
					       voided_at  = CASE WHEN $3 = 'void' THEN now() ELSE NULL END
					 WHERE tenant_id = $1 AND id = $2`,
					tid, uuid.MustParse(live.ID), to)

				triggerAllows := err == nil
				appAllows := invoice.CanTransition(from, to)

				if from == to {
					// The one documented difference, asserted on both sides so neither can
					// drift.
					//
					// A status UPDATE that changes nothing is not a transition, so the
					// trigger has no opinion and permits it — its guard is wrapped in
					// `IF OLD.status IS DISTINCT FROM NEW.status`. CanTransition refuses it,
					// because a transition that changes nothing is a caller bug rather than a
					// state change, and issuing a no-op silently would hide it.
					if !triggerAllows {
						t.Fatalf("the trigger refused a no-op %s update, but a no-op does not "+
							"change state and the trigger's guard skips it; error: %v", from, err)
					}
					if appAllows {
						t.Fatalf("CanTransition permits %s -> %s, so a no-op transition would "+
							"be treated as a real state change", from, to)
					}
					return
				}

				if triggerAllows != appAllows {
					t.Fatalf("the trigger and CanTransition disagree on %s -> %s:\n"+
						"  trigger allows:      %v (error: %v)\n"+
						"  CanTransition allows: %v\n"+
						"Two enforcement points that disagree mean one of them is wrong, and the "+
						"database is the one a migration or a script will hit.",
						from, to, triggerAllows, err, appAllows)
				}

				// The transition really did land, so a passing comparison above is not the
				// result of both sides failing for an unrelated reason.
				if triggerAllows && to != from {
					var stored string
					if qErr := s.db.Owner.QueryRow(ctx,
						`SELECT status FROM invoices WHERE tenant_id = $1 AND id = $2`,
						tid, uuid.MustParse(live.ID)).Scan(&stored); qErr != nil {
						t.Fatalf("read back after an allowed transition: %v", qErr)
					}
					if stored != to {
						t.Fatalf("the trigger permitted %s -> %s but the stored status is %s",
							from, to, stored)
					}
				}
			})
		}
	}
}

// TestInvoice_ResponseHeadersAndContentType are the transport-level checks.
func TestInvoice_ResponseHeadersAndContentType(t *testing.T) {
	s := newServer(t)
	session, tenantID := s.register(uniqueEmail("inv-ct"))

	res := s.do(http.MethodPost, invoiceBase(tenantID), map[string]any{"currency": "USD"}, session.AccessToken)
	if ct := res.header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if res.header.Get("X-Request-Id") == "" {
		t.Fatal("the response carries no X-Request-Id")
	}
	if !bytes.Contains(res.body, []byte(`"data"`)) {
		t.Fatalf("the success body is not wrapped in a data envelope: %s", res.body)
	}
}
