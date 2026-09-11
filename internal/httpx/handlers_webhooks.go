package httpx

import (
	"errors"
	"net/http"
	"strings"

	"github.com/aditya0si/tenant-api-platform/internal/platform/apperr"
	"github.com/aditya0si/tenant-api-platform/internal/platform/cursor"
	"github.com/aditya0si/tenant-api-platform/internal/platform/httperr"
	"github.com/aditya0si/tenant-api-platform/internal/webhook"
)

// webhookEndpointResponse is a registered receiver on the wire.
//
// The signing secret is deliberately absent, and its absence is the whole shape of this API: the
// secret is shown once, at creation, and never again. A list endpoint that returned it would put
// every tenant's signing key into every response, every log, and every support screenshot.
type webhookEndpointResponse struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	Description string   `json:"description"`
	Active      bool     `json:"active"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func webhookEndpointFrom(e webhook.Endpoint) webhookEndpointResponse {
	return webhookEndpointResponse{
		ID:          e.ID.String(),
		URL:         e.URL,
		Events:      e.Events,
		Description: e.Description,
		Active:      e.Active,
		CreatedAt:   timestamp(e.CreatedAt),
		UpdatedAt:   timestamp(e.UpdatedAt),
	}
}

// webhookDeliveryResponse is one queued event on the wire.
//
// The payload is not included. A delivery listing is for an operator triaging failures, and the
// bodies of a page of events are a large response for data they are not reading — last_error and
// last_status are what the screen shows.
type webhookDeliveryResponse struct {
	ID          string `json:"id"`
	EndpointID  string `json:"endpoint_id"`
	Event       string `json:"event"`
	State       string `json:"state"`
	Attempts    int    `json:"attempts"`
	Replays     int    `json:"replays"`
	NextAt      string `json:"next_at"`
	LastError   string `json:"last_error,omitempty"`
	LastStatus  int    `json:"last_status,omitempty"`
	DeliveredAt string `json:"delivered_at,omitempty"`
	CreatedAt   string `json:"created_at"`
}

func webhookDeliveryFrom(d webhook.Delivery) webhookDeliveryResponse {
	out := webhookDeliveryResponse{
		ID:         d.ID.String(),
		EndpointID: d.EndpointID.String(),
		Event:      d.Event,
		State:      d.State,
		Attempts:   d.Attempts,
		Replays:    d.Replays,
		NextAt:     timestamp(d.NextAt),
		LastError:  d.LastError,
		LastStatus: d.LastStatus,
		CreatedAt:  timestamp(d.CreatedAt),
	}
	if d.DeliveredAt != nil {
		out.DeliveredAt = timestamp(*d.DeliveredAt)
	}
	return out
}

// requireGuard refuses registration when no SSRF guard was configured.
//
// # Why this fails closed rather than skipping
//
// A nil guard means a URL could be registered with nothing validating it, and the delivery that
// follows would be a request to whatever address the tenant named — including 169.254.169.254,
// which returns cloud credentials on most instances. Silently skipping the check would register an
// endpoint that looks correct and is an exfiltration primitive.
//
// The alternative to refusing is panicking, which turns a configuration mistake into a crash. A
// 500 with a logged cause is the response that gets fixed.
func (d Deps) requireGuard(w http.ResponseWriter, r *http.Request) bool {
	if d.SSRF == nil {
		d.Log.Error("webhook registration attempted with no SSRF guard configured; refusing so that " +
			"an unvalidated URL cannot be registered")
		httperr.Write(w, r, http.StatusInternalServerError, "internal_error",
			"an internal error occurred")
		return false
	}
	return true
}

// handleCreateWebhookEndpoint registers a receiver.
//
// # The secret is returned exactly once
//
// It is in this response and in no other. A tenant that loses it registers a new endpoint, which
// is the same one-time-display contract as an API key — and for the same reason: a secret that can
// be read back is one that leaks from a list response, a log line, or a screenshot of a debugging
// session.
//
// # The URL is validated here, not in the store
//
// Resolution needs DNS and therefore a context, and the store is deliberately free of the network
// so its tests need none. The check happens before the insert, so an unreachable or non-public
// host is refused at registration rather than becoming a delivery that fails forever.
func (d Deps) handleCreateWebhookEndpoint(w http.ResponseWriter, r *http.Request) {
	if !d.requireGuard(w, r) {
		return
	}
	auth := authorizedFrom(r)

	var req struct {
		URL         string   `json:"url"`
		Events      []string `json:"events"`
		Description string   `json:"description"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	validated, err := webhook.ValidateCreate(webhook.CreateInput{
		URL:         req.URL,
		Events:      req.Events,
		Description: req.Description,
	})
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	// Registration-time resolution, so a typo or a blocked target is refused while the tenant is
	// looking at the form. Delivery re-validates regardless — a name can be repointed afterwards,
	// and the registration check is an early warning rather than a standing permission.
	if err := d.SSRF.ValidateEndpointURL(validated.URL); err != nil {
		// A refused destination is the tenant's input, not a failure of this service. Passed
		// unclassified it becomes a 500, which tells a client to retry a request that can never
		// succeed — and it hides the reason, which is the only part the tenant can act on. The
		// guard's message names the address and why it was refused, so it is passed through with
		// its package prefix trimmed.
		httperr.Fail(w, r, d.Log, apperr.Invalid("url", strings.TrimPrefix(err.Error(), "ssrf: ")))
		return
	}

	created, secret, err := d.Webhooks.CreateEndpoint(r.Context(), auth, validated)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	// Location is set explicitly because httperr.Created does not know the resource's canonical
	// path — and a wrong Location is worse than none.
	w.Header().Set("Location", "/v1/tenants/"+auth.Scope().ID().String()+"/webhooks/"+created.ID.String())
	httperr.Created(w, struct {
		webhookEndpointResponse
		// Secret is shown once. The field name says so rather than relying on documentation the
		// client may not read.
		Secret string `json:"secret"`
	}{
		webhookEndpointResponse: webhookEndpointFrom(created),
		Secret:                  secret,
	})
}

// handleListWebhookEndpoints returns one page of registered receivers.
func (d Deps) handleListWebhookEndpoints(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	limit, rawCursor, err := pageParams(r)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	binding := webhook.EndpointBinding(auth)
	after, ok := d.decodeCursor(w, r, binding, rawCursor)
	if !ok {
		return
	}

	endpoints, next, err := d.Webhooks.ListEndpoints(r.Context(), auth, after, limit)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]webhookEndpointResponse, 0, len(endpoints))
	for _, e := range endpoints {
		items = append(items, webhookEndpointFrom(e))
	}

	var nextToken string
	if next != nil {
		nextToken = d.encodeCursor(r, binding, *next)
	}
	httperr.Page(w, items, nextToken)
}

// handleGetWebhookEndpoint returns one receiver.
func (d Deps) handleGetWebhookEndpoint(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "endpointID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	e, err := d.Webhooks.GetEndpoint(r.Context(), auth, id)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, webhookEndpointFrom(e))
}

// handleUpdateWebhookEndpoint changes a subscription, description, or active flag.
func (d Deps) handleUpdateWebhookEndpoint(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	id, err := parseUUID(chiURLParam(r, "endpointID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	var req struct {
		// Pointers so an omitted field is distinguishable from one set to empty, which is the
		// same PATCH semantic as everywhere else in this API: {"events": [...]} replaces the
		// subscription, and omitting it leaves it alone.
		Events      *[]string `json:"events,omitempty"`
		Description *string   `json:"description,omitempty"`
		Active      *bool     `json:"active,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	if req.Events == nil && req.Description == nil && req.Active == nil {
		httperr.Fail(w, r, d.Log, apperr.Invalid("body", "supply at least one field to update"))
		return
	}

	updated, err := d.Webhooks.UpdateEndpoint(r.Context(), auth, id, webhook.UpdateInput{
		Events:      req.Events,
		Description: req.Description,
		Active:      req.Active,
	})
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, webhookEndpointFrom(updated))
}

// handleListWebhookDeliveries returns one page of an endpoint's delivery history.
//
// # Why deliveries live under an endpoint
//
// "Why did this receiver not get event X" is the question, and it is always asked about one
// endpoint. Scoping the route to the endpoint means the answer needs no filter the caller has to
// remember to apply — and it keeps a tenant with one noisy receiver from drowning a listing that
// covers all of them.
func (d Deps) handleListWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	endpointID, err := parseUUID(chiURLParam(r, "endpointID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	// The endpoint must exist in this tenant before its history is listed, so a wrong id is a
	// 404 rather than an empty page — an empty page for a nonexistent endpoint reads as "no
	// deliveries yet", which is a different and misleading answer.
	if _, err := d.Webhooks.GetEndpoint(r.Context(), auth, endpointID); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	limit, rawCursor, err := pageParams(r)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	filter := webhook.ListFilter{
		EndpointID: endpointID.String(),
		State:      r.URL.Query().Get("state"),
	}
	if _, err := webhook.NormalizeState(filter.State); err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	binding := webhook.DeliveryBinding(auth, filter)
	after, ok := d.decodeCursor(w, r, binding, rawCursor)
	if !ok {
		return
	}

	page, err := d.Webhooks.List(r.Context(), auth, filter, after, limit)
	if err != nil {
		httperr.Fail(w, r, d.Log, err)
		return
	}

	items := make([]webhookDeliveryResponse, 0, len(page.Deliveries))
	for _, del := range page.Deliveries {
		items = append(items, webhookDeliveryFrom(del))
	}

	var nextToken string
	if page.Next != nil {
		nextToken = d.encodeCursor(r, binding, *page.Next)
	}
	httperr.Page(w, items, nextToken)
}

// handleReplayWebhookDelivery re-queues a dead delivery.
//
// It is a guarded write, so it inherits authorization-then-idempotency. That matters here more
// than it looks: a replay is a command to re-send an event a receiver has already seen, and a
// client that retries the request because the response was lost would otherwise re-queue it
// again — resetting the attempt count each time and making the delivery history unreadable.
func (d Deps) handleReplayWebhookDelivery(w http.ResponseWriter, r *http.Request) {
	auth := authorizedFrom(r)

	deliveryID, err := parseUUID(chiURLParam(r, "deliveryID"))
	if err != nil {
		httperr.Fail(w, r, d.Log, apperr.ErrNotFound)
		return
	}

	replayed, err := d.Webhooks.Replay(r.Context(), auth, deliveryID)
	if err != nil {
		// A delivery that exists but is not dead is a 409, not a 404: the id is right and the
		// state is wrong, which is a different client action from "check your id".
		if errors.Is(err, webhook.ErrNotDead) {
			httperr.Fail(w, r, d.Log, apperr.ErrConflict)
			return
		}
		httperr.Fail(w, r, d.Log, err)
		return
	}
	httperr.OK(w, webhookDeliveryFrom(replayed))
}

// decodeCursor turns a pagination token into a position, writing the error response itself.
//
// It returns ok=false when it has already answered, so a handler is three lines instead of ten and
// the binding-mismatch message — which is the one that actually helps a client — cannot drift
// between the listings.
func (d Deps) decodeCursor(w http.ResponseWriter, r *http.Request, binding cursor.Binding, raw string) (*cursor.Position, bool) {
	if raw == "" {
		return nil, true
	}
	pos, err := d.Cursors.Decode(binding, raw)
	if err != nil {
		if errors.Is(err, cursor.ErrBinding) {
			httperr.Fail(w, r, d.Log, apperr.Invalid("cursor",
				"this cursor belongs to a different query; start from the first page"))
			return nil, false
		}
		httperr.Fail(w, r, d.Log, apperr.Invalid("cursor", "the cursor is not valid"))
		return nil, false
	}
	return &pos, true
}

// encodeCursor mints the next-page token, logging rather than failing on an encode error.
//
// An encode failure means the codec is misconfigured, not that the request was bad, so the page
// itself is valid and is returned without a cursor. Discarding data the client can use because a
// token could not be minted would turn a configuration fault into a failed request.
func (d Deps) encodeCursor(r *http.Request, binding cursor.Binding, pos cursor.Position) string {
	token, err := d.Cursors.Encode(binding, pos)
	if err != nil {
		d.Log.Error("failed to encode a pagination cursor", "err", err, "path", r.URL.Path)
		return ""
	}
	return token
}
