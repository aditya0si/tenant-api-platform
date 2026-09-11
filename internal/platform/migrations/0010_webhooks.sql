-- 0010_webhooks.sql — webhook endpoints and the transactional outbox.
--
-- # The outbox is the point
--
-- A webhook must not be sent from the request handler, and it must not be enqueued after the
-- transaction that produced it commits. Both of those lose events: the first makes a slow
-- receiver into a slow API and a failed receiver into a lost event, and the second has a
-- window between commit and enqueue where a crash drops the notification forever.
--
-- So the row is written *inside* the transaction that changes the data, and a separate worker
-- reads it afterwards. The event and the effect commit together or neither does. This is the
-- same argument as the audit trail (ADR-006), and it is the reason the outbox rather than a
-- message broker was chosen (ADR-001): a broker cannot participate in a Postgres transaction,
-- so it necessarily reintroduces that window.
--
-- # The payload is frozen at enqueue time
--
-- payload jsonb holds the event as it was when the event happened, not a pointer to the row it
-- describes. A delivery that rebuilt the payload from current state would send the invoice's
-- *new* contents under the old event's name — a receiver would be told "invoice.paid" and be
-- handed a body reflecting a later edit. Frozen payloads also make replay meaningful: the
-- stored event is exactly what would have been sent.
--
-- # At-least-once, and why that is the honest claim
--
-- A worker that crashes after the receiver processed a delivery but before recording it will
-- redeliver. Exactly-once delivery over a network is not achievable, so the design delivers at
-- least once and gives the receiver what it needs to deduplicate: a stable event id in the
-- payload and in a header. Claiming exactly-once would be a lie the receiver discovers.
-- ---------------------------------------------------------------------------

CREATE TABLE webhook_endpoints (
    id        uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- http is permitted rather than required. It is a real downgrade and the documentation says
    -- so, but refusing it outright would break receivers on private networks that have no
    -- certificate — and the request body is not the only protection: the signature is what
    -- authenticates the sender. A production deployment can restrict the scheme at registration
    -- if it wants to.
    url text NOT NULL CHECK (url ~ '^https?://' AND length(url) <= 2048),

    -- The signing secret. Recoverable by necessity: HMAC requires the key, so it cannot be
    -- hashed the way an API key is. That makes this column the one place in the schema holding
    -- a reversibly-stored secret, and it is why the API never returns it after creation — same
    -- shape as an API key's one-time display. The worker reads it to sign; nothing else needs it.
    secret text NOT NULL CHECK (length(secret) BETWEEN 32 AND 128),

    -- Which events this endpoint wants. An array rather than a join table because the set is
    -- small, read whole on every delivery, and never queried by membership across rows.
    events text[] NOT NULL CHECK (array_length(events, 1) BETWEEN 1 AND 32),

    -- A description for an operator reading a list, not for the receiver.
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),

    -- Deactivated rather than deleted, so its outbox history survives: a row referencing a
    -- deleted endpoint would cascade its deliveries away, and "we sent that and it failed" is
    -- exactly the fact an operator needs during an incident.
    active boolean NOT NULL DEFAULT true,

    created_by     uuid REFERENCES users(id),
    created_by_key uuid REFERENCES api_keys(id),

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (id),

    -- Composite key so the outbox can reference the pair, making a cross-tenant delivery
    -- structurally impossible rather than a rule the application remembers.
    UNIQUE (id, tenant_id),

    CONSTRAINT webhook_endpoints_creator_exactly_one CHECK (
        (created_by IS NOT NULL AND created_by_key IS NULL)
        OR (created_by IS NULL AND created_by_key IS NOT NULL)
    )
);

CREATE INDEX webhook_endpoints_tenant_idx ON webhook_endpoints (tenant_id, created_at DESC);

CREATE TABLE webhook_outbox (
    id          uuid NOT NULL,
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL,

    -- The event name, e.g. invoice.paid. Constrained to a dotted shape for the same reason
    -- audit actions are: a typo would introduce a second spelling of one event and make the
    -- stream unfilterable.
    event text NOT NULL CHECK (event ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),

    -- The frozen payload. See the header.
    payload jsonb NOT NULL,

    -- W3C trace context, so a delivery can be correlated with the request that caused it.
    -- Nullable because a background process may enqueue without an inbound trace.
    traceparent text,

    -- pending     — due for delivery (subject to next_at)
    -- delivering  — leased by a worker right now
    -- delivered   — acknowledged by the receiver
    -- dead        — attempts exhausted; the DLQ. Replayable.
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivering', 'delivered', 'dead')),

    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),

    -- When this row becomes eligible. Backoff moves it forward; the index below is on this.
    next_at timestamptz NOT NULL DEFAULT now(),

    -- The lease. A worker that dies mid-delivery leaves state = 'delivering' and a lease that
    -- stops being valid, at which point the row is claimable again. Without this a crash would
    -- strand the row in 'delivering' forever and the event would silently never arrive.
    --
    -- The lease must exceed the delivery timeout, or a slow-but-alive worker gets its row
    -- reclaimed underneath it and the receiver gets the delivery twice.
    lease_expires_at timestamptz,

    -- The most recent failure, kept for the DLQ view and for replay triage. The full history is
    -- the log stream's business; one row plus the attempt count is what an operator needs.
    last_error  text,
    last_status integer CHECK (last_status IS NULL OR (last_status BETWEEN 100 AND 599)),

    delivered_at timestamptz,

    -- How many times a human re-queued this row. Distinct from attempts so replay does not
    -- destroy the delivery history, and so a row that needed five replays is visible.
    replays integer NOT NULL DEFAULT 0 CHECK (replays >= 0),

    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (id),

    CONSTRAINT webhook_outbox_endpoint_fk
        FOREIGN KEY (endpoint_id, tenant_id)
        REFERENCES webhook_endpoints (id, tenant_id) ON DELETE CASCADE,

    -- A delivered row carries its timestamp, so "when did this arrive" is answerable without
    -- consulting the receiver. The reverse does not hold: a row with delivered_at but not the
    -- delivered state would be a bookkeeping bug.
    CONSTRAINT webhook_outbox_delivered_has_time CHECK (
        (state = 'delivered') = (delivered_at IS NOT NULL)
    ),

    -- A delivery is only ever leased while it is being delivered, and only the dead state is
    -- terminal-with-error. Without this a bug could leave a lease on a pending row, which would
    -- hold it out of the queue until the lease expired for no reason.
    CONSTRAINT webhook_outbox_lease_only_while_delivering CHECK (
        lease_expires_at IS NULL OR state = 'delivering'
    )
);

-- The worker's queue scan: "what is due?" Without the partial predicate this index would carry
-- every delivered row forever, and the scan would degrade as the table grows — which is the
-- one thing it must not do, since it runs on a timer.
CREATE INDEX webhook_outbox_due_idx ON webhook_outbox (state, next_at)
    WHERE state IN ('pending', 'delivering');

-- The per-endpoint history an operator reads when a receiver says "we missed one".
CREATE INDEX webhook_outbox_endpoint_idx ON webhook_outbox (endpoint_id, created_at DESC);

-- The DLQ view.
CREATE INDEX webhook_outbox_dead_idx ON webhook_outbox (tenant_id, created_at DESC)
    WHERE state = 'dead';

-- ---------------------------------------------------------------------------
-- Why there is no state-machine trigger here
--
-- invoices_guard exists because an invoice is acted on by two different parties — a client
-- through the API and an operator with SQL — and a future endpoint would not consult the Go
-- function. The outbox has exactly one writer, the worker, and every one of its transitions is
-- already a conditional UPDATE naming both the expected state and (for a lease) the lease
-- holder:
--
--   pending -> delivering   WHERE state = 'pending'  OR (state='delivering' AND lease expired)
--   delivering -> delivered WHERE state = 'delivering' AND lease_expires_at > now()
--   delivering -> pending   WHERE state = 'delivering' AND lease_expires_at > now()
--   delivering -> dead      WHERE state = 'delivering' AND lease_expires_at > now()
--   dead -> pending         WHERE state = 'dead'                      (replay)
--
-- The predicate is the guard, and it is testable without a database trigger. A trigger on top
-- would be a second place to keep in step for no additional protection — the reasoning that
-- makes two enforcement points worth it for invoices does not apply to a single-writer queue.
--
-- The CHECK constraints above still hold the invariants a bug could violate regardless of which
-- transition produced it.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- The same single-predicate shape as every other tenant table. webhook_outbox is reached by the
-- API only for reads (the delivery history) and by the worker, which sets the tenant GUC per
-- claimed row — so a worker bug cannot deliver one tenant's event to another's endpoint, and the
-- composite foreign key means it could not even reference one.
-- ---------------------------------------------------------------------------

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE  ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_tenant_isolation ON webhook_endpoints
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE webhook_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_outbox FORCE  ROW LEVEL SECURITY;
CREATE POLICY webhook_outbox_tenant_isolation ON webhook_outbox
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- app_rw receives DML through the ALTER DEFAULT PRIVILEGES set in 0001, so no explicit GRANT is
-- needed. That default is load-bearing for every migration after it.
