-- 0008_invoices.sql — invoices, their line items, and their lifecycle events.
--
-- # Money is an integer, and the database knows it
--
-- Every amount is a bigint in the currency's smallest unit (cents, paise, satoshi). There is
-- no float, no numeric, and no string amount anywhere in this schema. A float cannot
-- represent 0.10 exactly, so summing line items drifts and a total that is off by a
-- hundredth is a total that does not reconcile — which for a billing system is the one bug
-- that matters. ADR-008 records the decision; this table enforces it.
--
-- # Line totals are computed by the database, not asserted by the client
--
-- line_total_minor = unit_price_minor * quantity is a CHECK constraint, so a line item
-- cannot lie about its own arithmetic. The application computes it too, but only so the
-- error is a clear message rather than a constraint violation — the guarantee comes from
-- here. A client-supplied total would let a caller pay one cent for a thousand-dollar
-- invoice, and no amount of application validation fixes a schema that trusts the client.
--
-- The same reasoning applies to the invoice total: total_minor = subtotal_minor + tax_minor
-- is a CHECK. subtotal_minor is then derived from the items by the application inside the
-- same transaction, and the invariant that it equals their sum is asserted on every write
-- path (see internal/invoice/store.go), because a CHECK cannot aggregate across rows.
--
-- # The state machine is enforced in the database
--
-- draft -> open -> paid, and draft|open -> void. Paid and void are terminal. A BEFORE
-- trigger rejects any other transition, which means an application bug — or a future
-- endpoint somebody adds carelessly — cannot move an invoice backwards and re-open a paid
-- invoice. That is the failure that costs real money and is discovered by an accountant.
--
-- The trigger also freezes the financial fields the moment an invoice leaves draft. Once a
-- customer has seen a number, that number does not change; a correction is a new document
-- (void and reissue), which is what accounting practice actually requires.
--
-- # Cross-tenant references are structurally impossible
--
-- invoice_items and invoice_events reference (invoice_id, tenant_id) as a composite foreign
-- key against invoices (id, tenant_id), the same pattern as projects in 0004. An item
-- therefore cannot be attached to another tenant's invoice even if every application-level
-- check were bypassed: the database has no row to reference.
-- ---------------------------------------------------------------------------

-- Per-tenant invoice numbering.
--
-- A row per tenant, incremented with UPDATE ... RETURNING inside the creating transaction,
-- because that takes a row lock and serialises allocation. SELECT max(number) + 1 would be
-- the obvious alternative and it is wrong: two concurrent creates read the same maximum and
-- both try to insert the same number, so the loser gets a uniqueness violation on a request
-- that should have succeeded.
--
-- Numbers are consumed even if the transaction rolls back, which leaves gaps. Gaps are
-- acceptable — tax authorities care that numbers are unique and monotonic per issuer, not
-- that they are contiguous. Reusing a rolled-back number would be worse: an invoice number
-- is referenced by a document that may already have been emailed.
CREATE TABLE invoice_counters (
    tenant_id   uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    next_number bigint NOT NULL DEFAULT 1 CHECK (next_number > 0)
);

CREATE TABLE invoices (
    id        uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Unique per tenant, not globally: two tenants are different issuers and neither should
    -- be able to observe the other's numbering.
    number text NOT NULL CHECK (number ~ '^INV-[0-9]{6,}$'),

    status text NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'open', 'paid', 'void')),

    -- ISO 4217. Constrained to the shape rather than to a list, because the list changes and
    -- a stale list in a CHECK constraint is a migration nobody enjoys. The application
    -- validates against the currencies it actually supports.
    currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),

    subtotal_minor bigint NOT NULL CHECK (subtotal_minor >= 0),
    tax_minor      bigint NOT NULL DEFAULT 0 CHECK (tax_minor >= 0),
    total_minor    bigint NOT NULL CHECK (total_minor >= 0),

    -- Optimistic concurrency, exactly as on projects: asserted on every transition so two
    -- callers cannot both settle the same invoice.
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),

    -- Attribution: a human or a machine, never both. Same reasoning as projects — a key is
    -- not a user, and recording a machine action against a user column is a lie the audit
    -- trail then repeats.
    created_by     uuid REFERENCES users(id),
    created_by_key uuid REFERENCES api_keys(id),

    issued_at timestamptz,
    paid_at   timestamptz,
    voided_at timestamptz,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (id),

    -- The total is not independently assertable: it is the sum of its parts, and a row where
    -- it is not is corrupt regardless of how it got that way.
    CONSTRAINT invoices_total_is_sum CHECK (total_minor = subtotal_minor + tax_minor),

    -- Exactly one creator, mirroring projects_creator_exactly_one.
    CONSTRAINT invoices_creator_exactly_one CHECK (
        (created_by IS NOT NULL AND created_by_key IS NULL)
        OR (created_by IS NULL AND created_by_key IS NOT NULL)
    ),

    -- A timestamp exists only for a state that has been reached. Without this, a bug could
    -- record paid_at on a draft and a report reading paid_at would count unpaid invoices as
    -- revenue.
    CONSTRAINT invoices_state_timestamps CHECK (
        (status = 'draft' AND issued_at IS NULL AND paid_at IS NULL AND voided_at IS NULL)
        OR (status = 'open' AND issued_at IS NOT NULL AND paid_at IS NULL AND voided_at IS NULL)
        OR (status = 'paid' AND issued_at IS NOT NULL AND paid_at IS NOT NULL AND voided_at IS NULL)
        OR (status = 'void' AND voided_at IS NOT NULL AND paid_at IS NULL)
    ),

    -- Composite key so children can reference the pair. Redundant as a uniqueness claim —
    -- id is already the primary key — but a composite foreign key needs a unique constraint
    -- on exactly the referenced columns.
    UNIQUE (id, tenant_id),

    -- Per-tenant numbering. The partial predicate is not needed here the way it is on
    -- projects: an invoice is never hard-deleted, so there is no archived row to exclude.
    UNIQUE (tenant_id, number)
);

-- The listing query: one tenant's invoices, newest first.
CREATE INDEX invoices_tenant_created_idx ON invoices (tenant_id, created_at DESC, id DESC);

-- "Which invoices are unpaid?" — the question a billing screen asks on every load, and the
-- one that would otherwise scan a tenant's whole history.
CREATE INDEX invoices_tenant_status_idx ON invoices (tenant_id, status, created_at DESC);

CREATE TABLE invoice_items (
    id         uuid NOT NULL,
    invoice_id uuid NOT NULL,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Position within the invoice. Preserved so a re-rendered invoice lists its lines in the
    -- order the issuer chose rather than in whatever order the planner returns.
    position integer NOT NULL CHECK (position >= 0),

    description    text NOT NULL CHECK (length(description) BETWEEN 1 AND 500),
    quantity       integer NOT NULL CHECK (quantity > 0),
    unit_price_minor bigint NOT NULL CHECK (unit_price_minor >= 0),
    line_total_minor bigint NOT NULL CHECK (line_total_minor >= 0),

    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (id),

    -- The arithmetic invariant, enforced here so a line cannot misstate itself.
    CONSTRAINT invoice_items_line_total CHECK (line_total_minor = unit_price_minor * quantity),

    -- Composite foreign key: an item cannot belong to another tenant's invoice. There is
    -- simply no matching row to reference.
    CONSTRAINT invoice_items_invoice_fk
        FOREIGN KEY (invoice_id, tenant_id) REFERENCES invoices (id, tenant_id) ON DELETE CASCADE,

    UNIQUE (invoice_id, position)
);

CREATE INDEX invoice_items_invoice_idx ON invoice_items (invoice_id, position);

CREATE TABLE invoice_events (
    id         uuid NOT NULL,
    invoice_id uuid NOT NULL,
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Nullable for events that happen without a state change (an item added to a draft).
    -- Constrained below to a known set so a typo cannot invent a second spelling.
    kind text NOT NULL CHECK (kind IN ('created', 'item_added', 'item_removed', 'issued', 'paid', 'voided')),

    from_status text CHECK (from_status IS NULL OR from_status IN ('draft', 'open', 'paid', 'void')),
    to_status   text CHECK (to_status IS NULL OR to_status IN ('draft', 'open', 'paid', 'void')),

    actor_id   uuid,
    actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'api_key', 'system')),

    -- The same triple as audit_log: an entry must name its actor consistently, or it
    -- attributes an action to nobody while claiming to be a person.
    CONSTRAINT invoice_events_actor_matches_kind CHECK (
        (actor_kind = 'system' AND actor_id IS NULL)
        OR (actor_kind <> 'system' AND actor_id IS NOT NULL)
    ),

    -- A status change must record both ends, so the event log can be replayed into the
    -- current state and a gap is detectable rather than invisible. Item events are the
    -- exception: adding a line to a draft changes no status.
    CONSTRAINT invoice_events_status_pair CHECK (
        (kind IN ('item_added', 'item_removed')
            AND from_status IS NULL AND to_status IS NULL)
        OR (kind IN ('created', 'issued', 'paid', 'voided')
            AND from_status IS NOT NULL AND to_status IS NOT NULL)
    ),

    at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (id),
    FOREIGN KEY (invoice_id, tenant_id) REFERENCES invoices (id, tenant_id) ON DELETE CASCADE
);

CREATE INDEX invoice_events_invoice_idx ON invoice_events (invoice_id, at, id);

-- ---------------------------------------------------------------------------
-- Append-only guards
--
-- One generic function, applied to every append-only table, rather than a copy per table.
-- The message names the table via TG_TABLE_NAME so an operator reading the error knows which
-- invariant they hit. audit_log's own trigger from 0007 is migrated onto it here: two
-- implementations of "reject the mutation" is two places for the rule to drift.
--
-- 42501 is insufficient_privilege, which is what this is — the operation is not permitted on
-- this table, by anyone, through any path. The distinctive "append-only" wording is what
-- lets the application tell it apart from a row-level-security refusal, since both use that
-- code. internal/audit and internal/invoice both match on it.
-- ---------------------------------------------------------------------------

CREATE FUNCTION append_only_guard() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

-- Move audit_log onto the shared guard.
DROP TRIGGER audit_log_no_update ON audit_log;
DROP TRIGGER audit_log_no_delete ON audit_log;
DROP TRIGGER audit_log_no_truncate ON audit_log;
DROP FUNCTION audit_log_reject_mutation();

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION append_only_guard();

CREATE TRIGGER invoice_events_no_update
    BEFORE UPDATE ON invoice_events
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

CREATE TRIGGER invoice_events_no_delete
    BEFORE DELETE ON invoice_events
    FOR EACH ROW EXECUTE FUNCTION append_only_guard();

-- ---------------------------------------------------------------------------
-- The state machine and the financial freeze
-- ---------------------------------------------------------------------------

CREATE FUNCTION invoice_guard() RETURNS trigger AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        IF NOT (
            (OLD.status = 'draft' AND NEW.status IN ('open', 'void'))
            OR (OLD.status = 'open' AND NEW.status IN ('paid', 'void'))
        ) THEN
            RAISE EXCEPTION 'invoice % cannot move from % to %',
                OLD.number, OLD.status, NEW.status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    -- Once an invoice has been issued, its money is frozen. A correction is a void and a
    -- reissue, not an edit — which is what accounting practice requires and what an auditor
    -- assumes. Nothing here stops a draft from being edited, and nothing should.
    IF OLD.status <> 'draft' THEN
        IF NEW.number            IS DISTINCT FROM OLD.number
        OR NEW.currency          IS DISTINCT FROM OLD.currency
        OR NEW.subtotal_minor    IS DISTINCT FROM OLD.subtotal_minor
        OR NEW.tax_minor         IS DISTINCT FROM OLD.tax_minor
        OR NEW.total_minor       IS DISTINCT FROM OLD.total_minor
        OR NEW.created_by        IS DISTINCT FROM OLD.created_by
        OR NEW.created_by_key    IS DISTINCT FROM OLD.created_by_key THEN
            RAISE EXCEPTION 'invoice % is %, so its financial fields are immutable; void it and issue a replacement',
                OLD.number, OLD.status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER invoices_guard
    BEFORE UPDATE ON invoices
    FOR EACH ROW EXECUTE FUNCTION invoice_guard();

CREATE FUNCTION invoice_items_guard() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
-- A pinned search_path is required on a SECURITY DEFINER function: without it, a caller could
-- influence which schema an unqualified name resolves against.
SET search_path = public, pg_temp
AS $$
DECLARE
    parent_status text;
    parent_id     uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        parent_id := OLD.invoice_id;
    ELSE
        parent_id := NEW.invoice_id;
    END IF;

    SELECT status INTO parent_status FROM invoices WHERE id = parent_id;

    -- The parent is gone. Let the foreign key say so; this trigger has no opinion.
    IF parent_status IS NULL THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Defined as SECURITY DEFINER for this line and no other reason: it reads the parent
    -- regardless of the caller's row-level-security context. Under the default
    -- (SECURITY INVOKER) the SELECT would be subject to the tenant policy, so a caller with
    -- no tenant GUC set would read nothing, see a null status, and be allowed to edit the
    -- items of a settled invoice. That is the hole this closes, and it is invisible without
    -- the definer clause.
    --
    -- It does not widen what a caller can write: the INSERT itself is still evaluated
    -- against invoice_items' own policy under the caller's identity, and the composite
    -- foreign key means the parent must be in the same tenant.
    IF parent_status <> 'draft' THEN
        RAISE EXCEPTION 'items of invoice % cannot be modified once it is %',
            parent_id, parent_status
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

CREATE TRIGGER invoice_items_guard
    BEFORE INSERT OR UPDATE OR DELETE ON invoice_items
    FOR EACH ROW EXECUTE FUNCTION invoice_items_guard();

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- The single-predicate shape used everywhere else: every one of these tables is reached only
-- through a resolved tenant scope, so app.current_tenant_id is always set by the time a query
-- runs. The WITH CHECK arm is what stops a scoped request from writing into another tenant.
-- ---------------------------------------------------------------------------

ALTER TABLE invoice_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_counters FORCE  ROW LEVEL SECURITY;
CREATE POLICY invoice_counters_tenant_isolation ON invoice_counters
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE  ROW LEVEL SECURITY;
CREATE POLICY invoices_tenant_isolation ON invoices
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE invoice_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_items FORCE  ROW LEVEL SECURITY;
CREATE POLICY invoice_items_tenant_isolation ON invoice_items
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE invoice_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoice_events FORCE  ROW LEVEL SECURITY;
CREATE POLICY invoice_events_tenant_isolation ON invoice_events
    FOR ALL
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- app_rw receives DML on these tables through the ALTER DEFAULT PRIVILEGES set in 0001, so no
-- explicit GRANT is needed. That default is load-bearing for every migration after it.
