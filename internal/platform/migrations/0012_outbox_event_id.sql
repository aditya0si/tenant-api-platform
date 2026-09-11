-- 0012_outbox_event_id.sql — give the outbox row the event id a receiver deduplicates on.
--
-- Forward-only (ADR-011): 0010 is applied and checksummed, so this is a new file.
--
-- # Why a column rather than reading it out of the payload
--
-- The id is inside the JSON body (see Envelope), so delivery *could* unmarshal the payload to set
-- the Webhook-Id header. That is rejected because the id is not incidental content: a receiver
-- deduplicates on it, and the whole at-least-once contract depends on the header and the body
-- naming the same event. Deriving a first-class identity field from a JSON blob means a future
-- change to the envelope shape silently changes the identity, and the failure appears as duplicated
-- processing at a customer's end rather than as an error here.
--
-- A column also makes "was event X delivered to endpoint Y" answerable by index instead of by
-- scanning every payload.
--
-- # Why the default is deliberately absent
--
-- The UPDATE backfills existing rows; the ALTER then makes the column NOT NULL with no DEFAULT.
-- A DEFAULT gen_random_uuid() would have been shorter and is wrong: an insert that forgot to supply
-- the id would then get a random one, different from the id in its own payload — a divergence that
-- nothing checks and that breaks receiver deduplication silently. Without a default, forgetting it
-- is a constraint violation at the insert.
-- ---------------------------------------------------------------------------

ALTER TABLE webhook_outbox ADD COLUMN event_id uuid;

-- Backfill from the payload, which is where the id has been living. `payload->>'id'` is text; the
-- cast is safe because Enqueue only ever stores an Envelope, but a malformed row would fail the
-- migration loudly rather than leaving a null that the NOT NULL below would then reject with a
-- less useful message.
UPDATE webhook_outbox SET event_id = (payload->>'id')::uuid WHERE event_id IS NULL;

ALTER TABLE webhook_outbox ALTER COLUMN event_id SET NOT NULL;

-- The lookup an operator makes during an incident: "the receiver says they saw event X twice" or
-- "did X ever reach them".
CREATE INDEX webhook_outbox_event_idx ON webhook_outbox (tenant_id, event_id);
