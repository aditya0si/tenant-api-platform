-- 0009_invoice_event_created.sql — correct the status-pair constraint for 'created'.
--
-- Forward-only (ADR-011): 0008 is applied and its checksum recorded, so this is a new file
-- rather than an edit.
--
-- # What was wrong
--
-- 0008 required both from_status and to_status to be non-null for the events that change
-- state ('created', 'issued', 'paid', 'voided'). That is right for the three transitions and
-- wrong for the fourth: an invoice that has just come into existence has no previous state,
-- so the only way to satisfy the constraint would be to record from_status = 'draft' — a lie
-- written into an append-only event log whose entire purpose is to be replayable and
-- truthful.
--
-- A constraint that forces a false value is worse than no constraint, because it produces
-- clean-looking data that is wrong. The corrected form states each case exactly:
--
--   created              from NULL,  to 'draft'
--   issued/paid/voided   from set,   to set
--   item_added/removed   both NULL (no status change)
--
-- The replacement is not a loosening: every legal shape is still pinned, and 'created' is
-- still required to land in 'draft' rather than anywhere.
-- ---------------------------------------------------------------------------

ALTER TABLE invoice_events DROP CONSTRAINT invoice_events_status_pair;

ALTER TABLE invoice_events ADD CONSTRAINT invoice_events_status_pair CHECK (
    (kind = 'created' AND from_status IS NULL AND to_status = 'draft')
    OR (kind IN ('issued', 'paid', 'voided')
        AND from_status IS NOT NULL AND to_status IS NOT NULL)
    OR (kind IN ('item_added', 'item_removed')
        AND from_status IS NULL AND to_status IS NULL)
);

-- A transition must actually change state. Without this, 'issued' could record
-- open -> open, and the event log would claim a change that did not happen — the same
-- defect the audit trail's archiving rule avoids by recording only real transitions.
-- 'created' is exempt: it has no prior state to differ from.
ALTER TABLE invoice_events ADD CONSTRAINT invoice_events_transition_changes_state CHECK (
    kind = 'created' OR kind IN ('item_added', 'item_removed') OR from_status <> to_status
);
