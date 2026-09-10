-- 0005_project_attribution.sql — attribute a project to whoever created it, human or
-- machine.
--
-- Forward-only (ADR-011): 0004 is applied and its checksum is recorded, so this is a
-- new file rather than an edit.
--
-- # The problem this fixes
--
-- 0004 declared projects.created_by NOT NULL REFERENCES users(id). That is correct for
-- a human creator and impossible for a machine one: an API key is not a user, so a
-- write-scoped key creating a project would have to insert a NULL — which the NOT NULL
-- constraint rejects, turning a legitimate request into a foreign-key failure that
-- surfaces as a 500.
--
-- The permission model deliberately allows a key to hold project:write, so the schema
-- has to be able to represent the result. "Which key did this" is also the only useful
-- attribution for an unattended action: recording it as a user would be a lie the audit
-- trail then repeats.

-- A human creator is now optional, because the machine column can carry the attribution
-- instead.
ALTER TABLE projects ALTER COLUMN created_by DROP NOT NULL;

-- The machine creator. RESTRICT rather than CASCADE, for the same reason as created_by:
-- a key that authored a project must not be deletable out from under it, or the audit
-- trail would point at nothing. Keys are revoked, not deleted.
ALTER TABLE projects
    ADD COLUMN created_by_key uuid REFERENCES api_keys(id) ON DELETE RESTRICT;

-- Exactly one attribution, never both and never neither.
--
-- This is a CHECK rather than application logic because the failure it prevents is
-- silent: a row with both columns set would have two answers to "who created this", and
-- a row with neither would have none. Both are states that only become visible during
-- an incident review, which is the worst time to discover them.
ALTER TABLE projects
    ADD CONSTRAINT projects_creator_exactly_one CHECK (
        (created_by IS NOT NULL AND created_by_key IS NULL)
        OR (created_by IS NULL AND created_by_key IS NOT NULL)
    );

-- Existing rows predate keys, so every one of them has created_by set and
-- created_by_key NULL: the CHECK is satisfied by construction, which is why this
-- migration needs no backfill.
