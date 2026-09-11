-- 0007_audit_log.sql — the append-only audit trail.
--
-- # Why a table rather than log lines
--
-- Request logs answer "what did this process do"; an audit trail answers "who changed this
-- record, when, and from what". The second question gets asked months later, about one
-- resource, by someone who was not there — and it has to be answerable exactly, not by
-- grepping text and hoping the line was not rotated away. The log stream is sampled, mutable
-- by whoever owns the log platform, and has no schema; this does not.
--
-- # Append-only, enforced rather than promised
--
-- A trigger rejects UPDATE and DELETE outright. That is stronger than a privilege grant and
-- stronger than RLS:
--
--   * Privileges stop the application role, but nothing stops a later migration or an
--     operator with owner credentials.
--   * RLS makes other tenants' rows invisible, which for UPDATE and DELETE means the
--     statement silently affects zero rows rather than failing. Silence is the wrong
--     response to an attempt to rewrite history.
--
-- A BEFORE trigger fires on whatever rows are visible, so a scoped UPDATE or DELETE fails
-- loudly instead of no-opping. This is worth stating precisely because it is easy to get
-- wrong: RLS filters first, so without the trigger a delete would report success while
-- changing nothing, and the caller would believe the trail had been pruned.
--
-- The honest limit: an owner can disable the trigger or drop the table. No SQL-level control
-- survives the owner, which is why owner credentials live in a separate binary (cmd/migrate)
-- and never in the service. The trigger defends against every path the application could
-- take, including one added carelessly later.
--
-- # Tenant-keyed, like every other table
--
-- The same single-predicate policy as projects: this table is reached only through a resolved
-- tenant scope, so app.current_tenant_id is always set by the time a query runs. The WITH
-- CHECK arm matters as much as the USING arm — without it a scoped request could write an
-- entry attributed to another tenant, and the row would merely be invisible afterwards.
--
-- # What is deliberately not here
--
-- Pre-tenant events — a failed login for an address that does not exist, a refresh-token
-- reuse detected before any tenant is resolved — have no tenant to key on. They are recorded
-- to the log stream and to metrics instead, and the gap is stated in ADR-006 rather than
-- papered over with a nullable tenant column that would quietly weaken the policy for every
-- other row.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id uuid PRIMARY KEY,

    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Who acted. Nullable only for 'system', which is how a background worker's own
    -- maintenance actions are recorded. actor_id carries either a user id or an API key id,
    -- disambiguated by actor_kind — the same reasoning as projects.created_by/created_by_key,
    -- because "which key did this" is the only useful answer for an unattended action.
    actor_id   uuid,
    actor_kind text NOT NULL CHECK (actor_kind IN ('user', 'api_key', 'system')),

    -- A dotted verb, e.g. project.create. Constrained to a sane shape so a typo cannot
    -- introduce a second spelling of the same action, which would make the trail unqueryable
    -- by the time anyone needs it.
    action   text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),

    -- What was acted upon: a resource kind and, when the action names one row, its id.
    resource    text NOT NULL CHECK (resource ~ '^[a-z][a-z0-9_]*$'),
    resource_id uuid,

    -- The state transition, as it was visible to the application. Both are nullable: a create
    -- has no before, a hard delete has no after, and an archival has both.
    --
    -- These hold the fields the API exposes, not the raw rows. A trail that stored a password
    -- hash or a session token would convert an append-only table — which by design cannot be
    -- pruned — into a permanent secret store.
    before jsonb,
    after  jsonb,

    -- Correlates this entry with the log lines and the response that produced it, which is
    -- what makes "show me everything from that request" answerable.
    request_id text,

    at timestamptz NOT NULL DEFAULT now(),

    -- An entry must name its actor consistently: 'system' has no id, everything else must
    -- have one. Without this, a bug could write actor_kind='user' with a null id and the
    -- entry would be attributed to nobody while claiming to be a person.
    CONSTRAINT audit_log_actor_matches_kind CHECK (
        (actor_kind = 'system' AND actor_id IS NULL)
        OR (actor_kind <> 'system' AND actor_id IS NOT NULL)
    )
);

-- The listing query: one tenant's recent entries, newest first. Matches the index the design
-- specified, and it is the access pattern the RLS policy is built around.
CREATE INDEX audit_log_tenant_at_idx ON audit_log (tenant_id, at DESC);

-- "What happened to this record?" — the question that actually gets asked. Without this it is
-- a sequential scan of one tenant's entire history, filtered in the application.
CREATE INDEX audit_log_resource_idx ON audit_log (tenant_id, resource, resource_id, at DESC);

-- ---------------------------------------------------------------------------
-- Append-only enforcement
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_log_reject_mutation() RETURNS trigger AS $$
BEGIN
    -- 42501 is insufficient_privilege, which is exactly what this is: the operation is not
    -- permitted on this table, by anyone, through any path. The distinctive message is what
    -- lets the application distinguish it from an RLS refusal, since both use that code.
    RAISE EXCEPTION 'audit_log is append-only: % is not permitted', TG_OP
        USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_reject_mutation();

-- Statement-level, because TRUNCATE has no rows to iterate. The application role has no
-- TRUNCATE grant, so this closes the path an operator would otherwise reach for.
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_reject_mutation();

-- ---------------------------------------------------------------------------
-- Row-level security
-- ---------------------------------------------------------------------------

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE  ROW LEVEL SECURITY;

CREATE POLICY audit_log_tenant_isolation ON audit_log
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- app_rw receives DML on this table through the ALTER DEFAULT PRIVILEGES set in 0001, so no
-- explicit GRANT is needed. That default is load-bearing for every migration after it, and
-- the suite asserts the application role can actually use a table it was just given.
