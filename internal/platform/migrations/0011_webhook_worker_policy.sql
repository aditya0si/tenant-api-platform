-- 0011_webhook_worker_policy.sql — let the delivery worker see across tenants, and nothing else
-- see more than its own.
--
-- Forward-only (ADR-011): 0010 is applied and checksummed, so this is a new file.
--
-- # The problem
--
-- The worker must find every due delivery, which means reading webhook_outbox rows belonging to
-- every tenant. Row-level security forbids exactly that: the policy in 0010 admits only rows
-- whose tenant matches app.current_tenant_id, and the worker has no single tenant to declare.
--
-- # Why not owner credentials
--
-- The obvious fix is to run the worker on the role that bypasses RLS, the way cmd/migrate does.
-- It is rejected because it discards the policy for the component that handles tenant-supplied
-- URLs and holds tenant signing secrets. A bug in the worker — a mis-joined query, a delivery
-- attributed to the wrong row — would then be able to read or write any tenant's rows with
-- nothing to stop it. The migration binary accepts that exposure because it runs for seconds
-- under an operator's hand; a long-lived worker does not.
--
-- # What this does instead
--
-- Adds a second, permissive policy that admits rows when app.worker is 'true'. Postgres ORs
-- permissive policies, so a connection with the worker setting sees everything in these two
-- tables, and every other connection is unaffected.
--
-- The API never sets app.worker: the only place the setting exists in Go is the worker's claim
-- path, and `db.WithSettings` is the only way to apply it. So the API remains exactly as
-- tenant-scoped as it was.
--
-- # Fail-closed by construction
--
-- `current_setting('app.worker', true)` returns NULL when the setting is absent, and `NULL = 'true'`
-- is NULL rather than true — so an unset setting admits nothing. A missing GUC makes the worker
-- see zero rows, which is a loud failure (nothing is delivered, the depth gauge never falls)
-- rather than a silent one (everything is delivered by a connection that should not have seen it).
--
-- # Scope
--
-- Only these two tables. A worker that needed a third would need a deliberate change here, which
-- is the point: the blast radius of a worker bug is bounded by what this file lists.
-- ---------------------------------------------------------------------------

CREATE POLICY webhook_endpoints_worker ON webhook_endpoints
    FOR ALL
    USING (current_setting('app.worker', true) = 'true')
    WITH CHECK (current_setting('app.worker', true) = 'true');

CREATE POLICY webhook_outbox_worker ON webhook_outbox
    FOR ALL
    USING (current_setting('app.worker', true) = 'true')
    WITH CHECK (current_setting('app.worker', true) = 'true');

-- The worker's queue scan reads `WHERE state IN ('pending','delivering') AND next_at <= now()`
-- ordered by next_at. The partial index from 0010 covers the predicate but not the ordering
-- across states, so the planner can still sort the whole candidate set. Including next_at in the
-- key lets it walk the index in order and stop at the first row that is not yet due — which is
-- what keeps a poll over a large backlog proportional to the batch rather than to the queue.
DROP INDEX webhook_outbox_due_idx;

CREATE INDEX webhook_outbox_due_idx ON webhook_outbox (next_at, id)
    WHERE state IN ('pending', 'delivering');
