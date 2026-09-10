-- 0001_init.sql — core tenancy schema, tenant isolation policies, application role.
--
-- Applied by cmd/migrate inside one transaction per file (see
-- internal/platform/migrations). Forward-only: corrections ship as new files,
-- never as edits here — the runner records a checksum and refuses to run if an
-- already-applied file changed.

-- ---------------------------------------------------------------------------
-- Roles
--
-- The API connects as app_rw, which is deliberately neither a superuser nor
-- BYPASSRLS. Both bypass row-level security unconditionally, and a table owner
-- bypasses it unless the table is FORCE'd — so without a dedicated low-privilege
-- role every policy below would be decoration.
--
-- Dev convenience: creating the role here makes a fresh clone work with one
-- command. In production the role is provisioned out-of-band (DBA/Terraform)
-- with a secret-managed password, and the application is never given the DDL
-- role at all. See docs/adr/ADR-003-tenancy-and-rls.md.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
        CREATE ROLE app_rw LOGIN PASSWORD 'app_rw'
            NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
    END IF;
END $$;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_rw', current_database());
END $$;

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------
CREATE TABLE tenants (
    id         uuid PRIMARY KEY,          -- UUIDv7, generated in Go (ADR-007)
    slug       text NOT NULL UNIQUE CHECK (slug = lower(slug) AND slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- users — global identity, deliberately not tenant-scoped.
-- Reachable only through a membership join in every code path that returns
-- user data; see ADR-003 for the residual exposure and why it is accepted.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id         uuid PRIMARY KEY,
    email      text NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 320),
    pw_hash    text NOT NULL CHECK (length(pw_hash) >= 8),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- memberships — the tenant <-> user edge; every authorization decision resolves
-- against this table.
-- ---------------------------------------------------------------------------
CREATE TABLE memberships (
    tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

-- "Which tenants do I belong to?" and the per-request membership gate.
CREATE INDEX memberships_user_idx ON memberships (user_id, tenant_id);

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- Two transaction-scoped GUCs carry request identity:
--   app.current_tenant_id — the tenant selected for this request
--   app.current_user_id   — the authenticated principal
--
-- Both are written with set_config(name, value, is_local => true) inside the
-- request transaction, so they revert at commit/rollback and cannot leak onto
-- the next request that reuses a pooled connection. This is the single most
-- important invariant in the tenancy layer; it is what
-- TestRLS_ConcurrentScopes_NoLeak exists to catch.
--
-- NULLIF(current_setting(name, true), '')::uuid yields NULL when the GUC is
-- unset or empty, and `x = NULL` is NULL, so a missing context hides rows
-- instead of erroring. Fail-closed.
--
-- Policies are applied only where a tenant boundary actually exists. users has
-- no policy by design (see ADR-003); blanket RLS everywhere would be cargo cult.
-- ---------------------------------------------------------------------------
ALTER TABLE tenants     ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants     FORCE  ROW LEVEL SECURITY;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE  ROW LEVEL SECURITY;

-- tenants: visible only to principals who hold a membership in it. The
-- EXISTS subquery is itself subject to the memberships policies below, so it
-- resolves to "tenants where I am a member" — the id = current_tenant arm that
-- a naive design adds here would let a caller read a tenant they do not belong
-- to simply by presenting its id, so it is deliberately absent.
CREATE POLICY tenants_select ON tenants FOR SELECT USING (
    EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.tenant_id = tenants.id
          AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
);

-- Creation sets the new tenant as the active tenant for the creating
-- transaction; the membership row inserted in the same transaction is what
-- makes the tenant visible on later requests.
CREATE POLICY tenants_insert ON tenants FOR INSERT WITH CHECK (
    id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
);

CREATE POLICY tenants_update ON tenants FOR UPDATE USING (
    EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.tenant_id = tenants.id
          AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
) WITH CHECK (
    EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.tenant_id = tenants.id
          AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
);

CREATE POLICY tenants_delete ON tenants FOR DELETE USING (
    EXISTS (
        SELECT 1 FROM memberships m
        WHERE m.tenant_id = tenants.id
          AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
    )
);

-- memberships: two independent arms, both needed.
--   tenant arm — a request scoped to tenant T may read T's roster. This is the
--                arm that powers "list members of this tenant".
--   user arm   — a principal may always read their own memberships. This is the
--                arm that makes the pre-tenant queries work: login needs "which
--                tenants do I belong to", and the request gate needs "what is my
--                role in tenant T" — both before any tenant is selected.
-- Writes require an active tenant, so a scoped request cannot mint a membership
-- in another tenant or grant itself access elsewhere.
CREATE POLICY memberships_select ON memberships FOR SELECT USING (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
);

CREATE POLICY memberships_insert ON memberships FOR INSERT WITH CHECK (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
);

CREATE POLICY memberships_update ON memberships FOR UPDATE USING (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
) WITH CHECK (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
);

CREATE POLICY memberships_delete ON memberships FOR DELETE USING (
    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
);

-- ---------------------------------------------------------------------------
-- Application role privileges: DML only. No DDL, no ownership, and no ability
-- to alter or drop policies.
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA public TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_rw;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_rw;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO app_rw;
