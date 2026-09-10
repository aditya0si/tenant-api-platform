-- 0004_projects.sql — projects, plus the composite-key pattern that makes
-- cross-tenant references structurally impossible for every table that follows.
--
-- Forward-only (ADR-011).

-- ---------------------------------------------------------------------------
-- projects
-- ---------------------------------------------------------------------------
CREATE TABLE projects (
    id          uuid PRIMARY KEY,   -- UUIDv7, generated in Go (ADR-007)

    -- ON DELETE CASCADE: deleting a tenant takes its projects with it. The
    -- alternative (RESTRICT) would make tenant deletion a manual multi-table
    -- chore that is easy to get half-right, and a tenant row with no members is
    -- not a recoverable state anyone wants.
    tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    slug        text NOT NULL CHECK (slug = lower(slug) AND slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),

    -- Optimistic concurrency. Every update asserts the version it read and
    -- increments it, so two clients editing the same project cannot silently
    -- overwrite each other: the second one sees zero rows updated and is told its
    -- copy is stale (internal/project.Store.Update).
    --
    -- CHECK (version > 0) keeps the initial value meaningful — a zero version
    -- could not be distinguished from an unset column.
    version     integer NOT NULL DEFAULT 1 CHECK (version > 0),

    -- Who created it, kept for attribution. RESTRICT rather than CASCADE: a user
    -- who authored a project must not be deletable out from under it, because the
    -- audit trail would then point at nothing. Deactivating a user is the
    -- operation that exists for this; deleting is not.
    created_by  uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- Archiving rather than deleting. Deleting a project would orphan or cascade
    -- everything that will later reference it (invoices above all), and "this
    -- project existed and was retired" is almost always the fact worth keeping.
    -- DELETE on the API archives; see the handler.
    archived_at timestamptz,

    -- ---------------------------------------------------------------------
    -- The composite-key pattern.
    --
    -- id is already unique on its own, so this constraint is not about the id.
    -- It exists so that a child table can reference the *pair* (tenant_id, id)
    -- and thereby carry the tenant into the reference itself:
    --
    --   FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id)
    --
    -- With that in place, an invoice belonging to tenant A cannot reference a
    -- project belonging to tenant B, and the guarantee is a property of the
    -- schema rather than of whichever code path happens to be inserting. It
    -- holds regardless of whether row-level security is enabled, whether the
    -- author remembered to check, and whether a future query bypasses the
    -- application entirely.
    --
    -- The payoff arrives with invoices; it is established here, on the parent,
    -- because adding it later would mean rewriting the parent's constraints
    -- while children already reference it.
    -- ---------------------------------------------------------------------
    CONSTRAINT projects_tenant_id_id_key UNIQUE (tenant_id, id)
);

-- Slug is unique among *live* projects only.
--
-- A full unique index on (tenant_id, slug) would mean an archived project
-- permanently reserves its name, so a tenant could never reuse a slug after
-- retiring one — which is the opposite of what "archived" implies. The partial
-- index gives uniqueness exactly where it is needed and frees the name on archive.
CREATE UNIQUE INDEX projects_tenant_slug_live_idx
    ON projects (tenant_id, slug)
    WHERE archived_at IS NULL;

-- Two indexes for the list endpoint, because the default listing and the
-- include-archived listing are different queries:
--
--   projects_live_idx  serves GET /projects (the common case) and is smaller
--                      because it holds only live rows.
--   projects_all_idx   serves ?include_archived=true.
--
-- Both are ordered exactly as the keyset predicate orders — (created_at DESC,
-- id DESC) — so the pagination seek is an index scan that stops after one page
-- rather than a sort over the tenant's whole project list. The column order is
-- not cosmetic: reversing created_at or omitting id would force a sort, and the
-- difference is visible in EXPLAIN (see docs/BENCHMARKS.md).
CREATE INDEX projects_live_idx ON projects (tenant_id, created_at DESC, id DESC)
    WHERE archived_at IS NULL;
CREATE INDEX projects_all_idx ON projects (tenant_id, created_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- Kept in the same single-key shape as 0001: this table is reached only through a
-- resolved tenant scope, so app.current_tenant_id is always set by the time a
-- query runs, and one predicate covers every operation.
--
-- The WITH CHECK arm is the one that matters for writes: without it a scoped
-- request could insert a project into another tenant and the row would only be
-- invisible, not rejected.
-- ---------------------------------------------------------------------------
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE  ROW LEVEL SECURITY;

CREATE POLICY projects_tenant_isolation ON projects
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
    );

-- app_rw receives DML on new tables through the ALTER DEFAULT PRIVILEGES set in
-- 0001, so no explicit GRANT is needed here. That default is load-bearing for
-- every migration that follows, and it is asserted by the test that checks the
-- application role can actually read a table it was just given.
