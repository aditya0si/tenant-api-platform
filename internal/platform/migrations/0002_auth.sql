-- 0002_auth.sql — authentication state: refresh families, refresh tokens, API keys.
--
-- Forward-only (ADR-011). Adds authentication to the tenancy foundation from
-- 0001; no existing column or policy is touched.

-- ---------------------------------------------------------------------------
-- refresh_families
--
-- A "family" is one login session: the token issued at login plus every token
-- derived from it by rotation. Keeping the family as a first-class row is what
-- makes reuse detection possible — when a token that has already been consumed
-- is presented again, the only safe response is to revoke the entire family,
-- because the server cannot tell whether the thief or the legitimate client
-- holds the other half of the pair.
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_families (
    id             uuid PRIMARY KEY,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    revoked_reason text,

    -- A family is either live or revoked, never half-revoked: the pair is what
    -- an incident review reads, and a revoked_at without a reason is an
    -- investigation nobody can finish.
    CONSTRAINT refresh_families_revocation_consistent CHECK (
        (revoked_at IS NULL AND revoked_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_reason IS NOT NULL)
    )
);

-- "Revoke every session for this user" — the password-change and
-- suspected-compromise path.
CREATE INDEX refresh_families_user_idx ON refresh_families (user_id);

-- Partial index for the live families of a user. Sessions are typically revoked
-- far less often than they are listed, so the index stays small and the
-- revocation sweep does not scan dead rows.
CREATE INDEX refresh_families_live_idx ON refresh_families (user_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- refresh_tokens
--
-- Only the SHA-256 of the token is stored, never the token itself. The value is
-- 256 bits of CSPRNG output, so a fast hash is the correct choice here: there is
-- no dictionary to attack, and a slow KDF would only add latency to every
-- refresh. (Contrast with passwords, which are low-entropy and must use argon2id
-- — see internal/authn/password.go.)
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    token_hash  text PRIMARY KEY CHECK (length(token_hash) = 64),
    family_id   uuid NOT NULL REFERENCES refresh_families(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    -- Set exactly once, by the rotation that consumed this token. The
    -- `replaced_by = token_hash` pair is what lets an operator reconstruct a
    -- rotation chain during a reuse investigation.
    consumed_at timestamptz,
    replaced_by text,

    CONSTRAINT refresh_tokens_expiry_after_issue CHECK (expires_at > issued_at)
);

-- Self-referencing FK, added after the table exists. It points child -> parent,
-- so the successor row must be inserted before the predecessor is updated.
-- Without this constraint a rotation could record a successor that does not
-- exist, and the chain would be unreadable exactly when it is needed.
ALTER TABLE refresh_tokens
    ADD CONSTRAINT refresh_tokens_replaced_by_fkey
    FOREIGN KEY (replaced_by) REFERENCES refresh_tokens(token_hash) ON DELETE SET NULL;

-- Revoking a family touches every token in it.
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

-- Expiry sweeps and the "is this token still live" check both filter on
-- unconsumed, unexpired rows.
CREATE INDEX refresh_tokens_live_idx ON refresh_tokens (expires_at)
    WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- api_keys
--
-- Tenant-scoped machine credentials. As with refresh tokens, only a SHA-256 of
-- the secret is stored; the `prefix` column keeps the first characters in clear
-- text so a key can be identified in a UI or a log line without being usable.
-- ---------------------------------------------------------------------------
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Who created it. Kept for attribution and for revoking every key a
    -- departing employee minted; the key acts as the tenant, not as this user.
    created_by   uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,

    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text NOT NULL CHECK (length(prefix) BETWEEN 4 AND 16),
    key_hash     text NOT NULL UNIQUE CHECK (length(key_hash) = 64),

    -- Permission strings, not roles. A key is deliberately not a user: it should
    -- be able to hold a narrower set than any human role, and it must never be
    -- able to manage members or mint further keys by inheriting a role.
    scopes       text[] NOT NULL DEFAULT '{}',

    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz,
    revoked_at   timestamptz,

    CONSTRAINT api_keys_expiry_after_creation CHECK (expires_at IS NULL OR expires_at > created_at)
);

-- Listing a tenant's keys, newest first.
CREATE INDEX api_keys_tenant_idx ON api_keys (tenant_id, created_at DESC);

-- Live keys for a tenant: the common case when checking what is still in use.
CREATE INDEX api_keys_live_idx ON api_keys (tenant_id)
    WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- Two different shapes, because these three tables answer two different
-- questions.
--
-- refresh_families / refresh_tokens are keyed on the USER, not the tenant. A
-- refresh token is presented before a tenant is selected — at login there is no
-- tenant yet, and a person may belong to several — so a tenant-keyed policy
-- would hide every row on exactly the request that needs them. This mirrors the
-- memberships user arm in 0001 and is the same reasoning: scope RLS to the thing
-- that actually identifies the row's owner.
--
-- api_keys is keyed on the TENANT, because a key is a tenant-scoped credential.
-- The authentication path needs one extra arm, discussed below.
-- ---------------------------------------------------------------------------
ALTER TABLE refresh_families ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_families FORCE  ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens   ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens   FORCE  ROW LEVEL SECURITY;
ALTER TABLE api_keys         ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys         FORCE  ROW LEVEL SECURITY;

CREATE POLICY refresh_families_own_rows ON refresh_families
    FOR ALL
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

CREATE POLICY refresh_tokens_own_rows ON refresh_tokens
    FOR ALL
    USING (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid)
    WITH CHECK (user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid);

-- api_keys carries two arms, both required:
--
--   tenant arm — a request already scoped to tenant T may manage T's keys. This
--                is the listing and revocation path, and it is what stops a
--                scoped request from reading or minting keys for another tenant.
--
--   hash arm   — authentication happens before any tenant is known, because the
--                key itself is what identifies the tenant. So the lookup cannot
--                be tenant-scoped. Rather than punch a hole in the policy, this
--                arm admits exactly the one row whose hash the caller already
--                holds: the secret is what grants sight of its own record, and
--                nothing else becomes visible. `SELECT * FROM api_keys` from an
--                unauthenticated context still returns zero rows.
--
-- The alternative — no policy on api_keys, reasoning that "the hash is
-- unguessable" — would leave the table readable by any future query that forgets
-- a predicate, which is the bug class RLS exists to bound.
CREATE POLICY api_keys_tenant_or_own_hash ON api_keys
    FOR ALL
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        OR key_hash = NULLIF(current_setting('app.current_api_key_hash', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        OR key_hash = NULLIF(current_setting('app.current_api_key_hash', true), '')
    );
