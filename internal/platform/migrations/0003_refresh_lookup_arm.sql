-- 0003_refresh_lookup_arm.sql — let the refresh flow find a token before a user
-- is known.
--
-- Why this is a separate migration rather than an edit to 0002: 0002 is applied,
-- its checksum is recorded, and the runner refuses to run if an applied file
-- changes (ADR-011). That refusal is the feature — without it, two environments
-- silently diverge — so a correction ships as a new file.
--
-- The problem: refreshing a session is a pre-authentication operation. The client
-- presents an opaque token and nothing else; the server does not yet know who
-- they are, and the token itself is what identifies them. In 0002 the
-- refresh_tokens policy was keyed only on app.current_user_id, so the lookup
-- would have returned zero rows on exactly the request that needs the row —
-- the same trap documented for api_keys, and the same fix: admit precisely the
-- row whose secret the caller already holds.
--
-- Why that arm is safe: the value is 256 bits of CSPRNG output, so it is not
-- guessable, and possession of the hash is already sufficient to use the token.
-- The arm grants sight of one row, identified by the secret itself; it does not
-- widen the visible set. An unauthenticated `SELECT * FROM refresh_tokens` with
-- no GUC set still returns zero rows (NULL = NULL is NULL), and setting the GUC
-- to a value you do not hold simply matches nothing.

DROP POLICY refresh_tokens_own_rows ON refresh_tokens;

CREATE POLICY refresh_tokens_owner_or_presented_hash ON refresh_tokens
    FOR ALL
    USING (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        OR token_hash = NULLIF(current_setting('app.current_refresh_token_hash', true), '')
    )
    WITH CHECK (
        user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        OR token_hash = NULLIF(current_setting('app.current_refresh_token_hash', true), '')
    );

-- refresh_families needs no equivalent arm. By the time the family is read or
-- revoked, the token row has already been found and its user_id is known, so the
-- request can set app.current_user_id and use the policy from 0002. Keeping the
-- family keyed on the user alone means a stolen token cannot enumerate other
-- families: it unlocks one token row, and from there exactly the one family that
-- owns it.
