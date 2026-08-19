-- Authentication state.
--
-- What is stored and what is not, and why:
--   - password_hash is PHC-encoded argon2id: parameters travel with the hash so
--     they can be upgraded without invalidating existing records.
--   - mfa_secret_enc is AES-256-GCM ciphertext. The TOTP secret is a live shared
--     credential and never touches the database in the clear — the sealing key
--     lives in the service environment, which the database has no access to.
--   - Refresh-token revocation is NOT here. It lives in Valkey with a TTL equal
--     to the token's remaining life: hot-path, self-expiring state that a
--     relational table would only accumulate.

ALTER TABLE principal
    ADD COLUMN IF NOT EXISTS password_hash   TEXT,
    ADD COLUMN IF NOT EXISTS mfa_secret_enc  TEXT,
    ADD COLUMN IF NOT EXISTS mfa_enrolled_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS password_set_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_login_at   TIMESTAMPTZ;

-- One-time account setup credentials.
--
-- Only the SHA-256 of the secret is stored; 256 bits of entropy is what makes a
-- non-memory-hard hash sufficient. redeemed_at is set exactly once — the
-- application checks it, and the partial unique index below makes a second
-- unredeemed invite per principal impossible so a re-issue implicitly retires
-- the previous link.
CREATE TABLE IF NOT EXISTS invite (
    id           TEXT PRIMARY KEY,
    tenant_id    TEXT NOT NULL REFERENCES tenant(id),
    principal_id TEXT NOT NULL REFERENCES principal(id),
    secret_hash  TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    redeemed_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS invite_one_open_per_principal
    ON invite (principal_id) WHERE redeemed_at IS NULL;
