-- Ingest feeds: one row per configured delivery endpoint.
--
-- The feed IS the ingest identity — its id is the last path segment of the
-- ingest URL and its token authenticates deliveries to exactly that path.
-- Ported from v1's feed model with one deliberate change: only the SHA-256 of
-- the token's secret half is stored. v1 kept feed credentials reversibly
-- sealed because its receiver compared plaintext; hashing was chosen for v2 so
-- a database copy never yields a working credential (same argument as invite).
CREATE TABLE IF NOT EXISTS feed (
    id               TEXT PRIMARY KEY,
    tenant_id        TEXT NOT NULL REFERENCES tenant(id),
    provider         TEXT NOT NULL CHECK (provider IN ('cloudflare','datadome','f5asm','nginx')),
    name             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    token_hash       TEXT NOT NULL,
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_rotated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A name identifies a feed to a human; two feeds with one name in one tenant
-- would make "which token did I just rotate?" unanswerable.
CREATE UNIQUE INDEX IF NOT EXISTS feed_name_per_tenant ON feed (tenant_id, name);
