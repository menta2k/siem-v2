-- AS number → registry owner attribution (ported from v1).
--
-- Deliberately NOT tenant-scoped: registry attribution is public data and the
-- same for every tenant. Insert-only upsert, never truncated — a failed
-- refresh keeps yesterday's names rather than leaving numbers bare.
CREATE TABLE IF NOT EXISTS asn_owner (
    asn        BIGINT PRIMARY KEY,
    name       TEXT NOT NULL,
    country    TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
