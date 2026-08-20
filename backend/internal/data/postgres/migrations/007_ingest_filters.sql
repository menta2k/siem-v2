-- Per-tenant ingest filter rules (ported from v1): JSON array of
-- {field, op, values}. Matched records are never stored anywhere, which is
-- why the column lives on the tenant — the rules are a data-governance
-- decision, not a feed setting.
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS ingest_filters JSONB NOT NULL DEFAULT '[]';
