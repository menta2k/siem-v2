-- Per-tenant retention for raw provider evidence, configurable from the UI.
-- Raw records live in their own VictoriaLogs instance (separate retention
-- class); this value drives the scheduled delete task retentiond runs against
-- that instance. Default 7 days matches the spec's stated evidence window.
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS raw_retention_days INTEGER NOT NULL DEFAULT 7;
