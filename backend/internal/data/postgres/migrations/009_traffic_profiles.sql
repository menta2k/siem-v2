-- Traffic profiler: learned per-endpoint baselines and per-tenant policy.
--
-- Profiles are mutable, low-volume, relational aggregates — exactly the class
-- of state 001_core.sql assigns to PostgreSQL rather than VictoriaLogs. The
-- profiler process holds the authoritative in-memory state and flushes whole
-- endpoints; parameters therefore live in a JSONB column on the endpoint row
-- instead of a child table, because no reader needs a parameter outside its
-- endpoint and a child table would only add diff bookkeeping to the flush.

CREATE TABLE IF NOT EXISTS profile_endpoint (
    id                TEXT PRIMARY KEY,     -- deterministic hash of (tenant, host, method, template)
    tenant_id         TEXT NOT NULL REFERENCES tenant(id),
    host              TEXT NOT NULL,
    method            TEXT NOT NULL,
    path_template     TEXT NOT NULL,
    observations      BIGINT NOT NULL DEFAULT 0,
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    -- Structural ceilings. NULL means NOT MEASURED (the provider never shipped
    -- the fact), which is a different claim from a measured 0.
    max_request_bytes BIGINT,
    max_header_count  INTEGER,
    max_header_bytes  INTEGER,
    max_cookie_count  INTEGER,
    max_param_count   INTEGER,
    max_value_len     INTEGER,
    max_path_len      INTEGER,
    cookie_names      TEXT[] NOT NULL DEFAULT '{}',
    status_mix        JSONB NOT NULL DEFAULT '{}',
    providers         TEXT[] NOT NULL DEFAULT '{}',
    -- True when a cap stopped this profile from growing; an incomplete profile
    -- must never present as a complete one.
    truncated         BOOLEAN NOT NULL DEFAULT FALSE,
    -- The learned parameters: {"query page": {location, name, inferred_type, ...}}.
    params            JSONB NOT NULL DEFAULT '{}',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, host, method, path_template)
);

-- The list view: a tenant's endpoints, busiest first, optionally per host.
CREATE INDEX IF NOT EXISTS profile_endpoint_tenant_obs_idx
    ON profile_endpoint (tenant_id, observations DESC);
CREATE INDEX IF NOT EXISTS profile_endpoint_tenant_host_idx
    ON profile_endpoint (tenant_id, host);

-- Per-tenant profiler policy, on the tenant row like ingest_filters: which
-- hosts get analyzed is tenant-level data governance, not a feed setting.
-- Default: disabled, allow-list empty — enabling must be an explicit act.
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS profiler_config JSONB NOT NULL
    DEFAULT '{"enabled":false,"hosts":[],"exclude_paths":[],"cookie_names":false,"min_observations_to_publish":20}';
