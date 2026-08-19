-- Core relational schema.
--
-- What lives here and what does not is deliberate: VictoriaLogs holds the
-- append-only high-volume record stream, while PostgreSQL holds the mutable,
-- transactional, relational state a log store cannot serve — identities, policy,
-- and the audit trail that must be provably unalterable.

CREATE TABLE IF NOT EXISTS tenant (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    -- VictoriaLogs tenancy is an (AccountID, ProjectID) pair supplied by header.
    -- It is advisory there, so these values are only ever injected server-side.
    vl_account_id   BIGINT NOT NULL DEFAULT 0,
    vl_project_id   BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS principal (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenant(id),
    identity        TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('analyst','engineer','admin')),
    -- Empty scope means all properties within the tenant; a populated scope
    -- restricts further. Tenant is always the outer bound.
    property_scope  TEXT[] NOT NULL DEFAULT '{}',
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, identity)
);

CREATE TABLE IF NOT EXISTS log_source (
    id                        TEXT PRIMARY KEY,
    tenant_id                 TEXT NOT NULL REFERENCES tenant(id),
    provider                  TEXT NOT NULL,
    delivery_mode             TEXT NOT NULL CHECK (delivery_mode IN ('push','pull')),
    push_config               JSONB,
    pull_config               JSONB,
    -- The resume point for pull sources. Without it a restart either re-reads a
    -- window or skips one; skipping loses data silently.
    pull_watermark            TIMESTAMPTZ,
    -- Declared cadence is what makes silence detectable. A source with no stated
    -- expectation cannot be distinguished from one that is merely quiet.
    expected_cadence_seconds  INTEGER NOT NULL,
    data_classification       TEXT NOT NULL DEFAULT 'standard',
    retention_policy_id       TEXT,
    parser_version            TEXT NOT NULL,
    detection_posture         TEXT NOT NULL DEFAULT '',
    enabled                   BOOLEAN NOT NULL DEFAULT TRUE,
    last_record_at            TIMESTAMPTZ,
    health_state              TEXT NOT NULL DEFAULT 'awaiting_first_record',
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS log_source_tenant_idx ON log_source (tenant_id) WHERE enabled;

CREATE TABLE IF NOT EXISTS retention_policy (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenant(id),
    name            TEXT NOT NULL,
    data_category   TEXT NOT NULL,
    hot_days        INTEGER NOT NULL,
    warm_days       INTEGER NOT NULL,
    cold_months     INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS legal_hold (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenant(id),
    scope_filter    JSONB NOT NULL,
    reason          TEXT NOT NULL,
    placed_by       TEXT NOT NULL,
    placed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at     TIMESTAMPTZ,
    released_by     TEXT,
    preserved_refs  TEXT[] NOT NULL DEFAULT '{}'
);

-- Partial index: the only question asked at expiry time is "is anything holding
-- this?", which concerns open holds exclusively.
CREATE INDEX IF NOT EXISTS legal_hold_open_idx ON legal_hold (tenant_id) WHERE released_at IS NULL;

CREATE TABLE IF NOT EXISTS detection (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenant(id),
    name                    TEXT NOT NULL,
    version                 TEXT NOT NULL,
    severity                TEXT NOT NULL,
    category                TEXT NOT NULL,
    hypothesis              TEXT NOT NULL,
    mitre_attack            TEXT[] NOT NULL DEFAULT '{}',
    expected_response       TEXT NOT NULL,
    recommended_first_check TEXT NOT NULL,
    -- A detection cannot be enabled until it has passed a positive and a
    -- near-miss fixture; the application enforces this and records the outcome.
    fixtures_passed_at      TIMESTAMPTZ,
    enabled                 BOOLEAN NOT NULL DEFAULT FALSE,
    baseline_stats          JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, id, version)
);

CREATE TABLE IF NOT EXISTS alert (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL REFERENCES tenant(id),
    detection_id            TEXT NOT NULL,
    detection_version       TEXT NOT NULL,
    fired_at                TIMESTAMPTZ NOT NULL,
    severity                TEXT NOT NULL,
    title                   TEXT NOT NULL,
    evidence                JSONB NOT NULL DEFAULT '{}',
    linked_flow_ids         TEXT[] NOT NULL DEFAULT '{}',
    grouping_key            TEXT NOT NULL,
    occurrence_count        INTEGER NOT NULL DEFAULT 1,
    delivery_state          TEXT NOT NULL DEFAULT 'pending',
    acknowledged_by         TEXT,
    acknowledged_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS alert_tenant_time_idx ON alert (tenant_id, fired_at DESC);
CREATE INDEX IF NOT EXISTS alert_grouping_idx ON alert (grouping_key, fired_at DESC);

CREATE TABLE IF NOT EXISTS evaluation_run (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenant(id),
    flow_id             TEXT,
    event_id            TEXT,
    engine              TEXT NOT NULL,
    -- Pinned per run so a result stays interpretable after an upgrade moves the
    -- ruleset underneath it.
    engine_version      TEXT NOT NULL,
    ruleset_version     TEXT NOT NULL,
    scheme_version      TEXT,
    parameters          JSONB NOT NULL DEFAULT '{}',
    expression          TEXT,
    matched_rules       JSONB NOT NULL DEFAULT '[]',
    anomaly_score       INTEGER,
    resulting_action    TEXT,
    would_block         BOOLEAN,
    -- Records that the input was truncated, masked or partial, so a result from
    -- incomplete input can never be read as the production verdict.
    input_completeness  JSONB NOT NULL DEFAULT '{}',
    compared_to_run_id  TEXT,
    operator_id         TEXT NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS evaluation_run_flow_idx ON evaluation_run (tenant_id, flow_id);
