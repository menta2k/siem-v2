-- The audit trail, and the grants that make it mean something.
--
-- FR-055 requires a trail operators cannot alter. A table the application can
-- UPDATE or DELETE is not that, however carefully the application behaves — so
-- the guarantee is enforced by privilege, not by discipline.

CREATE TABLE IF NOT EXISTS audit_record (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    action          TEXT NOT NULL,
    scope           TEXT NOT NULL,
    target_ref      TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    outcome         TEXT NOT NULL,
    detail          JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS audit_tenant_time_idx ON audit_record (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_principal_idx ON audit_record (principal_id, occurred_at DESC);

-- Block mutation at the database level. A trigger is used rather than relying
-- solely on role grants because it holds even if someone later grants the
-- application broader privileges by accident.
CREATE OR REPLACE FUNCTION audit_record_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_record is append-only: % is not permitted', TG_OP
        USING HINT = 'Audit entries are evidence. Correct a mistake by appending a correcting entry.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_record_no_update ON audit_record;
CREATE TRIGGER audit_record_no_update
    BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_record
    FOR EACH STATEMENT EXECUTE FUNCTION audit_record_immutable();
