-- Repair tenants created from an older V1 catalog before the digest approval
-- reference column and audit history table were included.

ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_baselines
    ADD COLUMN IF NOT EXISTS approval_reference_verified boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS ${tenantSchema}.ai_security_baseline_history (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    digest_kind varchar(64) NOT NULL,
    action varchar(32) NOT NULL,
    actor varchar(255),
    source_run_id uuid,
    algorithm varchar(64),
    key_version varchar(64),
    approved_value text,
    approval_reference_verified boolean NOT NULL DEFAULT false,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ai_security_baseline_history_pkey PRIMARY KEY (id),
    CONSTRAINT ai_security_baseline_history_artifact_id_fkey
        FOREIGN KEY (artifact_id) REFERENCES ${tenantSchema}.ai_security_artifacts(id) ON DELETE CASCADE,
    CONSTRAINT ai_security_baseline_history_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id)
);

ALTER TABLE ${tenantSchema}.ai_security_baseline_history
    ADD COLUMN IF NOT EXISTS approval_reference_verified boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS ai_security_baseline_history_artifact_id_recorded_at_idx
    ON ${tenantSchema}.ai_security_baseline_history (artifact_id, recorded_at);

ALTER TABLE ${tenantSchema}.ai_security_baseline_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_security_baseline_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ${tenantSchema}.ai_security_baseline_history;
DROP POLICY IF EXISTS tenant_isolation ON ${tenantSchema}.ai_security_baseline_history;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_security_baseline_history
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
