-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Daily tenant CBOM posture points for the trend API. Derived data: regenerable from current
-- state for the day it is taken, retained for the configured trend window.
CREATE TABLE ${tenantSchema}.cbom_posture_snapshots (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    snapshot_date date NOT NULL,
    active_components integer NOT NULL,
    active_artifacts integer NOT NULL,
    assessed_artifacts integer NOT NULL,
    open_critical integer NOT NULL,
    open_high integer NOT NULL,
    open_medium integer NOT NULL,
    open_low integer NOT NULL,
    quantum_vulnerable integer NOT NULL,
    average_risk_score numeric(8,4),
    average_confidence numeric(6,5),
    average_completeness numeric(6,5),
    open_crypto_findings integer NOT NULL,
    overdue_crypto_findings integer NOT NULL,
    suppressed_crypto_findings integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, snapshot_date),
    CONSTRAINT cbom_posture_snapshot_scores_check CHECK (
        (average_confidence IS NULL OR average_confidence BETWEEN 0 AND 1)
        AND (average_completeness IS NULL OR average_completeness BETWEEN 0 AND 1))
);

-- Persisted assessment report artifacts. Content stays in the tenant schema (never deduplicated
-- across tenants); retention clears content and marks the row EXPIRED. Downloads are audited.
CREATE TABLE ${tenantSchema}.cbom_report_artifacts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    bom_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE,
    assessment_run_id uuid NOT NULL REFERENCES ${tenantSchema}.cbom_assessment_runs(id) ON DELETE CASCADE,
    format varchar(8) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'QUEUED',
    idempotency_key varchar(120) NOT NULL,
    regenerated_from uuid REFERENCES ${tenantSchema}.cbom_report_artifacts(id) ON DELETE SET NULL,
    requested_by varchar(255) NOT NULL,
    schema_version varchar(16),
    checksum_sha256 varchar(64),
    content_type varchar(80),
    filename varchar(255),
    size_bytes bigint,
    content bytea,
    error_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at timestamptz,
    download_count integer NOT NULL DEFAULT 0,
    last_downloaded_at timestamptz,
    last_downloaded_by varchar(255),
    CONSTRAINT cbom_report_format_check CHECK (format IN ('JSON','HTML')),
    CONSTRAINT cbom_report_status_check CHECK (status IN ('QUEUED','GENERATING','READY','FAILED','EXPIRED')),
    CONSTRAINT cbom_report_ready_shape_check CHECK (status <> 'READY' OR (content IS NOT NULL AND checksum_sha256 IS NOT NULL)),
    CONSTRAINT cbom_report_expired_shape_check CHECK (status <> 'EXPIRED' OR content IS NULL),
    CONSTRAINT cbom_report_idempotency_unique UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX idx_cbom_report_artifacts_bom ON ${tenantSchema}.cbom_report_artifacts(bom_id, created_at DESC);
CREATE INDEX idx_cbom_report_artifacts_expiry ON ${tenantSchema}.cbom_report_artifacts(expires_at) WHERE status = 'READY';

-- Analyst inventory filters over active components across documents.
CREATE INDEX idx_cbom_components_inventory
    ON ${tenantSchema}.cbom_components(tenant_id, active, risk_score DESC NULLS LAST, id);
CREATE INDEX idx_cbom_components_inventory_type
    ON ${tenantSchema}.cbom_components(tenant_id, asset_type, risk_score DESC NULLS LAST, id) WHERE active;
CREATE INDEX idx_cbom_risk_findings_open_component
    ON ${tenantSchema}.cbom_risk_findings(cbom_component_id, severity) WHERE status = 'OPEN';

ALTER TABLE ${tenantSchema}.cbom_posture_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_posture_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_posture_snapshots
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_report_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_report_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_report_artifacts
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
