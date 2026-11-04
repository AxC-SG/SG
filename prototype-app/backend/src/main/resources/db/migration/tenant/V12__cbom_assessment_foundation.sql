-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

CREATE TABLE ${tenantSchema}.cbom_rule_configurations (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    package_id varchar(120) NOT NULL DEFAULT 'scoutgrid-baseline',
    version_policy varchar(24) NOT NULL DEFAULT 'FOLLOW_LATEST',
    pinned_version varchar(40),
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_by varchar(255) NOT NULL DEFAULT 'system',
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    CONSTRAINT cbom_rule_config_version_policy_check CHECK (version_policy IN ('FOLLOW_LATEST','PINNED')),
    CONSTRAINT cbom_rule_config_pin_check CHECK (version_policy <> 'PINNED' OR pinned_version IS NOT NULL)
);

CREATE TABLE ${tenantSchema}.cbom_assessment_runs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    bom_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE,
    artifact_checksum varchar(128) NOT NULL,
    rule_package_id varchar(120) NOT NULL,
    rule_package_version varchar(40) NOT NULL,
    rule_package_digest varchar(128) NOT NULL,
    evaluator_version varchar(40) NOT NULL,
    status varchar(24) NOT NULL DEFAULT 'QUEUED',
    validation_outcome varchar(24) NOT NULL DEFAULT 'NOT_RUN',
    component_count integer NOT NULL DEFAULT 0,
    finding_count integer NOT NULL DEFAULT 0,
    confidence_score numeric(6,5),
    completeness_score numeric(6,5),
    started_at timestamptz,
    completed_at timestamptz,
    error_code varchar(80),
    error_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cbom_assessment_status_check CHECK (status IN ('QUEUED','RUNNING','SUCCEEDED','FAILED','CANCELLED')),
    CONSTRAINT cbom_assessment_validation_check CHECK (validation_outcome IN ('NOT_RUN','VALID','VALID_WITH_WARNINGS','INVALID')),
    CONSTRAINT cbom_assessment_score_check CHECK (
        (confidence_score IS NULL OR confidence_score BETWEEN 0 AND 1)
        AND (completeness_score IS NULL OR completeness_score BETWEEN 0 AND 1)
    )
);
CREATE UNIQUE INDEX uk_cbom_assessment_reproducible
    ON ${tenantSchema}.cbom_assessment_runs(bom_id, rule_package_digest, evaluator_version)
    WHERE status IN ('QUEUED','RUNNING','SUCCEEDED');
CREATE INDEX idx_cbom_assessment_runs_bom ON ${tenantSchema}.cbom_assessment_runs(bom_id, created_at DESC);
CREATE INDEX idx_cbom_assessment_runs_status ON ${tenantSchema}.cbom_assessment_runs(status, created_at);

CREATE TABLE ${tenantSchema}.cbom_validation_issues (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    assessment_run_id uuid NOT NULL REFERENCES ${tenantSchema}.cbom_assessment_runs(id) ON DELETE CASCADE,
    code varchar(100) NOT NULL,
    severity varchar(16) NOT NULL,
    json_pointer varchar(1000),
    message text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cbom_validation_issue_severity_check CHECK (severity IN ('INFO','WARNING','ERROR'))
);
CREATE INDEX idx_cbom_validation_issues_run ON ${tenantSchema}.cbom_validation_issues(assessment_run_id, severity, code);

CREATE TABLE ${tenantSchema}.cbom_claim_assurances (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    assessment_run_id uuid NOT NULL REFERENCES ${tenantSchema}.cbom_assessment_runs(id) ON DELETE CASCADE,
    cbom_component_id uuid REFERENCES ${tenantSchema}.cbom_components(id) ON DELETE CASCADE,
    claim_path varchar(1000) NOT NULL,
    assurance_level varchar(24) NOT NULL,
    evidence_state varchar(32) NOT NULL,
    explanation text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cbom_claim_assurance_level_check CHECK (assurance_level IN ('DECLARED','CORROBORATED','VERIFIED','CONFLICTING','UNKNOWN')),
    CONSTRAINT cbom_claim_evidence_state_check CHECK (evidence_state IN ('SUPPORTED','CONFLICTING','WITHDRAWN','LEGACY_UNKNOWN')),
    CONSTRAINT cbom_claim_assurance_unique UNIQUE (assessment_run_id, cbom_component_id, claim_path)
);
CREATE INDEX idx_cbom_claim_assurances_run ON ${tenantSchema}.cbom_claim_assurances(assessment_run_id, assurance_level);

ALTER TABLE ${tenantSchema}.cbom_rule_configurations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_rule_configurations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_rule_configurations
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_assessment_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_assessment_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_assessment_runs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_validation_issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_validation_issues FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_validation_issues
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_claim_assurances ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_claim_assurances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_claim_assurances
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
