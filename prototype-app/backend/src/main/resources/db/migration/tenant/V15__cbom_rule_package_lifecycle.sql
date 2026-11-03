-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Tenant-owned rule-package lifecycle state (ADR-0001). Rule content stays in application
-- packages; these tables record what the tenant has been offered, what is effective, and why.
ALTER TABLE ${tenantSchema}.cbom_rule_configurations
    ADD COLUMN effective_version varchar(40),
    ADD COLUMN pin_state varchar(24) NOT NULL DEFAULT 'CURRENT',
    ADD COLUMN deprecation_notice_at timestamptz,
    ADD COLUMN upgrade_required_at timestamptz,
    ADD CONSTRAINT cbom_rule_config_pin_state_check
        CHECK (pin_state IN ('CURRENT','UPGRADE_AVAILABLE','DEPRECATED','UPGRADE_REQUIRED','UNSUPPORTED'));

CREATE TABLE ${tenantSchema}.cbom_rule_availability (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    package_id varchar(120) NOT NULL,
    package_version varchar(40) NOT NULL,
    package_digest varchar(128) NOT NULL,
    evaluator_major integer NOT NULL,
    discovered_at timestamptz NOT NULL DEFAULT now(),
    rollout_stage varchar(16) NOT NULL,
    status varchar(24) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, package_id, package_version),
    CONSTRAINT cbom_rule_availability_stage_check CHECK (rollout_stage IN ('OBSERVE','CANARY','BATCHED','GENERAL')),
    CONSTRAINT cbom_rule_availability_status_check CHECK (status IN ('AVAILABLE','EFFECTIVE','DEFERRED_PINNED','RETIRED'))
);

CREATE TABLE ${tenantSchema}.cbom_rule_selection_history (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    package_id varchar(120) NOT NULL,
    action varchar(32) NOT NULL,
    from_version varchar(40),
    to_version varchar(40),
    version_policy varchar(24) NOT NULL,
    actor varchar(255) NOT NULL,
    reason text NOT NULL,
    parameters_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    impact_json jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cbom_rule_selection_action_check CHECK (action IN
        ('TENANT_UPDATE','ROLLOUT_UPGRADE','UPGRADE_AVAILABLE','DEPRECATION_NOTICE','UPGRADE_REQUIRED','FORCED_UPGRADE','UNSUPPORTED'))
);
CREATE INDEX idx_cbom_rule_selection_history_recent
    ON ${tenantSchema}.cbom_rule_selection_history(tenant_id, created_at DESC);

ALTER TABLE ${tenantSchema}.cbom_rule_availability ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_rule_availability FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_rule_availability
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_rule_selection_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_rule_selection_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_rule_selection_history
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
