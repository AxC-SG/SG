-- migration-guard: tenant-only
-- GCP Cloud Discovery connector: one tenant-level configuration holding the customer's own
-- service account credential, and one target per customer project.

CREATE TABLE ${tenantSchema}.gcp_discovery_configs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    source_system varchar(80) NOT NULL DEFAULT 'gcp',
    -- The customer's service account key JSON, encrypted with CredentialEncryptionService.
    -- Write-only: it is never returned by the API.
    credential_secret text,
    -- Read from the key at save time, for display and connection-test messages.
    service_account_email varchar(320),
    key_project_id varchar(64),
    enabled boolean NOT NULL DEFAULT true,
    auto_sync_enabled boolean NOT NULL DEFAULT false,
    interval_minutes integer NOT NULL DEFAULT 1440,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamptz,
    last_sync_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_gcp_discovery_configs_tenant_source UNIQUE (tenant_id, source_system)
);

ALTER TABLE ${tenantSchema}.gcp_discovery_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.gcp_discovery_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.gcp_discovery_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE TABLE ${tenantSchema}.gcp_discovery_targets (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    config_id uuid NOT NULL REFERENCES ${tenantSchema}.gcp_discovery_configs(id),
    -- GCP project IDs are 6-30 characters; the column leaves headroom for validation errors.
    project_id varchar(64) NOT NULL,
    display_name varchar(255),
    enabled boolean NOT NULL DEFAULT true,
    resource_types_json varchar(2000) NOT NULL,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamptz,
    last_sync_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_gcp_discovery_targets_config_project UNIQUE (config_id, project_id)
);

CREATE INDEX idx_gcp_discovery_targets_config ON ${tenantSchema}.gcp_discovery_targets(config_id);
CREATE INDEX idx_gcp_discovery_targets_tenant_enabled ON ${tenantSchema}.gcp_discovery_targets(tenant_id, enabled);

ALTER TABLE ${tenantSchema}.gcp_discovery_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.gcp_discovery_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.gcp_discovery_targets
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
