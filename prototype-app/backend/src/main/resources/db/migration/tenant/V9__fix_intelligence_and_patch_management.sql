-- migration-guard: tenant-only
-- Fix Intelligence: fix_records becomes the canonical fix (patch, workaround, compensating
-- control, ...), and patch management tools (SCCM, Intune, BigFix, Tanium) report patch
-- applicability, deployment and schedule state against assets.
--
-- Migration owners can still be subject to FORCE RLS. Bind this transaction explicitly.
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- ── fix_records: lifecycle, classification and remediation detail ────────────────────────

-- A patch reported by a tool may carry no CVE of its own; CVEs live in fix_record_cves.
ALTER TABLE ${tenantSchema}.fix_records ALTER COLUMN cve_id DROP NOT NULL;

ALTER TABLE ${tenantSchema}.fix_records
    ADD COLUMN title varchar(500),
    -- Lifecycle-managed records (patch tools, Fix Intelligence workarounds and controls) are
    -- never deleted by CVE Workbench regeneration, which only replaces its own records.
    ADD COLUMN managed boolean NOT NULL DEFAULT false,
    ADD COLUMN status varchar(32) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN severity varchar(16),
    ADD COLUMN ecosystem varchar(32),
    -- Deduplication key within a tenant, e.g. "KB5034441" for a Microsoft patch reported by
    -- several tools, or "bigfix:<site>:<fixlet>" for a tool-specific one.
    ADD COLUMN external_key varchar(200),
    ADD COLUMN effort varchar(16),
    ADD COLUMN risk_level varchar(16),
    ADD COLUMN requires_reboot boolean,
    ADD COLUMN estimated_downtime_minutes integer,
    ADD COLUMN installation_instructions text,
    ADD COLUMN rollback_instructions text,
    ADD COLUMN known_limitations text,
    ADD COLUMN superseded_by_id uuid REFERENCES ${tenantSchema}.fix_records(id) ON DELETE SET NULL,
    ADD COLUMN owner varchar(255),
    ADD COLUMN proposed_by varchar(255),
    ADD COLUMN approved_by varchar(255),
    ADD COLUMN approved_at timestamptz,
    ADD COLUMN review_due_at timestamptz,
    ADD COLUMN version bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT fix_records_status_check
        CHECK (status IN ('DRAFT', 'PROPOSED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'RETIRED')),
    ADD CONSTRAINT fix_records_severity_check
        CHECK (severity IS NULL OR severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    ADD CONSTRAINT fix_records_ecosystem_check
        CHECK (ecosystem IS NULL OR ecosystem IN ('WINDOWS', 'LINUX', 'MACOS', 'CROSS_PLATFORM'));

CREATE UNIQUE INDEX uk_fix_records_tenant_type_key
    ON ${tenantSchema}.fix_records(tenant_id, fix_type, external_key)
    WHERE external_key IS NOT NULL;
CREATE INDEX idx_fix_records_tenant_type_status
    ON ${tenantSchema}.fix_records(tenant_id, fix_type, status);

-- Existing CVE Workbench records keep working; give them the new classification.
UPDATE ${tenantSchema}.fix_records
   SET title = summary,
       ecosystem = CASE lower(coalesce(os_hint, ''))
                       WHEN 'windows' THEN 'WINDOWS'
                       WHEN 'linux' THEN 'LINUX'
                       WHEN 'macos' THEN 'MACOS'
                       ELSE 'CROSS_PLATFORM'
                   END;

UPDATE ${tenantSchema}.fix_records f
   SET severity = upper(v.severity)
  FROM platform.vulnerabilities v
 WHERE v.external_id = f.cve_id
   AND upper(v.severity) IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE');

-- ── Fix to CVE links ─────────────────────────────────────────────────────────────────────

CREATE TABLE ${tenantSchema}.fix_record_cves (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fix_id uuid NOT NULL REFERENCES ${tenantSchema}.fix_records(id) ON DELETE CASCADE,
    cve_id varchar(50) NOT NULL,
    -- VENDOR_STATED (the patch tool named it), KB_MAPPING (Microsoft CSAF), ANALYST, RECOMMENDATION
    source varchar(32) NOT NULL,
    confidence varchar(16) NOT NULL DEFAULT 'HIGH',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_fix_record_cves UNIQUE (fix_id, cve_id),
    CONSTRAINT fix_record_cves_source_check
        CHECK (source IN ('VENDOR_STATED', 'KB_MAPPING', 'ANALYST', 'RECOMMENDATION')),
    CONSTRAINT fix_record_cves_confidence_check CHECK (confidence IN ('HIGH', 'MEDIUM', 'LOW'))
);
CREATE INDEX idx_fix_record_cves_tenant_cve ON ${tenantSchema}.fix_record_cves(tenant_id, cve_id);

INSERT INTO ${tenantSchema}.fix_record_cves (tenant_id, fix_id, cve_id, source)
SELECT f.tenant_id, f.id, f.cve_id, 'RECOMMENDATION'
  FROM ${tenantSchema}.fix_records f
 WHERE f.cve_id IS NOT NULL AND f.cve_id <> ''
ON CONFLICT DO NOTHING;

INSERT INTO ${tenantSchema}.fix_record_cves (tenant_id, fix_id, cve_id, source)
SELECT f.tenant_id, f.id, related.value, 'RECOMMENDATION'
  FROM ${tenantSchema}.fix_records f,
       jsonb_array_elements_text(coalesce(f.related_cve_ids, '[]'::jsonb)) AS related(value)
 WHERE related.value ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
ON CONFLICT DO NOTHING;

-- ── Patch and control detail ─────────────────────────────────────────────────────────────

CREATE TABLE ${tenantSchema}.fix_patch_details (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fix_id uuid NOT NULL REFERENCES ${tenantSchema}.fix_records(id) ON DELETE CASCADE,
    provider varchar(16) NOT NULL,
    external_id varchar(255) NOT NULL,
    kb_article varchar(32),
    bulletin_id varchar(64),
    vendor varchar(255),
    product varchar(255),
    classification varchar(128),
    vendor_severity varchar(64),
    release_date timestamptz,
    superseded boolean NOT NULL DEFAULT false,
    info_url varchar(1000),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_fix_patch_details UNIQUE (tenant_id, provider, external_id),
    CONSTRAINT fix_patch_details_provider_check CHECK (provider IN ('SCCM', 'INTUNE', 'BIGFIX', 'TANIUM'))
);
CREATE INDEX idx_fix_patch_details_fix ON ${tenantSchema}.fix_patch_details(fix_id);

CREATE TABLE ${tenantSchema}.fix_control_details (
    fix_id uuid PRIMARY KEY REFERENCES ${tenantSchema}.fix_records(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    control_type varchar(64),
    scope_description varchar(2000),
    verification_method varchar(2000),
    residual_risk varchar(16),
    CONSTRAINT fix_control_details_residual_risk_check
        CHECK (residual_risk IS NULL OR residual_risk IN ('HIGH', 'MEDIUM', 'LOW'))
);

-- ── Devices, deployments and per-asset state ─────────────────────────────────────────────

CREATE TABLE ${tenantSchema}.device_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    asset_id uuid NOT NULL REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    provider varchar(16) NOT NULL,
    external_id varchar(255) NOT NULL,
    hostname varchar(255),
    normalized_hostname varchar(255),
    serial_number varchar(255),
    os_name varchar(255),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_device_identities UNIQUE (tenant_id, provider, external_id),
    CONSTRAINT device_identities_provider_check CHECK (provider IN ('SCCM', 'INTUNE', 'BIGFIX', 'TANIUM'))
);
CREATE INDEX idx_device_identities_hostname ON ${tenantSchema}.device_identities(tenant_id, normalized_hostname);
CREATE INDEX idx_device_identities_serial ON ${tenantSchema}.device_identities(tenant_id, serial_number);
CREATE INDEX idx_device_identities_asset ON ${tenantSchema}.device_identities(asset_id);

CREATE TABLE ${tenantSchema}.patch_deployments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(16) NOT NULL,
    external_id varchar(255) NOT NULL,
    name varchar(500),
    state varchar(64),
    target_name varchar(500),
    starts_at timestamptz,
    deadline_at timestamptz,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_patch_deployments UNIQUE (tenant_id, provider, external_id),
    CONSTRAINT patch_deployments_provider_check CHECK (provider IN ('SCCM', 'INTUNE', 'BIGFIX', 'TANIUM'))
);

CREATE TABLE ${tenantSchema}.fix_assets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fix_id uuid NOT NULL REFERENCES ${tenantSchema}.fix_records(id) ON DELETE CASCADE,
    asset_id uuid NOT NULL REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    -- Who reported this state; ANALYST for assets scoped onto a workaround or control.
    provider varchar(16) NOT NULL,
    status varchar(32) NOT NULL,
    deployment_id uuid REFERENCES ${tenantSchema}.patch_deployments(id) ON DELETE SET NULL,
    scheduled_at timestamptz,
    deadline_at timestamptz,
    installed_at timestamptz,
    error_code varchar(128),
    first_detected_at timestamptz NOT NULL DEFAULT now(),
    last_reported_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_fix_assets UNIQUE (fix_id, asset_id, provider),
    CONSTRAINT fix_assets_provider_check CHECK (provider IN ('SCCM', 'INTUNE', 'BIGFIX', 'TANIUM', 'ANALYST')),
    CONSTRAINT fix_assets_status_check CHECK (status IN ('MISSING', 'SCHEDULED', 'IN_PROGRESS', 'INSTALLED', 'FAILED',
        'PENDING_REBOOT', 'NOT_APPLICABLE', 'SUPERSEDED', 'APPLIED'))
);
CREATE INDEX idx_fix_assets_tenant_asset ON ${tenantSchema}.fix_assets(tenant_id, asset_id);
CREATE INDEX idx_fix_assets_fix_status ON ${tenantSchema}.fix_assets(fix_id, status);

CREATE TABLE ${tenantSchema}.fix_asset_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    fix_asset_id uuid NOT NULL REFERENCES ${tenantSchema}.fix_assets(id) ON DELETE CASCADE,
    from_status varchar(32),
    to_status varchar(32) NOT NULL,
    provider varchar(16) NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_fix_asset_events_asset ON ${tenantSchema}.fix_asset_events(fix_asset_id, occurred_at);
CREATE INDEX idx_fix_asset_events_occurred ON ${tenantSchema}.fix_asset_events(tenant_id, occurred_at);

-- ── Patch connector configuration ────────────────────────────────────────────────────────

CREATE TABLE ${tenantSchema}.patch_connector_configs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    provider varchar(16) NOT NULL,
    -- BigFix server URL or Tanium Cloud API URL; unused for SCCM (existing connection) and Intune.
    base_url varchar(1000),
    -- Intune: Entra directory (tenant) id and application (client) id.
    directory_id varchar(64),
    client_id varchar(64),
    username varchar(255),
    -- Encrypted with CredentialEncryptionService; write-only through the API.
    credential_secret text,
    enabled boolean NOT NULL DEFAULT true,
    auto_sync_enabled boolean NOT NULL DEFAULT false,
    interval_minutes integer NOT NULL DEFAULT 1440,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamptz,
    last_sync_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uk_patch_connector_configs UNIQUE (tenant_id, provider),
    CONSTRAINT patch_connector_configs_provider_check CHECK (provider IN ('SCCM', 'INTUNE', 'BIGFIX', 'TANIUM'))
);

-- ── Row-level security for every new table ───────────────────────────────────────────────

ALTER TABLE ${tenantSchema}.fix_record_cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.fix_record_cves FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_record_cves
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.fix_patch_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.fix_patch_details FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_patch_details
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.fix_control_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.fix_control_details FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_control_details
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.device_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.device_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.device_identities
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.patch_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.patch_deployments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.patch_deployments
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.fix_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.fix_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_assets
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.fix_asset_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.fix_asset_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.fix_asset_events
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.patch_connector_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.patch_connector_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.patch_connector_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
