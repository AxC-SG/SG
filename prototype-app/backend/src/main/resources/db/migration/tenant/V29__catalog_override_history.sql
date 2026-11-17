-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);
CREATE TABLE ${tenantSchema}.intelligence_catalog_overrides (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    vulnerability_id uuid NOT NULL REFERENCES platform.vulnerabilities(id),
    revision bigint NOT NULL CHECK (revision > 0),
    operation varchar(10) NOT NULL CHECK (operation IN ('INCLUDE','EXCLUDE','RESTORE')),
    reason varchar(500) NOT NULL CHECK (length(trim(reason)) > 0),
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, vulnerability_id, revision),
    CHECK (tenant_id = '${tenantId}'::uuid),
    CHECK (operation <> 'RESTORE' OR expires_at IS NULL),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
ALTER TABLE ${tenantSchema}.intelligence_catalog_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.intelligence_catalog_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.intelligence_catalog_overrides
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
CREATE TRIGGER intelligence_catalog_overrides_immutable
    BEFORE UPDATE OR DELETE ON ${tenantSchema}.intelligence_catalog_overrides
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.reject_catalog_policy_version_mutation();
