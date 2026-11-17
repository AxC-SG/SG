-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

CREATE TABLE ${tenantSchema}.intelligence_catalog_policy_versions (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    version bigint NOT NULL CHECK (version > 0),
    policy_json jsonb NOT NULL,
    policy_sha256 char(64) NOT NULL CHECK (policy_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version),
    CONSTRAINT intelligence_catalog_policy_version_tenant_check
        CHECK (tenant_id = '${tenantId}'::uuid)
);

ALTER TABLE ${tenantSchema}.intelligence_catalog_policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.intelligence_catalog_policy_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation
    ON ${tenantSchema}.intelligence_catalog_policy_versions
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

-- Policy versions are append-only, including for application roles with broad schema grants.
CREATE FUNCTION ${tenantSchema}.reject_catalog_policy_version_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'catalog policy versions are immutable';
END $$;
CREATE TRIGGER intelligence_catalog_policy_versions_immutable
    BEFORE UPDATE OR DELETE ON ${tenantSchema}.intelligence_catalog_policy_versions
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.reject_catalog_policy_version_mutation();
