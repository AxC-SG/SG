-- The tenant baseline expects one deployment-evidence freshness setting per tenant.
-- Some existing tenant schemas were created before this table was included.

CREATE TABLE IF NOT EXISTS ${tenantSchema}.ai_agent_deployment_settings (
    tenant_id uuid NOT NULL,
    freshness_hours integer NOT NULL DEFAULT 24,
    CONSTRAINT ai_agent_deployment_settings_freshness_hours_check
        CHECK (freshness_hours >= 1 AND freshness_hours <= 8760),
    CONSTRAINT ai_agent_deployment_settings_pkey PRIMARY KEY (tenant_id),
    CONSTRAINT ai_agent_deployment_settings_tenant_id_fkey
        FOREIGN KEY (tenant_id) REFERENCES platform.tenants(id) ON DELETE CASCADE
);

ALTER TABLE ${tenantSchema}.ai_agent_deployment_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_agent_deployment_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ${tenantSchema}.ai_agent_deployment_settings;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_agent_deployment_settings
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
