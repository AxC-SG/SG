-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Phase 0B §4.2: a CVE campaign's scope is its CVEs (campaign_vulnerabilities) and, now, the software a user added to it.
-- Findings on those software identities' components are members like findings of the CVEs, so the reconciler keeps
-- picking up new ones. The identity itself is global reference data, so it is deleted from here when it goes away.
CREATE TABLE ${tenantSchema}.campaign_software (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    campaign_id uuid NOT NULL REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE,
    software_identity_id uuid NOT NULL REFERENCES platform.software_identities(id) ON DELETE CASCADE,
    added_by varchar(255) NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (campaign_id, software_identity_id)
);
CREATE INDEX idx_campaign_software_identity ON ${tenantSchema}.campaign_software (software_identity_id);

ALTER TABLE ${tenantSchema}.campaign_software ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.campaign_software FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_software
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
