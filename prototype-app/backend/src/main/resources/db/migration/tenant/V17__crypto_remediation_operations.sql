-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Campaigns can group canonical findings that have no CVE (CRYPTO findings) in addition to the
-- existing CVE-based campaign_vulnerabilities links. Workflow stays on canonical findings.
CREATE TABLE ${tenantSchema}.campaign_findings (
    campaign_id uuid NOT NULL REFERENCES ${tenantSchema}.campaigns(id) ON DELETE CASCADE,
    finding_id uuid NOT NULL REFERENCES ${tenantSchema}.findings(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    added_by varchar(255) NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (campaign_id, finding_id)
);
CREATE INDEX idx_campaign_findings_finding ON ${tenantSchema}.campaign_findings(finding_id);

-- Ticket creation attempts, so a failed push is visible and can be retried. Error text is the
-- sanitized provider message; no credentials or request bodies are stored.
CREATE TABLE ${tenantSchema}.finding_ticket_attempts (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES ${tenantSchema}.findings(id) ON DELETE CASCADE,
    provider varchar(40),
    template varchar(40) NOT NULL,
    outcome varchar(16) NOT NULL,
    ticket_key varchar(255),
    error_message text,
    attempted_by varchar(255) NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT finding_ticket_attempts_outcome_check CHECK (outcome IN ('SUCCEEDED','FAILED'))
);
CREATE INDEX idx_finding_ticket_attempts_finding ON ${tenantSchema}.finding_ticket_attempts(finding_id, attempted_at DESC);

ALTER TABLE ${tenantSchema}.campaign_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.campaign_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_findings
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.finding_ticket_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.finding_ticket_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_ticket_attempts
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
