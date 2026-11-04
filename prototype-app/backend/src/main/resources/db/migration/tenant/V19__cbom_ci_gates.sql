-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Environment-specific CI gate policies. A missing environment falls back to the 'default' row,
-- then to the application default (fail on CRITICAL/HIGH, completeness >= 0.80).
CREATE TABLE ${tenantSchema}.cbom_gate_policies (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    environment varchar(40) NOT NULL,
    fail_on_severities varchar(80) NOT NULL DEFAULT 'CRITICAL,HIGH',
    minimum_completeness numeric(6,5) NOT NULL DEFAULT 0.80000,
    block_on_invalid boolean NOT NULL DEFAULT true,
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, environment),
    CONSTRAINT cbom_gate_policy_environment_check CHECK (environment ~ '^[a-z0-9][a-z0-9-]{0,39}$'),
    CONSTRAINT cbom_gate_policy_completeness_check CHECK (minimum_completeness BETWEEN 0 AND 1)
);

-- Least-privilege, single-job gate tokens. Only the SHA-256 of the token is stored; a token reads
-- the gate result of the one CBOM it was issued for and nothing else, and expires.
CREATE TABLE ${tenantSchema}.cbom_gate_tokens (
    token_hash char(64) PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    bom_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE,
    environment varchar(40) NOT NULL,
    issued_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_polled_at timestamptz,
    poll_count integer NOT NULL DEFAULT 0
);
CREATE INDEX idx_cbom_gate_tokens_bom ON ${tenantSchema}.cbom_gate_tokens(bom_id);
CREATE INDEX idx_cbom_gate_tokens_expiry ON ${tenantSchema}.cbom_gate_tokens(expires_at);

ALTER TABLE ${tenantSchema}.cbom_gate_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_gate_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_gate_policies
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.cbom_gate_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_gate_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_gate_tokens
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
