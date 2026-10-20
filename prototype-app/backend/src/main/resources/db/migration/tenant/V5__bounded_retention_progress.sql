CREATE TABLE ${tenantSchema}.ai_grid_retention_progress (
    tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id),
    after_id uuid,
    upper_id uuid,
    state varchar(24) NOT NULL DEFAULT 'NOT_RUN',
    last_started_at timestamptz,
    last_completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    last_error varchar(64)
);
ALTER TABLE ${tenantSchema}.ai_grid_retention_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ai_grid_retention_progress FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ai_grid_retention_progress
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);
