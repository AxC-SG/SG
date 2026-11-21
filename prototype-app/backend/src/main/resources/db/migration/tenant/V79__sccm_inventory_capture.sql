-- migration-guard: tenant-only
CREATE TABLE ${tenantSchema}.sccm_inventory_captures (
    run_id uuid PRIMARY KEY REFERENCES platform.sync_runs(id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    config_revision timestamptz NOT NULL,
    sealed boolean NOT NULL DEFAULT false,
    result jsonb,
    CONSTRAINT sccm_inventory_capture_tenant_check CHECK (tenant_id = '${tenantId}'::uuid)
);
CREATE TABLE ${tenantSchema}.sccm_inventory_capture_rows (
    run_id uuid NOT NULL REFERENCES ${tenantSchema}.sccm_inventory_captures(run_id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    section text NOT NULL CHECK (section IN ('INSTALL','DISCOVERY')),
    row_key text NOT NULL,
    sequence_no int NOT NULL CHECK (sequence_no >= 0),
    payload jsonb NOT NULL,
    PRIMARY KEY (run_id, section, row_key, sequence_no),
    CONSTRAINT sccm_inventory_capture_row_tenant_check CHECK (tenant_id = '${tenantId}'::uuid)
);

ALTER TABLE ${tenantSchema}.sccm_inventory_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.sccm_inventory_captures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.sccm_inventory_captures
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.sccm_inventory_capture_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.sccm_inventory_capture_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.sccm_inventory_capture_rows
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
