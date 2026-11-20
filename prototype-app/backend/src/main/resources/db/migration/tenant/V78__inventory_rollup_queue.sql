-- migration-guard: tenant-only
CREATE TABLE ${tenantSchema}.inventory_rollup_queue (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    rollup_kind text NOT NULL CHECK (rollup_kind IN ('SOFTWARE_IDENTITY', 'ORG_CVE')),
    subject_id uuid NOT NULL,
    marked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (rollup_kind, subject_id),
    CONSTRAINT inventory_rollup_queue_tenant_check CHECK (tenant_id = '${tenantId}'::uuid)
);
CREATE INDEX inventory_rollup_queue_oldest_idx
    ON ${tenantSchema}.inventory_rollup_queue (marked_at, rollup_kind, subject_id);

ALTER TABLE ${tenantSchema}.inventory_rollup_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.inventory_rollup_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.inventory_rollup_queue
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE FUNCTION ${tenantSchema}.mark_inventory_software_rollup()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    selected_tenant uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    previous_identity uuid := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.software_identity_id END;
    current_identity uuid := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE NEW.software_identity_id END;
BEGIN
    IF EXISTS (SELECT 1 FROM ${tenantSchema}.inventory_correlation_settings
               WHERE tenant_id = selected_tenant AND inventory_incremental_correlation_enabled) THEN
        INSERT INTO ${tenantSchema}.inventory_rollup_queue (tenant_id, rollup_kind, subject_id)
        SELECT selected_tenant, 'SOFTWARE_IDENTITY', identity_id
        FROM (SELECT DISTINCT unnest(ARRAY[previous_identity, current_identity]) AS identity_id) AS changed
        WHERE identity_id IS NOT NULL
        ORDER BY identity_id
        ON CONFLICT (rollup_kind, subject_id) DO UPDATE
            SET marked_at = least(inventory_rollup_queue.marked_at, excluded.marked_at);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER mark_inventory_software_rollup
    AFTER INSERT OR DELETE OR UPDATE OF software_identity_id, asset_id, sbom_upload_id, component_status,
        ecosystem, version, last_observed_at, is_eol, eol_date, eol_slug
    ON ${tenantSchema}.inventory_components
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.mark_inventory_software_rollup();
