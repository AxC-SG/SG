-- migration-guard: tenant-only
CREATE TABLE ${tenantSchema}.inventory_correlation_settings (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    inventory_incremental_correlation_enabled boolean NOT NULL DEFAULT false,
    CONSTRAINT inventory_correlation_settings_tenant_check CHECK (tenant_id = '${tenantId}'::uuid)
);

ALTER TABLE ${tenantSchema}.inventory_correlation_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.inventory_correlation_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.inventory_correlation_settings
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

CREATE FUNCTION ${tenantSchema}.enqueue_inventory_component_delta(tenant uuid, component uuid)
RETURNS void LANGUAGE sql SET search_path = pg_catalog AS $$
    INSERT INTO ${tenantSchema}.finding_delta_queue (event_type, tenant_id, component_id, source_tag, dedupe_key)
    VALUES ('SOFTWARE_DELTA', tenant, component, 'inventory-write',
            'software:' || tenant || ':' || component || ':inventory-write')
    ON CONFLICT (dedupe_key) WHERE status = 'PENDING' DO NOTHING;
$$;

CREATE FUNCTION ${tenantSchema}.schedule_inventory_correlation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    selected_tenant uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
    incremental boolean;
BEGIN
    SELECT inventory_incremental_correlation_enabled INTO incremental
    FROM ${tenantSchema}.inventory_correlation_settings WHERE tenant_id = selected_tenant;

    IF NOT coalesce(incremental, false) THEN
        IF TG_TABLE_NAME = 'inventory_components' THEN
            INSERT INTO platform.tenant_intelligence_processing (tenant_id) VALUES (selected_tenant)
            ON CONFLICT (tenant_id) DO UPDATE
            SET required_revision = tenant_intelligence_processing.required_revision + 1,
                status = 'PENDING', updated_at = now(), last_error = NULL;
        END IF;
        RETURN NULL;
    END IF;

    IF TG_TABLE_NAME = 'inventory_component_cpe_map' THEN
        IF TG_OP = 'UPDATE' THEN
            IF ROW(OLD.component_id, OLD.cpe_id, OLD.observed_version)
                IS NOT DISTINCT FROM ROW(NEW.component_id, NEW.cpe_id, NEW.observed_version) THEN
                RETURN NULL;
            END IF;
            IF OLD.component_id <> NEW.component_id THEN
                PERFORM ${tenantSchema}.enqueue_inventory_component_delta(selected_tenant, OLD.component_id);
            END IF;
        END IF;
        PERFORM ${tenantSchema}.enqueue_inventory_component_delta(selected_tenant,
            CASE WHEN TG_OP = 'DELETE' THEN OLD.component_id ELSE NEW.component_id END);
        RETURN NULL;
    END IF;

    -- Ingest timestamps and upload IDs change on rediscovery. Compare the matching,
    -- evidence and lifecycle values so those bookkeeping updates do not enqueue work.
    IF TG_OP = 'UPDATE' AND ROW(
        OLD.asset_id, OLD.component_status, OLD.component_digest, OLD.ecosystem, OLD.package_name,
        OLD.package_group, OLD.license, OLD.scope, OLD.version, OLD.purl, OLD.normalized_name,
        OLD.normalized_purl, OLD.normalized_version, OLD.coord_key, OLD.software_identity_id,
        OLD.manual_identity_id, OLD.bom_evidence_state, OLD.eol_slug, OLD.eol_cycle, OLD.eol_date,
        OLD.is_eol, OLD.eol_support_end_date, OLD.support_phase
    ) IS NOT DISTINCT FROM ROW(
        NEW.asset_id, NEW.component_status, NEW.component_digest, NEW.ecosystem, NEW.package_name,
        NEW.package_group, NEW.license, NEW.scope, NEW.version, NEW.purl, NEW.normalized_name,
        NEW.normalized_purl, NEW.normalized_version, NEW.coord_key, NEW.software_identity_id,
        NEW.manual_identity_id, NEW.bom_evidence_state, NEW.eol_slug, NEW.eol_cycle, NEW.eol_date,
        NEW.is_eol, NEW.eol_support_end_date, NEW.support_phase
    ) THEN
        RETURN NULL;
    END IF;

    PERFORM ${tenantSchema}.enqueue_inventory_component_delta(selected_tenant,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END);
    RETURN NULL;
END;
$$;

DROP TRIGGER schedule_inventory_intelligence ON ${tenantSchema}.inventory_components;
CREATE TRIGGER schedule_inventory_intelligence
    AFTER INSERT OR UPDATE OR DELETE ON ${tenantSchema}.inventory_components
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.schedule_inventory_correlation();

CREATE TRIGGER schedule_inventory_cpe_intelligence
    AFTER INSERT OR UPDATE OR DELETE ON ${tenantSchema}.inventory_component_cpe_map
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.schedule_inventory_correlation();
