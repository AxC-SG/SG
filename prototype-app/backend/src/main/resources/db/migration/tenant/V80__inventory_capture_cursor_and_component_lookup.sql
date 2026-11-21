-- migration-guard: tenant-only
ALTER TABLE ${tenantSchema}.sccm_inventory_captures ADD COLUMN last_install_key text;

CREATE INDEX idx_software_instances_inventory_component
    ON ${tenantSchema}.software_instances (inventory_component_id);
