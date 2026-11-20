-- Persist the latest supported release selected by EOL tenant denormalization.
ALTER TABLE ${tenantSchema}.software_instances
    ADD COLUMN IF NOT EXISTS latest_supported_version varchar(255);
ALTER TABLE ${tenantSchema}.inventory_components
    ADD COLUMN IF NOT EXISTS latest_supported_version varchar(255);
