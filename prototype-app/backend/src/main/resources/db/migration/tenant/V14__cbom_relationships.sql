-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

CREATE TABLE ${tenantSchema}.cbom_relationships (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    source_bom_id uuid NOT NULL REFERENCES ${tenantSchema}.bom_ingestion_records(id) ON DELETE CASCADE,
    source_type varchar(40) NOT NULL,
    source_id uuid NOT NULL,
    target_type varchar(40) NOT NULL,
    target_id uuid NOT NULL,
    relationship_type varchar(60) NOT NULL,
    evidence_kind varchar(20) NOT NULL,
    confidence numeric(6,5),
    evidence_summary text,
    valid_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT cbom_relationship_evidence_kind_check CHECK (evidence_kind IN ('DECLARED','OBSERVED')),
    CONSTRAINT cbom_relationship_confidence_check CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    CONSTRAINT cbom_relationship_no_self_loop CHECK (source_type <> target_type OR source_id <> target_id),
    CONSTRAINT cbom_relationship_unique UNIQUE
        (tenant_id, source_bom_id, source_type, source_id, target_type, target_id, relationship_type, evidence_kind)
);
CREATE INDEX idx_cbom_relationship_source
    ON ${tenantSchema}.cbom_relationships(tenant_id, source_type, source_id, relationship_type);
CREATE INDEX idx_cbom_relationship_target
    ON ${tenantSchema}.cbom_relationships(tenant_id, target_type, target_id, relationship_type);

ALTER TABLE ${tenantSchema}.cbom_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_relationships
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
