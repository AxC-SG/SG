-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Two current CBOMs for the same asset disagree about the same cryptographic asset (same bom-ref)
-- on an important claim. Detection marks both claims CONTRADICTED-equivalent (CONFLICTING); an
-- analyst review decides which source is right or dismisses the contradiction.
CREATE TABLE ${tenantSchema}.cbom_contradictions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    asset_id uuid REFERENCES ${tenantSchema}.assets(id) ON DELETE CASCADE,
    identity varchar(1000) NOT NULL,
    claim varchar(80) NOT NULL,
    component_a_id uuid NOT NULL REFERENCES ${tenantSchema}.cbom_components(id) ON DELETE CASCADE,
    component_b_id uuid NOT NULL REFERENCES ${tenantSchema}.cbom_components(id) ON DELETE CASCADE,
    value_a text,
    value_b text,
    status varchar(16) NOT NULL DEFAULT 'OPEN',
    detected_at timestamptz NOT NULL DEFAULT now(),
    reviewed_by varchar(255),
    reviewed_at timestamptz,
    review_note text,
    version bigint NOT NULL DEFAULT 0,
    CONSTRAINT cbom_contradiction_status_check CHECK (status IN ('OPEN','ACCEPTED_A','ACCEPTED_B','DISMISSED','OBSOLETE')),
    CONSTRAINT cbom_contradiction_review_shape_check CHECK (
        (status IN ('OPEN','OBSOLETE')) OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)),
    CONSTRAINT cbom_contradiction_distinct_components CHECK (component_a_id <> component_b_id)
);
CREATE UNIQUE INDEX uk_cbom_contradictions_pair
    ON ${tenantSchema}.cbom_contradictions(component_a_id, component_b_id, claim);
CREATE INDEX idx_cbom_contradictions_status ON ${tenantSchema}.cbom_contradictions(tenant_id, status, detected_at DESC);

ALTER TABLE ${tenantSchema}.cbom_contradictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_contradictions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_contradictions
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
