CREATE TABLE ${tenantSchema}.bom_upload_intents (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES platform.tenants (id),
    actor_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    metadata jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    object_version text,
    job_id uuid REFERENCES ${tenantSchema}.ingestion_jobs (id),
    UNIQUE (tenant_id, actor_id, idempotency_key),
    UNIQUE (job_id),
    CHECK ((object_version IS NULL) = (job_id IS NULL))
);

CREATE INDEX bom_upload_intents_pending_expiry_idx
    ON ${tenantSchema}.bom_upload_intents (tenant_id, expires_at)
    WHERE job_id IS NULL;

ALTER TABLE ${tenantSchema}.bom_upload_intents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.bom_upload_intents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.bom_upload_intents
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
