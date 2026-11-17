-- Small control-plane index for pending tenant catalog work. No vulnerability data lives here.
CREATE TABLE platform.tenant_catalog_build_queue (
    tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id),
    build_id uuid NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('PENDING','READY','STALE','CANCELLED','FAILED')),
    available_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenant_catalog_build_queue_pending
    ON platform.tenant_catalog_build_queue(available_at,updated_at,tenant_id) WHERE status='PENDING';
