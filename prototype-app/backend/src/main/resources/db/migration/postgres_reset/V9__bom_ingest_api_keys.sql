-- migration-guard: platform-only
-- Tenant-scoped credentials that can only push BOM documents from a pipeline. The secret is never
-- stored: a lookup prefix and a SHA-256 of the secret are. The table is in the platform schema
-- because the tenant has to be identified from the credential before any tenant schema is reachable.
CREATE TABLE platform.bom_ingest_api_keys (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id) ON DELETE CASCADE,
 name character varying(120) NOT NULL,
 key_prefix character varying(16) NOT NULL,
 key_hash character(64) NOT NULL,
 scope character varying(40) NOT NULL DEFAULT 'bom:ingest',
 created_by character varying(255) NOT NULL,
 created_at timestamp with time zone NOT NULL DEFAULT now(),
 expires_at timestamp with time zone,
 last_used_at timestamp with time zone,
 revoked_at timestamp with time zone,
 CONSTRAINT bom_ingest_api_keys_scope_check CHECK (scope = 'bom:ingest'),
 CONSTRAINT bom_ingest_api_keys_prefix_key UNIQUE (key_prefix)
);
CREATE INDEX bom_ingest_api_keys_tenant_idx ON platform.bom_ingest_api_keys (tenant_id, created_at DESC);
