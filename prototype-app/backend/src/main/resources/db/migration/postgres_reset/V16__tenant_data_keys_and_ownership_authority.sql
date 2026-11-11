-- migration-guard: platform-only
-- Ownership MVP Release 1 platform foundation (docs/ownership-phase-0a-design.md §1, §2, §8).
--
-- tenant_data_keys: per-tenant data-encryption keys, stored only wrapped by the configured key
-- wrapper (KMS in deployed environments). Plaintext keys never reach the database. Exactly one
-- ACTIVE version per tenant encrypts new values; DECRYPT_ONLY versions remain readable until they
-- are re-enveloped. Deleting a tenant removes its wrapped keys, which crypto-shreds its PII.
CREATE TABLE platform.tenant_data_keys (
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id) ON DELETE CASCADE,
 key_version integer NOT NULL,
 wrapper_kind character varying(32) NOT NULL,
 kms_key_ref character varying(512) NOT NULL,
 wrapped_dek bytea,
 state character varying(16) NOT NULL,
 created_at timestamp with time zone NOT NULL DEFAULT now(),
 rotated_at timestamp with time zone,
 CONSTRAINT tenant_data_keys_pkey PRIMARY KEY (tenant_id, key_version),
 CONSTRAINT tenant_data_keys_version_check CHECK (key_version > 0),
 CONSTRAINT tenant_data_keys_wrapper_check CHECK (wrapper_kind IN ('LOCAL','AWS_KMS')),
 CONSTRAINT tenant_data_keys_state_check CHECK (state IN ('ACTIVE','DECRYPT_ONLY','DESTROYED')),
 CONSTRAINT tenant_data_keys_material_check CHECK (state = 'DESTROYED' OR wrapped_dek IS NOT NULL)
);
CREATE UNIQUE INDEX tenant_data_keys_one_active_idx ON platform.tenant_data_keys (tenant_id) WHERE state = 'ACTIVE';

-- ownership_domain_authority: which writer is authoritative for each tenant and migration domain.
-- A missing row means LEGACY. CANONICAL requires a recorded acceptance (plan §15.3 step 5).
CREATE TABLE platform.ownership_domain_authority (
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id) ON DELETE CASCADE,
 domain character varying(32) NOT NULL,
 state character varying(16) NOT NULL DEFAULT 'LEGACY',
 accepted_by character varying(255),
 accepted_at timestamp with time zone,
 updated_by character varying(255),
 updated_at timestamp with time zone NOT NULL DEFAULT now(),
 CONSTRAINT ownership_domain_authority_pkey PRIMARY KEY (tenant_id, domain),
 CONSTRAINT ownership_domain_authority_domain_check CHECK (domain IN ('CORE','CLOUD_BOM','AI_GRID')),
 CONSTRAINT ownership_domain_authority_state_check CHECK (state IN ('LEGACY','DARK','CANONICAL')),
 CONSTRAINT ownership_domain_authority_acceptance_check CHECK (state <> 'CANONICAL' OR (accepted_by IS NOT NULL AND accepted_at IS NOT NULL))
);

-- ownership_kill_switches: operator pause for an ownership source kind, globally (tenant_id NULL)
-- or for one tenant. A row in PAUSED state stops publication from that source kind.
CREATE TABLE platform.ownership_kill_switches (
 id uuid PRIMARY KEY,
 source_kind character varying(40) NOT NULL,
 tenant_id uuid REFERENCES platform.tenants(id) ON DELETE CASCADE,
 state character varying(16) NOT NULL,
 reason character varying(500) NOT NULL,
 updated_by character varying(255) NOT NULL,
 updated_at timestamp with time zone NOT NULL DEFAULT now(),
 CONSTRAINT ownership_kill_switches_state_check CHECK (state IN ('ACTIVE','PAUSED')),
 CONSTRAINT ownership_kill_switches_source_check CHECK (source_kind IN ('MANUAL','CSV','SERVICENOW','ENTRA','OKTA','AWS','GCP','AI_GRID'))
);
CREATE UNIQUE INDEX ownership_kill_switches_scope_idx
 ON platform.ownership_kill_switches (source_kind, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));
