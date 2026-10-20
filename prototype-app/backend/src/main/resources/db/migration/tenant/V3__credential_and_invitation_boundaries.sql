-- Hash and retire old path links without retaining their raw bearer values.
-- Migration owners can still be subject to FORCE RLS. Bind this transaction
-- explicitly, including when the standalone bootstrap uses its raw pool.
SELECT set_config('app.current_tenant_id', '${tenantId}', true);
-- Shared demo invitations reference customer IDs rather than the template ID.
-- Flyway runs this migration in one transaction; the owner-only bypass and table
-- lock therefore end atomically with conversion, or roll back together on error.
ALTER TABLE ${tenantSchema}.demo_invites NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.demo_invites ADD COLUMN token_hash varchar(64);
UPDATE ${tenantSchema}.demo_invites
SET token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex'),
    status = CASE WHEN accepted_at IS NULL AND status NOT IN ('CANCELLED', 'EXPIRED')
                  THEN 'EXPIRED' ELSE status END,
    expires_at = CASE WHEN accepted_at IS NULL THEN LEAST(expires_at, now()) ELSE expires_at END;
ALTER TABLE ${tenantSchema}.demo_invites ALTER COLUMN token DROP NOT NULL;
UPDATE ${tenantSchema}.demo_invites SET token = NULL;
ALTER TABLE ${tenantSchema}.demo_invites
    ALTER COLUMN token_hash SET NOT NULL,
    ADD CONSTRAINT demo_invites_token_hash_unique UNIQUE (token_hash),
    ADD CONSTRAINT demo_invites_no_raw_token CHECK (token IS NULL),
    ADD CONSTRAINT demo_invites_token_hash_format CHECK (token_hash ~ '^[0-9a-f]{64}$');
ALTER TABLE ${tenantSchema}.demo_invites FORCE ROW LEVEL SECURITY;

-- Versioned AES-GCM envelopes must not be constrained by the former plaintext size.
ALTER TABLE ${tenantSchema}.aws_discovery_configs ALTER COLUMN credential_secret TYPE text;
ALTER TABLE ${tenantSchema}.sccm_cmdb_configs ALTER COLUMN credential_secret TYPE text;
ALTER TABLE ${tenantSchema}.servicenow_cmdb_configs ALTER COLUMN credential_secret TYPE text;

-- Existing caller-controlled ExternalIds are not a verified server binding.
-- Keep these connectors disabled until an explicit save/reconnect establishes one.
ALTER TABLE ${tenantSchema}.aws_discovery_configs
    ADD COLUMN credential_binding_version integer NOT NULL DEFAULT 0;
ALTER TABLE ${tenantSchema}.aws_discovery_targets
    ADD COLUMN credential_binding_version integer NOT NULL DEFAULT 0;
ALTER TABLE ${tenantSchema}.ai_security_connector_configs
    ADD COLUMN credential_binding_version integer NOT NULL DEFAULT 0;
UPDATE ${tenantSchema}.aws_discovery_configs SET enabled = false, auto_sync_enabled = false;
UPDATE ${tenantSchema}.aws_discovery_targets SET enabled = false;
UPDATE ${tenantSchema}.ai_security_connector_configs SET enabled = false WHERE provider = 'AWS';
