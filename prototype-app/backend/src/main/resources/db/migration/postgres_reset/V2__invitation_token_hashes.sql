-- migration-guard: platform-only
-- Retire legacy URL-path bearer links while preserving invitation history.
ALTER TABLE platform.tenant_user_invites
    ADD COLUMN token_hash varchar(64);

UPDATE platform.tenant_user_invites
SET token_hash = encode(sha256(convert_to(token, 'UTF8')), 'hex'),
    status = CASE WHEN accepted_at IS NULL AND status NOT IN ('CANCELLED', 'EXPIRED')
                  THEN 'EXPIRED' ELSE status END,
    expires_at = CASE WHEN accepted_at IS NULL THEN LEAST(expires_at, now()) ELSE expires_at END,
    updated_at = now();

ALTER TABLE platform.tenant_user_invites ALTER COLUMN token DROP NOT NULL;
UPDATE platform.tenant_user_invites SET token = NULL;
ALTER TABLE platform.tenant_user_invites
    ALTER COLUMN token_hash SET NOT NULL,
    ADD CONSTRAINT tenant_user_invites_token_hash_unique UNIQUE (token_hash),
    ADD CONSTRAINT tenant_user_invites_no_raw_token CHECK (token IS NULL),
    ADD CONSTRAINT tenant_user_invites_token_hash_format CHECK (token_hash ~ '^[0-9a-f]{64}$');
