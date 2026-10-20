-- migration-guard: platform-only
-- Durable platform work retains its original scope and accepted payload.
ALTER TABLE platform.sync_runs ADD COLUMN claim_token uuid;
ALTER TABLE platform.sync_runs ADD COLUMN lease_expires_at timestamptz;
ALTER TABLE platform.sync_runs ADD COLUMN heartbeat_at timestamptz;
ALTER TABLE platform.sync_runs ADD COLUMN attempt_count integer NOT NULL DEFAULT 0;
UPDATE platform.sync_runs SET lease_expires_at=now()+interval '2 minutes'
 WHERE lower(status)='running' AND run_scope='PLATFORM_VULNERABILITY' AND tenant_id IS NULL;
CREATE INDEX sync_runs_owned_claim_idx ON platform.sync_runs (lease_expires_at,id)
 WHERE run_scope='PLATFORM_VULNERABILITY' AND tenant_id IS NULL AND lower(status)='running';

ALTER TABLE platform.ai_grid_policy_rollout_tasks ADD COLUMN claim_token uuid;
ALTER TABLE platform.ai_grid_policy_rollout_tasks ADD COLUMN lease_expires_at timestamptz;
ALTER TABLE platform.ai_grid_policy_rollout_tasks ADD COLUMN assessment_request_id uuid;

ALTER TABLE platform.ai_grid_policy_deprecation_tasks ADD COLUMN claim_token uuid;
ALTER TABLE platform.ai_grid_policy_deprecation_tasks ADD COLUMN lease_expires_at timestamptz;
-- Give work accepted by the previous binary a grace period before recovery.
UPDATE platform.ai_grid_policy_deprecation_tasks SET lease_expires_at=now()+interval '2 minutes'
 WHERE state='PROCESSING';
CREATE INDEX ai_grid_policy_deprecation_expiry_idx
 ON platform.ai_grid_policy_deprecation_tasks(lease_expires_at,id) WHERE state='PROCESSING';

-- Invitation delivery is a platform/pre-authentication responsibility. Payloads
-- containing bearer material are encrypted, independent of hashed invite records.
CREATE TABLE platform.invitation_email_outbox (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
 delivery_type varchar(32) NOT NULL, related_id uuid NOT NULL, token_hash varchar(64) NOT NULL,
 encrypted_payload text NOT NULL, status varchar(32) NOT NULL DEFAULT 'PENDING',
 attempt_count integer NOT NULL DEFAULT 0, visible_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), first_attempt_at timestamptz,
 last_attempt_at timestamptz, claim_token uuid, lease_expires_at timestamptz,
 provider_message_id varchar(255), last_error_code varchar(64),
 UNIQUE(delivery_type,related_id,token_hash),
 CHECK(status IN ('PENDING','PROCESSING','ACCEPTED','FAILED','UNKNOWN','CANCELLED'))
);
CREATE INDEX invitation_email_outbox_pending_idx ON platform.invitation_email_outbox(visible_at,id)
 WHERE status IN ('PENDING','PROCESSING');


-- Keep newly fetched canonical content in PostgreSQL while local archiving is disabled.
ALTER TABLE platform.vulnerabilities ADD COLUMN description_text text;
ALTER TABLE platform.vulnerabilities ADD COLUMN raw_payload_text text;

ALTER TABLE platform.invitation_email_outbox ADD COLUMN reconciled_by varchar(255);
ALTER TABLE platform.invitation_email_outbox ADD COLUMN reconciled_at timestamptz;
ALTER TABLE platform.invitation_email_outbox ADD COLUMN reconciliation_note varchar(500);
