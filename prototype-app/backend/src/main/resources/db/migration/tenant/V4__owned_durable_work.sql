SELECT set_config('app.current_tenant_id', '${tenantId}', true);
-- Preserve existing queue contracts while making each recoverable attempt explicit.
ALTER TABLE ${tenantSchema}.ingestion_jobs ADD COLUMN claim_token uuid;
ALTER TABLE ${tenantSchema}.ingestion_jobs ADD COLUMN lease_expires_at timestamptz;
ALTER TABLE ${tenantSchema}.ingestion_jobs ADD COLUMN heartbeat_at timestamptz;
CREATE INDEX ingestion_jobs_expired_attempt_idx
    ON ${tenantSchema}.ingestion_jobs (lease_expires_at, id) WHERE status = 'RUNNING';

-- Existing revisions must be drained before release qualification. A legacy running
-- row is not reset merely because a new process starts; give it an explicit grace.
UPDATE ${tenantSchema}.ingestion_jobs SET lease_expires_at = now() + interval '2 minutes'
 WHERE status = 'RUNNING' AND lease_expires_at IS NULL;

-- Old split admission could leave a source claimed without an executable job.
-- Keep its evidence and make it eligible again rather than inventing an accepted job.
UPDATE ${tenantSchema}.github_sbom_sources source
   SET last_run_status = 'DEFERRED',
       last_error = 'Previous admission has no active durable job; eligible for retry'
 WHERE upper(last_run_status) IN ('QUEUED', 'RUNNING')
   AND NOT EXISTS (SELECT 1 FROM ${tenantSchema}.ingestion_jobs job
                    WHERE job.status IN ('QUEUED','RUNNING')
                      AND job.payload_json::jsonb->>'sourceId' = source.id::text);

-- Campaign delivery stays in its customer schema and uses the existing delivery
-- attempt as its logical identity; it is never merged with platform invitations.
CREATE TABLE ${tenantSchema}.campaign_email_outbox (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES platform.tenants(id),
 delivery_attempt_id uuid NOT NULL UNIQUE REFERENCES ${tenantSchema}.campaign_delivery_attempts(id),
 encrypted_payload text NOT NULL, status varchar(32) NOT NULL DEFAULT 'PENDING',
 attempt_count integer NOT NULL DEFAULT 0, visible_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(), first_attempt_at timestamptz,
 last_attempt_at timestamptz, claim_token uuid, lease_expires_at timestamptz,
 provider_message_id varchar(255), last_error_code varchar(64),
 CHECK(status IN ('PENDING','PROCESSING','ACCEPTED','FAILED','UNKNOWN','CANCELLED'))
);
ALTER TABLE ${tenantSchema}.campaign_email_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.campaign_email_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.campaign_email_outbox
 USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
 WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);
CREATE INDEX campaign_email_outbox_pending_idx ON ${tenantSchema}.campaign_email_outbox(visible_at,id)
 WHERE status IN ('PENDING','PROCESSING');

-- Queued and uncertain email remain part of the existing active demo request identity.
DROP INDEX ${tenantSchema}.uk_demo_requests_active_email;
CREATE UNIQUE INDEX uk_demo_requests_active_email ON ${tenantSchema}.demo_requests(lower(email))
 WHERE status IN ('PENDING','QUEUED','SENT','ERROR','DELIVERY_UNKNOWN','DELIVERY_ERROR');

ALTER TABLE ${tenantSchema}.campaign_email_outbox ADD COLUMN reconciled_by varchar(255);
ALTER TABLE ${tenantSchema}.campaign_email_outbox ADD COLUMN reconciled_at timestamptz;
ALTER TABLE ${tenantSchema}.campaign_email_outbox ADD COLUMN reconciliation_note varchar(500);
