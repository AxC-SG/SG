-- migration-guard: platform-only
-- Durable, multi-instance lease for the CBOM rule-package rollout reconciler. One row per
-- package version. The owner heartbeats while it works and commits a tenant cursor after each
-- tenant, so a new owner resumes from the cursor after lease expiry. This is operational safety
-- state, not policy approval: tenant selection and pinning stay in tenant schemas.
CREATE TABLE platform.cbom_rule_rollout_leases (
 package_key character varying(200) PRIMARY KEY,
 owner character varying(200),
 lease_expires_at timestamp with time zone,
 heartbeat_at timestamp with time zone,
 stage character varying(16) NOT NULL,
 cursor_tenant_id uuid,
 completed_stage character varying(16),
 tenants_processed bigint NOT NULL DEFAULT 0,
 jobs_enqueued bigint NOT NULL DEFAULT 0,
 updated_at timestamp with time zone NOT NULL DEFAULT now(),
 CONSTRAINT cbom_rule_rollout_leases_stage_check CHECK (stage IN ('OBSERVE','CANARY','BATCHED','GENERAL')),
 CONSTRAINT cbom_rule_rollout_leases_completed_check CHECK (completed_stage IS NULL OR completed_stage IN ('OBSERVE','CANARY','BATCHED','GENERAL'))
);
