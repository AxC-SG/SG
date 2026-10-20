-- migration-guard: platform-only
-- A completed or failed occurrence remains deduplicated after a process restart.
CREATE UNIQUE INDEX sync_runs_schedule_occurrence_idx
 ON platform.sync_runs ((metadata_json::jsonb->>'scheduleOccurrence'))
 WHERE run_scope='PLATFORM_VULNERABILITY' AND tenant_id IS NULL
   AND metadata_json::jsonb->>'scheduleOccurrence' IS NOT NULL;

-- This is scheduling progress, not customer evidence or delivery history.
CREATE TABLE platform.copilot_schedule_progress (
 tenant_id uuid NOT NULL REFERENCES platform.tenants(id) ON DELETE CASCADE,
 connector_id uuid NOT NULL,
 last_occurrence_at timestamptz,
 last_job_id uuid,
 PRIMARY KEY (tenant_id, connector_id)
);
