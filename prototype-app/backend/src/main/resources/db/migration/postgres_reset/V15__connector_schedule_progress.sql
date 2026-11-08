-- migration-guard: platform-only
-- One high-water mark per saved connector configuration or source.
CREATE TABLE platform.connector_schedule_progress (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(id) ON DELETE CASCADE,
    schedule_kind text NOT NULL CHECK (schedule_kind IN ('AWS_DISCOVERY', 'GITHUB_SOURCE')),
    source_id uuid NOT NULL,
    last_occurrence_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, schedule_kind, source_id)
);
