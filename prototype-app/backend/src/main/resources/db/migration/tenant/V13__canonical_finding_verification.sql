-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

ALTER TABLE ${tenantSchema}.findings
    ADD COLUMN workflow_substate varchar(40),
    ADD COLUMN target_state varchar(80),
    ADD COLUMN verification_required boolean NOT NULL DEFAULT false,
    ADD COLUMN verification_status varchar(24) NOT NULL DEFAULT 'NOT_REQUIRED',
    ADD COLUMN verification_evidence text,
    ADD COLUMN verification_requested_at timestamptz,
    ADD COLUMN verification_completed_at timestamptz,
    ADD COLUMN verification_actor varchar(255),
    ADD CONSTRAINT findings_verification_status_check
        CHECK (verification_status IN ('NOT_REQUIRED','REQUESTED','ACCEPTED','REJECTED')),
    ADD CONSTRAINT findings_verification_consistency_check
        CHECK (verification_required OR verification_status = 'NOT_REQUIRED');

CREATE INDEX idx_findings_verification_queue
    ON ${tenantSchema}.findings(verification_status, due_at)
    WHERE verification_required = true AND status = 'OPEN';
