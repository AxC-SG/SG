-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Generic pending suppression decisions. Canonical findings continue to own the applied
-- suppression; this table owns requester/decision state and optimistic concurrency.
CREATE TABLE ${tenantSchema}.finding_suppression_requests (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    finding_id uuid NOT NULL REFERENCES ${tenantSchema}.findings(id) ON DELETE CASCADE,
    finding_kind varchar(32) NOT NULL,
    severity_at_request varchar(32),
    requested_by varchar(255) NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now(),
    decision_due_at timestamptz NOT NULL,
    reason text NOT NULL,
    compensating_control text NOT NULL,
    proposed_suppressed_until timestamptz NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'REQUESTED',
    decided_by varchar(255),
    decided_at timestamptz,
    decision_reason text,
    applied_event_id uuid REFERENCES ${tenantSchema}.finding_events(id) ON DELETE SET NULL,
    version bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT finding_suppression_requests_status_check
        CHECK (status IN ('REQUESTED','APPROVED','REJECTED','CANCELLED','EXPIRED')),
    CONSTRAINT finding_suppression_requests_decision_shape_check CHECK (
        (status = 'REQUESTED' AND decided_by IS NULL AND decided_at IS NULL)
        OR
        (status <> 'REQUESTED' AND decided_at IS NOT NULL)
    ),
    CONSTRAINT finding_suppression_requests_deadline_check
        CHECK (decision_due_at > requested_at),
    CONSTRAINT finding_suppression_requests_expiry_check
        CHECK (proposed_suppressed_until > requested_at)
);

CREATE UNIQUE INDEX uk_finding_suppression_requests_active
    ON ${tenantSchema}.finding_suppression_requests(finding_id)
    WHERE status = 'REQUESTED';
CREATE INDEX idx_finding_suppression_requests_due
    ON ${tenantSchema}.finding_suppression_requests(status, decision_due_at, id);
CREATE INDEX idx_finding_suppression_requests_tenant_status
    ON ${tenantSchema}.finding_suppression_requests(tenant_id, status, updated_at DESC);

ALTER TABLE ${tenantSchema}.finding_suppression_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.finding_suppression_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.finding_suppression_requests
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

-- CRYPTO-only governance settings. Application maxima remain immutable; tenants can only
-- shorten these values.
CREATE TABLE ${tenantSchema}.cbom_tenant_settings (
    tenant_id uuid PRIMARY KEY DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    require_distinct_suppression_approver boolean NOT NULL DEFAULT false,
    suppression_request_deadline_days integer NOT NULL DEFAULT 14,
    low_suppression_max_days integer NOT NULL DEFAULT 365,
    medium_suppression_max_days integer NOT NULL DEFAULT 180,
    high_suppression_max_days integer NOT NULL DEFAULT 90,
    critical_suppression_max_days integer NOT NULL DEFAULT 30,
    updated_by varchar(255) NOT NULL DEFAULT 'system',
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    CONSTRAINT cbom_settings_request_deadline_check
        CHECK (suppression_request_deadline_days BETWEEN 1 AND 14),
    CONSTRAINT cbom_settings_low_max_check CHECK (low_suppression_max_days BETWEEN 1 AND 365),
    CONSTRAINT cbom_settings_medium_max_check CHECK (medium_suppression_max_days BETWEEN 1 AND 180),
    CONSTRAINT cbom_settings_high_max_check CHECK (high_suppression_max_days BETWEEN 1 AND 90),
    CONSTRAINT cbom_settings_critical_max_check CHECK (critical_suppression_max_days BETWEEN 1 AND 30)
);

ALTER TABLE ${tenantSchema}.cbom_tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.cbom_tenant_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.cbom_tenant_settings
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
