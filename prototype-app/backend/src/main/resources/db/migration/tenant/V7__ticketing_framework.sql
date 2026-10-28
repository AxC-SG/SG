-- migration-guard: tenant-only
-- Migration owners can still be subject to FORCE RLS. Bind this transaction explicitly,
-- and include ineligible intelligence rows so the backfills below see every finding.
SELECT set_config('app.current_tenant_id', '${tenantId}', true);
SELECT set_config('app.include_ineligible_intelligence', 'true', true);

-- Common ticketing framework: records which external system raised each finding's ticket,
-- tracks what Scout has already reflected on it, and adds the Jira connector configuration.

-- Which ticketing system holds findings.incident_id.
--
-- Deliberately not constrained to an enumerated list: provider keys come from
-- TicketingSystem, and adding an integration should not require a schema change. Unknown
-- values read back as "unrecognised" rather than corrupting the row.
ALTER TABLE ${tenantSchema}.findings ADD COLUMN incident_provider varchar(32);

-- Every pre-existing ticket came from ServiceNow, which was the only integration before this
-- migration. Without the backfill, status sync would have to guess, and after a tenant enables
-- Jira those historical ServiceNow incident numbers would be polled against Jira.
UPDATE ${tenantSchema}.findings
   SET incident_provider = 'servicenow'
 WHERE incident_id IS NOT NULL
   AND incident_id <> '';

CREATE INDEX idx_findings_incident_provider
    ON ${tenantSchema}.findings(tenant_id, incident_provider)
    WHERE incident_id IS NOT NULL;

-- Bidirectional sync watermark: the finding status already reflected on the ticket. The push
-- side acts only when the finding's current status differs from this, which stops the two
-- directions from ping-ponging: the pull side writes this column in the same transaction as
-- the status change it applied.
ALTER TABLE ${tenantSchema}.findings ADD COLUMN incident_pushed_status varchar(32);
ALTER TABLE ${tenantSchema}.findings ADD COLUMN incident_pushed_at timestamptz;

-- Existing tickets were created from an open finding and nothing has been pushed since, so
-- their reflected status is the status they were opened with. Leaving this NULL would make the
-- first sync push a redundant "still open" update to every historical ticket.
UPDATE ${tenantSchema}.findings
   SET incident_pushed_status = status
 WHERE incident_id IS NOT NULL
   AND incident_id <> '';

-- Drives the push scan: findings that carry a ticket whose reflected status has drifted.
CREATE INDEX idx_findings_incident_push_pending
    ON ${tenantSchema}.findings(tenant_id, status, incident_pushed_status)
    WHERE incident_id IS NOT NULL;

CREATE TABLE ${tenantSchema}.jira_ticketing_configs (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    base_url varchar(1000),
    auth_type varchar(32) NOT NULL DEFAULT 'BASIC',
    username varchar(255),
    -- Encrypted envelope (CredentialEncryptionService); text so key-versioned values never truncate.
    credential_secret text,
    project_key varchar(64),
    issue_type_id varchar(64),
    issue_type_name varchar(128) DEFAULT 'Task',
    default_labels varchar(1000),
    include_priority boolean NOT NULL DEFAULT true,
    enabled boolean NOT NULL DEFAULT true,
    last_test_status varchar(64),
    last_test_message varchar(2000),
    last_tested_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- One Jira connector per tenant: the active-provider resolution has no way to choose
    -- between two, and a second row would silently shadow the first.
    CONSTRAINT uk_jira_ticketing_configs_tenant UNIQUE (tenant_id),
    CONSTRAINT jira_ticketing_configs_auth_type_check
        CHECK (auth_type IN ('BASIC', 'BEARER'))
);

CREATE INDEX idx_jira_ticketing_configs_enabled
    ON ${tenantSchema}.jira_ticketing_configs(tenant_id, enabled);

ALTER TABLE ${tenantSchema}.jira_ticketing_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.jira_ticketing_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.jira_ticketing_configs
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
