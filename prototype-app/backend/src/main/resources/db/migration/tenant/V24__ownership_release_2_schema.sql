-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Ownership Release 2 tenant schema (Phase 0B contracts §1.8, §2.2/§2.9, §3.8, §4.11, §4.13).
-- Columns and constraints here do not depend on the R1 benchmark; if R1 changes the §3.8 index design, the fix is an
-- additive index-only migration. Nothing reads the new columns until the Release 2 producers and read waves are enabled.

-- §1.8: the CMDB support group's reference sys_id, kept next to the display name in cis.support_group.
ALTER TABLE ${tenantSchema}.cis ADD COLUMN support_group_sys_id varchar(32);
ALTER TABLE ${tenantSchema}.cis ADD CONSTRAINT cis_support_group_sys_id_check
    CHECK (support_group_sys_id ~ '^[0-9a-f]{32}$');

-- §2.2: per-tenant cloud ownership producer settings.
ALTER TABLE ${tenantSchema}.aws_discovery_configs
    ADD COLUMN ownership_owner_key_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN ownership_team_key_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN ownership_account_input_enabled boolean NOT NULL DEFAULT true;
ALTER TABLE ${tenantSchema}.gcp_discovery_configs
    ADD COLUMN ownership_owner_key_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN ownership_team_key_enabled boolean NOT NULL DEFAULT true,
    ADD COLUMN ownership_account_input_enabled boolean NOT NULL DEFAULT true;

-- §2.2.1: optional AWS Organizations role for account tags; never a discovery target role.
-- The external ID is tenant ciphertext and write-only.
ALTER TABLE ${tenantSchema}.aws_discovery_configs
    ADD COLUMN organizations_role_arn varchar(2048),
    ADD COLUMN organizations_external_id text;

-- §3.8: occurrence subjects for BOM and CBOM components.
ALTER TABLE ${tenantSchema}.inventory_components ADD COLUMN ownership_subject_id uuid;
ALTER TABLE ${tenantSchema}.inventory_components ADD CONSTRAINT inventory_components_ownership_subject_fk
    FOREIGN KEY (tenant_id, ownership_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id);
CREATE INDEX inventory_components_ownership_subject_idx ON ${tenantSchema}.inventory_components (ownership_subject_id)
    WHERE ownership_subject_id IS NOT NULL;

ALTER TABLE ${tenantSchema}.cbom_components ADD COLUMN ownership_subject_id uuid;
ALTER TABLE ${tenantSchema}.cbom_components ADD CONSTRAINT cbom_components_ownership_subject_fk
    FOREIGN KEY (tenant_id, ownership_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id);
CREATE INDEX cbom_components_ownership_subject_idx ON ${tenantSchema}.cbom_components (ownership_subject_id)
    WHERE ownership_subject_id IS NOT NULL;

-- §4.2/§4.3/§4.11: campaign scope, membership state, assignee, coordinating team and reconciler state.
-- Existing campaigns are complete; those with CVE links are CVE-scoped. The defaults only fill existing rows.
ALTER TABLE ${tenantSchema}.campaigns
    ADD COLUMN scope_kind varchar(16) NOT NULL DEFAULT 'FINDINGS',
    ADD COLUMN membership_state varchar(16) NOT NULL DEFAULT 'COMPLETE',
    ADD COLUMN assignee_principal_id uuid,
    ADD COLUMN coordinating_team_id uuid,
    ADD COLUMN reconcile_watermark jsonb,
    ADD COLUMN reconciled_at timestamptz,
    ADD COLUMN last_reconcile_added integer,
    ADD COLUMN last_reconcile_error text,
    ADD COLUMN reconcile_failures integer NOT NULL DEFAULT 0;
UPDATE ${tenantSchema}.campaigns c SET scope_kind = 'CVE'
 WHERE EXISTS (SELECT 1 FROM ${tenantSchema}.campaign_vulnerabilities v WHERE v.campaign_id = c.id);
ALTER TABLE ${tenantSchema}.campaigns
    ALTER COLUMN scope_kind DROP DEFAULT,
    ALTER COLUMN membership_state DROP DEFAULT;
ALTER TABLE ${tenantSchema}.campaigns
    ADD CONSTRAINT campaigns_scope_kind_check CHECK (scope_kind IN ('CVE','FINDINGS')),
    ADD CONSTRAINT campaigns_membership_state_check CHECK (membership_state IN ('MATERIALIZING','COMPLETE')),
    ADD CONSTRAINT campaigns_reconcile_failures_check CHECK (reconcile_failures >= 0),
    ADD CONSTRAINT campaigns_assignee_principal_fk
        FOREIGN KEY (assignee_principal_id) REFERENCES platform.app_users (id),
    ADD CONSTRAINT campaigns_coordinating_team_fk
        FOREIGN KEY (tenant_id, coordinating_team_id) REFERENCES ${tenantSchema}.team (tenant_id, id);

-- §4.4/§4.11: owner-at-add snapshot and how the member arrived. add_source is null only for rows written before
-- the ledger. The finding FK becomes tenant-inclusive and RESTRICT (§4.13): membership history is never cascaded away.
ALTER TABLE ${tenantSchema}.campaign_findings
    ADD COLUMN owner_team_id_at_add uuid,
    ADD COLUMN ownership_assignment_id_at_add uuid,
    ADD COLUMN ownership_status_at_add varchar(32),
    ADD COLUMN add_source varchar(16);
ALTER TABLE ${tenantSchema}.campaign_findings
    ADD CONSTRAINT campaign_findings_ownership_status_at_add_check
        CHECK (ownership_status_at_add IN ('OWNED','UNOWNED','CONFLICT','LEGACY_PENDING_MIGRATION')),
    ADD CONSTRAINT campaign_findings_add_source_check
        CHECK (add_source IN ('CREATE','RECONCILER','MANUAL','BACKFILL')),
    ADD CONSTRAINT campaign_findings_team_at_add_fk
        FOREIGN KEY (tenant_id, owner_team_id_at_add) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT campaign_findings_assignment_at_add_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id_at_add) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id);
ALTER TABLE ${tenantSchema}.campaign_findings DROP CONSTRAINT campaign_findings_finding_id_fkey;
ALTER TABLE ${tenantSchema}.campaign_findings ADD CONSTRAINT campaign_findings_finding_fk
    FOREIGN KEY (tenant_id, finding_id) REFERENCES ${tenantSchema}.findings (tenant_id, id) ON DELETE RESTRICT;
CREATE INDEX campaign_findings_owner_team_at_add_idx ON ${tenantSchema}.campaign_findings (campaign_id, owner_team_id_at_add);

-- §4.7: exceptions link to a member finding and snapshot its owner at request time.
ALTER TABLE ${tenantSchema}.campaign_exceptions
    ADD COLUMN finding_id uuid,
    ADD COLUMN owner_team_id_at_request uuid,
    ADD COLUMN ownership_assignment_id_at_request uuid;
ALTER TABLE ${tenantSchema}.campaign_exceptions
    ADD CONSTRAINT campaign_exceptions_finding_fk
        FOREIGN KEY (tenant_id, finding_id) REFERENCES ${tenantSchema}.findings (tenant_id, id),
    ADD CONSTRAINT campaign_exceptions_team_at_request_fk
        FOREIGN KEY (tenant_id, owner_team_id_at_request) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT campaign_exceptions_assignment_at_request_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id_at_request) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id);

-- §4.6: TEAM recipients use the team's channel; CUSTOM recipients keep a label and an encrypted address.
-- Every existing notify group is CUSTOM. group_email stays until E10 moves writers to group_email_enc.
ALTER TABLE ${tenantSchema}.campaign_notify_groups
    ADD COLUMN recipient_type varchar(16) NOT NULL DEFAULT 'CUSTOM',
    ADD COLUMN team_id uuid,
    ADD COLUMN group_email_enc text;
ALTER TABLE ${tenantSchema}.campaign_notify_groups ALTER COLUMN recipient_type DROP DEFAULT;
ALTER TABLE ${tenantSchema}.campaign_notify_groups
    ADD CONSTRAINT campaign_notify_groups_recipient_type_check CHECK (recipient_type IN ('TEAM','CUSTOM')),
    ADD CONSTRAINT campaign_notify_groups_recipient_team_check
        CHECK ((recipient_type = 'TEAM' AND team_id IS NOT NULL) OR (recipient_type = 'CUSTOM' AND team_id IS NULL)),
    ADD CONSTRAINT campaign_notify_groups_team_fk
        FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id);

-- §4.6: one encrypted notification address per team (TenantDataCipher).
ALTER TABLE ${tenantSchema}.team ADD COLUMN notification_email_enc text;

-- §4.9: ticket routing audit. Existing attempts predate routing and are LEGACY.
ALTER TABLE ${tenantSchema}.finding_ticket_attempts
    ADD COLUMN owner_team_id uuid,
    ADD COLUMN ownership_assignment_id uuid,
    ADD COLUMN assignment_group varchar(255),
    ADD COLUMN routing_source varchar(16) NOT NULL DEFAULT 'LEGACY',
    ADD COLUMN override_reason varchar(500),
    ADD COLUMN batch_id uuid;
ALTER TABLE ${tenantSchema}.finding_ticket_attempts ALTER COLUMN routing_source DROP DEFAULT;
ALTER TABLE ${tenantSchema}.finding_ticket_attempts
    ADD CONSTRAINT finding_ticket_attempts_routing_source_check
        CHECK (routing_source IN ('TEAM_MAPPING','TENANT_DEFAULT','USER_SELECTED','OVERRIDE','LEGACY')),
    ADD CONSTRAINT finding_ticket_attempts_owner_team_fk
        FOREIGN KEY (tenant_id, owner_team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT finding_ticket_attempts_assignment_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id);

-- §4.9/§4.11: explicit tenant default assignment group; ServiceNow ticketing reads servicenow_cmdb_configs.
ALTER TABLE ${tenantSchema}.servicenow_cmdb_configs ADD COLUMN default_assignment_group varchar(255);
ALTER TABLE ${tenantSchema}.jira_ticketing_configs ADD COLUMN default_assignment_group varchar(255);
