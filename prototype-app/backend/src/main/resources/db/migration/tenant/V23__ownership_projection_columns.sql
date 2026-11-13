-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Ownership MVP Release 1: additive projection and snapshot columns (plan §7.3, §7.5; design §1).
-- Expand-only: nothing reads these until the per-domain authority switch and consumer read waves (§15.3–15.4).
-- Owner display names are never stored here; readers join team at read time.

-- Candidate keys so ownership/exception references to assets and findings can be tenant-inclusive.
ALTER TABLE ${tenantSchema}.assets ADD CONSTRAINT assets_tenant_key UNIQUE (tenant_id, id);
ALTER TABLE ${tenantSchema}.findings ADD CONSTRAINT findings_tenant_key UNIQUE (tenant_id, id);

-- Inventory projection: the canonical ownership subject for this asset.
ALTER TABLE ${tenantSchema}.assets ADD COLUMN ownership_subject_id uuid;
ALTER TABLE ${tenantSchema}.assets ADD CONSTRAINT assets_ownership_subject_fk
    FOREIGN KEY (tenant_id, ownership_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id);
CREATE INDEX assets_ownership_subject_idx ON ${tenantSchema}.assets (ownership_subject_id) WHERE ownership_subject_id IS NOT NULL;

-- Finding projection: the subject the finding's ownership derives from (vulnerability adapter v1: the affected
-- asset's subject), and the person working it. Tenant membership of the assignee is enforced by the writer.
ALTER TABLE ${tenantSchema}.findings ADD COLUMN ownership_subject_id uuid;
ALTER TABLE ${tenantSchema}.findings ADD COLUMN assignee_principal_id uuid;
ALTER TABLE ${tenantSchema}.findings ADD CONSTRAINT findings_ownership_subject_fk
    FOREIGN KEY (tenant_id, ownership_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id);
ALTER TABLE ${tenantSchema}.findings ADD CONSTRAINT findings_assignee_principal_fk
    FOREIGN KEY (assignee_principal_id) REFERENCES platform.app_users (id);
CREATE INDEX findings_ownership_subject_idx ON ${tenantSchema}.findings (ownership_subject_id, status) WHERE ownership_subject_id IS NOT NULL;
CREATE INDEX findings_assignee_principal_idx ON ${tenantSchema}.findings (assignee_principal_id, status) WHERE assignee_principal_id IS NOT NULL;

-- Exception owner snapshots (§7.3): stable IDs captured when a suppression is requested and when it is decided.
-- Audit attribution only; never ownership evidence. Null for historical/system rows with no resolved owner.
ALTER TABLE ${tenantSchema}.finding_suppression_requests
    ADD COLUMN owner_team_id_at_request uuid,
    ADD COLUMN ownership_assignment_id_at_request uuid,
    ADD COLUMN owner_team_id_at_decision uuid,
    ADD COLUMN ownership_assignment_id_at_decision uuid;
ALTER TABLE ${tenantSchema}.finding_suppression_requests
    ADD CONSTRAINT finding_suppression_requests_team_at_request_fk
        FOREIGN KEY (tenant_id, owner_team_id_at_request) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT finding_suppression_requests_assignment_at_request_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id_at_request) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id),
    ADD CONSTRAINT finding_suppression_requests_team_at_decision_fk
        FOREIGN KEY (tenant_id, owner_team_id_at_decision) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT finding_suppression_requests_assignment_at_decision_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id_at_decision) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id);

-- Direct suppression, false-positive and accepted-risk decisions are recorded as finding_events; the snapshot
-- travels with the immutable event rather than with any ownership table.
ALTER TABLE ${tenantSchema}.finding_events
    ADD COLUMN owner_team_id uuid,
    ADD COLUMN ownership_assignment_id uuid;
ALTER TABLE ${tenantSchema}.finding_events
    ADD CONSTRAINT finding_events_owner_team_fk
        FOREIGN KEY (tenant_id, owner_team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    ADD CONSTRAINT finding_events_ownership_assignment_fk
        FOREIGN KEY (tenant_id, ownership_assignment_id) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id);

-- CSV templates for teams and aliases (plan §6.3) are import runs too.
ALTER TABLE ${tenantSchema}.identity_import_run DROP CONSTRAINT identity_import_run_kind_check;
ALTER TABLE ${tenantSchema}.identity_import_run ADD CONSTRAINT identity_import_run_kind_check
    CHECK (kind IN ('CSV_USERS','CSV_GROUPS','CSV_MEMBERSHIPS','CSV_TEAMS','CSV_TEAM_ALIASES','PROVIDER_SYNC'));
