-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Ownership MVP Release 1: identity and teams (plan §7.1, docs/ownership-phase-0a-design.md §1, §3).
-- Directory users and groups are observations about people; they never grant Scoutgrid access.
-- PII columns (*_enc) hold TenantDataCipher ciphertext (enc:t1:...). Exact lookups use tenant-keyed
-- HMAC blind indexes (*_index); prefix search uses HMAC tokens in directory_search_token. Every
-- cross-row reference is tenant-inclusive and nothing cascades across rows.

CREATE TABLE ${tenantSchema}.identity_source (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    kind varchar(16) NOT NULL,
    display_name varchar(200) NOT NULL,
    credentials_enc text,
    scope_config jsonb NOT NULL DEFAULT '{}'::jsonb,
    mapping_config jsonb NOT NULL DEFAULT '{}'::jsonb,
    sync_cursor text,
    schedule varchar(64),
    state varchar(16) NOT NULL DEFAULT 'DISABLED',
    health varchar(16) NOT NULL DEFAULT 'UNKNOWN',
    last_success_at timestamptz,
    last_error varchar(1000),
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT identity_source_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT identity_source_kind_check CHECK (kind IN ('MANUAL','CSV','SERVICENOW','ENTRA','OKTA')),
    CONSTRAINT identity_source_state_check CHECK (state IN ('DISABLED','ENABLED','PAUSED','ERROR')),
    CONSTRAINT identity_source_health_check CHECK (health IN ('UNKNOWN','HEALTHY','DEGRADED','FAILING')),
    CONSTRAINT identity_source_credentials_check CHECK (credentials_enc IS NULL OR credentials_enc LIKE 'enc:t1:%')
);
CREATE UNIQUE INDEX identity_source_one_manual_idx ON ${tenantSchema}.identity_source (tenant_id) WHERE kind = 'MANUAL';

CREATE TABLE ${tenantSchema}.identity_import_run (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    kind varchar(24) NOT NULL,
    state varchar(16) NOT NULL DEFAULT 'QUEUED',
    file_sha256 char(64),
    rows_total integer NOT NULL DEFAULT 0,
    rows_created integer NOT NULL DEFAULT 0,
    rows_updated integer NOT NULL DEFAULT 0,
    rows_unchanged integer NOT NULL DEFAULT 0,
    rows_rejected integer NOT NULL DEFAULT 0,
    cursor_start text,
    cursor_end text,
    error_summary varchar(2000),
    actor varchar(255) NOT NULL,
    started_at timestamptz,
    finished_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT identity_import_run_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT identity_import_run_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT identity_import_run_kind_check CHECK (kind IN ('CSV_USERS','CSV_GROUPS','CSV_MEMBERSHIPS','PROVIDER_SYNC')),
    CONSTRAINT identity_import_run_state_check CHECK (state IN ('QUEUED','RUNNING','VALIDATED','APPLIED','PARTIAL','FAILED','CANCELLED')),
    CONSTRAINT identity_import_run_counts_check CHECK (rows_total >= 0 AND rows_created >= 0 AND rows_updated >= 0 AND rows_unchanged >= 0 AND rows_rejected >= 0)
);
CREATE INDEX identity_import_run_source_idx ON ${tenantSchema}.identity_import_run (source_id, created_at DESC);

CREATE TABLE ${tenantSchema}.directory_user (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    display_name_enc text NOT NULL,
    email_enc text,
    email_index bytea,
    employee_id_enc text,
    employee_id_index bytea,
    manager_user_id uuid,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    created_source_id uuid NOT NULL,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT directory_user_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT directory_user_manager_fk FOREIGN KEY (tenant_id, manager_user_id) REFERENCES ${tenantSchema}.directory_user (tenant_id, id),
    CONSTRAINT directory_user_source_fk FOREIGN KEY (tenant_id, created_source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT directory_user_status_check CHECK (status IN ('ACTIVE','INACTIVE','DELETED')),
    CONSTRAINT directory_user_not_own_manager CHECK (manager_user_id IS NULL OR manager_user_id <> id),
    CONSTRAINT directory_user_enc_check CHECK (display_name_enc LIKE 'enc:t1:%' AND (email_enc IS NULL OR email_enc LIKE 'enc:t1:%') AND (employee_id_enc IS NULL OR employee_id_enc LIKE 'enc:t1:%')),
    CONSTRAINT directory_user_email_index_check CHECK ((email_enc IS NULL) = (email_index IS NULL)),
    CONSTRAINT directory_user_employee_index_check CHECK ((employee_id_enc IS NULL) = (employee_id_index IS NULL))
);
CREATE INDEX directory_user_email_idx ON ${tenantSchema}.directory_user (email_index) WHERE email_index IS NOT NULL;
CREATE INDEX directory_user_employee_idx ON ${tenantSchema}.directory_user (employee_id_index) WHERE employee_id_index IS NOT NULL;
CREATE INDEX directory_user_manager_idx ON ${tenantSchema}.directory_user (manager_user_id) WHERE manager_user_id IS NOT NULL;

CREATE TABLE ${tenantSchema}.directory_group (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    display_name varchar(255) NOT NULL,
    name_key varchar(255) NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    created_source_id uuid NOT NULL,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT directory_group_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT directory_group_source_fk FOREIGN KEY (tenant_id, created_source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT directory_group_status_check CHECK (status IN ('ACTIVE','INACTIVE','DELETED'))
);
CREATE INDEX directory_group_name_idx ON ${tenantSchema}.directory_group (name_key);

CREATE TABLE ${tenantSchema}.external_identity (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    external_id_enc text NOT NULL,
    external_id_index bytea NOT NULL,
    user_id uuid,
    link_status varchar(16) NOT NULL DEFAULT 'UNLINKED',
    email_enc text,
    email_index bytea,
    username_enc text,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    observed_at timestamptz NOT NULL DEFAULT now(),
    last_seen_run_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT external_identity_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT external_identity_external_key UNIQUE (tenant_id, source_id, external_id_index),
    CONSTRAINT external_identity_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT external_identity_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES ${tenantSchema}.directory_user (tenant_id, id),
    CONSTRAINT external_identity_run_fk FOREIGN KEY (tenant_id, last_seen_run_id) REFERENCES ${tenantSchema}.identity_import_run (tenant_id, id),
    CONSTRAINT external_identity_link_check CHECK (link_status IN ('LINKED','UNLINKED','AMBIGUOUS')),
    CONSTRAINT external_identity_linked_user_check CHECK ((link_status = 'LINKED') = (user_id IS NOT NULL)),
    CONSTRAINT external_identity_status_check CHECK (status IN ('ACTIVE','INACTIVE','DELETED')),
    CONSTRAINT external_identity_enc_check CHECK (external_id_enc LIKE 'enc:t1:%' AND (email_enc IS NULL OR email_enc LIKE 'enc:t1:%') AND (username_enc IS NULL OR username_enc LIKE 'enc:t1:%'))
);
CREATE INDEX external_identity_user_idx ON ${tenantSchema}.external_identity (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX external_identity_email_idx ON ${tenantSchema}.external_identity (email_index) WHERE email_index IS NOT NULL;

CREATE TABLE ${tenantSchema}.external_group (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    external_id_enc text NOT NULL,
    external_id_index bytea NOT NULL,
    display_name varchar(255) NOT NULL,
    group_id uuid,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    observed_at timestamptz NOT NULL DEFAULT now(),
    last_seen_run_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT external_group_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT external_group_external_key UNIQUE (tenant_id, source_id, external_id_index),
    CONSTRAINT external_group_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT external_group_group_fk FOREIGN KEY (tenant_id, group_id) REFERENCES ${tenantSchema}.directory_group (tenant_id, id),
    CONSTRAINT external_group_run_fk FOREIGN KEY (tenant_id, last_seen_run_id) REFERENCES ${tenantSchema}.identity_import_run (tenant_id, id),
    CONSTRAINT external_group_status_check CHECK (status IN ('ACTIVE','INACTIVE','DELETED')),
    CONSTRAINT external_group_enc_check CHECK (external_id_enc LIKE 'enc:t1:%')
);
CREATE INDEX external_group_group_idx ON ${tenantSchema}.external_group (group_id) WHERE group_id IS NOT NULL;

CREATE TABLE ${tenantSchema}.directory_group_member (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL,
    source_id uuid NOT NULL,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    observed_at timestamptz NOT NULL DEFAULT now(),
    last_seen_run_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT directory_group_member_key UNIQUE (tenant_id, group_id, user_id, source_id),
    CONSTRAINT directory_group_member_group_fk FOREIGN KEY (tenant_id, group_id) REFERENCES ${tenantSchema}.directory_group (tenant_id, id),
    CONSTRAINT directory_group_member_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES ${tenantSchema}.directory_user (tenant_id, id),
    CONSTRAINT directory_group_member_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT directory_group_member_run_fk FOREIGN KEY (tenant_id, last_seen_run_id) REFERENCES ${tenantSchema}.identity_import_run (tenant_id, id),
    CONSTRAINT directory_group_member_status_check CHECK (status IN ('ACTIVE','REMOVED'))
);
CREATE INDEX directory_group_member_user_idx ON ${tenantSchema}.directory_group_member (user_id, status);

CREATE TABLE ${tenantSchema}.directory_search_token (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    entity_kind varchar(8) NOT NULL,
    entity_id uuid NOT NULL,
    token bytea NOT NULL,
    PRIMARY KEY (tenant_id, entity_kind, entity_id, token),
    CONSTRAINT directory_search_token_kind_check CHECK (entity_kind IN ('USER','GROUP'))
);
CREATE INDEX directory_search_token_lookup_idx ON ${tenantSchema}.directory_search_token (entity_kind, token);

CREATE TABLE ${tenantSchema}.team (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    name varchar(200) NOT NULL,
    name_key varchar(200) NOT NULL,
    parent_team_id uuid,
    ticket_assignment_group varchar(255),
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by varchar(255) NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT team_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT team_name_key UNIQUE (tenant_id, name_key),
    CONSTRAINT team_parent_fk FOREIGN KEY (tenant_id, parent_team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT team_not_own_parent CHECK (parent_team_id IS NULL OR parent_team_id <> id),
    CONSTRAINT team_status_check CHECK (status IN ('ACTIVE','ARCHIVED')),
    CONSTRAINT team_name_key_check CHECK (name_key <> '' AND name_key = lower(name_key))
);
CREATE INDEX team_parent_idx ON ${tenantSchema}.team (parent_team_id) WHERE parent_team_id IS NOT NULL;

CREATE TABLE ${tenantSchema}.team_alias (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    team_id uuid NOT NULL,
    alias varchar(255) NOT NULL,
    alias_key varchar(255) NOT NULL,
    source_kind varchar(16) NOT NULL,
    source_id uuid,
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT team_alias_key UNIQUE (tenant_id, alias_key),
    CONSTRAINT team_alias_team_fk FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT team_alias_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT team_alias_source_kind_check CHECK (source_kind IN ('MANUAL','CSV','SERVICENOW','ENTRA','OKTA','AWS','GCP','AI_GRID')),
    CONSTRAINT team_alias_key_check CHECK (alias_key <> '' AND alias_key = lower(alias_key))
);
CREATE INDEX team_alias_team_idx ON ${tenantSchema}.team_alias (team_id);

CREATE TABLE ${tenantSchema}.external_group_team_mapping (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    external_group_id uuid NOT NULL,
    team_id uuid NOT NULL,
    state varchar(16) NOT NULL DEFAULT 'ACTIVE',
    provenance varchar(16) NOT NULL,
    effective_from timestamptz NOT NULL DEFAULT now(),
    effective_to timestamptz,
    reason varchar(500),
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT external_group_team_mapping_group_fk FOREIGN KEY (tenant_id, external_group_id) REFERENCES ${tenantSchema}.external_group (tenant_id, id),
    CONSTRAINT external_group_team_mapping_team_fk FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT external_group_team_mapping_state_check CHECK (state IN ('PROPOSED','ACTIVE','RETIRED')),
    CONSTRAINT external_group_team_mapping_provenance_check CHECK (provenance IN ('MANUAL','CSV','SUGGESTED')),
    CONSTRAINT external_group_team_mapping_window_check CHECK (effective_to IS NULL OR effective_to > effective_from)
);
CREATE UNIQUE INDEX external_group_team_mapping_active_idx ON ${tenantSchema}.external_group_team_mapping (tenant_id, external_group_id) WHERE state = 'ACTIVE';
CREATE INDEX external_group_team_mapping_team_idx ON ${tenantSchema}.external_group_team_mapping (team_id, state);

CREATE TABLE ${tenantSchema}.team_member (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    team_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_label varchar(80),
    source_kind varchar(16) NOT NULL DEFAULT 'MANUAL',
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, team_id, user_id),
    CONSTRAINT team_member_team_fk FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT team_member_user_fk FOREIGN KEY (tenant_id, user_id) REFERENCES ${tenantSchema}.directory_user (tenant_id, id),
    CONSTRAINT team_member_source_kind_check CHECK (source_kind IN ('MANUAL','CSV','SERVICENOW','ENTRA','OKTA'))
);
CREATE INDEX team_member_user_idx ON ${tenantSchema}.team_member (user_id);

ALTER TABLE ${tenantSchema}.identity_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.identity_source FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.identity_source
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.identity_import_run ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.identity_import_run FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.identity_import_run
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.directory_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.directory_user FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.directory_user
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.directory_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.directory_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.directory_group
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.external_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.external_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.external_identity
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.external_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.external_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.external_group
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.directory_group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.directory_group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.directory_group_member
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.directory_search_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.directory_search_token FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.directory_search_token
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.team ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.team FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.team
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.team_alias ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.team_alias FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.team_alias
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.external_group_team_mapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.external_group_team_mapping FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.external_group_team_mapping
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.team_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.team_member FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.team_member
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
