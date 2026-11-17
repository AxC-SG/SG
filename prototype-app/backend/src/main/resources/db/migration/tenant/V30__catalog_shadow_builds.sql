-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);
CREATE TABLE ${tenantSchema}.intelligence_catalog_builds (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    policy_version bigint NOT NULL,
    generation bigint NOT NULL,
    override_state text NOT NULL,
    source_state text NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('QUEUED','BUILDING','READY','STALE','CANCELLED','FAILED')),
    after_id uuid,
    scanned bigint NOT NULL DEFAULT 0 CHECK (scanned >= 0),
    matched bigint NOT NULL DEFAULT 0 CHECK (matched >= 0 AND matched <= scanned),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error varchar(64),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id,id),
    FOREIGN KEY (tenant_id,policy_version) REFERENCES ${tenantSchema}.intelligence_catalog_policy_versions(tenant_id,version),
    CHECK (tenant_id = '${tenantId}'::uuid)
);
CREATE UNIQUE INDEX intelligence_catalog_one_pending_build
    ON ${tenantSchema}.intelligence_catalog_builds(tenant_id) WHERE status IN ('QUEUED','BUILDING');
CREATE INDEX intelligence_catalog_builds_recent ON ${tenantSchema}.intelligence_catalog_builds(tenant_id,created_at DESC,id);
CREATE TABLE ${tenantSchema}.intelligence_catalog_members (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid,
    build_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL REFERENCES platform.vulnerabilities(id),
    reason varchar(20) NOT NULL CHECK (reason IN ('POLICY','MANUAL_INCLUDE')),
    PRIMARY KEY (tenant_id,build_id,vulnerability_id),
    FOREIGN KEY (tenant_id,build_id) REFERENCES ${tenantSchema}.intelligence_catalog_builds(tenant_id,id),
    CHECK (tenant_id = '${tenantId}'::uuid)
);
ALTER TABLE ${tenantSchema}.intelligence_catalog_builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.intelligence_catalog_builds FORCE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.intelligence_catalog_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.intelligence_catalog_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.intelligence_catalog_builds
    USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);
CREATE POLICY tenant_isolation ON ${tenantSchema}.intelligence_catalog_members
    USING (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id',true),'')::uuid);
