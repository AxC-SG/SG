-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Ownership MVP Release 1: ownership core (plan §6.8, §6.9, §7.2, §7.5; docs/ownership-phase-0a-design.md §1, §5).
-- Claims are source observations; ownership_assignment holds the direct result only for subjects that have
-- claims; inherited ownership is read through ownership_effective_assignment and never copied to descendants.
-- Every cross-row reference is tenant-inclusive and nothing cascades across rows.

CREATE TABLE ${tenantSchema}.ownership_subject (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    subject_type varchar(32) NOT NULL,
    source_object_id varchar(512) NOT NULL,
    context_key varchar(512) NOT NULL DEFAULT '',
    generation integer NOT NULL DEFAULT 1,
    lifecycle_status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    PRIMARY KEY (id),
    CONSTRAINT ownership_subject_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_subject_identity_key UNIQUE (tenant_id, subject_type, source_object_id, context_key, generation),
    CONSTRAINT ownership_subject_type_check CHECK (subject_type IN ('APPLICATION','HOST','CONTAINER_IMAGE','CLOUD_ACCOUNT',
        'CLOUD_RESOURCE','COMPONENT_OCCURRENCE','AI_SYSTEM','AI_ARTIFACT')),
    CONSTRAINT ownership_subject_status_check CHECK (lifecycle_status IN ('ACTIVE','RETIRED')),
    CONSTRAINT ownership_subject_retired_check CHECK ((lifecycle_status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT ownership_subject_generation_check CHECK (generation >= 1),
    CONSTRAINT ownership_subject_source_check CHECK (source_object_id <> '')
);
-- One live generation per contextual identity; older generations stay for history.
CREATE UNIQUE INDEX ownership_subject_active_idx ON ${tenantSchema}.ownership_subject (tenant_id, subject_type, source_object_id, context_key)
    WHERE lifecycle_status = 'ACTIVE';

CREATE TABLE ${tenantSchema}.ownership_subject_edge (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    child_subject_id uuid NOT NULL,
    parent_subject_id uuid NOT NULL,
    edge_type varchar(24) NOT NULL DEFAULT 'OWNERSHIP_PARENT',
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    created_by varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    PRIMARY KEY (id),
    CONSTRAINT ownership_subject_edge_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_subject_edge_child_fk FOREIGN KEY (tenant_id, child_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_subject_edge_parent_fk FOREIGN KEY (tenant_id, parent_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_subject_edge_type_check CHECK (edge_type IN ('OWNERSHIP_PARENT')),
    CONSTRAINT ownership_subject_edge_status_check CHECK (status IN ('ACTIVE','RETIRED')),
    CONSTRAINT ownership_subject_edge_retired_check CHECK ((status = 'RETIRED') = (retired_at IS NOT NULL)),
    CONSTRAINT ownership_subject_edge_not_self CHECK (child_subject_id <> parent_subject_id)
);
-- MVP: at most one active ownership parent per subject (plan §7.2).
CREATE UNIQUE INDEX ownership_subject_edge_one_parent_idx ON ${tenantSchema}.ownership_subject_edge (tenant_id, child_subject_id)
    WHERE edge_type = 'OWNERSHIP_PARENT' AND status = 'ACTIVE';
-- Lookup path for the effective-ownership walk (child -> parent); the unique index above leads with tenant_id.
CREATE INDEX ownership_subject_edge_child_idx ON ${tenantSchema}.ownership_subject_edge (child_subject_id, parent_subject_id)
    WHERE edge_type = 'OWNERSHIP_PARENT' AND status = 'ACTIVE';
CREATE INDEX ownership_subject_edge_parent_idx ON ${tenantSchema}.ownership_subject_edge (parent_subject_id)
    WHERE status = 'ACTIVE';

CREATE TABLE ${tenantSchema}.ownership_claim (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    subject_id uuid NOT NULL,
    role varchar(24) NOT NULL DEFAULT 'TECHNICAL_OWNER',
    team_id uuid NOT NULL,
    principal_user_id uuid,
    source_kind varchar(16) NOT NULL,
    priority_class varchar(24) NOT NULL,
    priority smallint GENERATED ALWAYS AS (CASE priority_class
        WHEN 'MANUAL' THEN 1 WHEN 'SERVICENOW' THEN 2 WHEN 'CLOUD_STRUCTURED' THEN 3
        WHEN 'AI_GRID' THEN 4 WHEN 'CLOUD_TAG' THEN 5 WHEN 'DIRECTORY' THEN 6 END) STORED,
    source_id uuid,
    source_ref varchar(512) NOT NULL,
    idempotency_key varchar(512) NOT NULL,
    producer_version varchar(64) NOT NULL,
    observed_at timestamptz NOT NULL,
    stale_after timestamptz,
    expires_at timestamptz,
    status varchar(16) NOT NULL DEFAULT 'ACTIVE',
    reason varchar(1000),
    actor varchar(255) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    ended_at timestamptz,
    ended_by varchar(255),
    PRIMARY KEY (id),
    CONSTRAINT ownership_claim_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_claim_idempotency_key UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT ownership_claim_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_claim_team_fk FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT ownership_claim_principal_fk FOREIGN KEY (tenant_id, principal_user_id) REFERENCES ${tenantSchema}.directory_user (tenant_id, id),
    CONSTRAINT ownership_claim_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT ownership_claim_role_check CHECK (role IN ('TECHNICAL_OWNER')),
    CONSTRAINT ownership_claim_status_check CHECK (status IN ('ACTIVE','SUPERSEDED','REVOKED','EXPIRED')),
    CONSTRAINT ownership_claim_ended_check CHECK ((status = 'ACTIVE') = (ended_at IS NULL)),
    CONSTRAINT ownership_claim_source_kind_check CHECK (source_kind IN ('MANUAL','SERVICENOW','AWS','GCP','AI_GRID','ENTRA','OKTA')),
    CONSTRAINT ownership_claim_priority_class_check CHECK (
        (priority_class = 'MANUAL' AND source_kind = 'MANUAL')
        OR (priority_class = 'SERVICENOW' AND source_kind = 'SERVICENOW')
        OR (priority_class IN ('CLOUD_STRUCTURED','CLOUD_TAG') AND source_kind IN ('AWS','GCP'))
        OR (priority_class = 'AI_GRID' AND source_kind = 'AI_GRID')
        OR (priority_class = 'DIRECTORY' AND source_kind IN ('ENTRA','OKTA'))),
    CONSTRAINT ownership_claim_manual_reason_check CHECK (priority_class <> 'MANUAL' OR (reason IS NOT NULL AND btrim(reason) <> '')),
    CONSTRAINT ownership_claim_expiry_check CHECK (expires_at IS NULL OR expires_at > observed_at),
    CONSTRAINT ownership_claim_stale_check CHECK (stale_after IS NULL OR stale_after > observed_at)
);
CREATE INDEX ownership_claim_active_subject_idx ON ${tenantSchema}.ownership_claim (subject_id, role) WHERE status = 'ACTIVE';
CREATE INDEX ownership_claim_active_team_idx ON ${tenantSchema}.ownership_claim (team_id) WHERE status = 'ACTIVE';
CREATE INDEX ownership_claim_active_expiry_idx ON ${tenantSchema}.ownership_claim (expires_at) WHERE status = 'ACTIVE' AND expires_at IS NOT NULL;
CREATE INDEX ownership_claim_active_source_idx ON ${tenantSchema}.ownership_claim (source_kind, source_ref) WHERE status = 'ACTIVE';

-- Direct result only. NONE means the subject has claims but none is eligible, so readers fall through to the parent.
CREATE TABLE ${tenantSchema}.ownership_assignment (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    subject_id uuid NOT NULL,
    role varchar(24) NOT NULL DEFAULT 'TECHNICAL_OWNER',
    status varchar(16) NOT NULL,
    team_id uuid,
    winning_claim_id uuid,
    winning_priority smallint,
    winning_source_kind varchar(16),
    conflict_team_ids uuid[] NOT NULL DEFAULT '{}'::uuid[],
    reason varchar(64) NOT NULL,
    resolver_version integer NOT NULL,
    input_watermark char(64) NOT NULL,
    resolved_at timestamptz NOT NULL,
    version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    CONSTRAINT ownership_assignment_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_assignment_subject_key UNIQUE (tenant_id, subject_id, role),
    CONSTRAINT ownership_assignment_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_assignment_team_fk FOREIGN KEY (tenant_id, team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT ownership_assignment_claim_fk FOREIGN KEY (tenant_id, winning_claim_id) REFERENCES ${tenantSchema}.ownership_claim (tenant_id, id),
    CONSTRAINT ownership_assignment_role_check CHECK (role IN ('TECHNICAL_OWNER')),
    CONSTRAINT ownership_assignment_status_check CHECK (status IN ('OWNED','CONFLICT','NONE')),
    CONSTRAINT ownership_assignment_shape_check CHECK (
        (status = 'OWNED' AND team_id IS NOT NULL AND winning_claim_id IS NOT NULL AND winning_priority IS NOT NULL)
        OR (status = 'CONFLICT' AND team_id IS NULL AND winning_priority IS NOT NULL AND cardinality(conflict_team_ids) >= 2)
        OR (status = 'NONE' AND team_id IS NULL AND winning_claim_id IS NULL AND winning_priority IS NULL))
);
-- Lookup path for the effective-ownership walk; the unique key above leads with tenant_id.
CREATE INDEX ownership_assignment_direct_idx ON ${tenantSchema}.ownership_assignment (subject_id)
    INCLUDE (id, status, team_id, winning_priority) WHERE status IN ('OWNED','CONFLICT');
CREATE INDEX ownership_assignment_team_idx ON ${tenantSchema}.ownership_assignment (team_id, status) WHERE team_id IS NOT NULL;

CREATE TABLE ${tenantSchema}.ownership_review_item (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    item_type varchar(32) NOT NULL,
    dedupe_key varchar(512) NOT NULL,
    subject_id uuid,
    source_kind varchar(16),
    source_id uuid,
    unresolved_value_enc text,
    unresolved_value_index bytea,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    state varchar(16) NOT NULL DEFAULT 'OPEN',
    occurrence_count integer NOT NULL DEFAULT 1,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolved_by varchar(255),
    resolution_note varchar(1000),
    PRIMARY KEY (id),
    CONSTRAINT ownership_review_item_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_review_item_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_review_item_source_fk FOREIGN KEY (tenant_id, source_id) REFERENCES ${tenantSchema}.identity_source (tenant_id, id),
    CONSTRAINT ownership_review_item_type_check CHECK (item_type IN ('UNMAPPED_VALUE','AMBIGUOUS_IDENTITY','CONFLICT',
        'INACTIVE_OWNER','INHERITANCE_ERROR','PRODUCER_ANOMALY')),
    CONSTRAINT ownership_review_item_state_check CHECK (state IN ('OPEN','RESOLVED','DISMISSED')),
    CONSTRAINT ownership_review_item_resolved_check CHECK ((state = 'OPEN') = (resolved_at IS NULL)),
    CONSTRAINT ownership_review_item_enc_check CHECK (unresolved_value_enc IS NULL OR unresolved_value_enc LIKE 'enc:t1:%'),
    CONSTRAINT ownership_review_item_index_check CHECK (unresolved_value_index IS NULL OR unresolved_value_enc IS NOT NULL),
    CONSTRAINT ownership_review_item_count_check CHECK (occurrence_count >= 1)
);
CREATE UNIQUE INDEX ownership_review_item_open_idx ON ${tenantSchema}.ownership_review_item (tenant_id, dedupe_key) WHERE state = 'OPEN';
CREATE INDEX ownership_review_item_open_type_idx ON ${tenantSchema}.ownership_review_item (item_type, last_seen_at DESC) WHERE state = 'OPEN';
CREATE INDEX ownership_review_item_subject_idx ON ${tenantSchema}.ownership_review_item (subject_id) WHERE subject_id IS NOT NULL;

-- Append-only; details carry stable IDs and action metadata, never names, emails or unresolved values.
CREATE TABLE ${tenantSchema}.ownership_event (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    id uuid NOT NULL,
    event_type varchar(48) NOT NULL,
    subject_id uuid,
    assignment_id uuid,
    claim_id uuid,
    actor varchar(255) NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id),
    CONSTRAINT ownership_event_tenant_key UNIQUE (tenant_id, id),
    CONSTRAINT ownership_event_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_event_assignment_fk FOREIGN KEY (tenant_id, assignment_id) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id),
    CONSTRAINT ownership_event_claim_fk FOREIGN KEY (tenant_id, claim_id) REFERENCES ${tenantSchema}.ownership_claim (tenant_id, id)
);
CREATE INDEX ownership_event_subject_idx ON ${tenantSchema}.ownership_event (subject_id, created_at DESC) WHERE subject_id IS NOT NULL;
CREATE INDEX ownership_event_type_idx ON ${tenantSchema}.ownership_event (event_type, created_at DESC);

CREATE FUNCTION ${tenantSchema}.ownership_event_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'ownership_event is append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;
CREATE TRIGGER ownership_event_append_only BEFORE UPDATE OR DELETE ON ${tenantSchema}.ownership_event
    FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.ownership_event_append_only();

-- Durable re-resolution work (plan §12.2): subjects whose eligibility changed outside their own claims
-- (e.g. a team archived or restored). Drained in bounded batches by the ownership maintenance job.
CREATE TABLE ${tenantSchema}.ownership_resolution_queue (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    subject_id uuid NOT NULL,
    reason varchar(32) NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject_id),
    CONSTRAINT ownership_resolution_queue_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_resolution_queue_reason_check CHECK (reason IN ('TEAM_STATUS_CHANGED','SOURCE_STATE_CHANGED','RESOLVER_UPGRADE'))
);
CREATE INDEX ownership_resolution_queue_order_idx ON ${tenantSchema}.ownership_resolution_queue (enqueued_at);

-- Phase-0A performance fallback (plan §7.5, design §7): selected because the smoke benchmark missed the
-- owner-team filter and coverage budgets. Read only by list filters and coverage counts; never authoritative,
-- never used for correctness-sensitive writes, no display names. inheritance_path is the subjects the walk
-- visited (the subject first, the origin or root last); a change at any subject invalidates exactly the rows
-- whose path contains it, so no descendant walk and no tenant-wide epoch are needed.
CREATE TABLE ${tenantSchema}.ownership_effective_cache (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    subject_id uuid NOT NULL,
    role varchar(24) NOT NULL DEFAULT 'TECHNICAL_OWNER',
    ownership_status varchar(16) NOT NULL,
    owner_team_id uuid,
    origin_subject_id uuid,
    assignment_id uuid,
    origin_assignment_version bigint,
    inheritance_path uuid[] NOT NULL,
    inheritance_depth smallint NOT NULL,
    refreshed_at timestamptz NOT NULL,
    invalidated_at timestamptz,
    PRIMARY KEY (tenant_id, subject_id, role),
    CONSTRAINT ownership_effective_cache_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_effective_cache_origin_fk FOREIGN KEY (tenant_id, origin_subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_effective_cache_team_fk FOREIGN KEY (tenant_id, owner_team_id) REFERENCES ${tenantSchema}.team (tenant_id, id),
    CONSTRAINT ownership_effective_cache_assignment_fk FOREIGN KEY (tenant_id, assignment_id) REFERENCES ${tenantSchema}.ownership_assignment (tenant_id, id),
    CONSTRAINT ownership_effective_cache_role_check CHECK (role IN ('TECHNICAL_OWNER')),
    CONSTRAINT ownership_effective_cache_status_check CHECK (ownership_status IN ('OWNED','CONFLICT','UNOWNED')),
    CONSTRAINT ownership_effective_cache_depth_check CHECK (inheritance_depth BETWEEN 0 AND 6),
    CONSTRAINT ownership_effective_cache_path_check CHECK (cardinality(inheritance_path) BETWEEN 1 AND 8
        AND inheritance_path[1] = subject_id),
    CONSTRAINT ownership_effective_cache_shape_check CHECK (
        (ownership_status = 'OWNED' AND owner_team_id IS NOT NULL AND assignment_id IS NOT NULL)
        OR (ownership_status <> 'OWNED' AND owner_team_id IS NULL))
);
-- Probe from the read side: a team/status filter or coverage count joins on subject_id.
CREATE INDEX ownership_effective_cache_subject_idx ON ${tenantSchema}.ownership_effective_cache (subject_id)
    INCLUDE (ownership_status, owner_team_id);
CREATE INDEX ownership_effective_cache_team_idx ON ${tenantSchema}.ownership_effective_cache (owner_team_id, ownership_status)
    INCLUDE (subject_id);
CREATE INDEX ownership_effective_cache_path_idx ON ${tenantSchema}.ownership_effective_cache USING gin (inheritance_path);
CREATE INDEX ownership_effective_cache_invalidated_idx ON ${tenantSchema}.ownership_effective_cache (invalidated_at)
    WHERE invalidated_at IS NOT NULL;

-- Subjects whose effective result may have changed: their own assignment changed, their parent edge changed, or
-- they were just registered. The cache writer expands each root to the cache rows whose path contains it.
CREATE TABLE ${tenantSchema}.ownership_cache_invalidation (
    tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id),
    subject_id uuid NOT NULL,
    reason varchar(32) NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, subject_id),
    CONSTRAINT ownership_cache_invalidation_subject_fk FOREIGN KEY (tenant_id, subject_id) REFERENCES ${tenantSchema}.ownership_subject (tenant_id, id),
    CONSTRAINT ownership_cache_invalidation_reason_check CHECK (reason IN ('ASSIGNMENT_CHANGED','TOPOLOGY_CHANGED','SUBJECT_REGISTERED','REBUILD'))
);
CREATE INDEX ownership_cache_invalidation_order_idx ON ${tenantSchema}.ownership_cache_invalidation (enqueued_at);

-- Effective ownership (plan §6.9 steps 3–6): the subject's own OWNED/CONFLICT assignment, else the first such
-- assignment up the single OWNERSHIP_PARENT chain within six hops. A cycle, a retired/missing parent or a chain
-- longer than six hops yields CONFLICT. No ancestor with a direct result yields UNOWNED.
-- Computed per subject by a function joined LATERAL, so a filter or join on subject_id walks only the chains it
-- needs (a recursive CTE over all subjects cannot be filtered by the planner). SECURITY INVOKER (the default) and
-- the view's security_invoker keep the caller's RLS in force.
CREATE FUNCTION ${tenantSchema}.ownership_effective_for(p_subject uuid)
RETURNS TABLE (ownership_status varchar(16), resolution varchar(24), owner_team_id uuid, ownership_origin_subject_id uuid,
               ownership_assignment_id uuid, ownership_source_kind varchar(16), ownership_resolved_at timestamptz,
               ownership_stale boolean, inheritance_depth smallint, inheritance_path uuid[])
LANGUAGE sql STABLE ROWS 1 COST 50 AS $$
WITH RECURSIVE walk AS (
    SELECT p_subject AS current_id, 0 AS depth, ARRAY[p_subject] AS path, false AS cycle, false AS missing
    UNION ALL
    SELECT e.parent_subject_id, w.depth + 1, w.path || e.parent_subject_id,
           e.parent_subject_id = ANY (w.path), p.id IS NULL
      FROM walk w
      LEFT JOIN ${tenantSchema}.ownership_assignment a
             ON a.subject_id = w.current_id AND a.role = 'TECHNICAL_OWNER' AND a.status IN ('OWNED','CONFLICT')
      JOIN ${tenantSchema}.ownership_subject_edge e
             ON e.child_subject_id = w.current_id AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
      LEFT JOIN ${tenantSchema}.ownership_subject p
             ON p.id = e.parent_subject_id AND p.lifecycle_status = 'ACTIVE'
     WHERE a.id IS NULL AND NOT w.cycle AND NOT w.missing AND w.depth <= 6
), t AS (
    SELECT * FROM walk ORDER BY depth DESC LIMIT 1
)
SELECT CASE WHEN t.cycle OR t.missing OR t.depth > 6 THEN 'CONFLICT'
            WHEN a.id IS NOT NULL THEN a.status
            ELSE 'UNOWNED' END::varchar(16),
       CASE WHEN t.cycle THEN 'CYCLE'
            WHEN t.missing THEN 'MISSING_PARENT'
            WHEN t.depth > 6 THEN 'DEPTH_EXCEEDED'
            WHEN a.id IS NOT NULL AND t.depth = 0 THEN 'DIRECT'
            WHEN a.id IS NOT NULL THEN 'INHERITED'
            ELSE 'NO_ELIGIBLE_CLAIM' END::varchar(24),
       a.team_id, a.subject_id, a.id, a.winning_source_kind, a.resolved_at,
       -- Stale when no active claim at the winning priority is still fresh; computed here so re-observation
       -- (which only moves claim timestamps) never rewrites the assignment.
       (a.id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM ${tenantSchema}.ownership_claim c
             WHERE c.subject_id = a.subject_id AND c.role = 'TECHNICAL_OWNER' AND c.status = 'ACTIVE'
               AND c.priority = a.winning_priority AND (c.stale_after IS NULL OR c.stale_after > now()))),
       LEAST(t.depth, 6)::smallint,
       t.path
  FROM t
  LEFT JOIN ${tenantSchema}.ownership_assignment a
         ON a.subject_id = t.current_id AND a.role = 'TECHNICAL_OWNER' AND a.status IN ('OWNED','CONFLICT')
        AND NOT (t.cycle OR t.missing OR t.depth > 6)
$$;

CREATE VIEW ${tenantSchema}.ownership_effective_assignment WITH (security_invoker = true) AS
SELECT s.tenant_id, s.id AS subject_id, 'TECHNICAL_OWNER'::varchar(24) AS role, e.*
  FROM ${tenantSchema}.ownership_subject s
 CROSS JOIN LATERAL ${tenantSchema}.ownership_effective_for(s.id) e;

ALTER TABLE ${tenantSchema}.ownership_subject ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_subject FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_subject
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_subject_edge ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_subject_edge FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_subject_edge
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_claim ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_claim FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_claim
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_assignment
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_review_item ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_review_item FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_review_item
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_event FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_event
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_effective_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_effective_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_effective_cache
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_cache_invalidation ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_cache_invalidation FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_cache_invalidation
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);

ALTER TABLE ${tenantSchema}.ownership_resolution_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${tenantSchema}.ownership_resolution_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ${tenantSchema}.ownership_resolution_queue
    USING (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.current_tenant_id', true), '')::uuid);
