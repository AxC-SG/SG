-- Ownership effective-owner benchmark seed (design §7). Runs against a DISPOSABLE database prepared by
-- run_benchmark.sh, which has already applied the real tenant V20/V21 migrations into schema "bench".
-- psql variables: findings, occurrences. Topology: occurrence -> host -> cloud account -> application (3 hops).
\set ON_ERROR_STOP on
SET search_path = bench, public;
SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-0000000000be', false);

CREATE TABLE bench.findings (id uuid PRIMARY KEY, status varchar(16) NOT NULL, ownership_subject_id uuid);

INSERT INTO identity_source (id, kind, display_name, created_by) VALUES ('00000000-0000-0000-0000-00000000005e', 'MANUAL', 'bench', 'bench');
INSERT INTO team (id, name, name_key, created_by, updated_by)
SELECT md5('team' || i)::uuid, 'Team ' || i, 'team ' || i, 'bench', 'bench' FROM generate_series(1, 200) i;

-- applications (2,000), accounts (10,000), hosts (findings / 10), occurrences (:occurrences)
INSERT INTO ownership_subject (id, subject_type, source_object_id)
SELECT md5('app' || i)::uuid, 'APPLICATION', 'app-' || i FROM generate_series(1, 2000) i;
INSERT INTO ownership_subject (id, subject_type, source_object_id)
SELECT md5('acct' || i)::uuid, 'CLOUD_ACCOUNT', 'acct-' || i FROM generate_series(1, 10000) i;
INSERT INTO ownership_subject (id, subject_type, source_object_id)
SELECT md5('host' || i)::uuid, 'HOST', 'host-' || i FROM generate_series(1, :findings / 10) i;
INSERT INTO ownership_subject (id, subject_type, source_object_id)
SELECT md5('occ' || i)::uuid, 'COMPONENT_OCCURRENCE', 'occ-' || i FROM generate_series(1, :occurrences) i;

INSERT INTO ownership_subject_edge (id, child_subject_id, parent_subject_id, created_by)
SELECT gen_random_uuid(), md5('acct' || i)::uuid, md5('app' || (1 + i % 2000))::uuid, 'bench' FROM generate_series(1, 10000) i;
INSERT INTO ownership_subject_edge (id, child_subject_id, parent_subject_id, created_by)
SELECT gen_random_uuid(), md5('host' || i)::uuid, md5('acct' || (1 + i % 10000))::uuid, 'bench' FROM generate_series(1, :findings / 10) i;
INSERT INTO ownership_subject_edge (id, child_subject_id, parent_subject_id, created_by)
SELECT gen_random_uuid(), md5('occ' || i)::uuid, md5('host' || (1 + i % (:findings / 10)))::uuid, 'bench'
  FROM generate_series(1, :occurrences) i;

-- Direct claims + assignments: every application (ServiceNow), 10% of hosts (manual), 1% of apps conflicting.
INSERT INTO ownership_claim (id, subject_id, team_id, source_kind, priority_class, source_ref, idempotency_key, producer_version,
                             observed_at, stale_after, actor)
SELECT md5('claim-app' || i)::uuid, md5('app' || i)::uuid, md5('team' || (1 + i % 200))::uuid, 'SERVICENOW', 'SERVICENOW',
       'sn:' || i, 'k-app-' || i, 'bench', now(), now() + interval '2 days', 'bench' FROM generate_series(1, 2000) i;
INSERT INTO ownership_assignment (id, subject_id, status, team_id, winning_claim_id, winning_priority, winning_source_kind, reason,
                                  resolver_version, input_watermark, resolved_at)
SELECT md5('asg-app' || i)::uuid, md5('app' || i)::uuid, 'OWNED', md5('team' || (1 + i % 200))::uuid, md5('claim-app' || i)::uuid, 2,
       'SERVICENOW', 'SINGLE_TEAM_AT_PRIORITY', 1, repeat('0', 64), now() FROM generate_series(21, 2000) i;
INSERT INTO ownership_assignment (id, subject_id, status, conflict_team_ids, winning_priority, winning_source_kind, reason,
                                  resolver_version, input_watermark, resolved_at)
SELECT md5('asg-app' || i)::uuid, md5('app' || i)::uuid, 'CONFLICT', ARRAY[md5('team1')::uuid, md5('team2')::uuid], 2, 'SERVICENOW',
       'CONFLICTING_TEAMS_AT_PRIORITY', 1, repeat('0', 64), now() FROM generate_series(1, 20) i;
INSERT INTO ownership_claim (id, subject_id, team_id, source_kind, priority_class, source_ref, idempotency_key, producer_version,
                             observed_at, reason, actor)
SELECT md5('claim-host' || i)::uuid, md5('host' || i)::uuid, md5('team' || (1 + i % 200))::uuid, 'MANUAL', 'MANUAL', 'manual:' || i,
       'k-host-' || i, 'bench', now(), 'bench', 'bench' FROM generate_series(1, :findings / 10, 10) i;
INSERT INTO ownership_assignment (id, subject_id, status, team_id, winning_claim_id, winning_priority, winning_source_kind, reason,
                                  resolver_version, input_watermark, resolved_at)
SELECT md5('asg-host' || i)::uuid, md5('host' || i)::uuid, 'OWNED', md5('team' || (1 + i % 200))::uuid, md5('claim-host' || i)::uuid, 1,
       'MANUAL', 'SINGLE_TEAM_AT_PRIORITY', 1, repeat('0', 64), now() FROM generate_series(1, :findings / 10, 10) i;

-- Findings are occurrence-scoped (worst case: 3 hops to the owning application); 5% have no subject.
INSERT INTO bench.findings (id, status, ownership_subject_id)
SELECT md5('f' || i)::uuid, CASE WHEN i % 4 = 0 THEN 'RESOLVED' ELSE 'OPEN' END,
       CASE WHEN i % 20 = 0 THEN NULL ELSE md5('occ' || (1 + i % :occurrences))::uuid END
  FROM generate_series(1, :findings) i;
CREATE INDEX findings_subject_idx ON bench.findings (ownership_subject_id, status);
CREATE INDEX findings_status_idx ON bench.findings (status, id);

-- Effective cache (design §7 fallback), built the way the cache writer builds it: one row per subject from the live walk.
INSERT INTO ownership_effective_cache (subject_id, ownership_status, owner_team_id, origin_subject_id, assignment_id,
                                       origin_assignment_version, inheritance_path, inheritance_depth, refreshed_at)
SELECT e.subject_id, e.ownership_status, CASE WHEN e.ownership_status = 'OWNED' THEN e.owner_team_id END,
       e.ownership_origin_subject_id, e.ownership_assignment_id, a.version, e.inheritance_path, e.inheritance_depth, now()
  FROM ownership_effective_assignment e LEFT JOIN ownership_assignment a ON a.id = e.ownership_assignment_id;
ANALYZE;
