-- migration-guard: platform-only
create table platform.intelligence_publication_progress (
 candidate_id uuid primary key,
 phase text not null default 'QUEUED', processed bigint not null default 0,
 total bigint not null default 0, heartbeat_at timestamptz, started_at timestamptz,
 checkpoint jsonb not null default '{}', requested_action text,
 attempt_count integer not null default 0
);
create table platform.intelligence_publication_events (
 id bigserial primary key, candidate_id uuid not null,
 level text not null, message text not null, created_at timestamptz not null default clock_timestamp()
);
create index on platform.intelligence_publication_events(candidate_id,id);
-- Independent telemetry must never acquire locks on candidates held by publication.
create table platform.intelligence_candidate_versions (
 candidate_id uuid primary key, cursor_id bigint not null default 0,
 processed bigint not null default 0, complete boolean not null default false
);
create table platform.intelligence_candidate_version_records (
 candidate_id uuid not null, record_id bigint not null, record jsonb not null,
 primary key(candidate_id,record_id)
);
