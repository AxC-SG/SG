-- migration-guard: platform-only
CREATE TABLE platform.intelligence_identifiers (
 identifier varchar(255) PRIMARY KEY, canonical_id uuid NOT NULL, verified boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE platform.intelligence_staged_records (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 sync_run_id uuid NOT NULL REFERENCES platform.sync_runs(id), kind varchar(32) NOT NULL,
 external_id varchar(255) NOT NULL, canonical_id uuid, source_system varchar(80) NOT NULL,
 payload jsonb NOT NULL, validation varchar(64) NOT NULL DEFAULT 'VALID', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX intelligence_staged_run_idx ON platform.intelligence_staged_records(sync_run_id,id);
CREATE FUNCTION platform.freeze_staged_intelligence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE run_status text;
BEGIN
 SELECT lower(status) INTO run_status FROM platform.sync_runs WHERE id=coalesce(NEW.sync_run_id,OLD.sync_run_id) FOR SHARE;
 IF run_status NOT IN ('running','queued') OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'Staged intelligence is immutable after normalization';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER freeze_staged_intelligence_insert BEFORE INSERT ON platform.intelligence_staged_records FOR EACH ROW EXECUTE FUNCTION platform.freeze_staged_intelligence();
CREATE TRIGGER freeze_staged_intelligence_update BEFORE UPDATE ON platform.intelligence_staged_records FOR EACH ROW EXECUTE FUNCTION platform.freeze_staged_intelligence();
CREATE TRIGGER freeze_staged_intelligence_delete BEFORE DELETE ON platform.intelligence_staged_records FOR EACH ROW EXECUTE FUNCTION platform.freeze_staged_intelligence();

CREATE TABLE platform.intelligence_candidates (
 id uuid PRIMARY KEY, status varchar(32) NOT NULL DEFAULT 'BUILDING', base_release_id uuid,
 selected_run_ids uuid[] NOT NULL, expanded_run_ids uuid[] NOT NULL DEFAULT '{}',
 normalization_policy varchar(64) NOT NULL, digest varchar(64), quality_report jsonb NOT NULL DEFAULT '{}',
 created_by varchar(255) NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), rejection_reason varchar(2000),
 published_release_id uuid, error_code varchar(255)
);
CREATE TABLE platform.intelligence_candidate_records (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, candidate_id uuid NOT NULL REFERENCES platform.intelligence_candidates(id),
 staged_record_id bigint NOT NULL REFERENCES platform.intelligence_staged_records(id),
 sync_run_id uuid NOT NULL, kind varchar(32) NOT NULL, external_id varchar(255) NOT NULL,canonical_id uuid,
 source_system varchar(80) NOT NULL, payload jsonb NOT NULL, validation varchar(64) NOT NULL,
 UNIQUE(candidate_id,staged_record_id)
);
CREATE INDEX intelligence_candidate_records_page_idx ON platform.intelligence_candidate_records(candidate_id,id);
CREATE TABLE platform.intelligence_releases (
 id uuid PRIMARY KEY, candidate_id uuid REFERENCES platform.intelligence_candidates(id), predecessor_id uuid REFERENCES platform.intelligence_releases(id),
 restores_release_id uuid REFERENCES platform.intelligence_releases(id), generation bigint NOT NULL UNIQUE,
 digest varchar(64) NOT NULL, actor varchar(255) NOT NULL, published_at timestamptz NOT NULL DEFAULT now(),
 kind varchar(32) NOT NULL DEFAULT 'PUBLICATION', status varchar(16) NOT NULL DEFAULT 'APPLYING'
);
ALTER TABLE platform.intelligence_candidates ADD CONSTRAINT candidate_base_release_fk FOREIGN KEY(base_release_id) REFERENCES platform.intelligence_releases(id);
ALTER TABLE platform.intelligence_candidates ADD CONSTRAINT candidate_published_release_fk FOREIGN KEY(published_release_id) REFERENCES platform.intelligence_releases(id);
CREATE TABLE platform.intelligence_active_state (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),release_id uuid REFERENCES platform.intelligence_releases(id),generation bigint NOT NULL DEFAULT 0
);
INSERT INTO platform.intelligence_active_state(singleton) VALUES(true);
CREATE TABLE platform.intelligence_release_changes (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,release_id uuid NOT NULL REFERENCES platform.intelligence_releases(id),
 table_schema varchar(64) NOT NULL,table_name varchar(64) NOT NULL,row_id uuid NOT NULL,previous_value jsonb,new_value jsonb
);
CREATE INDEX intelligence_release_changes_idx ON platform.intelligence_release_changes(release_id,id);
CREATE TABLE platform.intelligence_publication_outbox (
 id uuid PRIMARY KEY,candidate_id uuid REFERENCES platform.intelligence_candidates(id),release_id uuid REFERENCES platform.intelligence_releases(id),
 kind varchar(16) NOT NULL CHECK(kind IN ('BUILD','PUBLISH','WITHDRAW','FANOUT')),
 idempotency_key varchar(255) UNIQUE,status varchar(16) NOT NULL DEFAULT 'PENDING',
 expected_digest varchar(64),expected_base_release uuid, actor varchar(255) NOT NULL,
 attempt_count integer NOT NULL DEFAULT 0,visible_at timestamptz NOT NULL DEFAULT now(),last_error varchar(255),
 after_tenant_id uuid,created_at timestamptz NOT NULL DEFAULT now(),completed_at timestamptz
);
CREATE INDEX intelligence_publication_pending_idx ON platform.intelligence_publication_outbox(visible_at,id) WHERE status='PENDING';
CREATE TABLE platform.intelligence_published_runs (
 sync_run_id uuid PRIMARY KEY REFERENCES platform.sync_runs(id),release_id uuid NOT NULL REFERENCES platform.intelligence_releases(id)
);
CREATE TABLE platform.intelligence_audit_events (
 id uuid PRIMARY KEY,action varchar(32) NOT NULL,actor varchar(255) NOT NULL,candidate_id uuid,release_id uuid,
 detail jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION platform.immutable_intelligence_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Published intelligence evidence is immutable'; END $$;
CREATE TRIGGER immutable_candidate_records BEFORE UPDATE OR DELETE ON platform.intelligence_candidate_records
 FOR EACH ROW EXECUTE FUNCTION platform.immutable_intelligence_evidence();
CREATE TRIGGER immutable_release_changes BEFORE UPDATE OR DELETE ON platform.intelligence_release_changes
 FOR EACH ROW EXECUTE FUNCTION platform.immutable_intelligence_evidence();
CREATE TRIGGER immutable_intelligence_audit BEFORE UPDATE OR DELETE ON platform.intelligence_audit_events
 FOR EACH ROW EXECUTE FUNCTION platform.immutable_intelligence_evidence();
CREATE FUNCTION platform.guard_intelligence_release() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.status='PUBLISHED' OR NEW.id<>OLD.id OR NEW.digest<>OLD.digest OR NEW.actor<>OLD.actor
 THEN RAISE EXCEPTION 'Published releases are immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_intelligence_release BEFORE UPDATE OR DELETE ON platform.intelligence_releases
 FOR EACH ROW EXECUTE FUNCTION platform.guard_intelligence_release();

-- Capture every row changed by a publication, including summary, GHSA, configuration
-- and VEX artefacts, for transactional active-release withdrawal. Migration owners
-- can still load test fixtures and perform explicit control-plane operations.
CREATE FUNCTION platform.capture_intelligence_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE release uuid; previous jsonb; next_value jsonb; owner_name text;
BEGIN
 release=nullif(current_setting('app.intelligence_release_id',true),'')::uuid;
 IF release IS NULL THEN
   SELECT pg_get_userbyid(relowner) INTO owner_name FROM pg_class WHERE oid=TG_RELID;
   IF current_user<>owner_name THEN RAISE EXCEPTION 'Intelligence writes require reviewed publication'; END IF;
 ELSE
   IF NOT EXISTS(SELECT 1 FROM platform.intelligence_releases WHERE id=release AND status='APPLYING')
   THEN RAISE EXCEPTION 'Publication is unavailable'; END IF;
   IF TG_OP<>'INSERT' THEN previous=to_jsonb(OLD); END IF;
   IF TG_OP<>'DELETE' THEN next_value=to_jsonb(NEW); END IF;
   INSERT INTO platform.intelligence_release_changes(release_id,table_schema,table_name,row_id,previous_value,new_value)
   VALUES(release,TG_TABLE_SCHEMA,TG_TABLE_NAME,coalesce((next_value->>'id')::uuid,(previous->>'id')::uuid),previous,next_value);
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerabilities FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerabilities FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerabilities FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_intel_observations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_intel_observations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_intel_observations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_intel_summary FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_intel_summary FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_intel_summary FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_intel_summary_sources FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_intel_summary_sources FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_intel_summary_sources FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_intel_relations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_intel_relations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_intel_relations FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_targets FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_targets FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_targets FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_rules FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_rules FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_rules FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vulnerability_config_expr FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vulnerability_config_expr FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vulnerability_config_expr FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.vex_assertions FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.vex_assertions FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.vex_assertions FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON public.github_security_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON public.github_security_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON public.github_security_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();

ALTER TABLE platform.vulnerability_intel_observations DROP CONSTRAINT uk_vuln_intel_observation_source_record;
ALTER TABLE platform.vulnerability_intel_observations ADD CONSTRAINT uk_vuln_intel_observation_source_record
 UNIQUE(source_system,source_record_id,vulnerability_id);

CREATE TABLE platform.tenant_intelligence_processing (
 tenant_id uuid PRIMARY KEY REFERENCES platform.tenants(id),required_revision bigint NOT NULL DEFAULT 1,
 completed_revision bigint NOT NULL DEFAULT 0,completed_generation bigint NOT NULL DEFAULT 0,
 evaluating_revision bigint,evaluating_generation bigint,after_component_id uuid,
 status varchar(16) NOT NULL DEFAULT 'PENDING',last_completed_at timestamptz,last_error varchar(255),
 updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO platform.tenant_intelligence_processing(tenant_id) SELECT id FROM platform.tenants;
CREATE FUNCTION platform.schedule_tenant_intelligence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected_tenant uuid;
BEGIN
 IF TG_TABLE_SCHEMA='platform' AND TG_TABLE_NAME='tenants' THEN
  IF TG_OP='UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
  selected_tenant=NEW.id;
 ELSE
  IF TG_OP='DELETE' THEN selected_tenant=OLD.tenant_id; ELSE selected_tenant=NEW.tenant_id; END IF;
 END IF;
 INSERT INTO platform.tenant_intelligence_processing(tenant_id) VALUES(selected_tenant)
 ON CONFLICT(tenant_id) DO UPDATE SET required_revision=tenant_intelligence_processing.required_revision+1,
  status='PENDING',updated_at=now(),last_error=null;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER schedule_tenant_intelligence AFTER INSERT OR UPDATE OF status ON platform.tenants
 FOR EACH ROW EXECUTE FUNCTION platform.schedule_tenant_intelligence();

ALTER TABLE platform.vulnerability_targets ADD COLUMN source_record_id varchar(255);
ALTER TABLE platform.vulnerabilities ADD COLUMN intelligence_withdrawn boolean NOT NULL DEFAULT false;
ALTER TABLE platform.intelligence_publication_outbox ADD COLUMN result_release_id uuid REFERENCES platform.intelligence_releases(id);

CREATE TABLE platform.intelligence_feed_schedules (
 sync_type varchar(64) PRIMARY KEY,enabled boolean NOT NULL DEFAULT false,
 interval_hours integer NOT NULL DEFAULT 24 CHECK(interval_hours BETWEEN 1 AND 8760),
 next_due_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),updated_by varchar(255)
);
INSERT INTO platform.intelligence_feed_schedules(sync_type)
 SELECT unnest(ARRAY['NVD','KEV','GHSA','CSAF_MICROSOFT','CSAF_REDHAT','EUVD','JVN','EPSS','OSV','EOL_FULL_REFRESH','EOL_DATE_SWEEP']);
CREATE FUNCTION platform.guard_candidate_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_TABLE_NAME='intelligence_candidate_records' THEN
  IF NOT EXISTS(SELECT 1 FROM platform.intelligence_candidates WHERE id=NEW.candidate_id AND status='BUILDING' FOR SHARE)
  THEN RAISE EXCEPTION 'Candidate evidence is frozen'; END IF;
 ELSE
  IF OLD.status<>'BUILDING' AND (NEW.digest IS DISTINCT FROM OLD.digest OR NEW.base_release_id IS DISTINCT FROM OLD.base_release_id
   OR NEW.normalization_policy<>OLD.normalization_policy OR NEW.selected_run_ids<>OLD.selected_run_ids
   OR NEW.expanded_run_ids<>OLD.expanded_run_ids OR NEW.quality_report<>OLD.quality_report)
  THEN RAISE EXCEPTION 'Reviewed candidate content is immutable'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER freeze_candidate_content BEFORE UPDATE ON platform.intelligence_candidates
 FOR EACH ROW EXECUTE FUNCTION platform.guard_candidate_evidence();
CREATE TRIGGER freeze_candidate_record_insert BEFORE INSERT ON platform.intelligence_candidate_records
 FOR EACH ROW EXECUTE FUNCTION platform.guard_candidate_evidence();

CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.osv_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.osv_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.osv_advisories FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.advisory_equivalences FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.advisory_equivalences FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.advisory_equivalences FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();

CREATE TABLE platform.intelligence_canonical_redirects (
 id uuid PRIMARY KEY,canonical_id uuid NOT NULL,release_id uuid NOT NULL REFERENCES platform.intelligence_releases(id),
 CHECK(id<>canonical_id)
);
CREATE TRIGGER capture_intelligence_publication_insert BEFORE INSERT ON platform.intelligence_canonical_redirects FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_update BEFORE UPDATE ON platform.intelligence_canonical_redirects FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();
CREATE TRIGGER capture_intelligence_publication_delete BEFORE DELETE ON platform.intelligence_canonical_redirects FOR EACH ROW EXECUTE FUNCTION platform.capture_intelligence_publication();

-- Staging reserves stable identities, while publication may verify/consolidate
-- aliases. Journal only publication changes so withdrawal restores the exact
-- predecessor alias mapping along with its approved observations and redirects.
CREATE FUNCTION platform.capture_identifier_publication() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selected_release uuid;
BEGIN
 selected_release=nullif(current_setting('app.intelligence_release_id',true),'')::uuid;
 IF selected_release IS NULL THEN
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM platform.intelligence_releases WHERE id=selected_release AND status='APPLYING')
 THEN RAISE EXCEPTION 'Identifier publication requires an applying release'; END IF;
 INSERT INTO platform.intelligence_release_changes(release_id,table_schema,table_name,row_id,previous_value,new_value)
 VALUES(selected_release,'platform','intelligence_identifiers',md5(coalesce(NEW.identifier,OLD.identifier))::uuid,
  CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END,
  CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END);
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER capture_identifier_publication_insert BEFORE INSERT ON platform.intelligence_identifiers FOR EACH ROW EXECUTE FUNCTION platform.capture_identifier_publication();
CREATE TRIGGER capture_identifier_publication_update BEFORE UPDATE ON platform.intelligence_identifiers FOR EACH ROW EXECUTE FUNCTION platform.capture_identifier_publication();
CREATE TRIGGER capture_identifier_publication_delete BEFORE DELETE ON platform.intelligence_identifiers FOR EACH ROW EXECUTE FUNCTION platform.capture_identifier_publication();
