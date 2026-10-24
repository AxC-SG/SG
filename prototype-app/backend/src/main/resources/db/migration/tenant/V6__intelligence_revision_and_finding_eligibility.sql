ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_eligibility varchar(32) NOT NULL DEFAULT 'ELIGIBLE'
 CHECK(intelligence_eligibility IN ('ELIGIBLE','SOURCE_DISABLED','INTELLIGENCE_WITHDRAWN'));
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_release_id uuid;
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_severity varchar(32);
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_epss double precision;
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_in_kev boolean;
ALTER TABLE ${tenantSchema}.finding_delta_queue ADD COLUMN intelligence_release_id uuid;
ALTER TABLE ${tenantSchema}.finding_delta_queue ADD COLUMN intelligence_revision bigint;
CREATE INDEX finding_intelligence_eligibility_idx ON ${tenantSchema}.findings(intelligence_eligibility,status);
-- Restrictive policy composes with existing tenant isolation for dashboards,
-- exports, native SQL and downstream workflows. Evaluation/history explicitly opt in.
CREATE POLICY finding_intelligence_eligibility ON ${tenantSchema}.findings AS RESTRICTIVE FOR SELECT
 USING(intelligence_eligibility='ELIGIBLE' OR coalesce(current_setting('app.include_ineligible_intelligence',true),'')='true');
CREATE TRIGGER schedule_inventory_intelligence AFTER INSERT OR UPDATE OR DELETE ON ${tenantSchema}.inventory_components
 FOR EACH ROW EXECUTE FUNCTION platform.schedule_tenant_intelligence();
CREATE TRIGGER schedule_source_intelligence AFTER INSERT OR UPDATE OR DELETE ON ${tenantSchema}.vulnerability_source_filter_configs
 FOR EACH ROW EXECUTE FUNCTION platform.schedule_tenant_intelligence();
-- Persist supported defaults for every new or existing tenant through the normal
-- source setting table, including manual advisories and enrichment.
INSERT INTO ${tenantSchema}.vulnerability_source_filter_configs(id,tenant_id,source_system,enabled_for_correlation,filters_json,created_at,updated_at)
 SELECT md5('${tenantId}'||source)::uuid,'${tenantId}'::uuid,source,true,'{}',now(),now()
 FROM unnest(ARRAY['nvd','kev','ghsa','redhat','microsoft','euvd','jvn','advisory','epss']) source
 ON CONFLICT DO NOTHING;

CREATE POLICY projection_intelligence_eligibility ON ${tenantSchema}.finding_list_projection AS RESTRICTIVE FOR SELECT
 USING(EXISTS(SELECT 1 FROM ${tenantSchema}.findings f WHERE f.id=finding_id));
ALTER TABLE ${tenantSchema}.findings ADD COLUMN intelligence_merged_into_id uuid;
CREATE FUNCTION ${tenantSchema}.stamp_intelligence_queue_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 SELECT s.release_id,p.required_revision INTO NEW.intelligence_release_id,NEW.intelligence_revision
 FROM platform.intelligence_active_state s JOIN platform.tenant_intelligence_processing p ON p.tenant_id=NEW.tenant_id;
 RETURN NEW;
END $$;
CREATE TRIGGER stamp_intelligence_queue_revision_insert BEFORE INSERT ON ${tenantSchema}.finding_delta_queue
 FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.stamp_intelligence_queue_revision();
CREATE TRIGGER stamp_intelligence_queue_revision_update BEFORE UPDATE OF status ON ${tenantSchema}.finding_delta_queue
 FOR EACH ROW EXECUTE FUNCTION ${tenantSchema}.stamp_intelligence_queue_revision();
