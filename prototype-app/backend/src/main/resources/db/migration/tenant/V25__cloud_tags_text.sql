-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Phase 0B §2.2: AWS resource tags and GCP labels are ownership input. The V1 baseline sized assets.cloud_tags_json at
-- 255 characters, so an instance with a few tags failed to save or would lose the owner/team keys. Widen it to text.
ALTER TABLE ${tenantSchema}.assets ALTER COLUMN cloud_tags_json TYPE text;
