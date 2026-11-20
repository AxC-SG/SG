-- migration-guard: platform-only
ALTER TABLE platform.catalog_projection_versions ADD COLUMN candidate_id uuid;
CREATE UNIQUE INDEX catalog_projection_candidate_idx ON platform.catalog_projection_versions(candidate_id) WHERE candidate_id IS NOT NULL;
