-- migration-guard: platform-only
-- Independent canonical projections. No live-table or tenant FK changes.
CREATE TABLE platform.catalog_projection_versions (
 id uuid PRIMARY KEY, state text NOT NULL DEFAULT 'BUILDING'
 CHECK(state IN ('BUILDING','READY','ACTIVE','RETIRED','CANCELLED')),
 fence bigint NOT NULL DEFAULT 0, cursor_id bigint NOT NULL DEFAULT 0,
 processed bigint NOT NULL DEFAULT 0, expected_count bigint NOT NULL CHECK(expected_count>=0),
 base_version uuid, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE platform.catalog_projection_records (
 version_id uuid NOT NULL REFERENCES platform.catalog_projection_versions(id),
 ordinal bigint NOT NULL CHECK(ordinal>0), canonical_id uuid NOT NULL,
 payload jsonb NOT NULL, PRIMARY KEY(version_id,ordinal), UNIQUE(version_id,canonical_id)
);
CREATE TABLE platform.catalog_projection_active (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 version_id uuid REFERENCES platform.catalog_projection_versions(id)
);
INSERT INTO platform.catalog_projection_active(singleton) VALUES(true);
