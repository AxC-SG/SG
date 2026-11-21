-- migration-guard: platform-only
CREATE TABLE platform.intelligence_release_routes (
    release_id uuid PRIMARY KEY REFERENCES platform.intelligence_releases(id),
    mode text NOT NULL CHECK (mode IN ('APPLICABILITY', 'RANKING'))
);

CREATE TABLE platform.intelligence_release_route_vulnerabilities (
    release_id uuid NOT NULL REFERENCES platform.intelligence_release_routes(release_id),
    vulnerability_id uuid NOT NULL,
    PRIMARY KEY (release_id, vulnerability_id)
);

CREATE TABLE platform.intelligence_release_route_targets (
    release_id uuid NOT NULL REFERENCES platform.intelligence_release_routes(release_id),
    key_kind text NOT NULL CHECK (key_kind IN ('CPE', 'PURL', 'ECOSYSTEM', 'IDENTITY')),
    match_key text NOT NULL,
    PRIMARY KEY (release_id, key_kind, match_key)
);

ALTER TABLE platform.tenant_intelligence_processing
    ADD COLUMN targeted_revision bigint,
    ADD COLUMN targeted_generation bigint,
    ADD COLUMN ranking_rollups_complete boolean NOT NULL DEFAULT false;
