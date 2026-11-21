-- migration-guard: platform-only
ALTER TABLE platform.intelligence_release_route_targets
    DROP CONSTRAINT intelligence_release_route_targets_key_kind_check;
ALTER TABLE platform.intelligence_release_route_targets
    ADD CONSTRAINT intelligence_release_route_targets_key_kind_check
    CHECK (key_kind IN ('CPE', 'PURL', 'COORD', 'ECOSYSTEM', 'IDENTITY'));
