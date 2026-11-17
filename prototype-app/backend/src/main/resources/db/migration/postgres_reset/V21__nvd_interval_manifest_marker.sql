-- migration-guard: platform-only
-- Legacy observations have no trustworthy ID manifest, including zero-result windows.
ALTER TABLE platform.feed_coverage_observations
    ADD COLUMN ids_recorded_at timestamptz;
