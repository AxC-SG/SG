-- migration-guard: platform-only
-- Current observation metadata; historical rows remain unknown until re-acquired.
ALTER TABLE platform.vulnerability_intel_observations
    ADD COLUMN cvss_version varchar(20);
