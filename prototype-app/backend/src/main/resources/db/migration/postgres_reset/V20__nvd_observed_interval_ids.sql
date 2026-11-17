-- migration-guard: platform-only
-- IDs observed in a completed bounded fetch. This is not an independent NVD baseline certificate.
CREATE TABLE platform.nvd_observed_interval_ids (
    run_id uuid NOT NULL,
    interval_start timestamptz NOT NULL,
    interval_end timestamptz NOT NULL,
    cve_id varchar(32) NOT NULL,
    CONSTRAINT nvd_observed_interval_ids_pkey PRIMARY KEY (run_id, interval_start, interval_end, cve_id),
    CONSTRAINT nvd_observed_interval_ids_coverage_fk FOREIGN KEY (run_id, interval_start, interval_end)
        REFERENCES platform.feed_coverage_observations (run_id, interval_start, interval_end)
        ON DELETE CASCADE,
    CONSTRAINT nvd_observed_interval_ids_cve_check CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
);
CREATE INDEX nvd_observed_interval_ids_cve_idx ON platform.nvd_observed_interval_ids (cve_id);
