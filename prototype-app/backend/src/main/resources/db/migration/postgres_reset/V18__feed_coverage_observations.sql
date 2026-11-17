-- migration-guard: platform-only
-- A successful bounded fetch is evidence for one scope and interval, not a source-wide certificate.
CREATE TABLE platform.feed_coverage_observations (
    run_id uuid NOT NULL REFERENCES platform.sync_runs(id),
    source_system varchar(32) NOT NULL,
    feed_key varchar(128) NOT NULL,
    interval_start timestamptz NOT NULL,
    interval_end timestamptz NOT NULL,
    fetched_records integer NOT NULL CHECK (fetched_records >= 0),
    observed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT feed_coverage_observations_interval_check CHECK (interval_start < interval_end),
    CONSTRAINT feed_coverage_observations_pkey PRIMARY KEY (run_id, interval_start, interval_end)
);
CREATE INDEX feed_coverage_observations_scope_idx
    ON platform.feed_coverage_observations (feed_key, interval_start, interval_end);
CREATE INDEX feed_coverage_observations_source_idx
    ON platform.feed_coverage_observations (source_system, interval_end DESC);
