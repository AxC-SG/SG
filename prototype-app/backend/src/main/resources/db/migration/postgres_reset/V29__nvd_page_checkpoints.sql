-- migration-guard: platform-only
CREATE TABLE platform.nvd_run_plans (
    run_id uuid PRIMARY KEY REFERENCES platform.sync_runs(id) ON DELETE CASCADE,
    start_at timestamptz,
    end_at timestamptz,
    filters jsonb NOT NULL,
    CHECK ((start_at IS NULL AND end_at IS NULL) OR (start_at IS NOT NULL AND end_at IS NOT NULL AND start_at < end_at))
);

CREATE TABLE platform.nvd_page_checkpoints (
    run_id uuid NOT NULL REFERENCES platform.nvd_run_plans(run_id) ON DELETE CASCADE,
    window_key text NOT NULL,
    start_index integer NOT NULL CHECK (start_index >= 0),
    next_index integer NOT NULL CHECK (next_index > start_index),
    fetched integer NOT NULL CHECK (fetched >= 0),
    inserted integer NOT NULL CHECK (inserted >= 0),
    updated integer NOT NULL CHECK (updated >= 0),
    reported_total integer NOT NULL CHECK (reported_total >= 0),
    finished boolean NOT NULL,
    observed_ids varchar(32)[] NOT NULL CHECK (cardinality(observed_ids) <= 2000),
    PRIMARY KEY (run_id, window_key, start_index)
);
