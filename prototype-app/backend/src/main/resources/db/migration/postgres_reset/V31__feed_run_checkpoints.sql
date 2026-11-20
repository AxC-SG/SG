-- migration-guard: platform-only
CREATE TABLE platform.feed_run_checkpoints (
    run_id uuid PRIMARY KEY REFERENCES platform.sync_runs(id) ON DELETE CASCADE,
    source text NOT NULL,
    scope jsonb NOT NULL,
    next_batch integer NOT NULL DEFAULT 0 CHECK (next_batch >= 0),
    cursor_value text,
    reported_total integer CHECK (reported_total >= 0),
    fetched integer NOT NULL DEFAULT 0 CHECK (fetched >= 0),
    inserted integer NOT NULL DEFAULT 0 CHECK (inserted >= 0),
    updated integer NOT NULL DEFAULT 0 CHECK (updated >= 0),
    failed integer NOT NULL DEFAULT 0 CHECK (failed >= 0),
    finished boolean NOT NULL DEFAULT false
);

CREATE TABLE platform.feed_run_checkpoint_keys (
    run_id uuid NOT NULL REFERENCES platform.feed_run_checkpoints(run_id) ON DELETE CASCADE,
    key_kind text NOT NULL CHECK (key_kind IN ('RECORD', 'CURSOR')),
    key_value text NOT NULL CHECK (octet_length(key_value) BETWEEN 1 AND 2048),
    PRIMARY KEY (run_id, key_kind, key_value)
);
