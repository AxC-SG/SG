-- migration-guard: platform-only
CREATE TABLE platform.feed_sync_watermarks (
    feed_key varchar(128) PRIMARY KEY,
    completed_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
