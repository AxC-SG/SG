-- migration-guard: platform-only
CREATE TABLE platform.intelligence_import_profiles (
    id uuid PRIMARY KEY,
    name text NOT NULL,
    profile jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE platform.intelligence_import_profiles IS
    'Immutable platform acquisition profiles; publication years use source publication dates.';
