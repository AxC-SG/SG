-- migration-guard: platform-only
ALTER TABLE platform.intelligence_feed_schedules ADD COLUMN import_profile_id uuid REFERENCES platform.intelligence_import_profiles(id);
