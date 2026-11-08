-- migration-guard: platform-only
ALTER TABLE platform.managed_login_attempts ADD COLUMN invite_hash char(64);
