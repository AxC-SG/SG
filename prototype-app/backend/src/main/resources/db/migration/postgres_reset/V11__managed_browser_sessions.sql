-- migration-guard: platform-only
CREATE TABLE platform.managed_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer varchar(255) NOT NULL,
    subject varchar(255) NOT NULL,
    user_id uuid NOT NULL REFERENCES platform.app_users(id) ON DELETE CASCADE,
    UNIQUE (issuer, subject),
    UNIQUE (issuer, user_id)
);

CREATE TABLE platform.managed_login_attempts (
    state_hash char(64) PRIMARY KEY,
    browser_hash char(64) NOT NULL,
    verifier varchar(128) NOT NULL,
    nonce varchar(128) NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX managed_login_attempts_expiry_idx ON platform.managed_login_attempts (expires_at);

CREATE TABLE platform.managed_browser_sessions (
    token_hash char(64) PRIMARY KEY,
    identity_id uuid NOT NULL REFERENCES platform.managed_identities(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES platform.app_users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX managed_browser_sessions_expiry_idx ON platform.managed_browser_sessions (expires_at);
CREATE INDEX managed_browser_sessions_identity_idx ON platform.managed_browser_sessions (identity_id);
CREATE INDEX managed_browser_sessions_user_idx ON platform.managed_browser_sessions (user_id);
