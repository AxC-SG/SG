-- migration-guard: platform-only
-- Retain the installation record even when an operator identity is revoked.
CREATE TABLE platform.managed_operator_enrollment (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    request_digest char(64) NOT NULL,
    tenant_id uuid NOT NULL,
    owner_binding_id uuid NOT NULL,
    admin_binding_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT current_timestamp,
    CHECK (owner_binding_id <> admin_binding_id)
);

-- Owner-only registry. Runtime table grants cannot read or change the record.
ALTER TABLE platform.managed_operator_enrollment ENABLE ROW LEVEL SECURITY;
