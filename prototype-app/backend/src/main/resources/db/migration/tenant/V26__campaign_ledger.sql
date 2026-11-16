-- migration-guard: tenant-only
SELECT set_config('app.current_tenant_id', '${tenantId}', true);

-- Phase 0B §4.2/§4.3: the reconciler applies the same exception filter as the create transaction, so a campaign
-- created with includeExcepted keeps adding excepted findings when it materializes in batches.
ALTER TABLE ${tenantSchema}.campaigns ADD COLUMN include_excepted boolean NOT NULL DEFAULT false;

-- §4.3: the reconciler's keyset over (updated_at, id) for the findings of one CVE.
CREATE INDEX findings_vulnerability_updated_idx ON ${tenantSchema}.findings (vulnerability_id, updated_at, id)
    WHERE vulnerability_id IS NOT NULL;

-- §4.6/§4.10 contract cleanup: custom recipient addresses are stored only as tenant ciphertext (group_email_enc).
-- There is no customer data to carry over, so the plaintext column is dropped rather than re-encrypted.
ALTER TABLE ${tenantSchema}.campaign_notify_groups DROP COLUMN group_email;
