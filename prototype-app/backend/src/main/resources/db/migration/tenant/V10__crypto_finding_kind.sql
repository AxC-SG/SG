-- migration-guard: tenant-only
-- CBOM risk findings are mirrored into the canonical findings list as their own kind, CRYPTO,
-- so analysts see them beside vulnerability findings. The kind set is widened here, as
-- AI_RUNTIME was; the CHECK is replaced, never relaxed to accept arbitrary values.
ALTER TABLE ${tenantSchema}.findings DROP CONSTRAINT findings_kind_check;
ALTER TABLE ${tenantSchema}.findings ADD CONSTRAINT findings_kind_check
    CHECK (finding_kind IN ('VULNERABILITY','AI_POSTURE','AI_EXPOSURE','AI_RUNTIME','CRYPTO'));
