-- Repair tenants whose AI digest constraints predate guardrail observations
-- and the expanded comparison outcomes.

ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_baselines
    DROP CONSTRAINT IF EXISTS ai_security_digest_baseline_kind_check,
    ADD CONSTRAINT ai_security_digest_baseline_kind_check
        CHECK (digest_kind IN ('PROMPT', 'TOOL_DEFINITION', 'GUARDRAIL_CONFIGURATION'));

ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_observations
    DROP CONSTRAINT IF EXISTS ai_security_artifact_digest_observations_digest_kind_check,
    ADD CONSTRAINT ai_security_artifact_digest_observations_digest_kind_check
        CHECK (digest_kind IN ('PROMPT', 'TOOL_DEFINITION', 'GUARDRAIL_CONFIGURATION'));

ALTER TABLE ${tenantSchema}.ai_security_artifact_digest_observations
    DROP CONSTRAINT IF EXISTS ai_security_artifact_digest_observatio_comparison_outcome_check,
    ADD CONSTRAINT ai_security_artifact_digest_observatio_comparison_outcome_check
        CHECK (comparison_outcome IN (
            'UNAPPROVED',
            'UNCHANGED',
            'CHANGED_AFTER_APPROVAL',
            'BASELINE_UNKNOWN_REAPPROVAL_REQUIRED',
            'CONTROL_WEAKENED',
            'CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED',
            'CONFIGURATION_UNKNOWN'
        ));
