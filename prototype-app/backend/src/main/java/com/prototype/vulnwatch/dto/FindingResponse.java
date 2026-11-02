package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingStatus;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

public record FindingResponse(
        UUID id,
        String displayId,
        UUID componentId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String packageName,
        String packageVersion,
        String vulnerabilityId,
        String source,
        FindingCreationSource creationSource,
        String severity,
        boolean inKev,
        Double epss,
        double riskScore,
        double confidenceScore,
        String matchedBy,
        String assignedTo,
        Instant dueAt,
        String suppressionReason,
        Instant suppressedUntil,
        String evidence,
        String precedenceTrace,
        String vexStatus,
        String vexProvider,
        String vexFreshness,
        UUID matchedVexAssertionId,
        String impactReason,
        Instant firstObservedAt,
        Instant lastObservedAt,
        FindingDecisionState decisionState,
        FindingStatus status,
        Instant updatedAt,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        String incidentId,
        String incidentStatus,
        Double findingsScore,
        UUID suppressedByRuleId,
        String suppressedByRuleName,
        String ownerGroup,
        Integer consecutiveMisses,
        Instant autoCloseEligibleAt,
        Instant closedAt,
        String closedBy,
        FindingCloseReason closedReason,
        UUID closedRuleId,
        java.util.Map<String, String> ownership,
        /**
         * Declared AI-BOM resources (models/datasets) this finding transitively affects, per
         * {@code ai_bom_resource_vulnerability_links}. Empty for the vast majority of findings;
         * batch-loaded per page, never per-row.
         */
        java.util.List<AffectedAiResourceSummary> affectedAiResources,
        String intelligenceEligibility,
        UUID intelligenceReleaseId,
        long intelligenceRevision,
        UUID intelligenceMergedIntoId,
        /** VULNERABILITY, AI_POSTURE, AI_EXPOSURE or CRYPTO. */
        String findingKind
) {
}
