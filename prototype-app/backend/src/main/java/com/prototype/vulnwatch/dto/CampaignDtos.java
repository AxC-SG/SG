package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.CampaignExceptionStatus;
import com.prototype.vulnwatch.domain.CampaignWatchlistEntryType;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class CampaignDtos {
    private CampaignDtos() {
    }

    public record CampaignNotifyGroupRequest(
            String groupName,
            String groupEmail,
            String roleLabel,
            String triggerSummary,
            Boolean notificationsPaused
    ) {
    }

    public record CampaignWatchlistEntryRequest(
            CampaignWatchlistEntryType entryType,
            String label,
            String email,
            String triggerPolicy,
            Boolean active
    ) {
    }

    public record CampaignWatchlistEntryUpdateRequest(
            String label,
            String email,
            String triggerPolicy,
            Boolean active
    ) {
    }

    public record CampaignCreateRequest(
            String name,
            String summary,
            List<String> cveIds,
            Instant dueAt,
            List<CampaignNotifyGroupRequest> notifyGroups,
            List<CampaignWatchlistEntryRequest> watchlist,
            String launchNote
    ) {
    }

    /** A campaign over canonical findings without CVEs (for example CRYPTO findings), with optional bulk assignment. */
    public record CampaignFromFindingsRequest(
            String name,
            String summary,
            List<UUID> findingIds,
            Instant dueAt,
            String assignedTo,
            String ownerGroup,
            String launchNote
    ) {
    }

    public record CampaignFindingResponse(
            UUID findingId,
            String displayId,
            String title,
            String findingKind,
            String severity,
            String status,
            String assignedTo,
            String ownerGroup,
            Instant dueAt,
            String verificationStatus,
            Instant addedAt
    ) {
    }

    public record CampaignStatusUpdateRequest(
            CampaignStatus status,
            String note
    ) {
    }

    public record CampaignNoteRequest(String body) {
    }

    public record CampaignExceptionRequest(
            String findingDisplayId,
            String assetName,
            String packageName,
            String title,
            String reason,
            Instant decisionDueAt
    ) {
    }

    public record CampaignExceptionStatusUpdateRequest(
            CampaignExceptionStatus status
    ) {
    }

    public record CampaignVulnerabilityResponse(
            String externalId,
            String title,
            String severity
    ) {
    }

    public record CampaignNotifyGroupResponse(
            UUID id,
            String groupName,
            String groupEmail,
            String roleLabel,
            String triggerSummary,
            boolean notificationsPaused
    ) {
    }

    public record CampaignWatchlistEntryResponse(
            UUID id,
            CampaignWatchlistEntryType entryType,
            String label,
            String email,
            String triggerPolicy,
            boolean active
    ) {
    }

    public record CampaignNoteResponse(
            UUID id,
            String author,
            String body,
            Instant createdAt
    ) {
    }

    public record CampaignActivityResponse(
            UUID id,
            String activityType,
            String actor,
            String body,
            Instant createdAt
    ) {
    }

    public record CampaignDeliveryAttemptResponse(
            UUID id,
            String targetType,
            String targetLabel,
            String targetAddress,
            String subject,
            String deliveryState,
            String detail,
            Instant createdAt
    ) {
    }

    public record CampaignExceptionResponse(
            UUID id,
            String findingDisplayId,
            String assetName,
            String packageName,
            String title,
            String reason,
            CampaignExceptionStatus status,
            String requestedBy,
            Instant requestedAt,
            Instant decisionDueAt,
            String decisionedBy,
            Instant decisionedAt
    ) {
    }

    public record CampaignFindingRowResponse(
            String findingId,
            String displayId,
            String vulnerabilityId,
            String assetName,
            String assetIdentifier,
            String packageName,
            String severity,
            String ownerGroup,
            String status,
            Instant dueAt,
            String incidentId
    ) {
    }

    public record CampaignEvidenceRowResponse(
            String cveId,
            String displayId,
            String assetName,
            String assetIdentifier,
            String packageName,
            String severity,
            String ownerGroup,
            String status,
            String incidentId,
            Instant dueAt
    ) {
    }

    public record CampaignAssetRowResponse(
            String assetId,
            String assetName,
            String assetIdentifier,
            String environment,
            String supportGroup,
            long openFindings,
            long resolvedFindings
    ) {
    }

    public record CampaignSummaryResponse(
            UUID id,
            String name,
            String summary,
            CampaignStatus status,
            Instant dueAt,
            Instant startedAt,
            Instant updatedAt,
            List<String> cveIds,
            int totalFindings,
            int resolvedFindings,
            int openFindings,
            int assetCount,
            int exceptionCount,
            int notifyGroupCount,
            int watchlistCount,
            int completionPercent
    ) {
    }

    public record CampaignDetailResponse(
            CampaignSummaryResponse summary,
            List<CampaignVulnerabilityResponse> vulnerabilities,
            List<CampaignNotifyGroupResponse> notifyGroups,
            List<CampaignWatchlistEntryResponse> watchlist,
            List<CampaignNoteResponse> notes,
            List<CampaignExceptionResponse> exceptions,
            List<CampaignActivityResponse> activity,
            List<CampaignDeliveryAttemptResponse> deliveryAttempts,
            List<CampaignFindingRowResponse> findings,
            List<CampaignAssetRowResponse> assets,
            List<CampaignEvidenceRowResponse> evidence
    ) {
    }
}
