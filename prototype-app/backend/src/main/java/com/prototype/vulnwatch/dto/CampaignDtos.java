package com.prototype.vulnwatch.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.CampaignExceptionStatus;
import com.prototype.vulnwatch.domain.CampaignMembershipState;
import com.prototype.vulnwatch.domain.CampaignRecipientType;
import com.prototype.vulnwatch.domain.CampaignScopeKind;
import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.CampaignWatchlistEntryType;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class CampaignDtos {
    private CampaignDtos() {
    }

    /**
     * A notify recipient (Phase 0B §4.6). {@code TEAM} names a team by ID and uses its notification channel;
     * {@code CUSTOM} (the default) is a free-text label with an address and is never an owner recipient.
     */
    public record CampaignNotifyGroupRequest(
            CampaignRecipientType recipientType,
            UUID teamId,
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

    /**
     * Plan §8.7: one of {@code cveIds} or {@code findingIds}. {@code ownerGroup} and {@code supportGroup} are accepted
     * only so a request naming them can be rejected with 400; a campaign never sets ownership.
     */
    public record CampaignCreateRequest(
            String name,
            String summary,
            List<String> cveIds,
            List<UUID> findingIds,
            Instant dueAt,
            UUID assigneePrincipalId,
            UUID coordinatingTeamId,
            Boolean includeExcepted,
            List<CampaignNotifyGroupRequest> notifyGroups,
            List<CampaignWatchlistEntryRequest> watchlist,
            String launchNote,
            JsonNode ownerGroup,
            JsonNode supportGroup
    ) {
    }

    /**
     * A campaign over canonical findings without CVEs (for example CRYPTO findings). {@code ownerGroup} and the old
     * free-text {@code assignedTo} are rejected with 400; the assignee is a tenant principal.
     */
    public record CampaignFromFindingsRequest(
            String name,
            String summary,
            List<UUID> findingIds,
            Instant dueAt,
            UUID assigneePrincipalId,
            String launchNote,
            JsonNode ownerGroup,
            JsonNode assignedTo
    ) {
        public CampaignFromFindingsRequest(String name, String summary, List<UUID> findingIds, Instant dueAt,
                                           UUID assigneePrincipalId, String launchNote) {
            this(name, summary, findingIds, dueAt, assigneePrincipalId, launchNote, null, null);
        }
    }

    /** Add-findings action (Phase 0B §4.12): members added with {@code add_source = 'MANUAL'}. */
    public record CampaignAddMembersRequest(List<UUID> findingIds) {
    }

    public record CampaignStatusUpdateRequest(
            CampaignStatus status,
            String note
    ) {
    }

    public record CampaignNoteRequest(String body) {
    }

    /** §4.7: {@code findingId} (or a resolvable {@code findingDisplayId}) must name a member of the campaign. */
    public record CampaignExceptionRequest(
            UUID findingId,
            String findingDisplayId,
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

    /**
     * {@code label} is the team name joined at read time for TEAM recipients and the stored label for CUSTOM ones.
     * {@code groupEmail} is returned only for CUSTOM recipients; a TEAM recipient reports {@code channelConfigured}.
     */
    public record CampaignNotifyGroupResponse(
            UUID id,
            CampaignRecipientType recipientType,
            UUID teamId,
            String groupName,
            String groupEmail,
            boolean channelConfigured,
            boolean ownerRecipient,
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

    /** {@code linked} is false for exceptions written before §4.7; they count in no outcome bucket. */
    public record CampaignExceptionResponse(
            UUID id,
            UUID findingId,
            boolean linked,
            String findingDisplayId,
            String assetName,
            String packageName,
            UUID ownerTeamIdAtRequest,
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

    /**
     * Owner recorded when the member was added (§4.4). {@code status} is OWNED, UNOWNED, CONFLICT or
     * LEGACY_PENDING_MIGRATION, or null for members added before the ledger (shown as NOT_RECORDED).
     */
    public record OwnerAtAdd(
            UUID teamId,
            String teamName,
            String status,
            UUID assignmentId
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
            String status,
            String outcome,
            Instant dueAt,
            String incidentId,
            OwnerAtAdd ownerAtAdd,
            OwnershipReadAdapter.Summary currentOwnership
    ) {
    }

    public record CampaignEvidenceRowResponse(
            String cveId,
            String displayId,
            String assetName,
            String assetIdentifier,
            String packageName,
            String severity,
            String status,
            String outcome,
            String incidentId,
            Instant dueAt,
            OwnershipReadAdapter.Summary currentOwnership
    ) {
    }

    /** Grouped by asset ID; owner is read per member, never from {@code assets.support_group} (§4.5). */
    public record CampaignAssetRowResponse(
            String assetId,
            String assetName,
            String assetIdentifier,
            String environment,
            long activeFindings,
            long remediatedFindings,
            long members
    ) {
    }

    /**
     * §4.8 metrics: {@code remediatedCount} counts REMEDIATED only and {@code completionPercent} is REMEDIATED over
     * members. {@code activeRemainingCount} is OPEN + REOPENED. {@code outcomes} carries every bucket.
     */
    public record CampaignSummaryResponse(
            UUID id,
            String name,
            String summary,
            CampaignStatus status,
            CampaignScopeKind scopeKind,
            CampaignMembershipState membershipState,
            UUID assigneePrincipalId,
            UUID coordinatingTeamId,
            Instant dueAt,
            Instant startedAt,
            Instant updatedAt,
            List<String> cveIds,
            int totalFindings,
            int remediatedCount,
            int activeRemainingCount,
            Map<String, Long> outcomes,
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

    /**
     * One campaign member (§4.5). {@code ownershipChanged} is true only when both owners are canonical and the team or
     * status differs; {@code ownerAssignedSinceLaunch} marks a member that was pending migration at add and is canonical
     * now. {@code campaignExceptionStatus} is the latest campaign exception that names this finding, if any.
     */
    public record CampaignMemberResponse(
            UUID findingId,
            String displayId,
            String title,
            String findingKind,
            String severity,
            String findingStatus,
            String closedReason,
            String outcome,
            Instant suppressedUntil,
            Instant dueAt,
            UUID assetId,
            String assetName,
            Instant addedAt,
            String addedBy,
            String addSource,
            OwnerAtAdd ownerAtAdd,
            OwnershipReadAdapter.Summary currentOwnership,
            boolean ownershipChanged,
            boolean ownerAssignedSinceLaunch,
            String campaignExceptionStatus
    ) {
    }

    public record CampaignMemberPage(List<CampaignMemberResponse> items, String nextCursor) {
    }

    /**
     * One owner bucket (§4.5): a team ({@code bucket = "TEAM"}, {@code teamId} set), {@code UNOWNED}, {@code CONFLICT},
     * {@code PENDING_MIGRATION} or, for owner-at-add grouping only, {@code NOT_RECORDED}.
     */
    public record CampaignOwnerBucket(String bucket, UUID teamId, String teamName, long members, long activeRemaining,
                                      Map<String, Long> outcomes) {
    }

    public record CampaignReconciliationResponse(
            UUID campaignId,
            CampaignScopeKind scopeKind,
            CampaignMembershipState membershipState,
            Instant reconciledAt,
            JsonNode watermark,
            Integer lastAdded,
            String lastError,
            int consecutiveFailures,
            long members
    ) {
    }

    /** {@code teams} is the distribution by owner at add; {@code excluded} counts in-scope findings that would not join. */
    public record CampaignPreviewResponse(
            long memberCount,
            boolean exceedsCreateBound,
            List<CampaignOwnerBucket> distribution,
            Map<String, Long> excluded,
            List<PreviewTeam> teamsWithoutChannel
    ) {
    }

    public record PreviewTeam(UUID teamId, String teamName) {
    }
}
