package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

/**
 * Canonical findings filter contract shared by records, analytics, and future
 * saved/shared queue definitions.
 */
public record FindingsFilter(
        List<String> severity,
        List<String> status,
        List<String> decisionState,
        List<String> creationSource,
        List<String> matchMethod,
        List<String> vexStatus,
        List<String> vexFreshness,
        List<String> vexProvider,
        Double minConfidence,
        String vulnerabilityId,
        String packageName,
        String ecosystem,
        String ownerGroup,
        String assignedTo,
        Boolean unassignedOnly,
        Boolean incidentLinked,
        String dueDateBand,
        String assetName,
        String supportGroup,
        Boolean patchAvailable,
        String suppressedUntilBand,
        List<String> assetType,
        String groupField,
        String groupValue,
        /**
         * Finding kinds to include. Null or empty means every in-scope kind, which keeps the All
         * Findings view inclusive; the software-vulnerability view selects VULNERABILITY
         * explicitly. Cannot be inferred from vulnerabilityId, which the projection populates
         * with a CVE id or an AI policy id depending on the kind.
         */
        List<String> findingKind,
        /**
         * Restricts to findings transitively affecting one of these declared AI-BOM resource
         * ids ({@code ai_bom_resource_vulnerability_links.declared_resource_id}). Null or empty
         * means no restriction.
         */
        List<String> affectedAiResourceId,
        /**
         * {@code true} restricts to findings affecting any declared AI resource at all;
         * {@code false} restricts to findings affecting none. Null means no restriction.
         * Independent of {@link #affectedAiResourceId} -- both apply (ANDed) if both are set.
         */
        Boolean hasAffectedAiResource,
        /**
         * Canonical owner team (stable ID) and resolved ownership status (OWNED, UNOWNED, CONFLICT), ownership plan §9.7.
         * Only CORE (VULNERABILITY) findings can match, and only once findings ownership is canonical. Supported on
         * cursor (projection) paging; offset/JPA paging rejects them rather than returning a different result set.
         */
        UUID ownerTeamId,
        String ownershipStatus
) {
    /** Backward-compatible constructor for call sites predating the ownership filters. */
    public FindingsFilter(
            List<String> severity, List<String> status, List<String> decisionState, List<String> creationSource,
            List<String> matchMethod, List<String> vexStatus, List<String> vexFreshness, List<String> vexProvider,
            Double minConfidence, String vulnerabilityId, String packageName, String ecosystem, String ownerGroup,
            String assignedTo, Boolean unassignedOnly, Boolean incidentLinked, String dueDateBand, String assetName,
            String supportGroup, Boolean patchAvailable, String suppressedUntilBand, List<String> assetType,
            String groupField, String groupValue, List<String> findingKind, List<String> affectedAiResourceId,
            Boolean hasAffectedAiResource
    ) {
        this(severity, status, decisionState, creationSource, matchMethod, vexStatus, vexFreshness, vexProvider, minConfidence,
                vulnerabilityId, packageName, ecosystem, ownerGroup, assignedTo, unassignedOnly, incidentLinked, dueDateBand,
                assetName, supportGroup, patchAvailable, suppressedUntilBand, assetType, groupField, groupValue, findingKind,
                affectedAiResourceId, hasAffectedAiResource, null, null);
    }

    /** True when the canonical ownership filters are set. */
    public boolean hasOwnershipFilter() {
        return ownerTeamId != null || (ownershipStatus != null && !ownershipStatus.isBlank());
    }

    public FindingsFilter(
        List<String> severity,
        List<String> status,
        List<String> decisionState,
        List<String> creationSource,
        List<String> matchMethod,
        List<String> vexStatus,
        List<String> vexFreshness,
        List<String> vexProvider,
        Double minConfidence,
        String vulnerabilityId,
        String packageName,
        String ecosystem,
        String ownerGroup,
        String assignedTo,
        Boolean unassignedOnly,
        Boolean incidentLinked,
        String dueDateBand,
        String assetName,
        String supportGroup,
        Boolean patchAvailable,
        String suppressedUntilBand,
        List<String> assetType
    ) {
        this(severity, status, decisionState, creationSource, matchMethod, vexStatus, vexFreshness, vexProvider, minConfidence, vulnerabilityId, packageName, ecosystem, ownerGroup, assignedTo, unassignedOnly, incidentLinked, dueDateBand, assetName, supportGroup, patchAvailable, suppressedUntilBand, assetType, null, null, null, null, null);
    }

    /** Backward-compatible constructor for call sites predating the AI-resource filters. */
    public FindingsFilter(
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> creationSource,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem,
            String ownerGroup,
            String assignedTo,
            Boolean unassignedOnly,
            Boolean incidentLinked,
            String dueDateBand,
            String assetName,
            String supportGroup,
            Boolean patchAvailable,
            String suppressedUntilBand,
            List<String> assetType,
            String groupField,
            String groupValue,
            List<String> findingKind
    ) {
        this(
                severity, status, decisionState, creationSource, matchMethod, vexStatus, vexFreshness,
                vexProvider, minConfidence, vulnerabilityId, packageName, ecosystem, ownerGroup, assignedTo,
                unassignedOnly, incidentLinked, dueDateBand, assetName, supportGroup, patchAvailable,
                suppressedUntilBand, assetType, groupField, groupValue, findingKind, null, null
        );
    }

    /** Backward-compatible constructor for call sites predating the {@code assetType} filter. */
    public FindingsFilter(
            List<String> severity,
            List<String> status,
            List<String> decisionState,
            List<String> creationSource,
            List<String> matchMethod,
            List<String> vexStatus,
            List<String> vexFreshness,
            List<String> vexProvider,
            Double minConfidence,
            String vulnerabilityId,
            String packageName,
            String ecosystem,
            String ownerGroup,
            String assignedTo,
            Boolean unassignedOnly,
            Boolean incidentLinked,
            String dueDateBand,
            String assetName,
            String supportGroup,
            Boolean patchAvailable,
            String suppressedUntilBand
    ) {
        this(
                severity, status, decisionState, creationSource, matchMethod, vexStatus, vexFreshness,
                vexProvider, minConfidence, vulnerabilityId, packageName, ecosystem, ownerGroup, assignedTo,
                unassignedOnly, incidentLinked, dueDateBand, assetName, supportGroup, patchAvailable,
                suppressedUntilBand, null
        );
    }
}
