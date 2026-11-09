package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingsFilter;
import java.util.List;
import java.util.Objects;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingQueueResolutionService {

    private final WorkspaceService workspaceService;
    private final FindingQueueDefinitionService findingQueueDefinitionService;
    private final PersonalFindingQueueService personalFindingQueueService;

    public FindingQueueResolutionService(
            WorkspaceService workspaceService,
            FindingQueueDefinitionService findingQueueDefinitionService,
            PersonalFindingQueueService personalFindingQueueService
    ) {
        this.workspaceService = workspaceService;
        this.findingQueueDefinitionService = findingQueueDefinitionService;
        this.personalFindingQueueService = personalFindingQueueService;
    }

    @Transactional(readOnly = true)
    public FindingsFilter resolveEffectiveFilter(String queueRef, FindingsFilter adHocFilter) {
        if (!FindingFilterSpecifications.hasText(queueRef)) {
            return adHocFilter;
        }
        FindingsFilter builtInFilter = findingQueueDefinitionService.findBuiltInFilter(queueRef).orElse(null);
        FindingsFilter queueFilter;
        String queueTitle;
        if (builtInFilter != null) {
            queueFilter = builtInFilter;
            queueTitle = findingQueueDefinitionService.findBuiltInTitle(queueRef).orElse(queueRef);
        } else {
            Tenant tenant = workspaceService.getWorkspace();
            queueFilter = personalFindingQueueService.loadQueueFilterForCurrentUser(tenant, queueRef);
            queueTitle = personalFindingQueueService.queueTitleForCurrentUser(tenant, queueRef);
        }
        validateCompatible(queueFilter, adHocFilter, queueTitle);
        return merge(queueFilter, adHocFilter);
    }

    private void validateCompatible(FindingsFilter queueFilter, FindingsFilter adHocFilter, String queueTitle) {
        if (adHocFilter == null) {
            return;
        }
        requireSubset("severity", queueFilter.severity(), adHocFilter.severity(), queueTitle);
        requireSubset("status", queueFilter.status(), adHocFilter.status(), queueTitle);
        requireSubset("decisionState", queueFilter.decisionState(), adHocFilter.decisionState(), queueTitle);
        requireSubset("creationSource", queueFilter.creationSource(), adHocFilter.creationSource(), queueTitle);
        requireSubset("matchMethod", queueFilter.matchMethod(), adHocFilter.matchMethod(), queueTitle);
        requireSubset("vexStatus", queueFilter.vexStatus(), adHocFilter.vexStatus(), queueTitle);
        requireSubset("vexFreshness", queueFilter.vexFreshness(), adHocFilter.vexFreshness(), queueTitle);
        requireSubset("vexProvider", queueFilter.vexProvider(), adHocFilter.vexProvider(), queueTitle);
        requireSubset("assetType", queueFilter.assetType(), adHocFilter.assetType(), queueTitle);
        requireExact("groupField", queueFilter.groupField(), adHocFilter.groupField(), queueTitle);
        requireExact("groupValue", queueFilter.groupValue(), adHocFilter.groupValue(), queueTitle);
        requireExact("vulnerabilityId", queueFilter.vulnerabilityId(), adHocFilter.vulnerabilityId(), queueTitle);
        requireExact("packageName", queueFilter.packageName(), adHocFilter.packageName(), queueTitle);
        requireExact("ecosystem", queueFilter.ecosystem(), adHocFilter.ecosystem(), queueTitle);
        requireExact("ownerGroup", queueFilter.ownerGroup(), adHocFilter.ownerGroup(), queueTitle);
        requireExact("dueDateBand", queueFilter.dueDateBand(), adHocFilter.dueDateBand(), queueTitle);
        requireExact("suppressedUntilBand", queueFilter.suppressedUntilBand(), adHocFilter.suppressedUntilBand(), queueTitle);
        requireBoolean("incidentLinked", queueFilter.incidentLinked(), adHocFilter.incidentLinked(), queueTitle);
        requireBoolean("unassignedOnly", queueFilter.unassignedOnly(), adHocFilter.unassignedOnly(), queueTitle);
        requireBoolean("patchAvailable", queueFilter.patchAvailable(), adHocFilter.patchAvailable(), queueTitle);

        if (queueFilter.minConfidence() != null && adHocFilter.minConfidence() != null
                && adHocFilter.minConfidence() < queueFilter.minConfidence()) {
            throw conflict(queueTitle, "minConfidence");
        }
    }

    private FindingsFilter merge(FindingsFilter queueFilter, FindingsFilter adHocFilter) {
        if (adHocFilter == null) {
            return queueFilter;
        }
        return new FindingsFilter(
                coalesceList(adHocFilter.severity(), queueFilter.severity()),
                coalesceList(adHocFilter.status(), queueFilter.status()),
                coalesceList(adHocFilter.decisionState(), queueFilter.decisionState()),
                coalesceList(adHocFilter.creationSource(), queueFilter.creationSource()),
                coalesceList(adHocFilter.matchMethod(), queueFilter.matchMethod()),
                coalesceList(adHocFilter.vexStatus(), queueFilter.vexStatus()),
                coalesceList(adHocFilter.vexFreshness(), queueFilter.vexFreshness()),
                coalesceList(adHocFilter.vexProvider(), queueFilter.vexProvider()),
                adHocFilter.minConfidence() != null ? adHocFilter.minConfidence() : queueFilter.minConfidence(),
                coalesceText(adHocFilter.vulnerabilityId(), queueFilter.vulnerabilityId()),
                coalesceText(adHocFilter.packageName(), queueFilter.packageName()),
                coalesceText(adHocFilter.ecosystem(), queueFilter.ecosystem()),
                coalesceText(adHocFilter.ownerGroup(), queueFilter.ownerGroup()),
                coalesceText(adHocFilter.assignedTo(), queueFilter.assignedTo()),
                adHocFilter.unassignedOnly() != null ? adHocFilter.unassignedOnly() : queueFilter.unassignedOnly(),
                adHocFilter.incidentLinked() != null ? adHocFilter.incidentLinked() : queueFilter.incidentLinked(),
                coalesceText(adHocFilter.dueDateBand(), queueFilter.dueDateBand()),
                coalesceText(adHocFilter.assetName(), queueFilter.assetName()),
                coalesceText(adHocFilter.supportGroup(), queueFilter.supportGroup()),
                adHocFilter.patchAvailable() != null ? adHocFilter.patchAvailable() : queueFilter.patchAvailable(),
                coalesceText(adHocFilter.suppressedUntilBand(), queueFilter.suppressedUntilBand()),
                coalesceList(adHocFilter.assetType(), queueFilter.assetType()),
                coalesceText(adHocFilter.groupField(), queueFilter.groupField()),
                coalesceText(adHocFilter.groupValue(), queueFilter.groupValue()),
                coalesceList(adHocFilter.findingKind(), queueFilter.findingKind()),
                null,
                null,
                adHocFilter.ownerTeamId() != null ? adHocFilter.ownerTeamId() : queueFilter.ownerTeamId(),
                coalesceText(adHocFilter.ownershipStatus(), queueFilter.ownershipStatus())
        );
    }

    private <T> void requireSubset(String field, List<T> queueValues, List<T> adHocValues, String queueTitle) {
        if (queueValues == null || queueValues.isEmpty() || adHocValues == null || adHocValues.isEmpty()) {
            return;
        }
        if (!queueValues.containsAll(adHocValues)) {
            throw conflict(queueTitle, field);
        }
    }

    private void requireExact(String field, String queueValue, String adHocValue, String queueTitle) {
        if (!FindingFilterSpecifications.hasText(queueValue) || !FindingFilterSpecifications.hasText(adHocValue)) {
            return;
        }
        if (!queueValue.trim().equalsIgnoreCase(adHocValue.trim())) {
            throw conflict(queueTitle, field);
        }
    }

    private void requireBoolean(String field, Boolean queueValue, Boolean adHocValue, String queueTitle) {
        if (queueValue == null || adHocValue == null) {
            return;
        }
        if (!Objects.equals(queueValue, adHocValue)) {
            throw conflict(queueTitle, field);
        }
    }

    private IllegalArgumentException conflict(String queueTitle, String field) {
        return new IllegalArgumentException("Filter conflicts with queue \"" + queueTitle + "\" for field: " + field);
    }

    private <T> List<T> coalesceList(List<T> preferred, List<T> fallback) {
        return preferred != null && !preferred.isEmpty() ? preferred : fallback;
    }

    private String coalesceText(String preferred, String fallback) {
        return FindingFilterSpecifications.hasText(preferred) ? preferred.trim() : fallback;
    }
}
