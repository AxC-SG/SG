package com.prototype.vulnwatch.dto;

import java.util.List;

public record CreateServiceNowIncidentRequest(
        String findingTitle,
        String severity,
        Double cvssScore,
        Double epssScore,
        boolean inKev,
        String priority,
        String dueDate,
        String assignedTo,
        String notes,
        /** Patch / fix version info and remediation guidance, placed in resolution_notes */
        String solutionInfo,
        /** Due date (YYYY-MM-DD) for creating a Task SLA remediation target in ServiceNow */
        String taskSlaDueDate,
        List<AffectedAsset> affectedAssets,
        /** Phase 0B §4.9: the preview's routing hash, required on the canonical path. */
        String routingHash,
        /** Group for unmapped or unowned batches when the tenant has no default. */
        String selectedAssignmentGroup,
        /** Sends every batch as one ticket to this group; needs {@code overrideReason}. */
        String assignmentGroupOverride,
        String overrideReason
) {
    public CreateServiceNowIncidentRequest(String findingTitle, String severity, Double cvssScore, Double epssScore, boolean inKev,
                                           String priority, String dueDate, String assignedTo, String notes, String solutionInfo,
                                           String taskSlaDueDate, List<AffectedAsset> affectedAssets) {
        this(findingTitle, severity, cvssScore, epssScore, inKev, priority, dueDate, assignedTo, notes, solutionInfo, taskSlaDueDate,
                affectedAssets, null, null, null, null);
    }

    public record AffectedAsset(
            String componentId,
            String assetName,
            String assetIdentifier,
            String assetType,
            String packageName,
            String packageVersion,
            /** Per-asset CMDB support group; used only on the legacy routing path (Phase 0B §4.9). */
            String assignmentGroup
    ) {}
}
