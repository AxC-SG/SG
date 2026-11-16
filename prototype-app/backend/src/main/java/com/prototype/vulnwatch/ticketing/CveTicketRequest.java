package com.prototype.vulnwatch.ticketing;

import java.util.List;

/**
 * One ticket covering a CVE and a group of affected assets.
 *
 * <p>{@link TicketingService} partitions a CVE's assets into groups and issues one of these
 * per group, so a provider never has to know the grouping rules.
 *
 * @param cveId           the CVE this ticket is about
 * @param assignmentGroup the group that owns every asset in {@link #assets()}
 * @param assets          the assets this ticket covers; may be empty for a package-only group
 */
public record CveTicketRequest(
        String cveId,
        String assignmentGroup,
        String severity,
        String priority,
        String dueDate,
        String assignee,
        String notes,
        String solutionInfo,
        List<TicketAsset> assets,
        /**
         * True on the canonical routing path (Phase 0B §4.9): {@code assignmentGroup} was derived by the server for this
         * ticket's owner team and must be used as is; providers never fall back to a built-in default group.
         */
        boolean routed
) {
    public CveTicketRequest(String cveId, String assignmentGroup, String severity, String priority, String dueDate, String assignee,
                            String notes, String solutionInfo, List<TicketAsset> assets) {
        this(cveId, assignmentGroup, severity, priority, dueDate, assignee, notes, solutionInfo, assets, false);
    }


    public List<TicketAsset> safeAssets() {
        return assets == null ? List.of() : assets;
    }
}
