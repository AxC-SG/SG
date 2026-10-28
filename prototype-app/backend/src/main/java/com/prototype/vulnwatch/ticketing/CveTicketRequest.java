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
        List<TicketAsset> assets
) {

    public List<TicketAsset> safeAssets() {
        return assets == null ? List.of() : assets;
    }
}
