package com.prototype.vulnwatch.ticketing;

/**
 * One asset affected by a CVE, in provider-neutral terms.
 *
 * @param componentId      inventory component id, used to link the resulting ticket to findings
 * @param assetName        display name
 * @param assetIdentifier  provider-native identifier where one exists (a ServiceNow CI sys_id)
 * @param assetType        host, container, image, …
 * @param packageName      affected software package
 * @param packageVersion   installed version
 * @param assignmentGroup  owning group from CMDB ownership, when known
 */
public record TicketAsset(
        String componentId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String packageName,
        String packageVersion,
        String assignmentGroup
) {
}
