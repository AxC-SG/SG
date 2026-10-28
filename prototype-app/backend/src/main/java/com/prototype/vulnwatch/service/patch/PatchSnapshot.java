package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import java.time.Instant;
import java.util.List;

/**
 * A provider's view of one sync, in provider-neutral terms.
 *
 * @param complete false when any listing was truncated or failed; nothing is ever marked stale
 *                 from an incomplete snapshot
 */
public record PatchSnapshot(
        List<Device> devices,
        List<Patch> patches,
        List<Deployment> deployments,
        List<Status> statuses,
        boolean complete,
        List<String> warnings
) {

    public record Device(String externalId, String hostname, String serialNumber, String osName) {}

    /**
     * @param kbArticle   Microsoft KB number without the "KB" prefix, when the patch has one
     * @param cves        CVEs the tool itself attributes to the patch
     */
    public record Patch(
            String externalId,
            String kbArticle,
            String bulletinId,
            String title,
            String vendor,
            String product,
            String classification,
            String vendorSeverity,
            String severity,
            FixRecord.Ecosystem ecosystem,
            Instant releaseDate,
            boolean superseded,
            String infoUrl,
            List<String> cves
    ) {}

    public record Deployment(
            String externalId,
            String name,
            String state,
            String targetName,
            Instant startsAt,
            Instant deadlineAt
    ) {}

    public record Status(
            String deviceExternalId,
            String patchExternalId,
            FixAssetStatus status,
            String deploymentExternalId,
            Instant scheduledAt,
            Instant deadlineAt,
            Instant installedAt,
            String errorCode
    ) {}
}
