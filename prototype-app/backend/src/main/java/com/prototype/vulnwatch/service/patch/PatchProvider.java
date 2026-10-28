package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;

/**
 * One patch management tool behind a common contract.
 *
 * <p>Implementations only talk to their tool and translate its data into {@link PatchSnapshot};
 * they never write to the database. {@link PatchIngestionService} owns device matching, patch
 * deduplication, CVE linking and per-asset state, so every tool is ingested the same way.
 */
public interface PatchProvider {

    PatchProviderType type();

    /**
     * Validates provider-specific settings before they are saved.
     *
     * @throws IllegalArgumentException with an operator-facing reason
     */
    void validate(PatchConnectorConfig config, boolean secretPresent);

    /** Whether this provider authenticates with the connector's own secret. */
    default boolean requiresSecret() {
        return true;
    }

    /** Checks connectivity and each permission the sync needs, without importing anything. */
    PatchConnectionResult test(Tenant tenant, PatchConnectorConfig config, String secret);

    /** Reads the tool's current patches, devices, deployments and per-device state. */
    PatchSnapshot fetch(Tenant tenant, PatchConnectorConfig config, String secret);
}
