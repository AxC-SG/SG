package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/** Read-only cutover diagnostic. Release qualification is intentionally not a runtime toggle. */
@Service
public class CatalogActivationReadinessService {
    public record Review(UUID buildId, boolean localChecksPass, boolean activationEnabled,
                         List<String> blockers) {}

    private final CatalogBuildService builds;
    private final CatalogLegacyCompatibilityService legacy;
    private final WorkspaceService workspace;

    public CatalogActivationReadinessService(CatalogBuildService builds,
            CatalogLegacyCompatibilityService legacy, WorkspaceService workspace) {
        this.builds = builds;
        this.legacy = legacy;
        this.workspace = workspace;
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 20)
    public Review inspect(UUID buildId) {
        var blockers = new ArrayList<String>();
        var tenant = workspace.getWorkspace();
        if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) blockers.add("TENANT_NOT_ACTIVE");
        var inputs = builds.inputStatus(buildId);
        if (!inputs.current()) blockers.add(inputs.reason());
        if (!inputs.latestPolicy()) blockers.add("POLICY_SUPERSEDED");
        if (!legacy.inspect().gaps().isEmpty()) blockers.add("LEGACY_SETTINGS_NEED_REVIEW");
        boolean localChecksPass = blockers.isEmpty();
        blockers.add("RELEASE_GATES_UNQUALIFIED");
        return new Review(buildId, localChecksPass, false, List.copyOf(blockers));
    }
}
