package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.SyncRunResponse;
import com.prototype.vulnwatch.dto.VulnIntelSourceSummary;
import com.prototype.vulnwatch.dto.VulnIntelSourceSummary.SourceStatus;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

@Service
public class SyncRunHistoryService {

    private static final String CATEGORY_ALL = "all";
    private static final String CATEGORY_INVENTORY = "inventory";
    private static final String CATEGORY_VULN_INTEL = "vuln-intel";
    private static final String CATEGORY_PROCESSING = "processing";
    private static final String RUN_DOMAIN_INVENTORY = "INVENTORY";
    private static final String RUN_DOMAIN_VULN_INTEL = "VULN_INTEL";
    private static final String RUN_DOMAIN_PROCESSING = "PROCESSING";
    private static final String RUN_CLASS_INGESTION = "INGESTION";
    private static final String RUN_CLASS_REPAIR = "REPAIR";
    private static final String RUN_CLASS_BACKFILL = "BACKFILL";
    private static final String RUN_CLASS_RECOMPUTE = "RECOMPUTE";
    private static final List<String> VULN_INTEL_TYPES = List.of(
            "NVD", "KEV", "GHSA", "CSAF_MICROSOFT", "CSAF_REDHAT", "ADVISORY", "EUVD", "JVN"
    );
    private static final Set<String> EOL_CONNECTOR_RUN_TYPES = Set.of(
            "EOL_CATALOG_REFRESH",
            "EOL_RELEASE_REFRESH",
            "EOL_MAPPING_RESOLVE",
            "EOL_DENORMALIZE",
            "EOL_FULL_REFRESH"
    );
    private static final Set<String> PROCESSING_RUN_TYPES = Set.of(
            "VEX_ASSERTION_REPAIR",
            "VEX_ROLLOUT_BACKFILL",
            "EOL_DATE_SWEEP"
    );
    private static final Set<String> AI_INVENTORY_RUN_TYPES = Set.of(
            "AI_SECURITY_AWS_BEDROCK",
            "AI_SECURITY_AZURE_DISCOVERY"
    );

    private final SyncRunRepository syncRunRepository;
    private final RequestActorService requestActorService;

    public SyncRunHistoryService(
            SyncRunRepository syncRunRepository,
            RequestActorService requestActorService
    ) {
        this.syncRunRepository = syncRunRepository;
        this.requestActorService = requestActorService;
    }

    public List<SyncRunResponse> list(String category, int limit) {
        String normalizedCategory = normalizeCategory(category);
        int normalizedLimit = Math.max(1, Math.min(200, limit));
        RequestActor actor = requestActorService.currentActor();

        Map<UUID, Integer> queuePositions = activeQueuePositions(actor, normalizedCategory);
        return runsForActor(actor, normalizedCategory).stream()
                .filter(run -> actorCanViewRun(actor, run))
                .filter(run -> matchesCategory(run.getSyncType(), normalizedCategory))
                .map(run -> toResponse(run, queuePositions.get(run.getId())))
                .sorted(Comparator
                        .comparing(SyncRunResponse::startedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(SyncRunResponse::completedAt, Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(SyncRunResponse::id, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(normalizedLimit)
                .toList();
    }

    public VulnIntelSourceSummary sourcesSummary() {
        RequestActor actor = requestActorService.currentActor();
        Map<String, SourceStatus> sources = new LinkedHashMap<>();
        for (String type : VULN_INTEL_TYPES) {
            findLatestByActor(actor, type)
                    .ifPresentOrElse(
                            run -> sources.put(type, toSourceStatus(run)),
                            () -> sources.put(type, new SourceStatus("never", null, 0, 0, 0, null))
                    );
        }
        return new VulnIntelSourceSummary(sources);
    }

    private Map<UUID, Integer> activeQueuePositions(RequestActor actor, String category) {
        List<SyncRun> queue = queueForActor(actor, category).stream()
                .filter(run -> actorCanViewRun(actor, run))
                .filter(run -> matchesCategory(run.getSyncType(), category))
                .sorted(Comparator
                        .comparingInt((SyncRun run) -> "running".equalsIgnoreCase(run.getStatus()) ? 0 : 1)
                        .thenComparing(SyncRun::getStartedAt))
                .toList();
        Map<UUID, Integer> queuePositions = new HashMap<>();
        for (int i = 0; i < queue.size(); i++) {
            queuePositions.put(queue.get(i).getId(), i + 1);
        }
        return queuePositions;
    }

    private List<SyncRun> runsForActor(RequestActor actor, String category) {
        if (shouldUsePlatformVulnerabilityScope(actor, category)) {
            return inPlatformWorkspace(() ->
                    syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.DESC, "startedAt")));
        }
        if (actor.tenantId() == null) {
            return List.of();
        }
        return syncRunRepository.findByTenant_IdOrderByStartedAtDesc(actor.tenantId());
    }

    private List<SyncRun> queueForActor(RequestActor actor, String category) {
        if (shouldUsePlatformVulnerabilityScope(actor, category)) {
            return inPlatformWorkspace(() ->
                    syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.ASC, "startedAt")).stream()
                            .filter(run -> "queued".equalsIgnoreCase(run.getStatus()) || "running".equalsIgnoreCase(run.getStatus()))
                            .toList());
        }
        if (actor.tenantId() == null) {
            return List.of();
        }
        return syncRunRepository.findQueueByTenantAndStatuses(actor.tenantId(), List.of("queued", "running"));
    }

    private java.util.Optional<SyncRun> findLatestByActor(RequestActor actor, String syncType) {
        if (!isInventoryRunType(syncType)) {
            return inPlatformWorkspace(() ->
                    syncRunRepository.findByRunScope("PLATFORM_VULNERABILITY", Sort.by(Sort.Direction.DESC, "startedAt")).stream()
                            .filter(run -> syncType.equalsIgnoreCase(run.getSyncType()))
                            .findFirst());
        }
        if (actor.tenantId() == null) {
            return java.util.Optional.empty();
        }
        return syncRunRepository.findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(syncType, actor.tenantId());
    }

    private boolean actorCanViewRun(RequestActor actor, SyncRun run) {
        if (actor.hasRole("PLATFORM_OWNER") && "PLATFORM_VULNERABILITY".equalsIgnoreCase(safe(run.getRunScope()))) {
            return true;
        }
        if (actor.platformScope()) {
            return true;
        }
        if (actor.tenantId() == null) {
            return false;
        }
        return isInventoryRunType(run.getSyncType());
    }

    private SyncRunResponse toResponse(SyncRun run, Integer queuePosition) {
        SyncRunClassification classification = classifyRunType(run.getSyncType());
        return new SyncRunResponse(
                run.getId(),
                run.getSyncType(),
                classification.runDomain(),
                classification.runClass(),
                run.getStatus(),
                queuePosition,
                run.getRecordsFetched(),
                run.getRecordsInserted(),
                run.getRecordsUpdated(),
                run.getRecordsFailed(),
                run.getStartedAt(),
                run.getCompletedAt(),
                run.getErrorMessage(),
                run.getMetadataJson()
        );
    }

    private static SourceStatus toSourceStatus(SyncRun run) {
        return new SourceStatus(
                run.getStatus(),
                run.getCompletedAt(),
                run.getRecordsInserted(),
                run.getRecordsUpdated(),
                run.getRecordsFetched(),
                run.getErrorMessage()
        );
    }

    private boolean matchesCategory(String syncType, String category) {
        SyncRunClassification classification = classifyRunType(syncType);
        return switch (category) {
            case CATEGORY_INVENTORY -> RUN_DOMAIN_INVENTORY.equals(classification.runDomain());
            case CATEGORY_VULN_INTEL -> RUN_DOMAIN_VULN_INTEL.equals(classification.runDomain());
            case "vulnerability", "vuln" -> !RUN_DOMAIN_INVENTORY.equals(classification.runDomain());
            case CATEGORY_PROCESSING -> RUN_DOMAIN_PROCESSING.equals(classification.runDomain());
            default -> true;
        };
    }

    private boolean isInventoryRunType(String syncType) {
        String normalizedType = safe(syncType).toUpperCase(Locale.ROOT);
        return normalizedType.startsWith("GITHUB_")
                || "SERVICENOW_CMDB".equals(normalizedType)
                || "SCCM_CMDB".equals(normalizedType)
                || "AWS_DISCOVERY".equals(normalizedType)
                || "GCP_DISCOVERY".equals(normalizedType)
                || normalizedType.startsWith("PATCH_")
                || "AZURE_DISCOVERY".equals(normalizedType)
                || AI_INVENTORY_RUN_TYPES.contains(normalizedType);
    }

    private String normalizeCategory(String category) {
        String normalized = safe(category).toLowerCase(Locale.ROOT);
        return normalized.isBlank() ? CATEGORY_ALL : normalized;
    }

    private boolean shouldUsePlatformVulnerabilityScope(RequestActor actor, String category) {
        if (actor == null || !actor.hasRole("PLATFORM_OWNER")) {
            return false;
        }
        return !CATEGORY_INVENTORY.equals(category);
    }

    private <T> T inPlatformWorkspace(java.util.function.Supplier<T> supplier) {
        return TenantContext.runAsPlatform(supplier);
    }

    private SyncRunClassification classifyRunType(String syncType) {
        String normalizedType = safe(syncType).toUpperCase(Locale.ROOT);
        if (isInventoryRunType(normalizedType)) {
            return new SyncRunClassification(RUN_DOMAIN_INVENTORY, RUN_CLASS_INGESTION);
        }
        if (EOL_CONNECTOR_RUN_TYPES.contains(normalizedType)) {
            return new SyncRunClassification(RUN_DOMAIN_VULN_INTEL, RUN_CLASS_INGESTION);
        }
        if (PROCESSING_RUN_TYPES.contains(normalizedType)) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, classifyRunClass(normalizedType));
        }
        if (normalizedType.contains("RECOMPUTE")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_RECOMPUTE);
        }
        if (normalizedType.contains("BACKFILL")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_BACKFILL);
        }
        if (normalizedType.contains("REPAIR")) {
            return new SyncRunClassification(RUN_DOMAIN_PROCESSING, RUN_CLASS_REPAIR);
        }
        return new SyncRunClassification(RUN_DOMAIN_VULN_INTEL, RUN_CLASS_INGESTION);
    }

    private String classifyRunClass(String normalizedType) {
        if (normalizedType.contains("RECOMPUTE")) {
            return RUN_CLASS_RECOMPUTE;
        }
        if (normalizedType.contains("BACKFILL")) {
            return RUN_CLASS_BACKFILL;
        }
        if (normalizedType.contains("REPAIR")) {
            return RUN_CLASS_REPAIR;
        }
        return RUN_CLASS_INGESTION;
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private record SyncRunClassification(String runDomain, String runClass) {
    }
}
