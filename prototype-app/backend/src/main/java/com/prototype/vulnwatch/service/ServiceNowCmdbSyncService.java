package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import jakarta.persistence.EntityNotFoundException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.IntConsumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class ServiceNowCmdbSyncService {

    public static final String SYNC_TYPE_SERVICENOW_CMDB = "SERVICENOW_CMDB";
    private static final Logger LOG = LoggerFactory.getLogger(ServiceNowCmdbSyncService.class);
    private static final int FALLBACK_PAGE_SIZE_MEDIUM = 250;
    private static final int FALLBACK_PAGE_SIZE_SMALL = 100;
    private static final int FALLBACK_PAGE_SIZE_MIN = 25;

    private final ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final SyncRunRepository syncRunRepository;
    private final CmdbIngestionService cmdbIngestionService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final TaskExecutor integrationQueueExecutor;
    private final TransactionTemplate transactionTemplate;
    private final IngestionJobService jobs;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public ServiceNowCmdbSyncService(
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            SyncRunRepository syncRunRepository,
            CmdbIngestionService cmdbIngestionService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            @Qualifier("integrationQueueExecutor") TaskExecutor integrationQueueExecutor,
            TransactionTemplate transactionTemplate,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            IngestionJobService jobs
    ) {
        this.serviceNowCmdbConfigRepository = serviceNowCmdbConfigRepository;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.syncRunRepository = syncRunRepository;
        this.cmdbIngestionService = cmdbIngestionService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.integrationQueueExecutor = integrationQueueExecutor;
        this.transactionTemplate = transactionTemplate;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.jobs = jobs;
    }

    private com.prototype.vulnwatch.service.ownership.ServiceNowOwnershipProducer ownershipProducer;
    private boolean ownershipProducerEnabled;

    /** Optional: emits ServiceNow ownership claims after each successful sync when enabled (ownership MVP §6.4). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setOwnershipProducer(com.prototype.vulnwatch.service.ownership.ServiceNowOwnershipProducer ownershipProducer,
            @org.springframework.beans.factory.annotation.Value("${app.ownership.servicenow.producer-enabled:false}") boolean enabled) {
        this.ownershipProducer = ownershipProducer;
        this.ownershipProducerEnabled = enabled;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    public SyncTriggerResponse trigger() {
        var tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            ClaimedRun admitted = claimManualRun(tenant);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_SERVICENOW_CMDB,
                    admitted.configId(), admitted.runId(), "manual", null);
            return admitted;
        });
        if (!claimed.reusedActiveRun()) {
            return new SyncTriggerResponse(claimed.runId(), "queued", "ServiceNow CMDB sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "ServiceNow CMDB sync is already queued or running");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("servicenow-cmdb.run-scheduled-syncs")) {
            return;
        }
        List<ConfigRef> configs = TenantContext.runAsPlatform(() -> {
            List<ConfigRef> scheduledConfigs = new ArrayList<>();
            for (var tenant : tenantService.listActiveTenants()) {
                tenantSchemaExecutionService.run(tenant, () -> {
                    serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow")
                            .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                            .ifPresent(config -> scheduledConfigs.add(new ConfigRef(config.getId(), tenant.getId())));
                    return null;
                });
            }
            return scheduledConfigs;
        });
        for (ConfigRef configRef : configs) {
            try {
                Tenant tenant = tenantService.resolveTenantUuid(configRef.tenantId());
                jobs.withAdmission(tenant, () -> {
                    ServiceNowCmdbConfig config = serviceNowCmdbConfigRepository.findById(configRef.configId()).orElse(null);
                    ClaimedRun claimed = config == null ? null : claimScheduledRun(config);
                    if (claimed != null) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_SERVICENOW_CMDB,
                            claimed.configId(), claimed.runId(), "scheduled", null);
                    return null;
                });
            } catch (RuntimeException failure) {
                LOG.warn("Scheduled connector {} admission deferred", configRef.configId());
            }
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun() {
        var tenant = workspaceService.getWorkspace();
        return !syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenant.getId(), SYNC_TYPE_SERVICENOW_CMDB, List.of("queued", "running")).isEmpty();
    }

    private ClaimedRun claimManualRun(com.prototype.vulnwatch.domain.Tenant tenant) {
        ServiceNowCmdbConfig config = serviceNowCmdbConfigService.findConfig(tenant)
                .filter(this::isConfigured)
                .orElseThrow(() -> new IllegalStateException("ServiceNow CMDB connector is not configured"));
        if (!config.isEnabled()) {
            throw new IllegalStateException("ServiceNow CMDB connector is disabled");
        }
        return claimRunForConfig(config, "manual", true);
    }

    private ClaimedRun claimScheduledRun(ServiceNowCmdbConfig config) {
        return claimRunForConfig(config, "scheduled", false);
    }

    private ClaimedRun claimRunForConfig(ServiceNowCmdbConfig config, String triggerMode, boolean allowReuseActiveRun) {
        // The configuration row is the admission lock, including when no run exists yet.
        // Tenant context and the transaction are established by every caller before this lock.
        config = serviceNowCmdbConfigRepository.findByIdAndTenantIdForUpdate(config.getId(), config.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("ServiceNow CMDB config not found"));
        if ("scheduled".equals(triggerMode)
                && (!isConfigured(config) || !config.isEnabled() || !config.isAutoSyncEnabled() || !isDue(config))) {
            return null;
        }
        if ("manual".equals(triggerMode) && (!isConfigured(config) || !config.isEnabled())) {
            throw new IllegalStateException("ServiceNow CMDB connector is not configured or is disabled");
        }
        UUID tenantId = config.getTenant().getId();
        Optional<SyncRun> active = syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenantId, SYNC_TYPE_SERVICENOW_CMDB,
                List.of("queued", "running")
        ).stream().findFirst();
        if (active.isPresent()) {
            if (!allowReuseActiveRun) {
                return null;
            }
            return new ClaimedRun(config.getId(), active.get().getId(), true);
        }

        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(SYNC_TYPE_SERVICENOW_CMDB);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "sourceSystem", defaultIfBlank(config.getSourceSystem(), "servicenow"),
                "baseUrl", defaultIfBlank(config.getBaseUrl(), "")
        )));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(ServiceNowCmdbConfig config) {
        SyncRun latest = syncRunRepository.findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(
                SYNC_TYPE_SERVICENOW_CMDB, config.getTenant().getId()
        ).orElse(null);
        if (latest == null) {
            return true;
        }
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) {
            return true;
        }
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(5, config.getIntervalMinutes());
        return Duration.between(reference, Instant.now()).toMinutes() >= minutes;
    }

    public void executeQueuedRun(UUID tenantId, UUID configId, UUID runId, String triggerMode) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            markRunRunning(runId, triggerMode);
            java.time.Instant runStartedAt = java.time.Instant.now();
            try {
                ServiceNowCmdbConfig config = serviceNowCmdbConfigRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("ServiceNow CMDB config not found: " + configId));
                ServiceNowCmdbConfigService.ServiceNowRuntimeConfig runtimeConfig = serviceNowCmdbConfigService
                        .resolveRuntimeConfig(config.getTenant())
                        .orElseThrow(() -> new IllegalStateException("ServiceNow CMDB connector is not configured"));

                List<Map<String, String>> discoveryRows = fetchTableRows(
                        runtimeConfig,
                        runtimeConfig.discoveryModelTable(),
                        runtimeConfig.discoveryQuery(),
                        runtimeConfig.discoveryFields(),
                        fetched -> updateRunProgress(runId, fetched, "fetching-discovery", runtimeConfig.discoveryModelTable())
                );
                Map<String, Map<String, String>> discoveryBySysId = indexDiscoveryRows(discoveryRows);
                List<Map<String, String>> installRows = fetchTableRows(
                        runtimeConfig,
                        runtimeConfig.installTable(),
                        runtimeConfig.installQuery(),
                        runtimeConfig.installFields(),
                        fetched -> updateRunProgress(
                                runId,
                                discoveryRows.size() + fetched,
                                "fetching-install",
                                runtimeConfig.installTable()
                        )
                );
                enrichInstallRows(installRows, discoveryBySysId);

                CmdbInventorySyncResponse response = cmdbIngestionService.ingestRows(
                        config.getTenant(),
                        defaultIfBlank(config.getSourceSystem(), "servicenow"),
                        installRows,
                        discoveryRows,
                        new CmdbIngestionService.HostInventorySourceDescriptor(
                                "servicenow-live-sync",
                                "servicenow-table-api",
                                defaultIfBlank(config.getSourceSystem(), "servicenow"),
                                runtimeConfig.installTable(),
                                runtimeConfig.baseUrl(),
                                MediaType.APPLICATION_JSON_VALUE,
                                null
                        )
                );

                completeRun(configId, runId, response, discoveryRows.size() + installRows.size(), triggerMode);
                if (ownershipProducerEnabled && ownershipProducer != null) {
                    // Every approved CI was read, so the scan is complete; the producer never throws.
                    ownershipProducer.publishAfterSync(tenantId, runStartedAt);
                }
            } catch (Exception e) {
                failRun(runId, e.getMessage(), triggerMode);
            }
            return null;
        });
    }

    private void markRunRunning(UUID runId, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("running");
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "running",
                    "sourceSystem", "servicenow",
                    "assetType", "HOST"
            )));
            syncRunRepository.save(run);
        });
    }

    private void completeRun(UUID configId, UUID runId, CmdbInventorySyncResponse response, int fetched, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("completed");
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(response.ciCreated() + response.softwareInstancesCreated() + response.inventoryComponentsCreated());
            run.setRecordsUpdated(response.softwareInstancesUpdated() + response.inventoryComponentsUpdated());
            run.setRecordsFailed(0);
            run.setErrorMessage(null);
            run.setCompletedAt(Instant.now());
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", response.sourceSystem());
            metadata.put("assetType", "HOST");
            metadata.put("assetsIngested", response.assetsIngested());
            metadata.put("installRowsProcessed", response.installRowsProcessed());
            metadata.put("discoveryRowsProcessed", response.discoveryRowsProcessed());
            metadata.put("unmatchedDiscoveryRows", response.unmatchedDiscoveryRows());
            metadata.put("ciCreated", response.ciCreated());
            metadata.put("ciAliasesCreated", response.ciAliasesCreated());
            metadata.put("softwareInstancesCreated", response.softwareInstancesCreated());
            metadata.put("softwareInstancesUpdated", response.softwareInstancesUpdated());
            metadata.put("inventoryComponentsCreated", response.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", response.inventoryComponentsUpdated());
            metadata.put("findingsGenerated", response.findingsRecomputed());
            metadata.put("message", response.message());
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
            serviceNowCmdbConfigRepository.findById(configId).ifPresent(cfg -> {
                cfg.setLastSyncAt(Instant.now());
                serviceNowCmdbConfigRepository.save(cfg);
            });
        });
    }

    private void updateRunProgress(UUID runId, int recordsFetched, String stage, String tableName) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setRecordsFetched(recordsFetched);
            run.setMetadataJson(toJson(Map.of(
                    "sourceSystem", "servicenow",
                    "assetType", "HOST",
                    "stage", stage,
                    "tableName", tableName,
                    "recordsFetched", recordsFetched
            )));
            syncRunRepository.save(run);
        });
    }

    private void failRun(UUID runId, String errorMessage, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("failed");
            run.setRecordsFailed(Math.max(1, run.getRecordsFailed()));
            run.setErrorMessage(errorMessage);
            run.setCompletedAt(Instant.now());
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "failed",
                    "sourceSystem", "servicenow",
                    "assetType", "HOST"
            )));
            syncRunRepository.save(run);
        });
    }

    private List<Map<String, String>> fetchTableRows(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String tableName,
            String query,
            String fields,
            IntConsumer progressCallback
    ) throws Exception {
        List<Integer> pageSizes = candidatePageSizes(config.pageSize());
        String displayValueMode = displayValueModeForTable(config, tableName);
        for (int index = 0; index < pageSizes.size(); index++) {
            int pageSize = pageSizes.get(index);
            try {
                return fetchTableRowsWithPageSize(config, tableName, query, fields, progressCallback, pageSize, displayValueMode);
            } catch (Exception exception) {
                boolean hasFallback = index + 1 < pageSizes.size();
                if (!hasFallback || !shouldRetryWithReducedPageSize(exception)) {
                    throw exception;
                }
                if (progressCallback != null) {
                    progressCallback.accept(0);
                }
                int nextPageSize = pageSizes.get(index + 1);
                LOG.warn(
                        "Retrying ServiceNow table {} with reduced page size {} after response parsing failure at page size {}: {}",
                        tableName,
                        nextPageSize,
                        pageSize,
                        exception.getMessage()
                );
            }
        }
        throw new IllegalStateException("ServiceNow table fetch retry loop exhausted");
    }

    private List<Map<String, String>> fetchTableRowsWithPageSize(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String tableName,
            String query,
            String fields,
            IntConsumer progressCallback,
            int pageSize,
            String displayValueMode
    ) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        int offset = 0;
        while (true) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(config.baseUrl())
                    .path("/api/now/table/{tableName}")
                    .queryParam("sysparm_limit", pageSize)
                    .queryParam("sysparm_offset", offset)
                    .queryParam("sysparm_display_value", displayValueMode)
                    .queryParam("sysparm_exclude_reference_link", "true");
            if (hasText(fields)) {
                builder.queryParam("sysparm_fields", fields);
            }
            if (hasText(query)) {
                builder.queryParam("sysparm_query", query);
            }
            String uri = builder.buildAndExpand(tableName).toUriString();
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    uri,
                    HttpMethod.GET,
                    new HttpEntity<>(buildHeaders(config)),
                    String.class,
                    "ServiceNow table API",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            if (!response.getStatusCode().is2xxSuccessful() || !hasText(response.getBody())) {
                throw new IllegalStateException("ServiceNow table pull failed for " + tableName + " with HTTP " + response.getStatusCode().value());
            }
            JsonNode root = ServiceNowApiResponseParser.parseJson(
                    objectMapper,
                    response,
                    "ServiceNow table " + tableName
            );
            JsonNode result = root.path("result");
            if (!result.isArray()) {
                throw new IllegalStateException("ServiceNow table " + tableName + " did not return an array result");
            }
            if (result.isEmpty()) {
                break;
            }
            for (JsonNode node : result) {
                if (node.isObject()) {
                    rows.add(flattenRow(node));
                }
            }
            if (progressCallback != null) {
                progressCallback.accept(rows.size());
            }
            if (result.size() < pageSize) {
                break;
            }
            offset += result.size();
        }
        return rows;
    }

    static List<Integer> candidatePageSizes(Integer configuredPageSize) {
        int initial = configuredPageSize == null ? 1000 : Math.max(1, Math.min(10_000, configuredPageSize));
        Set<Integer> sizes = new LinkedHashSet<>();
        sizes.add(initial);
        sizes.add(Math.min(initial, FALLBACK_PAGE_SIZE_MEDIUM));
        sizes.add(Math.min(initial, FALLBACK_PAGE_SIZE_SMALL));
        sizes.add(Math.min(initial, FALLBACK_PAGE_SIZE_MIN));
        return sizes.stream()
                .filter(size -> size > 0)
                .toList();
    }

    static String displayValueModeForTable(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String tableName
    ) {
        if (config == null || tableName == null) {
            return "all";
        }
        String normalizedTable = tableName.trim();
        String installTable = config.installTable() == null ? "" : config.installTable().trim();
        return normalizedTable.equalsIgnoreCase(installTable) ? "all" : "false";
    }

    private boolean shouldRetryWithReducedPageSize(Exception exception) {
        String message = exception.getMessage();
        if (!hasText(message)) {
            return false;
        }
        String normalized = message.toLowerCase(Locale.ROOT);
        return normalized.contains("returned html instead of json")
                || normalized.contains("returned invalid json")
                || normalized.contains("did not return an array result");
    }

    private Map<String, Map<String, String>> indexDiscoveryRows(List<Map<String, String>> discoveryRows) {
        Map<String, Map<String, String>> indexed = new LinkedHashMap<>();
        for (Map<String, String> row : discoveryRows) {
            String sysId = normalizeKey(row.get("sys_id"));
            if (hasText(sysId)) {
                indexed.put(sysId, row);
            }
        }
        return indexed;
    }

    private void enrichInstallRows(List<Map<String, String>> installRows, Map<String, Map<String, String>> discoveryBySysId) {
        for (Map<String, String> row : installRows) {
            if (row == null) {
                continue;
            }
            String installedOnRaw = firstText(row.get("installed_on_sys_id"), row.get("installed_on_value"));
            if (hasText(installedOnRaw) && !hasText(row.get("installed_on_sys_id"))) {
                row.put("installed_on_sys_id", installedOnRaw);
            }
            String discoverySysId = firstText(row.get("discovery_model_sys_id"), row.get("discovery_model_value"));
            if (hasText(discoverySysId)) {
                row.put("discovery_model", discoverySysId);
                Map<String, String> discovery = discoveryBySysId.get(normalizeKey(discoverySysId));
                if (discovery != null) {
                    copyIfMissing(row, "discovery_model_pk", discovery.get("primary_key"));
                    copyIfMissing(row, "normalized_product", discovery.get("normalized_product"));
                    copyIfMissing(row, "normalized_publisher", discovery.get("normalized_publisher"));
                    copyIfMissing(row, "normalized_version", discovery.get("normalized_version"));
                    copyIfMissing(row, "product_hash", discovery.get("product_hash"));
                    copyIfMissing(row, "version_hash", discovery.get("version_hash"));
                }
            }
        }
    }

    private Map<String, String> flattenRow(JsonNode node) {
        Map<String, String> values = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> {
            String key = normalizeHeader(entry.getKey());
            JsonNode value = entry.getValue();
            if (value == null || value.isNull() || value.isMissingNode()) {
                return;
            }
            if (value.isObject()) {
                String raw = trimToNull(value.path("value").asText(null));
                String display = trimToNull(value.path("display_value").asText(null));
                if (hasText(display)) {
                    values.put(key, display);
                    values.put(key + "_display_value", display);
                } else if (hasText(raw)) {
                    values.put(key, raw);
                }
                if (hasText(raw)) {
                    values.put(key + "_value", raw);
                    values.put(key + "_sys_id", raw);
                }
                return;
            }
            values.put(key, trimToNull(value.asText(null)));
        });
        return values;
    }

    private HttpHeaders buildHeaders(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (config.authType() == ServiceNowAuthType.BEARER) {
            headers.setBearerAuth(config.credentialSecret());
        } else {
            headers.setBasicAuth(
                    config.username(),
                    config.credentialSecret() == null ? "" : config.credentialSecret(),
                    StandardCharsets.UTF_8
            );
        }
        return headers;
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("servicenow", 0L, null, null);
    }

    private void copyIfMissing(Map<String, String> row, String key, String value) {
        if (!hasText(value) || hasText(row.get(key))) {
            return;
        }
        row.put(key, value);
    }

    private boolean isConfigured(ServiceNowCmdbConfig config) {
        return config != null
                && config.getTenant() != null
                && hasText(config.getBaseUrl())
                && hasText(config.getCredentialSecret());
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private String firstText(String... values) {
        for (String value : values) {
            if (hasText(value)) {
                return value;
            }
        }
        return null;
    }

    private String normalizeHeader(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_").replaceAll("^_+|_+$", "");
    }

    private String normalizeKey(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ClaimedRun(
            UUID configId,
            UUID runId,
            boolean reusedActiveRun
    ) {
    }

    private record ConfigRef(UUID configId, UUID tenantId) {
    }
}
