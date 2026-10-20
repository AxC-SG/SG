package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.dto.IngestionJobPageResponse;
import com.prototype.vulnwatch.dto.IngestionJobResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class IngestionJobService {

    private static final Logger log = LoggerFactory.getLogger(IngestionJobService.class);

    public static final String JOB_TYPE_AWS_DISCOVERY = "AWS_DISCOVERY";
    public static final String JOB_TYPE_SERVICENOW_CMDB = "SERVICENOW_CMDB";
    public static final String JOB_TYPE_REMOTE_ENDPOINT = "REMOTE_ENDPOINT";
    public static final String JOB_TYPE_GITHUB_REPOSITORY = "GITHUB_REPOSITORY";
    public static final String JOB_TYPE_GITHUB_GHCR = "GITHUB_GHCR";
    public static final String JOB_TYPE_AI_SECURITY_AWS_BEDROCK = "AI_SECURITY_AWS_BEDROCK";
    public static final String JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY = "AI_SECURITY_AZURE_DISCOVERY";
    public static final String JOB_TYPE_AI_SECURITY_COPILOT_STUDIO = "AI_SECURITY_COPILOT_STUDIO";
    public static final String JOB_TYPE_AI_GRID_RUNTIME_ADAPTER = "AI_GRID_RUNTIME_ADAPTER";
    public static final String JOB_TYPE_AI_GRID_BOM_PROJECTION = "AI_GRID_BOM_PROJECTION";
    private static final List<String> AI_SECURITY_JOB_TYPES = List.of(
            JOB_TYPE_AI_SECURITY_AWS_BEDROCK,
            JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY,
            JOB_TYPE_AI_SECURITY_COPILOT_STUDIO,
            JOB_TYPE_AI_GRID_RUNTIME_ADAPTER,
            JOB_TYPE_AI_GRID_BOM_PROJECTION);
    public static final String STATUS_QUEUED = "QUEUED";
    public static final String STATUS_RUNNING = "RUNNING";
    public static final String STATUS_SUCCEEDED = "SUCCEEDED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_CANCELLED = "CANCELLED";

    private final IngestionJobRepository ingestionJobRepository;
    private final IngestionAttemptService attempts;
    @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.max-attempts:3}")
    private int maxAttempts = 3;
    private BackgroundTaskExecutionPolicy backgroundPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private final CredentialEncryptionService credentialEncryptionService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TenantService tenantService;
    private final TenantQuotaService tenantQuotaService;
    private final AuditEventService auditEventService;
    private final IngestionJobMetricsService ingestionJobMetricsService;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;

    public IngestionJobService(
            IngestionJobRepository ingestionJobRepository,
            IngestionAttemptService attempts,
            CredentialEncryptionService credentialEncryptionService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            TenantService tenantService,
            TenantQuotaService tenantQuotaService,
            AuditEventService auditEventService,
            IngestionJobMetricsService ingestionJobMetricsService,
            ObjectMapper objectMapper,
            TransactionTemplate transactionTemplate
    ) {
        this.ingestionJobRepository = ingestionJobRepository;
        this.attempts = attempts;
        this.credentialEncryptionService = credentialEncryptionService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.tenantService = tenantService;
        this.tenantQuotaService = tenantQuotaService;
        this.auditEventService = auditEventService;
        this.ingestionJobMetricsService = ingestionJobMetricsService;
        this.objectMapper = objectMapper;
        this.transactionTemplate = transactionTemplate;
    }

    public IngestionJobAcceptedResponse enqueueEndpointJob(Tenant tenant, SbomEndpointIngestionRequest request, String requestedBy) {
        BomFetchRequest bomRequest = new BomFetchRequest(
                com.prototype.vulnwatch.domain.BomType.SBOM,
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                request.sourceUrl(),
                request.sourceLabel(),
                null,
                request.authorizationHeader()
        );
        return enqueueBomFetchJob(tenant, bomRequest, requestedBy, "remote-endpoint");
    }

    public IngestionJobAcceptedResponse enqueueBomFetchJob(Tenant tenant, BomFetchRequest request, String requestedBy) {
        return enqueueBomFetchJob(tenant, request, requestedBy, "bom-fetch");
    }

    private IngestionJobAcceptedResponse enqueueBomFetchJob(Tenant tenant, BomFetchRequest request, String requestedBy, String quotaSource) {
        IngestionJobPayloads.EndpointIngestionPayload payload = new IngestionJobPayloads.EndpointIngestionPayload(
                request.bomType(),
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                request.sourceUrl(),
                request.sourceLabel(),
                request.supplier(),
                credentialEncryptionService.encrypt(request.authorizationHeader())
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_REMOTE_ENDPOINT,
                quotaSource,
                request.assetIdentifier(),
                requestedBy,
                payload
        );
    }

    public IngestionJobAcceptedResponse enqueueGithubRepositoryJob(
            Tenant tenant,
            GithubSbomIngestionRequest request,
            UUID syncRunId,
            UUID sourceId,
            String requestedBy
    ) {
        String normalizedRepo = request.repo() == null ? "" : request.repo().trim();
        String assetIdentifier = request.assetIdentifier() == null || request.assetIdentifier().isBlank()
                ? "github:" + normalize(request.owner()) + "/" + normalize(normalizedRepo)
                : request.assetIdentifier();
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = new IngestionJobPayloads.GithubRepositoryIngestionPayload(
                request.owner(),
                request.repo(),
                request.includeAllRepos(),
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                syncRunId,
                sourceId,
                request.path()
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_GITHUB_REPOSITORY,
                "github",
                assetIdentifier,
                requestedBy,
                payload
        );
    }

    public IngestionJobAcceptedResponse enqueueGithubGhcrJob(
            Tenant tenant,
            String owner,
            UUID syncRunId,
            UUID sourceId,
            String requestedBy
    ) {
        IngestionJobPayloads.GithubGhcrIngestionPayload payload = new IngestionJobPayloads.GithubGhcrIngestionPayload(
                owner,
                syncRunId,
                sourceId
        );
        return enqueueJob(
                tenant,
                JOB_TYPE_GITHUB_GHCR,
                "github",
                "ghcr:" + normalize(owner),
                requestedBy,
                payload
        );
    }

    public IngestionJobResponse getJob(Tenant tenant, UUID jobId) {
        IngestionJob job = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId)));
        return toResponse(job);
    }

    public IngestionJobPageResponse listJobs(Tenant tenant, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        Pageable pageable = PageRequest.of(safePage, safeSize);
        Page<IngestionJob> jobs = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findAllByOrderByRequestedAtDescIdDesc(pageable));
        return new IngestionJobPageResponse(
                jobs.getContent().stream().map(this::toResponse).toList(),
                jobs.getNumber(),
                jobs.getSize(),
                jobs.getTotalElements(),
                jobs.getTotalPages()
        );
    }

    // NOTE: do NOT annotate these worker-invoked methods with @Transactional. The tenant schema MUST be
    // selected before the transaction begins — TenantAwareDataSource pins a connection's search_path when
    // the connection is acquired, and a transaction binds that connection at its start. Opening the
    // transaction first (method-level @Transactional) pins the *default* schema, so the query silently
    // runs against the wrong tenant. Setting context via tenantSchemaExecutionService.run() and only then
    // opening a TransactionTemplate keeps the ordering correct for every tenant.
    public List<ClaimedJobRef> claimPendingJobs(Tenant tenant, int limit, int maxConcurrentPerTenant) {
        if (!backgroundPolicy.allowsBackgroundTask("ingestion-job.claim")) return List.of();
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> {
            attempts.lockCapacity(tenant.getId());
            long running = ingestionJobRepository.countByStatusExcludingJobTypes(
                    STATUS_RUNNING, isolatedJobTypes());
            if (running >= maxConcurrentPerTenant) {
                return List.of();
            }
            int claimLimit = Math.max(0, Math.min(limit, maxConcurrentPerTenant - (int) running));
            if (claimLimit == 0) {
                return List.of();
            }
            List<IngestionJob> jobs = ingestionJobRepository.pollPendingExcludingJobTypes(
                    isolatedJobTypes(), claimLimit);
            Instant now = Instant.now();
            for (IngestionJob job : jobs) {
                job.setStatus(STATUS_RUNNING);
                job.setStartedAt(now);
                job.setAttemptCount(job.getAttemptCount() + 1);
                job.setClaimToken(UUID.randomUUID());
                job.setHeartbeatAt(now);
                job.setLeaseExpiresAt(now.plusSeconds(attempts.leaseSeconds()));
            }
            ingestionJobRepository.saveAll(jobs);
            return jobs.stream()
                    .map(job -> new ClaimedJobRef(tenant.getId(), job.getId(), job.getClaimToken()))
                    .toList();
        }));
    }

    private List<String> isolatedJobTypes() {
        var types = new java.util.ArrayList<>(AI_SECURITY_JOB_TYPES);
        types.add(JOB_TYPE_AWS_DISCOVERY);
        types.add(JOB_TYPE_SERVICENOW_CMDB);
        return types;
    }

    public IngestionJobAcceptedResponse enqueueConnectorJob(Tenant tenant, String jobType,
            UUID configId, UUID runId, String triggerMode, UUID targetId) {
        if (!List.of(JOB_TYPE_AWS_DISCOVERY, JOB_TYPE_SERVICENOW_CMDB).contains(jobType)) {
            throw new IllegalArgumentException("Unsupported durable connector type");
        }
        return enqueueJob(tenant, jobType, jobType.toLowerCase(Locale.ROOT), configId.toString(),
                "connector:" + triggerMode, new ConnectorJobPayload(configId, runId, triggerMode, targetId));
    }

    public IngestionJobAcceptedResponse enqueueAiSecurityJob(
            Tenant tenant, UUID connectorId, String requestedBy) {
        return enqueueAiSecurityJob(
                tenant, connectorId, JOB_TYPE_AI_SECURITY_AWS_BEDROCK, "ai-security-aws", requestedBy);
    }

    public IngestionJobAcceptedResponse enqueueRuntimeAdapterJob(
            Tenant tenant, String producerId, UUID receiptId, com.fasterxml.jackson.databind.JsonNode batch) {
        return enqueueJob(
                tenant,
                JOB_TYPE_AI_GRID_RUNTIME_ADAPTER,
                "ai-grid-runtime-adapter",
                receiptId.toString(),
                producerId,
                new RuntimeAdapterJobPayload(producerId, receiptId, batch)
        );
    }

    /**
     * One active projection job per source at a time -- {@code enqueueJob}'s own dedupe key
     * ({@code jobType + ":" + sourceId}) already makes a second upload arriving while a job for
     * this source is still QUEUED a no-op rather than a pile-up. The worker always reads the
     * source's current state when it runs, so that single job still ends up covering the
     * latest revision.
     */
    public IngestionJobAcceptedResponse enqueueAiGridBomProjectionJob(Tenant tenant, UUID sourceId) {
        return enqueueJob(
                tenant,
                JOB_TYPE_AI_GRID_BOM_PROJECTION,
                "ai-grid-bom-projection",
                sourceId.toString(),
                "system:ai-bom-ingestion",
                new AiGridBomProjectionJobPayload(sourceId)
        );
    }

    public IngestionJobAcceptedResponse enqueueAiSecurityJob(
            Tenant tenant,
            UUID connectorId,
            String jobType,
            String source,
            String requestedBy
    ) {
        if (!AI_SECURITY_JOB_TYPES.contains(jobType)) {
            throw new IllegalArgumentException("Unsupported AI Security job type");
        }
        return enqueueJob(
                tenant,
                jobType,
                source,
                source + ":" + connectorId,
                requestedBy,
                new AiSecurityJobPayload(connectorId)
        );
    }

    public List<ClaimedJobRef> claimPendingJobsByType(
            Tenant tenant, String jobType, int limit, int maxConcurrentPerTenant) {
        if (!backgroundPolicy.allowsBackgroundTask("ingestion-job.claim")) return List.of();
        if (JOB_TYPE_AI_GRID_RUNTIME_ADAPTER.equals(jobType)) return List.of();
        if (!java.util.Set.of(JOB_TYPE_AI_SECURITY_AWS_BEDROCK,JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY,
                JOB_TYPE_AI_SECURITY_COPILOT_STUDIO,JOB_TYPE_AI_GRID_BOM_PROJECTION,JOB_TYPE_AWS_DISCOVERY,JOB_TYPE_SERVICENOW_CMDB).contains(jobType))
            throw new IllegalArgumentException("Unsupported retained ingestion job type");
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> {
            attempts.lockCapacity(tenant.getId());
            long running = ingestionJobRepository.countByStatusAndJobType(STATUS_RUNNING, jobType);
            if (running >= maxConcurrentPerTenant) {
                return List.of();
            }
            int claimLimit = Math.max(0, Math.min(limit, maxConcurrentPerTenant - (int) running));
            if (claimLimit == 0) {
                return List.of();
            }
            List<IngestionJob> jobs = ingestionJobRepository.pollPendingByJobType(jobType, claimLimit);
            Instant now = Instant.now();
            jobs.forEach(job -> {
                job.setStatus(STATUS_RUNNING);
                job.setStartedAt(now);
                job.setAttemptCount(job.getAttemptCount() + 1);
                job.setClaimToken(UUID.randomUUID());
                job.setHeartbeatAt(now);
                job.setLeaseExpiresAt(now.plusSeconds(attempts.leaseSeconds()));
            });
            ingestionJobRepository.saveAll(jobs);
            return jobs.stream().map(job -> new ClaimedJobRef(tenant.getId(), job.getId(), job.getClaimToken())).toList();
        }));
    }

    public java.util.Optional<UUID> activeGithubSourceRun(Tenant tenant,UUID sourceId) {
        return tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.findActiveGithubSource(sourceId.toString()).map(this::relatedSyncRun));
    }
    public UUID relatedSyncRun(IngestionJob job) {
        try { return UUID.fromString(objectMapper.readTree(job.getPayloadJson()).path("syncRunId").asText()); }
        catch (Exception failure) { throw new IllegalStateException("Accepted GitHub job has invalid run identity"); }
    }

    public IngestionJob loadJob(UUID tenantId, UUID jobId) {
        return tenantSchemaExecutionService.run(tenantId, () -> ingestionJobRepository.findById(jobId)
                .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId)));
    }

    public void markQueuedForRetry(UUID tenantId, UUID jobId, String failureCode, String failureMessage, Instant visibleAt) {
        tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> {
            attempts.lockOwnedJob(tenantId, jobId);
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            job.setStatus(STATUS_QUEUED);
            job.setFailureCode(failureCode);
            job.setFailureMessage(failureMessage);
            job.setVisibleAt(visibleAt);
            ingestionJobRepository.save(job);
            return null;
        }));
    }

    public void cancelRuntimeJob(UUID tenantId, UUID jobId) {
        tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> {
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            if (!JOB_TYPE_AI_GRID_RUNTIME_ADAPTER.equals(job.getJobType())
                    || !List.of(STATUS_QUEUED, STATUS_RUNNING).contains(job.getStatus())) return null;
            job.setStatus(STATUS_CANCELLED);
            job.setFailureCode("RUNTIME_OUT_OF_SCOPE");
            job.setFailureMessage("Runtime telemetry is outside the current release scope");
            job.setCompletedAt(Instant.now());
            ingestionJobRepository.save(job);
            auditEventService.recordExplicitActor(tenantId, "runtime-scope-release", "SYSTEM",
                    "ingestion.job.cancelled", "ingestion_job", jobId.toString(),
                    "{\"reason\":\"RUNTIME_OUT_OF_SCOPE\"}", "SUCCESS");
            return null;
        }));
    }

    public void markFailed(UUID tenantId, UUID jobId, String failureCode, String failureMessage) {
        tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> {
            attempts.lockOwnedJob(tenantId, jobId);
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            if (STATUS_SUCCEEDED.equals(job.getStatus())) return null;
            job.setStatus(STATUS_FAILED);
            job.setFailureCode(failureCode);
            job.setFailureMessage(failureMessage);
            job.setCompletedAt(Instant.now());
            ingestionJobRepository.save(job);
            return null;
        }));
    }

    public void markSucceeded(UUID tenantId, UUID jobId, SbomUpload sbomUpload, String resultJson) {
        tenantSchemaExecutionService.run(tenantId, () -> transactionTemplate.execute(status -> {
            attempts.lockOwnedJob(tenantId, jobId);
            IngestionJob job = ingestionJobRepository.findById(jobId)
                    .orElseThrow(() -> new IllegalArgumentException("Ingestion job not found: " + jobId));
            job.setStatus(STATUS_SUCCEEDED);
            job.setFailureCode(null);
            job.setFailureMessage(null);
            job.setCompletedAt(Instant.now());
            job.setSbomUpload(sbomUpload);
            job.setResultJson(resultJson);
            ingestionJobRepository.save(job);
            // Audit intent commits atomically with the outcome. Metric publication is ancillary.
            auditEventService.record("ingestion.job.completed", "ingestion_job", jobId.toString(), null);
            return null;
        }));
    }

    public int recoverInterruptedRunningJobs() {
        if (!backgroundPolicy.allowsBackgroundTask("ingestion-job.recover-expired")) return 0;
        return TenantContext.runAsPlatform(() -> {
            int recovered = 0;
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    recovered += tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> {
                        attempts.lockCapacity(tenant.getId());
                        var expired = ingestionJobRepository.pollExpiredAttempts(100);
                        int changed=0;
                        for (IngestionJob job : expired) {
                            com.fasterxml.jackson.databind.JsonNode payload;
                            try { payload=objectMapper.readTree(job.getPayloadJson()==null ? "{}" : job.getPayloadJson()); }
                            catch (java.io.IOException invalid) { throw new IllegalStateException("Expired job payload is invalid"); }
                            attempts.lockSourceForRecovery(job.getJobType(),payload);
                            if (!attempts.lockExpiredJob(job.getId())) continue;
                            changed++;
                            job.setClaimToken(null);
                            job.setHeartbeatAt(null);
                            job.setLeaseExpiresAt(null);
                            if (job.getAttemptCount() >= maxAttempts) {
                                job.setStatus(STATUS_FAILED);
                                job.setCompletedAt(Instant.now());
                                job.setFailureCode("ATTEMPTS_EXHAUSTED");
                                attempts.terminalizeExhausted(tenant.getId(),job.getJobType(),payload);
                            } else {
                                job.setStatus(STATUS_QUEUED);
                                job.setVisibleAt(Instant.now());
                                job.setFailureCode("ATTEMPT_EXPIRED");
                            }
                            job.setFailureMessage("Previous worker lease expired");
                        }
                        ingestionJobRepository.saveAll(expired);
                        return changed;
                    }));
                } catch (RuntimeException failure) {
                    log.warn("Skipped expired ingestion recovery for tenant {}", tenant.getId());
                }
            }
            return recovered;
        });
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundPolicy = java.util.Objects.requireNonNull(policy);
    }

    public IngestionAttemptService.AttemptScope openAttempt(UUID tenantId, UUID jobId, UUID token) {
        return attempts.open(tenantId, jobId, token);
    }

    public void retryRejectedClaim(ClaimedJobRef ref, String code, String message, Instant visibleAt) {
        try (var ignored = openAttempt(ref.tenantId(), ref.jobId(), ref.claimToken())) {
            markQueuedForRetry(ref.tenantId(), ref.jobId(), code, message, visibleAt);
        }
    }

    public <T> T withAdmission(Tenant tenant, java.util.function.Supplier<T> work) {
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> {
            attempts.lockCapacity(tenant.getId());
            return work.get();
        }));
    }

    public <T> T readPayload(IngestionJob job, Class<T> payloadType) {
        try {
            return objectMapper.readValue(job.getPayloadJson(), payloadType);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to deserialize ingestion payload", ex);
        }
    }

    public String decrypt(String storedValue) {
        return credentialEncryptionService.decrypt(storedValue);
    }

    public String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to serialize ingestion payload", ex);
        }
    }

    public void recordStarted(IngestionJob job) {
        auditEventService.record("ingestion.job.started", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordStarted(job.getSourceType());
        ingestionJobMetricsService.recordEnqueueToStartLatency(job.getSourceType(), job.getRequestedAt(), job.getStartedAt());
    }

    public void recordCompleted(IngestionJob job) {
        ingestionJobMetricsService.recordCompleted(job.getSourceType());
        ingestionJobMetricsService.recordExecutionDuration(job.getSourceType(), job.getStartedAt(), job.getCompletedAt());
    }

    public void recordFailed(IngestionJob job) {
        auditEventService.record("ingestion.job.failed", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordFailed(job.getSourceType());
    }

    public void recordLockRetry(IngestionJob job) {
        auditEventService.record("ingestion.job.lock_retry", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordLockRetry(job.getSourceType());
    }

    private IngestionJobAcceptedResponse enqueueJob(
            Tenant tenant,
            String jobType,
            String sourceType,
            String assetIdentifier,
            String requestedBy,
            Object payload
    ) {
        String normalizedAssetIdentifier = normalize(assetIdentifier);
        String dedupeKey = jobType.toLowerCase(Locale.ROOT) + ":" + normalizedAssetIdentifier;
        java.util.function.Supplier<IngestionJobAcceptedResponse> insert = () -> {
            attempts.lockIdentity(tenant.getId(), dedupeKey);
            return enqueueJobInCurrentTenantSchema(tenant, jobType, sourceType, assetIdentifier,
                    requestedBy, payload, dedupeKey);
        };
        if (List.of(JOB_TYPE_REMOTE_ENDPOINT, JOB_TYPE_GITHUB_REPOSITORY, JOB_TYPE_GITHUB_GHCR,
                JOB_TYPE_AWS_DISCOVERY, JOB_TYPE_SERVICENOW_CMDB).contains(jobType)) {
            return withAdmission(tenant, insert);
        }
        // AI projection/collection already owns its separate budget/source lock. Its
        // identity lock follows that lock; it must not invert the SBOM capacity order.
        return tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(status -> insert.get()));
    }

    private IngestionJobAcceptedResponse enqueueJobInCurrentTenantSchema(
            Tenant tenant,
            String jobType,
            String sourceType,
            String assetIdentifier,
            String requestedBy,
            Object payload,
            String dedupeKey
    ) {
        Optional<IngestionJob> existing = ingestionJobRepository.findActiveByDedupeKeyForUpdate(dedupeKey);
        if (existing.isPresent()) {
            IngestionJob job = existing.get();
            ingestionJobMetricsService.recordDeduped(sourceType);
            auditEventService.record("ingestion.job.deduped", "ingestion_job", job.getId().toString(), null);
            return new IngestionJobAcceptedResponse(job.getId(), job.getStatus(), "Existing ingestion job already active", true, null);
        }

        if (List.of(JOB_TYPE_REMOTE_ENDPOINT, JOB_TYPE_GITHUB_REPOSITORY, JOB_TYPE_GITHUB_GHCR).contains(jobType)) {
            tenantQuotaService.assertCanCreateSbomIngestionJob(tenant, sourceType);
        }
        IngestionJob newJob = new IngestionJob();
        newJob.setTenant(tenant);
        newJob.setJobType(jobType);
        newJob.setSourceType(sourceType);
        newJob.setAssetIdentifier(assetIdentifier);
        newJob.setRequestedBy(requestedBy);
        newJob.setDedupeKey(dedupeKey);
        newJob.setPayloadJson(toJson(payload));
        newJob.setVisibleAt(Instant.now());

        // The tenant capacity lock serializes every producer before this lookup/insert.
        // Keep the existing unique constraint as a backstop; never reuse an aborted transaction.
        IngestionJob job = ingestionJobRepository.saveAndFlush(newJob);

        auditEventService.record("ingestion.job.created", "ingestion_job", job.getId().toString(), null);
        ingestionJobMetricsService.recordEnqueued(sourceType);
        return new IngestionJobAcceptedResponse(job.getId(), job.getStatus(), "Ingestion job queued", false, null);
    }

    private IngestionJobResponse toResponse(IngestionJob job) {
        SbomUpload sbomUpload = job.getSbomUpload();
        return new IngestionJobResponse(
                job.getId(),
                job.getJobType(),
                job.getSourceType(),
                job.getAssetIdentifier(),
                job.getStatus(),
                job.getRequestedBy(),
                job.getRequestedAt(),
                job.getStartedAt(),
                job.getCompletedAt(),
                job.getAttemptCount(),
                job.getFailureCode(),
                job.getFailureMessage(),
                sbomUpload == null ? null : sbomUpload.getId(),
                job.getResultJson()
        );
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    public record ClaimedJobRef(UUID tenantId, UUID jobId, UUID claimToken) {
        public ClaimedJobRef(UUID tenantId, UUID jobId) { this(tenantId, jobId, null); }
    }

    public record ConnectorJobPayload(UUID configId, UUID runId, String triggerMode, UUID targetId) { }

    public record AiSecurityJobPayload(UUID connectorId) {
    }

    public record RuntimeAdapterJobPayload(String producerId, UUID receiptId,
                                           com.fasterxml.jackson.databind.JsonNode batch) {
    }

    public record AiGridBomProjectionJobPayload(UUID sourceId) {
    }
}
