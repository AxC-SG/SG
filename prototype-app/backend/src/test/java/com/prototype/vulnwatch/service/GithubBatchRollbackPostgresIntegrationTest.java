package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.GithubApiClient;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

/** Real per-document transactions through the batch service proxy, with offline GitHub responses. */
@PostgresIntegrationTest
class GithubBatchRollbackPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("github_batch_rollback");
    private static final byte[] GOOD = ("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\","
            + "\"components\":[{\"type\":\"library\",\"name\":\"batch-library\",\"version\":\"1\","
            + "\"purl\":\"pkg:npm/batch-library@1\"}]}").getBytes(StandardCharsets.UTF_8);
    private static final byte[] BAD = "{\"components\":[".getBytes(StandardCharsets.UTF_8);

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private SbomIngestionService ingestion;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private AssetRepository assets;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private IngestionJobService jobs;
    @Autowired private IngestionJobWorkerService worker;
    @Autowired private SyncRunRepository runs;
    @MockitoBean private GithubApiClient github;
    @Autowired private CredentialEncryptionService credentialEncryption;
    @Autowired private com.prototype.vulnwatch.repo.GithubSbomSourceRepository sources;
    private Tenant tenant;
    private boolean throughWorker;

    @BeforeEach
    void selectTenantBeforeTransactions() {
        throughWorker = false;
        // Accepted AI-BOMs legitimately queue projection work. Keep each case's real
        // admission quota independent instead of deleting that work or raising limits.
        String slug = "p25-batch-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenantService.resolveTenantUuid(tenant.getId());
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    static Stream<Arguments> mixedBatches() {
        return Stream.of("generated", "files", "ghcr").flatMap(kind ->
                Stream.of(Arguments.of(kind, false), Arguments.of(kind, true)));
    }

    @ParameterizedTest
    @MethodSource("mixedBatches")
    void malformedSiblingDoesNotRollBackAnAcceptedDocument(String kind, boolean invalidFirst) throws Exception {
        String owner = "batch-" + UUID.randomUUID();
        switch (kind) {
            case "generated" -> generated(owner, invalidFirst);
            case "files" -> files(owner, invalidFirst);
            case "ghcr" -> ghcr(owner, invalidFirst);
            default -> throw new IllegalArgumentException(kind);
        }
    }

    @ParameterizedTest
    @MethodSource("mixedBatches")
    void queuedMixedBatchCommitsAcceptedDocumentsAndReportsPartialSuccess(String kind, boolean invalidFirst)
            throws Exception {
        throughWorker = true;
        String owner = "worker-batch-" + UUID.randomUUID();
        switch (kind) {
            case "generated" -> generated(owner, invalidFirst);
            case "files" -> files(owner, invalidFirst);
            case "ghcr" -> ghcr(owner, invalidFirst);
            default -> throw new IllegalArgumentException(kind);
        }
    }

    private void generated(String owner, boolean invalidFirst) throws Exception {
        var good = new GithubApiClient.GithubRepositoryRef(owner, "good", owner + "/good", null, false, "main");
        var bad = new GithubApiClient.GithubRepositoryRef(owner, "bad", owner + "/bad", null, false, "main");
        when(github.listAccountRepositories(owner)).thenReturn(invalidFirst ? List.of(bad, good) : List.of(good, bad));
        for (String repo : List.of("good", "bad")) {
            String endpoint = "https://example.test/" + owner + "/" + repo;
            byte[] body = "good".equals(repo) ? GOOD : BAD;
            when(github.buildGeneratedSbomEndpoint(owner, repo)).thenReturn(endpoint);
            when(github.fetchGeneratedSbom(owner, repo)).thenReturn(new GithubApiClient.GithubSbomResponse(
                    body, 200, "application/json", body.length, endpoint));
        }
        var request = new GithubSbomIngestionRequest(owner, null, true, AssetType.APPLICATION, null, null, null);
        if (throughWorker) {
            workerRun(request, null);
        } else {
            var response = ingestion.ingestFromGithub(tenant, request);
            assertEquals(1, response.repositoriesSucceeded());
            assertEquals(1, response.repositoriesFailed());
            assertEquals(1, response.componentsIngested());
        }
        assertAccepted("github:" + owner + "/good");
        assertTrue(assets.findByIdentifier("github:" + owner + "/bad").isEmpty());
    }

    private void files(String owner, boolean invalidFirst) throws Exception {
        var good = new GithubApiClient.GithubRepoFileRef("good.aibom.json", "good-sha", GOOD.length);
        var bad = new GithubApiClient.GithubRepoFileRef("bad.aibom.json", "bad-sha", BAD.length);
        when(github.listRepoBomFiles(owner, "repo", BomType.AI_BOM))
                .thenReturn(invalidFirst ? List.of(bad, good) : List.of(good, bad));
        when(github.fetchRepoFileContent(owner, "repo", good.path())).thenReturn(GOOD);
        when(github.fetchRepoFileContent(owner, "repo", bad.path())).thenReturn(BAD);
        String identifier = "files:" + owner;
        var request = new GithubSbomIngestionRequest(owner, "repo", false, AssetType.APPLICATION,
                "file-batch", identifier, "repository/aibom");
        if (throughWorker) {
            workerRun(request, null);
        } else {
            var response = ingestion.ingestBomFilesFromGithub(tenant, request);
            assertEquals(1, response.repositoriesSucceeded());
            assertEquals(1, response.repositoriesFailed());
            assertEquals(1, response.componentsIngested());
        }
        assertAccepted(identifier);
    }

    private void ghcr(String owner, boolean invalidFirst) throws Exception {
        String repository = "ghcr.io/" + owner + "/app";
        String goodDigest = "sha256:" + "1".repeat(64);
        String badDigest = "sha256:" + "2".repeat(64);
        var good = new GithubApiClient.GithubContainerImageVersionRef(owner, "app", repository, goodDigest, List.of("good"));
        var bad = new GithubApiClient.GithubContainerImageVersionRef(owner, "app", repository, badDigest, List.of("bad"));
        when(github.listContainerPackages(owner)).thenReturn(List.of(
                new GithubApiClient.GithubContainerPackageRef(owner, "app", repository)));
        when(github.listContainerImageVersions(owner, "app"))
                .thenReturn(invalidFirst ? List.of(bad, good) : List.of(good, bad));
        when(github.fetchAttestedSbomsForOwnerBulk(eq(owner), anyList())).thenReturn(Map.of(
                repository + "@" + goodDigest, attestation(GOOD),
                repository + "@" + badDigest, attestation(BAD)));
        if (throughWorker) {
            workerRun(null, owner);
        } else {
            var response = ingestion.ingestAllFromGithubContainerRegistry(tenant, owner);
            assertEquals(1, response.imagesSucceeded());
            assertEquals(1, response.imagesFailed());
            assertEquals(1, response.componentsIngested());
        }
        assertAccepted(repository + "@" + goodDigest);
        // GHCR deliberately retains a failed-fetch evidence row; it must not promote a BOM.
        UUID failedAssetId = assets.findByIdentifier(repository + "@" + badDigest).orElseThrow().getId();
        assertEquals(0L, jdbc.queryForObject(
                "select count(*) from bom_ingestion_records where asset_id = ?", Long.class, failedAssetId));
    }

    private GithubApiClient.GithubAttestedSbomResponse attestation(byte[] body) {
        return new GithubApiClient.GithubAttestedSbomResponse(body, 200, "application/json", body.length,
                "https://example.test/attestation", "https://cyclonedx.org/bom", "app", 1);
    }

    private void workerRun(GithubSbomIngestionRequest request, String ghcrOwner) {
        SyncRun run = new SyncRun();
        run.setTenant(tenant);
        run.setRunScope("TENANT_INVENTORY");
        run.setSyncType(ghcrOwner != null ? GithubSbomSourceService.SYNC_TYPE_GITHUB_GHCR_SBOM
                : "repository/aibom".equals(request.path()) ? GithubSbomSourceService.SYNC_TYPE_GITHUB_REPOSITORY_AIBOM
                : GithubSbomSourceService.SYNC_TYPE_GITHUB_REPOSITORY_SBOM);
        run.setStatus("queued");
        run = runs.save(run);
        UUID credentialSourceId = null;
        if (ghcrOwner != null) {
            var source = new com.prototype.vulnwatch.domain.GithubSbomSource();
            source.setTenant(tenant);
            source.setName("Offline GHCR regression credential");
            source.setOwner(ghcrOwner);
            source.setRepo("*");
            source.setPath(GithubSbomSourceService.PATH_GHCR_ATTESTATIONS);
            source.setAssetName("Offline GHCR batch");
            source.setAssetIdentifier("ghcr:" + ghcrOwner);
            source.setGithubToken(credentialEncryption.encrypt("controlled-offline-ghcr-sentinel"));
            credentialSourceId = sources.save(source).getId();
        }
        var accepted = ghcrOwner != null
                ? jobs.enqueueGithubGhcrJob(tenant, ghcrOwner, run.getId(), credentialSourceId, "p25-regression")
                : jobs.enqueueGithubRepositoryJob(tenant, request, run.getId(), null, "p25-regression");
        assertTrue(jobs.claimPendingJobs(tenant, 1, 1).stream()
                .anyMatch(claimed -> claimed.jobId().equals(accepted.jobId())));
        worker.execute(tenant.getId(), accepted.jobId());
        var finishedJob = jobs.loadJob(tenant.getId(), accepted.jobId());
        assertEquals(IngestionJobService.STATUS_SUCCEEDED, finishedJob.getStatus(), finishedJob.getFailureMessage());
        SyncRun finishedRun = runs.findById(run.getId()).orElseThrow();
        assertEquals("partial_success", finishedRun.getStatus(), finishedRun.getErrorMessage());
        assertEquals(2, finishedRun.getRecordsFetched());
        assertEquals(1, finishedRun.getRecordsInserted());
        assertEquals(1, finishedRun.getRecordsFailed());
    }

    private void assertAccepted(String identifier) {
        UUID assetId = assets.findByIdentifier(identifier).orElseThrow().getId();
        assertEquals(1L, jdbc.queryForObject(
                "select count(*) from bom_ingestion_records where asset_id = ? and status = 'ACTIVE'", Long.class, assetId));
        assertEquals(1L, jdbc.queryForObject("select count(*) from bom_components where bom_id in "
                + "(select id from bom_ingestion_records where asset_id = ?) and is_active", Long.class, assetId));
        assertEquals(1L, jdbc.queryForObject("select count(*) from bom_sources where asset_id = ? and current_bom_id is not null",
                Long.class, assetId));
    }
}
