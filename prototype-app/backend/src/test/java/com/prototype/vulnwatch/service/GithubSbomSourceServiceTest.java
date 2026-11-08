package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.doAnswer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GithubTokenProvider;
import com.prototype.vulnwatch.domain.GithubSbomSource;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.function.Consumer;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class GithubSbomSourceServiceTest {

    @Mock
    private GithubSbomSourceRepository githubSbomSourceRepository;

    @Mock
    private SyncRunRepository syncRunRepository;

    @Mock
    private SbomIngestionService sbomIngestionService;

    @Mock
    private WorkspaceService workspaceService;

    @Mock
    private TenantService tenantService;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Mock
    private IngestionJobService ingestionJobService;

    @Mock
    private RequestActorService requestActorService;

    @Mock
    private TransactionTemplate transactionTemplate;

    @Mock
    private GithubTokenProvider githubTokenProvider;

    private GithubSbomSourceService githubSbomSourceService;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        lenient().when(githubTokenProvider.hasToken()).thenReturn(false);
        lenient().when(githubTokenProvider.configurationHint()).thenReturn(
                "Configure GITHUB_API_TOKEN_FILE, backend/secrets/github-api-token, or GITHUB_API_TOKEN for the backend."
        );
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Tenant A");
        lenient().when(workspaceService.getWorkspace()).thenReturn(tenant);
        lenient().when(tenantService.listActiveTenants()).thenReturn(java.util.List.of(tenant));
        lenient().when(tenantSchemaExecutionService.run(org.mockito.ArgumentMatchers.any(Tenant.class), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(tenantSchemaExecutionService.run(org.mockito.ArgumentMatchers.any(UUID.class), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(requestActorService.currentActor()).thenReturn(
                new RequestActor("local-analyst", false, tenant.getId(), tenant.getName())
        );
        lenient().when(transactionTemplate.execute(org.mockito.ArgumentMatchers.<TransactionCallback<?>>any()))
                .thenAnswer(invocation -> {
                    TransactionCallback<?> callback = invocation.getArgument(0);
                    return callback.doInTransaction((TransactionStatus) null);
                });
        lenient().when(ingestionJobService.withAdmission(org.mockito.ArgumentMatchers.any(Tenant.class), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        githubSbomSourceService = new GithubSbomSourceService(
                githubSbomSourceRepository,
                syncRunRepository,
                sbomIngestionService,
                workspaceService,
                ingestionJobService,
                requestActorService,
                githubTokenProvider,
                new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                transactionTemplate,
                new ObjectMapper(),
                tenantService,
                tenantSchemaExecutionService,
                org.mockito.Mockito.mock(ConnectorScheduleProgress.class)
        );
    }

    @Test
    void triggerGhcrRunOnceFailsFastWithoutConfiguredToken() {
        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> githubSbomSourceService.triggerGhcrRunOnce("openai")
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("read:packages"));
        verifyNoInteractions(syncRunRepository, transactionTemplate, ingestionJobService);
    }

    @Test
    void triggerSavedGhcrSourceFailsFastWithoutConfiguredToken() {
        UUID sourceId = UUID.randomUUID();
        GithubSbomSource source = new GithubSbomSource();
        source.setTenant(tenant);
        source.setPath(GithubSbomSourceService.PATH_GHCR_ATTESTATIONS);
        when(githubSbomSourceRepository.findById(sourceId)).thenReturn(Optional.of(source));

        ResponseStatusException exception = assertThrows(
                ResponseStatusException.class,
                () -> githubSbomSourceService.trigger(sourceId)
        );

        assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode());
        assertTrue(exception.getReason().contains("tenant GitHub token"));
        verify(githubSbomSourceRepository).findById(sourceId);
        verifyNoInteractions(syncRunRepository, transactionTemplate, ingestionJobService);
    }

    @Test
    void triggerSavedGhcrSourceAllowsSourceScopedTokenWithoutBackendToken() {
        UUID sourceId = UUID.randomUUID();
        UUID runId = UUID.randomUUID();
        GithubSbomSource source = new GithubSbomSource();
        source.setTenant(tenant);
        source.setPath(GithubSbomSourceService.PATH_GHCR_ATTESTATIONS);
        source.setOwner("openai");
        source.setAssetName("ghcr.io/openai");
        source.setAssetIdentifier("ghcr:openai");
        source.setGithubToken(new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").encrypt("ghp_source_token"));
        ReflectionTestUtils.setField(source, "id", sourceId);
        when(githubSbomSourceRepository.findById(sourceId)).thenReturn(Optional.of(source));
        when(githubSbomSourceRepository.findByIdForUpdate(sourceId)).thenReturn(Optional.of(source));
        when(githubSbomSourceRepository.save(source)).thenReturn(source);
        when(syncRunRepository.save(org.mockito.ArgumentMatchers.any(SyncRun.class))).thenAnswer(invocation -> {
            SyncRun run = invocation.getArgument(0);
            ReflectionTestUtils.setField(run, "id", runId);
            return run;
        });

        SyncTriggerResponse response = githubSbomSourceService.trigger(sourceId);

        assertNotNull(response);
        assertEquals(runId, response.runId());
        assertEquals("queued", response.status());
        verify(ingestionJobService).enqueueGithubGhcrJob(
                tenant,
                "openai",
                runId,
                sourceId,
                "local-analyst"
        );
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void partialRepositoryBatchCountsOnlySuccessfulAssets(boolean savedSource) throws Exception {
        UUID runId = UUID.randomUUID();
        SyncRun run = new SyncRun();
        run.setTenant(tenant);
        run.setSyncType(GithubSbomSourceService.SYNC_TYPE_GITHUB_REPOSITORY_SBOM);
        run.setStatus("queued");
        ReflectionTestUtils.setField(run, "id", runId);
        when(syncRunRepository.findById(runId)).thenReturn(Optional.of(run));
        doAnswer(invocation -> {
            Consumer<TransactionStatus> work = invocation.getArgument(0);
            work.accept(null);
            return null;
        }).when(transactionTemplate).executeWithoutResult(org.mockito.ArgumentMatchers.any());
        when(sbomIngestionService.ingestFromGithub(org.mockito.ArgumentMatchers.eq(tenant),
                org.mockito.ArgumentMatchers.any(GithubSbomIngestionRequest.class)))
                .thenReturn(new GithubSbomIngestionBatchResponse(9, 9, 2, 7, 2107, 0, List.of()));

        if (savedSource) {
            UUID sourceId = UUID.randomUUID();
            GithubSbomSource source = new GithubSbomSource();
            source.setTenant(tenant);
            source.setOwner("example");
            source.setRepo("app");
            source.setEnabled(true);
            source.setPath(GithubSbomSourceService.PATH_REPOSITORY_SBOM);
            when(githubSbomSourceRepository.findByIdForUpdate(sourceId)).thenReturn(Optional.of(source));
            githubSbomSourceService.executeSource(tenant.getId(), sourceId, runId);
            assertEquals("PARTIAL_SUCCESS", source.getLastRunStatus());
        } else {
            githubSbomSourceService.executeRepositoryRunOnce(tenant.getId(), runId,
                    new GithubSbomIngestionRequest("example", "app", false, null, null, null, null));
        }

        var metadata = new ObjectMapper().readTree(run.getMetadataJson());
        assertEquals("partial_success", run.getStatus());
        assertEquals(9, metadata.path("assetsDiscovered").asInt());
        assertEquals(2, metadata.path("assetsIngested").asInt());
        assertEquals(7, metadata.path("assetsFailed").asInt());
        assertEquals(2107, metadata.path("componentsIngested").asInt());
    }

}
