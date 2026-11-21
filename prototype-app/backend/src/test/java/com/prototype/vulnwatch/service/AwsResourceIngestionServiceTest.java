package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationResponse;
import software.amazon.awssdk.services.ssm.model.InstanceInformation;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesRequest;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesResponse;

class AwsResourceIngestionServiceTest {

    private static final String ACCOUNT_ID = "123456789012";
    private static final String BLANK_ACCOUNT_EC2_ARN = "arn:aws:ec2:us-east-1::instance/i-0123456789abcdef0";
    private static final String CANONICAL_EC2_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0";

    @Test
    void ingestAll_marksOnlyObservedResourceScopesStale() {
        Tenant tenant = tenant();
        Instant runStart = Instant.parse("2026-04-24T00:00:00Z");
        Asset staleEc2 = cloudAsset(tenant, "arn:aws:ec2:us-east-1:123456789012:instance/i-stale", "EC2", "us-east-1", runStart.minusSeconds(60));
        Asset otherCloudAsset = cloudAsset(tenant, "azure:/subscriptions/demo/resourceGroups/rg/providers/Microsoft.Sql/servers/stale", "AZURE_SQL", "eastus", runStart.minusSeconds(60));
        otherCloudAsset.setCloudProvider("azure");
        AwsResourceIngestionService service = service(tenant, List.of(staleEc2, otherCloudAsset));

        AwsResourceIngestionService.IngestionResult result = service.ingestAll(
                List.of(ec2Record(BLANK_ACCOUNT_EC2_ARN)),
                config(tenant),
                tenant,
                runStart
        );

        assertEquals(1, result.assetsMarkedInactive());
        assertEquals(AssetState.INACTIVE, staleEc2.getState());
        assertEquals(AssetState.ACTIVE, otherCloudAsset.getState());
    }

    @Test
    void ingestAll_upgradesBlankAccountEc2ArnWithoutCreatingANewCi() {
        Tenant tenant = tenant();
        Instant runStart = Instant.parse("2026-04-24T00:00:00Z");
        Asset existingAsset = cloudAsset(tenant, BLANK_ACCOUNT_EC2_ARN, "EC2", "us-east-1", runStart.minusSeconds(60));
        Ci existingCi = new Ci();
        existingCi.setTenant(tenant);
        existingCi.setAsset(existingAsset);
        existingCi.setSysId(BLANK_ACCOUNT_EC2_ARN);
        existingCi.setDisplayName("old-host");

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(CANONICAL_EC2_ARN)).thenReturn(Optional.empty());
        when(assetRepository.findByIdentifier(BLANK_ACCOUNT_EC2_ARN)).thenReturn(Optional.of(existingAsset));
        when(assetRepository.findAll()).thenReturn(List.of());
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(CANONICAL_EC2_ARN)).thenReturn(Optional.empty());
        when(ciRepository.findByAsset_Id(eq(existingAsset.getId()))).thenReturn(Optional.of(existingCi));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));

        AwsResourceIngestionService service = service(assetRepository, ciRepository);

        service.ingestAll(List.of(ec2Record(BLANK_ACCOUNT_EC2_ARN)), config(tenant), tenant, runStart);

        assertEquals(CANONICAL_EC2_ARN, existingAsset.getIdentifier());
        assertEquals(CANONICAL_EC2_ARN, existingAsset.getCloudArn());
        assertEquals(CANONICAL_EC2_ARN, existingCi.getSysId());
        assertEquals(existingAsset, existingCi.getAsset());
    }

    @Test
    void ssmFetchesHostsConcurrentlyAndMergesCompleteResultsIndividually() {
        var pool = Executors.newFixedThreadPool(2);
        try {
            var fixture = ssmFixture(pool);
            var eachHostStarted = new CountDownLatch(2);
            when(fixture.ssm().describeInstanceInformation(any(DescribeInstanceInformationRequest.class))).thenAnswer(call -> {
                eachHostStarted.countDown();
                if (!eachHostStarted.await(3, TimeUnit.SECONDS)) throw new IllegalStateException("Expected parallel host fetches");
                return registered(call.getArgument(0));
            });
            when(fixture.ssm().listInventoryEntries(any(ListInventoryEntriesRequest.class))).thenReturn(packagePage(null));
            when(fixture.cmdb().ingestRows(any(), eq("aws"), any(), eq(List.of()), any())).thenReturn(
                    new CmdbInventorySyncResponse("aws", 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, "complete"));

            var result = fixture.service().ingestEc2SsmPackages(List.of(ec2Record(CANONICAL_EC2_ARN),
                            ec2Record("arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef1")),
                    fixture.credentials(), List.of("us-east-1"), tenant(), ACCOUNT_ID);

            assertEquals(2, result.assetsIngested());
            assertEquals(0, result.failedInstances());
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void ssmFailureOnALaterPageLeavesTheHostInventoryUntouched() {
        var fixture = ssmFixture(Runnable::run);
        when(fixture.ssm().describeInstanceInformation(any(DescribeInstanceInformationRequest.class)))
                .thenAnswer(call -> registered(call.getArgument(0)));
        when(fixture.ssm().listInventoryEntries(any(ListInventoryEntriesRequest.class)))
                .thenReturn(packagePage("next")).thenThrow(new IllegalStateException("Second page unavailable"));

        var result = fixture.service().ingestEc2SsmPackages(List.of(ec2Record(CANONICAL_EC2_ARN)), fixture.credentials(),
                List.of("us-east-1"), tenant(), ACCOUNT_ID);

        assertEquals(1, result.failedInstances());
        assertEquals(0, result.assetsIngested());
        verifyNoInteractions(fixture.assets(), fixture.cmdb());
    }

    @Test
    void ssmAnOlderCaptureCannotOverwriteTheLatestHostInventory() {
        var fixture = ssmFixture(Runnable::run);
        Tenant tenant = tenant();
        Instant previousCapture = Instant.parse("2026-04-25T00:00:00Z");
        var existing = cloudAsset(tenant, CANONICAL_EC2_ARN, "EC2", "us-east-1", previousCapture);
        existing.setSsmInventoryLastCapturedAt(previousCapture);
        when(fixture.assets().lockByIdentifier(CANONICAL_EC2_ARN)).thenReturn(Optional.of(existing));
        when(fixture.ssm().describeInstanceInformation(any(DescribeInstanceInformationRequest.class)))
                .thenAnswer(call -> registered(call.getArgument(0)));
        when(fixture.ssm().listInventoryEntries(any(ListInventoryEntriesRequest.class))).thenReturn(packagePage(null));

        var result = fixture.service().ingestEc2SsmPackages(List.of(ec2Record(CANONICAL_EC2_ARN)), fixture.credentials(),
                List.of("us-east-1"), tenant, ACCOUNT_ID);

        assertEquals(0, result.assetsIngested());
        assertEquals(previousCapture, existing.getSsmInventoryLastCapturedAt());
        verifyNoInteractions(fixture.cmdb());
    }

    private SsmFixture ssmFixture(Executor executor) {
        var assets = mock(AssetRepository.class);
        var cmdb = mock(CmdbIngestionService.class);
        var schemas = mock(TenantSchemaExecutionService.class);
        doAnswer(call -> call.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(schemas).run(any(Tenant.class), any(java.util.function.Supplier.class));
        var manager = mock(PlatformTransactionManager.class);
        when(manager.getTransaction(any())).thenAnswer(call -> new SimpleTransactionStatus());
        var ssm = mock(SsmClient.class);
        var credentials = mock(AwsCredentialsProvider.class);
        var service = spy(new AwsResourceIngestionService(assets, mock(CiRepository.class), cmdb, new ObjectMapper(),
                mock(EntityManager.class), schemas, executor, new TransactionTemplate(manager)));
        doReturn(ssm).when(service).openSsm("us-east-1", credentials);
        return new SsmFixture(service, ssm, credentials, assets, cmdb);
    }

    private static DescribeInstanceInformationResponse registered(DescribeInstanceInformationRequest request) {
        return DescribeInstanceInformationResponse.builder().instanceInformationList(InstanceInformation.builder()
                .instanceId(request.filters().get(0).values().get(0)).build()).build();
    }

    private static ListInventoryEntriesResponse packagePage(String next) {
        return ListInventoryEntriesResponse.builder().entries(List.of(Map.of("Name", "fixture", "Version", "1")))
                .captureTime("2026-04-24T00:00:00Z").nextToken(next).build();
    }

    private record SsmFixture(AwsResourceIngestionService service, SsmClient ssm, AwsCredentialsProvider credentials,
                              AssetRepository assets, CmdbIngestionService cmdb) {}

    private AwsResourceIngestionService service(Tenant tenant, List<Asset> existingAssets) {
        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        when(assetRepository.findByIdentifier(anyString())).thenReturn(Optional.empty());
        when(assetRepository.findAll()).thenReturn(existingAssets);
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.findBySysId(anyString())).thenReturn(Optional.empty());
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        return service(assetRepository, ciRepository);
    }

    private AwsResourceIngestionService service(AssetRepository assetRepository, CiRepository ciRepository) {
        TenantSchemaExecutionService tenantSchemaExecutionService = mock(TenantSchemaExecutionService.class);
        doAnswer(invocation -> invocation.<java.util.function.Supplier<?>>getArgument(1).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), any(java.util.function.Supplier.class));
        return new AwsResourceIngestionService(
                assetRepository,
                ciRepository,
                mock(CmdbIngestionService.class),
                new ObjectMapper(),
                mock(EntityManager.class),
                tenantSchemaExecutionService,
                Runnable::run,
                mock(TransactionTemplate.class)
        );
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        return tenant;
    }

    private AwsDiscoveryConfig config(Tenant tenant) {
        AwsDiscoveryConfig config = new AwsDiscoveryConfig();
        config.setTenant(tenant);
        config.setAwsAccountId(ACCOUNT_ID);
        return config;
    }

    private Asset cloudAsset(Tenant tenant, String identifier, String resourceType, String region, Instant lastSyncAt) {
        Asset asset = new Asset();
        ReflectionTestUtils.setField(asset, "id", UUID.randomUUID());
        asset.setTenant(tenant);
        asset.setType("EC2".equals(resourceType) ? AssetType.HOST : AssetType.CLOUD_RESOURCE);
        asset.setName(identifier);
        asset.setIdentifier(identifier);
        asset.setState(AssetState.ACTIVE);
        asset.setCloudProvider("aws");
        asset.setCloudAccountId(ACCOUNT_ID);
        asset.setCloudResourceType(resourceType);
        asset.setCloudRegion(region);
        asset.setCloudArn(identifier);
        asset.setLastCmdbSyncAt(lastSyncAt);
        return asset;
    }

    private AwsResourceRecord ec2Record(String arn) {
        return new AwsResourceRecord(
                "EC2",
                arn,
                "app-01",
                "us-east-1",
                "us-east-1a",
                "",
                "t3.medium",
                "vpc-1",
                "subnet-1",
                "Linux/UNIX",
                "running",
                Instant.parse("2026-04-23T00:00:00Z"),
                Map.of("Name", "app-01"),
                "arn:aws:iam::" + ACCOUNT_ID + ":instance-profile/EC2-SSM-Profile"
        );
    }
}
