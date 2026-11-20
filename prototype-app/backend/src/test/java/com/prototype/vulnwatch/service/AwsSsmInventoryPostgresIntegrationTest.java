package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationResponse;
import software.amazon.awssdk.services.ssm.model.InstanceInformation;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesRequest;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesResponse;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AwsSsmInventoryPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("aws_ssm_inventory");
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String INSTANCE = "i-0123456789abcdef0";
    private static final String ARN = "arn:aws:ec2:" + REGION + ":" + ACCOUNT + ":instance/" + INSTANCE;
    private static final Instant ORIGINAL_CAPTURE = Instant.parse("2026-04-24T00:00:00Z");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaExecutionService schemas;
    @Autowired private AssetRepository assets;
    @Autowired private InventoryComponentRepository components;
    @MockitoSpyBean private AwsResourceIngestionService ingestion;

    @Test
    @Timeout(45)
    void commitsACompleteCaptureAndPreservesItOnALaterPageFailure() {
        var tenant = tenants.getDefaultTenant();
        var config = new AwsDiscoveryConfig();
        config.setTenant(tenant);
        config.setAwsAccountId(ACCOUNT);
        var host = new AwsResourceRecord("EC2", ARN, "ssm-fixture", REGION, "us-east-1a", ACCOUNT,
                "t3.medium", "vpc-fixture", "subnet-fixture", "Linux/UNIX", "running", ORIGINAL_CAPTURE,
                Map.of(), null);
        var ssm = mock(SsmClient.class);
        var credentials = mock(AwsCredentialsProvider.class);
        doReturn(ssm).when(ingestion).openSsm(eq(REGION), eq(credentials));
        when(ssm.describeInstanceInformation(any(DescribeInstanceInformationRequest.class)))
                .thenReturn(DescribeInstanceInformationResponse.builder().instanceInformationList(
                        InstanceInformation.builder().instanceId(INSTANCE).build()).build());
        when(ssm.listInventoryEntries(any(ListInventoryEntriesRequest.class)))
                .thenReturn(page("first-package", ORIGINAL_CAPTURE, null))
                .thenReturn(page("partial-package", ORIGINAL_CAPTURE.plusSeconds(3600), "next"))
                .thenThrow(new IllegalStateException("Next page unavailable"));

        schemas.run(tenant, () -> {
            ingestion.ingestAll(List.of(host), config, tenant, Instant.now(), ACCOUNT);
            var complete = ingestion.ingestEc2SsmPackages(List.of(host), credentials, List.of(REGION), tenant, ACCOUNT);
            assertEquals(1, complete.assetsIngested());
            assertEquals(0, complete.failedInstances());
            ingestion.ingestAll(List.of(host), config, tenant, Instant.now(), ACCOUNT);
            var partial = ingestion.ingestEc2SsmPackages(List.of(host), credentials, List.of(REGION), tenant, ACCOUNT);
            assertEquals(1, partial.failedInstances());
            var asset = assets.findByIdentifier(ARN).orElseThrow();
            assertEquals(ORIGINAL_CAPTURE, asset.getSsmInventoryLastCapturedAt());
            assertEquals(true, asset.getSsmInventoryAvailable());
            assertEquals(List.of("first_package"), components.findByAsset_IdIn(List.of(asset.getId())).stream()
                    .map(component -> component.getPackageName()).toList());
        });
    }

    private static ListInventoryEntriesResponse page(String name, Instant capture, String nextToken) {
        return ListInventoryEntriesResponse.builder().captureTime(capture.toString()).nextToken(nextToken)
                .entries(List.of(Map.of("Name", name, "Version", "1"))).build();
    }
}
