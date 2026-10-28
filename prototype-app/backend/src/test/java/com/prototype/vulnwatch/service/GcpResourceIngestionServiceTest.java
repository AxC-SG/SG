package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpInstanceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpResourceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.InventoryResult;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class GcpResourceIngestionServiceTest {

    private final AssetRepository assets = mock(AssetRepository.class);
    private final CiRepository cis = mock(CiRepository.class);
    private final CmdbIngestionService cmdb = mock(CmdbIngestionService.class);
    private final List<Asset> stored = new ArrayList<>();
    private GcpResourceIngestionService service;
    private Tenant tenant;
    private final Instant runStart = Instant.parse("2026-10-27T00:00:00Z");

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        service = new GcpResourceIngestionService(assets, cis, cmdb, new ObjectMapper(), mock(EntityManager.class));
        when(assets.findByIdentifier(anyString())).thenAnswer(call -> stored.stream()
                .filter(a -> call.getArgument(0).equals(a.getIdentifier())).findFirst());
        when(assets.save(any(Asset.class))).thenAnswer(call -> {
            Asset asset = call.getArgument(0);
            if (!stored.contains(asset)) stored.add(asset);
            return asset;
        });
        when(assets.findAll()).thenAnswer(call -> List.copyOf(stored));
        when(cis.findBySysId(anyString())).thenReturn(Optional.empty());
        when(cmdb.ingestRows(any(), anyString(), anyList(), anyList(), any()))
                .thenReturn(new CmdbInventorySyncResponse("gcp", 2, 0, 0, 1, 0, 0, 2, 0, 2, 0, 1, "ok"));
    }

    private static GcpInstanceRecord vm(String id, String status) {
        return new GcpInstanceRecord("acme-prod", id, "vm-" + id, "us-central1-a", "e2-medium", status,
                "default", "default", Map.of("env", "prod"), Instant.parse("2026-01-01T00:00:00Z"), true);
    }

    private Asset existing(String identifier, String type) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setIdentifier(identifier);
        asset.setCloudProvider("gcp");
        asset.setCloudAccountId("acme-prod");
        asset.setCloudResourceType(type);
        asset.setState(AssetState.ACTIVE);
        asset.setLastCmdbSyncAt(runStart.minusSeconds(3600));
        stored.add(asset);
        return asset;
    }

    @Test
    void vmsBecomeHostsWithCloudMetadataAndTheirPackagesFlowIntoCmdbIngestion() {
        var inventory = new InventoryResult(
                Map.of("111", List.of(Map.of("display_name", "openssl", "publisher", "", "version", "3.0.2"))),
                Map.of(), Map.of());

        var result = service.ingestProject(tenant, "acme-prod", List.of(vm("111", "RUNNING"), vm("222", "TERMINATED")),
                inventory, List.of(), Set.of(GcpResourceTypes.COMPUTE_INSTANCE), runStart);

        assertEquals(2, result.assetsUpserted());
        assertEquals(1, result.hostsWithPackages());
        Asset web = stored.get(0);
        assertEquals(AssetType.HOST, web.getType());
        assertEquals("gcp", web.getCloudProvider());
        assertEquals("acme-prod", web.getCloudAccountId());
        assertEquals("us-central1", web.getCloudRegion());
        assertEquals("us-central1-a", web.getCloudAvailabilityZone());
        assertEquals("e2-medium", web.getCloudInstanceType());
        assertEquals("{\"env\":\"prod\"}", web.getCloudTagsJson());
        assertEquals(AssetState.ACTIVE, web.getState());
        assertEquals(AssetState.INACTIVE, stored.get(1).getState(), "GCE reports a stopped VM as TERMINATED");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<Map<String, String>>> rows = ArgumentCaptor.forClass(List.class);
        verify(cmdb).ingestRows(eq(tenant), eq("gcp"), rows.capture(), eq(List.of()), any());
        Map<String, String> row = rows.getValue().get(0);
        assertEquals(web.getIdentifier(), row.get("ci_sys_id"));
        assertEquals("vm-111", row.get("hostname"));
        assertEquals("prod", row.get("environment"));
    }

    @Test
    void otherResourcesBecomeCloudResourcesKeyedByTheirFullResourceName() {
        var bucket = new GcpResourceRecord("//storage.googleapis.com/acme-logs", "storage.googleapis.com/Bucket",
                "STORAGE_BUCKET", "acme-prod", null, "us", null, Map.of(), null);

        service.ingestProject(tenant, "acme-prod", List.of(), null, List.of(bucket), Set.of("STORAGE_BUCKET"), runStart);

        Asset asset = stored.get(0);
        assertEquals(AssetType.CLOUD_RESOURCE, asset.getType());
        assertEquals("//storage.googleapis.com/acme-logs", asset.getIdentifier());
        assertEquals("acme-logs", asset.getName());
        assertEquals("STORAGE_BUCKET", asset.getCloudResourceType());
        assertNull(asset.getCloudTagsJson());
    }

    @Test
    void aCompleteListingDeactivatesOnlyMissingAssetsOfThatTypeInThatProject() {
        Asset gone = existing("//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/999", "COMPUTE_INSTANCE");
        Asset otherType = existing("//storage.googleapis.com/acme-old", "STORAGE_BUCKET");
        Asset otherProject = existing("//compute.googleapis.com/projects/acme-dev/zones/us-central1-a/instances/5", "COMPUTE_INSTANCE");
        otherProject.setCloudAccountId("acme-dev");

        var result = service.ingestProject(tenant, "acme-prod", List.of(vm("111", "RUNNING")), null, List.of(),
                Set.of(GcpResourceTypes.COMPUTE_INSTANCE), runStart);

        assertEquals(1, result.assetsMarkedInactive());
        assertEquals(AssetState.INACTIVE, gone.getState());
        assertEquals(AssetState.ACTIVE, otherType.getState(), "a type not listed this run is never touched");
        assertEquals(AssetState.ACTIVE, otherProject.getState(), "another project is never touched");
    }

    @Test
    void anIncompleteListingDeactivatesNothing() {
        Asset maybeGone = existing("//compute.googleapis.com/projects/acme-prod/zones/asia-east1-a/instances/999", "COMPUTE_INSTANCE");

        var result = service.ingestProject(tenant, "acme-prod", List.of(vm("111", "RUNNING")), null, List.of(),
                Set.of(), runStart);

        assertEquals(0, result.assetsMarkedInactive());
        assertEquals(AssetState.ACTIVE, maybeGone.getState());
    }

    @Test
    void aCompleteButEmptyListingDeactivatesNothing() {
        Asset maybeGone = existing("//storage.googleapis.com/acme-logs", "STORAGE_BUCKET");

        service.ingestProject(tenant, "acme-prod", List.of(), null, List.of(), Set.of("STORAGE_BUCKET"), runStart);

        assertEquals(AssetState.ACTIVE, maybeGone.getState(), "an empty result could be a lost grant, not a deletion");
        verify(cmdb, never()).ingestRows(any(), anyString(), anyList(), anyList(), any());
    }
}
