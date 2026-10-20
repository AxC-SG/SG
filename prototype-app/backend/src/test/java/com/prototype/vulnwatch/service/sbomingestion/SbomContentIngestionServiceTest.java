package com.prototype.vulnwatch.service.sbomingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.InventoryComponentCpeMappingService;
import com.prototype.vulnwatch.service.SbomParserService;
import com.prototype.vulnwatch.service.SoftwareIdentitySummaryProjectionService;
import com.prototype.vulnwatch.service.SoftwareInventorySyncService;
import jakarta.persistence.EntityManager;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

class SbomContentIngestionServiceTest {

    @Test
    void ingestBytes_setsAssetActiveAndInventoryTimestamp_withoutOpeningNestedTransaction() throws Exception {
        // Regression test for a deadlock: SbomContentIngestionService previously called
        // AssetLifecycleService.markInventoryIngested(asset), which opens a
        // PROPAGATION_REQUIRES_NEW transaction on a separate DB connection to re-save the
        // same asset row this method's own (still-open, uncommitted) outer transaction had
        // just created. For brand-new assets that nested save blocked in Postgres waiting on
        // this transaction to commit, while this transaction's thread was itself blocked
        // waiting on the nested save to return -- a permanent cross-connection deadlock that
        // left the per-asset SbomIngestionLockService lock held forever, so every retry for
        // the same asset failed with "An SBOM ingestion is already in progress for this asset."
        SbomParserService sbomParserService = mock(SbomParserService.class);
        SbomUploadRepository sbomUploadRepository = mock(SbomUploadRepository.class);
        InventoryComponentRepository inventoryComponentRepository = mock(InventoryComponentRepository.class);
        IdentityGraphService identityGraphService = mock(IdentityGraphService.class);
        InventoryComponentCpeMappingService inventoryComponentCpeMappingService =
                mock(InventoryComponentCpeMappingService.class);
        SoftwareInventorySyncService softwareInventorySyncService = mock(SoftwareInventorySyncService.class);
        FindingDeltaQueueService findingDeltaQueueService = mock(FindingDeltaQueueService.class);
        SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService =
                mock(SoftwareIdentitySummaryProjectionService.class);
        SbomUploadSupportService sbomUploadSupportService = mock(SbomUploadSupportService.class);
        EntityManager entityManager = mock(EntityManager.class);

        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        Asset newAsset = new Asset();
        newAsset.setTenant(tenant);
        newAsset.setIdentifier("pkg:npm/kanra-mobile@1.0.0");
        // Simulate a brand-new asset resolved (but not yet flushed/committed) by resolveAsset().
        newAsset.setState(AssetState.ACTIVE);

        when(sbomUploadSupportService.resolveAsset(tenant, AssetType.APPLICATION, "kanra-mobile", "pkg:npm/kanra-mobile@1.0.0"))
                .thenReturn(newAsset);
        when(sbomUploadSupportService.saveAsset(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomUploadRepository.save(any(SbomUpload.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(sbomParserService.detectFormat(any(byte[].class))).thenReturn(com.prototype.vulnwatch.domain.SbomFormat.CYCLONEDX);
        when(sbomParserService.parse(any(byte[].class))).thenReturn(List.of(new ParsedComponent("generic", "model", "1", "pkg:generic/model@1", null, List.of(), null, null, null, "machine-learning-model")));
        when(identityGraphService.resolveFromComponents(any())).thenReturn(Map.of());
        when(inventoryComponentRepository.findByAsset(any(Asset.class))).thenReturn(List.of());

        SbomContentIngestionService service = new SbomContentIngestionService(
                sbomParserService,
                sbomUploadRepository,
                inventoryComponentRepository,
                identityGraphService,
                inventoryComponentCpeMappingService,
                softwareInventorySyncService,
                findingDeltaQueueService,
                softwareIdentitySummaryProjectionService,
                sbomUploadSupportService,
                new com.prototype.vulnwatch.service.BomComponentCategorizationService(), scopedRunner()
        );
        ReflectionTestUtils.setField(service, "entityManager", entityManager);

        service.ingestBytes(
                tenant,
                AssetType.APPLICATION,
                "kanra-mobile",
                "pkg:npm/kanra-mobile@1.0.0",
                "{}".getBytes(),
                "kanra-mobile-sbom.json",
                new SbomIngestionSourceMetadata("UPLOAD", "bom-upload", "kanra-mobile-sbom.json", null, null, null, 2L, null),
                null
        );

        ArgumentCaptor<Asset> savedAssetCaptor = ArgumentCaptor.forClass(Asset.class);
        Mockito.verify(sbomUploadSupportService).saveAsset(savedAssetCaptor.capture());
        Asset savedAsset = savedAssetCaptor.getValue();
        assertEquals(AssetState.ACTIVE, savedAsset.getState());
        assertNotNull(savedAsset.getLastInventoryAt());
    }

    // Regression test for a false-remediation data-loss path. SbomContentIngestionService
    // retires every inventory component for the asset that is absent from the document being
    // ingested. BomIngestionOrchestrator routes every non-CBOM bom_type -- including AI_BOM --
    // through here, so uploading a partial AI-BOM against an asset that already had an SBOM
    // retired all of that asset's SBOM components, and FindingComponentRecomputeService then
    // auto-closed their still-unremediated findings as AUTO_COMPONENT_REMOVED.
    @Test
    void ingestBytes_nonAuthoritativeDocument_doesNotRetireComponentsItOmits() throws Exception {
        Fixture fixture = new Fixture();
        InventoryComponent preexisting = fixture.preexistingActiveComponent();

        fixture.service().ingestBytes(
                fixture.tenant(),
                AssetType.APPLICATION,
                "kanra-mobile",
                "pkg:npm/kanra-mobile@1.0.0",
                "{}".getBytes(),
                "kanra-mobile-ai-bom.json",
                new SbomIngestionSourceMetadata("UPLOAD", "bom-upload", "kanra-mobile-ai-bom.json", null, null, null, 2L, null),
                null,
                false
        );

        assertEquals(InventoryComponentStatus.ACTIVE, preexisting.getComponentStatus(),
                "a partial document must not retire a component it merely omits");
        assertNull(preexisting.getRetiredAt());
    }

    // Complement of the above: an authoritative document (SBOM/VENDOR, and the 8-arg overload
    // used by the direct upload/endpoint paths) must keep retiring omitted components.
    @Test
    void ingestBytes_authoritativeDocument_stillRetiresComponentsItOmits() throws Exception {
        Fixture fixture = new Fixture();
        InventoryComponent preexisting = fixture.preexistingActiveComponent();

        fixture.service().ingestBytes(
                fixture.tenant(),
                AssetType.APPLICATION,
                "kanra-mobile",
                "pkg:npm/kanra-mobile@1.0.0",
                "{}".getBytes(),
                "kanra-mobile-sbom.json",
                new SbomIngestionSourceMetadata("UPLOAD", "bom-upload", "kanra-mobile-sbom.json", null, null, null, 2L, null),
                null
        );

        assertEquals(InventoryComponentStatus.RETIRED, preexisting.getComponentStatus());
        assertNotNull(preexisting.getRetiredAt());
    }

    /** Mock wiring shared by the two retirement tests. */
    private static final class Fixture {
        private final Tenant tenant = new Tenant();
        private final InventoryComponentRepository inventoryComponentRepository =
                mock(InventoryComponentRepository.class);
        private final SbomContentIngestionService service;

        Fixture() throws Exception {
            tenant.setId(UUID.randomUUID());

            SbomParserService sbomParserService = mock(SbomParserService.class);
            SbomUploadRepository sbomUploadRepository = mock(SbomUploadRepository.class);
            IdentityGraphService identityGraphService = mock(IdentityGraphService.class);
            InventoryComponentCpeMappingService inventoryComponentCpeMappingService =
                    mock(InventoryComponentCpeMappingService.class);
            SoftwareInventorySyncService softwareInventorySyncService = mock(SoftwareInventorySyncService.class);
            FindingDeltaQueueService findingDeltaQueueService = mock(FindingDeltaQueueService.class);
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService =
                    mock(SoftwareIdentitySummaryProjectionService.class);
            SbomUploadSupportService sbomUploadSupportService = mock(SbomUploadSupportService.class);
            EntityManager entityManager = mock(EntityManager.class);

            Asset asset = new Asset();
            asset.setTenant(tenant);
            asset.setIdentifier("pkg:npm/kanra-mobile@1.0.0");
            asset.setState(AssetState.ACTIVE);

            when(sbomUploadSupportService.resolveAsset(any(Tenant.class), any(AssetType.class), anyString(), anyString()))
                    .thenReturn(asset);
            when(sbomUploadSupportService.saveAsset(any(Asset.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(sbomUploadRepository.save(any(SbomUpload.class)))
                    .thenAnswer(invocation -> invocation.getArgument(0));
            when(sbomParserService.detectFormat(any(byte[].class)))
                    .thenReturn(com.prototype.vulnwatch.domain.SbomFormat.CYCLONEDX);
            // A valid non-software declaration omits the pre-existing software component.
            // An actually empty document is rejected before any asset mutation.
            when(sbomParserService.parse(any(byte[].class))).thenReturn(List.of(new ParsedComponent("generic", "model", "1", "pkg:generic/model@1", null, List.of(), null, null, null, "machine-learning-model")));
            when(identityGraphService.resolveFromComponents(any())).thenReturn(Map.of());

            service = new SbomContentIngestionService(
                    sbomParserService,
                    sbomUploadRepository,
                    inventoryComponentRepository,
                    identityGraphService,
                    inventoryComponentCpeMappingService,
                    softwareInventorySyncService,
                    findingDeltaQueueService,
                    softwareIdentitySummaryProjectionService,
                    sbomUploadSupportService,
                    new com.prototype.vulnwatch.service.BomComponentCategorizationService(), scopedRunner()
            );
            ReflectionTestUtils.setField(service, "entityManager", entityManager);
        }

        Tenant tenant() {
            return tenant;
        }

        SbomContentIngestionService service() {
            return service;
        }

        InventoryComponent preexistingActiveComponent() {
            InventoryComponent component = new InventoryComponent();
            component.setEcosystem("npm");
            component.setPackageName("lodash");
            component.setVersion("4.17.20");
            component.setPurl("pkg:npm/lodash@4.17.20");
            component.setComponentStatus(InventoryComponentStatus.ACTIVE);
            when(inventoryComponentRepository.findByAsset(any(Asset.class))).thenReturn(List.of(component));
            return component;
        }
    }

    private static com.prototype.vulnwatch.service.TenantWorkRunner scopedRunner() {
        return mock(com.prototype.vulnwatch.service.TenantWorkRunner.class, invocation -> {
            if (invocation.getMethod().getName().equals("runScopedChecked")) {
                return invocation.<java.util.concurrent.Callable<?>>getArgument(1).call();
            }
            return org.mockito.Answers.RETURNS_DEFAULTS.answer(invocation);
        });
    }
}
