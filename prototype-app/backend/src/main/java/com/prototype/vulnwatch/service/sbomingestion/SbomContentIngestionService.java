package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ParsedComponent;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.InventoryComponentCpeMappingService;
import com.prototype.vulnwatch.service.SbomParserService;
import com.prototype.vulnwatch.service.SoftwareInventorySyncService;
import com.prototype.vulnwatch.service.SoftwareIdentitySummaryProjectionService;
import com.prototype.vulnwatch.util.PurlUtil;
import com.prototype.vulnwatch.util.BomInputLimits;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.io.IOException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;

@Service
public class SbomContentIngestionService {

    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(SbomContentIngestionService.class);

    private final SbomParserService sbomParserService;
    private final SbomUploadRepository sbomUploadRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final IdentityGraphService identityGraphService;
    private final InventoryComponentCpeMappingService inventoryComponentCpeMappingService;
    private final SoftwareInventorySyncService softwareInventorySyncService;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final SbomUploadSupportService sbomUploadSupportService;
    private final com.prototype.vulnwatch.service.BomComponentCategorizationService categorizationService;

    private final TenantWorkRunner tenantWorkRunner;

    @PersistenceContext
    private EntityManager entityManager;

    public SbomContentIngestionService(
            SbomParserService sbomParserService,
            SbomUploadRepository sbomUploadRepository,
            InventoryComponentRepository inventoryComponentRepository,
            IdentityGraphService identityGraphService,
            InventoryComponentCpeMappingService inventoryComponentCpeMappingService,
            SoftwareInventorySyncService softwareInventorySyncService,
            FindingDeltaQueueService findingDeltaQueueService,
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            SbomUploadSupportService sbomUploadSupportService,
            com.prototype.vulnwatch.service.BomComponentCategorizationService categorizationService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.sbomParserService = sbomParserService;
        this.sbomUploadRepository = sbomUploadRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.identityGraphService = identityGraphService;
        this.inventoryComponentCpeMappingService = inventoryComponentCpeMappingService;
        this.softwareInventorySyncService = softwareInventorySyncService;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.sbomUploadSupportService = sbomUploadSupportService;
        this.categorizationService = categorizationService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    public SbomIngestionResponse ingestBytes(
            Tenant tenant,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            byte[] content,
            String originalFilename,
            SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer
    ) throws IOException {
        return ingestBytes(tenant, assetType, assetName, assetIdentifier, content,
                originalFilename, metadata, assetCustomizer, true);
    }

    // authoritativeForAssetSoftware=false means the document only adds evidence and never
    // implies absence. A partial document (AI-BOM) must not retire components it does not
    // list: that would auto-close their findings as AUTO_COMPONENT_REMOVED, reporting
    // unremediated vulnerabilities as fixed.
    public SbomIngestionResponse ingestBytes(
            Tenant tenant,
            AssetType assetType,
            String assetName,
            String assetIdentifier,
            byte[] content,
            String originalFilename,
            SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer,
            boolean authoritativeForAssetSoftware
    ) throws IOException {
        return ingestPrepared(tenant, assetType, assetName, assetIdentifier, prepare(content), originalFilename,
                metadata, assetCustomizer, authoritativeForAssetSoftware);
    }

    public PreparedContent prepare(byte[] content) throws IOException {
        BomInputLimits.checkBytes(content);
        SbomFormat format = sbomParserService.detectFormat(content);
        if (format == SbomFormat.UNKNOWN) {
            throw new IOException("Unsupported or unrecognized BOM format");
        }
        List<ParsedComponent> components = sbomParserService.parse(content);
        if (components.isEmpty()) {
            throw new IOException("No BOM components could be extracted from the submitted document");
        }
        return new PreparedContent(format, List.copyOf(components), content.length, sha256(content));
    }

    public SbomIngestionResponse ingestPrepared(
            Tenant tenant, AssetType assetType, String assetName, String assetIdentifier,
            PreparedContent content, String originalFilename, SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer, boolean authoritativeForAssetSoftware
    ) throws IOException {
        return tenantWorkRunner.runScopedChecked(tenant, () -> ingestScoped(tenant, assetType, assetName,
                assetIdentifier, content, originalFilename, metadata, assetCustomizer, authoritativeForAssetSoftware));
    }

    private SbomIngestionResponse ingestScoped(
            Tenant tenant, AssetType assetType, String assetName, String assetIdentifier,
            PreparedContent content, String originalFilename, SbomIngestionSourceMetadata metadata,
            Consumer<Asset> assetCustomizer, boolean authoritativeForAssetSoftware
    ) throws IOException {
        SbomFormat format = content.format();
        List<ParsedComponent> components = content.components();
        Asset asset = sbomUploadSupportService.resolveAsset(tenant, assetType, assetName, assetIdentifier);
        asset.setName(assetName);
        asset.setType(assetType);
        if (assetCustomizer != null) {
            assetCustomizer.accept(asset);
        }
        // Set lifecycle fields in-line (same session/transaction) rather than routing through
        // AssetLifecycleService.markInventoryIngested(), which opens a PROPAGATION_REQUIRES_NEW
        // transaction on a separate connection. Doing that here deadlocked against this method's
        // own still-open outer transaction for brand-new assets: the REQUIRES_NEW transaction's
        // save() of the same not-yet-committed asset row blocks in Postgres waiting for this
        // transaction to commit, while this transaction's thread is blocked waiting on it.
        asset.setLastInventoryAt(Instant.now());
        asset.setState(AssetState.ACTIVE);
        asset = sbomUploadSupportService.saveAsset(asset);

        SbomUpload upload = new SbomUpload();
        upload.setTenant(tenant);
        upload.setAsset(asset);
        upload.setFormat(SbomFormat.UNKNOWN);
        upload.setStatus(SbomIngestionStatus.IN_PROGRESS);
        upload.setOriginalFilename(originalFilename);
        upload.setIngestionSourceType(metadata.sourceType());
        upload.setIngestionSourceSystem(metadata.sourceSystem());
        upload.setSourceReference(metadata.sourceReference());
        upload.setSourceEndpoint(metadata.sourceEndpoint());
        upload.setFetchStatusCode(metadata.fetchStatusCode());
        upload.setContentType(metadata.contentType());
        upload.setContentLengthBytes(metadata.contentLengthBytes() == null ? (long) content.length() : metadata.contentLengthBytes());
        upload.setContentSha256(content.sha256());
        upload.setComponentCount(0);
        upload.setFindingsGenerated(0);
        upload.setEvidenceJson(metadata.evidenceJson());
        upload = sbomUploadRepository.save(upload);

        try {
            // Declared model, dataset and cryptographic types stay outside this software
            // inventory pipeline. Direct artifact advisory ingestion is separate; this
            // boundary does not imply that those artifacts cannot have vulnerabilities. They belong to the declared AI inventory and the CBOM evaluator
            // respectively. This is keyed on each component's own type, so an AI-BOM's software
            // dependencies still enter inventory and still get correlated.
            List<ParsedComponent> softwareComponents = components.stream()
                    .filter(parsed -> categorizationService.entersSoftwareInventory(parsed.componentType()))
                    .toList();
            int nonSoftwareSkipped = components.size() - softwareComponents.size();
            if (nonSoftwareSkipped > 0) {
                log.info("Skipped {} non-software component(s) for asset {} during software inventory ingestion",
                        nonSoftwareSkipped, asset.getIdentifier());
            }

            Map<String, ParsedComponent> parsedByKey = new LinkedHashMap<>();
            for (ParsedComponent parsed : softwareComponents) {
                parsedByKey.put(componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl()), parsed);
            }

            Map<IdentityGraphService.ComponentIdentityInput, String> componentKeyByIdentityInput = new LinkedHashMap<>();
            for (ParsedComponent parsed : parsedByKey.values()) {
                componentKeyByIdentityInput.put(
                        new IdentityGraphService.ComponentIdentityInput(
                                parsed.ecosystem(),
                                parsed.packageName(),
                                parsed.purl(),
                                "sbom"
                        ),
                        componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl())
                );
            }

            Map<String, SoftwareIdentity> softwareIdentityByComponentKey = new HashMap<>();
            Map<IdentityGraphService.ComponentIdentityInput, SoftwareIdentity> resolvedIdentities =
                    identityGraphService.resolveFromComponents(componentKeyByIdentityInput.keySet());
            for (Map.Entry<IdentityGraphService.ComponentIdentityInput, String> entry : componentKeyByIdentityInput.entrySet()) {
                SoftwareIdentity softwareIdentity = resolvedIdentities.get(entry.getKey());
                if (softwareIdentity != null) {
                    softwareIdentityByComponentKey.put(entry.getValue(), softwareIdentity);
                }
            }

            List<InventoryComponent> existingComponents = inventoryComponentRepository.findByAsset(asset);
            Map<String, InventoryComponent> existingByKey = new HashMap<>();
            for (InventoryComponent existing : existingComponents) {
                existingByKey.put(componentKey(existing.getEcosystem(), existing.getPackageName(), existing.getVersion(), existing.getPurl()), existing);
            }

            Instant now = Instant.now();
            List<InventoryComponent> toPersist = new ArrayList<>();
            for (ParsedComponent parsed : parsedByKey.values()) {
                String key = componentKey(parsed.ecosystem(), parsed.packageName(), parsed.version(), parsed.purl());
                InventoryComponent component = existingByKey.remove(key);
                if (component == null) {
                    component = new InventoryComponent();
                    component.setTenant(tenant);
                    component.setAsset(asset);
                    component.setIngestedAt(now);
                }
                component.setSbomUpload(upload);
                component.setEcosystem(parsed.ecosystem().toLowerCase(Locale.ROOT));
                component.setPackageName(parsed.packageName().toLowerCase(Locale.ROOT));
                component.setPackageGroup(parsed.packageGroup());
                component.setLicense(parsed.license());
                component.setScope(parsed.scope());
                component.setVersion(parsed.version());
                component.setPurl(parsed.purl());
                component.setComponentDigest(parsed.digest());
                component.setComponentStatus(InventoryComponentStatus.ACTIVE);
                component.setRetiredAt(null);
                component.setLastObservedAt(now);
                component.setSoftwareIdentity(softwareIdentityByComponentKey.get(key));
                component.setNormalizedName(resolveNormalizedName(parsed));
                component.setNormalizedVersion(resolveNormalizedVersion(parsed.version()));
                toPersist.add(component);
            }

            if (authoritativeForAssetSoftware) {
                for (InventoryComponent component : existingByKey.values()) {
                    if (component.getComponentStatus() != InventoryComponentStatus.RETIRED) {
                        component.setComponentStatus(InventoryComponentStatus.RETIRED);
                        component.setRetiredAt(now);
                        toPersist.add(component);
                    }
                }
            }
            if (!toPersist.isEmpty()) {
                inventoryComponentRepository.saveAll(toPersist);
            }

            if (!toPersist.isEmpty()) {
                Map<UUID, List<String>> componentCpesById = new LinkedHashMap<>();
                for (InventoryComponent component : toPersist) {
                    if (component.getId() == null || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                        componentCpesById.put(component.getId(), List.of());
                        continue;
                    }
                    ParsedComponent parsed = parsedByKey.get(componentKey(
                            component.getEcosystem(),
                            component.getPackageName(),
                            component.getVersion(),
                            component.getPurl()
                    ));
                    componentCpesById.put(component.getId(), parsed == null ? List.of() : parsed.cpes());
                }
                inventoryComponentCpeMappingService.syncComponentMappings(toPersist, componentCpesById);
            }

            softwareInventorySyncService.syncFromInventoryDelta(tenant, toPersist, now);
            entityManager.flush();
            entityManager.clear();

            Set<UUID> recomputedComponentIds = new LinkedHashSet<>();
            for (InventoryComponent component : toPersist) {
                if (component.getId() != null) {
                    recomputedComponentIds.add(component.getId());
                }
            }
            findingDeltaQueueService.enqueueSoftwareDeltas(
                    tenant.getId(),
                    recomputedComponentIds,
                    "sbom-ingestion"
            );
            softwareIdentitySummaryProjectionService.refreshTenant(tenant);
            upload.setFormat(format);
            upload.setComponentCount(components.size());
            upload.setFindingsGenerated(0);
            upload.setStatus(SbomIngestionStatus.SUCCESS);
            sbomUploadRepository.save(upload);
            return new SbomIngestionResponse(asset.getId(), upload.getId(), softwareComponents.size(), 0);
        } catch (RuntimeException runtimeException) {
            sbomUploadSupportService.markUploadFailed(upload, runtimeException.getMessage());
            throw runtimeException;
        }
    }

    private String componentKey(String ecosystem, String packageName, String version, String purl) {
        String normalizedPurl = normalize(purl);
        if (!normalizedPurl.isBlank()) {
            return "purl:" + normalizedPurl;
        }
        return "coord:"
                + normalize(ecosystem)
                + ":"
                + normalize(packageName)
                + "@"
                + normalize(version);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String resolveNormalizedName(ParsedComponent parsed) {
        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(parsed.purl());
        String namespace = normalize(parsedPurl.namespace());
        String packageName = normalize(parsedPurl.packageName());
        if (!packageName.isBlank() && !"unknown".equals(packageName)) {
            return namespace.isBlank() ? packageName : namespace + "/" + packageName;
        }

        String fallbackPackage = normalize(parsed.packageName());
        if (!fallbackPackage.isBlank()) {
            return fallbackPackage;
        }
        return "unknown";
    }

    private String resolveNormalizedVersion(String version) {
        String normalized = normalize(version);
        if (normalized.isBlank()) {
            return "unknown";
        }
        if (normalized.startsWith("v") && normalized.length() > 1 && Character.isDigit(normalized.charAt(1))) {
            return normalized.substring(1);
        }
        return normalized;
    }

    private String sha256(byte[] content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    public record PreparedContent(SbomFormat format, List<ParsedComponent> components, int length, String sha256) { }
}
