package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.EolRelease;
import com.prototype.vulnwatch.dto.ApplicationCveResponse;
import com.prototype.vulnwatch.dto.ApplicationRiskResponse;
import com.prototype.vulnwatch.dto.BomComponentCveSummary;
import com.prototype.vulnwatch.dto.BomComponentDetailResponse;
import com.prototype.vulnwatch.dto.BomComponentSummaryResponse;
import com.prototype.vulnwatch.dto.BomDashboardBreakdownItemResponse;
import com.prototype.vulnwatch.dto.EolReleaseSummary;
import com.prototype.vulnwatch.dto.BomDashboardResponse;
import com.prototype.vulnwatch.dto.BomComponentResponse;
import com.prototype.vulnwatch.dto.BomDetailResponse;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.dto.BomInventoryItemResponse;
import com.prototype.vulnwatch.dto.BomLineageItemResponse;
import com.prototype.vulnwatch.dto.BomSupportMatrixResponse;
import com.prototype.vulnwatch.dto.BomWorkflowSummaryResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomComponentEvidenceRepository;
import com.prototype.vulnwatch.repo.BomComponentVulnerabilityLinkRepository;
import com.prototype.vulnwatch.repo.BomComponentWorkflowRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class BomInventoryReadService {

    private final BomIngestionRecordRepository bomRecordRepository;
    private final com.prototype.vulnwatch.repo.BomSourceRepository bomSourceRepository;
    private final BomComponentRepository bomComponentRepository;
    private final BomComponentEvidenceRepository bomComponentEvidenceRepository;
    private final BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository;
    private final BomComponentWorkflowRepository bomComponentWorkflowRepository;
    private final SbomParserService sbomParserService;
    private final AssetRepository assetRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final EolReleaseRepository eolReleaseRepository;
    private final FindingRepository findingRepository;
    private final BomContributionService bomContributionService;
    /** Ecosystem marker on BOM Components rows that are CBOM cryptographic assets. */
    public static final String CRYPTO_ECOSYSTEM = "crypto";

    private final com.prototype.vulnwatch.service.cbom.CbomIngestionService cbomIngestionService;
    private final com.prototype.vulnwatch.repo.CbomComponentRepository cbomComponentRepository;
    private final com.prototype.vulnwatch.service.cbom.CbomReadService cbomReadService;
    private final com.prototype.vulnwatch.repo.CbomRiskFindingRepository cbomRiskFindingRepository;

    public BomInventoryReadService(
            BomIngestionRecordRepository bomRecordRepository,
            com.prototype.vulnwatch.repo.BomSourceRepository bomSourceRepository,
            BomComponentRepository bomComponentRepository,
            BomComponentEvidenceRepository bomComponentEvidenceRepository,
            BomComponentVulnerabilityLinkRepository bomComponentVulnerabilityLinkRepository,
            BomComponentWorkflowRepository bomComponentWorkflowRepository,
            SbomParserService sbomParserService,
            AssetRepository assetRepository,
            InventoryComponentRepository inventoryComponentRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            EolReleaseRepository eolReleaseRepository,
            FindingRepository findingRepository,
            BomContributionService bomContributionService,
            com.prototype.vulnwatch.service.cbom.CbomIngestionService cbomIngestionService,
            com.prototype.vulnwatch.repo.CbomComponentRepository cbomComponentRepository,
            com.prototype.vulnwatch.service.cbom.CbomReadService cbomReadService,
            com.prototype.vulnwatch.repo.CbomRiskFindingRepository cbomRiskFindingRepository
    ) {
        this.bomRecordRepository = bomRecordRepository;
        this.bomSourceRepository = bomSourceRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.bomComponentEvidenceRepository = bomComponentEvidenceRepository;
        this.bomComponentVulnerabilityLinkRepository = bomComponentVulnerabilityLinkRepository;
        this.bomComponentWorkflowRepository = bomComponentWorkflowRepository;
        this.sbomParserService = sbomParserService;
        this.assetRepository = assetRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.eolReleaseRepository = eolReleaseRepository;
        this.findingRepository = findingRepository;
        this.bomContributionService = bomContributionService;
        this.cbomIngestionService = cbomIngestionService;
        this.cbomComponentRepository = cbomComponentRepository;
        this.cbomReadService = cbomReadService;
        this.cbomRiskFindingRepository = cbomRiskFindingRepository;
    }

    @Transactional(readOnly = true)
    public List<BomInventoryItemResponse> listInventory(Tenant tenant, int page, int size) {
        Pageable pageable = PageRequest.of(page, Math.min(size, 200));
        List<BomIngestionRecord> records = bomRecordRepository
                .findByTenant_IdAndStatusOrderByIngestedAtDesc(tenant.getId(), BomStatus.ACTIVE, pageable);
        return records.stream().map(this::toInventoryItem).toList();
    }

    @Transactional(readOnly = true)
    public BomDashboardResponse getDashboard(Tenant tenant) {
        List<BomIngestionRecord> records = bomRecordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE);
        List<UUID> bomIds = records.stream().map(BomIngestionRecord::getId).toList();
        if (bomIds.isEmpty()) {
            return new BomDashboardResponse(0, 0, 0, 0, 0, 0, 0, 0, List.of(), List.of(), List.of(), List.of());
        }
        List<com.prototype.vulnwatch.domain.BomComponent> components = bomComponentRepository.findByBomIdInAndActiveTrue(bomIds);
        List<UUID> componentIds = components.stream().map(com.prototype.vulnwatch.domain.BomComponent::getId).toList();
        Map<UUID, Integer> evidenceCountByComponent = toCountMap(
                bomComponentEvidenceRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentEvidence::getBomComponentId
        );
        Map<UUID, Integer> vulnerabilityCountByComponent = toCountMap(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId
        );
        List<com.prototype.vulnwatch.domain.BomComponentWorkflow> workflows = bomComponentWorkflowRepository.findByBomComponentIdIn(componentIds);
        Map<UUID, String> latestWorkflowStatus = workflows.stream().collect(Collectors.toMap(
                com.prototype.vulnwatch.domain.BomComponentWorkflow::getBomComponentId,
                workflow -> workflow.getWorkflowStatus().name(),
                (left, right) -> right
        ));
        // A CBOM keeps its assets in cbom_components, so bom_components alone undercounts it.
        List<UUID> cbomIds = records.stream()
                .filter(record -> record.getBomType() == BomType.CBOM)
                .map(BomIngestionRecord::getId)
                .toList();
        long cbomAssetCount = cbomIds.isEmpty()
                ? 0
                : cbomComponentRepository.countActiveBySourceBomIds(tenant.getId(), cbomIds);
        long componentCount = components.size() + cbomAssetCount;
        long evidenceCount = evidenceCountByComponent.values().stream().mapToLong(Integer::longValue).sum();
        long vulnerabilityLinkCount = vulnerabilityCountByComponent.values().stream().mapToLong(Integer::longValue).sum();
        long correlatedComponentCount = components.stream()
                .filter(component -> vulnerabilityCountByComponent.getOrDefault(component.getId(), 0) > 0)
                .count();
        long openRemediationCount = workflows.stream()
                .filter(workflow -> workflow.getWorkflowStatus() == com.prototype.vulnwatch.domain.BomWorkflowStatus.REMEDIATION_OPEN)
                .count();
        return new BomDashboardResponse(
                records.size(),
                componentCount,
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                workflows.size(),
                openRemediationCount,
                records.stream().map(record -> coalesce(record.getSourceSystem(), record.getSourceType() != null ? record.getSourceType().name() : null))
                        .filter(value -> value != null && !value.isBlank())
                        .distinct()
                        .count(),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> record.getBomType() != null ? record.getBomType().name() : "UNKNOWN",
                        Collectors.counting()
                ))),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> record.getSpecFamily() != null ? record.getSpecFamily().name() : "UNKNOWN",
                        Collectors.counting()
                ))),
                toBreakdown(records.stream().collect(Collectors.groupingBy(
                        record -> {
                            String value = coalesce(record.getSourceSystem(), record.getSourceType() != null ? record.getSourceType().name() : null);
                            return value == null || value.isBlank() ? "UNKNOWN" : value;
                        },
                        Collectors.counting()
                ))),
                toBreakdown(workflows.stream().collect(Collectors.groupingBy(
                        workflow -> workflow.getWorkflowStatus().name(),
                        Collectors.counting()
                )))
        );
    }

    @Transactional(readOnly = true)
    public List<BomLineageItemResponse> getLineage(Tenant tenant, UUID bomId) {
        BomIngestionRecord seed = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));
        Map<UUID, BomIngestionRecord> byId = bomRecordRepository.findByTenant_IdOrderByIngestedAtDesc(tenant.getId(), PageRequest.of(0, 500))
                .stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity(), (left, right) -> left));
        List<BomLineageItemResponse> lineage = new java.util.ArrayList<>();
        BomIngestionRecord cursor = seed;
        while (cursor != null) {
            lineage.add(toLineageItem(cursor));
            UUID previousId = cursor.getPreviousBomId();
            cursor = previousId != null ? byId.get(previousId) : null;
        }
        UUID forward = seed.getSupersededBy();
        while (forward != null) {
            BomIngestionRecord next = byId.get(forward);
            if (next == null) {
                break;
            }
            lineage.add(0, toLineageItem(next));
            forward = next.getSupersededBy();
        }
        return lineage;
    }

    @Transactional(readOnly = true)
    public List<com.prototype.vulnwatch.dto.CbomBomAssetResponse> getCbomAssets(Tenant tenant, UUID bomId) {
        bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .filter(r -> r.getBomType() == BomType.CBOM)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CBOM record not found"));
        return cbomReadService.listAssetsForBom(tenant, bomId);
    }

    @Transactional(readOnly = true)
    public BomSupportMatrixResponse getSupportMatrix() {
        return sbomParserService.supportMatrix();
    }

    @Transactional(readOnly = true)
    public BomDetailResponse getDetail(Tenant tenant, UUID bomId) {
        BomIngestionRecord record = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));

        List<com.prototype.vulnwatch.domain.BomComponent> allBomComponents =
                bomComponentRepository.findByBomIdAndActiveTrue(bomId);
        List<com.prototype.vulnwatch.domain.BomComponent> bomComponents =
                allBomComponents.stream().limit(500).toList();
        List<UUID> componentIds = bomComponents.stream().map(com.prototype.vulnwatch.domain.BomComponent::getId).toList();
        Map<UUID, Integer> evidenceCountByComponent = toCountMap(
                bomComponentEvidenceRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentEvidence::getBomComponentId
        );
        Map<UUID, Integer> vulnerabilityCountByComponent = toCountMap(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(componentIds),
                com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId
        );
        List<UUID> allComponentIds = allBomComponents.stream()
                .map(com.prototype.vulnwatch.domain.BomComponent::getId).toList();
        Map<UUID, String> workflowStatusByComponent = bomComponentWorkflowRepository.findByBomComponentIdIn(allComponentIds)
                .stream()
                .collect(Collectors.toMap(
                        com.prototype.vulnwatch.domain.BomComponentWorkflow::getBomComponentId,
                        workflow -> workflow.getWorkflowStatus().name(),
                        (left, right) -> right
                ));
        List<BomComponentResponse> components = bomComponents.stream()
                .map(component -> toComponentResponse(component, vulnerabilityCountByComponent, evidenceCountByComponent, workflowStatusByComponent))
                .toList();
        List<BomWorkflowSummaryResponse> workflowSummary = allBomComponents.stream()
                .collect(Collectors.groupingBy(
                        component -> workflowStatusByComponent.getOrDefault(component.getId(), component.getWorkflowStatus().name()),
                        Collectors.counting()
                ))
                .entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> new BomWorkflowSummaryResponse(entry.getKey(), entry.getValue()))
                .toList();
        long evidenceCount = bomComponentEvidenceRepository.countByBomId(bomId);
        long vulnerabilityLinkCount = bomComponentVulnerabilityLinkRepository.countByBomId(bomId);
        Set<UUID> linkedComponentIds = bomComponentVulnerabilityLinkRepository.findByBomIdIn(List.of(bomId))
                .stream().map(com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId)
                .collect(Collectors.toSet());
        long correlatedComponentCount = allBomComponents.stream()
                .filter(component -> linkedComponentIds.contains(component.getId())).count();
        BomInspectionResponse inspection = sbomParserService.inspectResolved(
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null
        );

        return new BomDetailResponse(
                record.getId(),
                record.getAssetId(),
                record.getBomType() != null ? record.getBomType().name() : null,
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null,
                record.getSerialNumber(),
                record.getSupplier(),
                record.getSourceMethod(),
                record.getSourceType() != null ? record.getSourceType().name() : null,
                record.getSourceSystem(),
                record.getSourceReference(),
                record.getSourceUrl(),
                record.getChecksumSha256(),
                inspection,
                componentCountFor(record, allBomComponents.size()),
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                record.getStatus().name(),
                record.getIngestedAt(),
                record.getIngestedBy(),
                workflowSummary,
                components
        );
    }

    @Transactional
    public void softDelete(Tenant tenant, UUID bomId) {
        BomIngestionRecord record = bomRecordRepository.findById(bomId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "BOM record not found"));
        if (record.getSourceId() != null) {
            var source = bomSourceRepository.findForUpdate(record.getSourceId()).orElseThrow();
            // Deletion invalidates any captured reconciliation revision, under the upload lock.
            if (bomId.equals(source.getCurrentBomId())) {
                source.setRevision(source.getRevision() + 1);
                bomSourceRepository.save(source);
            }
        }
        bomComponentRepository.softDeleteByBomId(bomId);
        // Withdraw the evidence this document carried, without inferring that anything is
        // absent. Finding status deliberately survives: deleting the document that reported a
        // vulnerable component is not evidence the vulnerability was remediated.
        bomContributionService.withdrawForDeletedDocument(record);
        if (record.getBomType() == BomType.CBOM) {
            // A CBOM's cryptographic assets and findings live in their own tables, so
            // soft-deleting bom_components does not reach them; deleting a CBOM previously
            // left its components active and its findings' evidence standing.
            cbomIngestionService.deactivateBySourceBomId(bomId);
        }
        record.setStatus(BomStatus.SUPERSEDED);
        bomRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public List<BomComponentSummaryResponse> getBomComponentSummaries(Tenant tenant, int page, int size) {
        List<BomIngestionRecord> activeBomRecords = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE);
        Map<UUID, BomIngestionRecord> bomRecordById = activeBomRecords.stream()
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity()));
        Map<UUID, List<String>> bomTypesBySbomUpload = activeBomRecords.stream()
                .filter(b -> b.getSbomUploadId() != null)
                .collect(Collectors.groupingBy(
                        BomIngestionRecord::getSbomUploadId,
                        Collectors.mapping(
                                b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN",
                                Collectors.toList()
                        )
                ));

        List<InventoryComponent> inventoryComponents = inventoryComponentRepository
                .findActiveApplicationComponentsWithAsset(
                        tenant.getId(),
                        InventoryComponentStatus.ACTIVE
                );
        List<UUID> inventoryComponentIds = inventoryComponents.stream().map(InventoryComponent::getId).toList();
        Map<UUID, List<ComponentVulnerabilityState>> statesByComponent = new HashMap<>();
        if (!inventoryComponentIds.isEmpty()) {
            componentVulnerabilityStateRepository
                    .findWithVulnerabilityByTenantIdAndComponentIds(tenant.getId(), inventoryComponentIds)
                    .forEach(s -> statesByComponent
                            .computeIfAbsent(s.getComponent().getId(), k -> new ArrayList<>())
                            .add(s));
        }
        Map<UUID, List<com.prototype.vulnwatch.domain.Finding>> findingsByComponent = inventoryComponentIds.isEmpty()
                ? Map.of()
                : findingRepository.findOpenByTenantAndComponentIds(tenant.getId(), inventoryComponentIds).stream()
                        .collect(Collectors.groupingBy(finding -> finding.getComponent().getId()));

        List<BomComponentSummaryResponse> summaries = new ArrayList<>();
        inventoryComponents.forEach(c -> {
            List<ComponentVulnerabilityState> states = statesByComponent.getOrDefault(c.getId(), List.of());
            List<ComponentVulnerabilityState> applicable = states.stream()
                    .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                    .toList();
            int critical = (int) applicable.stream()
                    .filter(s -> "CRITICAL".equals(s.getVulnerability().getSeverity())).count();
            int high = (int) applicable.stream()
                    .filter(s -> "HIGH".equals(s.getVulnerability().getSeverity())).count();
            int medium = (int) applicable.stream()
                    .filter(s -> "MEDIUM".equals(s.getVulnerability().getSeverity())).count();
            int low = (int) applicable.stream()
                    .filter(s -> "LOW".equals(s.getVulnerability().getSeverity())).count();

            String correlationState;
            if (!applicable.isEmpty()) {
                correlationState = "APPLICABLE";
            } else if (states.stream().anyMatch(s -> s.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE)) {
                correlationState = "NOT_APPLICABLE";
            } else if (!states.isEmpty()) {
                correlationState = "UNKNOWN";
            } else {
                correlationState = "UNCHECKED";
            }

            List<String> bomTypes = c.getSbomUpload() == null
                    ? List.of()
                    : bomTypesBySbomUpload.getOrDefault(c.getSbomUpload().getId(), List.of())
                            .stream().distinct().sorted().toList();
            double score = computeApplicationRiskScore(critical, high, medium, low);

            List<com.prototype.vulnwatch.domain.Finding> componentFindings =
                    findingsByComponent.getOrDefault(c.getId(), List.of());
            int findingCount = componentFindings.size();
            int criticalFindingCount = (int) componentFindings.stream()
                    .filter(finding -> "CRITICAL".equals(resolvedFindingSeverity(finding))).count();
            int highFindingCount = (int) componentFindings.stream()
                    .filter(finding -> "HIGH".equals(resolvedFindingSeverity(finding))).count();

            summaries.add(new BomComponentSummaryResponse(
                    c.getId().toString(),
                    c.getPackageName(),
                    c.getVersion(),
                    c.getPurl(),
                    c.getEcosystem(),
                    c.getLicense(),
                    c.getAsset().getId().toString(),
                    c.getAsset().getName(),
                    bomTypes,
                    Boolean.TRUE.equals(c.getIsEol()),
                    c.getEolSupportEndDate() != null ? c.getEolSupportEndDate().toString() : null,
                    critical, high, medium, low, applicable.size(),
                    correlationState,
                    toApplicationRiskLevel(score),
                    findingCount,
                    criticalFindingCount,
                    highFindingCount,
                    c.getBomEvidenceState() == null ? null : c.getBomEvidenceState().name()
            ));
        });

        List<UUID> activeBomIds = activeBomRecords.stream().map(BomIngestionRecord::getId).toList();
        List<com.prototype.vulnwatch.domain.BomComponent> bomComponents = activeBomIds.isEmpty()
                ? List.of()
                : bomComponentRepository.findByBomIdInAndActiveTrue(activeBomIds);
        List<UUID> bomComponentIds = bomComponents.stream()
                .map(com.prototype.vulnwatch.domain.BomComponent::getId)
                .toList();
        Map<UUID, Integer> vulnerabilityCountByComponent = toCountMap(
                bomComponentVulnerabilityLinkRepository.findByBomComponentIdIn(bomComponentIds),
                com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId
        );
        Map<UUID, Integer> workflowCountByComponent = toCountMap(
                bomComponentWorkflowRepository.findByBomComponentIdIn(bomComponentIds),
                com.prototype.vulnwatch.domain.BomComponentWorkflow::getBomComponentId
        );
        Map<UUID, Asset> assetById = assetRepository.findAllById(activeBomRecords.stream()
                        .map(BomIngestionRecord::getAssetId)
                        .filter(java.util.Objects::nonNull)
                        .distinct()
                        .toList())
                .stream()
                .collect(Collectors.toMap(Asset::getId, Function.identity()));

        bomComponents.forEach(component -> {
            BomIngestionRecord record = bomRecordById.get(component.getBomId());
            if (record == null) {
                return;
            }
            Asset asset = record.getAssetId() != null ? assetById.get(record.getAssetId()) : null;
            int vulnerabilityCount = vulnerabilityCountByComponent.getOrDefault(component.getId(), 0);
            summaries.add(new BomComponentSummaryResponse(
                    component.getId().toString(),
                    component.getName(),
                    component.getVersion(),
                    component.getPurl(),
                    ecosystemFor(component),
                    component.getLicense(),
                    asset != null ? asset.getId().toString() : null,
                    asset != null ? asset.getName() : "Unassigned",
                    List.of(record.getBomType() != null ? record.getBomType().name() : "UNKNOWN"),
                    false,
                    null,
                    0, 0, 0, 0, vulnerabilityCount,
                    vulnerabilityCount > 0 ? "APPLICABLE" : "UNCHECKED",
                    vulnerabilityCount > 0 ? "HIGH" : "NONE",
                    workflowCountByComponent.getOrDefault(component.getId(), 0),
                    0,
                    0,
                    // A BOM component that resolved to no inventory component has no evidence
                    // state: the state describes a component's presence, and this row is a
                    // document entry that was never mapped to one.
                    null
            ));
        });

        addCbomAssetRows(tenant, activeBomRecords, assetById, summaries);

        summaries.sort(Comparator
                .comparing(BomComponentSummaryResponse::packageName, String.CASE_INSENSITIVE_ORDER)
                .thenComparing(response -> response.version() != null ? response.version() : ""));
        int boundedSize = Math.max(1, Math.min(size, 2000));
        int fromIndex = Math.min(Math.max(0, page) * boundedSize, summaries.size());
        int toIndex = Math.min(fromIndex + boundedSize, summaries.size());
        return summaries.subList(fromIndex, toIndex);
    }

    /**
     * A CBOM's cryptographic assets live in cbom_components, not bom_components, so they get their
     * own rows here. The ecosystem is the fixed marker {@link #CRYPTO_ECOSYSTEM}; the grid keys off it.
     */
    private void addCbomAssetRows(
            Tenant tenant,
            List<BomIngestionRecord> activeBomRecords,
            Map<UUID, Asset> assetById,
            List<BomComponentSummaryResponse> summaries
    ) {
        Map<UUID, BomIngestionRecord> cbomRecords = activeBomRecords.stream()
                .filter(record -> record.getBomType() == BomType.CBOM)
                .collect(Collectors.toMap(BomIngestionRecord::getId, Function.identity()));
        if (cbomRecords.isEmpty()) {
            return;
        }
        List<com.prototype.vulnwatch.domain.CbomComponent> assets = cbomComponentRepository
                .findByTenant_IdAndSourceBom_IdInAndActiveTrue(tenant.getId(), cbomRecords.keySet());
        Map<UUID, List<com.prototype.vulnwatch.domain.CbomRiskFinding>> openFindings = assets.isEmpty()
                ? Map.of()
                : cbomRiskFindingRepository
                        .findByTenant_IdAndComponent_IdIn(tenant.getId(), assets.stream().map(com.prototype.vulnwatch.domain.CbomComponent::getId).toList())
                        .stream()
                        .filter(f -> f.getStatus() == com.prototype.vulnwatch.domain.CbomFindingStatus.OPEN)
                        .collect(Collectors.groupingBy(f -> f.getComponent().getId()));
        for (com.prototype.vulnwatch.domain.CbomComponent asset : assets) {
            BomIngestionRecord record = cbomRecords.get(asset.getSourceBom().getId());
            Asset application = record.getAssetId() != null ? assetById.get(record.getAssetId()) : null;
            List<com.prototype.vulnwatch.domain.CbomRiskFinding> findings = openFindings.getOrDefault(asset.getId(), List.of());
            double score = asset.getRiskScore() == null ? 0.0 : asset.getRiskScore().doubleValue();
            summaries.add(new BomComponentSummaryResponse(
                    asset.getId().toString(),
                    asset.getName(),
                    null,
                    null,
                    CRYPTO_ECOSYSTEM,
                    null,
                    application != null ? application.getId().toString() : null,
                    application != null ? application.getName() : "Unassigned",
                    List.of(BomType.CBOM.name()),
                    false,
                    null,
                    0, 0, 0, 0, 0,
                    "UNCHECKED",
                    toApplicationRiskLevel(score),
                    findings.size(),
                    (int) findings.stream().filter(f -> f.getSeverity() == com.prototype.vulnwatch.domain.CbomRiskSeverity.CRITICAL).count(),
                    (int) findings.stream().filter(f -> f.getSeverity() == com.prototype.vulnwatch.domain.CbomRiskSeverity.HIGH).count(),
                    null
            ));
        }
    }

    @Transactional(readOnly = true)
    public List<ApplicationRiskResponse> getApplicationRisk(Tenant tenant) {
        List<Asset> assets = assetRepository.findByTenant(tenant).stream()
                .filter(a -> a.getType() == AssetType.APPLICATION && a.getState() == AssetState.ACTIVE)
                .toList();
        if (assets.isEmpty()) {
            return List.of();
        }
        List<UUID> assetIds = assets.stream().map(Asset::getId).toList();

        List<BomIngestionRecord> activeBoms = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null && assetIds.contains(b.getAssetId()))
                .toList();
        Map<UUID, List<String>> bomTypesByAsset = activeBoms.stream()
                .collect(Collectors.groupingBy(
                        BomIngestionRecord::getAssetId,
                        Collectors.mapping(
                                b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN",
                                Collectors.toList()
                        )
                ));
        Map<UUID, Instant> lastIngestedByAsset = activeBoms.stream()
                .collect(Collectors.toMap(
                        BomIngestionRecord::getAssetId,
                        BomIngestionRecord::getIngestedAt,
                        (a, b) -> a.isAfter(b) ? a : b
                ));

        List<InventoryComponent> allComponents = inventoryComponentRepository.findByAsset_IdIn(assetIds);
        Map<UUID, Long> totalByAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .collect(Collectors.groupingBy(c -> c.getAsset().getId(), Collectors.counting()));
        Map<UUID, Long> eolByAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE
                        && Boolean.TRUE.equals(c.getIsEol()))
                .collect(Collectors.groupingBy(c -> c.getAsset().getId(), Collectors.counting()));

        List<UUID> allActiveComponentIds = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .map(InventoryComponent::getId)
                .toList();
        Map<UUID, UUID> componentToAsset = allComponents.stream()
                .filter(c -> c.getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .collect(Collectors.toMap(InventoryComponent::getId, c -> c.getAsset().getId()));
        Set<UUID> vulnerableComponentIds = new HashSet<>();
        if (!allActiveComponentIds.isEmpty()) {
            componentVulnerabilityStateRepository
                    .findSummariesByTenantIdAndComponentIds(tenant.getId(), allActiveComponentIds)
                    .stream()
                    .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                    .forEach(s -> vulnerableComponentIds.add(s.getComponentId()));
        }
        Map<UUID, Long> vulnerableByAsset = vulnerableComponentIds.stream()
                .filter(componentToAsset::containsKey)
                .collect(Collectors.groupingBy(componentToAsset::get, Collectors.counting()));

        Map<UUID, Long> findingCountByAsset = findingRepository
                .countOpenFindingsByAssetIds(tenant.getId(), assetIds)
                .stream()
                .collect(Collectors.toMap(
                        row -> (UUID) row[0],
                        row -> (Long) row[1]
                ));

        return assets.stream().map(asset -> {
            List<ComponentVulnerabilityStateRepository.HostApplicableCveRow> cves =
                    componentVulnerabilityStateRepository
                            .findHostApplicableCvesByTenantIdAndAssetId(tenant.getId(), asset.getId());
            Map<UUID, String> severityByVulnId = cves.stream()
                    .collect(Collectors.toMap(
                            ComponentVulnerabilityStateRepository.HostApplicableCveRow::getVulnerabilityId,
                            c -> c.getSeverity() != null ? c.getSeverity() : "UNKNOWN",
                            (a, b) -> a
                    ));
            int critical = (int) severityByVulnId.values().stream().filter("CRITICAL"::equals).count();
            int high = (int) severityByVulnId.values().stream().filter("HIGH"::equals).count();
            int medium = (int) severityByVulnId.values().stream().filter("MEDIUM"::equals).count();
            int low = (int) severityByVulnId.values().stream()
                    .filter(s -> "LOW".equals(s) || "NONE".equals(s)).count();
            int total = severityByVulnId.size();
            double riskScore = computeApplicationRiskScore(critical, high, medium, low);
            List<String> bomTypes = bomTypesByAsset.getOrDefault(asset.getId(), List.of())
                    .stream().distinct().sorted().toList();
            Instant lastIngested = lastIngestedByAsset.get(asset.getId());
            return new ApplicationRiskResponse(
                    asset.getId().toString(),
                    asset.getName(),
                    asset.getIdentifier(),
                    asset.getBusinessCriticality() != null ? asset.getBusinessCriticality().name() : "MEDIUM",
                    bomTypes,
                    totalByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    vulnerableByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    eolByAsset.getOrDefault(asset.getId(), 0L).intValue(),
                    critical, high, medium, low, total,
                    riskScore,
                    toApplicationRiskLevel(riskScore),
                    lastIngested != null ? lastIngested.toString() : null,
                    findingCountByAsset.getOrDefault(asset.getId(), 0L).intValue()
            );
        })
        .sorted(Comparator.comparingDouble(ApplicationRiskResponse::riskScore).reversed())
        .toList();
    }

    @Transactional(readOnly = true)
    public List<ApplicationCveResponse> getApplicationCves(Tenant tenant, UUID assetId) {
        return componentVulnerabilityStateRepository
                .findHostApplicableCvesByTenantIdAndAssetId(tenant.getId(), assetId)
                .stream()
                .map(r -> new ApplicationCveResponse(
                        r.getVulnerabilityId().toString(),
                        r.getComponentId().toString(),
                        r.getExternalId(),
                        r.getSeverity(),
                        r.getCvssScore(),
                        r.getEpssScore(),
                        r.getPackageName(),
                        r.getVersion(),
                        r.getLastEvaluatedAt() != null ? r.getLastEvaluatedAt().toString() : null
                ))
                .toList();
    }

    @Transactional(readOnly = true)
    public BomComponentDetailResponse getComponentDetail(Tenant tenant, UUID componentId) {
        var bomComponent = bomComponentRepository.findById(componentId)
                .filter(component -> component.isActive()
                        && component.getTenant().getId().equals(tenant.getId()));
        if (bomComponent.isPresent()) {
            return toBomComponentDetail(tenant, bomComponent.get());
        }

        InventoryComponent component = inventoryComponentRepository.findById(componentId)
                .filter(c -> c.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Component not found"));

        List<BomIngestionRecord> assetBoms = bomRecordRepository
                .findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                .stream()
                .filter(b -> b.getAssetId() != null && b.getAssetId().equals(component.getAsset().getId()))
                .toList();
        List<String> bomTypes = assetBoms.stream()
                .map(b -> b.getBomType() != null ? b.getBomType().name() : "UNKNOWN")
                .distinct().sorted().toList();

        List<ComponentVulnerabilityState> states = componentVulnerabilityStateRepository
                .findWithVulnerabilityByTenantIdAndComponentIds(tenant.getId(), List.of(componentId));

        List<ComponentVulnerabilityState> applicable = states.stream()
                .filter(s -> s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                .toList();
        int critical = (int) applicable.stream().filter(s -> "CRITICAL".equals(s.getVulnerability().getSeverity())).count();
        int high    = (int) applicable.stream().filter(s -> "HIGH".equals(s.getVulnerability().getSeverity())).count();
        int medium  = (int) applicable.stream().filter(s -> "MEDIUM".equals(s.getVulnerability().getSeverity())).count();
        int low     = (int) applicable.stream().filter(s -> "LOW".equals(s.getVulnerability().getSeverity())).count();
        double riskScore = computeApplicationRiskScore(critical, high, medium, low);

        String correlationState;
        if (!applicable.isEmpty()) {
            correlationState = "APPLICABLE";
        } else if (states.stream().anyMatch(s -> s.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE)) {
            correlationState = "NOT_APPLICABLE";
        } else if (!states.isEmpty()) {
            correlationState = "UNKNOWN";
        } else {
            correlationState = "UNCHECKED";
        }

        List<BomComponentCveSummary> cves = states.stream()
                .sorted(Comparator.comparing(s -> s.getVulnerability().getSeverity() != null ? s.getVulnerability().getSeverity() : ""))
                .map(s -> new BomComponentCveSummary(
                        s.getVulnerability().getId().toString(),
                        s.getVulnerability().getExternalId(),
                        s.getVulnerability().getSeverity(),
                        s.getVulnerability().getTitle(),
                        s.getApplicabilityState().name(),
                        s.getVulnerability().getEpssScore(),
                        s.getVulnerability().getCvssScore()
                ))
                .toList();

        List<EolReleaseSummary> eolReleases = List.of();
        if (component.getEolSlug() != null && !component.getEolSlug().isBlank()) {
            eolReleases = eolReleaseRepository.findByProductSlug(component.getEolSlug()).stream()
                    .sorted(Comparator.comparing(EolRelease::getReleaseDate, Comparator.nullsLast(Comparator.reverseOrder())))
                    .map(r -> new EolReleaseSummary(
                            r.getCycle(),
                            r.getReleaseDate() != null ? r.getReleaseDate().toString() : null,
                            r.getEolDate() != null ? r.getEolDate().toString() : null,
                            r.getSupportEndDate() != null ? r.getSupportEndDate().toString() : null,
                            r.getLatestVersion(),
                            r.getLatestReleaseDate() != null ? r.getLatestReleaseDate().toString() : null,
                            r.isEol(),
                            r.isLts()
                    ))
                    .toList();
        }

        Asset asset = component.getAsset();
        return new BomComponentDetailResponse(
                component.getId().toString(),
                component.getPackageName(),
                component.getPackageGroup(),
                component.getVersion(),
                component.getPurl(),
                component.getEcosystem(),
                component.getLicense(),
                component.getScope(),
                component.getNormalizedName(),
                component.getEolSlug(),
                component.getEolCycle(),
                Boolean.TRUE.equals(component.getIsEol()),
                component.getEolDate() != null ? component.getEolDate().toString() : null,
                component.getEolSupportEndDate() != null ? component.getEolSupportEndDate().toString() : null,
                component.getSupportPhase(),
                component.getEolCheckedAt() != null ? component.getEolCheckedAt().toString() : null,
                component.getIngestedAt().toString(),
                component.getLastObservedAt().toString(),
                asset.getId().toString(),
                asset.getName(),
                asset.getIdentifier(),
                asset.getType() != null ? asset.getType().name() : null,
                bomTypes,
                correlationState,
                toApplicationRiskLevel(riskScore),
                critical, high, medium, low, states.size(),
                cves,
                eolReleases
        );
    }

    private BomComponentDetailResponse toBomComponentDetail(
            Tenant tenant,
            com.prototype.vulnwatch.domain.BomComponent component
    ) {
        BomIngestionRecord record = bomRecordRepository.findById(component.getBomId())
                .filter(bom -> bom.getTenant().getId().equals(tenant.getId())
                        && bom.getStatus() == BomStatus.ACTIVE)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Active BOM record not found"));
        Asset asset = record.getAssetId() == null
                ? null
                : assetRepository.findById(record.getAssetId()).orElse(null);
        List<com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink> links =
                bomComponentVulnerabilityLinkRepository.findByBomComponentId(component.getId());
        List<BomComponentCveSummary> cves = links.stream()
                .map(link -> new BomComponentCveSummary(
                        link.getId().toString(),
                        link.getVulnerabilityKey(),
                        null,
                        "BOM vulnerability correlation",
                        "APPLICABLE",
                        null,
                        null
                ))
                .toList();
        int workflowCount = bomComponentWorkflowRepository
                .findByBomComponentIdIn(List.of(component.getId()))
                .size();
        String bomType = record.getBomType() != null ? record.getBomType().name() : "UNKNOWN";
        String timestamp = record.getIngestedAt().toString();
        int vulnerabilityCount = links.size();

        return new BomComponentDetailResponse(
                component.getId().toString(),
                component.getName(),
                component.getGroupName(),
                component.getVersion(),
                component.getPurl(),
                ecosystemFor(component),
                component.getLicense(),
                component.getScope(),
                component.getName().toLowerCase(),
                null,
                null,
                false,
                null,
                null,
                null,
                null,
                timestamp,
                timestamp,
                asset != null ? asset.getId().toString() : null,
                asset != null ? asset.getName() : "Unassigned",
                asset != null ? asset.getIdentifier() : null,
                asset != null && asset.getType() != null ? asset.getType().name() : null,
                List.of(bomType),
                vulnerabilityCount > 0 ? "APPLICABLE" : "UNCHECKED",
                vulnerabilityCount > 0 || workflowCount > 0 ? "HIGH" : "NONE",
                0,
                0,
                0,
                0,
                vulnerabilityCount,
                cves,
                List.of()
        );
    }

    private String ecosystemFor(com.prototype.vulnwatch.domain.BomComponent component) {
        String purl = component.getPurl();
        if (purl != null && purl.startsWith("pkg:")) {
            int separator = purl.indexOf('/', 4);
            String type = separator > 4 ? purl.substring(4, separator) : purl.substring(4);
            return switch (type.toLowerCase()) {
                case "pypi" -> "PYPI";
                case "golang" -> "GO";
                default -> type.toUpperCase();
            };
        }
        return switch (component.getCategory()) {
            case AI_MODEL -> "AI/ML";
            case CRYPTOGRAPHIC -> "CRYPTO";
            default -> component.getComponentType() != null
                    ? component.getComponentType().toUpperCase()
                    : "GENERIC";
        };
    }

    private double computeApplicationRiskScore(int critical, int high, int medium, int low) {
        int total = critical + high + medium + low;
        if (total == 0) {
            return 0.0;
        }
        double weighted = critical * 10.0 + high * 7.0 + medium * 4.0 + low * 1.0;
        return Math.min(10.0, weighted / total);
    }

    private String toApplicationRiskLevel(double score) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        if (score > 0.0) return "LOW";
        return "NONE";
    }

    private String resolvedFindingSeverity(com.prototype.vulnwatch.domain.Finding finding) {
        if (finding.getSeverityOverride() != null && !finding.getSeverityOverride().isBlank()) {
            return finding.getSeverityOverride().toUpperCase(java.util.Locale.ROOT);
        }
        if (finding.getVulnerability() != null && finding.getVulnerability().getSeverity() != null) {
            return finding.getVulnerability().getSeverity().toUpperCase(java.util.Locale.ROOT);
        }
        return finding.getRiskScore() >= 9 ? "CRITICAL" : finding.getRiskScore() >= 7 ? "HIGH" : "OTHER";
    }

    /** A CBOM's components are its cbom_components assets; every other type uses bom_components. */
    private int componentCountFor(BomIngestionRecord record, int bomComponentCount) {
        if (record.getBomType() != BomType.CBOM) {
            return bomComponentCount;
        }
        return (int) cbomComponentRepository.countByTenant_IdAndSourceBom_IdAndActiveTrue(
                record.getTenant().getId(), record.getId());
    }

    private BomInventoryItemResponse toInventoryItem(BomIngestionRecord r) {
        long evidenceCount = bomComponentEvidenceRepository.countByBomId(r.getId());
        long vulnerabilityLinkCount = bomComponentVulnerabilityLinkRepository.countByBomId(r.getId());
        Set<UUID> linkedComponentIds = bomComponentVulnerabilityLinkRepository.findByBomIdIn(List.of(r.getId())).stream()
                .map(com.prototype.vulnwatch.domain.BomComponentVulnerabilityLink::getBomComponentId)
                .collect(Collectors.toSet());
        List<com.prototype.vulnwatch.domain.BomComponent> activeComponents =
                bomComponentRepository.findByBomIdAndActiveTrue(r.getId());
        long correlatedComponentCount = activeComponents.stream()
                .filter(component -> linkedComponentIds.contains(component.getId()))
                .count();
        BomInspectionResponse inspection = sbomParserService.inspectResolved(
                r.getFormat() != null ? r.getFormat().name() : null,
                r.getFormatVersion(),
                r.getSpecFamily() != null ? r.getSpecFamily().name() : null,
                r.getDocumentFormat() != null ? r.getDocumentFormat().name() : null
        );
        return new BomInventoryItemResponse(
                r.getId(),
                r.getAssetId(),
                r.getBomType() != null ? r.getBomType().name() : null,
                r.getFormat() != null ? r.getFormat().name() : null,
                r.getFormatVersion(),
                r.getSpecFamily() != null ? r.getSpecFamily().name() : null,
                r.getDocumentFormat() != null ? r.getDocumentFormat().name() : null,
                r.getSerialNumber(),
                r.getSupplier(),
                r.getSourceMethod(),
                r.getSourceType() != null ? r.getSourceType().name() : null,
                r.getSourceSystem(),
                r.getSourceUrl(),
                inspection.supportLevel(),
                inspection.supported(),
                componentCountFor(r, activeComponents.size()),
                evidenceCount,
                vulnerabilityLinkCount,
                correlatedComponentCount,
                r.getStatus().name(),
                r.getIngestedAt(),
                r.getIngestedBy(),
                r.getSourceLabel(),
                r.getSourceReference()
        );
    }

    private BomComponentResponse toComponentResponse(
            com.prototype.vulnwatch.domain.BomComponent c,
            Map<UUID, Integer> vulnerabilityCountByComponent,
            Map<UUID, Integer> evidenceCountByComponent,
            Map<UUID, String> workflowStatusByComponent
    ) {
        return new BomComponentResponse(
                c.getId(),
                c.getName(),
                c.getVersion(),
                c.getPurl(),
                c.getCpe(),
                c.getLicense(),
                c.getSupplier(),
                c.getComponentType(),
                c.getCategory() != null ? c.getCategory().name() : null,
                workflowStatusByComponent.getOrDefault(c.getId(), c.getWorkflowStatus().name()),
                vulnerabilityCountByComponent.getOrDefault(c.getId(), 0),
                evidenceCountByComponent.getOrDefault(c.getId(), 0),
                c.isActive()
        );
    }

    private <T> Map<UUID, Integer> toCountMap(Collection<T> rows, Function<T, UUID> idExtractor) {
        return rows.stream().collect(Collectors.toMap(
                idExtractor,
                row -> 1,
                Integer::sum
        ));
    }

    private List<BomDashboardBreakdownItemResponse> toBreakdown(Map<String, Long> counts) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .map(entry -> new BomDashboardBreakdownItemResponse(entry.getKey(), entry.getKey().replace('_', ' '), entry.getValue()))
                .toList();
    }

    private BomLineageItemResponse toLineageItem(BomIngestionRecord record) {
        return new BomLineageItemResponse(
                record.getId(),
                record.getPreviousBomId(),
                record.getSupersededBy(),
                record.getBomType() != null ? record.getBomType().name() : null,
                record.getStatus() != null ? record.getStatus().name() : null,
                record.getFormat() != null ? record.getFormat().name() : null,
                record.getFormatVersion(),
                record.getSpecFamily() != null ? record.getSpecFamily().name() : null,
                record.getDocumentFormat() != null ? record.getDocumentFormat().name() : null,
                record.getSourceType() != null ? record.getSourceType().name() : null,
                record.getSourceSystem(),
                record.getSourceReference(),
                record.getChecksumSha256(),
                record.getComponentCount(),
                record.getIngestedAt()
        );
    }

    private String coalesce(String left, String right) {
        return left != null && !left.isBlank() ? left : right;
    }
}
