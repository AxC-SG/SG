package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.repo.BomAssetBackfillStateRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Reconstructs the source and contribution rows for BOM documents ingested before either
 * existed.
 *
 * <p>There is nothing to migrate: the BOM-to-inventory match was recomputed at ingest and
 * discarded, so the mapping has to be rebuilt from what survived. Two things did. Documents
 * were chained by {@code previous_bom_id}/{@code superseded_by}, and one chain is exactly one
 * logical source. And {@code inventory_components.sbom_upload_id} credits a component to the
 * upload that produced it.
 *
 * <p>That second link is single-valued, and re-ingesting an asset from another source
 * overwrites it. So a component can only be attributed to whichever source wrote it last, and
 * components an earlier source contributed are no longer attributable at all. Those are left
 * with no contribution rows on purpose. {@code deriveEvidenceState} maps an empty claim set to
 * LEGACY_UNKNOWN whatever the asset's backfill state, so marking an asset backfilled can never
 * turn a component we failed to attribute into one believed absent. Guessing would.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BomContributionBackfillService {

    private final BomIngestionRecordRepository recordRepository;
    private final BomSourceRepository sourceRepository;
    private final BomComponentContributionRepository contributionRepository;
    private final BomAssetBackfillStateRepository backfillStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final BomContributionService contributionService;
    private final com.prototype.vulnwatch.repo.BomComponentRepository bomComponentRepository;
    private final BomComponentCategorizationService categorizationService;
    private final com.prototype.vulnwatch.repo.FindingRepository findingRepository;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate transactionTemplate;

    @Value("${app.bom.contribution-backfill.batch-size:25}")
    private int batchSize = 25;

    /**
     * Off by default, and that is the intended posture. Enabling it retires inventory rows and
     * closes their findings, which is a one-way change to customer data driven by a heuristic
     * over historical documents. It should be switched on deliberately, per environment, after
     * reading the reported counts.
     */
    @Value("${app.bom.reclassification.retire-non-software:false}")
    private boolean retireNonSoftware = false;

    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy =
            BackgroundTaskExecutionPolicy.allowAll();

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundTaskExecutionPolicy =
                policy == null ? BackgroundTaskExecutionPolicy.allowAll() : policy;
    }

    /**
     * Walks tenants backfilling assets whose documents predate source tracking.
     *
     * <p>Tenant context is established before each transaction opens, not inside it.
     * TenantAwareDataSource pins a connection's search_path when the connection is acquired,
     * and a transaction binds its connection at the start, so opening the transaction first
     * would silently run every tenant's backfill against the default schema.
     */
    @Scheduled(
            fixedDelayString = "${app.bom.contribution-backfill.interval-ms:300000}",
            initialDelayString = "${app.bom.contribution-backfill.initial-delay-ms:60000}")
    public void backfillPendingAssets() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("bom-contribution.backfill")) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    tenantSchemaExecutionService.run(tenant, () -> {
                        List<UUID> assetIds = recordRepository.findAssetIdsAwaitingSourceBackfill(
                                PageRequest.of(0, Math.max(1, batchSize)));
                        for (UUID assetId : assetIds) {
                            try {
                                transactionTemplate.execute(status ->
                                        backfillAsset(tenant.getId(), assetId));
                            } catch (RuntimeException ex) {
                                // Recorded as FAILED against the asset; the sweep continues so
                                // one bad asset cannot stall the rest of the tenant.
                                log.warn("Contribution backfill skipped asset {} for tenant {}: {}",
                                        assetId, tenant.getId(), ex.getMessage());
                            }
                        }
                        return null;
                    });
                } catch (Exception ex) {
                    log.warn("Contribution backfill failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return null;
        });
    }

    public record AssetBackfillResult(
            UUID assetId,
            int sourcesCreated,
            int recordsAssigned,
            int contributionsCreated,
            int componentsLeftUnattributed,
            /**
             * Inventory components whose only BOM evidence is a non-software entry -- a model,
             * dataset or cryptographic asset that predates type-aware ingestion and is still
             * being correlated for CVEs. Reported, not corrected: retiring them closes live
             * findings, and there is no close reason meaning "this was never software", so
             * doing it silently would be the false remediation the reconciliation rules forbid.
             */
            int misclassifiedNonSoftwareComponents
    ) {
    }

    /**
     * Rebuilds one asset's sources and contributions, then opens the reconciliation gate for
     * it. Idempotent: document versions that already carry a source are skipped, so a re-run
     * neither duplicates sources nor disturbs live evidence.
     */
    public AssetBackfillResult backfillAsset(UUID tenantId, UUID assetId) {
        // Select progress only after locking the document chain, so another
        // sweep cannot reconstruct a second source from an old source_id view.
        recordRepository.lockAssetRecords(assetId);
        BomAssetBackfillState state = backfillStateRepository.findByAssetId(assetId)
                .orElseGet(() -> {
                    BomAssetBackfillState fresh = new BomAssetBackfillState();
                    fresh.setTenantId(tenantId);
                    fresh.setAssetId(assetId);
                    return fresh;
                });
        state.setAttemptCount(state.getAttemptCount() + 1);

        try {
            AssetBackfillResult result = reconstruct(tenantId, assetId);
            state.setState(BomBackfillState.BACKFILLED);
            state.setBackfilledAt(Instant.now());
            state.setFailureMessage(null);
            backfillStateRepository.save(state);
            return result;
        } catch (RuntimeException ex) {
            // Left un-backfilled deliberately: a partially reconstructed asset must not have
            // the gate opened, or absence could be concluded from claims that were never written.
            state.setState(BomBackfillState.FAILED);
            state.setBackfilledAt(null);
            state.setFailureMessage(ex.getMessage());
            backfillStateRepository.save(state);
            log.warn("Contribution backfill failed for asset {}", assetId, ex);
            throw ex;
        }
    }

    private AssetBackfillResult reconstruct(UUID tenantId, UUID assetId) {
        List<BomIngestionRecord> records = recordRepository.findByAssetId(assetId);
        if (records.isEmpty()) {
            return new AssetBackfillResult(assetId, 0, 0, 0, 0, 0);
        }

        Map<UUID, BomIngestionRecord> byId = new LinkedHashMap<>();
        for (BomIngestionRecord record : records) {
            byId.put(record.getId(), record);
        }

        int sourcesCreated = 0;
        int recordsAssigned = 0;
        int contributionsCreated = 0;
        Set<UUID> attributed = new LinkedHashSet<>();
        Set<UUID> visited = new HashSet<>();

        for (BomIngestionRecord record : records) {
            if (visited.contains(record.getId())) {
                continue;
            }
            List<BomIngestionRecord> chain = chainFrom(record, byId, visited);
            if (chain.stream().allMatch(r -> r.getSourceId() != null)) {
                continue;
            }

            BomIngestionRecord current = currentOf(chain);
            BomSource source = new BomSource();
            source.setTenantId(tenantId);
            source.setBomType(current.getBomType());
            source.setAssetId(assetId);
            source.setSupplier(current.getSupplier());
            source.setSourceReference(current.getSourceReference());
            source.setCurrentBomId(current.getId());
            source.setRevision(chain.size());
            // Never inferred as complete. A historical document left no record of anyone
            // asserting it covered the asset, and only an audited assertion may do that.
            source.setCompleteness(BomSourceCompleteness.PARTIAL);
            source = sourceRepository.save(source);
            sourcesCreated++;

            for (BomIngestionRecord version : chain) {
                if (version.getSourceId() != null) {
                    continue;
                }
                version.setSourceId(source.getId());
                version.setCompleteness(BomSourceCompleteness.PARTIAL);
                recordRepository.save(version);
                recordsAssigned++;
            }

            contributionsCreated += rebuildContributions(tenantId, assetId, source, current, attributed);
        }

        int unattributed = countUnattributedComponents(assetId, attributed);
        if (unattributed > 0) {
            log.info("Backfill left {} of asset {}'s components unattributed; they stay LEGACY_UNKNOWN",
                    unattributed, assetId);
        }
        if (!attributed.isEmpty()) {
            contributionService.recomputeEvidenceStates(assetId, attributed, Instant.now());
        }
        int misclassified = countMisclassifiedNonSoftwareComponents(assetId, records);
        if (misclassified > 0) {
            log.warn("Asset {} has {} inventory component(s) whose only BOM evidence is a "
                            + "non-software entry; these are still under CVE evaluation and need "
                            + "a reviewed reclassification pass",
                    assetId, misclassified);
            if (retireNonSoftware) {
                int corrected = retireNonSoftwareComponents(assetId, records);
                log.warn("Reclassified {} component(s) on asset {} as not software and closed "
                                + "their findings as AUTO_RECLASSIFIED_NOT_SOFTWARE",
                        corrected, assetId);
            }
        }
        return new AssetBackfillResult(
                assetId, sourcesCreated, recordsAssigned, contributionsCreated, unattributed,
                misclassified);
    }

    private int rebuildContributions(
            UUID tenantId, UUID assetId, BomSource source, BomIngestionRecord current, Set<UUID> attributed) {
        if (current.getSbomUploadId() == null) {
            return 0;
        }
        List<InventoryComponent> components =
                inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(assetId, current.getSbomUploadId());
        Instant now = Instant.now();
        List<BomComponentContribution> toSave = new ArrayList<>();
        for (InventoryComponent component : components) {
            if (component.getId() == null
                    || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                continue;
            }
            if (contributionRepository
                    .findBySourceIdAndInventoryComponentId(source.getId(), component.getId())
                    .isPresent()) {
                continue;
            }
            BomComponentContribution contribution = new BomComponentContribution();
            contribution.setTenantId(tenantId);
            contribution.setSourceId(source.getId());
            contribution.setBomId(current.getId());
            // Unknowable: the BOM component that justified this match was never recorded.
            contribution.setBomComponentId(null);
            contribution.setInventoryComponentId(component.getId());
            contribution.setResolvedIdentityKey(identityKey(component));
            contribution.setContributionState(BomContributionState.SUPPORTED);
            contribution.setAuthoritativeAbsence(false);
            contribution.setFirstContributedAt(now);
            contribution.setLastContributedAt(now);
            toSave.add(contribution);
            attributed.add(component.getId());
        }
        if (toSave.isEmpty()) {
            return 0;
        }
        contributionRepository.saveAll(toSave);
        return toSave.size();
    }

    /** Walks back to the chain's root, then forward, so each chain is visited once. */
    private List<BomIngestionRecord> chainFrom(
            BomIngestionRecord seed, Map<UUID, BomIngestionRecord> byId, Set<UUID> visited) {
        BomIngestionRecord root = seed;
        Set<UUID> backGuard = new HashSet<>();
        while (root.getPreviousBomId() != null
                && byId.containsKey(root.getPreviousBomId())
                && backGuard.add(root.getId())) {
            root = byId.get(root.getPreviousBomId());
        }

        List<BomIngestionRecord> chain = new ArrayList<>();
        BomIngestionRecord cursor = root;
        // The guard is defensive: a corrupted supersede link could otherwise loop forever.
        Set<UUID> forwardGuard = new HashSet<>();
        while (cursor != null && forwardGuard.add(cursor.getId())) {
            chain.add(cursor);
            visited.add(cursor.getId());
            cursor = cursor.getSupersededBy() == null ? null : byId.get(cursor.getSupersededBy());
        }
        return chain;
    }

    private static BomIngestionRecord currentOf(List<BomIngestionRecord> chain) {
        return chain.stream()
                .filter(r -> r.getStatus() == BomStatus.ACTIVE)
                .reduce((first, second) -> second)
                .orElseGet(() -> chain.get(chain.size() - 1));
    }

    private int countUnattributedComponents(UUID assetId, Set<UUID> attributed) {
        int unattributed = 0;
        List<InventoryComponent> all = inventoryComponentRepository.findByAssetId(assetId);
        for (InventoryComponent component : all) {
            if (component.getComponentStatus() == InventoryComponentStatus.ACTIVE
                    && component.getId() != null
                    && !attributed.contains(component.getId())) {
                unattributed++;
            }
        }
        return unattributed;
    }

    /**
     * Counts inventory components that only ever had non-software BOM evidence.
     *
     * <p>Uses the type retained on bom_components, which survived even though the inventory
     * path used to discard it. A component is only counted when no software-typed entry
     * supports it, so anything an SBOM also reports as a library is left alone -- that is the
     * "no independent software evidence" condition.
     */
    private int countMisclassifiedNonSoftwareComponents(UUID assetId, List<BomIngestionRecord> records) {
        List<UUID> activeBomIds = records.stream()
                .filter(record -> record.getStatus() == BomStatus.ACTIVE)
                .map(BomIngestionRecord::getId)
                .toList();
        if (activeBomIds.isEmpty()) {
            return 0;
        }
        Set<String> nonSoftwareKeys = new LinkedHashSet<>();
        Set<String> softwareKeys = new LinkedHashSet<>();
        for (com.prototype.vulnwatch.domain.BomComponent component
                : bomComponentRepository.findByBomIdInAndActiveTrue(activeBomIds)) {
            String key = nameVersionKey(component.getName(), component.getVersion());
            if (categorizationService.entersSoftwareInventory(component.getComponentType())) {
                softwareKeys.add(key);
            } else {
                nonSoftwareKeys.add(key);
            }
        }
        if (nonSoftwareKeys.isEmpty()) {
            return 0;
        }
        int misclassified = 0;
        for (InventoryComponent component : inventoryComponentRepository.findByAssetId(assetId)) {
            if (component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                continue;
            }
            String key = nameVersionKey(component.getPackageName(), component.getVersion());
            if (nonSoftwareKeys.contains(key) && !softwareKeys.contains(key)) {
                misclassified++;
            }
        }
        return misclassified;
    }

    /**
     * Retires components whose only BOM evidence is a non-software entry and closes their
     * findings as a classification correction.
     *
     * <p>Findings are closed here rather than left to the ordinary removal sweep, which would
     * label them AUTO_COMPONENT_REMOVED and so report a still-unremediated vulnerability as
     * having gone away. Nothing was fixed; the subject was never software. Resolution
     * timestamps of already-closed findings are left alone.
     *
     * <p>Gated on the asset being backfilled: before that, a component with no contribution
     * rows is indistinguishable from one whose rows were never written.
     */
    private int retireNonSoftwareComponents(UUID assetId, List<BomIngestionRecord> records) {
        boolean backfilled = backfillStateRepository.findByAssetId(assetId)
                .map(BomAssetBackfillState::getState)
                .filter(state -> state == BomBackfillState.BACKFILLED)
                .isPresent();
        if (!backfilled) {
            return 0;
        }
        List<UUID> activeBomIds = records.stream()
                .filter(record -> record.getStatus() == BomStatus.ACTIVE)
                .map(BomIngestionRecord::getId)
                .toList();
        if (activeBomIds.isEmpty()) {
            return 0;
        }
        Set<String> nonSoftwareKeys = new LinkedHashSet<>();
        Set<String> softwareKeys = new LinkedHashSet<>();
        for (com.prototype.vulnwatch.domain.BomComponent component
                : bomComponentRepository.findByBomIdInAndActiveTrue(activeBomIds)) {
            String key = nameVersionKey(component.getName(), component.getVersion());
            if (categorizationService.entersSoftwareInventory(component.getComponentType())) {
                softwareKeys.add(key);
            } else {
                nonSoftwareKeys.add(key);
            }
        }

        Instant now = Instant.now();
        List<InventoryComponent> toRetire = new ArrayList<>();
        for (InventoryComponent component : inventoryComponentRepository.findByAssetId(assetId)) {
            if (component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                continue;
            }
            String key = nameVersionKey(component.getPackageName(), component.getVersion());
            if (nonSoftwareKeys.contains(key) && !softwareKeys.contains(key)) {
                component.setComponentStatus(InventoryComponentStatus.RETIRED);
                component.setRetiredAt(now);
                toRetire.add(component);
            }
        }
        if (toRetire.isEmpty()) {
            return 0;
        }
        inventoryComponentRepository.saveAll(toRetire);

        List<UUID> retiredIds = toRetire.stream().map(InventoryComponent::getId).toList();
        List<com.prototype.vulnwatch.domain.Finding> toClose = new ArrayList<>();
        for (com.prototype.vulnwatch.domain.Finding finding
                : findingRepository.findByComponent_IdIn(retiredIds)) {
            if (finding.getStatus() != com.prototype.vulnwatch.domain.FindingStatus.OPEN) {
                continue;
            }
            finding.setStatus(com.prototype.vulnwatch.domain.FindingStatus.AUTO_CLOSED);
            finding.setClosedReason(
                    com.prototype.vulnwatch.domain.FindingCloseReason.AUTO_RECLASSIFIED_NOT_SOFTWARE);
            finding.setClosedBy("bom-reclassification");
            finding.setClosedAt(now);
            toClose.add(finding);
        }
        if (!toClose.isEmpty()) {
            findingRepository.saveAll(toClose);
        }
        return toRetire.size();
    }

    private static String nameVersionKey(String name, String version) {
        return normalise(name) + "|" + normalise(version);
    }

    private static String identityKey(InventoryComponent component) {
        String purl = normalise(component.getPurl());
        if (!purl.isEmpty()) {
            return purl;
        }
        return normalise(component.getEcosystem()) + "|"
                + normalise(component.getPackageName()) + "|"
                + normalise(component.getVersion());
    }

    private static String normalise(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
