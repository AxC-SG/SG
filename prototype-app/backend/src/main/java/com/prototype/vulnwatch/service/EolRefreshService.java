package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.EolApiClient;
import com.prototype.vulnwatch.client.EolApiClient.EolCycleData;
import com.prototype.vulnwatch.client.EolApiClient.EolProductSummary;
import com.prototype.vulnwatch.client.EolApiClient.EolReleaseFetchResult;
import com.prototype.vulnwatch.domain.EolProductCatalog;
import com.prototype.vulnwatch.domain.EolRelease;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.EolProductCatalogRepository;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SoftwareEolMappingRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.util.CpeUtil;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Scheduled service that keeps EOL data in sync with endoflife.date.
 *
 * Jobs (all configurable via application.yml):
 *  1. fullCatalogRefresh  — Sunday 2am: batch-upserts all product slugs + CPE/PURL/alias metadata
 *  2. releaseDataRefresh  — Sunday 3am: conditional fetch (If-Modified-Since) per mapped slug
 *  3. resolveInstanceMappings — Sunday 3:30am: maps SoftwareIdentities to EOL slugs (in-memory)
 *  4. denormalizeEolStatus — Sunday 4am: set-based UPDATE with DISTINCT ON; writes latest_supported_version
 */
@Service
public class EolRefreshService {

    private static final Logger LOG = LoggerFactory.getLogger(EolRefreshService.class);

    // Batch size for catalog upserts
    private static final int CATALOG_BATCH_SIZE = 100;

    private static final String CATALOG_UPSERT_SQL = """
            INSERT INTO eol_product_catalog
                (slug, display_name, cpe_vendor, cpe_product, purl_type, purl_namespace,
                 aliases, last_fetched_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, now(), now(), now())
            ON CONFLICT (slug) DO UPDATE SET
                display_name    = COALESCE(EXCLUDED.display_name,    eol_product_catalog.display_name),
                cpe_vendor      = COALESCE(EXCLUDED.cpe_vendor,      eol_product_catalog.cpe_vendor),
                cpe_product     = COALESCE(EXCLUDED.cpe_product,     eol_product_catalog.cpe_product),
                purl_type       = COALESCE(EXCLUDED.purl_type,       eol_product_catalog.purl_type),
                purl_namespace  = COALESCE(EXCLUDED.purl_namespace,  eol_product_catalog.purl_namespace),
                aliases         = COALESCE(EXCLUDED.aliases,         eol_product_catalog.aliases),
                last_fetched_at = now(),
                updated_at      = now()
            """;

    @Value("${app.eol.enabled:true}")
    private boolean enabled;

    private final EolApiClient eolApiClient;
    private final EolProductCatalogRepository catalogRepository;
    private final EolReleaseRepository releaseRepository;
    private final SoftwareEolMappingRepository mappingRepository;
    private final EolSlugResolverService slugResolverService;
    private final JdbcTemplate jdbcTemplate;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final OrgCveRecordService orgCveRecordService;
    private final TenantRepository tenantRepository;
    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final QualityIssueProjectionService qualityIssueProjectionService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public EolRefreshService(
            EolApiClient eolApiClient,
            EolProductCatalogRepository catalogRepository,
            EolReleaseRepository releaseRepository,
            SoftwareEolMappingRepository mappingRepository,
            EolSlugResolverService slugResolverService,
            JdbcTemplate jdbcTemplate,
            InventoryComponentRepository inventoryComponentRepository,
            FindingDeltaQueueService findingDeltaQueueService,
            OrgCveRecordService orgCveRecordService,
            TenantRepository tenantRepository,
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            QualityIssueProjectionService qualityIssueProjectionService,
            TenantWorkRunner tenantWorkRunner) {
        this.eolApiClient = eolApiClient;
        this.catalogRepository = catalogRepository;
        this.releaseRepository = releaseRepository;
        this.mappingRepository = mappingRepository;
        this.slugResolverService = slugResolverService;
        this.jdbcTemplate = jdbcTemplate;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.orgCveRecordService = orgCveRecordService;
        this.tenantRepository = tenantRepository;
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.qualityIssueProjectionService = qualityIssueProjectionService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    private com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService durableRuns;
    private org.springframework.transaction.support.TransactionTemplate mutations;

    @org.springframework.beans.factory.annotation.Autowired
    void configureDurableRuns(com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService runs,
                              org.springframework.transaction.PlatformTransactionManager manager) {
        this.durableRuns = runs;
        this.mutations = new org.springframework.transaction.support.TransactionTemplate(manager);
    }

    @Value("${app.eol.catalog-refresh-cron:0 0 2 * * SUN}") private String catalogCron;
    @Value("${app.eol.release-refresh-cron:0 0 3 * * SUN}") private String releaseCron;
    @Value("${app.eol.resolve-mappings-cron:0 30 3 * * SUN}") private String mappingCron;
    @Value("${app.eol.denormalize-cron:0 0 4 * * SUN}") private String denormalizeCron;
    @Value("${app.eol.lifecycle-date-sweep-cron:0 15 0 * * *}") private String dateSweepCron;

    public SyncTriggerResponse triggerCatalogRefresh() { return queue("EOL_CATALOG_REFRESH"); }
    public SyncTriggerResponse triggerReleaseRefresh() { return queue("EOL_RELEASE_REFRESH"); }
    public SyncTriggerResponse triggerMappingResolve() { return queue("EOL_MAPPING_RESOLVE"); }
    public SyncTriggerResponse triggerDenormalize() { return queue("EOL_DENORMALIZE"); }
    public SyncTriggerResponse triggerFullRefresh() { return queue("EOL_FULL_REFRESH"); }

    private SyncTriggerResponse queue(String type) {
        if (!enabled) throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.CONFLICT, "EOL refresh is disabled");
        return TenantContext.runAsPlatform(() -> durableRuns.prepareQueuedRun(type, List.of(type))
                .toResponse("EOL refresh already accepted", "EOL refresh queued"));
    }

    private void schedule(String type, String cron) {
        if (!enabled || !backgroundTaskExecutionPolicy.allowsBackgroundTask("eol.schedule")) return;
        Instant occurrence = ScheduleOccurrence.due(cron, Instant.now());
        if (occurrence == null) {
            LOG.warn("EOL callback missed its one-minute admission window: {}", type);
            return;
        }
        TenantContext.runAsPlatform(() -> durableRuns.prepareScheduledRun(type, occurrence));
    }

    /** Called only inside the durable worker's owned attempt. */
    public void executeQueuedRun(java.util.UUID runId) {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("eol.execute")) return;
        SyncRun run = durableRuns.markRunning(runId);
        try {
            if (!enabled) throw new IllegalStateException("EOL refresh is disabled");
            int count = switch (run.getSyncType()) {
                case "EOL_CATALOG_REFRESH" -> runCatalogRefresh();
                case "EOL_RELEASE_REFRESH" -> runReleaseRefresh();
                case "EOL_MAPPING_RESOLVE" -> runMappingResolveAcrossTenants();
                case "EOL_DENORMALIZE" -> runDenormalizeAcrossTenants();
                case "EOL_DATE_SWEEP" -> runDateSweepAcrossTenants();
                case "EOL_FULL_REFRESH" -> runCatalogRefresh() + runReleaseRefresh()
                        + runMappingResolveAcrossTenants() + runDenormalizeAcrossTenants();
                default -> throw new IllegalArgumentException("Unsupported EOL work type");
            };
            durableRuns.completeRun(run, "completed", 0, 0, count, 0, null);
        } catch (com.prototype.vulnwatch.service.vulningestion.VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (RuntimeException failure) {
            durableRuns.completeRun(run, "failed", 0, 0, 0, 1, failure.getMessage());
        }
    }

    private int runDateSweepAcrossTenants() {
        DenormalizeAccumulator total = new DenormalizeAccumulator();
        forEachTenant(tenant -> total.add(runLifecycleDateSweep()));
        return total.count();
    }

    private void forEachTenant(java.util.function.Consumer<Tenant> work) {
        RuntimeException incomplete = null;
        for (Tenant tenant : tenantRepository.findAllByOrderByCreatedAtAsc()) {
            if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) continue;
            try { tenantWorkRunner.runScoped(tenant, () -> work.accept(tenant)); }
            catch (com.prototype.vulnwatch.service.vulningestion.VulnerabilityAttemptService.StaleAttemptException stale) {
                throw stale;
            } catch (RuntimeException failure) {
                if (incomplete == null) incomplete = new IllegalStateException("EOL tenant publication is incomplete");
                incomplete.addSuppressed(failure);
            }
        }
        if (incomplete != null) throw incomplete;
    }

    // -------------------------------------------------------------------------
    // Job 1: Full catalog refresh — batch JDBC upsert
    // -------------------------------------------------------------------------

    @Scheduled(zone = "UTC", cron = "${app.eol.catalog-refresh-cron:0 0 2 * * SUN}")
    public void fullCatalogRefresh() {
        schedule("EOL_CATALOG_REFRESH", catalogCron);
    }

    private int runCatalogRefresh() {
        LOG.info("Starting EOL full catalog refresh");
        List<EolProductSummary> products = eolApiClient.fetchAllProducts();
        if (products.isEmpty()) {
            throw new IllegalStateException("EOL catalog API returned 0 products — possible network or API issue");
        }

        List<Object[]> params = new ArrayList<>(products.size());
        for (EolProductSummary product : products) {
            if (product.slug() == null || product.slug().isBlank()) continue;
            String[] cpe = extractCpeComponents(product.cpe());
            String[] purl = extractPurlComponents(product.purl());
            String aliasesStr = product.aliases() == null || product.aliases().isEmpty()
                    ? null : String.join(",", product.aliases());
            params.add(new Object[]{
                    product.slug(), product.label(),
                    cpe[0], cpe[1], purl[0], purl[1],
                    aliasesStr
            });
        }

        int total = 0;
        for (int i = 0; i < params.size(); i += CATALOG_BATCH_SIZE) {
            List<Object[]> batch = params.subList(i, Math.min(i + CATALOG_BATCH_SIZE, params.size()));
            int[] counts = mutations.execute(status -> jdbcTemplate.batchUpdate(CATALOG_UPSERT_SQL, batch));
            for (int c : counts) total += Math.max(0, c);
        }
        LOG.info("EOL catalog upserted {} / {} products", total, products.size());
        return total;
    }

    // -------------------------------------------------------------------------
    // Job 2: Release data refresh — conditional fetch using Last-Modified
    // -------------------------------------------------------------------------

    @Scheduled(zone = "UTC", cron = "${app.eol.release-refresh-cron:0 0 3 * * SUN}")
    public void releaseDataRefresh() {
        schedule("EOL_RELEASE_REFRESH", releaseCron);
    }

    private int runReleaseRefresh() {
        LOG.info("Starting EOL release data refresh for tracked products");
        List<String> trackedSlugs = mappingRepository.findDistinctMappedSlugs();

        if (trackedSlugs.isEmpty()) {
            trackedSlugs = catalogRepository.findSlugsByHasIdentifiers();
            LOG.info("No mappings yet — fetching release data for {} identified catalog slugs", trackedSlugs.size());
        }

        Map<String, String> lastModifiedBySlug = catalogRepository.findAll().stream()
                .filter(c -> c.getLastModified() != null)
                .collect(Collectors.toMap(
                        EolProductCatalog::getSlug,
                        EolProductCatalog::getLastModified,
                        (a, b) -> a));

        int refreshed = 0;
        int skipped = 0;
        int failed = 0;

        for (String slug : trackedSlugs) {
            try {
                String ifModifiedSince = lastModifiedBySlug.get(slug);
                EolReleaseFetchResult result = eolApiClient.fetchProductReleasesConditional(slug, ifModifiedSince);
                if (result.notModified()) {
                    skipped++;
                    continue;
                }
                mutations.executeWithoutResult(status -> {
                    refreshReleasesForSlug(slug, result.cycles());
                    if (result.lastModified() != null) updateCatalogLastModified(slug, result.lastModified());
                });
                refreshed++;
            } catch (com.prototype.vulnwatch.service.vulningestion.VulnerabilityAttemptService.StaleAttemptException stale) {
                throw stale;
            } catch (Exception e) {
                failed++;
                LOG.warn("Failed to refresh releases for slug '{}': {}", slug, e.getMessage());
            }
        }

        LOG.info("EOL release refresh — refreshed {}, skipped (304) {}, failed {} of {} slugs",
                refreshed, skipped, failed, trackedSlugs.size());
        if (failed > 0) throw new IllegalStateException("EOL release refresh is incomplete: " + failed + " slugs failed");
        return refreshed;
    }

    @Transactional
    void refreshReleasesForSlug(String slug, List<EolCycleData> cycles) {
        if (cycles == null || cycles.isEmpty()) return;

        for (EolCycleData cycle : cycles) {
            Optional<EolRelease> existing = releaseRepository.findByProductSlugAndCycle(slug, cycle.cycle());
            EolRelease release = existing.orElseGet(EolRelease::new);

            release.setProductSlug(slug);
            release.setCycle(cycle.cycle());
            release.setReleaseDate(cycle.releaseDate());
            release.setEolDate(cycle.eolDate());
            release.setEolBoolean(cycle.eolBoolean());
            release.setSupportEndDate(cycle.supportEndDate());
            release.setExtendedSupportDate(cycle.extendedSupportDate());
            release.setLatestVersion(cycle.latestVersion());
            release.setLatestReleaseDate(cycle.latestReleaseDate());
            release.setLts(cycle.lts());
            release.setEol(cycle.isEol());
            release.setEoas(cycle.isEoas());
            release.setEoes(cycle.isEoes());
            release.setDiscontinued(cycle.discontinued());
            release.setSecuritySupportDate(cycle.securitySupportDate());
            release.setOfficialSourceUrl(cycle.officialSourceUrl());
            release.setSupportPhase(computeSupportPhase(
                    cycle.discontinued(), cycle.isEol(), cycle.isEoas(), cycle.isEoes(), cycle.lts()));
            release.touch();
            releaseRepository.save(release);
        }
    }

    private void updateCatalogLastModified(String slug, String lastModified) {
        jdbcTemplate.update(
                "UPDATE eol_product_catalog SET last_modified = ?, last_fetched_at = now(), updated_at = now() WHERE slug = ?",
                lastModified, slug);
    }

    // -------------------------------------------------------------------------
    // Job 3: Resolve SoftwareIdentity → EOL slug mappings
    // -------------------------------------------------------------------------

    @Scheduled(zone = "UTC", cron = "${app.eol.resolve-mappings-cron:0 30 3 * * SUN}")
    public void resolveInstanceMappings() {
        schedule("EOL_MAPPING_RESOLVE", mappingCron);
    }

    private int runMappingResolve() {
        LOG.info("Starting EOL slug mapping resolution");
        return slugResolverService.resolveAll();
    }

    private int runMappingResolveAcrossTenants() {
        DenormalizeAccumulator accumulator = new DenormalizeAccumulator();
        forEachTenant(tenant -> accumulator.add(runMappingResolve()));
        return accumulator.count();
    }

    // -------------------------------------------------------------------------
    // Job 4: Denormalize EOL status — set-based DISTINCT ON rewrite
    // -------------------------------------------------------------------------

    @Scheduled(zone = "UTC", cron = "${app.eol.denormalize-cron:0 0 4 * * SUN}")
    public void denormalizeEolStatus() {
        schedule("EOL_DENORMALIZE", denormalizeCron);
    }

    private int runDenormalizeAcrossTenants() {
        DenormalizeAccumulator accumulator = new DenormalizeAccumulator();
        forEachTenant(tenant -> accumulator.add(runDenormalize()));
        return accumulator.count();
    }

    private int runDenormalize() {
        LOG.info("Starting EOL status denormalization");
        int instancesUpdated = denormalizeSoftwareInstances();
        int componentsUpdated = denormalizeInventoryComponents();
        LOG.info("EOL denormalization — updated {} software_instances, {} inventory_components",
                instancesUpdated, componentsUpdated);
        enqueueLifecycleDeltasForTrackedComponents("eol-denormalize");
        softwareIdentitySummaryProjectionService.refreshAll();
        return instancesUpdated + componentsUpdated;
    }

    private static final class DenormalizeAccumulator {
        private int count;

        void add(int value) {
            count += value;
        }

        int count() {
            return count;
        }
    }

    public int refreshConfirmedMapping(String normalizedKey) {
        LOG.info("Refreshing EOL projection for confirmed mapping '{}'", normalizedKey);
        clearSoftwareInstanceProjection(normalizedKey);
        clearInventoryComponentProjection(normalizedKey);
        int instancesUpdated = denormalizeSoftwareInstances(normalizedKey);
        int componentsUpdated = denormalizeInventoryComponents(normalizedKey);
        enqueueLifecycleDeltasForNormalizedKey(normalizedKey, "eol-confirmed-mapping");
        softwareIdentitySummaryProjectionService.refreshByNormalizedKey(normalizedKey);
        return instancesUpdated + componentsUpdated;
    }

    @Scheduled(zone = "UTC", cron = "${app.eol.lifecycle-date-sweep-cron:0 15 0 * * *}")
    public void lifecycleDateSweep() {
        schedule("EOL_DATE_SWEEP", dateSweepCron);
    }

    int runLifecycleDateSweep() {
        LocalDate today = LocalDate.now(java.time.ZoneOffset.UTC);
        LocalDate eosThreshold = today.plusDays(EolConstants.NEAR_EOL_THRESHOLD_DAYS);
        List<java.util.UUID> candidateIds = inventoryComponentRepository.findLifecycleTransitionComponentIds(today, eosThreshold);
        if (candidateIds.isEmpty()) {
            return 0;
        }

        Instant now = Instant.now();
        List<com.prototype.vulnwatch.domain.InventoryComponent> components = inventoryComponentRepository.findAllById(candidateIds);
        List<com.prototype.vulnwatch.domain.InventoryComponent> changedComponents = new ArrayList<>();
        Map<java.util.UUID, List<java.util.UUID>> componentIdsByTenant = new LinkedHashMap<>();

        for (com.prototype.vulnwatch.domain.InventoryComponent component : components) {
            if (component.getTenant() == null || component.getTenant().getId() == null || component.getId() == null) {
                continue;
            }
            componentIdsByTenant
                    .computeIfAbsent(component.getTenant().getId(), ignored -> new ArrayList<>())
                    .add(component.getId());

            boolean changed = false;
            if (component.getEolDate() != null && !today.isBefore(component.getEolDate()) && !Boolean.TRUE.equals(component.getIsEol())) {
                component.setIsEol(true);
                changed = true;
            }
            if (changed || component.getEolCheckedAt() == null) {
                component.setEolCheckedAt(now);
                changed = true;
            }
            if (changed) {
                changedComponents.add(component);
            }
        }

        if (!changedComponents.isEmpty()) {
            inventoryComponentRepository.saveAll(changedComponents);
        }
        componentIdsByTenant.forEach((tenantId, componentIds) ->
                findingDeltaQueueService.enqueueLifecycleDeltas(tenantId, componentIds, "eol-date-sweep"));
        return candidateIds.size();
    }

    private void refreshOrgCveEolCounts() {
        try {
            List<Tenant> tenants = tenantRepository.findAllByOrderByCreatedAtAsc();
            for (Tenant tenant : tenants) {
                int updated = orgCveRecordService.refreshForTenant(tenant);
                LOG.info("EOL denormalization — refreshed org_cve_records for tenant {}: {} records updated",
                        tenant.getId(), updated);
            }
        } catch (Exception e) {
            LOG.warn("EOL denormalization — org_cve_records refresh failed: {}", e.getMessage());
        }
    }

    private void enqueueLifecycleDeltasForTrackedComponents(String sourceTag) {
        Map<java.util.UUID, List<java.util.UUID>> componentIdsByTenant = inventoryComponentRepository.findAllById(
                        inventoryComponentRepository.findActiveLifecycleTrackedIds()
                ).stream()
                .filter(component -> component.getTenant() != null && component.getTenant().getId() != null && component.getId() != null)
                .collect(Collectors.groupingBy(
                        component -> component.getTenant().getId(),
                        LinkedHashMap::new,
                        Collectors.mapping(component -> component.getId(), Collectors.toList())
                ));
        componentIdsByTenant.forEach((tenantId, componentIds) ->
                findingDeltaQueueService.enqueueLifecycleDeltas(tenantId, componentIds, sourceTag));
    }

    private void enqueueLifecycleDeltasForNormalizedKey(String normalizedKey, String sourceTag) {
        if (normalizedKey == null || normalizedKey.isBlank()) {
            return;
        }
        List<java.util.UUID> componentIds = inventoryComponentRepository.findActiveIdsBySoftwareIdentityNormalizedKey(
                normalizedKey.trim().toLowerCase(Locale.ROOT)
        );
        if (componentIds.isEmpty()) {
            return;
        }
        Map<java.util.UUID, List<java.util.UUID>> componentIdsByTenant = inventoryComponentRepository.findAllById(componentIds).stream()
                .filter(component -> component.getTenant() != null && component.getTenant().getId() != null && component.getId() != null)
                .collect(Collectors.groupingBy(
                        component -> component.getTenant().getId(),
                        LinkedHashMap::new,
                        Collectors.mapping(component -> component.getId(), Collectors.toList())
                ));
        componentIdsByTenant.forEach((tenantId, ids) ->
                findingDeltaQueueService.enqueueLifecycleDeltas(tenantId, ids, sourceTag));
    }

    // NOTE: software_instances rows are read by HostInventoryReadService (host asset detail view),
    // not by the CVE correlation path. This denormalization is therefore NOT dead code even though
    // inventory_components is the primary target for CVE/finding workflows.
    private int denormalizeSoftwareInstances() {
        return denormalizeSoftwareInstances(null);
    }

    private int denormalizeSoftwareInstances(String normalizedKey) {
        // Set-based update using DISTINCT ON to pick the best-matching cycle per instance.
        // DISTINCT ON (si2.id) ORDER BY si2.id, r.cycle DESC picks the highest cycle string,
        // which is the best prefix match for the installed version.
        String identityKeyExpr = normalizedKeyExpression("sid");
        String normalizedKeyFilter = normalizedKey == null ? "" : " AND " + identityKeyExpr + " = ?";
        String sql = """
                UPDATE software_instances si
                SET
                    eol_slug                 = bc.eol_slug,
                    eol_cycle                = bc.cycle,
                    eol_date                 = bc.eol_date,
                    is_eol                   = bc.is_eol,
                    eol_support_end_date     = bc.support_end_date,
                    support_phase            = bc.support_phase,
                    latest_supported_version = bc.latest_version,
                    eol_checked_at           = now()
                FROM (
                    SELECT DISTINCT ON (si2.id)
                        si2.id           AS si_id,
                        m.eol_slug,
                        r.cycle,
                        r.eol_date,
                        r.is_eol,
                        r.support_end_date,
                        r.support_phase,
                        r.latest_version
                    FROM software_instances si2
                    JOIN software_identities sid ON sid.id = si2.software_identity_id
                    JOIN software_eol_mapping m ON (
                            m.software_identity_id = si2.software_identity_id
                            OR (m.software_identity_id IS NULL AND m.normalized_key = %s)
                    )
                    JOIN eol_release r           ON r.product_slug = m.eol_slug
                                                AND (   si2.normalized_version LIKE r.cycle || '%'
                                                     OR si2.normalized_version = r.cycle)
                    WHERE m.eol_slug IS NOT NULL
                    %s
                    ORDER BY si2.id, r.cycle DESC
                ) bc
                WHERE si.id = bc.si_id
                """.formatted(identityKeyExpr, normalizedKeyFilter);
        try {
            return normalizedKey == null ? jdbcTemplate.update(sql) : jdbcTemplate.update(sql, normalizedKey);
        } catch (Exception e) {
            throw new IllegalStateException("software_instances EOL denormalization failed", e);
        }
    }

    private int denormalizeInventoryComponents() {
        return denormalizeInventoryComponents(null);
    }

    private int denormalizeInventoryComponents(String normalizedKey) {
        String identityKeyExpr = normalizedKeyExpression("sid");
        String normalizedKeyFilter = normalizedKey == null ? "" : " AND " + identityKeyExpr + " = ?";
        String sql = """
                UPDATE inventory_components ic
                SET
                    eol_slug                 = bc.eol_slug,
                    eol_cycle                = bc.cycle,
                    eol_date                 = bc.eol_date,
                    is_eol                   = bc.is_eol,
                    eol_support_end_date     = bc.support_end_date,
                    support_phase            = bc.support_phase,
                    latest_supported_version = bc.latest_version,
                    eol_checked_at           = now()
                FROM (
                    SELECT DISTINCT ON (ic2.id)
                        ic2.id           AS ic_id,
                        m.eol_slug,
                        r.cycle,
                        r.eol_date,
                        r.is_eol,
                        r.support_end_date,
                        r.support_phase,
                        r.latest_version
                    FROM inventory_components ic2
                    JOIN software_identities sid ON sid.id = ic2.software_identity_id
                    JOIN software_eol_mapping m ON (
                            m.software_identity_id = ic2.software_identity_id
                            OR (m.software_identity_id IS NULL AND m.normalized_key = %s)
                    )
                    JOIN eol_release r           ON r.product_slug = m.eol_slug
                                                AND (   ic2.normalized_version LIKE r.cycle || '%'
                                                     OR ic2.normalized_version = r.cycle)
                    WHERE m.eol_slug IS NOT NULL
                    %s
                    ORDER BY ic2.id, r.cycle DESC
                ) bc
                WHERE ic.id = bc.ic_id
                """.formatted(identityKeyExpr, normalizedKeyFilter);
        try {
            return normalizedKey == null ? jdbcTemplate.update(sql) : jdbcTemplate.update(sql, normalizedKey);
        } catch (Exception e) {
            throw new IllegalStateException("inventory_components EOL denormalization failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Support phase derivation
    // -------------------------------------------------------------------------

    /**
     * Derives a human-readable support phase label from EOL lifecycle flags.
     *
     * Phase precedence (highest to lowest):
     *  discontinued → eol → extended → lts → active
     *
     * "eol" is set when isEol=true OR isEoes=true (extended support also ended).
     * "extended" means active support ended (isEoas=true) but extended is still running.
     * "lts" means the cycle is long-term-supported and active support has not ended.
     */
    static String computeSupportPhase(boolean discontinued, boolean isEol,
                                       Boolean isEoas, Boolean isEoes, boolean lts) {
        if (discontinued)                         return "discontinued";
        if (isEol || Boolean.TRUE.equals(isEoes)) return "eol";
        if (Boolean.TRUE.equals(isEoas))          return "extended";
        return lts ? "lts" : "active";
    }

    // -------------------------------------------------------------------------
    // CPE / PURL parsing helpers for batch upsert
    // -------------------------------------------------------------------------

    /** Returns [vendor, product] from a CPE string, or [null, null] if absent or unparseable. */
    private String[] extractCpeComponents(String cpe) {
        if (cpe == null || cpe.isBlank()) return new String[]{null, null};
        try {
            CpeUtil.ParsedCpe parsed = CpeUtil.parse(cpe + ":*:*:*:*:*:*:*:*:*");
            return new String[]{
                    parsed.vendor().isBlank() ? null : parsed.vendor(),
                    parsed.product().isBlank() ? null : parsed.product()
            };
        } catch (Exception e) {
            return new String[]{null, null};
        }
    }

    /** Returns [type, namespace] from a PURL string, or [null, null] if unparseable. */
    private String[] extractPurlComponents(String purl) {
        if (purl == null || purl.isBlank()) return new String[]{null, null};
        try {
            String stripped = purl.startsWith("pkg:") ? purl.substring(4) : purl;
            int slashIdx = stripped.indexOf('/');
            if (slashIdx < 0) {
                return new String[]{stripped.split("@")[0].toLowerCase(Locale.ROOT), null};
            }
            String type = stripped.substring(0, slashIdx).toLowerCase(Locale.ROOT);
            String remainder = stripped.substring(slashIdx + 1);
            int nextSlash = remainder.indexOf('/');
            String namespace = nextSlash > 0
                    ? remainder.substring(0, nextSlash).toLowerCase(Locale.ROOT)
                    : remainder.split("@")[0].split("#")[0].toLowerCase(Locale.ROOT);
            return new String[]{type, namespace.isBlank() ? null : namespace};
        } catch (Exception e) {
            LOG.debug("Failed to parse PURL for catalog batch upsert: {}", purl);
            return new String[]{null, null};
        }
    }

    private int clearSoftwareInstanceProjection(String normalizedKey) {
        String identityKeyExpr = normalizedKeyExpression("sid");
        String sql = """
                UPDATE software_instances si
                SET
                    eol_slug                 = NULL,
                    eol_cycle                = NULL,
                    eol_date                 = NULL,
                    is_eol                   = NULL,
                    eol_support_end_date     = NULL,
                    support_phase            = NULL,
                    latest_supported_version = NULL,
                    eol_checked_at           = now()
                FROM software_identities sid
                WHERE si.software_identity_id = sid.id
                  AND %s = ?
                """.formatted(identityKeyExpr);
        return jdbcTemplate.update(sql, normalizedKey);
    }

    private int clearInventoryComponentProjection(String normalizedKey) {
        String identityKeyExpr = normalizedKeyExpression("sid");
        String sql = """
                UPDATE inventory_components ic
                SET
                    eol_slug                 = NULL,
                    eol_cycle                = NULL,
                    eol_date                 = NULL,
                    is_eol                   = NULL,
                    eol_support_end_date     = NULL,
                    support_phase            = NULL,
                    latest_supported_version = NULL,
                    eol_checked_at           = now()
                FROM software_identities sid
                WHERE ic.software_identity_id = sid.id
                  AND %s = ?
                """.formatted(identityKeyExpr);
        return jdbcTemplate.update(sql, normalizedKey);
    }

    private String normalizedKeyExpression(String alias) {
        return "lower(coalesce(" + alias + ".vendor, '')) || '::' || lower(coalesce(" + alias + ".product, ''))";
    }
}
