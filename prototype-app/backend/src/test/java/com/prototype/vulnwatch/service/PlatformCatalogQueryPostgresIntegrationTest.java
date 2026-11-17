package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityIntelObservation;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {"app.runtime.role=api", "app.correlation.backfill-targets-on-startup=false"})
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class PlatformCatalogQueryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("platform_catalog_query");

    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired VulnerabilityRepository vulnerabilities;
    @Autowired VulnerabilityIntelObservationRepository observations;
    @Autowired PlatformVulnRepoService catalog;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.prototype.vulnwatch.controller.PlatformVulnRepoController controller;
    @Autowired com.prototype.vulnwatch.controller.PlatformIntelligenceProgressController progressController;

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void nvdScopeInventoryIsBoundedAndCursorOrdered() {
        var runId = java.util.UUID.randomUUID();
        jdbc.update("""
                insert into platform.sync_runs(id,records_failed,records_fetched,records_inserted,records_updated,
                  run_scope,started_at,status,sync_type,tenant_id)
                values (?,0,0,0,0,'PLATFORM_VULNERABILITY',now(),'completed','NVD',null)
                """, runId);
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                select ?, 'nvd', 'nvd:' || lpad(to_hex(n),32,'0'),
                       '2026-01-01T00:00:00Z'::timestamptz + n * interval '1 day',
                       '2026-01-02T00:00:00Z'::timestamptz + n * interval '1 day', 0, now()
                from generate_series(1,51) n
                """, runId);
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                values (?,'nvd','nvd:legacy','2026-05-01T00:00:00Z'::timestamptz,
                        '2026-05-02T00:00:00Z'::timestamptz,0,now())
                """, runId);
        var first = progressController.nvdObservedScopes(null);
        assertEquals(50, first.items().size());
        org.junit.jupiter.api.Assertions.assertTrue(first.hasMore());
        assertEquals(first.items().get(49).feedKey(), first.nextAfterFeedKey());
        assertEquals(1, first.items().get(0).observedWindowCount());
        assertEquals(java.time.Instant.parse("2026-01-02T00:00:00Z"),
                first.items().get(0).firstObservedIntervalStart());
        var second = progressController.nvdObservedScopes(first.nextAfterFeedKey());
        assertEquals(1, second.items().size());
        org.junit.jupiter.api.Assertions.assertFalse(second.hasMore());
        org.junit.jupiter.api.Assertions.assertTrue(
                second.items().get(0).feedKey().compareTo(first.nextAfterFeedKey()) > 0);
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> progressController.nvdObservedScopes("nvd:not-a-hash"));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotListNvdObservedScopes() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> progressController.nvdObservedScopes(null));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void nvdGapDiagnosticMergesWindowsAndIsolatesFilterScope() {
        var runId = java.util.UUID.randomUUID();
        jdbc.update("""
                insert into platform.sync_runs(id,records_failed,records_fetched,records_inserted,records_updated,
                  run_scope,started_at,status,sync_type,tenant_id)
                values (?,0,0,0,0,'PLATFORM_VULNERABILITY',now(),'completed','NVD',null)
                """, runId);
        String scope = "nvd:00000000000000000000000000000001";
        String otherScope = "nvd:00000000000000000000000000000002";
        var base = java.time.Instant.parse("2026-01-01T00:00:00Z");
        for (int[] window : new int[][] {{1, 3}, {2, 4}, {4, 5}, {7, 9}}) {
            jdbc.update("""
                    insert into platform.feed_coverage_observations
                      (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                    values (?,'nvd',?,?,?,0,now())
                    """, runId, scope, java.sql.Timestamp.from(base.plusSeconds(window[0] * 3600L)),
                    java.sql.Timestamp.from(base.plusSeconds(window[1] * 3600L)));
        }
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                values (?,'nvd',?,?,?,0,now())
                """, runId, otherScope, java.sql.Timestamp.from(base.plusSeconds(5 * 3600L)),
                java.sql.Timestamp.from(base.plusSeconds(7 * 3600L)));
        var result = progressController.nvdObservedGaps(scope, base, base.plusSeconds(10 * 3600L));
        assertEquals(4, result.observedWindowCount());
        assertEquals("UNKNOWN", result.historicalCoverageStatus());
        assertEquals(List.of(
                new com.prototype.vulnwatch.dto.NvdObservedGapsResponse.Interval(base, base.plusSeconds(3600)),
                new com.prototype.vulnwatch.dto.NvdObservedGapsResponse.Interval(
                        base.plusSeconds(5 * 3600L), base.plusSeconds(7 * 3600L)),
                new com.prototype.vulnwatch.dto.NvdObservedGapsResponse.Interval(
                        base.plusSeconds(9 * 3600L), base.plusSeconds(10 * 3600L))),
                result.unobservedIntervals());
        assertEquals(1, progressController.nvdObservedGaps(otherScope, base,
                base.plusSeconds(10 * 3600L)).observedWindowCount());
        assertEquals(1, progressController.nvdObservedGaps("nvd:00000000000000000000000000000003",
                base, base.plusSeconds(10 * 3600L)).unobservedIntervals().size());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void completedLegacyObservationWithoutManifestDoesNotHideGap() {
        var runId = java.util.UUID.randomUUID();
        var from = java.time.Instant.parse("2025-01-01T00:00:00Z");
        var to = from.plusSeconds(86400);
        String scope = "nvd:00000000000000000000000000000006";
        jdbc.update("""
                insert into platform.sync_runs(id,records_failed,records_fetched,records_inserted,records_updated,
                  run_scope,started_at,status,sync_type,tenant_id)
                values (?,0,0,0,0,'PLATFORM_VULNERABILITY',now(),'completed','NVD',null)
                """, runId);
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records)
                values (?,'nvd',?,?,?,0)
                """, runId, scope, java.sql.Timestamp.from(from), java.sql.Timestamp.from(to));
        var result = progressController.nvdObservedGaps(scope, from, to);
        assertEquals(0, result.observedWindowCount());
        assertEquals(List.of(new com.prototype.vulnwatch.dto.NvdObservedGapsResponse.Interval(from, to)),
                result.unobservedIntervals());
        org.junit.jupiter.api.Assertions.assertTrue(progressController.nvdObservedScopes(null).items().stream()
                .noneMatch(item -> item.feedKey().equals(scope)));
        var nvd = progressController.get().sources().stream()
                .filter(source -> source.source().equals("NVD")).findFirst().orElseThrow();
        assertEquals(0, nvd.observedWindowCount());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void nvdGapDiagnosticRejectsInvalidAndOverlargeQueries() {
        var from = java.time.Instant.parse("2026-01-01T00:00:00Z");
        var scope = "nvd:00000000000000000000000000000004";
        var bad = org.springframework.web.server.ResponseStatusException.class;
        org.junit.jupiter.api.Assertions.assertThrows(bad,
                () -> progressController.nvdObservedGaps("nvd:other", from, from.plusSeconds(3600)));
        org.junit.jupiter.api.Assertions.assertThrows(bad,
                () -> progressController.nvdObservedGaps(scope, from, from));
        org.junit.jupiter.api.Assertions.assertThrows(bad,
                () -> progressController.nvdObservedGaps(scope, from, from.plusSeconds(121 * 86400L)));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void nvdGapDiagnosticFailsClosedWhenWindowCapIsExceeded() {
        var runId = java.util.UUID.randomUUID();
        var from = java.time.Instant.parse("2026-01-01T00:00:00Z");
        var scope = "nvd:00000000000000000000000000000005";
        jdbc.update("""
                insert into platform.sync_runs(id,records_failed,records_fetched,records_inserted,records_updated,
                  run_scope,started_at,status,sync_type,tenant_id)
                values (?,0,0,0,0,'PLATFORM_VULNERABILITY',now(),'completed','NVD',null)
                """, runId);
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                select ?, 'nvd', ?, ?::timestamptz + n * interval '2 minutes',
                       ?::timestamptz + n * interval '2 minutes' + interval '1 minute', 0, now()
                from generate_series(0,1000) n
                """, runId, scope, java.sql.Timestamp.from(from), java.sql.Timestamp.from(from));
        var failure = org.junit.jupiter.api.Assertions.assertThrows(
                org.springframework.web.server.ResponseStatusException.class,
                () -> progressController.nvdObservedGaps(scope, from, from.plusSeconds(3 * 86400L)));
        assertEquals(org.springframework.http.HttpStatus.CONFLICT, failure.getStatusCode());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotReadNvdObservedGaps() {
        var from = java.time.Instant.parse("2026-01-01T00:00:00Z");
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> progressController.nvdObservedGaps("nvd:00000000000000000000000000000004",
                        from, from.plusSeconds(3600)));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void detailExposesObservationProvenanceWithoutRawPayload() {
        String externalId = ("CVE-2098-PROV-" + java.util.UUID.randomUUID().toString().substring(0, 8))
                .toUpperCase(java.util.Locale.ROOT);
        var vulnerability = record(externalId, false, "HIGH", false);
        var observation = new VulnerabilityIntelObservation();
        observation.setVulnerability(vulnerability);
        observation.setSourceSystem("nvd");
        observation.setSourceRecordId("nvd-" + java.util.UUID.randomUUID());
        observation.setDescription("Source-side fixture description");
        observation.setPayloadHash("fixture-fingerprint");
        observation.setCvssScore(8.1);
        observation.setCvssVersion("3.1");
        observation.setRawPayload("private fixture payload");
        observation.setObservedAt(java.time.Instant.parse("2026-01-01T00:00:00Z"));
        observation.setLastSeenAt(java.time.Instant.parse("2026-01-02T00:00:00Z"));
        observations.saveAndFlush(observation);

        var detail = TenantContext.runAsPlatform(() -> controller.getIntelDetail(externalId, true));
        assertEquals(1, detail.observations().size());
        var evidence = detail.observations().get(0);
        assertEquals("fixture-fingerprint", evidence.payloadHash());
        assertEquals("3.1", evidence.cvssVersion());
        assertEquals("2026-01-01T00:00:00Z", evidence.observedAt());
        assertEquals("2026-01-02T00:00:00Z", evidence.lastSeenAt());
        org.junit.jupiter.api.Assertions.assertFalse(detail.toString().contains("private fixture payload"));

        var summary = TenantContext.runAsPlatform(() -> controller.getIntelDetail(externalId, false));
        assertEquals(List.of(), summary.observations());
        assertEquals(detail.fullDescription(), summary.fullDescription());
        assertEquals("Source-side fixture description", summary.fullDescription());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void observationCursorIsBoundedAndDoesNotExposeRawPayload() {
        var record = record(("CVE-2098-OBSPAGE-" + java.util.UUID.randomUUID().toString().substring(0, 8))
                        .toUpperCase(java.util.Locale.ROOT),
                false, "HIGH", false);
        for (int i = 0; i < 3; i++) {
            var observation = evidence(record, "nvd", "page-evidence-" + i + java.util.UUID.randomUUID());
            observation.setRawPayload("private page payload");
            observation.setPayloadHash("fingerprint-" + i);
            observation.setCvssVersion("3.1");
            observations.saveAndFlush(observation);
        }
        evidence(record("CVE-2098-OBSPAGE-OTHER", false, "HIGH", false), "nvd", "other-record");
        var first = TenantContext.runAsPlatform(() -> controller.getIntelObservations(record.getExternalId(), 2, null));
        assertEquals(2, first.items().size());
        org.junit.jupiter.api.Assertions.assertTrue(first.hasMore());
        var second = TenantContext.runAsPlatform(() -> controller.getIntelObservations(
                record.getExternalId(), 2, first.nextAfterId()));
        assertEquals(1, second.items().size());
        org.junit.jupiter.api.Assertions.assertFalse(second.hasMore());
        org.junit.jupiter.api.Assertions.assertNotEquals(first.items().get(0).id(), second.items().get(0).id());
        org.junit.jupiter.api.Assertions.assertFalse((first.toString() + second).contains("private page payload"));
        assertEquals("fingerprint-", first.items().get(0).observation().payloadHash().substring(0, 12));
        assertEquals("3.1", first.items().get(0).observation().cvssVersion());
        assertEquals("3.1", second.items().get(0).observation().cvssVersion());
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> controller.getIntelObservations(record.getExternalId(), 101, null));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotReadPlatformObservations() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> controller.getIntelObservations("CVE-2098-1001", 25, null));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void progressSeparatesFetchedRecordsFromPublicationAndTenantDelivery() {
        var runId = java.util.UUID.randomUUID();
        jdbc.update("""
                insert into platform.sync_runs(id,records_failed,records_fetched,records_inserted,records_updated,
                  run_scope,started_at,status,sync_type,tenant_id)
                values (?,2,7,3,4,'PLATFORM_VULNERABILITY',now(),'completed','NVD',null)
                """, runId);
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records,ids_recorded_at)
                values (?,'nvd','nvd:fixture',now()-interval '1 hour',now(),7,now())
                """, runId);
        var inventoryBefore = progressController.get().catalogInventory();
        var progressRecord = record("CVE-2098-PROGRESS-" + java.util.UUID.randomUUID(), false, "HIGH", false);
        evidence(progressRecord, "nvd", "progress-observation-" + java.util.UUID.randomUUID());
        var status = progressController.get();
        assertEquals(runId, status.acquisition().runId());
        assertEquals(7, status.acquisition().fetchedRecords());
        assertEquals(2, status.acquisition().failedRecords());
        assertEquals(inventoryBefore.canonicalRecords() + 1, status.catalogInventory().canonicalRecords());
        assertEquals(inventoryBefore.activeCanonicalRecords() + 1, status.catalogInventory().activeCanonicalRecords());
        assertEquals(inventoryBefore.withdrawnCanonicalRecords(), status.catalogInventory().withdrawnCanonicalRecords());
        assertEquals(inventoryBefore.sourceObservationRows() + 1, status.catalogInventory().sourceObservationRows());
        assertEquals("NOT_SEPARATELY_TRACKED", status.assetEvaluationStatus());
        var nvd = status.sources().stream().filter(source -> source.source().equals("NVD")).findFirst().orElseThrow();
        assertEquals(runId, nvd.latestRunId());
        assertEquals(7, nvd.latestFetchedRecords());
        assertEquals("UNKNOWN", nvd.historicalCoverageStatus());
        assertEquals("VULNERABILITY", nvd.evidenceRole());
        assertEquals("FILTERED_PAGINATED_API", nvd.acquisitionScope());
        assertEquals(1, nvd.observedWindowCount());
        assertEquals(1, nvd.observedFilterScopeCount());
        org.junit.jupiter.api.Assertions.assertNotNull(nvd.latestObservedIntervalEnd());
        var euvd = status.sources().stream().filter(source -> source.source().equals("EUVD")).findFirst().orElseThrow();
        assertNull(euvd.latestRunId());
        assertEquals("UNKNOWN", euvd.historicalCoverageStatus());
        assertEquals(0, euvd.observedWindowCount());
        var osv = status.sources().stream().filter(source -> source.source().equals("OSV")).findFirst().orElseThrow();
        assertEquals("INVENTORY_SCOPED_QUERY", osv.acquisitionScope());
        org.junit.jupiter.api.Assertions.assertFalse(osv.tenantPolicySelectable());
        assertEquals(status.tenantDelivery().activeTenants(), status.tenantDelivery().currentTenants()
                + status.tenantDelivery().updatingTenants() + status.tenantDelivery().failedTenants());
        org.junit.jupiter.api.Assertions.assertTrue(status.publication().activeGeneration() >= 0);
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotReadPlatformProgress() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> progressController.get());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void progressCountsOnlyPartialTenantScansWithInvalidatedCheckpoints() {
        var tenant = jdbc.queryForObject("select id from platform.tenants where status='ACTIVE' order by id limit 1",
                java.util.UUID.class);
        long generation = jdbc.queryForObject("select generation from platform.intelligence_active_state where singleton=true",
                Long.class);
        jdbc.update("""
                update platform.tenant_intelligence_processing
                set status='PENDING',required_revision=2,evaluating_revision=1,
                    evaluating_generation=?,after_component_id=? where tenant_id=?
                """, generation, java.util.UUID.randomUUID(), tenant);
        assertEquals(1, progressController.get().tenantDelivery().staleCheckpoints());
        jdbc.update("update platform.tenant_intelligence_processing set evaluating_revision=2 where tenant_id=?", tenant);
        assertEquals(0, progressController.get().tenantDelivery().staleCheckpoints());
        jdbc.update("update platform.tenant_intelligence_processing set evaluating_generation=? where tenant_id=?",
                generation + 1, tenant);
        assertEquals(1, progressController.get().tenantDelivery().staleCheckpoints());
        jdbc.update("update platform.tenant_intelligence_processing set after_component_id=null where tenant_id=?", tenant);
        assertEquals(0, progressController.get().tenantDelivery().staleCheckpoints());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotReadPlatformRecords() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> controller.listCentralRecords(0, 25, null, null, null, null,
                        com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.ALL,
                        com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void platformOwnerCanReadCentralRecords() {
        record("CVE-2098-6001", false, "HIGH", false);
        assertEquals(1, controller.listCentralRecords(0, 25, "2098-6001", null, null, null,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.CVE,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE).totalItems());
    }

    @Test void centralRecordsSeparateKindAndWithdrawalWithoutTenantTables() {
        record("CVE-2098-4001", false, "HIGH", true);
        record("GHSA-2098-4002", false, "MEDIUM", false);
        record("CVE-2098-4003", true, "HIGH", true);
        jdbc.execute("set local search_path to pg_catalog");
        var all = catalog.listCentralRecords(0, 25, "2098-400", null, null, null,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.ALL,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ALL);
        assertEquals(3, all.totalItems());
        var other = catalog.listCentralRecords(0, 25, "2098-400", null, null, null,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.OTHER,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE);
        assertEquals(1, other.totalItems());
        assertEquals("GHSA-2098-4002", other.items().get(0).externalId());
        var withdrawn = catalog.listCentralRecords(0, 25, "2098-400", true, "high", null,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.CVE,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.WITHDRAWN);
        assertEquals(1, withdrawn.totalItems());
        assertEquals("CVE-2098-4003", withdrawn.items().get(0).externalId());
        assertEquals(com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.WITHDRAWN,
                withdrawn.items().get(0).status());
    }

    @Test void centralRecordsSourceFilterDeduplicatesAndBoundsPages() {
        var first = record("CVE-2098-5001", false, "HIGH", true);
        evidence(first, "japan-vulndb", "jvn-5001");
        evidence(first, "japan-vulndb", "jvn-5002");
        evidence(record("GHSA-2098-5002", false, "HIGH", true), "jvn", "jvn-5003");
        var result = catalog.listCentralRecords(-1, 1, "2098-500", true, "HIGH", "JVNDB",
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.ALL,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE);
        assertEquals(2, result.totalItems());
        assertEquals(2, result.totalPages());
        assertEquals(0, result.page());
        assertEquals(1, result.items().size());
        assertEquals("CVE-2098-5001", result.items().get(0).externalId());
        assertEquals(List.of("jvn"), result.items().get(0).sourceSystems());
    }

    @Test void cursorPagesUseStableKeysetWithoutCountOrTenantSchema() {
        var first = record("CVE-2098-CURSOR-01", false, "HIGH", true);
        var second = record("CVE-2098-CURSOR-02", false, "HIGH", true);
        var third = record("CVE-2098-CURSOR-03", false, "HIGH", true);
        for (var record : List.of(first, second, third)) evidence(record, "nvd", record.getExternalId());
        evidence(second, "nvd", "duplicate-source-observation");
        jdbc.execute("set local search_path to pg_catalog");
        var kind = com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.CVE;
        var status = com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE;
        var page1 = catalog.scanCentralRecords(1, "2098-CURSOR", true, "HIGH", "nvd", kind, status, null, null);
        assertEquals(List.of(first.getId()), page1.items().stream().map(item -> item.id()).toList());
        assertEquals(true, page1.hasMore());
        var page2 = catalog.scanCentralRecords(1, "2098-CURSOR", true, "HIGH", "nvd", kind, status,
                page1.nextAfterExternalId(), page1.nextAfterId());
        assertEquals(List.of(second.getId()), page2.items().stream().map(item -> item.id()).toList());
        assertEquals(List.of("nvd"), page2.items().get(0).sourceSystems());
        var page3 = catalog.scanCentralRecords(1, "2098-CURSOR", true, "HIGH", "nvd", kind, status,
                page2.nextAfterExternalId(), page2.nextAfterId());
        assertEquals(List.of(third.getId()), page3.items().stream().map(item -> item.id()).toList());
        assertEquals(false, page3.hasMore());
        assertNull(page3.nextAfterId());
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> catalog.scanCentralRecords(1, "2098-CURSOR", true, "HIGH", "nvd", kind, status, "CVE-2098-CURSOR-01", null));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdministratorCannotUseCursor() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> controller.scanCentralRecords(25, null, null, null, null,
                        com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.ALL,
                        com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE, null, null));
    }

    @Test void centralListWorksWithNoTenantSchemaInSearchPath() {
        var vulnerability = record("CVE-2098-1001", false, "HIGH", true);
        evidence(vulnerability, "nvd", "nvd-a");
        jdbc.execute("set local search_path to pg_catalog");

        var result = catalog.listVulnerabilities(0, 25, "2098-1001", true, "high", "nvd");

        assertEquals(1, result.totalItems());
        assertEquals("UNKNOWN", result.items().get(0).impactState());
        assertNull(result.items().get(0).lastEvaluatedAt());
    }

    @Test void provenanceExistsDoesNotDuplicateRowsAndWithdrawnRecordsStayHidden() {
        var first = record("CVE-2098-2001", false, "HIGH", true);
        evidence(first, "ghsa", "ghsa-a");
        evidence(first, "ghsa", "ghsa-b");
        evidence(record("CVE-2098-2002", false, "HIGH", true), "ghsa", "ghsa-c");
        evidence(record("CVE-2098-2003", true, "HIGH", true), "ghsa", "ghsa-d");
        evidence(record("CVE-2098-2004", false, "LOW", false), "nvd", "nvd-b");

        var page = vulnerabilities.searchPlatformCatalog("CVE-", "2098-200", "HIGH", true, "ghsa", PageRequest.of(0, 1));
        assertEquals(2, page.getTotalElements());
        assertEquals("CVE-2098-2001", page.getContent().get(0).getExternalId());
        var next = vulnerabilities.searchPlatformCatalog("CVE-", "2098-200", "HIGH", true, "ghsa", PageRequest.of(1, 1));
        assertEquals("CVE-2098-2002", next.getContent().get(0).getExternalId());
        assertEquals(0, vulnerabilities.searchPlatformCatalog("CVE-", "2098-200", "", null, "missing", PageRequest.of(0, 25)).getTotalElements());
        assertEquals(3, vulnerabilities.searchPlatformCatalog("CVE-", "2098-200", "", null, "", PageRequest.of(0, 25)).getTotalElements());
    }

    @Test void japaneseSourceAliasesResolveToTheSamePublishedEvidence() {
        evidence(record("CVE-2098-3001", false, "MEDIUM", false), "japan-vulndb", "jvn-a");
        evidence(record("CVE-2098-3002", false, "MEDIUM", false), "jvndb", "jvn-b");
        for (String source : List.of("jvn", "JVNDB", " Japan-VulnDB ")) {
            assertEquals(2, catalog.listVulnerabilities(0, 25, "2098-300", null, null, source).totalItems());
        }
        var rows = catalog.listCentralRecords(0, 25, "2098-300", null, null, "jvn",
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Kind.ALL,
                com.prototype.vulnwatch.dto.CentralCatalogPageResponse.Status.ACTIVE);
        assertEquals(2, rows.totalItems());
        assertEquals(List.of("jvn"), rows.items().get(1).sourceSystems());
    }

    private Vulnerability record(String externalId, boolean withdrawn, String severity, boolean kev) {
        var record = new Vulnerability();
        record.setExternalId(externalId);
        record.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
        record.setTitle("Platform catalog regression");
        record.setSeverity(severity);
        record.setInKev(kev);
        record.setIntelligenceWithdrawn(withdrawn);
        return vulnerabilities.saveAndFlush(record);
    }

    private VulnerabilityIntelObservation evidence(Vulnerability vulnerability, String source, String externalId) {
        var observation = new VulnerabilityIntelObservation();
        observation.setVulnerability(vulnerability);
        observation.setSourceSystem(source);
        observation.setSourceRecordId(externalId);
        return observations.saveAndFlush(observation);
    }
}
