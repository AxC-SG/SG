package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.*;
import com.prototype.vulnwatch.dto.CatalogPolicyPreview.*;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {"app.runtime.role=api", "app.correlation.backfill-targets-on-startup=false"})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CatalogPolicyPreviewPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("catalog_policy_preview");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url); registry.add("DB_USERNAME", DATABASE::username); registry.add("DB_PASSWORD", DATABASE::password);
    }
    @Autowired CatalogPolicyPreviewService preview;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaExecutionService schemas;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityRepository vulnerabilities;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository observations;
    @Autowired com.prototype.vulnwatch.controller.CatalogPolicyPreviewController controller;
    @Autowired CatalogLegacyCompatibilityService legacyCompatibility;
    @Autowired VulnerabilitySourceFilterConfigService sourceConfig;
    @Autowired TenantWorkRunner tenantWork;

    @Test void previewReducesManyAllowedObservationsToDeterministicFactWitnesses() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            var record = new com.prototype.vulnwatch.domain.Vulnerability();
            record.setExternalId("CVE-2099-REDUCED-EVIDENCE"); record.setTitle("Reduced evidence fixture");
            record.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            record = vulnerabilities.saveAndFlush(record);
            UUID id = record.getId();
            var first = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            first.setVulnerability(record); first.setSourceSystem("nvd"); first.setSourceRecordId("reduced-nvd-first");
            first.setCvssScore(8.0); first = observations.saveAndFlush(first);
            var second = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            second.setVulnerability(record); second.setSourceSystem("nvd"); second.setSourceRecordId("reduced-nvd-second");
            second.setCvssScore(8.0); second = observations.saveAndFlush(second);
            UUID cvssWitness = Comparator.comparing(UUID::toString).compare(first.getId(), second.getId()) < 0
                    ? first.getId() : second.getId();
            var epss = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            epss.setVulnerability(record); epss.setSourceSystem("epss"); epss.setSourceRecordId("reduced-epss");
            epss.setEpssScore(0.9); observations.saveAndFlush(epss);
            var kev = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            kev.setVulnerability(record); kev.setSourceSystem("kev"); kev.setSourceRecordId("reduced-kev");
            kev.setInKev(true); observations.saveAndFlush(kev);
            var lowerScores = new ArrayList<com.prototype.vulnwatch.domain.VulnerabilityIntelObservation>();
            for (int index = 0; index < 140; index++) {
                var lower = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
                lower.setVulnerability(record); lower.setSourceSystem("nvd");
                lower.setSourceRecordId("reduced-nvd-lower-" + index); lower.setCvssScore(2.0);
                lowerScores.add(lower);
            }
            observations.saveAllAndFlush(lowerScores); // Exercise more rows than one JDBC observation fetch.
            var rule = new Rule(Op.ALL, null, null, null, List.of(
                    new Rule(Op.GTE, Field.CVSS, 8.0, null, null),
                    new Rule(Op.GTE, Field.EPSS, 0.8, null, null),
                    new Rule(Op.EQ, Field.CISA_KEV, null, true, null)));
            var policy = new CatalogPolicy(1, Set.of("nvd", "epss", "kev"), false,
                    ScoreResolution.MAX_ALLOWED_OBSERVATION_V1, rule);
            var match = schemas.run(tenant, () -> preview.preview(new Request(policy, null, null))).matches().stream()
                    .filter(item -> item.id().equals(id)).findFirst().orElseThrow();
            assertEquals(8.0, match.facts().cvss());
            assertEquals(0.9, match.facts().epss());
            assertEquals(true, match.facts().cisaKev());
            assertEquals(cvssWitness, match.attribution().cvss().observationId());
            assertEquals("reduced-epss", match.attribution().epss().sourceRecordId());
            assertEquals("reduced-kev", match.attribution().cisaKev().sourceRecordId());
            assertEquals("reduced-epss", match.attribution().sourcePresence().sourceRecordId());
        });
    }

    @Test void previewAppliesLatestOverrideAndRejectsStaleContinuation() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            var record = new com.prototype.vulnwatch.domain.Vulnerability();
            record.setExternalId("CVE-2026-OVERRIDE-PREVIEW"); record.setTitle("Override preview"); record.setSeverity("HIGH");
            record.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            record = vulnerabilities.saveAndFlush(record);
            UUID id = record.getId();
            var observation = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            observation.setVulnerability(record); observation.setSourceSystem("nvd"); observation.setSourceRecordId("override-preview");
            observation.setCvssScore(9.0); observations.saveAndFlush(observation);
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 8.0, null, null));
            var initial = schemas.run(tenant, () -> preview.preview(new Request(policy, null, null)));
            assertTrue(initial.matches().stream().anyMatch(m -> m.id().equals(id)));
            tenantWork.runScoped(tenant, () -> jdbc.update("""
                    insert into intelligence_catalog_overrides(tenant_id,vulnerability_id,revision,operation,reason)
                    values(?,?,1,'EXCLUDE','test')
                    """, tenant.getId(), id));
            var excluded = schemas.run(tenant, () -> preview.preview(new Request(policy, null, null)));
            assertFalse(excluded.matches().stream().anyMatch(m -> m.id().equals(id)));
            assertEquals(409, assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> preview.preview(new Request(policy, id, initial.generation(), initial.overrideState(), initial.sourceState())))).getStatusCode().value());
            // The latest expired override must fall back to policy, not the older exclusion.
            tenantWork.runScoped(tenant, () -> jdbc.update("""
                    insert into intelligence_catalog_overrides(tenant_id,vulnerability_id,revision,operation,reason,created_at,expires_at)
                    values(?,?,2,'EXCLUDE','expired',now()-interval '2 days',now()-interval '1 day')
                    """, tenant.getId(), id));
            assertTrue(schemas.run(tenant, () -> preview.preview(new Request(policy, null, null))).matches().stream().anyMatch(m -> m.id().equals(id)));
            var strict = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 10.0, null, null));
            tenantWork.runScoped(tenant, () -> jdbc.update("""
                    insert into intelligence_catalog_overrides(tenant_id,vulnerability_id,revision,operation,reason)
                    values(?,?,3,'INCLUDE','test')
                    """, tenant.getId(), id));
            assertTrue(schemas.run(tenant, () -> preview.preview(new Request(strict, null, null))).matches().stream().anyMatch(m -> m.id().equals(id)));
            tenantWork.runScoped(tenant, () -> jdbc.update("""
                    insert into intelligence_catalog_overrides(tenant_id,vulnerability_id,revision,operation,reason)
                    values(?,?,4,'RESTORE','test')
                    """, tenant.getId(), id));
            assertFalse(schemas.run(tenant, () -> preview.preview(new Request(strict, null, null))).matches().stream().anyMatch(m -> m.id().equals(id)));
            jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?", id);
        });
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void previewUsesAllowedEvidencePublicationYearAndGenerationWithoutWrites() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            var record = new com.prototype.vulnwatch.domain.Vulnerability();
            record.setExternalId("CVE-1999-99001"); record.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            record.setTitle("Preview"); record.setSeverity("HIGH");
            record = vulnerabilities.saveAndFlush(record);
            UUID id = record.getId();
            for (String source : List.of("nvd", "ghsa")) {
                var observation = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
                observation.setVulnerability(record); observation.setSourceSystem(source); observation.setSourceRecordId("preview-" + source);
                observation.setCvssScore(source.equals("nvd") ? 6.0 : 9.0);
                observation.setCvssVersion(source.equals("nvd") ? "3.1" : null);
                observation.setPayloadHash(source + "-fingerprint");
                observation.setRawPayload("private fixture source payload");
                observation.setPublishedAt(java.time.Instant.parse(source.equals("nvd") ? "2021-01-01T00:00:00Z" : "2010-01-01T00:00:00Z"));
                observations.saveAndFlush(observation);
            }
            var rule = new Rule(Op.ALL, null, null, null, List.of(
                    new Rule(Op.GTE, Field.CVSS, 6.0, null, null), new Rule(Op.GTE, Field.PUBLICATION_YEAR, 2020.0, null, null)));
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1, rule);
            var response = schemas.run(tenant, () -> controller.preview(new Request(policy, null, null)));
            assertEquals(1, response.matched());
            assertEquals(2021, response.matches().get(0).facts().publicationYear());
            assertEquals(6.0, response.matches().get(0).facts().cvss());
            var attribution = response.matches().get(0).attribution();
            assertEquals("nvd", attribution.publicationYear().sourceSystem());
            assertEquals("preview-nvd", attribution.publicationYear().sourceRecordId());
            assertEquals("preview-nvd", attribution.cvss().sourceRecordId());
            assertEquals("nvd-fingerprint", attribution.cvss().payloadHash());
            assertEquals("3.1", attribution.cvss().cvssVersion());
            assertNull(attribution.epss());
            assertNull(attribution.cisaKev());
            assertEquals("preview-nvd", attribution.sourcePresence().sourceRecordId());
            assertFalse(response.toString().contains("private fixture source payload"));
            var later = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            later.setVulnerability(record);
            later.setSourceSystem("nvd");
            later.setSourceRecordId("preview-nvd-later");
            later.setPublishedAt(java.time.Instant.parse("2025-01-01T00:00:00Z"));
            later.setCvssScore(9.0);
            later.setCvssVersion("4.0");
            later.setPayloadHash("later-fingerprint");
            observations.saveAndFlush(later);
            var unversioned = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            unversioned.setVulnerability(record);
            unversioned.setSourceSystem("nvd");
            unversioned.setSourceRecordId("preview-nvd-unversioned");
            unversioned.setCvssScore(10.0);
            observations.saveAndFlush(unversioned);
            var mixedFacts = schemas.run(tenant, () -> controller.preview(new Request(policy, null, null)));
            var mixed = mixedFacts.matches().stream().filter(match -> match.id().equals(id)).findFirst().orElseThrow();
            assertEquals(2021, mixed.facts().publicationYear());
            assertEquals(10.0, mixed.facts().cvss());
            assertEquals("preview-nvd", mixed.attribution().publicationYear().sourceRecordId());
            assertEquals("preview-nvd-unversioned", mixed.attribution().cvss().sourceRecordId());
            var v31 = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_CVSS_V3_1, rule);
            var v31Match = schemas.run(tenant, () -> controller.preview(new Request(v31, null, null))).matches().stream()
                    .filter(match -> match.id().equals(id)).findFirst().orElseThrow();
            assertEquals(6.0, v31Match.facts().cvss());
            assertEquals("3.1", v31Match.attribution().cvss().cvssVersion());
            var v40 = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_CVSS_V4_0, rule);
            var v40Match = schemas.run(tenant, () -> controller.preview(new Request(v40, null, null))).matches().stream()
                    .filter(match -> match.id().equals(id)).findFirst().orElseThrow();
            assertEquals(9.0, v40Match.facts().cvss());
            assertEquals("4.0", v40Match.attribution().cvss().cvssVersion());
            assertNull(response.matches().get(0).facts().cisaKev());
            assertTrue(response.complete());
            assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> preview.preview(new Request(policy, id, response.generation() + 1))));
            assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> preview.preview(new Request(policy, id, null))));
            jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?", id);
            assertEquals(0, schemas.run(tenant, () -> preview.preview(new Request(policy, null, null))).matched());
        });
    }

    @Test void batchesUseKeysetContinuationAndRejectDisabledSources() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 6.0, null, null));
            // Fixed upper-range UUIDs make this test independent of other fixture ordering.
            for (int i = 1; i <= 101; i++) {
                UUID id = UUID.fromString("ffffffff-ffff-ffff-ffff-" + String.format("%012d", i));
                jdbc.update("""
                        insert into platform.vulnerabilities(id,external_id,source,title,severity,in_kev,created_at,updated_at)
                        values (?,?,'NVD','Batch fixture','HIGH',false,now(),now())
                        """, id, "CVE-2098-BATCH" + i);
            }
            long generation = jdbc.queryForObject("select generation from platform.intelligence_active_state where singleton=true", Long.class);
            UUID start = UUID.fromString("ffffffff-ffff-ffff-ffff-000000000000");
            var state = schemas.run(tenant, () -> preview.snapshot(policy));
            var first = schemas.run(tenant, () -> preview.preview(new Request(policy, start, generation, state.overrideState(), state.sourceState())));
            assertEquals(100, first.scanned()); assertFalse(first.complete()); assertNotNull(first.nextAfterId());
            var last = schemas.run(tenant, () -> preview.preview(new Request(policy, first.nextAfterId(), generation, first.overrideState(), first.sourceState())));
            assertEquals(1, last.scanned()); assertTrue(last.complete()); assertNull(last.nextAfterId());
            assertEquals(0, first.matched()); // No allowed observations; no global-score fallback.
            var missing = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.MISSING, Field.CVSS, null, null, null));
            assertEquals(0, schemas.run(tenant, () -> preview.preview(new Request(missing, start, generation, state.overrideState(), state.sourceState()))).matched());
            var sourcePresent = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.SOURCE_PRESENT, null, null, null, null));
            assertEquals(0, schemas.run(tenant, () -> preview.preview(new Request(sourcePresent, start, generation, state.overrideState(), state.sourceState()))).matched());
            UUID nvdRecord = UUID.fromString("ffffffff-ffff-ffff-ffff-000000000001");
            UUID ghsaOnlyRecord = UUID.fromString("ffffffff-ffff-ffff-ffff-000000000002");
            var nvdEvidence = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            nvdEvidence.setVulnerability(vulnerabilities.findById(nvdRecord).orElseThrow());
            nvdEvidence.setSourceSystem("nvd"); nvdEvidence.setSourceRecordId("source-present-fixture-nvd");
            observations.saveAndFlush(nvdEvidence);
            var ghsaEvidence = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            ghsaEvidence.setVulnerability(vulnerabilities.findById(ghsaOnlyRecord).orElseThrow());
            ghsaEvidence.setSourceSystem("ghsa"); ghsaEvidence.setSourceRecordId("source-present-fixture-ghsa");
            observations.saveAndFlush(ghsaEvidence);
            var selected = schemas.run(tenant, () -> preview.preview(new Request(sourcePresent, start, generation, state.overrideState(), state.sourceState())));
            assertTrue(selected.matches().stream().anyMatch(match -> match.id().equals(nvdRecord)));
            assertFalse(selected.matches().stream().anyMatch(match -> match.id().equals(ghsaOnlyRecord)));
            assertEquals(1,selected.matched());
            assertEquals("source-present-fixture-nvd", selected.matches().get(0).attribution().sourcePresence().sourceRecordId());
            tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                    new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(false,
                            null,null,null,null,null,null,null,null,null,null,null,null,null,null,null)));
            try {
                var failure = assertThrows(ResponseStatusException.class,
                        () -> schemas.run(tenant, () -> preview.preview(new Request(policy, null, null))));
                assertEquals(400, failure.getStatusCode().value());
            } finally {
                tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                        new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                                null,null,null,null,null,null,null,null,null,null,null,null,null,null,null)));
                jdbc.update("delete from platform.vulnerability_intel_observations where source_record_id like 'source-present-fixture-%'");
                jdbc.update("delete from platform.vulnerabilities where external_id like 'CVE-2098-BATCH%'");
            }
        });
    }

    @Test void sameEnabledSourcesWithEditedFiltersInvalidateContinuation() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 6.0, null, null));
            var before = schemas.run(tenant, () -> preview.snapshot(policy));
            try {
                tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                        new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                                "cpe:2.3:a:example:changed:*:*:*:*:*:*:*:*", null, null,
                                null, null, null, null, null, null, null, null, null, null, null, null)));
                var after = schemas.run(tenant, () -> preview.snapshot(policy));
                assertNotEquals(before.sourceState(), after.sourceState());
                var stale = assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                        () -> preview.preview(new Request(policy, UUID.randomUUID(), before.generation(),
                                before.overrideState(), before.sourceState()))));
                assertEquals(409, stale.getStatusCode().value());
            } finally {
                tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                        new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null)));
            }
        });
    }

    @Test void platformContextCannotFallBackToDefaultTenant() {
        TenantContext.runAsPlatform(() -> assertThrows(ResponseStatusException.class,
                () -> preview.preview(new Request(null, null, null))));
        TenantContext.runAsPlatform(() -> assertThrows(ResponseStatusException.class,
                legacyCompatibility::inspect));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void legacySettingsDiagnosticDoesNotSilentlyApplyStoredSourceAlias() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            UUID aliasId = UUID.randomUUID();
            try {
                tenantWork.runScoped(tenant, () -> jdbc.update("""
                        insert into vulnerability_source_filter_configs
                        (id,tenant_id,source_system,enabled_for_correlation,filters_json,created_at,updated_at)
                        values (?,?,'jvndb',false,'{}',now(),now())
                        """, aliasId, tenant.getId()));
                var report = schemas.run(tenant, controller::legacyCompatibility);
                var alias = report.gaps().stream().filter(gap -> gap.source().equals("jvndb"))
                        .findFirst().orElseThrow();
                assertEquals("SOURCE_ALIAS_NOT_APPLIED", alias.reason());
                assertEquals("jvn", alias.canonicalSource());
                assertTrue(report.enabledSources().contains("jvn"));
                assertTrue(tenantWork.runScoped(tenant,
                        () -> sourceConfig.enabledSourcesForCorrelation(tenant).contains("jvn")));
            } finally {
                tenantWork.runScoped(tenant, () -> jdbc.update(
                        "delete from vulnerability_source_filter_configs where id=?", aliasId));
            }
        });
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void legacySettingsDiagnosticExposesFilterGapsWithoutChangingSettings() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            try {
                tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                        new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                                "cpe:2.3:a:example:product:*:*:*:*:*:*:*:*", null, true,
                                null, null, null, null, null, null, null, null, null, null, null, null)));
                var report = schemas.run(tenant, controller::legacyCompatibility);
                assertTrue(report.enabledSources().contains("nvd"));
                assertEquals(List.of("cpeName", "hasKev"), report.gaps().stream()
                        .filter(gap -> gap.source().equals("nvd")).findFirst().orElseThrow().fields());
                assertEquals("FILTER_NOT_REPRESENTABLE", report.gaps().stream()
                        .filter(gap -> gap.source().equals("nvd")).findFirst().orElseThrow().reason());
                tenantWork.runScoped(tenant, () -> jdbc.update(
                        "update vulnerability_source_filter_configs set filters_json='[]' where source_system='nvd'"));
                var malformed = schemas.run(tenant, controller::legacyCompatibility);
                assertEquals("MALFORMED_FILTERS", malformed.gaps().stream()
                        .filter(gap -> gap.source().equals("nvd")).findFirst().orElseThrow().reason());
            } finally {
                tenantWork.runScoped(tenant, () -> sourceConfig.save(tenant, "nvd",
                        new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                                null, null, null, null, null, null, null, null, null, null, null, null, null, null, null)));
            }
        });
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "SECURITY_ANALYST")
    void analystCannotPreviewAdministrativePolicy() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> controller.preview(new Request(null, null, null)));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                controller::legacyCompatibility);
    }
}
