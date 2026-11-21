package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.*;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;

@SpringBootTest(properties={"app.runtime.role=api","app.correlation.backfill-targets-on-startup=false"})
@ActiveProfiles("postgres")
@WithMockUser(roles="PLATFORM_OWNER")
@EnabledIfSystemProperty(named="run.postgres.it",matches="true")
class IntelligencePublicationPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE=LocalPostgresTestDatabase.provision("reviewed_intelligence_publication");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("DB_URL",DATABASE::url);registry.add("DB_USERNAME",DATABASE::username);registry.add("DB_PASSWORD",DATABASE::password);
    }
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @Autowired VulnerabilityIngestionService ingestion;
    @Autowired IntelligencePublicationService publications;
    @Autowired IntelligenceReleaseChangeScopeService changeScope;
    @Autowired com.prototype.vulnwatch.controller.PlatformIntelligenceController platformController;
    @Autowired ObservationIngestionService observations;
    @Autowired VexAssertionService vex;
    @Autowired EntityManager entities;
    @Autowired PlatformTransactionManager manager;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantWorkRunner tenantWork;
    @Autowired TenantSchemaExecutionService schemas;
    @Autowired FindingComponentRecomputeService recompute;
    @Autowired FindingDeltaQueueService findingQueue;
    @Autowired IntelligenceEvaluationFence evaluationFence;
    @Autowired FindingsScoreRecomputeService findingScores;
    @Autowired VulnerabilitySourceFilterConfigService settings;
    @Autowired com.prototype.vulnwatch.repo.AssetRepository assets;
    @Autowired com.prototype.vulnwatch.repo.SbomUploadRepository uploads;
    @Autowired com.prototype.vulnwatch.repo.InventoryComponentRepository inventory;
    @Autowired com.prototype.vulnwatch.repo.FindingRepository findings;
    @Autowired VulnerabilityIntelSummaryService summaries;
    private IntelligencePublicationService worker;
    private TenantIntelligenceProcessingService tenantWorker;

    @BeforeEach void worker() {
        worker=new IntelligencePublicationService(jdbc,mapper,observations,vex,entities,BackgroundTaskExecutionPolicy.allowAll(),manager);
        org.springframework.test.util.ReflectionTestUtils.setField(worker,"summaries",summaries);
        tenantWorker=new TenantIntelligenceProcessingService(jdbc,schemas,recompute,BackgroundTaskExecutionPolicy.allowAll(),manager);
        org.springframework.test.util.ReflectionTestUtils.setField(tenantWorker,"findingQueue",findingQueue);
    }

    @Test void ingestionIsInvisibleUntilAnExactReviewedCandidatePublishesAndWithdrawalRetainsCanonicalIdentity() {
        TenantContext.runAsPlatform(() -> {
            String external="CVE-2099-78001";
            var tenant=tenants.getDefaultTenant();
            tenantWork.runScoped(tenant,() -> {
                var asset=new com.prototype.vulnwatch.domain.Asset();asset.setTenant(tenant);asset.setType(com.prototype.vulnwatch.domain.AssetType.HOST);asset.setName("Publication test");asset.setIdentifier("publication-test");asset=assets.save(asset);
                var upload=new com.prototype.vulnwatch.domain.SbomUpload();upload.setTenant(tenant);upload.setAsset(asset);upload.setOriginalFilename("publication-test.json");upload=uploads.save(upload);
                var component=new com.prototype.vulnwatch.domain.InventoryComponent();component.setTenant(tenant);component.setAsset(asset);component.setSbomUpload(upload);component.setEcosystem("npm");component.setPackageName("sg-review-test");component.setVersion("1.0.0");component.setPurl("pkg:npm/sg-review-test@1.0.0");inventory.saveAndFlush(component);
                var unrelated = new com.prototype.vulnwatch.domain.InventoryComponent();
                unrelated.setTenant(tenant); unrelated.setAsset(asset); unrelated.setSbomUpload(upload);
                unrelated.setEcosystem("npm"); unrelated.setPackageName("unrelated"); unrelated.setVersion("1.0.0");
                unrelated.setPurl("pkg:npm/unrelated@1.0.0"); inventory.saveAndFlush(unrelated);
            });
            ingestion.ingestAdvisories(new AdvisoryBatchRequest(List.of(new AdvisoryRequest(external,"Reviewed advisory","A prepared applicability rule",9.1,"CRITICAL",
                    List.of(new AdvisoryRuleRequest("npm","sg-review-test","1.0.0",null,null,null))))));
            assertEquals(0,count("platform.vulnerabilities"));
            assertEquals(0,count("platform.vulnerability_targets"));
            UUID run=jdbc.queryForObject("select id from platform.sync_runs where sync_type='ADVISORY' order by started_at desc limit 1",UUID.class);
            UUID candidate=(UUID)publications.createCandidate(List.of(run),"test-owner").get("id");
            worker.poll();
            var reviewed=publications.candidate(candidate);
            assertEquals("READY",reviewed.get("status"));
            String digest=(String)reviewed.get("digest");
            assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> publications.publish(candidate,"0".repeat(64),null,"changed-digest","test-owner"));
            assertThrows(org.springframework.dao.DataAccessException.class,() -> jdbc.update("update platform.intelligence_staged_records set validation='VALID' where sync_run_id=?",run));
            var queued=publications.publish(candidate,digest,null,"reviewed-publication","test-owner");
            assertEquals(queued.get("id"),publications.publish(candidate,digest,null,"reviewed-publication","test-owner").get("id"));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from platform.intelligence_audit_events
                    where action='PUBLICATION_QUEUED' and candidate_id=?
                      and detail->>'approvalMode'='OWNER_REVIEW'
                      and detail->'feedReviewWait'->0->>'runId'=?
                      and (detail->'feedReviewWait'->0->>'waitMillis')::bigint>=0
                    """, Integer.class, candidate, run.toString()));
            worker.poll();
            assertEquals("PUBLISHED",publications.candidate(candidate).get("status"));
            assertEquals(1,count("platform.vulnerabilities"));assertEquals(1,count("platform.vulnerability_targets"));
            UUID canonical=jdbc.queryForObject("select id from platform.vulnerabilities where external_id=?",UUID.class,external);
            UUID release=jdbc.queryForObject("select release_id from platform.intelligence_active_state",UUID.class);
            var scope=platformController.changeScope(release,null);
            assertFalse(scope.routingReady());
            assertFalse(scope.changes().isEmpty());
            assertTrue(scope.changes().stream().anyMatch(change -> change.directVulnerabilityIds().contains(canonical)));
            String targetKey=jdbc.queryForObject("select normalized_target_key from platform.vulnerability_targets where vulnerability_id=?",String.class,canonical);
            assertTrue(scope.changes().stream().filter(change -> change.tableName().equals("vulnerability_targets"))
                    .anyMatch(change -> change.directProductKeys().contains(targetKey)));
            assertFalse(scope.toString().contains("A prepared applicability rule"));
            assertEquals(0,changeScope.inspect(release,Long.MAX_VALUE).changes().size());
            assertEquals(400,assertThrows(org.springframework.web.server.ResponseStatusException.class,
                    ()->changeScope.inspect(release,-1L)).getStatusCode().value());
            assertEquals(404,assertThrows(org.springframework.web.server.ResponseStatusException.class,
                    ()->changeScope.inspect(UUID.randomUUID(),null)).getStatusCode().value());
            assertEquals(1,jdbc.queryForObject("select count(*) from platform.intelligence_publication_outbox where kind='FANOUT' and release_id=?",Integer.class,release));
            assertThrows(org.springframework.dao.DataAccessException.class,() -> jdbc.update("update platform.intelligence_releases set digest=? where id=?","f".repeat(64),release));
            jdbc.update("update tenant_default.inventory_components set software_identity_id=(select software_identity_id from platform.vulnerability_targets limit 1) where package_name='sg-review-test'");
            String peerSlug="publication-peer-"+UUID.randomUUID().toString().substring(0,8);
            var peer=tenants.createTenant(peerSlug,peerSlug,"ENTERPRISE",null);migrations.provisionNewTenant(peer);
            peer=tenants.resolveTenantUuid(peer.getId());
            schemas.run(peer,() -> {
                jdbc.execute("create function fail_tenant_evaluation() returns trigger language plpgsql as $$ begin raise exception 'injected tenant failure'; end $$");
                jdbc.execute("create trigger fail_tenant_evaluation before insert on finding_delta_queue for each row execute function fail_tenant_evaluation()");
            });
            tenantWorker.poll();
            assertEquals("FAILED",jdbc.queryForObject("select status from platform.tenant_intelligence_processing where tenant_id=?",String.class,peer.getId()));
            schemas.run(peer,() -> jdbc.execute("drop trigger fail_tenant_evaluation on finding_delta_queue"));
            jdbc.update("update platform.tenant_intelligence_processing set updated_at=now()-interval '1 minute' where tenant_id=?",peer.getId());
            tenantWorker.poll();
            assertEquals("COMPLETED",jdbc.queryForObject("select status from platform.tenant_intelligence_processing where tenant_id=?",String.class,peer.getId()));
            assertEquals("COMPLETED",jdbc.queryForObject("select status from platform.tenant_intelligence_processing where tenant_id=?",String.class,tenant.getId()));
            assertEquals(1,count("tenant_default.findings"));
            assertRuntimeVisibility(tenant.getId(),1,false);
            UUID finding=jdbc.queryForObject("select id from tenant_default.findings",UUID.class);
            jdbc.update("update tenant_default.findings set status='SUPPRESSED',suppression_reason='Analyst decision' where id=?",finding);
            tenantWork.runScoped(tenant,() -> settings.save(tenant,"advisory",new VulnerabilitySourceFilterConfigRequest(false,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null)));
            tenantWorker.poll();
            assertRuntimeVisibility(tenant.getId(),0,false);
            assertRuntimeVisibility(tenant.getId(),1,true);
            assertEquals("SOURCE_DISABLED",jdbc.queryForObject("select intelligence_eligibility from tenant_default.findings where id=?",String.class,finding));
            assertEquals("SUPPRESSED",jdbc.queryForObject("select status from tenant_default.findings where id=?",String.class,finding));
            tenantWork.runScoped(tenant,() -> settings.save(tenant,"advisory",new VulnerabilitySourceFilterConfigRequest(true,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null)));
            tenantWorker.poll();
            assertEquals(1,count("tenant_default.findings"));
            assertEquals("ELIGIBLE",jdbc.queryForObject("select intelligence_eligibility from tenant_default.findings where id=?",String.class,finding));
            assertEquals("SUPPRESSED",jdbc.queryForObject("select status from tenant_default.findings where id=?",String.class,finding));
            var routing = enableTargetedDelivery();
            tenantWork.runScoped(tenant, () -> jdbc.update("""
                    insert into inventory_correlation_settings (tenant_id,inventory_incremental_correlation_enabled)
                    values (?,true)
                    """, tenant.getId()));
            publications.withdraw(release,"withdraw-first-release","test-owner");worker.poll();
            UUID withdrawal = jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class);
            assertEquals("APPLICABILITY", routing.mode(withdrawal));
            assertTrue(changeScope.inspect(withdrawal, null).routingReady());
            assertTrue(jdbc.queryForList("""
                    select match_key from platform.intelligence_release_route_targets
                    where release_id=? and key_kind='COORD'
                    """, String.class, withdrawal).contains(targetKey));
            tenantWork.runScoped(tenant, () -> {
                var page = routing.componentPage(withdrawal, null);
                assertEquals(2, page.examined().size());
                assertEquals(List.of(jdbc.queryForObject("select id from inventory_components where package_name='sg-review-test'",
                        UUID.class)), page.affected());
            });
            tenantWorker.poll();
            assertEquals("INTELLIGENCE_WITHDRAWN",jdbc.queryForObject("select intelligence_eligibility from tenant_default.findings where id=?",String.class,finding));
            assertEquals(0,count("platform.vulnerability_targets"));assertEquals(canonical,jdbc.queryForObject("select id from platform.vulnerabilities where external_id=?",UUID.class,external));
            assertTrue(jdbc.queryForObject("select intelligence_withdrawn from platform.vulnerabilities where id=?",Boolean.class,canonical));
            assertEquals(2L,jdbc.queryForObject("select generation from platform.intelligence_active_state",Long.class));
        });
    }

    @Test void capturesRankingOnlyAndFallsBackForUnresolvedJournalRows() {
        TenantContext.runAsPlatform(() -> {
            UUID parent = UUID.randomUUID();
            UUID scoped = UUID.randomUUID();
            UUID unresolved = UUID.randomUUID();
            UUID vulnerability = UUID.randomUUID();
            for (UUID release : List.of(parent, scoped, unresolved)) {
                jdbc.update("""
                        insert into platform.intelligence_releases(id,generation,digest,actor,status)
                        values (?, (select coalesce(max(generation),0)+100 from platform.intelligence_releases),
                            ?, 'manifest-test', 'PUBLISHED')
                        """, release, "0".repeat(64));
            }
            jdbc.update("""
                    insert into platform.intelligence_release_changes
                        (release_id,table_schema,table_name,row_id,previous_value,new_value)
                    values (?,'platform','vulnerabilities',?,
                        '{"epss_score":0.1,"severity":"HIGH"}'::jsonb,
                        '{"epss_score":0.9,"severity":"HIGH"}'::jsonb)
                    """, scoped, vulnerability);
            jdbc.update("""
                    insert into platform.intelligence_release_changes
                        (release_id,table_schema,table_name,row_id,previous_value,new_value)
                    values (?,'platform','vulnerability_targets',?,null,'{"vulnerability_id":"invalid"}'::jsonb)
                    """, unresolved, UUID.randomUUID());
            var routing = new IntelligenceReleaseRoutingService(jdbc, true);
            new org.springframework.transaction.support.TransactionTemplate(manager).executeWithoutResult(status -> {
                routing.capture(scoped, parent);
                routing.capture(unresolved, parent);
            });

            assertEquals("RANKING", routing.mode(scoped));
            assertEquals(List.of(vulnerability), jdbc.queryForList("""
                    select vulnerability_id from platform.intelligence_release_route_vulnerabilities where release_id=?
                    """, UUID.class, scoped));
            assertNull(routing.mode(unresolved));
        });
    }

    private IntelligenceReleaseRoutingService enableTargetedDelivery() {
        var routing = new IntelligenceReleaseRoutingService(jdbc, true);
        org.springframework.test.util.ReflectionTestUtils.setField(worker, "releaseRouting", routing);
        org.springframework.test.util.ReflectionTestUtils.setField(tenantWorker, "releaseRouting", routing);
        org.springframework.test.util.ReflectionTestUtils.setField(tenantWorker, "evaluationFence", evaluationFence);
        org.springframework.test.util.ReflectionTestUtils.setField(tenantWorker, "findingScores", findingScores);
        return routing;
    }
    @Test
    @WithMockUser(roles="TENANT_ADMIN")
    void tenantAdminCannotInspectPlatformReleaseChangeScope() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->platformController.changeScope(UUID.randomUUID(),null));
    }

    @Test void scheduledPublicationRequiresOptInAndNeverIncludesAnUnreviewedFullRun() {
        TenantContext.runAsPlatform(() -> {
            UUID scheduled = UUID.randomUUID();
            UUID manual = UUID.randomUUID();
            jdbc.update("update platform.intelligence_feed_schedules set enabled = (sync_type = 'NVD')");
            jdbc.update("""
                    insert into platform.sync_runs (id, sync_type, run_scope, status, started_at, metadata_json,
                                                    records_failed, records_fetched, records_inserted, records_updated)
                    values
                        (?, 'NVD_FULL', 'PLATFORM_VULNERABILITY', 'completed', now() - interval '3 days', null, 0, 0, 0, 0),
                        (?, 'NVD', 'PLATFORM_VULNERABILITY', 'completed', now() - interval '1 day',
                            '{"scheduleOccurrence":"NVD:scheduled-publication-test"}', 0, 0, 0, 0)
                    """, manual, scheduled);
            try {
                worker.poll();
                assertEquals(0, scheduledCandidates(scheduled));

                org.springframework.test.util.ReflectionTestUtils.setField(worker, "scheduledAutoPublicationEnabled", true);
                worker.poll();
                assertEquals(0, scheduledCandidates(scheduled));

                jdbc.update("update platform.sync_runs set status='failed' where id=?", manual);
                worker.poll();
                assertEquals(1, scheduledCandidates(scheduled));
                assertEquals(0, scheduledCandidates(manual));
            } finally {
                jdbc.update("update platform.intelligence_feed_schedules set enabled = false where sync_type = 'NVD'");
            }
        });
    }

    private int scheduledCandidates(UUID run) {
        return jdbc.queryForObject("""
                select count(*) from platform.intelligence_candidates where created_by='scheduled-intelligence-publisher'
                  and (?=any(selected_run_ids) or ?=any(expanded_run_ids))
                """, Integer.class, run, run);
    }

    @Test void malformedJournalReferenceIsUnresolvedWithoutBreakingThePageOrLeakingPayload() {
        TenantContext.runAsPlatform(() -> {
            UUID release=UUID.randomUUID();
            UUID canonical=UUID.randomUUID();
            jdbc.update("""
                    insert into platform.intelligence_releases(id,generation,digest,actor,status)
                    values (?,(select coalesce(max(generation),0)+100 from platform.intelligence_releases),?,?,'PUBLISHED')
                    """,release,"0".repeat(64),"scope-test");
            jdbc.update("""
                    insert into platform.intelligence_release_changes
                      (release_id,table_schema,table_name,row_id,previous_value,new_value)
                    values (?,'platform','intelligence_identifiers',?,?::jsonb,?::jsonb)
                    """,release,UUID.randomUUID(),
                    "{\"canonical_id\":\""+canonical+"\"}",
                    "{\"canonical_id\":\"not-a-uuid\",\"raw_payload\":\"private-marker\"}");
            jdbc.update("""
                    insert into platform.intelligence_release_changes
                      (release_id,table_schema,table_name,row_id,previous_value,new_value)
                    values (?,'platform','vulnerabilities',?,null,null)
                    """,release,canonical);
            var scope=changeScope.inspect(release,null);
            assertEquals(2,scope.changes().size());
            assertTrue(scope.changes().get(0).directVulnerabilityIds().contains(canonical));
            assertTrue(scope.changes().get(0).unresolved());
            assertFalse(scope.changes().get(1).unresolved());
            assertFalse(scope.routingReady());
            assertFalse(scope.toString().contains("private-marker"));
        });
    }
    private void assertRuntimeVisibility(UUID tenant,int expected,boolean includeHistory) {
        String role="review_rls_"+UUID.randomUUID().toString().replace("-","");
        jdbc.execute("create role "+role+" nologin nosuperuser nobypassrls");
        try {
            jdbc.execute("grant usage on schema platform,tenant_default to "+role);
            jdbc.execute("grant select on all tables in schema platform,tenant_default to "+role);
            new org.springframework.transaction.support.TransactionTemplate(manager).executeWithoutResult(status -> {
                jdbc.execute("set local role "+role);
                jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,tenant.toString());
                if(includeHistory) jdbc.queryForObject("select set_config('app.include_ineligible_intelligence','true',true)",String.class);
                assertEquals(expected,count("tenant_default.findings"));
                jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,UUID.randomUUID().toString());
                assertEquals(0,count("tenant_default.findings"));
            });
        } finally {jdbc.execute("drop owned by "+role);jdbc.execute("drop role "+role);}
    }
    private int count(String table) { return jdbc.queryForObject("select count(*) from "+table,Integer.class); }
}
