package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.*;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(properties={"app.runtime.role=api","app.correlation.backfill-targets-on-startup=false"})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named="run.postgres.it",matches="true")
class CatalogBuildPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE=LocalPostgresTestDatabase.provision("catalog_builds");
    @DynamicPropertySource static void database(DynamicPropertyRegistry r) {
        r.add("DB_URL",DATABASE::url); r.add("DB_USERNAME",DATABASE::username); r.add("DB_PASSWORD",DATABASE::password);
    }
    @Autowired CatalogBuildService builds;
    @Autowired CatalogActivationReadinessService readiness;
    @Autowired VulnerabilitySourceFilterConfigService sourceConfig;
    @Autowired CatalogPolicyVersionService versions;
    @Autowired CatalogOverrideService overrides;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaExecutionService schemas;
    @Autowired TenantWorkRunner work;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityRepository vulnerabilities;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository observations;
    @Autowired com.prototype.vulnwatch.controller.CatalogBuildController controller;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired org.springframework.transaction.PlatformTransactionManager manager;
    @MockBean RequestActorService actors;

    @Test void sourcePresentSavedPolicyBuildsOnlyAllowedCurrentEvidenceWithoutActivation() {
        TenantContext.runAsPlatform(() -> {
            var tenant = freshTenant("source-present-build");
            when(actors.currentActor()).thenReturn(new RequestActor("source-present-build-test", false,
                    tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN")));
            var eligible = new com.prototype.vulnwatch.domain.Vulnerability();
            eligible.setExternalId("CVE-2099-SOURCE-PRESENT"); eligible.setTitle("Source-present fixture");
            eligible.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            eligible = vulnerabilities.saveAndFlush(eligible);
            var nvd = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            nvd.setVulnerability(eligible); nvd.setSourceSystem("nvd");
            nvd.setSourceRecordId("source-present-build-nvd"); observations.saveAndFlush(nvd);
            var wrongSource = new com.prototype.vulnwatch.domain.Vulnerability();
            wrongSource.setExternalId("CVE-2099-SOURCE-OTHER"); wrongSource.setTitle("Other-source fixture");
            wrongSource.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            wrongSource = vulnerabilities.saveAndFlush(wrongSource);
            var ghsa = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            ghsa.setVulnerability(wrongSource); ghsa.setSourceSystem("ghsa");
            ghsa.setSourceRecordId("source-present-build-ghsa"); observations.saveAndFlush(ghsa);
            var withdrawn = new com.prototype.vulnwatch.domain.Vulnerability();
            withdrawn.setExternalId("CVE-2099-SOURCE-WITHDRAWN"); withdrawn.setTitle("Withdrawn fixture");
            withdrawn.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            withdrawn.setIntelligenceWithdrawn(true); withdrawn = vulnerabilities.saveAndFlush(withdrawn);
            var withdrawnEvidence = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            withdrawnEvidence.setVulnerability(withdrawn); withdrawnEvidence.setSourceSystem("nvd");
            withdrawnEvidence.setSourceRecordId("source-present-build-withdrawn"); observations.saveAndFlush(withdrawnEvidence);

            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.SOURCE_PRESENT, null, null, null, null));
            schemas.run(tenant, () -> versions.save(0L, policy));
            UUID build = UUID.randomUUID(); schemas.run(tenant, () -> builds.create(build, 1));
            for (int i = 0; i < 20 && !"READY".equals(schemas.run(tenant, () -> builds.get(build)).status()); i++)
                assertTrue(schemas.run(tenant, builds::processNext));
            assertEquals("READY", schemas.run(tenant, () -> builds.get(build)).status());
            UUID eligibleId = eligible.getId(), wrongSourceId = wrongSource.getId(), withdrawnId = withdrawn.getId();
            work.runScoped(tenant, () -> {
                assertEquals(1, jdbc.queryForObject("select count(*) from intelligence_catalog_members where build_id=? and vulnerability_id=?",
                        Integer.class, build, eligibleId));
                assertEquals(0, jdbc.queryForObject("select count(*) from intelligence_catalog_members where build_id=? and vulnerability_id=?",
                        Integer.class, build, wrongSourceId));
                assertEquals(0, jdbc.queryForObject("select count(*) from intelligence_catalog_members where build_id=? and vulnerability_id=?",
                        Integer.class, build, withdrawnId));
            });
            assertTrue(schemas.run(tenant, () -> builds.inputStatus(build)).current());
            var review = schemas.run(tenant, () -> readiness.inspect(build));
            assertTrue(review.localChecksPass());
            assertFalse(review.activationEnabled());
            assertEquals(java.util.List.of("RELEASE_GATES_UNQUALIFIED"), review.blockers());
        });
    }

    @Test void simultaneousSameRequestCreatesOneBuildAndAudit() {
        TenantContext.runAsPlatform(() -> {
            var tenant=freshTenant("concurrent");
            when(actors.currentActor()).thenReturn(new RequestActor("concurrency-test",false,tenant.getId(),tenant.getName(),Set.of("TENANT_ADMIN")));
            var policy=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT,Field.CVSS,6.0,null,null));
            schemas.run(tenant,()->versions.save(0L,policy));
            UUID id=UUID.randomUUID();
            var executor=java.util.concurrent.Executors.newFixedThreadPool(2);
            var start=new java.util.concurrent.CountDownLatch(1);
            try {
                java.util.concurrent.Callable<CatalogBuildService.Build> request=()->{
                    start.await();
                    return TenantContext.runAsPlatform(()->schemas.run(tenant,()->builds.create(id,1)));
                };
                var first=executor.submit(request); var second=executor.submit(request); start.countDown();
                assertEquals(id,first.get(20,java.util.concurrent.TimeUnit.SECONDS).id());
                assertEquals(id,second.get(20,java.util.concurrent.TimeUnit.SECONDS).id());
                assertEquals(1,schemas.run(tenant,builds::list).size());
                work.runScoped(tenant,()->assertEquals(1,jdbc.queryForObject("select count(*) from audit_events where action='tenant.intelligence_catalog_build.requested'",Integer.class)));
            } catch(Exception failure) { throw new AssertionError(failure); }
            finally { executor.shutdownNow(); }
        });
    }

    @Test void runtimeRoleCannotReadOrWriteAnotherTenantCatalog() {
        TenantContext.runAsPlatform(() -> {
            var tenant=freshTenant("rls");
            when(actors.currentActor()).thenReturn(new RequestActor("rls-test",false,tenant.getId(),tenant.getName(),Set.of("TENANT_ADMIN")));
            var policy=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT,Field.CVSS,6.0,null,null));
            schemas.run(tenant,()->versions.save(0L,policy));
            UUID build=UUID.randomUUID(); schemas.run(tenant,()->builds.create(build,1));
            assertEquals("BUILD_NOT_READY", schemas.run(tenant, () -> builds.inputStatus(build)).reason());
            String role="catalog_rls_"+UUID.randomUUID().toString().replace("-","");
            String schema='"'+tenant.getSchemaName()+'"';
            jdbc.execute("create role "+role+" nologin nosuperuser nobypassrls");
            try {
                jdbc.execute("grant usage on schema platform,"+schema+" to "+role);
                jdbc.execute("grant select on all tables in schema platform to "+role);
                jdbc.execute("grant select,insert,update,delete on all tables in schema "+schema+" to "+role);
                work.runScoped(tenant,()->{
                    jdbc.execute("set local role "+role);
                    assertFalse(jdbc.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname=current_user",Boolean.class));
                    assertEquals(1,jdbc.queryForObject("select count(*) from intelligence_catalog_builds",Integer.class));
                    jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,UUID.randomUUID().toString());
                    assertEquals(0,jdbc.queryForObject("select count(*) from intelligence_catalog_builds",Integer.class));
                    assertEquals(0,jdbc.queryForObject("select count(*) from intelligence_catalog_policy_versions",Integer.class));
                    assertEquals(0,jdbc.update("update intelligence_catalog_builds set status='CANCELLED'"));
                });
                assertThrows(org.springframework.dao.DataAccessException.class,()->work.runScoped(tenant,()->{
                    jdbc.execute("set local role "+role);
                    jdbc.queryForObject("select set_config('app.current_tenant_id',?,true)",String.class,UUID.randomUUID().toString());
                    jdbc.update("insert into intelligence_catalog_policy_versions(tenant_id,version,policy_json,policy_sha256) values(?,2,'{}',repeat('a',64))",tenant.getId());
                }));
                assertEquals("QUEUED",schemas.run(tenant,()->builds.get(build)).status());
                var peer=freshTenant("peer");
                assertEquals(404,assertThrows(ResponseStatusException.class,()->schemas.run(peer,()->builds.get(build))).getStatusCode().value());
                assertEquals(404,assertThrows(ResponseStatusException.class,()->schemas.run(peer,()->builds.inputStatus(build))).getStatusCode().value());
                assertEquals(404,assertThrows(ResponseStatusException.class,()->schemas.run(peer,()->readiness.inspect(build))).getStatusCode().value());
            } finally { jdbc.execute("drop owned by "+role); jdbc.execute("drop role "+role); }
        });
    }

    @Test void failedMidBatchRollsBackMembersAndCheckpointThenResumes() {
        TenantContext.runAsPlatform(() -> {
            var tenant=freshTenant("rollback");
            when(actors.currentActor()).thenReturn(new RequestActor("rollback-test",false,tenant.getId(),tenant.getName(),Set.of("TENANT_ADMIN")));
            for(int i=0;i<2;i++) {
                var v=new com.prototype.vulnwatch.domain.Vulnerability();
                v.setExternalId("CVE-2026-ROLLBACK-"+i); v.setTitle("Rollback test"); v.setSeverity("HIGH");
                v.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD); v=vulnerabilities.saveAndFlush(v);
                var o=new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
                o.setVulnerability(v); o.setSourceSystem("nvd"); o.setSourceRecordId("rollback-"+i); o.setCvssScore(9.0); observations.saveAndFlush(o);
            }
            var policy=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,new Rule(Op.GT,Field.CVSS,6.0,null,null));
            schemas.run(tenant,()->versions.save(0L,policy));
            UUID id=UUID.randomUUID(); schemas.run(tenant,()->builds.create(id,1));
            String schema='"'+tenant.getSchemaName()+'"';
            jdbc.execute("create function "+schema+".fail_second_catalog_member() returns trigger language plpgsql as $$ begin if exists(select 1 from "+schema+".intelligence_catalog_members where build_id=NEW.build_id) then raise exception 'injected batch failure'; end if; return NEW; end $$");
            jdbc.execute("create trigger fail_catalog_member before insert on "+schema+".intelligence_catalog_members for each row execute function "+schema+".fail_second_catalog_member()");
            try {
                var failure=assertThrows(CatalogBuildService.BatchFailure.class,()->schemas.run(tenant,builds::processNext));
                assertEquals(0,schemas.run(tenant,()->builds.get(id)).scanned());
                assertTrue(schemas.run(tenant,()->builds.members(id,null)).isEmpty());
                schemas.run(tenant,()->{builds.recordWorkerFailure(failure.buildId(),failure.checkpoint()); return null;});
                assertFalse(schemas.run(tenant,builds::processNext)); // Retry backoff.
            } finally {
                jdbc.execute("drop trigger fail_catalog_member on "+schema+".intelligence_catalog_members");
                jdbc.execute("drop function "+schema+".fail_second_catalog_member()");
            }
            work.runScoped(tenant,()->jdbc.update("update intelligence_catalog_builds set updated_at=now()-interval '31 seconds' where id=?",id));
            for(int i=0;i<5 && !schemas.run(tenant,()->builds.get(id)).status().equals("READY");i++) schemas.run(tenant,builds::processNext);
            assertEquals("READY",schemas.run(tenant,()->builds.get(id)).status());
            assertTrue(schemas.run(tenant,()->builds.get(id)).matched()>=2);
        });
    }

    @Test void unchangedEnabledSetWithEditedFilterStalesQueuedBuild() {
        TenantContext.runAsPlatform(() -> {
            var tenant = freshTenant("source-fence");
            when(actors.currentActor()).thenReturn(new RequestActor("source-fence-test", false,
                    tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN")));
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 6.0, null, null));
            schemas.run(tenant, () -> versions.save(0L, policy));
            UUID id = UUID.randomUUID();
            schemas.run(tenant, () -> builds.create(id, 1));
            schemas.run(tenant, () -> sourceConfig.save(tenant, "nvd",
                    new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                            "cpe:2.3:a:example:changed:*:*:*:*:*:*:*:*", null, null,
                            null, null, null, null, null, null, null, null, null, null, null, null)));
            assertTrue(schemas.run(tenant, builds::processNext));
            assertEquals("STALE", schemas.run(tenant, () -> builds.get(id)).status());
            assertEquals(0, schemas.run(tenant, () -> builds.get(id)).scanned());
            assertEquals("STALE", jdbc.queryForObject(
                    "select status from platform.tenant_catalog_build_queue where tenant_id=?", String.class, tenant.getId()));
        });
    }

    private com.prototype.vulnwatch.domain.Tenant freshTenant(String suffix) {
        String slug="catalog-"+suffix+"-"+UUID.randomUUID().toString().substring(0,8);
        var tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(tenant);
        return tenants.resolveTenantUuid(tenant.getId());
    }

    @Test void savedVersionScopedPolicyBuildUsesOnlyMatchingCvssEvidence() {
        TenantContext.runAsPlatform(() -> {
            var tenant = freshTenant("cvss-version");
            when(actors.currentActor()).thenReturn(new RequestActor("cvss-version-test", false,
                    tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN")));
            var eligible = new com.prototype.vulnwatch.domain.Vulnerability();
            eligible.setExternalId("CVE-2026-V31-" + UUID.randomUUID());
            eligible.setTitle("v3.1 selected"); eligible.setSeverity("HIGH");
            eligible.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            eligible = vulnerabilities.saveAndFlush(eligible);
            UUID eligibleId = eligible.getId();
            var versioned = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            versioned.setVulnerability(eligible); versioned.setSourceSystem("nvd");
            versioned.setSourceRecordId("v31-" + eligibleId); versioned.setCvssScore(7.0);
            versioned.setCvssVersion("3.1"); observations.saveAndFlush(versioned);
            var unknown = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            unknown.setVulnerability(eligible); unknown.setSourceSystem("nvd");
            unknown.setSourceRecordId("unversioned-" + eligibleId); unknown.setCvssScore(10.0);
            observations.saveAndFlush(unknown);
            var ineligible = new com.prototype.vulnwatch.domain.Vulnerability();
            ineligible.setExternalId("CVE-2026-V40-" + UUID.randomUUID());
            ineligible.setTitle("v4 only"); ineligible.setSeverity("HIGH");
            ineligible.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            ineligible = vulnerabilities.saveAndFlush(ineligible);
            UUID ineligibleId = ineligible.getId();
            var v4 = new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
            v4.setVulnerability(ineligible); v4.setSourceSystem("nvd");
            v4.setSourceRecordId("v40-" + ineligibleId); v4.setCvssScore(9.0);
            v4.setCvssVersion("4.0"); observations.saveAndFlush(v4);
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_CVSS_V3_1,
                    new Rule(Op.GT, Field.CVSS, 6.0, null, null));
            schemas.run(tenant, () -> versions.save(0L, policy));
            UUID buildId = UUID.randomUUID(); schemas.run(tenant, () -> builds.create(buildId, 1));
            for (int i = 0; i < 20 && !"READY".equals(schemas.run(tenant, () -> builds.get(buildId)).status()); i++)
                assertTrue(schemas.run(tenant, builds::processNext));
            assertEquals("READY", schemas.run(tenant, () -> builds.get(buildId)).status());
            assertTrue(schemas.run(tenant, () -> builds.inputStatus(buildId)).current());
            assertEquals(1, schemas.run(tenant, () -> jdbc.queryForObject(
                    "select count(*) from intelligence_catalog_members where build_id=? and vulnerability_id=?",
                    Integer.class, buildId, eligibleId)));
            assertEquals(0, schemas.run(tenant, () -> jdbc.queryForObject(
                    "select count(*) from intelligence_catalog_members where build_id=? and vulnerability_id=?",
                    Integer.class, buildId, ineligibleId)));
            schemas.run(tenant, () -> sourceConfig.save(tenant, "nvd",
                    new com.prototype.vulnwatch.dto.VulnerabilitySourceFilterConfigRequest(true,
                            "cpe:2.3:a:example:changed:*:*:*:*:*:*:*:*", null, null,
                            null, null, null, null, null, null, null, null, null, null, null, null)));
            assertEquals("INPUTS_CHANGED", schemas.run(tenant, () -> builds.inputStatus(buildId)).reason());
        });
    }

    @Test void readyBuildReportsWhenANewerPolicyVersionExistsWithoutRewritingItsInputStatus() {
        TenantContext.runAsPlatform(() -> {
            var tenant=freshTenant("newer-policy");
            when(actors.currentActor()).thenReturn(new RequestActor("newer-policy-test",false,
                    tenant.getId(),tenant.getName(),Set.of("TENANT_ADMIN")));
            var first=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT,Field.CVSS,6.0,null,null));
            schemas.run(tenant,()->versions.save(0L,first));
            UUID id=UUID.randomUUID(); schemas.run(tenant,()->builds.create(id,1));
            for(int i=0;i<20 && !"READY".equals(schemas.run(tenant,()->builds.get(id)).status());i++)
                assertTrue(schemas.run(tenant,builds::processNext));
            assertEquals("READY",schemas.run(tenant,()->builds.get(id)).status());
            var original=schemas.run(tenant,()->builds.inputStatus(id));
            assertTrue(original.current()); assertTrue(original.latestPolicy());
            assertEquals(1,original.policyVersion()); assertEquals(1,original.latestPolicyVersion());
            var second=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT,Field.CVSS,8.0,null,null));
            schemas.run(tenant,()->versions.save(1L,second));
            var after=schemas.run(tenant,()->builds.inputStatus(id));
            assertTrue(after.current());
            assertEquals("INPUTS_MATCH",after.reason());
            assertFalse(after.latestPolicy());
            assertEquals(1,after.policyVersion()); assertEquals(2,after.latestPolicyVersion());
            var review=schemas.run(tenant,()->readiness.inspect(id));
            assertFalse(review.localChecksPass());
            assertFalse(review.activationEnabled());
            assertTrue(review.blockers().contains("POLICY_SUPERSEDED"));
        });
    }

    @Test void boundedBuildResumesIsIdempotentAndFencesChangedInputs() {
        TenantContext.runAsPlatform(() -> {
            var tenant=tenants.getDefaultTenant();
            when(actors.currentActor()).thenReturn(new RequestActor("build-test",false,tenant.getId(),tenant.getName(),Set.of("TENANT_ADMIN")));
            UUID example=null;
            for(int i=0;i<101;i++) {
                var v=new com.prototype.vulnwatch.domain.Vulnerability();
                v.setExternalId("CVE-2026-BUILD-"+i); v.setTitle("Build test"); v.setSeverity("HIGH");
                v.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
                v=vulnerabilities.saveAndFlush(v); example=v.getId();
                var o=new com.prototype.vulnwatch.domain.VulnerabilityIntelObservation();
                o.setVulnerability(v); o.setSourceSystem("nvd"); o.setSourceRecordId("build-"+i); o.setCvssScore(9.0);
                observations.saveAndFlush(o);
            }
            UUID recordId=example;
            var policy=new CatalogPolicy(1,Set.of("nvd"),false,ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT,Field.CVSS,6.0,null,null));
            var version=schemas.run(tenant,()->versions.save(0L,policy));
            UUID id=UUID.randomUUID();
            assertEquals("QUEUED",schemas.run(tenant,()->builds.create(id,version.version())).status());
            assertEquals("PENDING",jdbc.queryForObject("select status from platform.tenant_catalog_build_queue where tenant_id=?",String.class,tenant.getId()));
            assertEquals(id,schemas.run(tenant,()->builds.create(id,version.version())).id());
            assertEquals(409,assertThrows(ResponseStatusException.class,()->schemas.run(tenant,()->builds.create(UUID.randomUUID(),version.version()))).getStatusCode().value());
            new CatalogBuildWorker(jdbc,schemas,builds,BackgroundTaskExecutionPolicy.allowAll()).poll();
            assertEquals("BUILDING",schemas.run(tenant,()->builds.get(id)).status());
            assertEquals(100,schemas.run(tenant,()->builds.get(id)).scanned());
            assertTrue(schemas.run(tenant,builds::processNext));
            var ready=schemas.run(tenant,()->builds.get(id));
            assertEquals("READY",ready.status()); assertTrue(ready.matched()>=101);
            var comparison=schemas.run(tenant,()->builds.compareFindings(id));
            assertEquals(ready.matched(),comparison.selectedRecords());
            assertEquals(0,comparison.existingFindingRows());
            var noOrgRows=schemas.run(tenant,()->builds.compareOrgCveRecords(id));
            assertEquals(0,noOrgRows.existingOrgCveRecords());
            assertEquals(ready.matched(),noOrgRows.selectedWithoutOrgCveRecord());
            var outside=new com.prototype.vulnwatch.domain.Vulnerability();
            outside.setExternalId("CVE-2026-OUTSIDE-"+UUID.randomUUID()); outside.setTitle("Outside catalog");
            outside.setSeverity("LOW"); outside.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            outside=vulnerabilities.saveAndFlush(outside);
            UUID outsideId=outside.getId(); UUID assetId=UUID.randomUUID();
            work.runScoped(tenant,()->{
                for(UUID vulnerabilityId:java.util.List.of(recordId,outsideId)) {
                    UUID orgRecordId=UUID.randomUUID();
                    jdbc.update("""
                            insert into org_cve_records
                            (id,applicability_state,applicable_component_count,created_at,eol_component_count,
                             eos_component_count,external_id,fixed_component_count,impact_state,impacted,
                             impacted_component_count,in_kev,last_evaluated_at,matched_asset_count,
                             matched_component_count,matched_software_count,no_patch_component_count,
                             not_affected_component_count,severity,under_investigation_component_count,
                             unknown_component_count,updated_at,tenant_id,vulnerability_id)
                            values (?,'APPLICABLE',0,now(),0,0,?,0,'UNKNOWN',false,0,false,now(),0,
                                    0,0,0,0,'UNKNOWN',0,0,now(),?,?)
                            """,orgRecordId,"CVE-2026-ORG-"+orgRecordId,tenant.getId(),vulnerabilityId);
                }
                jdbc.update("insert into assets (id,business_criticality,created_at,identifier,name,state,type,environment,tenant_id) values (?,'HIGH',now(),?,'catalog impact','ACTIVE','APPLICATION','test',?)",
                        assetId,"catalog:"+assetId,tenant.getId());
                for(UUID vulnerabilityId:java.util.List.of(recordId,outsideId)) {
                    UUID findingId=UUID.randomUUID();
                    jdbc.update("insert into findings (id,created_at,creation_source,display_id,matched_by,risk_score,status,updated_at,asset_id,tenant_id,vulnerability_id) values (?,now(),'MANUAL',?,'CVE',0,'OPEN',now(),?,?,?)",
                            findingId,"F-"+findingId.toString().substring(0,12),assetId,tenant.getId(),vulnerabilityId);
                }
                UUID historicalId=UUID.randomUUID();
                jdbc.update("insert into findings (id,created_at,creation_source,display_id,matched_by,risk_score,status,updated_at,asset_id,tenant_id,vulnerability_id) values (?,now(),'MANUAL',?,'CVE',0,'RESOLVED',now(),?,?,?)",
                        historicalId,"F-"+historicalId.toString().substring(0,12),assetId,tenant.getId(),outsideId);
                UUID postureId=UUID.randomUUID();
                jdbc.update("insert into findings (id,created_at,creation_source,display_id,matched_by,risk_score,status,updated_at,asset_id,tenant_id,finding_kind) values (?,now(),'MANUAL',?,'AI_POSTURE',0,'OPEN',now(),?,?,'AI_POSTURE')",
                        postureId,"F-"+postureId.toString().substring(0,12),assetId,tenant.getId());
            });
            var populated=schemas.run(tenant,()->builds.compareFindings(id));
            assertEquals(3,populated.existingFindingRows());
            assertEquals(1,populated.unlinkedFindingRows());
            assertEquals(2,populated.findingRowsOutsideSelection());
            assertEquals(1,populated.distinctRecordsOutsideSelection());
            assertEquals(1,populated.openOutsideSelection());
            assertEquals(1,populated.resolvedOutsideSelection());
            assertEquals(0,populated.suppressedOutsideSelection());
            assertEquals(0,populated.autoClosedOutsideSelection());
            var orgComparison=schemas.run(tenant,()->builds.compareOrgCveRecords(id));
            assertEquals(2,orgComparison.existingOrgCveRecords());
            assertEquals(1,orgComparison.overlappingRecords());
            assertEquals(1,orgComparison.orgCveRecordsOutsideSelection());
            assertEquals(ready.matched()-1,orgComparison.selectedWithoutOrgCveRecord());
            var outsidePage=schemas.run(tenant,()->builds.orgCveDifferences(id,
                    CatalogBuildService.DifferenceDirection.ORG_OUTSIDE_SELECTION,null));
            assertEquals(1,outsidePage.records().size());
            assertEquals(outsideId,outsidePage.records().get(0).vulnerabilityId());
            assertTrue(outsidePage.complete());
            var missingFirst=schemas.run(tenant,()->builds.orgCveDifferences(id,
                    CatalogBuildService.DifferenceDirection.SELECTED_WITHOUT_ORG,null));
            assertEquals(50,missingFirst.records().size());
            assertFalse(missingFirst.complete());
            assertNotNull(missingFirst.nextAfterId());
            var missingNext=schemas.run(tenant,()->builds.orgCveDifferences(id,
                    CatalogBuildService.DifferenceDirection.SELECTED_WITHOUT_ORG,missingFirst.nextAfterId()));
            assertEquals(50,missingNext.records().size());
            assertTrue(missingFirst.records().stream().noneMatch(first -> missingNext.records().stream()
                    .anyMatch(next -> next.vulnerabilityId().equals(first.vulnerabilityId()))));
            assertEquals(400,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(tenant,()->builds.orgCveDifferences(id,null,null))).getStatusCode().value());
            var otherTenant=freshTenant("comparison_peer");
            assertEquals(404,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(otherTenant,()->builds.compareFindings(id))).getStatusCode().value());
            assertEquals(404,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(otherTenant,()->builds.compareOrgCveRecords(id))).getStatusCode().value());
            assertEquals(404,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(otherTenant,()->builds.orgCveDifferences(id,
                            CatalogBuildService.DifferenceDirection.ORG_OUTSIDE_SELECTION,null))).getStatusCode().value());
            assertEquals(3,schemas.run(tenant,()->builds.compareFindings(id)).existingFindingRows());
            assertEquals("READY",jdbc.queryForObject("select status from platform.tenant_catalog_build_queue where tenant_id=?",String.class,tenant.getId()));
            assertFalse(schemas.run(tenant,builds::processNext));
            var first=schemas.run(tenant,()->builds.members(id,null));
            assertEquals(100,first.size()); assertEquals("POLICY",first.get(0).reason());
            assertEquals(ready.matched()-100,schemas.run(tenant,()->builds.members(id,first.get(99).vulnerabilityId())).size());

            UUID stale=UUID.randomUUID(); schemas.run(tenant,()->builds.create(stale,version.version()));
            schemas.run(tenant,()->overrides.change(recordId,new CatalogOverrideService.Change(0L,CatalogOverrideService.Operation.EXCLUDE,"Outside scope",null)));
            schemas.run(tenant,builds::processNext);
            assertEquals("STALE",schemas.run(tenant,()->builds.get(stale)).status());
            assertEquals(409,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(tenant,()->builds.compareFindings(id))).getStatusCode().value());
            assertEquals(409,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(tenant,()->builds.compareOrgCveRecords(id))).getStatusCode().value());
            assertEquals(409,assertThrows(ResponseStatusException.class,
                    ()->schemas.run(tenant,()->builds.orgCveDifferences(id,
                            CatalogBuildService.DifferenceDirection.ORG_OUTSIDE_SELECTION,null))).getStatusCode().value());
            assertEquals("STALE",jdbc.queryForObject("select status from platform.tenant_catalog_build_queue where tenant_id=?",String.class,tenant.getId()));
            assertEquals(0,schemas.run(tenant,()->builds.get(stale)).scanned());
            assertEquals(ready.matched(),schemas.run(tenant,()->builds.get(id)).matched()); // Existing shadow is untouched.

            UUID cancelled=UUID.randomUUID(); schemas.run(tenant,()->builds.create(cancelled,version.version()));
            assertEquals("CANCELLED",schemas.run(tenant,()->builds.cancel(cancelled)).status());
            assertEquals("CANCELLED",jdbc.queryForObject("select status from platform.tenant_catalog_build_queue where tenant_id=?",String.class,tenant.getId()));
            assertFalse(schemas.run(tenant,builds::processNext));
            UUID failedAudit=UUID.randomUUID();
            when(actors.currentActor()).thenThrow(new IllegalStateException("audit unavailable"));
            assertThrows(IllegalStateException.class,()->schemas.run(tenant,()->builds.create(failedAudit,version.version())));
            assertEquals(404,assertThrows(ResponseStatusException.class,()->schemas.run(tenant,()->builds.get(failedAudit))).getStatusCode().value());
        });
    }
    @Test void platformContextCannotReadBuilds() {
        TenantContext.runAsPlatform(()->assertThrows(ResponseStatusException.class,builds::list));
    }
    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles="SECURITY_ANALYST")
    void analystCannotRequestOrReadBuilds() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,controller::list);
        assertThrows(org.springframework.security.access.AccessDeniedException.class,()->controller.create(null));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->controller.compareFindings(UUID.randomUUID()));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->controller.compareOrgCveRecords(UUID.randomUUID()));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->controller.orgCveDifferences(UUID.randomUUID(),CatalogBuildService.DifferenceDirection.ORG_OUTSIDE_SELECTION,null));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->controller.inputStatus(UUID.randomUUID()));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                ()->controller.activationReadiness(UUID.randomUUID()));
    }
}
