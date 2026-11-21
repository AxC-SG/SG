package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.*;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import com.prototype.vulnwatch.support.*;
import jakarta.persistence.EntityManager;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;

@PostgresIntegrationTest
@WithMockUser(roles="PLATFORM_OWNER")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class IntelligencePublicationRecoveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("publication_recovery");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {PostgresITSupport.registerDatabaseProperties(registry,DB);}
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @Autowired VulnerabilityIngestionService ingestion;
    @Autowired IntelligencePublicationService publications;
    @Autowired ObservationIngestionService observations;
    @Autowired VexAssertionService vex;
    @Autowired EntityManager entities;
    @Autowired PlatformTransactionManager manager;
    @Autowired VulnerabilityIntelSummaryService summaries;
    @Autowired VulnerabilitySyncRunService syncRuns;
    @Autowired IntelligenceStagingService staging;
    @Autowired VulnerabilityRepository vulnerabilities;

    @Test @Order(2) void profileCandidateDoesNotExpandUnfilteredOrOtherProfileRuns() {
        var worker=new IntelligencePublicationService(jdbc,mapper,observations,vex,entities,BackgroundTaskExecutionPolicy.allowAll(),manager);
        ReflectionTestUtils.setField(worker,"summaries",summaries);
        var runs=new ArrayList<UUID>();
        for(int n=0;n<4;n++) {
            ingestion.ingestAdvisories(new AdvisoryBatchRequest(List.of(new AdvisoryRequest("CVE-2098-"+(90000+n),"Scope fixture","Scope isolation",8.1,"HIGH",List.of()))));
            UUID run=jdbc.queryForObject("select id from platform.sync_runs where sync_type='ADVISORY' order by started_at desc limit 1",UUID.class);
            runs.add(run);
            if(n>0) jdbc.update("update platform.sync_runs set metadata_json=? where id=?","{\"importScopeKey\":\"profile:"+(n==1?"other":"selected")+"\"}",run);
            jdbc.update("update platform.sync_runs set started_at=now()-(? * interval '1 minute') where id=?",4-n,run);
        }
        UUID candidate=(UUID)publications.createCandidate(List.of(runs.get(3)),"owner").get("id");
        worker.poll();
        var expanded=jdbc.queryForList("select distinct sync_run_id from platform.intelligence_candidate_records where candidate_id=?",UUID.class,candidate);
        assertEquals(Set.of(runs.get(2),runs.get(3)),new HashSet<>(expanded));
        var declared=jdbc.queryForList("select unnest(expanded_run_ids) from platform.intelligence_candidates where id=?",UUID.class,candidate);
        assertEquals(new HashSet<>(expanded),new HashSet<>(declared));
        UUID unscoped=(UUID)publications.createCandidate(List.of(runs.get(0)),"owner").get("id");
        worker.poll();
        assertEquals(List.of(runs.get(0)),jdbc.queryForList("select distinct sync_run_id from platform.intelligence_candidate_records where candidate_id=?",UUID.class,unscoped));
    }

    @Test @Order(1) void thousandRecordPublicationRollsBackRetriesAndSerializesDuplicateApproval() throws Exception {
        var worker=new IntelligencePublicationService(jdbc,mapper,observations,vex,entities,BackgroundTaskExecutionPolicy.allowAll(),manager);
        ReflectionTestUtils.setField(worker,"summaries",summaries);
        var batch=new ArrayList<AdvisoryRequest>();
        for(int n=0;n<1000;n++) batch.add(new AdvisoryRequest("CVE-2099-"+(80000+n),"Prepared record "+n,"Offline full-feed-shaped fixture",8.1,"HIGH",List.of(new AdvisoryRuleRequest("npm","publication-recovery-"+n,"1.0.0",null,null,null))));
        ingestion.ingestAdvisories(new AdvisoryBatchRequest(batch));
        assertEquals(0,count("platform.vulnerabilities"));
        UUID run=jdbc.queryForObject("select id from platform.sync_runs where sync_type='ADVISORY'",UUID.class);
        UUID candidate=(UUID)publications.createCandidate(List.of(run),"owner").get("id");
        UUID stale=(UUID)publications.createCandidate(List.of(run),"owner").get("id");
        worker.poll();
        String digest=(String)publications.candidate(candidate).get("digest");
        assertNotNull(digest);
        var pool=Executors.newFixedThreadPool(2);
        var start=new CyclicBarrier(2);
        try {
            Callable<Object> approve=()->{
                var security=SecurityContextHolder.createEmptyContext();
                security.setAuthentication(new UsernamePasswordAuthenticationToken("owner","",List.of(new SimpleGrantedAuthority("ROLE_PLATFORM_OWNER"))));
                SecurityContextHolder.setContext(security);
                try {start.await(10,TimeUnit.SECONDS);return publications.publish(candidate,digest,null,"same-concurrent-approval","owner").get("id");}
                finally {SecurityContextHolder.clearContext();}
            };
            var a=pool.submit(approve);var b=pool.submit(approve);
            assertEquals(a.get(20,TimeUnit.SECONDS),b.get(20,TimeUnit.SECONDS));
        } finally {pool.shutdownNow();}
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.intelligence_publication_outbox where kind='PUBLISH'",Integer.class));
        jdbc.execute("create function platform.fail_prepared_target() returns trigger language plpgsql as $$ begin raise exception 'injected publication interruption'; end $$");
        jdbc.execute("create trigger fail_prepared_target before insert on platform.vulnerability_targets for each row execute function platform.fail_prepared_target()");
        worker.poll();
        assertEquals(0,count("platform.vulnerabilities"));assertEquals(0,count("platform.intelligence_releases"));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.intelligence_publication_outbox where kind='FANOUT'",Integer.class));
        assertEquals(0L,jdbc.queryForObject("select generation from platform.intelligence_active_state",Long.class));
        jdbc.execute("drop trigger fail_prepared_target on platform.vulnerability_targets");
        jdbc.update("update platform.intelligence_publication_outbox set visible_at=now() where kind='PUBLISH'");
        long started=System.nanoTime();worker.poll();
        assertEquals("PUBLISHED",publications.candidate(candidate).get("status"));
        assertEquals(1000,count("platform.vulnerabilities"));assertEquals(1000,count("platform.vulnerability_targets"));
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.intelligence_publication_outbox where kind='FANOUT'",Integer.class));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->publications.publish(stale,(String)publications.candidate(stale).get("digest"),null,"stale-review","owner"));
        worker.poll();assertEquals(1,count("platform.intelligence_releases"));
        System.out.println("reviewed_publication_fixture_records=1000 publication_ms="+TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-started));
    }
    private int count(String table) {return jdbc.queryForObject("select count(*) from "+table,Integer.class);}

    @Test @Order(3)
    void buildQuarantinesInvalidObservationSiblingsWithinTheirRunWithoutDuplicatingRows() {
        UUID canonical = UUID.randomUUID();
        String external = "CVE-2099-79999";
        var invalid = syncRuns.createRunningRun("NVD");
        try {
            staging.append("OBSERVATION", external, canonical, "nvd", Map.of(), "INVALID_SCORE");
            staging.append("OBSERVATION", external, canonical, "nvd", Map.of(), "INVALID_IDENTIFIER");
            staging.append("TARGET", external, canonical, "nvd", Map.of(), "VALID");
            staging.append("RULE", external, canonical, "nvd", Map.of(), "INVALID_RULE");
            syncRuns.completeRun(invalid, "completed", 2, 0, 0, 0, null);
        } finally {
            IntelligenceWriteContext.endRun(invalid.getId());
        }
        var valid = syncRuns.createRunningRun("NVD");
        try {
            staging.append("OBSERVATION", external, canonical, "nvd", Map.of(), "VALID");
            staging.append("TARGET", external, canonical, "nvd", Map.of(), "VALID");
            syncRuns.completeRun(valid, "completed", 1, 1, 0, 0, null);
        } finally {
            IntelligenceWriteContext.endRun(valid.getId());
        }

        UUID candidate = (UUID) publications.createCandidate(List.of(valid.getId()), "owner").get("id");
        publications.poll();
        assertEquals("READY", publications.candidate(candidate).get("status"));
        assertEquals(List.of("INVALID_SCORE", "INVALID_IDENTIFIER", "INVALID_CANONICAL_RECORD", "INVALID_RULE"),
                validations(candidate, invalid.getId()));
        assertEquals(List.of("VALID", "VALID"), validations(candidate, valid.getId()));
    }

    private List<String> validations(UUID candidate, UUID run) {
        return jdbc.queryForList("""
                select validation from platform.intelligence_candidate_records
                where candidate_id=? and sync_run_id=? order by staged_record_id
                """, String.class, candidate, run);
    }

    @Test @Order(4)
    void replacesOnlyTargetsAndAssertionsInTheSelectedSourceRecordAndWithdrawalRestoresThem() {
        Vulnerability vulnerability = vulnerabilities.findByExternalId("CVE-2099-80000").orElseThrow();
        String source = "microsoft-vex";
        var initial = syncRuns.createRunningRun("CSAF_MICROSOFT");
        try {
            for (String record : List.of("qualification-remove", "qualification-retain")) {
                IntelligenceWriteContext.sourceRecord(record);
                var target = new VulnerabilityTarget();
                target.setVulnerability(vulnerability);
                target.setTargetType(VulnerabilityTargetType.PURL);
                target.setNormalizedTargetKey("pkg:npm/" + record + "@1");
                target.setSource(source);
                target.setQualifiersJson("""
                        {"vexStatus":"KNOWN_NOT_AFFECTED","vexProvider":"microsoft",
                         "advisoryDocumentId":"%s"}
                        """.formatted(record));
                staging.entity("TARGET", vulnerability, source, target);
            }
            syncRuns.completeRun(initial, "completed", 2, 0, 2, 0, null);
        } finally {
            IntelligenceWriteContext.endRun(initial.getId());
        }
        UUID base = jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class);
        base = publishFixture(initial.getId(), base);
        assertEquals(2, matchingAssertions(vulnerability.getId(), source).size());

        var replace = syncRuns.createRunningRun("CSAF_MICROSOFT");
        try {
            staging.replaceForRecord(vulnerability, List.of(source), "qualification-remove");
            syncRuns.completeRun(replace, "completed", 1, 0, 1, 0, null);
        } finally {
            IntelligenceWriteContext.endRun(replace.getId());
        }
        UUID removed = publishFixture(replace.getId(), base);
        assertEquals(List.of("qualification-retain"), matchingAssertions(vulnerability.getId(), source));
        assertEquals(List.of("qualification-retain"), jdbc.queryForList("""
                select source_record_id from platform.vulnerability_targets where vulnerability_id=? and source=?
                """, String.class, vulnerability.getId(), source));

        publications.withdraw(removed, "restore-scoped-vex", "owner");
        publications.poll();
        assertEquals(List.of("qualification-remove", "qualification-retain"),
                matchingAssertions(vulnerability.getId(), source));
    }

    private UUID publishFixture(UUID run, UUID base) {
        UUID candidate = (UUID) publications.createCandidate(List.of(run), "owner").get("id");
        publications.poll();
        var reviewed = publications.candidate(candidate);
        assertEquals("READY", reviewed.get("status"));
        publications.publish(candidate, (String) reviewed.get("digest"), base, "release:" + run, "owner");
        publications.poll();
        assertEquals("PUBLISHED", publications.candidate(candidate).get("status"));
        return jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class);
    }

    private List<String> matchingAssertions(UUID vulnerability, String source) {
        return jdbc.queryForList("""
                select document_id from platform.vex_assertions where vulnerability_id=? and source_system=?
                order by document_id
                """, String.class, vulnerability, source);
    }
}
