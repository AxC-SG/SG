package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.*;
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

    @Test void thousandRecordPublicationRollsBackRetriesAndSerializesDuplicateApproval() throws Exception {
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
}
