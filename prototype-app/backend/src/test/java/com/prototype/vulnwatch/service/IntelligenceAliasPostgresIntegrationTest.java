package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import com.prototype.vulnwatch.support.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
@WithMockUser(roles="PLATFORM_OWNER")
class IntelligenceAliasPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("intelligence_alias");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {PostgresITSupport.registerDatabaseProperties(registry,DB);}
    @Autowired JdbcTemplate jdbc;
    @Autowired IntelligenceStagingService staging;
    @Autowired VulnerabilitySyncRunService runs;
    @Autowired ApplicationContext context;

    @Test void structuredAliasesConsolidateGhsaIdentityWhileMultiCveAndAmbiguousMappingsStayDistinct() {
        var first=runs.createRunningRun("GHSA");
        UUID old=observe("GHSA-AAAA-BBBB-CCCC","GHSA-aaaa-bbbb-cccc","{}");
        runs.completeRun(first,"completed",1,1,0,0,null);
        ReviewedIntelligenceTestSupport.publishAll(context);
        assertEquals(old,jdbc.queryForObject("select id from platform.vulnerabilities where external_id='GHSA-AAAA-BBBB-CCCC'",UUID.class));
        var second=runs.createRunningRun("GHSA");
        UUID canonical=observe("CVE-2099-81001","GHSA-aaaa-bbbb-cccc","{\"identifiers\":[{\"type\":\"CVE\",\"value\":\"CVE-2099-81001\"}]}");
        String multi="{\"identifiers\":[{\"type\":\"CVE\",\"value\":\"CVE-2099-81002\"},{\"type\":\"CVE\",\"value\":\"CVE-2099-81003\"}]}";
        UUID a=observe("CVE-2099-81002","GHSA-DDDD-EEEE-FFFF",multi);
        UUID b=observe("CVE-2099-81003","GHSA-DDDD-EEEE-FFFF",multi);
        runs.completeRun(second,"completed",3,3,0,0,null);
        ReviewedIntelligenceTestSupport.publishAll(context);
        assertEquals(canonical,jdbc.queryForObject("select canonical_id from platform.intelligence_canonical_redirects where id=?",UUID.class,old));
        assertTrue(jdbc.queryForObject("select intelligence_withdrawn from platform.vulnerabilities where id=?",Boolean.class,old));
        assertEquals(canonical,jdbc.queryForObject("select canonical_id from platform.intelligence_identifiers where identifier='GHSA-AAAA-BBBB-CCCC'",UUID.class));
        assertNotEquals(a,b);
        assertEquals(2,jdbc.queryForObject("select count(*) from platform.vulnerability_intel_observations where source_record_id='GHSA-DDDD-EEEE-FFFF'",Integer.class));
        ReviewedIntelligenceTestSupport.withdrawActive(context);
        assertEquals(old,jdbc.queryForObject("select canonical_id from platform.intelligence_identifiers where identifier='GHSA-AAAA-BBBB-CCCC'",UUID.class));
        assertFalse(jdbc.queryForObject("select intelligence_withdrawn from platform.vulnerabilities where id=?",Boolean.class,old));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.intelligence_canonical_redirects where id=?",Integer.class,old));
        var replay=runs.createRunningRun("GHSA");
        assertEquals(old,observe("GHSA-AAAA-BBBB-CCCC","GHSA-aaaa-bbbb-cccc","{}"));
        assertEquals(canonical,observe("CVE-2099-81001","GHSA-aaaa-bbbb-cccc","{\"identifiers\":[{\"type\":\"CVE\",\"value\":\"CVE-2099-81001\"}]}"));
        runs.completeRun(replay,"completed",2,2,0,0,null);
        ReviewedIntelligenceTestSupport.publishAll(context);
        assertEquals(canonical,jdbc.queryForObject("select canonical_id from platform.intelligence_canonical_redirects where id=?",UUID.class,old));
        var conflicting=runs.createRunningRun("GHSA");
        observe("CVE-2099-81004","GHSA-aaaa-bbbb-cccc","{\"identifiers\":[{\"type\":\"CVE\",\"value\":\"CVE-2099-81004\"}]}");
        runs.completeRun(conflicting,"completed",1,1,0,0,null);
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.intelligence_staged_records where sync_run_id=? and validation='AMBIGUOUS_ALIAS'",Integer.class,conflicting.getId()));
        ReviewedIntelligenceTestSupport.publishAll(context);
        assertEquals(canonical,jdbc.queryForObject("select canonical_id from platform.intelligence_identifiers where identifier='GHSA-AAAA-BBBB-CCCC'",UUID.class));
    }
    private UUID observe(String external,String advisory,String payload) {
        return staging.observation(new VulnerabilityIntelligenceService.ObservationUpsertRequest(external,"ghsa",advisory,null,"Offline alias fixture","Incidental CVE-2099-99999 is not an alias","HIGH",8.1,null,null,null,null,null,null,null,null,java.time.Instant.now(),payload)).vulnerability().getId();
    }
}
