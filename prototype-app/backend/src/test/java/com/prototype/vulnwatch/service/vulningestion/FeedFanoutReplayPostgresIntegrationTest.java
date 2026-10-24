package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.*;
import java.util.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Shared publication paths used by the retained NVD/GHSA/CSAF/KEV/EUVD/JVN producers. */
@PostgresIntegrationTest
class FeedFanoutReplayPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("phase3_feed_fanout");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry){PostgresITSupport.registerDatabaseProperties(registry,DB);}
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired VulnerabilityRepository vulnerabilities;
    @Autowired VulnerabilityIngestionEffectsService effects;
    @Autowired JdbcTemplate jdbc;
    @AfterEach void clear(){TenantContext.clear();}

    @ParameterizedTest @ValueSource(strings={"CVE","METADATA","VEX"})
    void normalizationCannotFanOutBeforeReviewedPublication(String type){
        Tenant first=tenant(),second=tenant();
        Vulnerability vulnerability=new Vulnerability();vulnerability.setExternalId("CVE-2099-"+UUID.randomUUID());
        vulnerability.setSource(VulnerabilitySource.NVD);vulnerability.setTitle("Offline fanout fixture");
        UUID id=vulnerabilities.save(vulnerability).getId();
        scoped.run(second,()->{
            jdbc.execute("create function fail_publication() returns trigger language plpgsql as $$ begin raise exception 'offline tenant unavailable';end $$");
            jdbc.execute("create trigger fail_publication before insert on finding_delta_queue for each row execute function fail_publication()");
        });
        TenantContext.runAsPlatform(()->publish(type,id));
        assertEquals(0,queued(first));assertEquals(0,queued(second));
        assertTrue(vulnerabilities.findById(id).isPresent());
        scoped.run(second,()->jdbc.execute("drop trigger fail_publication on finding_delta_queue"));
        TenantContext.runAsPlatform(()->publish(type,id));
        assertEquals(0,queued(first));assertEquals(0,queued(second));
    }
    private int publish(String type,UUID id){return switch(type){case "CVE"->effects.recomputeCveDeltas(List.of(id));case "METADATA"->effects.enqueueCveMetadataDeltas(List.of(id));case "VEX"->effects.applyVexDeltas(List.of(id),"offline-provider");default->throw new IllegalArgumentException(type);};}
    private int queued(Tenant tenant){return scoped.run(tenant,()->jdbc.queryForObject("select count(*) from finding_delta_queue",Integer.class));}
    private Tenant tenant(){String slug="fanout-"+UUID.randomUUID().toString().substring(0,8);Tenant tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);migrations.provisionNewTenant(tenant);return tenants.resolveTenantUuid(tenant.getId());}
}
