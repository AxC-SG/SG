package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.*;
import java.sql.DriverManager;
import java.util.UUID;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Runs against the pre-phase candidate as a red reproduction and the current candidate as its control. */
@PostgresIntegrationTest
class FindingDeltaAtomicPublicationPostgresIntegrationTest {
    static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision(System.getProperty("phase3.atomic.database-key","phase3_delta_atomic_publication"));
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {PostgresITSupport.registerDatabaseProperties(registry,DB);}
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired FindingDeltaQueueService deltas;
    @Autowired PlatformTransactionManager manager;
    @Autowired JdbcTemplate jdbc;
    Tenant tenant;
    @BeforeEach void setup() {
        String slug="delta-atomic-"+UUID.randomUUID().toString().substring(0,8);
        tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);migrations.provisionNewTenant(tenant);tenant=tenants.resolveTenantUuid(tenant.getId());
    }
    long published() {
        try(var connection=DriverManager.getConnection(DB.url(),DB.username(),DB.password());var statement=connection.createStatement();var rows=statement.executeQuery("select count(*) from \""+tenant.getSchemaName()+"\".finding_delta_queue")) {rows.next();return rows.getLong(1);}
        catch(Exception failure) {throw new AssertionError(failure);}
    }
    @Test void rolledBackSourceNeverPublishesOrLeavesIntent() {
        long visibleDuring=scoped.run(tenant,() -> new TransactionTemplate(manager).execute(status -> {
            jdbc.update("update platform.tenants set billing_ref='uncommitted source' where id=?",tenant.getId());
            deltas.enqueueNoiseReductionRefresh(tenant.getId(),"atomic-publication-test");
            long visible=published();status.setRollbackOnly();return visible;
        }));
        assertAll(() -> assertEquals(0,visibleDuring,"consumer must not see intent before source commit"),
                () -> assertEquals(0,published(),"rolled-back source must leave no pending intent"),
                () -> assertEquals(tenant.getBillingRef(),tenants.resolveTenantUuid(tenant.getId()).getBillingRef()));
    }
    @Test void committedSourcePublishesOneIntent() {
        scoped.run(tenant,() -> new TransactionTemplate(manager).executeWithoutResult(status -> {
            jdbc.update("update platform.tenants set billing_ref='committed source' where id=?",tenant.getId());
            deltas.enqueueNoiseReductionRefresh(tenant.getId(),"atomic-publication-test");
        }));
        assertEquals(1,published());assertEquals("committed source",tenants.resolveTenantUuid(tenant.getId()).getBillingRef());
    }
}
