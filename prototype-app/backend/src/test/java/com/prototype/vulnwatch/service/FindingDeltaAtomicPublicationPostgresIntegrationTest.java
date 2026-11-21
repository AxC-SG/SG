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
    @Autowired InventoryRollupWorker rollups;
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

    @Test
    void inventoryCutoverQueuesOnlyCommittedSemanticChangesAndKeepsLegacySchedulingAvailable() {
        UUID asset = UUID.randomUUID();
        UUID upload = UUID.randomUUID();
        UUID component = UUID.randomUUID();
        UUID cpe = UUID.randomUUID();
        UUID mapping = UUID.randomUUID();
        UUID identity = UUID.randomUUID();
        TransactionTemplate transactions = new TransactionTemplate(manager);

        scoped.run(tenant, () -> transactions.executeWithoutResult(status -> {
            assertFalse(deltas.usesIncrementalInventoryCorrelation(tenant.getId()));
            long revision = requiredRevision();
            jdbc.update("""
                    insert into assets (id, business_criticality, created_at, identifier, name, state, type, environment)
                    values (?, 'HIGH', now(), ?, 'Inventory fixture', 'ACTIVE', 'APPLICATION', 'test')
                    """, asset, asset.toString());
            jdbc.update("""
                    insert into sbom_uploads (id, asset_id, format, original_filename, status, uploaded_at)
                    values (?, ?, 'HOST_INVENTORY', 'inventory.json', 'SUCCESS', now())
                    """, upload, asset);
            jdbc.update("""
                    insert into platform.software_identities (id, canonical_key, display_name, vendor, product,
                                                              created_at, updated_at)
                    values (?, ?, 'Inventory fixture', 'test', 'fixture', now(), now())
                    """, identity, identity.toString());
            jdbc.update("""
                    insert into inventory_components (id, component_status, ecosystem, package_name, purl,
                                                      version, asset_id, sbom_upload_id, software_identity_id,
                                                      ingested_at, last_observed_at)
                    values (?, 'ACTIVE', 'maven', 'fixture', 'pkg:maven/test/fixture@1', '1', ?, ?, ?, now(), now())
                    """, component, asset, upload, identity);
            assertEquals(revision + 1, requiredRevision());
            assertEquals(0, published());
            jdbc.update("""
                    insert into inventory_correlation_settings (tenant_id, inventory_incremental_correlation_enabled)
                    values (?, true)
                    """, tenant.getId());
        }));

        scoped.run(tenant, () -> transactions.executeWithoutResult(status -> {
            assertTrue(deltas.usesIncrementalInventoryCorrelation(tenant.getId()));
            long revision = requiredRevision();
            jdbc.update("update inventory_components set last_observed_at = now() where id = ?", component);
            assertEquals(revision, requiredRevision());
            assertEquals(0, jdbc.queryForObject("select count(*) from finding_delta_queue", Integer.class));
            jdbc.update("update inventory_components set version = '2' where id = ?", component);
            assertEquals(0, published());
            assertEquals(1, jdbc.queryForObject("select count(*) from inventory_rollup_queue", Integer.class));
            status.setRollbackOnly();
        }));
        assertEquals(0, published());

        scoped.run(tenant, () -> transactions.executeWithoutResult(status -> {
            long revision = requiredRevision();
            jdbc.update("update inventory_components set version = '2' where id = ?", component);
            jdbc.update("""
                    insert into platform.cpe_dim (id, raw_cpe, normalized_cpe, part, vendor, product, cpe_key,
                                                  created_at, updated_at)
                    values (?, ?, ?, 'a', 'test', 'fixture', ?, now(), now())
                    """, cpe, cpe.toString(), cpe.toString(), cpe.toString());
            jdbc.update("""
                    insert into inventory_component_cpe_map (id, component_id, cpe_id, first_seen_at, last_seen_at)
                    values (?, ?, ?, now(), now())
                    """, mapping, component, cpe);
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_delta_queue
                    where component_id = ? and event_type = 'SOFTWARE_DELTA' and status = 'PENDING'
                    """, Integer.class, component));
            assertEquals(revision, requiredRevision());
            assertEquals(1, jdbc.queryForObject("select count(*) from inventory_rollup_queue", Integer.class));
            assertEquals(0, jdbc.queryForObject("select count(*) from software_identity_summary", Integer.class));
        }));
        assertEquals(1, published());
        rollups.drainBatch(tenant);
        scoped.run(tenant, () -> transactions.executeWithoutResult(status -> {
            assertEquals(0, jdbc.queryForObject("select count(*) from inventory_rollup_queue", Integer.class));
            assertEquals(1, jdbc.queryForObject("""
                    select component_count from software_identity_summary where software_identity_id = ?
                    """, Integer.class, identity));
        }));

        scoped.run(tenant, () -> transactions.executeWithoutResult(status -> {
            jdbc.update("update finding_delta_queue set status = 'PROCESSING' where component_id = ?", component);
            jdbc.update("update inventory_component_cpe_map set last_seen_at = now() where id = ?", mapping);
            assertEquals(0, jdbc.queryForObject("select count(*) from finding_delta_queue where status = 'PENDING'",
                    Integer.class));
            jdbc.update("delete from inventory_component_cpe_map where id = ?", mapping);
            assertEquals(1, jdbc.queryForObject("select count(*) from finding_delta_queue where status = 'PENDING'",
                    Integer.class));
            long revision = requiredRevision();
            jdbc.update("update vulnerability_source_filter_configs set enabled_for_correlation = false where source_system = 'nvd'");
            assertEquals(revision + 1, requiredRevision());
            jdbc.update("update inventory_correlation_settings set inventory_incremental_correlation_enabled = false");
            assertFalse(deltas.usesIncrementalInventoryCorrelation(tenant.getId()));
            jdbc.update("update inventory_components set version = '3' where id = ?", component);
            assertEquals(revision + 2, requiredRevision());
        }));
        assertEquals(2, published());
    }

    private long requiredRevision() {
        return jdbc.queryForObject("select required_revision from platform.tenant_intelligence_processing where tenant_id = ?",
                Long.class, tenant.getId());
    }
}
