package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomUploadRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariDataSource;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
class BomUploadPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("durable_bom_uploads");
    private static final BomUploadRequest REQUEST = new BomUploadRequest(BomType.SBOM, AssetType.APPLICATION,
            "Synthetic asset", "bom-upload-test", null, "fixture.json", 21,
            "zadF0MgpQ6R/vPDzwdEGdn0PFllM0VmEiLuiL0OZyhA=", null, null);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.runtime.role", () -> "api");
    }

    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scopes;
    @Autowired BomUploadService uploads;
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper mapper;
    @Autowired IngestionJobService jobs;
    @Autowired TenantQuotaService quotas;
    @Autowired BomIngestionOrchestrator orchestrator;
    @Autowired @Qualifier("hikariDataSource") HikariDataSource database;
    @MockitoBean BomUploadStorage storage;

    @Test
    void duplicateCompletionCreatesOneJobAndAnotherTenantCannotReadTheIntent() throws Exception {
        Fixture original = fixture();
        Fixture other = fixture();
        when(storage.sign(anyString(), anyLong(), anyString(), any()))
                .thenReturn(new BomUploadStorage.SignedPut("https://example.test/signed", Map.of()));
        when(storage.verifiedVersion(anyString(), anyLong(), anyString())).thenReturn("immutable-version-1");
        UUID key = UUID.randomUUID();
        UUID uploadId = uploads.create(original.tenant(), original.actor(), key, REQUEST).upload().uploadId();
        assertEquals(uploadId, uploads.create(original.tenant(), original.actor(), key, REQUEST).upload().uploadId());
        assertEquals(HttpStatus.NOT_FOUND, assertThrows(ResponseStatusException.class,
                () -> uploads.get(other.tenant(), other.actor(), uploadId)).getStatusCode());

        var pool = Executors.newFixedThreadPool(2);
        var start = new CyclicBarrier(2);
        try {
            java.util.concurrent.Callable<UUID> complete = () -> {
                start.await(10, TimeUnit.SECONDS);
                return uploads.complete(original.tenant(), original.actor(), uploadId).jobId();
            };
            var first = pool.submit(complete);
            var second = pool.submit(complete);
            UUID jobId = first.get(20, TimeUnit.SECONDS);
            assertNotNull(jobId);
            assertEquals(jobId, second.get(20, TimeUnit.SECONDS));
            assertEquals(jobId, uploads.get(original.tenant(), original.actor(), uploadId).jobId());
        } finally {
            pool.shutdownNow();
        }
        scopes.run(original.tenant(), () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs where job_type='BOM_UPLOAD'", Integer.class));
            assertEquals("immutable-version-1", jdbc.queryForObject(
                    "select object_version from bom_upload_intents where id=?", String.class, uploadId));
        });

        var accepted = jobs.loadJob(original.tenant().getId(), uploads.get(original.tenant(), original.actor(), uploadId).jobId());
        jdbc.update("update platform.tenant_memberships set status='REVOKED' where tenant_id=?", original.tenant().getId());
        assertEquals(HttpStatus.FORBIDDEN, assertThrows(ResponseStatusException.class,
                () -> uploads.prepare(original.tenant(), accepted)).getStatusCode());
        verify(storage, never()).read(anyString(), anyString(), org.mockito.ArgumentMatchers.anyInt(), anyString());
    }

    @Test
    void aSecondWorkerCannotClaimAcrossTenantsWhileTheGlobalUploadSlotIsHeld() {
        Fixture first = fixture();
        Fixture second = fixture();
        when(storage.configured()).thenReturn(true);
        when(storage.sign(anyString(), anyLong(), anyString(), any()))
                .thenReturn(new BomUploadStorage.SignedPut("https://example.test/signed", Map.of()));
        when(storage.verifiedVersion(anyString(), anyLong(), anyString())).thenReturn("immutable-version");
        for (Fixture fixture : Set.of(first, second)) {
            var intent = uploads.create(fixture.tenant(), fixture.actor(), UUID.randomUUID(), REQUEST).upload();
            uploads.complete(fixture.tenant(), fixture.actor(), intent.uploadId());
        }
        var secondWorker = new BomUploadService(jdbc, mapper, storage, scopes, jobs, quotas, orchestrator, database);
        assertTrue(uploads.withWorkerSlot(first.tenant(), () -> {
            assertFalse(secondWorker.withWorkerSlot(second.tenant(), () -> {
                throw new AssertionError("second worker entered the occupied global slot");
            }));
            return true;
        }));
        assertTrue(secondWorker.withWorkerSlot(second.tenant(), () -> true));
    }

    private Fixture fixture() {
        String slug = "uploads-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        Tenant ready = tenants.resolveTenantUuid(tenant.getId());
        UUID user = UUID.randomUUID();
        String subject = user.toString();
        jdbc.update("""
                insert into platform.app_users(id,external_subject,status,platform_owner,created_at,updated_at)
                values (?,?,'ACTIVE',false,now(),now())
                """, user, subject);
        jdbc.update("""
                insert into platform.tenant_memberships(id,tenant_id,user_id,role,status,created_at,updated_at)
                values (?,?,?,'TENANT_ADMIN','ACTIVE',now(),now())
                """, UUID.randomUUID(), ready.getId(), user);
        return new Fixture(ready, new RequestActor(subject, false, ready.getId(), ready.getName(),
                Set.of("TENANT_ADMIN"), TenantAccessMode.TENANT_MEMBERSHIP, null, null));
    }

    private record Fixture(Tenant tenant, RequestActor actor) { }
}
