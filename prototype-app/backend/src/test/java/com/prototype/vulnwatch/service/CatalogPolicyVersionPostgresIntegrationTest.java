package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicy.*;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.Set;
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

@SpringBootTest(properties = {"app.runtime.role=api", "app.correlation.backfill-targets-on-startup=false"})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CatalogPolicyVersionPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("catalog_policy_versions");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url); registry.add("DB_USERNAME", DATABASE::username); registry.add("DB_PASSWORD", DATABASE::password);
    }
    @Autowired CatalogPolicyVersionService versions;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaExecutionService schemas;
    @Autowired TenantWorkRunner work;
    @Autowired JdbcTemplate jdbc;
    @MockBean RequestActorService actors;
    @Autowired CatalogOverrideService overrides;
    @Autowired com.prototype.vulnwatch.controller.CatalogOverrideController overrideController;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityRepository vulnerabilities;

    @Test void overrideHistoryIsImmutableAndAuditFailureRollsBackRestore() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            doReturn(new RequestActor("override-test", false, tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN"))).when(actors).currentActor();
            var record = new com.prototype.vulnwatch.domain.Vulnerability();
            record.setExternalId("CVE-2026-OVERRIDE"); record.setTitle("Override fixture"); record.setSeverity("HIGH");
            record.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
            var id = vulnerabilities.saveAndFlush(record).getId();
            var exclude = new CatalogOverrideService.Change(0L, CatalogOverrideService.Operation.EXCLUDE, "Outside scope", null);
            var entry = schemas.run(tenant, () -> overrides.change(id, exclude));
            assertEquals(1, entry.revision());
            assertEquals(CatalogOverrideService.Operation.EXCLUDE, entry.operation());
            assertEquals(409, assertThrows(ResponseStatusException.class,
                    () -> schemas.run(tenant, () -> overrides.change(id, exclude))).getStatusCode().value());
            assertThrows(org.springframework.dao.DataAccessException.class, () -> work.runScoped(tenant,
                    () -> jdbc.update("delete from intelligence_catalog_overrides where vulnerability_id=?", id)));
            var restore = new CatalogOverrideService.Change(1L, CatalogOverrideService.Operation.RESTORE, "Back in scope", null);
            when(actors.currentActor()).thenThrow(new IllegalStateException("audit unavailable"));
            assertThrows(IllegalStateException.class, () -> schemas.run(tenant, () -> overrides.change(id, restore)));
            assertEquals(1, schemas.run(tenant, () -> overrides.history(id, null)).size());
            doReturn(new RequestActor("override-test", false, tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN"))).when(actors).currentActor();
            assertEquals(2, schemas.run(tenant, () -> overrides.change(id, restore)).revision());
            assertEquals(1, schemas.run(tenant, () -> overrides.history(id, 2L)).get(0).revision());
            jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?", id);
            assertEquals(409, assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> overrides.change(id, new CatalogOverrideService.Change(2L, CatalogOverrideService.Operation.INCLUDE, "Include", null)))).getStatusCode().value());
            assertEquals(400, assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> overrides.change(id, new CatalogOverrideService.Change(2L, CatalogOverrideService.Operation.EXCLUDE, "", null)))).getStatusCode().value());
            assertEquals(400, assertThrows(ResponseStatusException.class, () -> schemas.run(tenant,
                    () -> overrides.change(id, new CatalogOverrideService.Change(2L, CatalogOverrideService.Operation.EXCLUDE, "Expired", java.time.Instant.EPOCH)))).getStatusCode().value());
            assertTrue(vulnerabilities.findById(id).isPresent());
        });
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "SECURITY_ANALYST")
    void analystCannotChangeOrReadAdministrativeOverrides() {
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> overrideController.change(java.util.UUID.randomUUID(), null));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> overrideController.history(java.util.UUID.randomUUID(), null));
    }

    @Test void savesImmutableVersionsRejectsStaleWritesAndRollsBackAuditFailure() {
        TenantContext.runAsPlatform(() -> {
            var tenant = tenants.getDefaultTenant();
            when(actors.currentActor()).thenReturn(new RequestActor("catalog-test", false, tenant.getId(), tenant.getName(), Set.of("TENANT_ADMIN")));
            var policy = new CatalogPolicy(1, Set.of("nvd"), false, ScoreResolution.MAX_ALLOWED_OBSERVATION_V1,
                    new Rule(Op.GT, Field.CVSS, 6.0, null, null));
            var saved = schemas.run(tenant, () -> versions.save(0L, policy));
            assertEquals(1, saved.version());
            assertEquals(64, saved.sha256().length());
            assertEquals(policy, saved.policy());
            assertEquals(1, schemas.run(tenant, () -> versions.list()).size());
            var conflict = assertThrows(ResponseStatusException.class, () -> schemas.run(tenant, () -> versions.save(0L, policy)));
            assertEquals(409, conflict.getStatusCode().value());
            work.runScoped(tenant, () -> assertEquals(1, jdbc.queryForObject(
                    "select count(*) from audit_events where action='tenant.intelligence_catalog_policy.saved'", Integer.class)));
            assertThrows(org.springframework.dao.DataAccessException.class, () -> work.runScoped(tenant,
                    () -> jdbc.update("delete from intelligence_catalog_policy_versions where version=1")));
            when(actors.currentActor()).thenThrow(new IllegalStateException("simulated audit failure"));
            assertThrows(IllegalStateException.class, () -> schemas.run(tenant, () -> versions.save(1L, policy)));
            assertEquals(1, schemas.run(tenant, () -> versions.list()).size());
        });
    }

    @Test void platformContextCannotAccessTenantVersions() {
        TenantContext.runAsPlatform(() -> assertThrows(ResponseStatusException.class, () -> versions.list()));
        TenantContext.runAsPlatform(() -> assertThrows(ResponseStatusException.class,
                () -> overrides.history(java.util.UUID.randomUUID(), null)));
    }
}
