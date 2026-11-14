package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class AiSecurityAzureCredentialPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_azure_credentials");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private AiSecurityAzureCredentialService credentials;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    @MockitoBean private IngestionJobWorkerService ingestionJobWorkerService;
    @MockitoBean private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void encryptsSecretsAndRejectsCrossTenantResolutionAndRevokedUse() {
        Tenant first = provision("Azure AI First", "azure-ai-first");
        Tenant second = provision("Azure AI Second", "azure-ai-second");
        String plaintext = "pilot-secret-value";

        var profile = credentials.create(
                first,
                new AiSecurityAzureCredentialService.CredentialProfileRequest(
                        "Pilot credential",
                        "11111111-1111-1111-1111-111111111111",
                        "22222222-2222-2222-2222-222222222222",
                        plaintext,
                        Instant.now().plus(30, ChronoUnit.DAYS)),
                "tenant-admin");

        String stored = tenantExecution.run(first, () -> jdbc.queryForObject("""
                select active_secret_ciphertext
                  from ai_security_azure_credential_profiles
                 where id = :id
                """, Map.of("id", profile.id()), String.class));
        assertNotEquals(plaintext, stored);
        assertTrue(stored.startsWith("enc:v2:"));
        assertThrows(ResponseStatusException.class, () -> credentials.secret(second, profile.id()));

        credentials.revoke(first, profile.id(), "tenant-admin");
        assertThrows(ResponseStatusException.class, () -> credentials.secret(first, profile.id()));
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenants.createTenant(name, slug, "pilot", null);
        migrations.provisionNewTenant(tenant);
        return tenant;
    }
}
