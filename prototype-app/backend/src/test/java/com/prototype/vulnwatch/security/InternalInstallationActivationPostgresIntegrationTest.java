package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.migration.ProductionBootstrapCli;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties={"app.runtime.role=api","app.security.allow-api-key-auth=false","app.correlation.backfill-targets-on-startup=false"})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named="run.postgres.it",matches="true")
class InternalInstallationActivationPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE=installation();
    private static LocalPostgresTestDatabase.DatabaseConfig installation() {
        var database=LocalPostgresTestDatabase.provision("internal_installation_activation");
        Map<String,String> properties=new LinkedHashMap<>();
        properties.put("DB_URL",database.url());properties.put("DB_USERNAME",database.username());properties.put("DB_PASSWORD",database.password());
        properties.put("RUNTIME_DB_USERNAME","sg_internal_activation_runtime");properties.put("RUNTIME_DB_PASSWORD","test-only-runtime-password");
        properties.put("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED","true");properties.put("PLATFORM_OWNER_SETUP_EMAIL","installation-owner@example.test");
        properties.put("SG_INTERNAL_ADMIN_EMAIL","installation-admin@example.test");properties.put("APP_CREDENTIAL_ENCRYPTION_KEY",Base64.getEncoder().encodeToString(new byte[32]));
        properties.put("PLATFORM_OWNER_SETUP_APP_BASE_URL","https://example.test");
        try {
            properties.forEach(System::setProperty);
            ProductionBootstrapCli.main(new String[0]);ProductionBootstrapCli.main(new String[0]);
        } catch(Exception failure) { throw new IllegalStateException("Disposable installation bootstrap failed",failure); }
        finally { properties.keySet().forEach(System::clearProperty); }
        return database;
    }
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) {
        registry.add("DB_URL",DATABASE::url);registry.add("DB_USERNAME",DATABASE::username);registry.add("DB_PASSWORD",DATABASE::password);
    }
    @Autowired JdbcTemplate jdbc;
    @Autowired CredentialEncryptionService encryption;
    @Autowired ObjectMapper mapper;
    @Autowired LocalCredentialAuthService auth;
    @Autowired MockMvc http;

    @Test void bothAccountsActivateIndependentlyWithSeparateAuthorityAndNoAutomaticOwnerTenantAccess() throws Exception {
        assertEquals(2,jdbc.queryForObject("select count(*) from platform.app_users",Integer.class));
        assertEquals(2,jdbc.queryForObject("select count(*) from platform.invitation_email_outbox",Integer.class));
        assertEquals(0,jdbc.queryForObject("select count(*) from platform.tenant_memberships m join platform.app_users u on u.id=m.user_id where u.platform_owner and m.status='ACTIVE'",Integer.class));
        String adminToken=activationToken("INTERNAL_ADMIN_SETUP");
        String adminSession=TenantContext.runAsPreAuthentication(() -> auth.exchangePasswordSetupToken(adminToken));
        var admin=TenantContext.runAsPreAuthentication(() -> auth.setupPassword(adminSession,"Internal-test-password-2026!"));
        assertEquals(1,jdbc.queryForObject("select count(*) from platform.app_users where password_hash is not null",Integer.class));
        http.perform(get("/api/platform/intelligence/releases").header("Authorization","Bearer "+admin.token())).andExpect(status().isForbidden());
        String ownerToken=activationToken("PLATFORM_OWNER_SETUP");
        String ownerSession=TenantContext.runAsPreAuthentication(() -> auth.exchangePasswordSetupToken(ownerToken));
        var owner=TenantContext.runAsPreAuthentication(() -> auth.setupPassword(ownerSession,"Owner-test-password-2026!"));
        http.perform(get("/api/platform/intelligence/releases").header("Authorization","Bearer "+owner.token())).andExpect(status().isOk());
        http.perform(get("/api/assets").header("Authorization","Bearer "+owner.token())).andExpect(status().isForbidden());
        assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> TenantContext.runAsPreAuthentication(() -> auth.exchangePasswordSetupToken(ownerToken)));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,() -> TenantContext.runAsPreAuthentication(() -> auth.setupPassword(ownerSession,"Replayed-test-password!")));
        assertEquals(2,jdbc.queryForObject("select count(*) from platform.app_users where password_hash is not null",Integer.class));
    }
    private String activationToken(String type) throws Exception {
        String encrypted=jdbc.queryForObject("select encrypted_payload from platform.invitation_email_outbox where delivery_type=?",String.class,type);
        var message=mapper.readValue(encryption.decrypt(encrypted),ResendEmailClient.EmailMessage.class);
        assertEquals("Complete your SG account setup",message.subject());assertTrue(message.tags().isEmpty());
        assertFalse(message.text().contains("tenant_default"));assertFalse(message.text().contains("PLATFORM_OWNER"));
        var match=java.util.regex.Pattern.compile("/setup#token=([0-9a-f-]+)").matcher(message.text());assertTrue(match.find());return match.group(1);
    }
}
