package com.prototype.vulnwatch.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
import com.prototype.vulnwatch.service.DemoInviteEmailService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.InvitationTokens;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantInviteEmailService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@PostgresControllerIntegrationTest
class InvitationTokenPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("invitation_tokens");
    @DynamicPropertySource static void database(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry, DATABASE); }
    @Autowired MockMvc http;
    @Autowired TenantService tenantService;
    @Autowired TenantRepository tenants;
    @Autowired AppUserRepository users;
    @Autowired TenantUserInviteRepository tenantInvites;
    @Autowired TenantUserInviteService tenantServiceInvites;
    @Autowired DemoInviteRepository demoInvites;
    @Autowired DemoRequestRepository requests;
    @Autowired DemoLifecycleService demos;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.prototype.vulnwatch.service.TenantSchemaMigrationService migrations;
    @MockitoBean TenantInviteEmailService tenantEmail;
    @MockitoBean DemoInviteEmailService demoEmail;

    @Test
    void bothInvitationKindsPersistOnlyHashesAndAcceptOnceUnderConcurrency() throws Exception {
        Tenant tenant = activeTenant();
        String tenantToken = UUID.randomUUID().toString();
        TenantUserInvite tenantInvite = tenantInvite(tenant, tenantToken);
        assertEquals(InvitationTokens.hash(tenantToken), tenantInvites.findById(tenantInvite.getId()).orElseThrow().getTokenHash());
        assertNull(tenantInvites.findById(tenantInvite.getId()).orElseThrow().getToken());
        assertEquals(0, jdbc.queryForObject("select count(*) from platform.tenant_user_invites where token is not null", Integer.class));
        assertSingleAcceptance("/api/tenant-invites/accept", tenantToken);

        String demoToken = UUID.randomUUID().toString();
        DemoInvite demoInvite = demoInvite(tenant, demoToken);
        assertNull(TenantContext.runAsPreAuthentication(() -> demoInvites.findById(demoInvite.getId()).orElseThrow().getToken()));
        assertSingleAcceptance("/api/demo-invites/accept", demoToken);
    }

    @Test
    void reissueRotatesHashesAndRetiresOldBearerValuesForBothKinds() throws Exception {
        Tenant tenant = activeTenant();
        String token = UUID.randomUUID().toString();
        TenantUserInvite invite = tenantInvite(tenant, token);
        AtomicReference<String> replacement = new AtomicReference<>();
        when(tenantEmail.sendInvite(any())).thenAnswer(call -> {
            replacement.set(call.getArgument(0, TenantUserInvite.class).getToken());
            return ResendEmailClient.DeliveryResult.skipped("test transport disabled");
        });
        TenantContext.runAsPreAuthentication(() -> tenantServiceInvites.resendInvite(tenant.getId(), invite.getId()));
        assertNotEquals(token, replacement.get());
        assertTrue(status("/api/tenant-invites/validate", token) >= 400);
        assertEquals(200, status("/api/tenant-invites/validate", replacement.get()));

        String demoToken = UUID.randomUUID().toString();
        DemoInvite demo = demoInvite(tenant, demoToken);
        when(demoEmail.sendInvite(any(), any())).thenAnswer(call -> {
            replacement.set(call.getArgument(1, DemoInvite.class).getToken());
            return ResendEmailClient.DeliveryResult.skipped("test transport disabled");
        });
        TenantContext.runAsPreAuthentication(() -> demos.resendInvite(demo.getRequest().getId()));
        assertNotEquals(demoToken, replacement.get());
        assertTrue(status("/api/demo-invites/validate", demoToken) >= 400);
        assertEquals(200, status("/api/demo-invites/validate", replacement.get()));
        assertEquals(410, http.perform(post("/api/demo-invites/legacy-token/accept")).andReturn().getResponse().getStatus());
        assertEquals(410, http.perform(post("/api/tenant-invites/legacy-token/accept")).andReturn().getResponse().getStatus());
    }

    private Tenant activeTenant() {
        String slug="invite-"+UUID.randomUUID().toString().substring(0,8);
        Tenant tenant = tenantService.createTenant(slug,slug,"ENTERPRISE",null);
        migrations.provisionNewTenant(tenant);
        tenant=tenantService.resolveTenantUuid(tenant.getId());
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(Instant.now().plusSeconds(86400));
        return tenants.saveAndFlush(tenant);
    }

    private TenantUserInvite tenantInvite(Tenant tenant, String token) {
        TenantUserInvite invite = new TenantUserInvite();
        invite.setTenant(tenant);
        invite.setEmail(UUID.randomUUID() + "@example.com");
        invite.setExternalSubject(invite.getEmail());
        invite.setRole("TENANT_ADMIN");
        invite.setToken(token);
        invite.setExpiresAt(Instant.now().plusSeconds(3600));
        return tenantInvites.saveAndFlush(invite);
    }

    private DemoInvite demoInvite(Tenant tenant, String token) {
        return TenantContext.runAsPreAuthentication(() -> {
            AppUser user = new AppUser();
            user.setExternalSubject(UUID.randomUUID() + "@example.com");
            user.setEmail(user.getExternalSubject());
            user.setStatus("ACTIVE");
            users.saveAndFlush(user);
            DemoRequest request = new DemoRequest();
            request.setEmail(user.getEmail()); request.setFullName("Invitation Test"); request.setCompany("Example");
            request.setTenantId(tenant.getId()); request = requests.saveAndFlush(request);
            DemoInvite invite = new DemoInvite();
            invite.setRequest(request); invite.setTenant(tenant); invite.setEmail(user.getEmail());
            invite.setToken(token); invite.setExpiresAt(Instant.now().plusSeconds(3600));
            return demoInvites.saveAndFlush(invite);
        });
    }

    private void assertSingleAcceptance(String path, String token) throws Exception {
        var executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            var first = executor.submit(() -> { start.await(); return status(path, token); });
            var second = executor.submit(() -> { start.await(); return status(path, token); });
            start.countDown();
            List<Integer> statuses = List.of(first.get(30, TimeUnit.SECONDS), second.get(30, TimeUnit.SECONDS));
            assertEquals(1, statuses.stream().filter(code -> code == 200).count());
            assertFalse(statuses.stream().anyMatch(code -> code >= 500));
        } finally { executor.shutdownNow(); }
    }

    private int status(String path, String token) throws Exception {
        return http.perform(post(path).contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + token + "\"}")).andReturn().getResponse().getStatus();
    }
}
