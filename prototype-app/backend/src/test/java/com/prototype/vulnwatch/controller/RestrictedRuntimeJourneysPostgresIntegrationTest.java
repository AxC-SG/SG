package com.prototype.vulnwatch.controller;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.config.JwtDecoderConfig;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.migration.ProductionBootstrapCli;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.*;
import com.zaxxer.hikari.HikariDataSource;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.*;

/** Bootstrap owns fixture DDL; real MVC/JWT/registry journeys use the bootstrap-provisioned runtime role. */
@PostgresControllerIntegrationTest
class RestrictedRuntimeJourneysPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB=LocalPostgresTestDatabase.provision("phase3_runtime_journeys");
    private static final String SIGNING_MATERIAL=UUID.randomUUID().toString()+UUID.randomUUID();
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry){
        PostgresITSupport.registerDatabaseProperties(registry,DB);registry.add("APP_JWT_HMAC_SECRET",()->SIGNING_MATERIAL);
        registry.add("app.entitlements.mode", () -> "ENFORCE");
        registry.add("app.entitlements.enforce-tenant-allowlist", () -> "slug:closure-entitlement");
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired AppUserRepository users;
    @Autowired TenantMembershipRepository memberships;
    @Autowired TenantUserInviteRepository invites;
    @Autowired TenantSupportGrantRepository grants;
    @Autowired ServiceAccountRepository accounts;
    @Autowired JwtTenantAuthenticationService authentication;
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired HikariDataSource pool;
    @Autowired JdbcTemplate jdbc;
    @Autowired TenantSchemaStatusService schemaStatus;
    Tenant tenant;
    JdbcTemplate owner;
    String runtimeRole;
    String memberEmail;
    String ownerEmail;
    String invitedEmail;
    String inviteToken;
    String machine;
    UUID support;

    @BeforeEach void setup() throws Exception {
        TenantContext.clear();
        owner=new JdbcTemplate(new DriverManagerDataSource(DB.url(),DB.username(),DB.password()));
        String slug="journey-"+UUID.randomUUID().toString().substring(0,8);
        tenant=tenants.createTenant(slug,slug,"ENTERPRISE",null);migrations.provisionNewTenant(tenant);
        tenant=tenants.resolveTenantUuid(tenant.getId());
        memberEmail=slug+"@example.test";ownerEmail="owner-"+memberEmail;invitedEmail="invited-"+memberEmail;
        AppUser member=user(memberEmail,false),platformOwner=user(ownerEmail,true);
        TenantMembership membership=new TenantMembership();membership.setTenant(tenant);membership.setUser(member);
        membership.setRole("TENANT_ADMIN");membership.setStatus("ACTIVE");memberships.save(membership);
        TenantSupportGrant grant=new TenantSupportGrant();grant.setTenant(tenant);grant.setInvitedPlatformSubject(ownerEmail);
        grant.setReason("Offline qualification");grant.setScope("Read-only workspace");grant.setAccessMode("READ_ONLY");
        grant.setStatus("ACTIVE");grant.setGrantedBy(platformOwner);grant.setAcceptedBy(platformOwner);
        grant.setRequestedAt(Instant.now());grant.setAcceptedAt(Instant.now());grant.setExpiresAt(Instant.now().plusSeconds(3600));grant.setUpdatedAt(Instant.now());
        support=grants.save(grant).getId();
        inviteToken="offline-"+UUID.randomUUID();
        TenantUserInvite invite=new TenantUserInvite();invite.setTenant(tenant);invite.setEmail(invitedEmail);
        invite.setExternalSubject(invitedEmail);invite.setRole("READ_ONLY_AUDITOR");invite.setToken(inviteToken);
        invite.setStatus("QUEUED");invite.setExpiresAt(Instant.now().plusSeconds(3600));invites.save(invite);
        machine="machine-"+UUID.randomUUID();
        scoped.run(tenant,()->{ServiceAccount account=new ServiceAccount();account.setTenant(tenant);account.setName("Offline producer");
            account.setKeyId(machine);account.setRole("SERVICE_ACCOUNT");accounts.save(account);});
        runtimeRole="journey_"+UUID.randomUUID().toString().replace("-","");
        String password=UUID.randomUUID().toString();
        try(var connection=DriverManager.getConnection(DB.url(),DB.username(),DB.password())){
            ReflectionTestUtils.invokeMethod(ProductionBootstrapCli.class, "provisionRuntimeRole",
                    connection, runtimeRole, password, 0);
        }
        pool.getHikariConfigMXBean().setUsername(runtimeRole);pool.getHikariConfigMXBean().setPassword(password);
        pool.getHikariPoolMXBean().softEvictConnections();
        assertEquals(runtimeRole,jdbc.queryForObject("select current_user",String.class));
        assertFalse(jdbc.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname=current_user",Boolean.class));
    }

    @AfterEach void cleanup(){
        TenantContext.clear();
        pool.getHikariConfigMXBean().setUsername(DB.username());pool.getHikariConfigMXBean().setPassword(DB.password());
        pool.getHikariPoolMXBean().softEvictConnections();
        if (runtimeRole != null && Boolean.TRUE.equals(owner.queryForObject(
                "select exists (select 1 from pg_roles where rolname = ?)", Boolean.class, runtimeRole))) {
            owner.execute("drop owned by " + runtimeRole);
            owner.execute("drop role " + runtimeRole);
        }
    }

    @Test void localLoginWorkspaceAndRevocationUseRestrictedConnections() throws Exception {
        String token=login(memberEmail);
        mvc.perform(get("/api/auth/context").header("Authorization","Bearer "+token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()));
        owner.update("update platform.app_users set status='INACTIVE' where external_subject=?",memberEmail);
        mvc.perform(get("/api/auth/context").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
    }

    @Test void supportContextCannotSurviveGrantRevocation() throws Exception {
        String platformToken=login(ownerEmail);
        MvcResult selected=mvc.perform(post("/api/auth/tenant-context").header("Authorization","Bearer "+platformToken)
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("tenantId",tenant.getId()))))
                .andExpect(status().isOk()).andReturn();
        String tenantToken=mapper.readTree(selected.getResponse().getContentAsString()).path("token").asText();
        mvc.perform(get("/api/auth/context").header("Authorization","Bearer "+tenantToken)).andExpect(status().isOk())
                .andExpect(jsonPath("$.supportAccessMode").value("READ_ONLY"));
        owner.update("update platform.tenant_support_grants set status='REVOKED',revoked_at=now() where id=?",support);
        mvc.perform(get("/api/auth/context").header("Authorization","Bearer "+tenantToken)).andExpect(status().is4xxClientError());
    }

    @Test void entitlementEnforcementAndContextAgreeAtTheRetainedApiBoundary() throws Exception {
        owner.update("update platform.tenants set slug='closure-entitlement' where id=?", tenant.getId());
        String token = login(memberEmail);
        mvc.perform(get("/api/auth/context").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.entitlements['ai.security']").value(false));
        mvc.perform(get("/api/ai-systems").header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        owner.update("""
                insert into platform.tenant_entitlement_overrides
                  (id,tenant_id,entitlement_key,enabled,config_json,reason,created_at,updated_at)
                values (?,?,'ai.security',true,'{}','Controlled fixture',now(),now())
                """, UUID.randomUUID(), tenant.getId());
        mvc.perform(get("/api/auth/context").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.entitlements['ai.security']").value(true));
        mvc.perform(get("/api/ai-systems").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        // An entitlement cannot re-enable independent server containment.
        for (String path : List.of("azure-discovery")) {
            mvc.perform(post("/api/connectors/" + path + "/test").header("Authorization", "Bearer " + token))
                    .andExpect(status().isGone());
        }
        owner.update("update platform.tenant_entitlement_overrides set expires_at=now()-interval '1 second' where tenant_id=?", tenant.getId());
        mvc.perform(get("/api/ai-systems").header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        owner.update("update platform.tenants set slug=? where id=?", "outside-" + tenant.getId(), tenant.getId());
        mvc.perform(get("/api/auth/context").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.entitlements['ai.security']").value(true));
        mvc.perform(get("/api/ai-systems").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
    }

    @Test void auditExportIsTenantScopedEncodedAndHasNoMutationRoute() throws Exception {
        String token = login(memberEmail);
        scoped.run(tenant, () -> jdbc.update("""
                insert into audit_events(id,tenant_id,occurred_at,actor_subject,action,target_type,details_json,outcome)
                values (?,?,now(),'=controlled-formula','closure.audit','tenant','{"text":"controlled fixture"}','SUCCESS')
                """, UUID.randomUUID(), tenant.getId()));
        MvcResult export = mvc.perform(get("/api/audit-events/export").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn();
        assertTrue(export.getResponse().getContentAsString().contains("\"'=controlled-formula\""));
        scoped.run(tenant, () -> assertEquals(1, jdbc.queryForObject("select count(*) from audit_events where action='audit_events.exported'", Integer.class)));
        for (var request : List.of(put("/api/audit-events"), delete("/api/audit-events"))) {
            mvc.perform(request.header("Authorization", "Bearer " + token)).andExpect(status().isMethodNotAllowed());
        }
        owner.update("update platform.tenant_memberships set status='REVOKED' where tenant_id=? and user_id=(select id from platform.app_users where external_subject=?)", tenant.getId(), memberEmail);
        mvc.perform(get("/api/audit-events/export").header("Authorization", "Bearer " + token)).andExpect(status().isForbidden());
        // Even a manually selected wrong setting cannot expose this schema's audit rows under RLS.
        try (var connection = pool.getConnection(); var statement = connection.createStatement()) {
            statement.execute("select set_config('search_path','" + tenant.getSchemaName() + ",platform',false)");
            statement.execute("select set_config('app.current_tenant_id','" + UUID.randomUUID() + "',false)");
            try (var rows = statement.executeQuery("select count(*) from audit_events where action='closure.audit'")) {
                assertTrue(rows.next()); assertEquals(0, rows.getInt(1));
            } finally { statement.execute("reset search_path"); statement.execute("reset app.current_tenant_id"); }
        }
    }

    @Test void missingPlatformDependencyBlocksStartupAndReadinessThenRecovers() {
        var startup = new com.prototype.vulnwatch.config.PlatformSchemaStartupValidator(schemaStatus, true);
        var readiness = new com.prototype.vulnwatch.config.TenantSchemaReadinessHealthIndicator(
                schemaStatus, new com.prototype.vulnwatch.migration.PackagedMigrationCatalog());
        startup.validate();
        assertEquals(org.springframework.boot.actuate.health.Status.UP, readiness.health().getStatus());
        owner.execute("alter table platform.feed_sync_watermarks rename to closure_hidden_watermarks");
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, startup::validate);
            assertEquals(org.springframework.boot.actuate.health.Status.DOWN, readiness.health().getStatus());
        } finally { owner.execute("alter table platform.closure_hidden_watermarks rename to feed_sync_watermarks"); }
        startup.validate();
        assertEquals(org.springframework.boot.actuate.health.Status.UP, readiness.health().getStatus());
        // The V6 constraint is also a runtime dependency, even with every table still present.
        owner.execute("alter table platform.ai_grid_policy_rollout_tasks drop constraint ai_grid_policy_rollout_tasks_status_check");
        try {
            assertThrows(IllegalStateException.class, startup::validate);
            assertEquals(org.springframework.boot.actuate.health.Status.DOWN, readiness.health().getStatus());
        } finally {
            owner.execute("""
                    alter table platform.ai_grid_policy_rollout_tasks add constraint ai_grid_policy_rollout_tasks_status_check
                    check(status in ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','WAITING_FOR_ASSESSMENT','COMPLETED','FAILED','CANCELLED'))
                    """);
        }
        startup.validate();
    }

    @Test void invitationAcceptSetupCookieCsrfAndPasswordLoginCompleteWithoutEmailSend() throws Exception {
        MvcResult accepted=mvc.perform(post("/api/tenant-invites/accept").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token",inviteToken)))).andExpect(status().isOk()).andReturn();
        var cookie=accepted.getResponse().getCookie("scout_setup_session");assertNotNull(cookie);
        MvcResult csrf=mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn();
        var csrfJson=mapper.readTree(csrf.getResponse().getContentAsString());
        mvc.perform(post("/api/auth/setup-password").cookie(cookie).header("X-Scout-Setup","1")
                .header(csrfJson.path("headerName").asText(),csrfJson.path("token").asText())
                .cookie(csrf.getResponse().getCookies()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"offline-password-123\"}"))
                .andExpect(status().isOk());
        String token=login(invitedEmail);
        mvc.perform(get("/api/auth/context").header("Authorization","Bearer "+token)).andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()));
        assertEquals("ACCEPTED",owner.queryForObject("select status from platform.tenant_user_invites where token_hash=?",String.class,InvitationTokens.hash(inviteToken)));
    }

    @Test void externalSignedHumanAndMachineClaimsRespectRuntimeRegistryAndTenant() throws Exception {
        var key=new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(2048).keyID("offline-test").generate();
        var server=com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1",0),0);
        byte[] jwks=new com.nimbusds.jose.jwk.JWKSet(key.toPublicJWK()).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        server.createContext("/jwks",exchange->{exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(200,jwks.length);try(var out=exchange.getResponseBody()){out.write(jwks);}});
        server.start();
        try {
            String issuer="http://127.0.0.1:"+server.getAddress().getPort();
            var decoder=new JwtDecoderConfig().jwtDecoder(issuer,issuer+"/jwks","","scoutgrid-api","EXTERNAL","");
            var human=authentication.authenticate(decoder.decode(externalToken(key,issuer,memberEmail,"TENANT_ADMIN",tenant.getId())));
            assertEquals(tenant.getId(),human.tenantId());TenantContext.clear();
            var machineToken=decoder.decode(externalToken(key,issuer,machine,"SERVICE_ACCOUNT",tenant.getId()));
            assertEquals(Set.of("SERVICE_ACCOUNT"),authentication.authenticate(machineToken).roles());TenantContext.clear();
            owner.update("update \""+tenant.getSchemaName()+"\".service_accounts set status='INACTIVE' where key_id=?",machine);
            assertThrows(org.springframework.web.server.ResponseStatusException.class,()->authentication.authenticate(machineToken));
            TenantContext.clear();
            var wrongTenant=decoder.decode(externalToken(key,issuer,machine,"SERVICE_ACCOUNT",tenants.getDefaultTenant().getId()));
            assertThrows(org.springframework.web.server.ResponseStatusException.class,()->authentication.authenticate(wrongTenant));
        } finally {server.stop(0);TenantContext.clear();}
    }

    private AppUser user(String email,boolean platformOwner){AppUser user=new AppUser();user.setExternalSubject(email);user.setEmail(email);user.setDisplayName("Offline user");
        user.setPlatformOwner(platformOwner);user.setStatus("ACTIVE");user.setPasswordHash(BCrypt.hashpw("offline-password-123",BCrypt.gensalt(10)));user.setPasswordSetAt(Instant.now());return users.save(user);}
    private String login(String email)throws Exception{return mapper.readTree(mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
            .content(mapper.writeValueAsString(Map.of("email",email,"password","offline-password-123")))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("token").asText();}
    private static String externalToken(com.nimbusds.jose.jwk.RSAKey key,String issuer,String subject,String role,UUID tenant)throws Exception{
        var claims=new com.nimbusds.jwt.JWTClaimsSet.Builder().issuer(issuer).subject(subject).audience("scoutgrid-api")
                .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(300))).claim("token_use","access")
                .claim("roles",List.of(role)).claim("active_tenant_id",tenant.toString()).claim("email",subject).build();
        var token=new com.nimbusds.jwt.SignedJWT(new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),claims);
        token.sign(new com.nimbusds.jose.crypto.RSASSASigner(key));return token.serialize();
    }
}
