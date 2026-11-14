package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.DirectoryTable;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.FailureKind;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ProbeOutcome;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ServiceNowDirectoryException;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.TableProbe;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ConnectionTest;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ServiceNowSourceRequest;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.SourceView;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

/** Real-PostgreSQL proof for ServiceNow identity-source configuration and lifecycle (Phase 0B contract §1.1–§1.2). */
@PostgresIntegrationTest
class OwnershipIdentitySourcePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_identity_source");
    private static final String URL = "https://acme.service-now.com";
    private static final String SECRET = "integration-s3cret";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.servicenow.directory-enabled", () -> "true");
    }

    @Autowired private IdentitySourceService sources;
    @Autowired private DirectoryService directory;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private ObjectMapper json;
    @MockitoBean private ServiceNowDirectoryClient client;
    /** Allows the two test instances without DNS; any other host is rejected by the real policy. */
    @TestBean private OutboundHostPolicy hostPolicy;

    static OutboundHostPolicy hostPolicy() {
        return OutboundHostPolicy.forTests("servicenow=acme.service-now.com,other.service-now.com");
    }

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenant = newTenant(true);
        enter(tenant);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void aNewSourceIsDisabledWithEncryptedWriteOnlyCredentials() throws Exception {
        SourceView created = sources.create(request(URL + "/", "basic", "svc-directory", SECRET,
                Map.of("sys_user", " active=true "), null, null), "admin");

        assertThat(created.kind()).isEqualTo("SERVICENOW");
        assertThat(created.state()).isEqualTo("DISABLED");
        assertThat(created.health()).isEqualTo("UNKNOWN");
        assertThat(created.schedule()).isEqualTo("PT24H");
        assertThat(created.instanceUrl()).isEqualTo(URL);
        assertThat(created.authType()).isEqualTo("BASIC");
        assertThat(created.hasCredentials()).isTrue();
        assertThat(created.filters()).isEqualTo(Map.of("sys_user", "active=true"));
        assertThat(json.writeValueAsString(created)).doesNotContain(SECRET).doesNotContain("svc-directory");
        assertThat(json.writeValueAsString(sources.list())).doesNotContain(SECRET);

        Map<String, Object> row = jdbc.queryForMap("SELECT credentials_enc, scope_config::text AS scope FROM identity_source WHERE id = ?",
                created.id());
        assertThat((String) row.get("credentials_enc")).startsWith("enc:t1:").doesNotContain(SECRET).doesNotContain("svc-directory");
        assertThat((String) row.get("scope")).contains("sys_user_grmember").contains("employee_number").doesNotContain(SECRET);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM audit_events WHERE target_id = ? AND action = 'ownership.identity_source.created'",
                Long.class, created.id().toString())).isEqualTo(1L);
    }

    @Test
    void configurationFailsClosedUntilTheTenantKeyIsProvisioned() {
        enter(newTenant(false));
        assertStatus(503, () -> sources.create(request(URL, "BASIC", "svc", SECRET, null, null, null), "admin"));
    }

    @Test
    void invalidConfigurationIsRejected() {
        assertStatus(400, () -> sources.create(request("https://evil.example.com", "BASIC", "svc", SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request("http://acme.service-now.com", "BASIC", "svc", SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL + "/api/now", "BASIC", "svc", SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL + "?x=1", "BASIC", "svc", SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "BASIC", null, SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "BASIC", "svc", " ", null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "OAUTH", "svc", SECRET, null, null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "BASIC", "svc", SECRET, null, "PT5M", null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "BASIC", "svc", SECRET, Map.of("sys_user", "active=true^ORDERBYname"), null, null), "admin"));
        assertStatus(400, () -> sources.create(request(URL, "BASIC", "svc", SECRET, Map.of("cmdb_ci", "active=true"), null, null), "admin"));
        assertThat(sources.list()).isEmpty();
    }

    @Test
    void changingTheInstanceNeedsTheSecretAgainAndAStaleVersionConflicts() {
        SourceView created = sources.create(request(URL, "BASIC", "svc", SECRET, null, null, null), "admin");

        assertStatus(400, () -> sources.update(created.id(),
                request("https://other.service-now.com", "BASIC", "svc", null, null, null, created.version()), "admin"));
        assertStatus(400, () -> sources.update(created.id(), request(URL, "BASIC", "svc-renamed", null, null, null, created.version()), "admin"));

        SourceView renamed = sources.update(created.id(), new ServiceNowSourceRequest("Renamed", URL, "BASIC", "svc", null, null,
                "PT6H", created.version()), "admin");
        assertThat(renamed.displayName()).isEqualTo("Renamed");
        assertThat(renamed.schedule()).isEqualTo("PT6H");
        assertThat(renamed.version()).isEqualTo(created.version() + 1);

        assertStatus(409, () -> sources.update(created.id(), request(URL, "BASIC", "svc", null, null, null, created.version()), "admin"));

        SourceView moved = sources.update(created.id(), request("https://other.service-now.com", "BEARER", null, "token-2", null, null,
                renamed.version()), "admin");
        assertThat(moved.instanceUrl()).isEqualTo("https://other.service-now.com");
        assertThat(moved.authType()).isEqualTo("BEARER");
    }

    @Test
    void aScopeChangeReturnsAnEnabledSourceToDisabledButACredentialRotationDoesNot() {
        SourceView created = sources.create(request(URL, "BASIC", "svc", SECRET, null, null, null), "admin");
        jdbc.update("UPDATE identity_source SET state = 'ENABLED' WHERE id = ?", created.id());

        SourceView rotated = sources.update(created.id(), request(URL, "BASIC", "svc", "new-secret", null, null, created.version()), "admin");
        assertThat(rotated.state()).isEqualTo("ENABLED");

        SourceView filtered = sources.update(created.id(), request(URL, "BASIC", "svc", null, Map.of("sys_user_group", "active=true"),
                null, rotated.version()), "admin");
        assertThat(filtered.state()).isEqualTo("DISABLED");
    }

    @Test
    void theConnectionTestReportsEachTableWithTheStoredCredentialsAndFilters() throws Exception {
        SourceView created = sources.create(request(URL, "BASIC", "svc", SECRET, Map.of("sys_user", "active=true"), null, null), "admin");
        when(client.probe(argThat(c -> c != null && URL.equals(c.baseUrl()) && c.authType() == ServiceNowAuthType.BASIC
                && "svc".equals(c.username()) && SECRET.equals(c.secret())), eq(DirectoryTable.USERS), eq("active=true")))
                .thenReturn(new TableProbe(DirectoryTable.USERS, ProbeOutcome.READABLE, 1200L));
        when(client.probe(any(), eq(DirectoryTable.GROUPS), isNull()))
                .thenReturn(new TableProbe(DirectoryTable.GROUPS, ProbeOutcome.READABLE, 80L));
        when(client.probe(any(), eq(DirectoryTable.MEMBERSHIPS), isNull()))
                .thenReturn(new TableProbe(DirectoryTable.MEMBERSHIPS, ProbeOutcome.DENIED, null));

        ConnectionTest result = sources.testConnection(created.id(), "admin");

        assertThat(result.succeeded()).isFalse();
        assertThat(result.failure()).isEqualTo("PERMISSION_DENIED");
        assertThat(result.tables()).extracting(IdentitySourceService.TableCheck::outcome).containsExactly("READABLE", "READABLE", "DENIED");
        assertThat(result.tables().get(0).rowCount()).isEqualTo(1200L);
        assertThat(sources.get(created.id()).orElseThrow().state()).isEqualTo("DISABLED");
        String details = jdbc.queryForObject("SELECT details_json::text FROM audit_events WHERE target_id = ? AND action = 'ownership.identity_source.connection_tested'",
                String.class, created.id().toString());
        assertThat(details).contains("PERMISSION_DENIED").doesNotContain("1200");
    }

    @Test
    void rejectedCredentialsEndTheTestWithThatFailure() {
        SourceView created = sources.create(request(URL, "BEARER", null, "token-1", null, null, null), "admin");
        when(client.probe(any(), eq(DirectoryTable.USERS), isNull())).thenThrow(new ServiceNowDirectoryException(
                FailureKind.AUTHENTICATION_FAILED, 401, "ServiceNow rejected the integration account credentials"));

        ConnectionTest result = sources.testConnection(created.id(), "admin");

        assertThat(result.succeeded()).isFalse();
        assertThat(result.failure()).isEqualTo("AUTHENTICATION_FAILED");
        assertThat(result.tables()).isEmpty();
    }

    @Test
    void thePlatformKillSwitchBlocksTestingAndResuming() {
        SourceView created = sources.create(request(URL, "BASIC", "svc", SECRET, null, null, null), "admin");
        jdbc.update("UPDATE identity_source SET state = 'PAUSED' WHERE id = ?", created.id());
        jdbc.update("""
                INSERT INTO platform.ownership_kill_switches (id, source_kind, tenant_id, state, reason, updated_by)
                VALUES (?, 'SERVICENOW', ?, 'PAUSED', 'incident', 'operator')
                """, UUID.randomUUID(), tenant.getId());

        assertStatus(409, () -> sources.testConnection(created.id(), "admin"));
        assertStatus(409, () -> sources.resume(created.id(), "admin"));
        verify(client, never()).probe(any(), any(), any());
        assertThat(sources.disable(created.id(), "admin").state()).isEqualTo("DISABLED");
    }

    @Test
    void pauseResumeAndDisableFollowTheLifecycle() {
        SourceView created = sources.create(request(URL, "BASIC", "svc", SECRET, null, null, null), "admin");
        assertStatus(409, () -> sources.pause(created.id(), null, "admin"));
        assertStatus(409, () -> sources.resume(created.id(), "admin"));

        jdbc.update("UPDATE identity_source SET state = 'ENABLED' WHERE id = ?", created.id());
        assertThat(sources.pause(created.id(), "Investigating a bad import", "admin").state()).isEqualTo("PAUSED");
        assertThat(sources.resume(created.id(), "admin").state()).isEqualTo("ENABLED");
        assertThat(sources.disable(created.id(), "admin").state()).isEqualTo("DISABLED");
        assertStatus(409, () -> sources.disable(created.id(), "admin"));
        assertStatus(400, () -> sources.pause(created.id(), "x".repeat(501), "admin"));
        assertThat(jdbc.queryForList("SELECT action FROM audit_events WHERE target_id = ? ORDER BY occurred_at", String.class,
                created.id().toString())).containsSubsequence("ownership.identity_source.paused",
                "ownership.identity_source.resumed", "ownership.identity_source.disabled");
    }

    @Test
    void manualSourcesAreListedButNotConfiguredHere() {
        UUID manual = directory.manualSource("admin");

        assertThat(sources.list()).extracting(SourceView::kind).containsExactly("MANUAL");
        assertThat(sources.get(manual).orElseThrow().hasCredentials()).isFalse();
        assertStatus(409, () -> sources.update(manual, request(URL, "BASIC", "svc", SECRET, null, null, 0L), "admin"));
        assertStatus(409, () -> sources.disable(manual, "admin"));
        assertStatus(404, () -> sources.testConnection(UUID.randomUUID(), "admin"));
    }

    private static ServiceNowSourceRequest request(String url, String authType, String username, String secret,
                                                   Map<String, String> filters, String schedule, Long version) {
        return new ServiceNowSourceRequest("Acme ServiceNow", url, authType, username, secret, filters, schedule, version);
    }

    private static void assertStatus(int status, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(status));
    }

    private Tenant newTenant(boolean withKey) {
        String slug = "own-src-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        Tenant resolved = tenantService.resolveTenantUuid(created.getId());
        if (withKey) keys.provision(resolved.getId());
        return resolved;
    }

    private void enter(Tenant t) {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(t.getId());
        TenantContext.setCurrentSchemaName(t.getSchemaName());
    }
}
