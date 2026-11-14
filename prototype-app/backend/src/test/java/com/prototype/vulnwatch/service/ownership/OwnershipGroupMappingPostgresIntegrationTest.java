package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.DirectoryService.ObservedGroup;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.ChangeResult;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.Impact;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.Mapping;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof for group-to-team mapping and mapping-driven CMDB resolution (Phase 0B contract §1.8):
 * suggestions never activate, changes need an impact preview, a sys_id support group resolves through an active
 * mapping on the CMDB's instance only, and names still resolve by team name or alias.
 */
@PostgresIntegrationTest
class OwnershipGroupMappingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_group_mapping");
    private static final String GROUP_SYS_ID = "a".repeat(32);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.servicenow.producer-enabled", () -> "true");
    }

    @Autowired private GroupTeamMappingService mappings;
    @Autowired private ServiceNowOwnershipProducer producer;
    @Autowired private DirectoryService directory;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;
    private UUID group;

    @BeforeEach
    void setUp() {
        String slug = "own-map-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, updated_by) VALUES (?, 'CORE', 'DARK', 'test')""",
                tenant.getId()));
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        jdbc.update("""
                INSERT INTO servicenow_cmdb_configs (id, auth_type, auto_sync_enabled, ci_table, created_at, discovery_model_table, enabled,
                                                     install_table, interval_minutes, page_size, source_system, updated_at, base_url)
                VALUES (?, 'BASIC', false, 'cmdb_ci', now(), 'cmdb_sam_sw_discovery_model', true, 'cmdb_sam_sw_install', 60, 500,
                        'servicenow', now(), 'https://ACME.service-now.com/')
                """, UUID.randomUUID());
        group = groupOn("https://acme.service-now.com", GROUP_SYS_ID, "Payments");
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void anExactNameMatchIsOnlySuggestedAndADismissedSuggestionIsNotProposedAgain() {
        assertThat(mappings.suggest(group, "Payments", "sync")).isTrue();
        assertThat(mappings.suggest(group, "Payments", "sync")).as("one pending suggestion per group").isFalse();
        Mapping suggestion = mappings.mappings("PROPOSED", 10).get(0);
        assertThat(suggestion.provenance()).isEqualTo("SUGGESTED");
        assertThat(suggestion.teamId()).isEqualTo(payments);
        assertThat(mappings.mappings("ACTIVE", 10)).isEmpty();

        UUID web = ci("b".repeat(32), GROUP_SYS_ID);
        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(ownerOf(web)).as("a suggestion never resolves a CI").isNull();

        assertThat(mappings.dismiss(suggestion.id(), "admin").state()).isEqualTo("RETIRED");
        assertThat(mappings.suggest(group, "Payments", "sync")).isFalse();
        UUID unknown = groupOn("https://acme.service-now.com", "c".repeat(32), "Mystery Ops");
        assertThat(mappings.suggest(unknown, "Mystery Ops", "sync")).as("no team has this name").isFalse();
    }

    @Test
    void activatingNeedsAPreviewAndASysIdSupportGroupThenResolvesThroughTheMapping() {
        mappings.suggest(group, "Payments", "sync");
        UUID web = ci("b".repeat(32), GROUP_SYS_ID);
        UUID db = ci("d".repeat(32), GROUP_SYS_ID.toUpperCase());
        UUID named = ci("e".repeat(32), "Payments");

        Impact impact = mappings.preview(group, identity, "admin");
        assertThat(impact.sameInstance()).isTrue();
        assertThat(impact.affectedCis()).isEqualTo(2);
        assertThat(impact.currentTeamId()).isNull();
        assertThat(impact.largeChange()).isFalse();

        assertStatus(409, () -> mappings.activate(group, identity, null, null, false, "admin"));
        assertStatus(409, () -> mappings.activate(group, identity, null, impact.previewToken(), false, "another-admin"));
        assertStatus(409, () -> mappings.activate(group, payments, null, impact.previewToken(), false, "admin"));

        ChangeResult result = mappings.activate(group, identity, "Identity runs these hosts", impact.previewToken(), false, "admin");
        enter();
        assertThat(result.mapping().state()).isEqualTo("ACTIVE");
        assertThat(result.mapping().provenance()).isEqualTo("MANUAL");
        assertThat(result.republishedCis()).isEqualTo(2);
        assertThat(result.republishSkipped()).isNull();
        assertThat(ownerOf(web)).isEqualTo(identity);
        assertThat(ownerOf(db)).isEqualTo(identity);
        assertThat(mappings.mappings("PROPOSED", 10)).as("the pending suggestion is closed").isEmpty();

        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(ownerOf(web)).as("the CMDB sync resolves the sys_id through the mapping").isEqualTo(identity);
        assertThat(ownerOf(named)).as("a name still resolves by team name").isEqualTo(payments);
        assertThat(jdbc.queryForObject("SELECT details_json::text FROM audit_events WHERE action = 'ownership.group_mapping.activated'", String.class))
                .contains(identity.toString()).doesNotContain(GROUP_SYS_ID);
    }

    @Test
    void remappingInvalidatesOldPreviewsAndRetiringLeavesTheLastClaimUntilTheValueMaps() {
        UUID web = ci("b".repeat(32), GROUP_SYS_ID);
        Impact first = mappings.preview(group, identity, "admin");
        Mapping active = mappings.activate(group, identity, null, first.previewToken(), false, "admin").mapping();
        enter();

        Impact toPayments = mappings.preview(group, payments, "admin");
        assertThat(toPayments.currentTeamId()).isEqualTo(identity);
        assertStatus(409, () -> mappings.activate(group, payments, null, first.previewToken(), false, "admin"));
        Mapping remapped = mappings.activate(group, payments, null, toPayments.previewToken(), false, "admin").mapping();
        enter();
        assertThat(ownerOf(web)).isEqualTo(payments);
        assertThat(jdbc.queryForObject("SELECT state FROM external_group_team_mapping WHERE id = ?", String.class, active.id())).isEqualTo("RETIRED");

        Impact retire = mappings.preview(group, null, "admin");
        assertStatus(409, () -> mappings.retire(remapped.id(), null, toPayments.previewToken(), false, "admin"));
        assertThat(mappings.retire(remapped.id(), "Group disbanded", retire.previewToken(), false, "admin").mapping().state()).isEqualTo("RETIRED");
        enter();
        assertThat(mappings.mappings("ACTIVE", 10)).isEmpty();
        assertThat(ownerOf(web)).as("an unmapped value does not remove the previous owner").isEqualTo(payments);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM ownership_review_item WHERE item_type = 'UNMAPPED_VALUE' AND state = 'OPEN'",
                Integer.class)).isEqualTo(1);
        assertStatus(409, () -> mappings.preview(group, null, "admin"));
    }

    @Test
    void aGroupOnAnotherInstanceAffectsNoCiAndNeverResolvesOne() {
        UUID elsewhere = groupOn("https://other.service-now.com", "f".repeat(32), "Elsewhere");
        UUID web = ci("b".repeat(32), "f".repeat(32));

        Impact impact = mappings.preview(elsewhere, identity, "admin");
        assertThat(impact.sameInstance()).isFalse();
        assertThat(impact.affectedCis()).isZero();
        ChangeResult result = mappings.activate(elsewhere, identity, null, impact.previewToken(), false, "admin");
        assertThat(result.republishedCis()).isZero();

        producer.publish(tenant.getId(), Instant.now().minusSeconds(1), true, false);
        enter();
        assertThat(ownerOf(web)).isNull();
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID groupOn(String instance, String sysId, String name) {
        UUID source = jdbc.queryForList("SELECT id FROM identity_source WHERE scope_config ->> 'instanceUrl' = ?", UUID.class, instance).stream()
                .findFirst().orElseGet(() -> directory.createProviderSource("SERVICENOW", "ServiceNow " + instance, null,
                        "{\"instanceUrl\":\"" + instance + "\"}", "PT24H", "admin"));
        return directory.observeGroup(new ObservedGroup(source, sysId, name, true), null, "sync").externalGroupId();
    }

    private UUID ci(String sysId, String supportGroup) {
        UUID asset = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type, support_group, last_cmdb_sync_at)
                VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST', ?, now())""", asset, sysId, sysId, supportGroup);
        jdbc.update("""
                INSERT INTO cis (id, business_criticality, created_at, display_name, sys_id, updated_at, asset_id, support_group, last_cmdb_sync_at)
                VALUES (?, 'HIGH', now(), ?, ?, now(), ?, ?, now())""", UUID.randomUUID(), sysId, sysId, asset, supportGroup);
        return asset;
    }

    private UUID ownerOf(UUID asset) {
        return jdbc.queryForList("""
                SELECT e.owner_team_id FROM assets a JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                 WHERE a.id = ?""", UUID.class, asset).stream().filter(java.util.Objects::nonNull).findFirst().orElse(null);
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    private static void assertStatus(int status, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(status));
    }
}
