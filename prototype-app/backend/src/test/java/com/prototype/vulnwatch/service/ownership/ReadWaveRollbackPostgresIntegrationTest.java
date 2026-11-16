package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketRequest;
import com.prototype.vulnwatch.ticketing.TicketRoutingService;
import com.prototype.vulnwatch.ticketing.TicketingProvider;
import com.prototype.vulnwatch.ticketing.TicketingProviderRegistry;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

/**
 * Phase 0B §4.10 rollback: with the CAMPAIGNS, TICKETS and findings read waves empty (their default) and every domain
 * CANONICAL, campaigns render legacy labels, tickets route on the legacy path and the occurrence filters refuse, while
 * the owner-at-add snapshot is still recorded because it is gated by authority, not by the read wave.
 */
@PostgresIntegrationTest
class ReadWaveRollbackPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("read_wave_rollback");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        // No read-waves.* property is set: every wave is empty.
    }

    @MockitoBean private TicketingProviderRegistry providers;
    @Autowired private TicketingService ticketing;
    @Autowired private CampaignService campaigns;
    @Autowired private OwnershipReadAdapter reads;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private FindingSubjectAdapterRegistry findingSubjects;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;

    @BeforeEach
    void setUp() {
        String slug = "rollb-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE");
        authority("CLOUD_BOM");
        enter();
        payments = teams.createTeam("Payments", null, "grp-payments", "admin").id();
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void emptyWavesGiveLegacyCampaignsAndLegacyTicketRoutingButKeepTheSnapshot() {
        UUID host = host();
        UUID finding = finding(host);

        UUID campaign = campaigns.createFromFindings(tenant, new CampaignFromFindingsRequest("Rollback", null, List.of(finding), null, null, null),
                "analyst").summary().id();
        enter();
        assertThat(jdbc.queryForObject("SELECT ownership_status_at_add || '|' || owner_team_id_at_add FROM campaign_findings WHERE campaign_id = ?",
                String.class, campaign)).isEqualTo("OWNED|" + payments);
        var member = campaigns.members(tenant, campaign, null, true, null, null, null, null, 50).items().get(0);
        assertThat(member.currentOwnership().authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");
        assertThat(member.ownershipChanged()).isFalse();
        assertThat(campaigns.buckets(tenant, campaign, null)).extracting(b -> b.bucket()).containsExactly("PENDING_MIGRATION");
        assertThat(campaigns.buckets(tenant, campaign, "atAdd")).extracting(b -> b.bucket()).containsExactly("TEAM");

        TicketingProvider provider = Mockito.mock(TicketingProvider.class);
        when(provider.system()).thenReturn(TicketingSystem.JIRA);
        when(provider.createForFinding(any(), any(), any())).thenReturn(new TicketRef(TicketingSystem.JIRA, "SEC-1", "1", "https://j/SEC-1", "Open", "ok"));
        when(providers.activeProvider(any())).thenReturn(Optional.of(provider));
        var preview = ticketing.previewForFindings(tenant, List.of(finding), TicketRoutingService.Choice.none());
        assertThat(preview.canonical()).as("tickets read wave is empty").isFalse();
        assertThat(preview.routingHash()).isNull();
        ticketing.createTicketForFinding(tenant, finding, new TicketRequest(null, null, null, null, null, "caller-group", null, null),
                TicketingService.TicketContext.system("analyst"));
        assertThat(jdbc.queryForObject("SELECT routing_source || '|' || assignment_group FROM finding_ticket_attempts WHERE finding_id = ?",
                String.class, finding)).isEqualTo("LEGACY|caller-group");

        assertThatThrownBy(() -> reads.occurrenceIds(OwnershipReadAdapter.OccurrenceTable.INVENTORY_COMPONENTS, payments, null))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));
        assertThat(reads.forFindings(OwnershipReadAdapter.Consumer.CAMPAIGNS, List.of(finding)).get(0).authorityState())
                .isEqualTo("LEGACY_PENDING_MIGRATION");
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID host() {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, "host-" + id, "host-" + id);
        claims.recordClaim(new ClaimRequest(inventory.subjectForAsset(id).orElseThrow(), payments, null, "SERVICENOW", "SERVICENOW", null,
                "servicenow:cmdb_ci:" + id + ":support_group", "v1", "sn-1", Instant.now(), null, null, null, "test"));
        return id;
    }

    private UUID finding(UUID asset) {
        UUID vulnerability = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'Rollback fixture', 'HIGH', false, now(), now())""", vulnerability, "CVE-2026-" + (10000 + (int) (Math.random() * 89999))));
        enter();
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, finding_kind, vulnerability_id, asset_id)
                VALUES (?, ?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, 0.9, 'OPEN', 'VULNERABILITY', ?, ?)""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), vulnerability, asset);
        findingSubjects.subjectForFinding(id);
        return id;
    }

    private void authority(String domain) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, ?, 'CANONICAL', 'test', now(), 'test')
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = 'CANONICAL', accepted_by = 'test', accepted_at = now()""",
                tenant.getId(), domain));
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }
}
