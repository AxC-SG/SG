package com.prototype.vulnwatch.ticketing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.FindingSubjectAdapterRegistry;
import com.prototype.vulnwatch.service.ownership.InventorySubjectAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Batch;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Choice;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Preview;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.RoutingChangedException;
import com.prototype.vulnwatch.ticketing.TicketingService.TicketContext;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof for server-derived ticket routing (Phase 0B §4.9): every row of the routing table, mixed-team
 * CVE batches, the preview hash, override audit, the legacy path and attempts on every path. The provider is a fake
 * behind the registry, so the test sees exactly what each ticket would carry.
 */
@PostgresIntegrationTest
class TicketRoutingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ticket_routing");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.read-waves.tickets", () -> "*");
    }

    @MockitoBean private TicketingProviderRegistry providers;
    @Autowired private TicketingService ticketing;
    @Autowired private FindingSubjectAdapterRegistry findingSubjects;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private JdbcTemplate jdbc;

    private final FakeProvider provider = new FakeProvider();
    private Tenant tenant;
    private UUID payments;
    private UUID identity;
    private UUID unmapped;
    private UUID vulnerability;
    private String cve;

    @BeforeEach
    void setUp() {
        String slug = "route-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE", "CANONICAL");
        enter();
        payments = mappedTeam("Payments", "grp-shared");
        identity = mappedTeam("Identity", "grp-shared");
        unmapped = teams.createTeam("Unmapped", null, null, "admin").id();
        vulnerability = UUID.randomUUID();
        cve = "CVE-2026-" + (10000 + (int) (Math.random() * 89999));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'Routing fixture', 'HIGH', false, now(), now())""", vulnerability, cve));
        enter();
        when(providers.activeProvider(any())).thenReturn(Optional.of(provider));
        when(providers.configuredSystems(any())).thenReturn(List.of(TicketingSystem.JIRA));
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void everyRowOfTheRoutingTableAndTheTenantDefaultWinsOverASelection() {
        UUID mapped = finding(host(payments));
        UUID noMapping = finding(host(unmapped));
        UUID unowned = finding(host(null));
        UUID conflict = finding(conflictHost());
        List<UUID> all = List.of(mapped, noMapping, unowned, conflict);

        Preview none = ticketing.previewForFindings(tenant, all, Choice.none());
        assertThat(none.canonical()).isTrue();
        assertThat(none.batches()).singleElement().satisfies(b -> {
            assertThat(b.routingSource()).isEqualTo(RoutingSource.TEAM_MAPPING);
            assertThat(b.assignmentGroup()).isEqualTo("grp-shared");
            assertThat(b.findingIds()).containsExactly(mapped);
        });
        assertThat(none.unroutable()).extracting(u -> u.findingId() + "|" + u.bucket())
                .containsExactlyInAnyOrder(noMapping + "|TEAM", unowned + "|UNOWNED", conflict + "|CONFLICT");

        Preview selected = ticketing.previewForFindings(tenant, all, new Choice("grp-picked", null, null));
        assertThat(selected.batches()).extracting(b -> b.bucket() + "|" + b.teamId() + "|" + b.assignmentGroup() + "|" + b.routingSource())
                .containsExactlyInAnyOrder("TEAM|" + payments + "|grp-shared|TEAM_MAPPING", "TEAM|" + unmapped + "|grp-picked|USER_SELECTED",
                        "UNOWNED|null|grp-picked|USER_SELECTED");
        assertThat(selected.unroutable()).extracting(u -> u.findingId()).containsExactly(conflict);

        jdbc.update("INSERT INTO jira_ticketing_configs (id, enabled, include_priority, created_at, updated_at, default_assignment_group)"
                + " VALUES (gen_random_uuid(), true, true, now(), now(), 'grp-default')");
        Preview defaulted = ticketing.previewForFindings(tenant, all, new Choice("grp-picked", null, null));
        assertThat(defaulted.tenantDefaultGroup()).isEqualTo("grp-default");
        assertThat(defaulted.batches()).filteredOn(b -> b.routingSource() != RoutingSource.TEAM_MAPPING)
                .allSatisfy(b -> assertThat(b.assignmentGroup() + "|" + b.routingSource()).isEqualTo("grp-default|TENANT_DEFAULT"));

        Preview override = ticketing.previewForFindings(tenant, all, new Choice(null, "grp-coordinator", "Coordinated fix"));
        assertThat(override.batches()).singleElement().satisfies(b -> {
            assertThat(b.routingSource()).isEqualTo(RoutingSource.OVERRIDE);
            assertThat(b.findingIds()).containsExactlyInAnyOrderElementsOf(all);
        });
        assertThatThrownBy(() -> ticketing.previewForFindings(tenant, all, new Choice(null, "grp", " ")))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
        assertThat(provider.calls).as("previews write and send nothing").isEmpty();
    }

    @Test
    void mixedTeamCveTicketsAreOnePerTeamEvenOnASharedGroupAndConflictGetsNone() {
        UUID a = finding(host(payments));
        UUID b = finding(host(identity));
        UUID c = finding(conflictHost());
        CveTicketRequest request = cveRequest(a, b, c);
        Preview preview = ticketing.previewForCve(tenant, cve, components(a, b, c), Choice.none());
        assertThat(preview.batches()).hasSize(2);

        List<TicketRef> refs = ticketing.createTicketsForCve(tenant, cve, request, context(preview.routingHash(), Choice.none()));
        assertThat(refs).hasSize(2);
        assertThat(provider.cveRequests).allSatisfy(r -> {
            assertThat(r.assignmentGroup()).isEqualTo("grp-shared");
            assertThat(r.safeAssets()).hasSize(1).allSatisfy(asset -> assertThat(asset.assignmentGroup()).as("caller CMDB group ignored").isNull());
        });
        assertThat(incident(a)).isNotNull();
        assertThat(incident(b)).isNotNull().isNotEqualTo(incident(a));
        assertThat(incident(c)).isNull();
        assertThat(jdbc.queryForList("SELECT routing_source || '|' || owner_team_id FROM finding_ticket_attempts ORDER BY 1", String.class))
                .containsExactlyInAnyOrder("TEAM_MAPPING|" + payments, "TEAM_MAPPING|" + identity);
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT batch_id) FROM finding_ticket_attempts", Integer.class)).isEqualTo(2);
    }

    @Test
    void createNeedsACurrentUntamperedHashAndAMappingChangeReturnsAFreshPreview() {
        UUID f = finding(host(payments));
        assertThatThrownBy(() -> ticketing.createTicketForFinding(tenant, f, TicketRequest.empty(), context(null, Choice.none())))
                .isInstanceOf(RoutingChangedException.class);
        Preview preview = ticketing.previewForFindings(tenant, List.of(f), Choice.none());
        String tampered = preview.routingHash().substring(0, preview.routingHash().length() - 2) + "AA";
        assertThatThrownBy(() -> ticketing.createTicketForFinding(tenant, f, TicketRequest.empty(), context(tampered, Choice.none())))
                .isInstanceOf(RoutingChangedException.class);

        long version = teams.team(payments).orElseThrow().version();
        teams.updateTeam(payments, null, "grp-payments-new", version, "admin");
        RoutingChangedException changed = (RoutingChangedException) org.junit.jupiter.api.Assertions.assertThrows(RoutingChangedException.class,
                () -> ticketing.createTicketForFinding(tenant, f, TicketRequest.empty(), context(preview.routingHash(), Choice.none())));
        assertThat(changed.preview().batches()).extracting(Batch::assignmentGroup).containsExactly("grp-payments-new");
        assertThat(provider.calls).isEmpty();

        // The fresh hash works, and the routed group replaces the caller's.
        TicketRequest withGroup = new TicketRequest(null, null, null, null, null, "caller-group", null, null);
        ticketing.createTicketForFinding(tenant, f, withGroup, context(changed.preview().routingHash(), Choice.none()));
        assertThat(provider.findingRequests).singleElement().satisfies(r -> assertThat(r.assignmentGroup()).isEqualTo("grp-payments-new"));
        assertThat(jdbc.queryForObject("""
                SELECT routing_source || '|' || assignment_group || '|' || owner_team_id || '|' || (ownership_assignment_id IS NOT NULL) || '|' || outcome
                  FROM finding_ticket_attempts WHERE finding_id = ?""", String.class, f))
                .isEqualTo("TEAM_MAPPING|grp-payments-new|" + payments + "|true|SUCCEEDED");
    }

    @Test
    void anOverrideIsAuditedOnTheAttemptAndAsAFindingEventWithTheOwnerSnapshot() {
        UUID f = finding(conflictHost());
        Choice override = new Choice(null, "grp-coordinator", "Owners disagree; security coordinates");
        Preview preview = ticketing.previewForFindings(tenant, List.of(f), override);
        ticketing.createTicketForFinding(tenant, f, TicketRequest.empty(), context(preview.routingHash(), override));
        assertThat(jdbc.queryForObject("SELECT routing_source || '|' || assignment_group || '|' || override_reason FROM finding_ticket_attempts",
                String.class)).isEqualTo("OVERRIDE|grp-coordinator|Owners disagree; security coordinates");
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM finding_events WHERE finding_id = ? AND event_type = 'TICKET_ROUTING_OVERRIDE'
                   AND ownership_assignment_id IS NOT NULL AND details_json ->> 'reason' = 'Owners disagree; security coordinates'""",
                Integer.class, f)).isEqualTo(1);
    }

    @Test
    void theLegacyPathKeepsTodaysBehaviourAndStillRecordsAttemptsIncludingFailures() {
        authority("CORE", "DARK");
        enter();
        UUID f = finding(host(payments));
        TicketRequest withGroup = new TicketRequest(null, null, null, null, null, "caller-group", null, null);
        ticketing.createTicketForFinding(tenant, f, withGroup, context(null, Choice.none()));
        assertThat(provider.findingRequests).singleElement().satisfies(r -> assertThat(r.assignmentGroup()).isEqualTo("caller-group"));
        assertThat(jdbc.queryForObject("SELECT routing_source || '|' || outcome FROM finding_ticket_attempts WHERE finding_id = ?", String.class, f))
                .isEqualTo("LEGACY|SUCCEEDED");

        UUID g = finding(host(payments));
        provider.fail = true;
        assertThatThrownBy(() -> ticketing.createTicketForFinding(tenant, g, TicketRequest.empty(), context(null, Choice.none())))
                .isInstanceOf(ResponseStatusException.class);
        assertThat(jdbc.queryForObject("SELECT outcome || '|' || error_message FROM finding_ticket_attempts WHERE finding_id = ?", String.class, g))
                .isEqualTo("FAILED|Remote system unavailable");
        assertThat(incident(g)).isNull();
    }

    @Test
    void ticketSyncNeverReadsOwnershipSoAnOwnerChangeCannotMoveATicket() throws Exception {
        String sync = Files.readString(Path.of("src/main/java/com/prototype/vulnwatch/service/FindingIncidentSyncService.java"));
        assertThat(sync).doesNotContainIgnoringCase("ownership").doesNotContain("owner_team").doesNotContain("ownerGroup");
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private TicketContext context(String hash, Choice choice) {
        return new TicketContext("analyst", "DEFAULT", hash, choice);
    }

    private UUID mappedTeam(String name, String group) {
        return teams.createTeam(name, null, group, "admin").id();
    }

    private UUID host(UUID team) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, "host-" + id, "host-" + id);
        UUID subject = inventory.subjectForAsset(id).orElseThrow();
        if (team != null) claims.recordClaim(claim(subject, team, "ci-" + id));
        return id;
    }

    private UUID conflictHost() {
        UUID id = host(payments);
        claims.recordClaim(claim(inventory.subjectForAsset(id).orElseThrow(), identity, "other-" + id));
        return id;
    }

    private final Map<UUID, UUID> componentOf = new java.util.HashMap<>();

    private UUID finding(UUID asset) {
        UUID upload = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at) VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'b.json', now())",
                upload, asset);
        UUID component = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version, asset_id, sbom_upload_id)
                VALUES (?, 'ACTIVE', 'npm', now(), now(), 'lodash', 'pkg:npm/lodash@1.0.0', '1.0.0', ?, ?)""", component, asset, upload);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, finding_kind, vulnerability_id, asset_id, component_id)
                VALUES (?, ?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, 0.9, 'OPEN', 'VULNERABILITY', ?, ?, ?)""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), vulnerability, asset, component);
        findingSubjects.subjectForFinding(id);
        componentOf.put(id, component);
        return id;
    }

    private List<String> components(UUID... findings) {
        List<String> ids = new ArrayList<>();
        for (UUID f : findings) ids.add(componentOf.get(f).toString());
        return ids;
    }

    private CveTicketRequest cveRequest(UUID... findings) {
        List<TicketAsset> assets = new ArrayList<>();
        for (String component : components(findings)) {
            assets.add(new TicketAsset(component, "host", null, "HOST", "lodash", "1.0.0", "CMDB Support Group"));
        }
        return new CveTicketRequest(cve, null, "HIGH", null, null, null, null, null, assets);
    }

    private String incident(UUID finding) {
        return jdbc.queryForObject("SELECT incident_id FROM findings WHERE id = ?", String.class, finding);
    }

    private ClaimRequest claim(UUID subject, UUID team, String ref) {
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "servicenow:cmdb_ci:" + ref + ":support_group", "v1",
                "servicenow-cmdb-1", Instant.now(), null, null, null, "test");
    }

    private void authority(String domain, String state) {
        boolean canonical = "CANONICAL".equals(state);
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by)
                VALUES (?, ?, ?, ?, CASE WHEN ? THEN now() END, 'test')
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = EXCLUDED.state, accepted_by = EXCLUDED.accepted_by,
                       accepted_at = EXCLUDED.accepted_at""", tenant.getId(), domain, state, canonical ? "test" : null, canonical));
    }

    private void enter() {
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    /** Records what each ticket would carry; optionally fails like an unreachable remote system. */
    static final class FakeProvider implements TicketingProvider {
        final List<String> calls = new ArrayList<>();
        final List<TicketRequest> findingRequests = new ArrayList<>();
        final List<CveTicketRequest> cveRequests = new ArrayList<>();
        boolean fail;

        @Override public TicketingSystem system() { return TicketingSystem.JIRA; }
        @Override public boolean isConfigured(Tenant tenant) { return true; }

        @Override
        public TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request) {
            if (fail) throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Remote system unavailable");
            calls.add("finding");
            findingRequests.add(request);
            return ref();
        }

        @Override
        public TicketRef createForCve(Tenant tenant, CveTicketRequest request) {
            calls.add("cve");
            cveRequests.add(request);
            return ref();
        }

        @Override public Optional<TicketStatus> fetchStatus(Tenant tenant, String externalKey) { return Optional.empty(); }
        @Override public boolean pushFindingStatus(Tenant tenant, String externalKey, TicketPush push) { return false; }

        private TicketRef ref() {
            String key = "SEC-" + (calls.size() + 100);
            return new TicketRef(TicketingSystem.JIRA, key, key, "https://jira.example.test/browse/" + key, "Open", "created");
        }
    }
}
