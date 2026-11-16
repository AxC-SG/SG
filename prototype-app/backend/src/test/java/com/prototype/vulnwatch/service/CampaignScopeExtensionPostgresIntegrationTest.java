package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.CampaignMembershipState;
import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAddCvesRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAddSoftwareRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.ownership.InventorySubjectAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof that Add CVE and Add software save to a CVE campaign (Phase 0B §4.2): the scope grows, the
 * findings it covers become MANUAL members with a live owner snapshot, the reconciler keeps picking up later findings,
 * and a scope that does not fit the create bound finishes through the reconciler.
 */
@PostgresIntegrationTest
class CampaignScopeExtensionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("campaign_scope_extension");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private CampaignService campaigns;
    @Autowired private CampaignMembershipReconciler reconciler;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID host;
    private String cveA;
    private String cveB;
    private UUID vulnA;
    private UUID vulnB;

    @BeforeEach
    void setUp() {
        String slug = "scope-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        vulnA = vulnerability("A");
        vulnB = vulnerability("B");
        cveA = externalId(vulnA);
        cveB = externalId(vulnB);
        enter();
        host = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                host, "host-" + host, "host-" + host);
        claims.recordClaim(new ClaimRequest(inventory.subjectForAsset(host).orElseThrow(), payments, null, "SERVICENOW", "SERVICENOW", null,
                "servicenow:cmdb_ci:" + host + ":support_group", "v1", "sn-1", Instant.now(), null, null, null, "test"));
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("analyst", "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void addingACveSavesItAndAddsItsOpenFindingsAsManualMembersWithALiveSnapshot() {
        UUID first = finding(vulnA, null, "OPEN", null);
        UUID open = finding(vulnB, null, "OPEN", null);
        finding(vulnB, null, "RESOLVED", "MANUAL_FIXED");
        UUID campaign = createCampaign(List.of(cveA));
        assertThat(memberIds(campaign)).containsExactly(first);

        CampaignDetailResponse detail = campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of(cveB, cveB)), "analyst");
        enter();
        assertThat(detail.summary().cveIds()).containsExactlyInAnyOrder(cveA, cveB);
        assertThat(detail.vulnerabilities()).extracting(v -> v.externalId()).containsExactlyInAnyOrder(cveA, cveB);
        assertThat(memberIds(campaign)).containsExactlyInAnyOrder(first, open);
        assertThat(jdbc.queryForObject("SELECT add_source || '|' || ownership_status_at_add || '|' || owner_team_id_at_add FROM campaign_findings"
                + " WHERE campaign_id = ? AND finding_id = ?", String.class, campaign, open)).isEqualTo("MANUAL|OWNED|" + payments);
        assertThat(activities(campaign)).contains("SCOPE_ADDED");

        assertThatThrownBy(() -> campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of(cveB)), "analyst"))
                .as("nothing new").isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of("CVE-1900-0001")), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of()), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void theReconcilerKeepsAddingFindingsOfAnAddedCveAndOfAddedSoftware() {
        UUID software = softwareIdentity("openssl");
        UUID component = component(software);
        finding(vulnA, null, "OPEN", null);
        UUID campaign = createCampaign(List.of(cveA));
        campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of(cveB)), "analyst");
        enter();
        CampaignDetailResponse detail = campaigns.addSoftware(tenant, campaign, new CampaignAddSoftwareRequest(List.of(software)), "analyst");
        enter();
        assertThat(detail.softwareItems()).singleElement().satisfies(item -> {
            assertThat(item.id()).isEqualTo(software);
            assertThat(item.displayName()).isEqualTo("openssl");
        });

        // New findings, aged past the reconciler's in-flight window: one on the added CVE, one on the added software
        // under an unrelated CVE, and one on neither.
        UUID onCve = finding(vulnB, null, "OPEN", null);
        UUID onSoftware = finding(vulnA, component, "OPEN", null);
        UUID unrelated = finding(vulnerability("C"), null, "OPEN", null);
        enter();
        jdbc.update("UPDATE findings SET updated_at = now() - interval '5 minutes'");
        assertThat(reconciler.reconcile(tenant, campaign)).isEqualTo(2);
        enter();
        assertThat(memberIds(campaign)).contains(onCve, onSoftware).doesNotContain(unrelated);
        assertThat(jdbc.queryForObject("SELECT add_source FROM campaign_findings WHERE finding_id = ?", String.class, onSoftware)).isEqualTo("RECONCILER");
        assertThat(campaigns.getDetail(tenant, campaign).softwareItems()).singleElement()
                .satisfies(item -> assertThat(item.openFindingCount()).isEqualTo(1));
    }

    @Test
    void addingSoftwareAddsItsExistingFindingsOnceAndRefusesUnknownOrRepeatedItems() {
        UUID software = softwareIdentity("lodash");
        UUID component = component(software);
        UUID onSoftware = finding(vulnB, component, "OPEN", null);
        UUID campaign = createCampaign(List.of(cveA));
        assertThat(memberIds(campaign)).isEmpty();

        CampaignDetailResponse detail = campaigns.addSoftware(tenant, campaign, new CampaignAddSoftwareRequest(List.of(software)), "analyst");
        enter();
        assertThat(memberIds(campaign)).containsExactly(onSoftware);
        assertThat(detail.summary().totalFindings()).isEqualTo(1);
        assertThat(detail.softwareItems()).singleElement().satisfies(item -> {
            assertThat(item.assetCount()).isEqualTo(1);
            assertThat(item.openFindingCount()).isEqualTo(1);
        });
        assertThatThrownBy(() -> campaigns.addSoftware(tenant, campaign, new CampaignAddSoftwareRequest(List.of(software)), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> campaigns.addSoftware(tenant, campaign, new CampaignAddSoftwareRequest(List.of(UUID.randomUUID())), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
    }

    @Test
    void aScopeLargerThanTheCreateBoundFinishesThroughTheReconciler() {
        UUID campaign = createCampaign(List.of(cveA));
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, finding_kind, vulnerability_id, asset_id)
                SELECT gen_random_uuid(), ?, now(), now() - interval '5 minutes', 'AUTOMATIC', 'S-' || lpad(i::text, 6, '0'), 'CPE', 7.0, 0.9, 'OPEN',
                       'VULNERABILITY', ?, ?
                  FROM generate_series(1, ?) i""", tenant.getId(), vulnB, host, CampaignLedger.CREATE_BOUND + 3);

        campaigns.addCves(tenant, campaign, new CampaignAddCvesRequest(List.of(cveB)), "analyst");
        enter();
        assertThat(membershipState(campaign)).isEqualTo(CampaignMembershipState.MATERIALIZING.name());
        assertThat(count("campaign_findings")).isEqualTo(CampaignLedger.CREATE_BOUND);

        assertThat(reconciler.reconcile(tenant, campaign)).isEqualTo(3);
        enter();
        assertThat(count("campaign_findings")).isEqualTo(CampaignLedger.CREATE_BOUND + 3);
        assertThat(membershipState(campaign)).isEqualTo(CampaignMembershipState.COMPLETE.name());
    }

    @Test
    void onlyOpenCveCampaignsCanBeExtended() {
        UUID finding = finding(vulnA, null, "OPEN", null);
        UUID byFindings = campaigns.create(tenant, new CampaignCreateRequest("By findings", null, null, List.of(finding), null, null, null, null,
                null, null, null, null, null), "analyst").summary().id();
        enter();
        assertThatThrownBy(() -> campaigns.addCves(tenant, byFindings, new CampaignAddCvesRequest(List.of(cveB)), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));
        assertThatThrownBy(() -> campaigns.addSoftware(tenant, byFindings, new CampaignAddSoftwareRequest(List.of(softwareIdentity("x"))), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));

        UUID closed = createCampaign(List.of(cveA));
        campaigns.updateStatus(tenant, closed, new CampaignStatusUpdateRequest(CampaignStatus.CLOSED, null), "analyst");
        enter();
        assertThatThrownBy(() -> campaigns.addCves(tenant, closed, new CampaignAddCvesRequest(List.of(cveB)), "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM campaign_software", Integer.class)).isZero();
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID createCampaign(List<String> cves) {
        UUID id = campaigns.create(tenant, new CampaignCreateRequest("Scope", null, cves, null, null, null, null, false, List.of(), List.of(), null,
                null, null), "analyst").summary().id();
        enter();
        return id;
    }

    private UUID vulnerability(String suffix) {
        UUID id = UUID.randomUUID();
        String external = "CVE-2026-" + (10000 + (int) (Math.random() * 89999));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', ?, 'HIGH', false, now(), now())""", id, external, "Scope fixture " + suffix));
        return id;
    }

    private String externalId(UUID vulnerability) {
        return TenantContext.runAsPlatform(() -> jdbc.queryForObject("SELECT external_id FROM platform.vulnerabilities WHERE id = ?", String.class, vulnerability));
    }

    private UUID softwareIdentity(String name) {
        UUID id = UUID.randomUUID();
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.software_identities (id, canonical_key, display_name, vendor, created_at, updated_at)
                VALUES (?, ?, ?, 'Vendor', now(), now())""", id, name + "-" + id, name));
        enter();
        return id;
    }

    private UUID component(UUID softwareIdentity) {
        UUID upload = UUID.randomUUID();
        jdbc.update("INSERT INTO sbom_uploads (id, asset_id, format, status, original_filename, uploaded_at) VALUES (?, ?, 'CYCLONEDX', 'SUCCESS', 'b.json', now())",
                upload, host);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO inventory_components (id, tenant_id, component_status, ecosystem, ingested_at, last_observed_at, package_name, purl, version,
                    asset_id, sbom_upload_id, software_identity_id)
                VALUES (?, ?, 'ACTIVE', 'npm', now(), now(), 'pkg', 'pkg:npm/pkg@1.0.0', '1.0.0', ?, ?, ?)""",
                id, tenant.getId(), host, upload, softwareIdentity);
        return id;
    }

    private UUID finding(UUID vulnerability, UUID component, String status, String closedReason) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, confidence_score,
                    status, closed_reason, finding_kind, vulnerability_id, asset_id, component_id, ownership_subject_id)
                SELECT ?, ?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, 0.9, ?, ?, 'VULNERABILITY', ?, a.id, ?, a.ownership_subject_id
                  FROM assets a WHERE a.id = ?""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), status, closedReason, vulnerability, component, host);
        return id;
    }

    private List<UUID> memberIds(UUID campaign) {
        return jdbc.queryForList("SELECT finding_id FROM campaign_findings WHERE campaign_id = ?", UUID.class, campaign);
    }

    private List<String> activities(UUID campaign) {
        return jdbc.queryForList("SELECT activity_type FROM campaign_activities WHERE campaign_id = ?", String.class, campaign);
    }

    private String membershipState(UUID campaign) {
        return jdbc.queryForObject("SELECT membership_state FROM campaigns WHERE id = ?", String.class, campaign);
    }

    private int count(String table) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
        return n == null ? 0 : n;
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
