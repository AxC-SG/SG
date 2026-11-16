package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.domain.CampaignExceptionStatus;
import com.prototype.vulnwatch.domain.CampaignMembershipState;
import com.prototype.vulnwatch.domain.CampaignRecipientType;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAddMembersRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignMemberPage;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignMemberResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignOwnerBucket;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignPreviewResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.ownership.FindingSubjectAdapterRegistry;
import com.prototype.vulnwatch.service.ownership.InventorySubjectAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof for the campaign membership ledger (Phase 0B §4.2–§4.8): set-based materialization with a
 * live owner snapshot, the create bound and reconciler, outcomes, exceptions and TEAM/CUSTOM recipients.
 */
@PostgresIntegrationTest
class CampaignLedgerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("campaign_ledger");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private CampaignService campaigns;
    @Autowired private CampaignMembershipReconciler reconciler;
    @Autowired private FindingSubjectAdapterRegistry findingSubjects;
    @Autowired private InventorySubjectAdapter inventory;
    @Autowired private OwnershipClaimService claims;
    @Autowired private TeamNamespaceService teams;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private MeterRegistry metrics;
    @Autowired private JdbcTemplate jdbc;

    private Tenant tenant;
    private UUID payments;
    private UUID identity;
    private UUID vulnerability;
    private String cve;

    @BeforeEach
    void setUp() {
        String slug = "camp-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        authority("CORE", "CANONICAL");
        authority("CLOUD_BOM", "DARK");
        enter();
        payments = teams.createTeam("Payments", null, null, "admin").id();
        identity = teams.createTeam("Identity", null, null, "admin").id();
        vulnerability = UUID.randomUUID();
        cve = "CVE-2026-" + (10000 + (int) (Math.random() * 89999));
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)
                VALUES (?, ?, 'NVD', 'Campaign fixture', 'HIGH', false, now(), now())""", vulnerability, cve));
        enter();
        analyst();
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
        TenantContext.clear();
        TenantContext.runAsPlatform(() -> jdbc.update("DELETE FROM platform.ownership_domain_authority WHERE tenant_id = ?", tenant.getId()));
    }

    @Test
    void createMaterializesOpenMembersWithALiveSnapshotThatNeverChanges() {
        UUID host = ownedHost(payments);
        UUID open = finding(host, "OPEN", null);
        finding(host, "RESOLVED", FindingCloseReason.MANUAL_FIXED);
        UUID suppressed = finding(host, "SUPPRESSED", null);
        // A stale cache row naming another team must not leak into the snapshot (plan §7.5).
        jdbc.update("""
                INSERT INTO ownership_effective_cache (tenant_id, subject_id, ownership_status, owner_team_id, assignment_id, inheritance_path,
                    inheritance_depth, refreshed_at)
                SELECT ?, a.subject_id, 'OWNED', ?, a.id, ARRAY[a.subject_id], 0, now() - interval '1 day'
                  FROM ownership_assignment a WHERE a.subject_id = ?""", tenant.getId(), identity, assetSubject(host));

        CampaignPreviewResponse preview = campaigns.preview(tenant, cveRequest("Preview", false, List.of()));
        assertThat(preview.memberCount()).isEqualTo(1);
        assertThat(preview.excluded()).containsEntry("CLOSED", 1L).containsEntry("SUPPRESSED", 1L);
        assertThat(preview.distribution()).singleElement().satisfies(b -> assertThat(b.teamId()).isEqualTo(payments));
        assertThat(preview.teamsWithoutChannel()).extracting(t -> t.teamId()).containsExactly(payments);
        assertThat(count("campaigns")).as("preview writes nothing").isZero();

        UUID campaign = create(cveRequest("Kernel", false, List.of()));
        assertThat(memberIds(campaign)).containsExactly(open);
        assertThat(snapshot(campaign, open)).isEqualTo("OWNED|" + payments + "|CREATE");
        assertThat(jdbc.queryForObject("SELECT ownership_assignment_id_at_add FROM campaign_findings WHERE finding_id = ?", UUID.class, open))
                .isNotNull();

        UUID withExcepted = create(cveRequest("Kernel incl. excepted", true, List.of()));
        assertThat(memberIds(withExcepted)).containsExactlyInAnyOrder(open, suppressed);

        // A later owner change (a competing claim makes the asset CONFLICT) leaves the snapshot alone.
        claims.recordClaim(serviceNow(assetSubject(host), identity, "other-ci"));
        assertThat(snapshot(campaign, open)).isEqualTo("OWNED|" + payments + "|CREATE");

        // The read wave for campaigns is off: current ownership is the legacy envelope and nothing reads as changed.
        CampaignMemberResponse member = campaigns.members(tenant, campaign, null, false, null, null, null, null, 50).items().get(0);
        assertThat(member.currentOwnership().authorityState()).isEqualTo("LEGACY_PENDING_MIGRATION");
        assertThat(member.ownershipChanged()).isFalse();
        assertThat(member.ownerAtAdd().teamName()).isEqualTo("Payments");
        assertThat(campaigns.buckets(tenant, campaign, null)).extracting(CampaignOwnerBucket::bucket).containsExactly("PENDING_MIGRATION");

        // A team rename changes only the label: one bucket, by team ID.
        long version = teams.team(payments).orElseThrow().version();
        teams.renameTeam(payments, "Payments Platform", version, "admin");
        List<CampaignOwnerBucket> atAdd = campaigns.buckets(tenant, withExcepted, "atAdd");
        assertThat(atAdd).singleElement().satisfies(b -> {
            assertThat(b.teamId()).isEqualTo(payments);
            assertThat(b.teamName()).isEqualTo("Payments Platform");
            assertThat(b.members()).isEqualTo(2);
        });
    }

    @Test
    void snapshotsArePendingMigrationOutsideCanonicalDomainsAndMixedCampaignsKeepEachDomain() {
        UUID host = ownedHost(payments);
        UUID vuln = finding(host, "OPEN", null);
        UUID crypto = cryptoFinding(host);

        UUID mixed = create(findingsRequest("Mixed", List.of(vuln, crypto)));
        assertThat(snapshot(mixed, vuln)).isEqualTo("OWNED|" + payments + "|CREATE");
        assertThat(snapshot(mixed, crypto)).isEqualTo("LEGACY_PENDING_MIGRATION|null|CREATE");

        authority("CORE", "DARK");
        enter();
        UUID dark = create(findingsRequest("Dark", List.of(vuln)));
        assertThat(snapshot(dark, vuln)).isEqualTo("LEGACY_PENDING_MIGRATION|null|CREATE");
    }

    @Test
    void theCreateBoundLeavesTheCampaignMaterializingUntilTheReconcilerCompletesIt() {
        UUID host = ownedHost(payments);
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, status, finding_kind,
                    vulnerability_id, asset_id)
                SELECT gen_random_uuid(), ?, now(), now() - interval '5 minutes', 'AUTOMATIC', 'B-' || lpad(i::text, 6, '0'), 'CPE', 7.0, 'OPEN',
                       'VULNERABILITY', ?, ?
                  FROM generate_series(1, ?) i""", tenant.getId(), vulnerability, host, CampaignLedger.CREATE_BOUND + 3);

        UUID campaign = create(cveRequest("Large", false, List.of()));
        assertThat(count("campaign_findings")).isEqualTo(CampaignLedger.CREATE_BOUND);
        assertThat(membershipState(campaign)).isEqualTo(CampaignMembershipState.MATERIALIZING.name());
        assertThat(activities(campaign)).doesNotContain("NOTIFIED");

        assertThat(reconciler.reconcile(tenant, campaign)).isEqualTo(3);
        enter();
        assertThat(count("campaign_findings")).isEqualTo(CampaignLedger.CREATE_BOUND + 3);
        assertThat(membershipState(campaign)).isEqualTo(CampaignMembershipState.COMPLETE.name());
        assertThat(activities(campaign)).contains("MATERIALIZED", "NOTIFIED");
        assertThat(campaigns.reconciliation(tenant, campaign).lastAdded()).isEqualTo(3);
    }

    @Test
    void theReconcilerAddsNewAndReopenedFindingsOnlyOnceNeverRemovesAndSkipsClosedCampaigns() {
        UUID host = ownedHost(payments);
        UUID member = finding(host, "OPEN", null);
        UUID closedBefore = finding(host, "RESOLVED", FindingCloseReason.MANUAL_FIXED);
        UUID campaign = create(cveRequest("Rolling", false, List.of()));
        UUID closedCampaign = create(cveRequest("Done", false, List.of()));
        campaigns.updateStatus(tenant, closedCampaign, new CampaignStatusUpdateRequest(CampaignStatus.CLOSED, null), "analyst");

        UUID later = finding(host, "OPEN", null);
        setStatus(closedBefore, "OPEN", null);
        setStatus(member, "RESOLVED", FindingCloseReason.MANUAL_FIXED);
        jdbc.update("UPDATE findings SET updated_at = now() - interval '2 minutes'");

        assertThat(reconciler.runForTenant(tenant)).isEqualTo(2);
        enter();
        assertThat(memberIds(campaign)).containsExactlyInAnyOrder(member, closedBefore, later);
        assertThat(jdbc.queryForList("SELECT add_source FROM campaign_findings WHERE campaign_id = ? AND finding_id <> ?", String.class, campaign, member))
                .containsOnly("RECONCILER");
        assertThat(memberIds(closedCampaign)).containsExactly(member);

        // Idempotent under retry: the watermark has moved and a replay from the start adds nothing.
        assertThat(reconciler.reconcile(tenant, campaign)).isZero();
        enter();
        jdbc.update("UPDATE campaigns SET reconcile_watermark = NULL WHERE id = ?", campaign);
        assertThat(reconciler.reconcile(tenant, campaign)).isZero();
        enter();
        assertThat(memberIds(campaign)).hasSize(3);
    }

    @Test
    void threeConsecutiveReconcilerFailuresAreRecordedOnce() {
        finding(ownedHost(payments), "OPEN", null);
        UUID campaign = create(cveRequest("Broken", false, List.of()));
        // An unreadable watermark makes every batch fail; the finding is outside the in-flight window so it is scanned.
        jdbc.update("UPDATE findings SET updated_at = now() - interval '5 minutes'");
        jdbc.update("UPDATE campaigns SET reconcile_watermark = '{\"updatedAt\":\"not-a-time\"}'::jsonb WHERE id = ?", campaign);
        double before = metrics.counter(CampaignMembershipReconciler.FAILURE_METRIC).count();
        for (int i = 0; i < 4; i++) {
            reconciler.reconcile(tenant, campaign);
            enter();
        }
        assertThat(campaigns.reconciliation(tenant, campaign).consecutiveFailures()).isEqualTo(4);
        assertThat(campaigns.reconciliation(tenant, campaign).lastError()).isNotBlank();
        assertThat(activities(campaign).stream().filter("RECONCILE_FAILED"::equals)).hasSize(1);
        assertThat(metrics.counter(CampaignMembershipReconciler.FAILURE_METRIC).count()).isEqualTo(before + 1);
    }

    @Test
    void outcomesDriveTheMetricsAndExceptedMembersAreHiddenByDefault() {
        UUID host = ownedHost(payments);
        UUID fixed = finding(host, "OPEN", null);
        UUID accepted = finding(host, "OPEN", null);
        UUID reopened = finding(host, "OPEN", null);
        UUID excepted = finding(host, "OPEN", null);
        UUID open = finding(host, "OPEN", null);
        UUID campaign = create(cveRequest("Outcomes", false, List.of()));

        setStatus(fixed, "RESOLVED", FindingCloseReason.MANUAL_FIXED);
        setStatus(accepted, "AUTO_CLOSED", FindingCloseReason.MANUAL_ACCEPTED_RISK);
        jdbc.update("""
                INSERT INTO finding_events (id, tenant_id, actor, created_at, event_type, summary, finding_id, details_json)
                VALUES (gen_random_uuid(), ?, 'test', now() + interval '1 second', 'STATUS_CHANGED', 'reopened', ?, '{"from":"RESOLVED","to":"OPEN"}')""",
                tenant.getId(), reopened);
        UUID exception = campaigns.addException(tenant, campaign, new CampaignExceptionRequest(excepted, null, "Freeze", "Window", null), "analyst").id();
        campaigns.updateExceptionStatus(tenant, campaign, exception, new CampaignExceptionStatusUpdateRequest(CampaignExceptionStatus.APPROVED), "admin");

        var summary = campaigns.getDetail(tenant, campaign).summary();
        assertThat(summary.totalFindings()).isEqualTo(5);
        assertThat(summary.remediatedCount()).isEqualTo(1);
        assertThat(summary.activeRemainingCount()).isEqualTo(2);
        assertThat(summary.completionPercent()).isEqualTo(20);
        assertThat(summary.outcomes()).containsEntry("REMEDIATED", 1L).containsEntry("ACCEPTED_RISK", 1L).containsEntry("REOPENED", 1L)
                .containsEntry("CAMPAIGN_EXCEPTED", 1L).containsEntry("OPEN", 1L).containsEntry("FALSE_POSITIVE", 0L);

        assertThat(campaigns.members(tenant, campaign, null, false, null, null, null, null, 50).items())
                .extracting(CampaignMemberResponse::findingId).doesNotContain(accepted).contains(open, fixed);
        assertThat(campaigns.members(tenant, campaign, List.of("ACCEPTED_RISK"), false, null, null, null, null, 50).items())
                .extracting(CampaignMemberResponse::findingId).containsExactly(accepted);

        // Cursor paging over every member, two at a time.
        List<UUID> seen = new ArrayList<>();
        String cursor = null;
        do {
            CampaignMemberPage page = campaigns.members(tenant, campaign, null, true, null, null, null, cursor, 2);
            page.items().forEach(item -> seen.add(item.findingId()));
            cursor = page.nextCursor();
        } while (cursor != null);
        assertThat(seen).containsExactlyInAnyOrder(fixed, accepted, reopened, excepted, open);
    }

    @Test
    void outcomeSqlMatchesTheJavaClassifierForEveryStatusAndReason() {
        List<String> reasons = new ArrayList<>();
        reasons.add(null);
        for (FindingCloseReason reason : FindingCloseReason.values()) reasons.add(reason.name());
        String sql = "SELECT " + CampaignOutcomeClassifier.sql("?::text", "?::text", "?::boolean", "?::boolean");
        for (String status : List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED")) {
            for (String reason : reasons) {
                for (boolean excepted : new boolean[] { false, true }) {
                    for (boolean reopened : new boolean[] { false, true }) {
                        // Bind order follows the CASE: rule 1 (status, status, reason), rules 2-4 (status, reason), rule 5, 6, 7.
                        Object[] args = { status, status, reason, status, reason, status, reason, status, reason, status, excepted, reopened };
                        assertThat(jdbc.queryForObject(sql, String.class, args)).as(status + "/" + reason + "/" + excepted + "/" + reopened)
                                .isEqualTo(CampaignOutcomeClassifier.classify(status, reason, excepted, reopened).name());
                    }
                }
            }
        }
    }

    @Test
    void exceptionsNeedAMemberSnapshotTheOwnerAndNeverChangeTheFinding() {
        UUID host = ownedHost(payments);
        UUID member = finding(host, "OPEN", null);
        UUID campaign = create(cveRequest("Exceptions", false, List.of()));
        UUID outsider = finding(ownedHost(identity), "OPEN", null);

        assertThatThrownBy(() -> campaigns.addException(tenant, campaign, new CampaignExceptionRequest(outsider, null, "t", "r", null), "a"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(409));
        String displayId = jdbc.queryForObject("SELECT display_id FROM findings WHERE id = ?", String.class, member);
        var exception = campaigns.addException(tenant, campaign, new CampaignExceptionRequest(null, displayId, "Freeze", "Window", null), "a");
        assertThat(exception.findingId()).isEqualTo(member);
        assertThat(exception.ownerTeamIdAtRequest()).isEqualTo(payments);
        campaigns.updateExceptionStatus(tenant, campaign, exception.id(), new CampaignExceptionStatusUpdateRequest(CampaignExceptionStatus.APPROVED), "a");
        assertThat(jdbc.queryForObject("SELECT status || '|' || coalesce(closed_reason, '-') FROM findings WHERE id = ?", String.class, member))
                .isEqualTo("OPEN|-");
    }

    @Test
    void findingsWithCampaignMembershipCannotBeDeletedAndManualAddsAreRecorded() {
        UUID host = ownedHost(payments);
        UUID member = finding(host, "OPEN", null);
        UUID campaign = create(findingsRequest("Manual", List.of(member)));
        UUID extra = finding(host, "RESOLVED", FindingCloseReason.MANUAL_FIXED);
        campaigns.addMembers(tenant, campaign, new CampaignAddMembersRequest(List.of(extra, member)), "analyst");
        assertThat(snapshot(campaign, extra)).isEqualTo("OWNED|" + payments + "|MANUAL");
        assertThat(snapshot(campaign, member)).endsWith("|CREATE");
        assertThatThrownBy(() -> jdbc.update("DELETE FROM findings WHERE id = ?", member)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void teamRecipientsUseTheTeamChannelAndCustomRecipientsAreEncryptedAndRoleChecked() {
        ownedHost(payments);
        UUID campaign = create(cveRequest("Recipients", false, List.of(
                new CampaignNotifyGroupRequest(CampaignRecipientType.TEAM, payments, null, null, null, null, false),
                new CampaignNotifyGroupRequest(null, null, "Vendor desk", "vendor@example.test", null, null, false))));
        assertThat(delivery(campaign, "TEAM")).isEqualTo("SKIPPED|Team has no notification channel");
        assertThat(delivery(campaign, "GROUP")).isEqualTo("QUEUED|null");
        assertThat(jdbc.queryForObject("SELECT group_email_enc FROM campaign_notify_groups WHERE recipient_type = 'CUSTOM'", String.class))
                .startsWith("enc:t1:");
        CampaignDetailResponse detail = campaigns.getDetail(tenant, campaign);
        assertThat(detail.notifyGroups()).anySatisfy(g -> {
            assertThat(g.recipientType()).isEqualTo(CampaignRecipientType.CUSTOM);
            assertThat(g.groupEmail()).isEqualTo("vendor@example.test");
            assertThat(g.ownerRecipient()).isFalse();
        });
        assertThat(activities(campaign)).contains("CUSTOM_RECIPIENT_ADDED");

        teams.setNotificationEmail(payments, "Payments@Example.test", teams.team(payments).orElseThrow().version(), "admin");
        assertThat(jdbc.queryForObject("SELECT notification_email_enc FROM team WHERE id = ?", String.class, payments)).startsWith("enc:t1:");
        UUID second = create(cveRequest("Recipients 2", false, List.of(
                new CampaignNotifyGroupRequest(CampaignRecipientType.TEAM, payments, null, null, null, null, false))));
        assertThat(jdbc.queryForObject("SELECT delivery_state || '|' || target_address FROM campaign_delivery_attempts WHERE campaign_id = ?"
                + " AND target_type = 'TEAM'", String.class, second)).isEqualTo("QUEUED|payments@example.test");

        // Custom recipients need TENANT_ADMIN or SECURITY_ANALYST; a request naming an owner is rejected.
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("owner", "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_INVENTORY_ADMIN"))));
        assertThatThrownBy(() -> create(cveRequest("No role", false, List.of(
                new CampaignNotifyGroupRequest(null, null, "Desk", "desk@example.test", null, null, false)))))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(403));
        CampaignCreateRequest named = new CampaignCreateRequest("Owner", null, List.of(cve), null, null, null, null, null, null, null, null,
                new com.fasterxml.jackson.databind.node.TextNode("Platform Ops"), null);
        assertThatThrownBy(() -> campaigns.create(tenant, named, "analyst"))
                .isInstanceOfSatisfying(ResponseStatusException.class, e -> assertThat(e.getStatusCode().value()).isEqualTo(400));
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private UUID create(CampaignCreateRequest request) {
        UUID id = campaigns.create(tenant, request, "analyst").summary().id();
        enter();
        return id;
    }

    private CampaignCreateRequest cveRequest(String name, boolean includeExcepted, List<CampaignNotifyGroupRequest> groups) {
        return new CampaignCreateRequest(name, null, List.of(cve), null, Instant.now().plusSeconds(86_400), null, null, includeExcepted,
                groups, List.of(), null, null, null);
    }

    private CampaignCreateRequest findingsRequest(String name, List<UUID> findingIds) {
        return new CampaignCreateRequest(name, null, null, findingIds, null, null, null, null, null, null, null, null, null);
    }

    private UUID ownedHost(UUID team) {
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO assets (id, business_criticality, created_at, identifier, name, state, type) VALUES (?, 'HIGH', now(), ?, ?, 'ACTIVE', 'HOST')",
                id, "host-" + id, "host-" + id);
        claims.recordClaim(serviceNow(inventory.subjectForAsset(id).orElseThrow(), team, "ci-" + id));
        return id;
    }

    private UUID assetSubject(UUID host) {
        return inventory.subjectForAsset(host).orElseThrow();
    }

    private UUID finding(UUID asset, String status, FindingCloseReason reason) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, status, closed_reason,
                    finding_kind, vulnerability_id, asset_id)
                VALUES (?, ?, now(), now(), 'AUTOMATIC', ?, 'CPE', 7.0, ?, ?, 'VULNERABILITY', ?, ?)""",
                id, tenant.getId(), "F-" + id.toString().substring(0, 8), status, reason == null ? null : reason.name(), vulnerability, asset);
        findingSubjects.subjectForFinding(id);
        return id;
    }

    private UUID cryptoFinding(UUID asset) {
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO findings (id, tenant_id, created_at, updated_at, creation_source, display_id, matched_by, risk_score, status, finding_kind, asset_id)
                VALUES (?, ?, now(), now(), 'AUTOMATIC', ?, 'CBOM_RULE', 5.0, 'OPEN', 'CRYPTO', ?)""",
                id, tenant.getId(), "C-" + id.toString().substring(0, 8), asset);
        return id;
    }

    private void setStatus(UUID finding, String status, FindingCloseReason reason) {
        jdbc.update("UPDATE findings SET status = ?, closed_reason = ?, updated_at = now() WHERE id = ?", status,
                reason == null ? null : reason.name(), finding);
    }

    private List<UUID> memberIds(UUID campaign) {
        return jdbc.queryForList("SELECT finding_id FROM campaign_findings WHERE campaign_id = ?", UUID.class, campaign);
    }

    private String snapshot(UUID campaign, UUID finding) {
        return jdbc.queryForObject("SELECT ownership_status_at_add || '|' || coalesce(owner_team_id_at_add::text, 'null') || '|' || add_source"
                + " FROM campaign_findings WHERE campaign_id = ? AND finding_id = ?", String.class, campaign, finding);
    }

    private String membershipState(UUID campaign) {
        return jdbc.queryForObject("SELECT membership_state FROM campaigns WHERE id = ?", String.class, campaign);
    }

    private List<String> activities(UUID campaign) {
        return jdbc.queryForList("SELECT activity_type FROM campaign_activities WHERE campaign_id = ?", String.class, campaign);
    }

    private String delivery(UUID campaign, String targetType) {
        return jdbc.queryForObject("SELECT delivery_state || '|' || coalesce(detail, 'null') FROM campaign_delivery_attempts"
                + " WHERE campaign_id = ? AND target_type = ?", String.class, campaign, targetType);
    }

    private int count(String table) {
        Integer n = jdbc.queryForObject("SELECT count(*) FROM " + table, Integer.class);
        return n == null ? 0 : n;
    }

    private ClaimRequest serviceNow(UUID subject, UUID team, String ref) {
        return new ClaimRequest(subject, team, null, "SERVICENOW", "SERVICENOW", null, "servicenow:cmdb_ci:" + ref + ":support_group", "v1",
                "servicenow-cmdb-1", Instant.now(), null, null, null, "test");
    }

    private void analyst() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("analyst", "n/a",
                List.of(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"))));
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
}
