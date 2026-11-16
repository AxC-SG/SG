package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.Campaign;
import com.prototype.vulnwatch.domain.CampaignActivity;
import com.prototype.vulnwatch.domain.CampaignDeliveryAttempt;
import com.prototype.vulnwatch.domain.CampaignException;
import com.prototype.vulnwatch.domain.CampaignExceptionStatus;
import com.prototype.vulnwatch.domain.CampaignMembershipState;
import com.prototype.vulnwatch.domain.CampaignNote;
import com.prototype.vulnwatch.domain.CampaignNotifyGroup;
import com.prototype.vulnwatch.domain.CampaignRecipientType;
import com.prototype.vulnwatch.domain.CampaignScopeKind;
import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.CampaignVulnerability;
import com.prototype.vulnwatch.domain.CampaignWatchlistEntry;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignActivityResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAddMembersRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAssetRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDeliveryAttemptResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignEvidenceRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFindingRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignMemberPage;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignMemberResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignOwnerBucket;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignPreviewResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignReconciliationResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignSummaryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignVulnerabilityResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.OwnerAtAdd;
import com.prototype.vulnwatch.dto.CampaignDtos.PreviewTeam;
import com.prototype.vulnwatch.repo.CampaignActivityRepository;
import com.prototype.vulnwatch.repo.CampaignDeliveryAttemptRepository;
import com.prototype.vulnwatch.repo.CampaignExceptionRepository;
import com.prototype.vulnwatch.repo.CampaignNoteRepository;
import com.prototype.vulnwatch.repo.CampaignNotifyGroupRepository;
import com.prototype.vulnwatch.repo.CampaignRepository;
import com.prototype.vulnwatch.repo.CampaignVulnerabilityRepository;
import com.prototype.vulnwatch.repo.CampaignWatchlistEntryRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.CampaignLedger.AddSource;
import com.prototype.vulnwatch.service.CampaignLedger.Grouping;
import com.prototype.vulnwatch.service.CampaignLedger.MemberFilter;
import com.prototype.vulnwatch.service.CampaignLedger.MemberRow;
import com.prototype.vulnwatch.service.CampaignOutcomeClassifier.Outcome;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * Remediation campaigns over the membership ledger (Phase 0B §4). Membership lives only in {@code campaign_findings}
 * ({@link CampaignLedger}); CVE scope is {@code campaign_vulnerabilities}. A campaign never sets ownership: launch
 * may name an assignee principal and a coordinating team, and owner state is read per member.
 */
@Service
public class CampaignService {

    /** §4.2: the finding-scope cap, also the bound of one add-findings call. */
    public static final int MAX_CAMPAIGN_FINDINGS = 500;
    public static final int MAX_MEMBER_PAGE = OwnershipReadAdapter.MAX_IDS;
    static final String P_RECIPIENT_EMAIL = "campaign.recipient.email";
    private static final Set<String> CUSTOM_RECIPIENT_ROLES = Set.of("TENANT_ADMIN", "SECURITY_ANALYST");
    private static final Set<CampaignStatus> FINISHED = Set.of(CampaignStatus.CLOSED, CampaignStatus.CANCELLED);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final CampaignRepository campaignRepository;
    private final CampaignVulnerabilityRepository campaignVulnerabilityRepository;
    private final CampaignNotifyGroupRepository campaignNotifyGroupRepository;
    private final CampaignWatchlistEntryRepository campaignWatchlistEntryRepository;
    private final CampaignNoteRepository campaignNoteRepository;
    private final CampaignActivityRepository campaignActivityRepository;
    private final CampaignDeliveryAttemptRepository campaignDeliveryAttemptRepository;
    private final CampaignExceptionRepository campaignExceptionRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final CampaignLedger ledger;
    private final OwnershipReadAdapter ownershipReads;
    private final TeamNamespaceService teams;
    private final TenantDataCipher cipher;
    private final JdbcTemplate jdbc;
    private TransactionTemplate readTransactionTemplate;
    private TransactionTemplate writeTransactionTemplate;
    private RequestActorService requestActors;
    private CampaignEmailOutboxService emailOutbox;

    public CampaignService(
            CampaignRepository campaignRepository,
            CampaignVulnerabilityRepository campaignVulnerabilityRepository,
            CampaignNotifyGroupRepository campaignNotifyGroupRepository,
            CampaignWatchlistEntryRepository campaignWatchlistEntryRepository,
            CampaignNoteRepository campaignNoteRepository,
            CampaignActivityRepository campaignActivityRepository,
            CampaignDeliveryAttemptRepository campaignDeliveryAttemptRepository,
            CampaignExceptionRepository campaignExceptionRepository,
            VulnerabilityRepository vulnerabilityRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            CampaignLedger ledger,
            OwnershipReadAdapter ownershipReads,
            TeamNamespaceService teams,
            TenantDataCipher cipher,
            JdbcTemplate jdbc
    ) {
        this.campaignRepository = campaignRepository;
        this.campaignVulnerabilityRepository = campaignVulnerabilityRepository;
        this.campaignNotifyGroupRepository = campaignNotifyGroupRepository;
        this.campaignWatchlistEntryRepository = campaignWatchlistEntryRepository;
        this.campaignNoteRepository = campaignNoteRepository;
        this.campaignActivityRepository = campaignActivityRepository;
        this.campaignDeliveryAttemptRepository = campaignDeliveryAttemptRepository;
        this.campaignExceptionRepository = campaignExceptionRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.ledger = ledger;
        this.ownershipReads = ownershipReads;
        this.teams = teams;
        this.cipher = cipher;
        this.jdbc = jdbc;
    }

    @Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Autowired
    void configure(RequestActorService requestActors, CampaignEmailOutboxService outbox) {
        this.requestActors = requestActors;
        this.emailOutbox = outbox;
    }

    // ------------------------------------------------------------------ list, detail, create

    public List<CampaignSummaryResponse> list(Tenant tenant, CampaignStatus status) {
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            List<Campaign> campaigns = status == null
                    ? campaignRepository.findAllByTenant_IdOrderByUpdatedAtDesc(tenant.getId())
                    : campaignRepository.findAllByTenant_IdAndStatusOrderByUpdatedAtDesc(tenant.getId(), status);
            return campaigns.stream().map(this::toSummary).toList();
        }));
    }

    public CampaignDetailResponse create(Tenant tenant, CampaignCreateRequest request, String actor) {
        Spec spec = specFor(request);
        return tenantSchemaExecutionService.run(tenant, () -> {
            UUID campaignId = executeWrite(() -> createInCurrentTenantSchema(tenant, spec, actor));
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    /** Creates a campaign over existing findings in this tenant; unknown IDs are rejected. */
    public CampaignDetailResponse createFromFindings(Tenant tenant, CampaignFromFindingsRequest request, String actor) {
        if (request == null || isBlank(request.name())) throw badRequest("name is required");
        if (request.ownerGroup() != null) throw badRequest("Campaigns do not set ownership; ownerGroup is not accepted");
        if (request.assignedTo() != null) throw badRequest("assignedTo is not accepted; use assigneePrincipalId");
        Spec spec = new Spec(request.name().trim(), trimToNull(request.summary()), request.dueAt(), CampaignScopeKind.FINDINGS, List.of(),
                findingIds(request.findingIds()), request.assigneePrincipalId(), null, false, List.of(), List.of(), request.launchNote());
        return tenantSchemaExecutionService.run(tenant, () -> {
            UUID campaignId = executeWrite(() -> createInCurrentTenantSchema(tenant, spec, actor));
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public CampaignDetailResponse getDetail(Tenant tenant, UUID campaignId) {
        return tenantSchemaExecutionService.run(tenant, () -> getDetailInCurrentTenantSchema(tenant, campaignId));
    }

    /** §4.2 preview: the same body as create, writing nothing. */
    public CampaignPreviewResponse preview(Tenant tenant, CampaignCreateRequest request) {
        Spec spec = specFor(request);
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            List<UUID> vulnerabilityIds = spec.scope() == CampaignScopeKind.CVE
                    ? resolveVulnerabilities(spec.cveIds()).stream().map(Vulnerability::getId).toList() : null;
            CampaignLedger.PreviewCounts counts = ledger.preview(vulnerabilityIds,
                    spec.scope() == CampaignScopeKind.FINDINGS ? spec.findingIds() : null, spec.includeExcepted());
            List<UUID> teamIds = new ArrayList<>(counts.ownerTeams());
            for (CampaignNotifyGroupRequest group : spec.notifyGroups()) {
                if (group.recipientType() == CampaignRecipientType.TEAM && group.teamId() != null && !teamIds.contains(group.teamId())) {
                    teamIds.add(group.teamId());
                }
            }
            List<PreviewTeam> withoutChannel = teamIds.isEmpty() ? List.of() : jdbc.query(
                    "SELECT id, name FROM team WHERE id = ANY (?::uuid[]) AND notification_email_enc IS NULL ORDER BY name",
                    (rs, n) -> new PreviewTeam(rs.getObject(1, UUID.class), rs.getString(2)), array(teamIds));
            return new CampaignPreviewResponse(counts.eligible(),
                    spec.scope() == CampaignScopeKind.CVE && counts.eligible() > CampaignLedger.CREATE_BOUND,
                    counts.distribution(), counts.excluded(), withoutChannel);
        }));
    }

    private record Spec(String name, String summary, Instant dueAt, CampaignScopeKind scope, List<String> cveIds, List<UUID> findingIds,
                        UUID assigneePrincipalId, UUID coordinatingTeamId, boolean includeExcepted,
                        List<CampaignNotifyGroupRequest> notifyGroups, List<CampaignWatchlistEntryRequest> watchlist, String launchNote) { }

    private static Spec specFor(CampaignCreateRequest request) {
        if (request == null || isBlank(request.name())) throw badRequest("name is required");
        if (request.ownerGroup() != null || request.supportGroup() != null) {
            throw badRequest("Campaigns do not set ownership; ownerGroup and supportGroup are not accepted");
        }
        List<String> cves = nullSafe(request.cveIds()).stream().filter(Objects::nonNull).map(String::trim).filter(v -> !v.isEmpty())
                .distinct().toList();
        boolean byFindings = request.findingIds() != null && !request.findingIds().isEmpty();
        if (!cves.isEmpty() == byFindings) throw badRequest("Provide either cveIds or findingIds");
        return new Spec(request.name().trim(), trimToNull(request.summary()), request.dueAt(),
                byFindings ? CampaignScopeKind.FINDINGS : CampaignScopeKind.CVE, cves, byFindings ? findingIds(request.findingIds()) : List.of(),
                request.assigneePrincipalId(), request.coordinatingTeamId(), Boolean.TRUE.equals(request.includeExcepted()),
                nullSafe(request.notifyGroups()).stream().filter(Objects::nonNull).toList(),
                nullSafe(request.watchlist()), request.launchNote());
    }

    private static List<UUID> findingIds(List<UUID> requested) {
        List<UUID> ids = nullSafe(requested).stream().filter(Objects::nonNull).distinct().toList();
        if (ids.isEmpty()) throw badRequest("At least one finding is required");
        if (ids.size() > MAX_CAMPAIGN_FINDINGS) throw badRequest("A campaign can start with at most " + MAX_CAMPAIGN_FINDINGS + " findings");
        return ids;
    }

    private UUID createInCurrentTenantSchema(Tenant tenant, Spec spec, String actor) {
        if (spec.assigneePrincipalId() != null) requireActiveMember(tenant, spec.assigneePrincipalId());
        if (spec.coordinatingTeamId() != null) requireActiveTeam(spec.coordinatingTeamId());
        List<PreparedRecipient> recipients = new ArrayList<>();
        for (CampaignNotifyGroupRequest group : spec.notifyGroups()) {
            if (group.recipientType() != CampaignRecipientType.TEAM && isBlank(group.groupName())) continue;
            recipients.add(prepareRecipient(tenant, group));
        }
        List<Vulnerability> vulnerabilities = spec.scope() == CampaignScopeKind.CVE ? resolveVulnerabilities(spec.cveIds()) : List.of();

        Campaign campaign = new Campaign();
        campaign.setTenant(tenant);
        campaign.setScopeKind(spec.scope());
        campaign.setMembershipState(CampaignMembershipState.COMPLETE);
        campaign.setName(spec.name());
        campaign.setSummary(spec.summary());
        campaign.setStatus(CampaignStatus.ACTIVE);
        campaign.setCreatedBy(actor);
        campaign.setDueAt(spec.dueAt());
        campaign.setStartedAt(Instant.now());
        campaign.setAssigneePrincipalId(spec.assigneePrincipalId());
        campaign.setCoordinatingTeamId(spec.coordinatingTeamId());
        campaign.setIncludeExcepted(spec.includeExcepted());
        campaign.touch();
        // Flushed so the set-based member insert below can reference the campaign and its CVE links.
        Campaign saved = campaignRepository.saveAndFlush(campaign);

        int members;
        boolean materializing = false;
        if (spec.scope() == CampaignScopeKind.CVE) {
            for (Vulnerability vulnerability : vulnerabilities) {
                CampaignVulnerability link = new CampaignVulnerability();
                link.setCampaign(saved);
                link.setVulnerability(vulnerability);
                link.setExternalId(vulnerability.getExternalId());
                link.setTitle(vulnerability.getTitle());
                link.setSeverity(vulnerability.getSeverity());
                campaignVulnerabilityRepository.save(link);
            }
            campaignVulnerabilityRepository.flush();
            members = ledger.materializeCve(saved.getId(), spec.includeExcepted(), actor, CampaignLedger.CREATE_BOUND);
            if (ledger.hasUnmaterialized(saved.getId(), spec.includeExcepted())) {
                ledger.setMembershipState(saved.getId(), CampaignMembershipState.MATERIALIZING.name());
                materializing = true;
            }
            ledger.initializeWatermark(saved.getId(), materializing);
        } else {
            if (ledger.countExisting(spec.findingIds()) != spec.findingIds().size()) {
                throw badRequest((spec.findingIds().size() - ledger.countExisting(spec.findingIds())) + " finding(s) were not found in this workspace");
            }
            members = ledger.addFindings(saved.getId(), spec.findingIds(), actor, AddSource.CREATE);
        }

        for (PreparedRecipient recipient : recipients) {
            CampaignNotifyGroup group = new CampaignNotifyGroup();
            group.setCampaign(saved);
            recipient.applyTo(group);
            campaignNotifyGroupRepository.save(group);
            if (recipient.type() == CampaignRecipientType.CUSTOM) {
                recordActivity(saved, actor, "CUSTOM_RECIPIENT_ADDED", "Custom recipient added (not an owner recipient): " + group.getGroupName() + ".");
            }
        }
        for (CampaignWatchlistEntryRequest watchRequest : spec.watchlist()) {
            if (watchRequest == null || isBlank(watchRequest.label())) continue;
            CampaignWatchlistEntry entry = new CampaignWatchlistEntry();
            entry.setCampaign(saved);
            entry.setEntryType(watchRequest.entryType());
            entry.setLabel(watchRequest.label().trim());
            entry.setEmail(trimToNull(watchRequest.email()));
            entry.setTriggerPolicy(trimToNull(watchRequest.triggerPolicy()));
            entry.setActive(!Boolean.FALSE.equals(watchRequest.active()));
            campaignWatchlistEntryRepository.save(entry);
        }
        if (!isBlank(spec.launchNote())) {
            CampaignNote note = new CampaignNote();
            note.setCampaign(saved);
            note.setAuthor(actor);
            note.setBody(spec.launchNote().trim());
            campaignNoteRepository.save(note);
        }
        String source = spec.scope() == CampaignScopeKind.CVE
                ? spec.cveIds().size() + " CVE" + (spec.cveIds().size() == 1 ? "" : "s")
                : spec.findingIds().size() + " finding" + (spec.findingIds().size() == 1 ? "" : "s");
        recordActivity(saved, actor, "CREATED", "Campaign created from " + source + " with " + members + " member"
                + (members == 1 ? "" : "s") + (materializing ? "; the remaining members are added in batches." : "."));
        // §4.6: launch notifications wait until every member is materialized.
        if (!materializing) deliverLaunchNotifications(saved, actor);
        return saved.getId();
    }

    private List<Vulnerability> resolveVulnerabilities(List<String> cveIds) {
        Map<String, Vulnerability> byExternalId = vulnerabilityRepository.findByExternalIdIn(cveIds).stream()
                .collect(Collectors.toMap(Vulnerability::getExternalId, Function.identity(), (a, b) -> a));
        List<Vulnerability> resolved = new ArrayList<>();
        for (String cveId : cveIds) {
            Vulnerability vulnerability = byExternalId.get(cveId);
            if (vulnerability == null) throw badRequest("Unknown CVE: " + cveId);
            resolved.add(vulnerability);
        }
        return resolved;
    }

    /** The same check as {@code findings.assignee_principal_id}: an ACTIVE user with an ACTIVE membership here. */
    private void requireActiveMember(Tenant tenant, UUID principalId) {
        Boolean active = jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM platform.tenant_memberships m JOIN platform.app_users u ON u.id = m.user_id
                                WHERE m.tenant_id = ? AND m.user_id = ? AND m.status = 'ACTIVE' AND u.status = 'ACTIVE')
                """, Boolean.class, tenant.getId(), principalId);
        if (!Boolean.TRUE.equals(active)) throw badRequest("assigneePrincipalId is not an active member of this workspace");
    }

    private void requireActiveTeam(UUID teamId) {
        List<String> status = jdbc.queryForList("SELECT status FROM team WHERE id = ?", String.class, teamId);
        if (status.isEmpty()) throw badRequest("Team not found: " + teamId);
        if (!"ACTIVE".equals(status.get(0))) throw badRequest("Team is not active: " + teamId);
    }

    // ------------------------------------------------------------------ members

    public CampaignMemberPage members(Tenant tenant, UUID campaignId, List<String> outcomes, boolean includeHidden, String groupBy,
                                      String bucket, UUID teamId, String cursor, int limit) {
        List<Outcome> wanted = new ArrayList<>();
        for (String value : nullSafe(outcomes)) {
            for (String part : value.split(",")) {
                if (part.isBlank()) continue;
                try { wanted.add(Outcome.valueOf(part.strip().toUpperCase(Locale.ROOT))); }
                catch (IllegalArgumentException unknown) { throw badRequest("Unknown outcome: " + part.strip()); }
            }
        }
        Grouping grouping = grouping(groupBy);
        String bucketName = bucket == null || bucket.isBlank() ? null : bucket.strip().toUpperCase(Locale.ROOT);
        if (bucketName != null && !Set.of("TEAM", "UNOWNED", "CONFLICT", "PENDING_MIGRATION", "NOT_RECORDED").contains(bucketName)) {
            throw badRequest("Unknown owner bucket: " + bucket);
        }
        int page = Math.max(1, Math.min(limit <= 0 ? 50 : limit, MAX_MEMBER_PAGE));
        Cursor after = Cursor.decode(cursor);
        MemberFilter filter = new MemberFilter(wanted, includeHidden, grouping, bucketName, teamId);
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            loadCampaign(tenant, campaignId);
            List<MemberRow> rows = ledger.page(campaignId, filter, after == null ? null : after.addedAt(),
                    after == null ? null : after.findingId(), page + 1);
            boolean more = rows.size() > page;
            List<MemberRow> items = more ? rows.subList(0, page) : rows;
            Map<UUID, Summary> current = currentOwnership(items.stream().map(MemberRow::findingId).toList());
            List<CampaignMemberResponse> responses = items.stream().map(row -> toMember(row, current.get(row.findingId()))).toList();
            MemberRow last = items.isEmpty() ? null : items.get(items.size() - 1);
            return new CampaignMemberPage(responses, more && last != null ? new Cursor(last.addedAt(), last.findingId()).encode() : null);
        }));
    }

    /** Add-findings action (§4.12): writes members with {@code add_source = 'MANUAL'} and their live snapshot. */
    public CampaignDetailResponse addMembers(Tenant tenant, UUID campaignId, CampaignAddMembersRequest request, String actor) {
        List<UUID> ids = findingIds(request == null ? null : request.findingIds());
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                if (FINISHED.contains(campaign.getStatus())) throw new ResponseStatusException(HttpStatus.CONFLICT, "The campaign is " + campaign.getStatus());
                int existing = ledger.countExisting(ids);
                if (existing != ids.size()) throw badRequest((ids.size() - existing) + " finding(s) were not found in this workspace");
                int added = ledger.addFindings(campaignId, ids, actor, AddSource.MANUAL);
                campaign.touch();
                campaignRepository.save(campaign);
                recordActivity(campaign, actor, "MEMBERS_ADDED", "Added " + added + " finding" + (added == 1 ? "" : "s") + " to the campaign.");
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public List<CampaignOwnerBucket> buckets(Tenant tenant, UUID campaignId, String groupBy) {
        Grouping grouping = grouping(groupBy);
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            loadCampaign(tenant, campaignId);
            return ledger.buckets(campaignId, grouping);
        }));
    }

    public CampaignReconciliationResponse reconciliation(Tenant tenant, UUID campaignId) {
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            loadCampaign(tenant, campaignId);
            return jdbc.queryForObject("""
                    SELECT c.scope_kind, c.membership_state, c.reconciled_at, c.reconcile_watermark::text, c.last_reconcile_added,
                           c.last_reconcile_error, c.reconcile_failures,
                           (SELECT count(*) FROM campaign_findings cf WHERE cf.campaign_id = c.id)
                      FROM campaigns c WHERE c.id = ?
                    """, (rs, n) -> new CampaignReconciliationResponse(campaignId, CampaignScopeKind.valueOf(rs.getString(1)),
                    CampaignMembershipState.valueOf(rs.getString(2)), rs.getTimestamp(3) == null ? null : rs.getTimestamp(3).toInstant(),
                    readJson(rs.getString(4)), (Integer) rs.getObject(5), rs.getString(6), rs.getInt(7), rs.getLong(8)), campaignId);
        }));
    }

    private static Grouping grouping(String groupBy) {
        if (groupBy == null || groupBy.isBlank() || "current".equalsIgnoreCase(groupBy)) return Grouping.CURRENT;
        if ("atAdd".equalsIgnoreCase(groupBy) || "AT_ADD".equalsIgnoreCase(groupBy)) return Grouping.AT_ADD;
        throw badRequest("groupBy must be current or atAdd");
    }

    private Map<UUID, Summary> currentOwnership(List<UUID> findingIds) {
        Map<UUID, Summary> byId = new HashMap<>();
        for (int from = 0; from < findingIds.size(); from += OwnershipReadAdapter.MAX_IDS) {
            ownershipReads.forFindings(Consumer.CAMPAIGNS, findingIds.subList(from, Math.min(findingIds.size(), from + OwnershipReadAdapter.MAX_IDS)))
                    .forEach(summary -> byId.put(summary.objectId(), summary));
        }
        return byId;
    }

    private static CampaignMemberResponse toMember(MemberRow row, Summary current) {
        OwnerAtAdd atAdd = row.ownerAtAdd();
        boolean atAddCanonical = atAdd.status() != null && !"LEGACY_PENDING_MIGRATION".equals(atAdd.status());
        boolean nowCanonical = current != null && "CANONICAL".equals(current.authorityState());
        boolean changed = atAddCanonical && nowCanonical && current.ownershipStatus() != null
                && (!Objects.equals(atAdd.teamId(), current.ownerTeamId()) || !Objects.equals(atAdd.status(), current.ownershipStatus()));
        boolean assignedSince = "LEGACY_PENDING_MIGRATION".equals(atAdd.status()) && nowCanonical;
        return new CampaignMemberResponse(row.findingId(), row.displayId(), row.title(), row.findingKind(), row.severity(), row.status(),
                row.closedReason(), row.outcome(), row.suppressedUntil(), row.dueAt(), row.assetId(), row.assetName(), row.addedAt(),
                row.addedBy(), row.addSource(), atAdd, current, changed, assignedSince, row.campaignExceptionStatus());
    }

    /** Keyset cursor over {@code (added_at, finding_id)}. */
    private record Cursor(Instant addedAt, UUID findingId) {
        String encode() {
            return Base64.getUrlEncoder().withoutPadding().encodeToString((addedAt + "|" + findingId).getBytes(StandardCharsets.UTF_8));
        }

        static Cursor decode(String value) {
            if (value == null || value.isBlank()) return null;
            try {
                String[] parts = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split("\\|", 2);
                return new Cursor(Instant.parse(parts[0]), UUID.fromString(parts[1]));
            } catch (RuntimeException invalid) {
                throw badRequest("Invalid cursor");
            }
        }
    }

    // ------------------------------------------------------------------ lifecycle

    public CampaignDetailResponse updateStatus(Tenant tenant, UUID campaignId, CampaignStatusUpdateRequest request, String actor) {
        if (request == null || request.status() == null) throw badRequest("status is required");
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                campaign.setStatus(request.status());
                if (request.status() == CampaignStatus.ACTIVE && campaign.getStartedAt() == null) campaign.setStartedAt(Instant.now());
                if (request.status() == CampaignStatus.PAUSED) campaign.setPausedAt(Instant.now());
                if (FINISHED.contains(request.status())) campaign.setClosedAt(Instant.now());
                campaign.touch();
                campaignRepository.save(campaign);
                recordActivity(campaign, actor, "STATUS_CHANGED", "Campaign moved to " + request.status() + ".");
                notifyWatchlistForEvent(campaign, actor, "STATUS_CHANGES", "Campaign status changed to " + request.status() + ".");
                if (!isBlank(request.note())) {
                    CampaignNote note = new CampaignNote();
                    note.setCampaign(campaign);
                    note.setAuthor(actor);
                    note.setBody(request.note().trim());
                    campaignNoteRepository.save(note);
                }
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public CampaignNoteResponse addNote(Tenant tenant, UUID campaignId, CampaignNoteRequest request, String actor) {
        if (request == null || isBlank(request.body())) throw badRequest("body is required");
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            Campaign campaign = loadCampaign(tenant, campaignId);
            CampaignNote note = new CampaignNote();
            note.setCampaign(campaign);
            note.setAuthor(actor);
            note.setBody(request.body().trim());
            CampaignNote saved = campaignNoteRepository.save(note);
            recordActivity(campaign, actor, "NOTE_ADDED", "Added a campaign note.");
            notifyWatchlistForEvent(campaign, actor, "NOTES_ONLY", "New campaign note: " + saved.getBody());
            campaign.touch();
            campaignRepository.save(campaign);
            return new CampaignNoteResponse(saved.getId(), saved.getAuthor(), saved.getBody(), saved.getCreatedAt());
        }));
    }

    public CampaignDetailResponse updateNotifyGroup(Tenant tenant, UUID campaignId, UUID notifyGroupId, CampaignNotifyGroupRequest request,
                                                    String actor) {
        if (request == null) throw badRequest("A recipient is required");
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                CampaignNotifyGroup group = campaignNotifyGroupRepository.findById(notifyGroupId)
                        .filter(item -> item.getCampaign().getId().equals(campaignId))
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign notify group not found"));
                CampaignRecipientType type = request.recipientType() == null ? group.getRecipientType() : request.recipientType();
                if (type == CampaignRecipientType.CUSTOM && isBlank(request.groupName())) throw badRequest("groupName is required");
                PreparedRecipient recipient = prepareRecipient(tenant, new CampaignNotifyGroupRequest(type,
                        request.teamId() == null && type == CampaignRecipientType.TEAM ? group.getTeamId() : request.teamId(),
                        request.groupName(), request.groupEmail(), request.roleLabel(), request.triggerSummary(), request.notificationsPaused()));
                recipient.applyTo(group);
                campaignNotifyGroupRepository.save(group);
                campaign.touch();
                campaignRepository.save(campaign);
                if (type == CampaignRecipientType.CUSTOM) {
                    recordActivity(campaign, actor, "CUSTOM_RECIPIENT_UPDATED", "Custom recipient updated (not an owner recipient): " + group.getGroupName() + ".");
                } else {
                    recordActivity(campaign, actor, "GROUP_UPDATED", "Team recipient updated: " + group.getGroupName() + ".");
                }
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public CampaignDetailResponse updateWatchlistEntry(Tenant tenant, UUID campaignId, UUID watchlistEntryId,
                                                       CampaignWatchlistEntryUpdateRequest request, String actor) {
        if (request == null || isBlank(request.label())) throw badRequest("label is required");
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                CampaignWatchlistEntry entry = campaignWatchlistEntryRepository.findById(watchlistEntryId)
                        .filter(item -> item.getCampaign().getId().equals(campaignId))
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign watchlist entry not found"));
                entry.setLabel(request.label().trim());
                entry.setEmail(trimToNull(request.email()));
                entry.setTriggerPolicy(trimToNull(request.triggerPolicy()));
                entry.setActive(!Boolean.FALSE.equals(request.active()));
                campaignWatchlistEntryRepository.save(entry);
                campaign.touch();
                campaignRepository.save(campaign);
                recordActivity(campaign, actor, "WATCHLIST_UPDATED", "Watchlist entry updated: " + entry.getLabel() + ".");
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    /**
     * §4.7: the exception names a member finding and snapshots its owner at request time. It stays campaign-local and
     * never suppresses, closes or changes the finding.
     */
    public CampaignExceptionResponse addException(Tenant tenant, UUID campaignId, CampaignExceptionRequest request, String actor) {
        if (request == null || isBlank(request.title()) || isBlank(request.reason())) throw badRequest("title and reason are required");
        if (request.findingId() == null && isBlank(request.findingDisplayId())) throw badRequest("findingId is required");
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            Campaign campaign = loadCampaign(tenant, campaignId);
            Map<String, Object> finding = findingForException(request);
            UUID findingId = (UUID) finding.get("id");
            if (!ledger.isMember(campaignId, findingId)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "The finding is not a member of this campaign");
            }
            OwnerAtAdd owner = ledger.ownerNow(findingId);
            CampaignException exception = new CampaignException();
            exception.setCampaign(campaign);
            exception.setFindingId(findingId);
            exception.setFindingDisplayId((String) finding.get("display_id"));
            exception.setAssetName((String) finding.get("asset_name"));
            exception.setPackageName((String) finding.get("package_name"));
            exception.setOwnerTeamIdAtRequest(owner == null ? null : owner.teamId());
            exception.setOwnershipAssignmentIdAtRequest(owner == null ? null : owner.assignmentId());
            exception.setTitle(request.title().trim());
            exception.setReason(request.reason().trim());
            exception.setRequestedBy(actor);
            exception.setDecisionDueAt(request.decisionDueAt());
            exception.touch();
            CampaignException saved = campaignExceptionRepository.save(exception);
            recordActivity(campaign, actor, "EXCEPTION_ADDED", "Exception added: " + saved.getTitle() + ".");
            notifyWatchlistForEvent(campaign, actor, "CLOSURE_RISK", "Exception raised: " + saved.getTitle() + ".");
            campaign.touch();
            campaignRepository.save(campaign);
            return toException(saved);
        }));
    }

    private Map<String, Object> findingForException(CampaignExceptionRequest request) {
        String select = """
                SELECT f.id, f.display_id, a.name AS asset_name, ic.package_name FROM findings f
                  LEFT JOIN assets a ON a.id = f.asset_id LEFT JOIN inventory_components ic ON ic.id = f.component_id
                """;
        List<Map<String, Object>> rows = request.findingId() != null
                ? jdbc.queryForList(select + " WHERE f.id = ?", request.findingId())
                : jdbc.queryForList(select + " WHERE f.display_id = ?", request.findingDisplayId().trim());
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Finding not found");
        return rows.get(0);
    }

    public CampaignDetailResponse updateExceptionStatus(Tenant tenant, UUID campaignId, UUID exceptionId,
                                                        CampaignExceptionStatusUpdateRequest request, String actor) {
        if (request == null || request.status() == null) throw badRequest("status is required");
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                CampaignException exception = campaignExceptionRepository.findById(exceptionId)
                        .filter(item -> item.getCampaign().getId().equals(campaignId))
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign exception not found"));
                exception.setStatus(request.status());
                exception.setDecisionedBy(actor);
                exception.setDecisionedAt(Instant.now());
                exception.touch();
                campaignExceptionRepository.save(exception);
                recordActivity(campaign, actor, "EXCEPTION_STATUS_CHANGED", "Exception " + exception.getTitle() + " moved to " + request.status() + ".");
                notifyWatchlistForEvent(campaign, actor, "CLOSURE_RISK", "Exception " + exception.getTitle() + " moved to " + request.status() + ".");
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    // ------------------------------------------------------------------ recipients

    /** A validated recipient ready to store: TEAM rows carry the team, CUSTOM rows the encrypted address. */
    private record PreparedRecipient(CampaignRecipientType type, UUID teamId, String label, String emailCiphertext, String roleLabel,
                                     String triggerSummary, boolean paused) {
        void applyTo(CampaignNotifyGroup group) {
            group.setRecipientType(type);
            group.setTeamId(teamId);
            group.setGroupName(label);
            group.setGroupEmailEnc(emailCiphertext);
            group.setRoleLabel(roleLabel);
            group.setTriggerSummary(triggerSummary);
            group.setNotificationsPaused(paused);
        }
    }

    private PreparedRecipient prepareRecipient(Tenant tenant, CampaignNotifyGroupRequest request) {
        CampaignRecipientType type = request.recipientType() == null ? CampaignRecipientType.CUSTOM : request.recipientType();
        String roleLabel = trimToNull(request.roleLabel());
        String trigger = trimToNull(request.triggerSummary());
        boolean paused = Boolean.TRUE.equals(request.notificationsPaused());
        if (type == CampaignRecipientType.TEAM) {
            if (request.teamId() == null) throw badRequest("teamId is required for a TEAM recipient");
            if (request.groupEmail() != null && !request.groupEmail().isBlank()) {
                throw badRequest("A TEAM recipient uses the team's notification channel; groupEmail is not accepted");
            }
            requireActiveTeam(request.teamId());
            String name = teams.team(request.teamId()).map(TeamNamespaceService.Team::name).orElseThrow();
            return new PreparedRecipient(type, request.teamId(), name, null, roleLabel, trigger, paused);
        }
        if (request.teamId() != null) throw badRequest("A CUSTOM recipient does not name a team");
        if (isBlank(request.groupName())) throw badRequest("groupName is required");
        requireCustomRecipientRole();
        String email = trimToNull(request.groupEmail());
        return new PreparedRecipient(type, null, request.groupName().trim(), email == null ? null : encrypt(tenant, email), roleLabel, trigger, paused);
    }

    /** §4.6/§4.13: custom recipients need TENANT_ADMIN or SECURITY_ANALYST; the change is always recorded as activity. */
    private void requireCustomRecipientRole() {
        RequestActor actor = requestActors == null ? null : requestActors.currentActor();
        if (actor == null || CUSTOM_RECIPIENT_ROLES.stream().noneMatch(actor::hasRole)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Custom campaign recipients need the TENANT_ADMIN or SECURITY_ANALYST role");
        }
    }

    private String encrypt(Tenant tenant, String email) {
        var readiness = cipher.readiness(tenant.getId());
        if (!readiness.ready()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready (" + readiness.reason() + ")");
        }
        return cipher.encrypt(tenant.getId(), P_RECIPIENT_EMAIL, email);
    }

    private String decryptOrNull(UUID tenantId, String ciphertext) {
        if (ciphertext == null) return null;
        try {
            return cipher.decrypt(tenantId, P_RECIPIENT_EMAIL, ciphertext);
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    private record TeamChannel(String name, boolean configured) { }

    private Map<UUID, TeamChannel> teamChannels(List<CampaignNotifyGroup> groups) {
        List<UUID> ids = groups.stream().map(CampaignNotifyGroup::getTeamId).filter(Objects::nonNull).distinct().toList();
        if (ids.isEmpty()) return Map.of();
        Map<UUID, TeamChannel> channels = new HashMap<>();
        jdbc.query("SELECT id, name, notification_email_enc IS NOT NULL FROM team WHERE id = ANY (?::uuid[])",
                rs -> { channels.put(rs.getObject(1, UUID.class), new TeamChannel(rs.getString(2), rs.getBoolean(3))); }, array(ids));
        return channels;
    }

    private record Address(String label, String email, String missingDetail) { }

    private Address address(Campaign campaign, CampaignNotifyGroup group) {
        if (group.getRecipientType() == CampaignRecipientType.TEAM) {
            String name = teams.team(group.getTeamId()).map(TeamNamespaceService.Team::name).orElse(group.getGroupName());
            String email;
            try {
                email = teams.notificationEmail(group.getTeamId()).orElse(null);
            } catch (RuntimeException unavailable) {
                return new Address(name, null, "Team notification channel could not be read");
            }
            return new Address(name, email, "Team has no notification channel");
        }
        String email = decryptOrNull(campaign.getTenant().getId(), group.getGroupEmailEnc());
        return new Address(group.getGroupName(), email,
                group.getGroupEmailEnc() == null ? "No email configured for this recipient" : "Recipient address could not be decrypted");
    }

    // ------------------------------------------------------------------ notifications

    /**
     * Launch notifications (§4.6), for both scope kinds, once membership is COMPLETE. The reconciler calls this in its
     * own transaction when a materializing campaign completes.
     */
    public void deliverLaunchNotifications(Campaign campaign, String actor) {
        List<CampaignWatchlistEntry> watchlist = campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId());
        List<CampaignNotifyGroup> notifyGroups = campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId());
        List<CampaignVulnerability> vulnerabilities = campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId());
        CampaignLedger.Totals totals = ledger.totals(campaign.getId());
        String scope = vulnerabilities.isEmpty()
                ? "Findings: " + totals.members()
                : "CVEs: " + vulnerabilities.stream().map(CampaignVulnerability::getExternalId).collect(Collectors.joining(", "));
        String subject = "[Campaign launched] " + campaign.getName();
        String text = "Campaign: " + campaign.getName() + "\n"
                + "Status: " + campaign.getStatus() + "\n"
                + scope + "\n"
                + "Members: " + totals.members() + "\n"
                + "Due: " + (campaign.getDueAt() == null ? "TBD" : campaign.getDueAt()) + "\n";

        for (CampaignWatchlistEntry entry : watchlist) {
            deliverAttempt(campaign, entry.getLabel(), entry.getEmail(), "WATCHLIST", subject, text, "launch", "No email configured for watchlist entry");
        }
        for (CampaignNotifyGroup group : notifyGroups) {
            Address address = address(campaign, group);
            if (group.isNotificationsPaused()) {
                CampaignDeliveryAttempt attempt = new CampaignDeliveryAttempt();
                attempt.setCampaign(campaign);
                attempt.setTargetType(targetType(group));
                attempt.setTargetLabel(address.label());
                attempt.setSubject(subject);
                attempt.setDeliveryState("SKIPPED");
                attempt.setDetail("Notifications are paused for this group");
                campaignDeliveryAttemptRepository.save(attempt);
                continue;
            }
            deliverAttempt(campaign, address.label(), address.email(), targetType(group), subject, text, "launch", address.missingDetail());
        }
        recordActivity(campaign, actor, "NOTIFIED",
                "Launch notifications recorded for " + (watchlist.size() + notifyGroups.size()) + " watchlist/group target(s).");
    }

    private static String targetType(CampaignNotifyGroup group) {
        return group.getRecipientType() == CampaignRecipientType.TEAM ? "TEAM" : "GROUP";
    }

    private void notifyWatchlistForEvent(Campaign campaign, String actor, String triggerPolicy, String message) {
        List<CampaignWatchlistEntry> watchlist = campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId());
        List<CampaignNotifyGroup> groups = campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId());
        String subject = "[Campaign update] " + campaign.getName();
        String text = "Campaign: " + campaign.getName() + "\n"
                + "Actor: " + actor + "\n"
                + "Update: " + message + "\n";
        for (CampaignWatchlistEntry entry : watchlist) {
            if (!entry.isActive()) continue;
            String policy = isBlank(entry.getTriggerPolicy()) ? "ALL_EVENTS" : entry.getTriggerPolicy().trim();
            if (!"ALL_EVENTS".equalsIgnoreCase(policy) && !policy.equalsIgnoreCase(triggerPolicy)) continue;
            deliverAttempt(campaign, entry.getLabel(), entry.getEmail(), "WATCHLIST", subject, text, triggerPolicy.toLowerCase(Locale.ROOT),
                    "No email configured for watchlist entry");
        }
        for (CampaignNotifyGroup group : groups) {
            if (group.isNotificationsPaused()) continue;
            Address address = address(campaign, group);
            deliverAttempt(campaign, address.label(), address.email(), targetType(group), subject, text, triggerPolicy.toLowerCase(Locale.ROOT),
                    address.missingDetail());
        }
    }

    private void deliverAttempt(Campaign campaign, String label, String email, String targetType, String subject, String text,
                                String idempotencySuffix, String missingDetail) {
        CampaignDeliveryAttempt attempt = new CampaignDeliveryAttempt();
        attempt.setCampaign(campaign);
        attempt.setTargetType(targetType);
        attempt.setTargetLabel(label);
        attempt.setTargetAddress(email);
        attempt.setSubject(subject);
        if (isBlank(email)) {
            attempt.setDeliveryState("SKIPPED");
            attempt.setDetail(missingDetail);
        } else {
            attempt.setDeliveryState("QUEUED");
            campaignDeliveryAttemptRepository.saveAndFlush(attempt);
            emailOutbox.enqueue(campaign.getTenant().getId(), attempt.getId(), new ResendEmailClient.EmailMessage(
                    email, subject, "<p>" + escapeHtml(text).replace("\n", "<br/>") + "</p>", text,
                    Map.of("feature", "campaign", "campaignId", campaign.getId().toString()), attempt.getId().toString()));
        }
        campaignDeliveryAttemptRepository.save(attempt);
    }

    void recordActivity(Campaign campaign, String actor, String type, String body) {
        CampaignActivity activity = new CampaignActivity();
        activity.setCampaign(campaign);
        activity.setActor(actor);
        activity.setActivityType(type);
        activity.setBody(body);
        campaignActivityRepository.save(activity);
    }

    // ------------------------------------------------------------------ read models

    private CampaignDetailResponse getDetailInCurrentTenantSchema(Tenant tenant, UUID campaignId) {
        return executeRead(() -> {
            Campaign campaign = loadCampaign(tenant, campaignId);
            List<CampaignNotifyGroup> groups = campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaignId);
            Map<UUID, TeamChannel> channels = teamChannels(groups);
            List<MemberRow> recent = ledger.recent(campaignId, 150);
            Map<UUID, Summary> current = currentOwnership(recent.stream().map(MemberRow::findingId).toList());
            return new CampaignDetailResponse(
                    toSummary(campaign),
                    campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaignId).stream()
                            .map(item -> new CampaignVulnerabilityResponse(item.getExternalId(), item.getTitle(), item.getSeverity()))
                            .toList(),
                    groups.stream().map(group -> toNotifyGroup(tenant, group, group.getTeamId() == null ? null : channels.get(group.getTeamId()))).toList(),
                    campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaignId).stream()
                            .map(item -> new CampaignWatchlistEntryResponse(item.getId(), item.getEntryType(), item.getLabel(), item.getEmail(),
                                    item.getTriggerPolicy(), item.isActive()))
                            .toList(),
                    campaignNoteRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignNoteResponse(item.getId(), item.getAuthor(), item.getBody(), item.getCreatedAt()))
                            .toList(),
                    campaignExceptionRepository.findAllByCampaign_IdOrderByRequestedAtDesc(campaignId).stream().map(CampaignService::toException).toList(),
                    campaignActivityRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignActivityResponse(item.getId(), item.getActivityType(), item.getActor(), item.getBody(), item.getCreatedAt()))
                            .toList(),
                    campaignDeliveryAttemptRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignDeliveryAttemptResponse(item.getId(), item.getTargetType(), item.getTargetLabel(),
                                    item.getTargetAddress(), item.getSubject(), item.getDeliveryState(), item.getDetail(), item.getCreatedAt()))
                            .toList(),
                    recent.stream().limit(100).map(row -> new CampaignFindingRowResponse(row.findingId().toString(), row.displayId(), row.cveId(),
                            row.assetName(), row.assetIdentifier(), row.packageName(), row.severity(), row.status(), row.outcome(), row.dueAt(),
                            row.incidentId(), row.ownerAtAdd(), current.get(row.findingId()))).toList(),
                    ledger.assets(campaignId, 500).stream().map(row -> new CampaignAssetRowResponse(row.assetId().toString(), row.name(),
                            row.identifier(), row.environment(), row.active(), row.remediated(), row.members())).toList(),
                    recent.stream().map(row -> new CampaignEvidenceRowResponse(row.cveId(), row.displayId(), row.assetName(),
                            row.assetIdentifier(), row.packageName(), row.severity(), row.status(), row.outcome(), row.incidentId(), row.dueAt(),
                            current.get(row.findingId()))).toList()
            );
        });
    }

    private CampaignNotifyGroupResponse toNotifyGroup(Tenant tenant, CampaignNotifyGroup group, TeamChannel channel) {
        if (group.getRecipientType() == CampaignRecipientType.TEAM) {
            return new CampaignNotifyGroupResponse(group.getId(), group.getRecipientType(), group.getTeamId(),
                    channel == null ? group.getGroupName() : channel.name(), null, channel != null && channel.configured(), true,
                    group.getRoleLabel(), group.getTriggerSummary(), group.isNotificationsPaused());
        }
        return new CampaignNotifyGroupResponse(group.getId(), group.getRecipientType(), null, group.getGroupName(),
                decryptOrNull(tenant.getId(), group.getGroupEmailEnc()), group.getGroupEmailEnc() != null, false,
                group.getRoleLabel(), group.getTriggerSummary(), group.isNotificationsPaused());
    }

    private static CampaignExceptionResponse toException(CampaignException item) {
        return new CampaignExceptionResponse(item.getId(), item.getFindingId(), item.getFindingId() != null, item.getFindingDisplayId(),
                item.getAssetName(), item.getPackageName(), item.getOwnerTeamIdAtRequest(), item.getTitle(), item.getReason(), item.getStatus(),
                item.getRequestedBy(), item.getRequestedAt(), item.getDecisionDueAt(), item.getDecisionedBy(), item.getDecisionedAt());
    }

    private CampaignSummaryResponse toSummary(Campaign campaign) {
        CampaignLedger.Totals totals = ledger.totals(campaign.getId());
        long remediated = totals.count(Outcome.REMEDIATED);
        long active = totals.count(Outcome.OPEN) + totals.count(Outcome.REOPENED);
        int completion = totals.members() == 0 ? 0 : Math.round((remediated * 100f) / totals.members());
        long pendingExceptions = campaignExceptionRepository.findAllByCampaign_IdOrderByRequestedAtDesc(campaign.getId()).stream()
                .filter(item -> item.getStatus() == CampaignExceptionStatus.PENDING_DECISION)
                .count();
        CampaignMembershipState state = jdbc.queryForObject("SELECT membership_state FROM campaigns WHERE id = ?",
                (rs, n) -> CampaignMembershipState.valueOf(rs.getString(1)), campaign.getId());
        return new CampaignSummaryResponse(
                campaign.getId(),
                campaign.getName(),
                campaign.getSummary(),
                campaign.getStatus(),
                campaign.getScopeKind(),
                state,
                campaign.getAssigneePrincipalId(),
                campaign.getCoordinatingTeamId(),
                campaign.getDueAt(),
                campaign.getStartedAt(),
                campaign.getUpdatedAt(),
                campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId()).stream()
                        .map(CampaignVulnerability::getExternalId).toList(),
                (int) totals.members(),
                (int) remediated,
                (int) active,
                CampaignLedger.outcomeMap(totals.outcomes()),
                (int) totals.assets(),
                (int) (pendingExceptions + totals.overdueActive()),
                campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId()).size(),
                campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId()).size(),
                completion
        );
    }

    private Campaign loadCampaign(Tenant tenant, UUID campaignId) {
        return campaignRepository.findByIdAndTenant_Id(campaignId, tenant.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign not found"));
    }

    // ------------------------------------------------------------------ helpers

    private static JsonNode readJson(String value) {
        if (value == null) return null;
        try {
            return JSON.readTree(value);
        } catch (Exception invalid) {
            return null;
        }
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static String trimToNull(String value) {
        return isBlank(value) ? null : value.trim();
    }

    private static <T> List<T> nullSafe(List<T> list) {
        return list == null ? List.of() : list;
    }

    private static String array(List<UUID> ids) {
        return "{" + ids.stream().map(UUID::toString).collect(Collectors.joining(",")) + "}";
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private <T> T executeRead(java.util.function.Supplier<T> work) {
        return readTransactionTemplate.execute(status -> work.get());
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
