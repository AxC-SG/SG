package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Campaign;
import com.prototype.vulnwatch.domain.CampaignActivity;
import com.prototype.vulnwatch.domain.CampaignDeliveryAttempt;
import com.prototype.vulnwatch.domain.CampaignException;
import com.prototype.vulnwatch.domain.CampaignExceptionStatus;
import com.prototype.vulnwatch.domain.CampaignNote;
import com.prototype.vulnwatch.domain.CampaignNotifyGroup;
import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.CampaignVulnerability;
import com.prototype.vulnwatch.domain.CampaignWatchlistEntry;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignActivityResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAssetRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFindingResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDeliveryAttemptResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignEvidenceRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFindingRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignSummaryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignVulnerabilityResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryUpdateRequest;
import com.prototype.vulnwatch.repo.CampaignActivityRepository;
import com.prototype.vulnwatch.repo.CampaignDeliveryAttemptRepository;
import com.prototype.vulnwatch.repo.CampaignExceptionRepository;
import com.prototype.vulnwatch.repo.CampaignNoteRepository;
import com.prototype.vulnwatch.repo.CampaignNotifyGroupRepository;
import com.prototype.vulnwatch.repo.CampaignRepository;
import com.prototype.vulnwatch.repo.CampaignVulnerabilityRepository;
import com.prototype.vulnwatch.repo.CampaignWatchlistEntryRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CampaignService {

    private final CampaignRepository campaignRepository;
    private final CampaignVulnerabilityRepository campaignVulnerabilityRepository;
    private final CampaignNotifyGroupRepository campaignNotifyGroupRepository;
    private final CampaignWatchlistEntryRepository campaignWatchlistEntryRepository;
    private final CampaignNoteRepository campaignNoteRepository;
    private final CampaignActivityRepository campaignActivityRepository;
    private final CampaignDeliveryAttemptRepository campaignDeliveryAttemptRepository;
    private final CampaignExceptionRepository campaignExceptionRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final FindingRepository findingRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final ResendEmailClient resendEmailClient;
    private TransactionTemplate readTransactionTemplate;
    private TransactionTemplate writeTransactionTemplate;

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
            FindingRepository findingRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            ResendEmailClient resendEmailClient
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
        this.findingRepository = findingRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.resendEmailClient = resendEmailClient;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.readTransactionTemplate = null;
            this.writeTransactionTemplate = null;
            return;
        }
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public List<CampaignSummaryResponse> list(Tenant tenant, CampaignStatus status) {
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> {
            List<Campaign> campaigns = status == null
                    ? campaignRepository.findAllByTenant_IdOrderByUpdatedAtDesc(tenant.getId())
                    : campaignRepository.findAllByTenant_IdAndStatusOrderByUpdatedAtDesc(tenant.getId(), status);
            return campaigns.stream()
                    .map(campaign -> toSummary(tenant, campaign))
                    .toList();
        }));
    }

    public CampaignDetailResponse create(Tenant tenant, CampaignCreateRequest request, String actor) {
        validateCreateRequest(request);
        return tenantSchemaExecutionService.run(tenant, () -> {
            UUID campaignId = executeWrite(() -> createInCurrentTenantSchema(tenant, request, actor));
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public CampaignDetailResponse getDetail(Tenant tenant, UUID campaignId) {
        return tenantSchemaExecutionService.run(tenant, () -> getDetailInCurrentTenantSchema(tenant, campaignId));
    }

    public CampaignDetailResponse updateStatus(Tenant tenant, UUID campaignId, CampaignStatusUpdateRequest request, String actor) {
        if (request == null || request.status() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "status is required");
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                campaign.setStatus(request.status());
                if (request.status() == CampaignStatus.ACTIVE && campaign.getStartedAt() == null) {
                    campaign.setStartedAt(Instant.now());
                }
                if (request.status() == CampaignStatus.PAUSED) {
                    campaign.setPausedAt(Instant.now());
                }
                if (request.status() == CampaignStatus.CLOSED || request.status() == CampaignStatus.CANCELLED) {
                    campaign.setClosedAt(Instant.now());
                }
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
        if (request == null || isBlank(request.body())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "body is required");
        }
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

    public CampaignDetailResponse updateNotifyGroup(
            Tenant tenant,
            UUID campaignId,
            UUID notifyGroupId,
            CampaignNotifyGroupRequest request,
            String actor
    ) {
        if (request == null || isBlank(request.groupName())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "groupName is required");
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            executeWrite(() -> {
                Campaign campaign = loadCampaign(tenant, campaignId);
                CampaignNotifyGroup group = campaignNotifyGroupRepository.findById(notifyGroupId)
                        .filter(item -> item.getCampaign().getId().equals(campaignId))
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign notify group not found"));
                group.setGroupName(request.groupName().trim());
                group.setGroupEmail(trimToNull(request.groupEmail()));
                group.setRoleLabel(trimToNull(request.roleLabel()));
                group.setTriggerSummary(trimToNull(request.triggerSummary()));
                group.setNotificationsPaused(Boolean.TRUE.equals(request.notificationsPaused()));
                campaignNotifyGroupRepository.save(group);
                campaign.touch();
                campaignRepository.save(campaign);
                recordActivity(campaign, actor, "GROUP_UPDATED", "Notify group updated: " + group.getGroupName() + ".");
                return null;
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public CampaignDetailResponse updateWatchlistEntry(
            Tenant tenant,
            UUID campaignId,
            UUID watchlistEntryId,
            CampaignWatchlistEntryUpdateRequest request,
            String actor
    ) {
        if (request == null || isBlank(request.label())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "label is required");
        }
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

    public CampaignExceptionResponse addException(Tenant tenant, UUID campaignId, CampaignExceptionRequest request, String actor) {
        if (request == null || isBlank(request.title()) || isBlank(request.reason())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "title and reason are required");
        }
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            Campaign campaign = loadCampaign(tenant, campaignId);
            CampaignException exception = new CampaignException();
            exception.setCampaign(campaign);
            exception.setFindingDisplayId(trimToNull(request.findingDisplayId()));
            exception.setAssetName(trimToNull(request.assetName()));
            exception.setPackageName(trimToNull(request.packageName()));
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
            return new CampaignExceptionResponse(
                    saved.getId(),
                    saved.getFindingDisplayId(),
                    saved.getAssetName(),
                    saved.getPackageName(),
                    saved.getTitle(),
                    saved.getReason(),
                    saved.getStatus(),
                    saved.getRequestedBy(),
                    saved.getRequestedAt(),
                    saved.getDecisionDueAt(),
                    saved.getDecisionedBy(),
                    saved.getDecisionedAt()
            );
        }));
    }

    public CampaignDetailResponse updateExceptionStatus(Tenant tenant, UUID campaignId, UUID exceptionId, CampaignExceptionStatusUpdateRequest request, String actor) {
        if (request == null || request.status() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "status is required");
        }
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

    private org.springframework.jdbc.core.JdbcTemplate jdbc;

    @org.springframework.beans.factory.annotation.Autowired
    public void setJdbcTemplate(org.springframework.jdbc.core.JdbcTemplate value) { this.jdbc = value; }

    public static final int MAX_CAMPAIGN_FINDINGS = 500;

    /** Creates a campaign over existing canonical findings in this tenant; unknown IDs are rejected. */
    public CampaignDetailResponse createFromFindings(Tenant tenant, CampaignFromFindingsRequest request, String actor) {
        if (request == null || isBlank(request.name())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required");
        }
        List<UUID> ids = nullSafe(request.findingIds()).stream().filter(java.util.Objects::nonNull).distinct().toList();
        if (ids.isEmpty()) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one finding is required");
        if (ids.size() > MAX_CAMPAIGN_FINDINGS) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A campaign can start with at most " + MAX_CAMPAIGN_FINDINGS + " findings");
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            UUID campaignId = executeWrite(() -> {
                Campaign campaign = new Campaign();
                campaign.setTenant(tenant);
                campaign.setName(request.name().trim());
                campaign.setSummary(trimToNull(request.summary()));
                campaign.setStatus(CampaignStatus.ACTIVE);
                campaign.setCreatedBy(actor);
                campaign.setDueAt(request.dueAt());
                campaign.setStartedAt(Instant.now());
                campaign.touch();
                // Flushed so the JDBC link rows below can reference the new campaign.
                Campaign saved = campaignRepository.saveAndFlush(campaign);
                int linked = 0;
                for (UUID findingId : ids) {
                    linked += jdbc.update("""
                            INSERT INTO campaign_findings (campaign_id, finding_id, added_by)
                            SELECT ?, f.id, ? FROM findings f WHERE f.id = ?
                            ON CONFLICT DO NOTHING
                            """, saved.getId(), actor, findingId);
                }
                if (linked != ids.size()) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, (ids.size() - linked) + " finding(s) were not found in this workspace");
                }
                if (!isBlank(request.launchNote())) {
                    CampaignNote note = new CampaignNote();
                    note.setCampaign(saved);
                    note.setAuthor(actor);
                    note.setBody(request.launchNote().trim());
                    campaignNoteRepository.save(note);
                }
                recordActivity(saved, actor, "CREATED",
                        "Campaign created from " + linked + " finding" + (linked == 1 ? "" : "s") + ".");
                return saved.getId();
            });
            return getDetailInCurrentTenantSchema(tenant, campaignId);
        });
    }

    public List<CampaignFindingResponse> findings(Tenant tenant, UUID campaignId) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            getDetailInCurrentTenantSchema(tenant, campaignId);
            return jdbc.query("""
                    SELECT f.id, f.display_id, f.title, f.finding_kind, f.severity_override, f.status, f.assigned_to,
                           f.owner_group, f.due_at, f.verification_status, cf.added_at
                      FROM campaign_findings cf JOIN findings f ON f.id = cf.finding_id
                     WHERE cf.campaign_id = ?
                     ORDER BY CASE upper(coalesce(f.severity_override, '')) WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                              WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.due_at NULLS LAST, f.display_id
                    """, (rs, row) -> new CampaignFindingResponse(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                    rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                    rs.getTimestamp(9) == null ? null : rs.getTimestamp(9).toInstant(), rs.getString(10),
                    rs.getTimestamp(11).toInstant()), campaignId);
        });
    }

    private UUID createInCurrentTenantSchema(Tenant tenant, CampaignCreateRequest request, String actor) {
        Campaign campaign = new Campaign();
        campaign.setTenant(tenant);
        campaign.setName(request.name().trim());
        campaign.setSummary(trimToNull(request.summary()));
        campaign.setStatus(CampaignStatus.ACTIVE);
        campaign.setCreatedBy(actor);
        campaign.setDueAt(request.dueAt());
        campaign.setStartedAt(Instant.now());
        campaign.touch();
        Campaign saved = campaignRepository.save(campaign);

        List<Vulnerability> vulnerabilities = vulnerabilityRepository.findByExternalIdIn(request.cveIds().stream()
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toList());
        Map<String, Vulnerability> vulnerabilitiesByExternalId = vulnerabilities.stream()
                .collect(Collectors.toMap(Vulnerability::getExternalId, value -> value));
        for (String cveId : request.cveIds()) {
            Vulnerability vulnerability = vulnerabilitiesByExternalId.get(cveId.trim());
            if (vulnerability == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown CVE: " + cveId);
            }
            CampaignVulnerability link = new CampaignVulnerability();
            link.setCampaign(saved);
            link.setVulnerability(vulnerability);
            link.setExternalId(vulnerability.getExternalId());
            link.setTitle(vulnerability.getTitle());
            link.setSeverity(vulnerability.getSeverity());
            campaignVulnerabilityRepository.save(link);
        }

        for (CampaignNotifyGroupRequest groupRequest : nullSafe(request.notifyGroups())) {
            if (groupRequest == null || isBlank(groupRequest.groupName())) {
                continue;
            }
            CampaignNotifyGroup group = new CampaignNotifyGroup();
            group.setCampaign(saved);
            group.setGroupName(groupRequest.groupName().trim());
            group.setGroupEmail(trimToNull(groupRequest.groupEmail()));
            group.setRoleLabel(trimToNull(groupRequest.roleLabel()));
            group.setTriggerSummary(trimToNull(groupRequest.triggerSummary()));
            group.setNotificationsPaused(Boolean.TRUE.equals(groupRequest.notificationsPaused()));
            campaignNotifyGroupRepository.save(group);
        }

        for (CampaignWatchlistEntryRequest watchRequest : nullSafe(request.watchlist())) {
            if (watchRequest == null || isBlank(watchRequest.label())) {
                continue;
            }
            CampaignWatchlistEntry entry = new CampaignWatchlistEntry();
            entry.setCampaign(saved);
            entry.setEntryType(watchRequest.entryType());
            entry.setLabel(watchRequest.label().trim());
            entry.setEmail(trimToNull(watchRequest.email()));
            entry.setTriggerPolicy(trimToNull(watchRequest.triggerPolicy()));
            entry.setActive(!Boolean.FALSE.equals(watchRequest.active()));
            campaignWatchlistEntryRepository.save(entry);
        }

        if (!isBlank(request.launchNote())) {
            CampaignNote note = new CampaignNote();
            note.setCampaign(saved);
            note.setAuthor(actor);
            note.setBody(request.launchNote().trim());
            campaignNoteRepository.save(note);
        }

        recordActivity(saved, actor, "CREATED",
                "Campaign created from " + request.cveIds().size() + " CVE" + (request.cveIds().size() == 1 ? "" : "s") + ".");
        deliverLaunchNotifications(saved, actor);
        return saved.getId();
    }

    private CampaignDetailResponse getDetailInCurrentTenantSchema(Tenant tenant, UUID campaignId) {
        return executeRead(() -> {
            Campaign campaign = loadCampaign(tenant, campaignId);
            CampaignSummaryResponse summary = toSummary(tenant, campaign);
            return new CampaignDetailResponse(
                    summary,
                    campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaignId).stream()
                            .map(item -> new CampaignVulnerabilityResponse(item.getExternalId(), item.getTitle(), item.getSeverity()))
                            .toList(),
                    campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaignId).stream()
                            .map(item -> new CampaignNotifyGroupResponse(item.getId(), item.getGroupName(), item.getGroupEmail(), item.getRoleLabel(), item.getTriggerSummary(), item.isNotificationsPaused()))
                            .toList(),
                    campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaignId).stream()
                            .map(item -> new CampaignWatchlistEntryResponse(item.getId(), item.getEntryType(), item.getLabel(), item.getEmail(), item.getTriggerPolicy(), item.isActive()))
                            .toList(),
                    campaignNoteRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignNoteResponse(item.getId(), item.getAuthor(), item.getBody(), item.getCreatedAt()))
                            .toList(),
                    campaignExceptionRepository.findAllByCampaign_IdOrderByRequestedAtDesc(campaignId).stream()
                            .map(item -> new CampaignExceptionResponse(
                                    item.getId(),
                                    item.getFindingDisplayId(),
                                    item.getAssetName(),
                                    item.getPackageName(),
                                    item.getTitle(),
                                    item.getReason(),
                                    item.getStatus(),
                                    item.getRequestedBy(),
                                    item.getRequestedAt(),
                                    item.getDecisionDueAt(),
                                    item.getDecisionedBy(),
                                    item.getDecisionedAt()
                            ))
                            .toList(),
                    campaignActivityRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignActivityResponse(item.getId(), item.getActivityType(), item.getActor(), item.getBody(), item.getCreatedAt()))
                            .toList(),
                    campaignDeliveryAttemptRepository.findAllByCampaign_IdOrderByCreatedAtDesc(campaignId).stream()
                            .map(item -> new CampaignDeliveryAttemptResponse(item.getId(), item.getTargetType(), item.getTargetLabel(), item.getTargetAddress(), item.getSubject(), item.getDeliveryState(), item.getDetail(), item.getCreatedAt()))
                            .toList(),
                    toFindingRows(tenant, campaign),
                    toAssetRows(tenant, campaign),
                    toEvidenceRows(tenant, campaign)
            );
        });
    }

    private Campaign loadCampaign(Tenant tenant, UUID campaignId) {
        return campaignRepository.findByIdAndTenant_Id(campaignId, tenant.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Campaign not found"));
    }

    private void validateCreateRequest(CampaignCreateRequest request) {
        if (request == null || isBlank(request.name())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required");
        }
        if (request.cveIds() == null || request.cveIds().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one CVE is required");
        }
    }

    private void deliverLaunchNotifications(Campaign campaign, String actor) {
        List<CampaignWatchlistEntry> watchlist = campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId());
        List<CampaignNotifyGroup> notifyGroups = campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId());
        List<CampaignVulnerability> vulnerabilities = campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId());
        String cveSummary = vulnerabilities.stream().map(CampaignVulnerability::getExternalId).collect(Collectors.joining(", "));
        String subject = "[Campaign launched] " + campaign.getName();
        String text = "Campaign: " + campaign.getName() + "\n"
                + "Status: " + campaign.getStatus() + "\n"
                + "CVEs: " + cveSummary + "\n"
                + "Due: " + (campaign.getDueAt() == null ? "TBD" : campaign.getDueAt()) + "\n";

        for (CampaignWatchlistEntry entry : watchlist) {
            deliverAttempt(campaign, entry.getLabel(), entry.getEmail(), "WATCHLIST", subject, text, entry.getId().toString(), "launch");
        }

        for (CampaignNotifyGroup group : notifyGroups) {
            if (group.isNotificationsPaused()) {
                CampaignDeliveryAttempt attempt = new CampaignDeliveryAttempt();
                attempt.setCampaign(campaign);
                attempt.setTargetType("GROUP");
                attempt.setTargetLabel(group.getGroupName());
                attempt.setSubject(subject);
                attempt.setDeliveryState("SKIPPED");
                attempt.setDetail("Notifications are paused for this group");
                campaignDeliveryAttemptRepository.save(attempt);
                continue;
            }
            deliverAttempt(campaign, group.getGroupName(), group.getGroupEmail(), "GROUP", subject, text, group.getId().toString(), "launch");
        }

        recordActivity(campaign, actor, "NOTIFIED",
                "Launch notifications recorded for " + (watchlist.size() + notifyGroups.size()) + " watchlist/group target(s).");
    }

    private void notifyWatchlistForEvent(Campaign campaign, String actor, String triggerPolicy, String message) {
        List<CampaignWatchlistEntry> watchlist = campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId());
        List<CampaignNotifyGroup> groups = campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId());
        String subject = "[Campaign update] " + campaign.getName();
        String text = "Campaign: " + campaign.getName() + "\n"
                + "Actor: " + actor + "\n"
                + "Update: " + message + "\n";
        for (CampaignWatchlistEntry entry : watchlist) {
            if (!entry.isActive()) {
                continue;
            }
            String policy = entry.getTriggerPolicy() == null || entry.getTriggerPolicy().isBlank()
                    ? "ALL_EVENTS"
                    : entry.getTriggerPolicy().trim();
            if (!"ALL_EVENTS".equalsIgnoreCase(policy) && !policy.equalsIgnoreCase(triggerPolicy)) {
                continue;
            }
            deliverAttempt(campaign, entry.getLabel(), entry.getEmail(), "WATCHLIST", subject, text, entry.getId().toString(), triggerPolicy.toLowerCase());
        }
        for (CampaignNotifyGroup group : groups) {
            if (group.isNotificationsPaused()) {
                continue;
            }
            deliverAttempt(campaign, group.getGroupName(), group.getGroupEmail(), "GROUP", subject, text, group.getId().toString(), triggerPolicy.toLowerCase());
        }
    }

    private CampaignEmailOutboxService emailOutbox;
    @org.springframework.beans.factory.annotation.Autowired
    void configureEmailOutbox(CampaignEmailOutboxService outbox) { emailOutbox=outbox; }

    private void deliverAttempt(
            Campaign campaign,
            String label,
            String email,
            String targetType,
            String subject,
            String text,
            String targetId,
            String idempotencySuffix
    ) {
        CampaignDeliveryAttempt attempt = new CampaignDeliveryAttempt();
        attempt.setCampaign(campaign);
        attempt.setTargetType(targetType);
        attempt.setTargetLabel(label);
        attempt.setTargetAddress(email);
        attempt.setSubject(subject);
        if (email == null || email.isBlank()) {
            attempt.setDeliveryState("SKIPPED");
            attempt.setDetail("No email configured for watchlist entry");
        } else {
            attempt.setDeliveryState("QUEUED");
            campaignDeliveryAttemptRepository.saveAndFlush(attempt);
            emailOutbox.enqueue(campaign.getTenant().getId(),attempt.getId(),new ResendEmailClient.EmailMessage(
                    email,subject,"<p>"+escapeHtml(text).replace("\n","<br/>")+"</p>",text,
                    Map.of("feature","campaign","campaignId",campaign.getId().toString()),attempt.getId().toString()));
        }
        campaignDeliveryAttemptRepository.save(attempt);
    }

    private void recordActivity(Campaign campaign, String actor, String type, String body) {
        CampaignActivity activity = new CampaignActivity();
        activity.setCampaign(campaign);
        activity.setActor(actor);
        activity.setActivityType(type);
        activity.setBody(body);
        campaignActivityRepository.save(activity);
    }

    private CampaignSummaryResponse toSummary(Tenant tenant, Campaign campaign) {
        List<CampaignVulnerability> vulnerabilities = campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId());
        List<Finding> findings = loadFindingsForCampaign(tenant, vulnerabilities);
        Set<UUID> assetIds = findings.stream()
                .map(Finding::getAsset)
                .filter(Objects::nonNull)
                .map(Asset::getId)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        int totalFindings = findings.size();
        int resolvedFindings = (int) findings.stream().filter(this::isResolvedFinding).count();
        int openFindings = totalFindings - resolvedFindings;
        int completionPercent = totalFindings == 0 ? 0 : Math.round((resolvedFindings * 100f) / totalFindings);
        long explicitExceptionCount = campaignExceptionRepository.findAllByCampaign_IdOrderByRequestedAtDesc(campaign.getId()).stream()
                .filter(item -> item.getStatus() == CampaignExceptionStatus.PENDING_DECISION)
                .count();
        long overdueFindingCount = findings.stream()
                .filter(finding -> !isResolvedFinding(finding) && finding.getDueAt() != null && finding.getDueAt().isBefore(Instant.now()))
                .count();
        return new CampaignSummaryResponse(
                campaign.getId(),
                campaign.getName(),
                campaign.getSummary(),
                campaign.getStatus(),
                campaign.getDueAt(),
                campaign.getStartedAt(),
                campaign.getUpdatedAt(),
                vulnerabilities.stream().map(CampaignVulnerability::getExternalId).toList(),
                totalFindings,
                resolvedFindings,
                openFindings,
                assetIds.size(),
                (int) (explicitExceptionCount + overdueFindingCount),
                campaignNotifyGroupRepository.findAllByCampaign_IdOrderByGroupNameAsc(campaign.getId()).size(),
                campaignWatchlistEntryRepository.findAllByCampaign_IdOrderByCreatedAtAsc(campaign.getId()).size(),
                completionPercent
        );
    }

    private List<CampaignFindingRowResponse> toFindingRows(Tenant tenant, Campaign campaign) {
        return loadFindingsForCampaign(tenant, campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId())).stream()
                .sorted(Comparator.comparing(Finding::getUpdatedAt).reversed())
                .limit(100)
                .map(finding -> new CampaignFindingRowResponse(
                        finding.getId().toString(),
                        finding.getDisplayId(),
                        finding.getVulnerability() == null ? null : finding.getVulnerability().getExternalId(),
                        finding.getAsset() == null ? null : finding.getAsset().getName(),
                        finding.getAsset() == null ? null : finding.getAsset().getIdentifier(),
                        finding.getComponent() == null ? null : finding.getComponent().getPackageName(),
                        finding.getVulnerability() == null ? null : finding.getVulnerability().getSeverity(),
                        finding.getOwnerGroup(),
                        finding.getStatus().name(),
                        finding.getDueAt(),
                        finding.getIncidentId()
                ))
                .toList();
    }

    private List<CampaignAssetRowResponse> toAssetRows(Tenant tenant, Campaign campaign) {
        Map<UUID, AssetAccumulator> byAsset = new LinkedHashMap<>();
        for (Finding finding : loadFindingsForCampaign(tenant, campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId()))) {
            Asset asset = finding.getAsset();
            if (asset == null) {
                continue;
            }
            AssetAccumulator accumulator = byAsset.computeIfAbsent(asset.getId(), key -> new AssetAccumulator(asset));
            if (isResolvedFinding(finding)) {
                accumulator.resolvedFindings++;
            } else {
                accumulator.openFindings++;
            }
        }
        return byAsset.values().stream()
                .map(accumulator -> new CampaignAssetRowResponse(
                        accumulator.asset.getId().toString(),
                        accumulator.asset.getName(),
                        accumulator.asset.getIdentifier(),
                        accumulator.asset.getEnvironment(),
                        accumulator.asset.getSupportGroup(),
                        accumulator.openFindings,
                        accumulator.resolvedFindings
                ))
                .toList();
    }

    private List<CampaignEvidenceRowResponse> toEvidenceRows(Tenant tenant, Campaign campaign) {
        return loadFindingsForCampaign(tenant, campaignVulnerabilityRepository.findAllByCampaign_IdOrderByExternalIdAsc(campaign.getId())).stream()
                .sorted(Comparator.comparing(Finding::getUpdatedAt).reversed())
                .limit(150)
                .map(finding -> new CampaignEvidenceRowResponse(
                        finding.getVulnerability() == null ? null : finding.getVulnerability().getExternalId(),
                        finding.getDisplayId(),
                        finding.getAsset() == null ? null : finding.getAsset().getName(),
                        finding.getAsset() == null ? null : finding.getAsset().getIdentifier(),
                        finding.getComponent() == null ? null : finding.getComponent().getPackageName(),
                        finding.getVulnerability() == null ? null : finding.getVulnerability().getSeverity(),
                        finding.getOwnerGroup(),
                        finding.getStatus().name(),
                        finding.getIncidentId(),
                        finding.getDueAt()
                ))
                .toList();
    }

    private List<Finding> loadFindingsForCampaign(Tenant tenant, Collection<CampaignVulnerability> vulnerabilities) {
        List<UUID> vulnerabilityIds = vulnerabilities.stream()
                .map(CampaignVulnerability::getVulnerability)
                .filter(Objects::nonNull)
                .map(Vulnerability::getId)
                .toList();
        if (vulnerabilityIds.isEmpty()) {
            return List.of();
        }
        return findingRepository.findByTenant_IdAndVulnerability_IdIn(tenant.getId(), vulnerabilityIds);
    }

    private boolean isResolvedFinding(Finding finding) {
        return finding.getStatus() == FindingStatus.RESOLVED
                || finding.getStatus() == FindingStatus.SUPPRESSED
                || finding.getStatus() == FindingStatus.AUTO_CLOSED;
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

    private static String escapeHtml(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private <T> T executeRead(java.util.function.Supplier<T> work) {
        if (readTransactionTemplate == null) {
            return work.get();
        }
        T result = readTransactionTemplate.execute(status -> work.get());
        return result == null ? work.get() : result;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }

    private static final class AssetAccumulator {
        private final Asset asset;
        private long openFindings;
        private long resolvedFindings;

        private AssetAccumulator(Asset asset) {
            this.asset = asset;
        }
    }
}
