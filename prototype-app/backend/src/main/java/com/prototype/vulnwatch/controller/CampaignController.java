package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignAddMembersRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignMemberPage;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignOwnerBucket;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignPreviewResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignReconciliationResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignSummaryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryUpdateRequest;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.CampaignAiService;
import com.prototype.vulnwatch.service.CampaignAiService.CampaignAiResponse;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/campaigns")
public class CampaignController {

    private final WorkspaceService workspaceService;
    private final RequestActorService requestActorService;
    private final CampaignService campaignService;
    private final CampaignAiService campaignAiService;

    public CampaignController(
            WorkspaceService workspaceService,
            RequestActorService requestActorService,
            CampaignService campaignService,
            CampaignAiService campaignAiService
    ) {
        this.workspaceService = workspaceService;
        this.requestActorService = requestActorService;
        this.campaignService = campaignService;
        this.campaignAiService = campaignAiService;
    }

    @PostMapping("/{campaignId}/ai-insights")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignAiResponse generateAiInsights(@PathVariable UUID campaignId) {
        return campaignAiService.insights(workspaceService.getWorkspace(), campaignId);
    }

    @PostMapping("/{campaignId}/ai-advisories")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignAiResponse generateAiAdvisories(@PathVariable UUID campaignId) {
        return campaignAiService.advisories(workspaceService.getWorkspace(), campaignId);
    }

    @GetMapping
    public List<CampaignSummaryResponse> list(@RequestParam(required = false) CampaignStatus status) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.list(tenant, status);
    }

    @GetMapping("/{campaignId}")
    public CampaignDetailResponse detail(@PathVariable UUID campaignId) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.getDetail(tenant, campaignId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse create(@RequestBody CampaignCreateRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.create(tenant, request, requestActorService.currentActor().userId());
    }

    /** Phase 0B §4.2: the create body, writing nothing. */
    @PostMapping("/preview")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignPreviewResponse preview(@RequestBody CampaignCreateRequest request) {
        return campaignService.preview(workspaceService.getWorkspace(), request);
    }

    /**
     * §4.5: cursor-paged members (at most 200 per page) with owner at add and current owner. Suppressed,
     * false-positive and accepted-risk members are hidden unless {@code outcome} names them or
     * {@code includeHidden=true}. {@code bucket}/{@code teamId} filter by the {@code groupBy} owner grouping.
     */
    @GetMapping("/{campaignId}/members")
    public CampaignMemberPage members(@PathVariable UUID campaignId,
                                      @RequestParam(required = false) List<String> outcome,
                                      @RequestParam(defaultValue = "false") boolean includeHidden,
                                      @RequestParam(required = false) String groupBy,
                                      @RequestParam(required = false) String bucket,
                                      @RequestParam(required = false) UUID teamId,
                                      @RequestParam(required = false) String cursor,
                                      @RequestParam(defaultValue = "50") int limit) {
        return campaignService.members(workspaceService.getWorkspace(), campaignId, outcome, includeHidden, groupBy, bucket, teamId, cursor, limit);
    }

    /** §4.12 add-findings action. */
    @PostMapping("/{campaignId}/members")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse addMembers(@PathVariable UUID campaignId, @RequestBody CampaignAddMembersRequest request) {
        return campaignService.addMembers(workspaceService.getWorkspace(), campaignId, request, requestActorService.currentActor().userId());
    }

    /** §4.5 owner buckets; {@code groupBy} is {@code current} (default) or {@code atAdd}. */
    @GetMapping("/{campaignId}/owner-buckets")
    public List<CampaignOwnerBucket> ownerBuckets(@PathVariable UUID campaignId, @RequestParam(required = false) String groupBy) {
        return campaignService.buckets(workspaceService.getWorkspace(), campaignId, groupBy);
    }

    /** §4.3 reconciler state. */
    @GetMapping("/{campaignId}/reconciliation")
    public CampaignReconciliationResponse reconciliation(@PathVariable UUID campaignId) {
        return campaignService.reconciliation(workspaceService.getWorkspace(), campaignId);
    }

    @PostMapping("/{campaignId}/status")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateStatus(
            @PathVariable UUID campaignId,
            @RequestBody CampaignStatusUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateStatus(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/notes")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignNoteResponse addNote(
            @PathVariable UUID campaignId,
            @RequestBody CampaignNoteRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.addNote(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/exceptions")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignExceptionResponse addException(
            @PathVariable UUID campaignId,
            @RequestBody CampaignExceptionRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.addException(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/notify-groups/{notifyGroupId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateNotifyGroup(
            @PathVariable UUID campaignId,
            @PathVariable UUID notifyGroupId,
            @RequestBody CampaignNotifyGroupRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateNotifyGroup(tenant, campaignId, notifyGroupId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/watchlist/{watchlistEntryId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateWatchlistEntry(
            @PathVariable UUID campaignId,
            @PathVariable UUID watchlistEntryId,
            @RequestBody CampaignWatchlistEntryUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateWatchlistEntry(tenant, campaignId, watchlistEntryId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/exceptions/{exceptionId}/status")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateExceptionStatus(
            @PathVariable UUID campaignId,
            @PathVariable UUID exceptionId,
            @RequestBody CampaignExceptionStatusUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateExceptionStatus(tenant, campaignId, exceptionId, request, requestActorService.currentActor().userId());
    }
}
