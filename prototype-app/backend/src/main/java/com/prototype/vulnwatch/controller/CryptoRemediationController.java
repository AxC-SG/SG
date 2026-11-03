package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFindingResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFromFindingsRequest;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CryptoRemediationService;
import com.prototype.vulnwatch.ticketing.TicketRequest;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Crypto remediation operations: ticket template and attempts, queues, effectiveness, finding campaigns. */
@RestController
public class CryptoRemediationController {
    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final CryptoRemediationService remediation;
    private final CampaignService campaigns;

    public CryptoRemediationController(WorkspaceService workspace, RequestActorService actors,
            CryptoRemediationService remediation, CampaignService campaigns) {
        this.workspace = workspace; this.actors = actors; this.remediation = remediation; this.campaigns = campaigns;
    }

    @GetMapping("/api/findings/{findingId}/ticket-template")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN')")
    public TicketRequest ticketTemplate(@PathVariable UUID findingId) {
        workspace.getWorkspace();
        return remediation.template(findingId);
    }

    @GetMapping("/api/findings/{findingId}/ticket-attempts")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public List<CryptoRemediationService.TicketAttempt> ticketAttempts(@PathVariable UUID findingId) {
        workspace.getWorkspace();
        return remediation.attempts(findingId);
    }

    @GetMapping("/api/bom/cbom/remediation/queue")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public CryptoRemediationService.RemediationQueue queue() {
        workspace.getWorkspace();
        return remediation.queue();
    }

    @GetMapping("/api/bom/cbom/remediation/effectiveness")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public CryptoRemediationService.Effectiveness effectiveness(@RequestParam(defaultValue = "90") int days) {
        workspace.getWorkspace();
        return remediation.effectiveness(days);
    }

    @PostMapping("/api/campaigns/from-findings")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("campaign.created_from_findings")
    public CampaignDetailResponse createCampaign(@RequestBody CampaignFromFindingsRequest request) {
        return remediation.createCampaign(workspace.getWorkspace(), request, actor());
    }

    @GetMapping("/api/campaigns/{campaignId}/findings")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public List<CampaignFindingResponse> campaignFindings(@PathVariable UUID campaignId) {
        return campaigns.findings(workspace.getWorkspace(), campaignId);
    }

    private String actor() {
        var actor = actors.currentActor();
        return actor == null ? "api" : actor.userId();
    }
}
