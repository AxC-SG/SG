package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.*;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** Provider acceptance and manual reconciliation use the existing platform operations authority. */
@RestController
@RequestMapping("/api/operations/email-deliveries")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class EmailDeliveryOperationsController {
    public enum Family { INVITATION,CAMPAIGN }
    public record Reconciliation(String outcome,String providerMessageId,String note) { }
    private final InvitationEmailOutboxService invitations;
    private final CampaignEmailOutboxService campaigns;
    private final TenantSchemaExecutionService tenants;
    private final RequestActorService actors;
    public EmailDeliveryOperationsController(InvitationEmailOutboxService invitations,CampaignEmailOutboxService campaigns,
            TenantSchemaExecutionService tenants,RequestActorService actors) {
        this.invitations=invitations;this.campaigns=campaigns;this.tenants=tenants;this.actors=actors;
    }
    @GetMapping
    public List<Map<String,Object>> status(@RequestParam Family family,@RequestParam UUID tenantId) {
        return family==Family.INVITATION ? TenantContext.runAsPlatform(() -> invitations.status(tenantId))
                : tenants.run(tenantId,() -> campaigns.status(tenantId));
    }
    @PostMapping("/{deliveryId}/reconcile")
    public void reconcile(@PathVariable UUID deliveryId,@RequestParam Family family,@RequestParam UUID tenantId,
            @RequestBody Reconciliation request) {
        String actor=actors.currentActor().userId();
        if (family==Family.INVITATION) TenantContext.runAsPlatform(() -> invitations.reconcile(tenantId,deliveryId,request.outcome(),request.providerMessageId(),actor,request.note()));
        else tenants.run(tenantId,() -> {campaigns.reconcile(tenantId,deliveryId,request.outcome(),request.providerMessageId(),actor,request.note());return null;});
    }
}
