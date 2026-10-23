package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.AccountSetupRecoveryService;
import java.security.Principal;
import java.util.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/platform/setup-deliveries")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformAccountSetupController {
    private final AccountSetupRecoveryService setup;
    public PlatformAccountSetupController(AccountSetupRecoveryService setup) { this.setup=setup; }
    public record ReissueRequest(String reason) { }
    public record ReconcileRequest(String outcome,String providerMessageId,String note) { }
    @GetMapping public List<Map<String,Object>> status() { return setup.status(); }
    @PostMapping("/users/{userId}/reissue")
    public Map<String,Object> reissue(@PathVariable UUID userId,@RequestBody ReissueRequest request,Principal actor) { return setup.reissue(userId,request.reason(),actor.getName()); }
    @PostMapping("/{id}/reconcile")
    public void reconcile(@PathVariable UUID id,@RequestBody ReconcileRequest request,Principal actor) { setup.reconcile(id,request.outcome(),request.providerMessageId(),request.note(),actor.getName()); }
}
