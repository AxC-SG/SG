package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.cbom.CbomAssessmentBackfillService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Fleet-wide CBOM assessment backfill for the deployment runbook. */
@RestController
@RequestMapping("/api/platform/cbom/assessment-backfill")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformCbomBackfillController {
    private final CbomAssessmentBackfillService backfill;
    private final RequestActorService actors;

    public PlatformCbomBackfillController(CbomAssessmentBackfillService backfill, RequestActorService actors) {
        this.backfill = backfill;
        this.actors = actors;
    }

    @GetMapping
    public List<CbomAssessmentBackfillService.BackfillStatus> status() {
        return backfill.statusAllTenants();
    }

    @PostMapping
    public CbomAssessmentBackfillService.PlatformBackfillResult start(@RequestParam(required = false) Integer limitPerTenant) {
        var actor = actors.currentActor();
        return backfill.startAllTenants(actor == null ? "platform" : "platform:" + actor.userId(), limitPerTenant);
    }
}
