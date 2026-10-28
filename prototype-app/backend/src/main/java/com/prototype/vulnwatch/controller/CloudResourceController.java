package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CloudResourcePageResponse;
import com.prototype.vulnwatch.service.CloudResourceService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Read-only Cloud Resources inventory across AWS, Azure and GCP discovery. */
@RestController
@RequestMapping("/api/cloud-resources")
public class CloudResourceController {

    private final WorkspaceService workspaceService;
    private final CloudResourceService cloudResourceService;

    public CloudResourceController(WorkspaceService workspaceService, CloudResourceService cloudResourceService) {
        this.workspaceService = workspaceService;
        this.cloudResourceService = cloudResourceService;
    }

    @GetMapping
    public CloudResourcePageResponse list(
            @RequestParam(required = false) String provider,
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false) String region,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        // Resolving the workspace pins the request to the caller's tenant before any query runs.
        workspaceService.getWorkspace();
        return cloudResourceService.search(
                new CloudResourceService.Filter(provider, accountId, region, resourceType, state, search), page, size);
    }
}
