package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.*;
import java.util.Map;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/connectors/vulnerability-sources/processing")
public class TenantIntelligenceStatusController {
    private final WorkspaceService workspace;
    private final TenantIntelligenceProcessingService processing;
    public TenantIntelligenceStatusController(WorkspaceService workspace,TenantIntelligenceProcessingService processing) {
        this.workspace=workspace;this.processing=processing;
    }
    @GetMapping
    public Map<String,Object> status() { return processing.status(workspace.getWorkspace().getId()); }
}
