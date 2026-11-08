package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.BomUploadRequest;
import com.prototype.vulnwatch.service.BomUploadService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bom/uploads")
@ConditionalOnProperty(name = "app.bom.uploads.enabled", havingValue = "true")
@PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
public class BomUploadController {
    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final BomUploadService uploads;

    public BomUploadController(WorkspaceService workspace, RequestActorService actors, BomUploadService uploads) {
        this.workspace = workspace;
        this.actors = actors;
        this.uploads = uploads;
    }

    @PostMapping
    public ResponseEntity<BomUploadService.UploadTicket> create(
            @RequestHeader("Idempotency-Key") UUID key, @Valid @RequestBody BomUploadRequest request) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(uploads.create(workspace.getWorkspace(), actors.currentActor(), key, request));
    }

    @PostMapping("/{id}/complete")
    public ResponseEntity<BomUploadService.UploadStatus> complete(@PathVariable UUID id) {
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore())
                .body(uploads.complete(workspace.getWorkspace(), actors.currentActor(), id));
    }

    @GetMapping("/{id}")
    public ResponseEntity<BomUploadService.UploadStatus> get(@PathVariable UUID id) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(uploads.get(workspace.getWorkspace(), actors.currentActor(), id));
    }
}
