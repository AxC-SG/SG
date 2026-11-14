package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ConnectionTest;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.Preview;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ServiceNowSourceRequest;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.SourceView;
import java.util.List;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Identity sources for directory sync (Phase 0B contract §1.1, §1.6). Configure, test, preview, enable and resume need
 * CONFIGURE_IDENTITY_SOURCE (tenant admins); pause needs PAUSE_SOURCE. Credentials are write-only.
 */
@RestController
@RequestMapping("/api/ownership/identity-sources")
public class IdentitySourceController {

    public record PauseRequest(String reason) { }

    public record EnableRequest(String previewToken) { }

    private final IdentitySourceService sources;
    private final RequestActorService actors;

    public IdentitySourceController(IdentitySourceService sources, RequestActorService actors) {
        this.sources = sources;
        this.actors = actors;
    }

    @GetMapping
    @PreAuthorize("@ownershipAuthorization.can('VIEW_IDENTITY_SOURCE')")
    public List<SourceView> list() {
        return sources.list();
    }

    @GetMapping("/{id}")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_IDENTITY_SOURCE')")
    public SourceView get(@PathVariable UUID id) {
        return sources.get(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Identity source not found"));
    }

    @PostMapping
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public ResponseEntity<SourceView> create(@RequestBody ServiceNowSourceRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(sources.create(req, actor()));
    }

    @PutMapping("/{id}")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public SourceView update(@PathVariable UUID id, @RequestBody ServiceNowSourceRequest req) {
        return sources.update(id, req, actor());
    }

    @PostMapping("/{id}/test")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public ConnectionTest test(@PathVariable UUID id) {
        return sources.testConnection(id, actor());
    }

    /** Sample rows carry full names and emails for tenant admins only (§1.6), so the response must never be cached. */
    @PostMapping("/{id}/preview")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public ResponseEntity<Preview> preview(@PathVariable UUID id) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).header(HttpHeaders.PRAGMA, "no-cache")
                .body(sources.preview(id, actor()));
    }

    @PostMapping("/{id}/enable")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public SourceView enable(@PathVariable UUID id, @RequestBody(required = false) EnableRequest req) {
        return sources.enable(id, req == null ? null : req.previewToken(), actor());
    }

    @PostMapping("/{id}/pause")
    @PreAuthorize("@ownershipAuthorization.can('PAUSE_SOURCE')")
    public SourceView pause(@PathVariable UUID id, @RequestBody(required = false) PauseRequest req) {
        return sources.pause(id, req == null ? null : req.reason(), actor());
    }

    @PostMapping("/{id}/resume")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public SourceView resume(@PathVariable UUID id) {
        return sources.resume(id, actor());
    }

    @PostMapping("/{id}/disable")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_IDENTITY_SOURCE')")
    public SourceView disable(@PathVariable UUID id) {
        return sources.disable(id, actor());
    }

    private String actor() {
        return actors.currentActor().userId();
    }
}
