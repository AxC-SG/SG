package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Provider;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipSourceService;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipSourceService.SettingsRequest;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipSourceService.Status;
import java.util.List;
import java.util.Locale;
import org.springframework.http.HttpStatus;
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
 * AWS and GCP ownership producers in the hub's Sources view (Phase 0B §2.1, §2.2). Reading needs VIEW_IDENTITY_SOURCE;
 * settings need CONFIGURE_OWNERSHIP_PRODUCER; pause and resume need PAUSE_SOURCE. The cloud credentials stay on the
 * discovery connectors and are never read here.
 */
@RestController
@RequestMapping("/api/ownership/cloud-sources")
public class CloudOwnershipSourceController {

    public record PauseRequest(String reason) { }

    private final CloudOwnershipSourceService sources;
    private final RequestActorService actors;

    public CloudOwnershipSourceController(CloudOwnershipSourceService sources, RequestActorService actors) {
        this.sources = sources;
        this.actors = actors;
    }

    @GetMapping
    @PreAuthorize("@ownershipAuthorization.can('VIEW_IDENTITY_SOURCE')")
    public List<Status> list() {
        return List.of(sources.status(Provider.AWS), sources.status(Provider.GCP));
    }

    @GetMapping("/{provider}")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_IDENTITY_SOURCE')")
    public Status get(@PathVariable String provider) {
        return sources.status(provider(provider));
    }

    @PutMapping("/{provider}/settings")
    @PreAuthorize("@ownershipAuthorization.can('CONFIGURE_OWNERSHIP_PRODUCER')")
    public Status updateSettings(@PathVariable String provider, @RequestBody SettingsRequest request) {
        return sources.updateSettings(provider(provider), request, actor());
    }

    @PostMapping("/{provider}/pause")
    @PreAuthorize("@ownershipAuthorization.can('PAUSE_SOURCE')")
    public Status pause(@PathVariable String provider, @RequestBody(required = false) PauseRequest request) {
        return sources.pause(provider(provider), request == null ? null : request.reason(), actor());
    }

    /** Resuming after an anomaly pause is the admin's approval of the reviewed changes (§2.8). */
    @PostMapping("/{provider}/resume")
    @PreAuthorize("@ownershipAuthorization.can('PAUSE_SOURCE')")
    public Status resume(@PathVariable String provider) {
        return sources.resume(provider(provider), actor());
    }

    private static Provider provider(String value) {
        try {
            return Provider.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown cloud ownership source");
        }
    }

    private String actor() {
        return actors.currentActor().userId();
    }
}
