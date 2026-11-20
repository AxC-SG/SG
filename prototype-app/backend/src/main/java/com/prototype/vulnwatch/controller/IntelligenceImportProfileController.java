package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.IntelligenceImportProfileService;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;

@RestController
@RequestMapping("/api/platform/intelligence/import-profiles")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class IntelligenceImportProfileController {
    private final IntelligenceImportProfileService service;
    public IntelligenceImportProfileController(IntelligenceImportProfileService service) { this.service=service; }
    @GetMapping public List<IntelligenceImportProfileService.Profile> list() { return service.list(); }
    @PostMapping public IntelligenceImportProfileService.Profile save(@RequestBody IntelligenceImportProfileService.Profile profile) { return service.save(profile); }
    @PostMapping("/{id}/run") public Object run(@PathVariable UUID id) { return service.run(id); }
    public record Schedule(boolean enabled,int intervalHours) {}
    @GetMapping("/{id}/schedule") public Object schedule(@PathVariable UUID id) { return service.schedule(id); }
    @PostMapping("/{id}/schedule") public Object schedule(@PathVariable UUID id,@RequestBody Schedule schedule) { return service.schedule(id,schedule.enabled(),schedule.intervalHours()); }
}
