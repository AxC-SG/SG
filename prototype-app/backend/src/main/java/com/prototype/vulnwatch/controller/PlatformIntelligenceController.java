package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.IntelligencePublicationService;
import java.security.Principal;
import java.util.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/platform/intelligence")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformIntelligenceController {
    private final IntelligencePublicationService intelligence;
    @org.springframework.beans.factory.annotation.Autowired
    private com.prototype.vulnwatch.service.TenantIntelligenceProcessingService processing;
    public PlatformIntelligenceController(IntelligencePublicationService intelligence) { this.intelligence=intelligence; }
    @org.springframework.beans.factory.annotation.Autowired
    private com.prototype.vulnwatch.service.IntelligenceFeedScheduleService schedules;
    @org.springframework.beans.factory.annotation.Autowired
    private com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService runs;
    @PostMapping("/feeds/{type}/run")
    public ResponseEntity<com.prototype.vulnwatch.dto.SyncTriggerResponse> run(@PathVariable String type) {
        if(!Set.of("OSV","EPSS").contains(type)) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Use the source-specific trigger for this feed");
        return ResponseEntity.accepted().body(com.prototype.vulnwatch.service.TenantContext.runAsPlatform(() ->
                runs.prepareQueuedRun(type,List.of(type)).toResponse("Feed sync is already in progress","Feed sync queued")));
    }
    public record ScheduleRequest(boolean enabled,int intervalHours) { }
    @GetMapping("/schedules")
    public List<Map<String,Object>> schedules() { return schedules.list(); }
    @PutMapping("/schedules/{type}")
    public Map<String,Object> schedule(@PathVariable String type,@RequestBody ScheduleRequest request,Principal actor) {
        return schedules.save(type,request.enabled(),request.intervalHours(),actor.getName());
    }
    @org.springframework.beans.factory.annotation.Autowired
    private com.prototype.vulnwatch.service.IntelligenceOperationalMetrics metrics;
    @GetMapping("/health")
    public Map<String,Object> health() { return metrics.health(); }
    public record CandidateRequest(List<UUID> syncRunIds) { }
    public record PublishRequest(String digest,UUID baseReleaseId,String idempotencyKey) { }
    public record RejectRequest(String reason) { }
    public record WithdrawRequest(String idempotencyKey) { }
    @PostMapping("/candidates")
    public ResponseEntity<Map<String,Object>> create(@RequestBody CandidateRequest request,Principal actor) {
        return ResponseEntity.accepted().body(intelligence.createCandidate(request.syncRunIds(),actor.getName()));
    }
    @GetMapping("/candidates/{id}")
    public Map<String,Object> candidate(@PathVariable UUID id) { return intelligence.candidate(id); }
    @GetMapping("/candidates/{id}/records")
    public List<Map<String,Object>> records(@PathVariable UUID id,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size) {
        return intelligence.records(id,page,size);
    }
    @PostMapping("/candidates/{id}/publish")
    public ResponseEntity<Map<String,Object>> publish(@PathVariable UUID id,@RequestBody PublishRequest request,Principal actor) {
        return ResponseEntity.accepted().body(intelligence.publish(id,request.digest(),request.baseReleaseId(),request.idempotencyKey(),actor.getName()));
    }
    @PostMapping("/candidates/{id}/reject")
    public Map<String,Object> reject(@PathVariable UUID id,@RequestBody RejectRequest request,Principal actor) { return intelligence.reject(id,request.reason(),actor.getName()); }
    @GetMapping("/releases")
    public List<Map<String,Object>> releases(@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size) { return intelligence.releases(page,size); }
    @GetMapping("/releases/{id}/processing")
    public List<Map<String,Object>> processing(@PathVariable UUID id,@RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size) {
        return processing.processing(id,page,size);
    }
    @PostMapping("/releases/{id}/withdraw")
    public ResponseEntity<Map<String,Object>> withdraw(@PathVariable UUID id,@RequestBody WithdrawRequest request,Principal actor) {
        return ResponseEntity.accepted().body(intelligence.withdraw(id,request.idempotencyKey(),actor.getName()));
    }
}
