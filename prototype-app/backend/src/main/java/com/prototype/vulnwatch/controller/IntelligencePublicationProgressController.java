package com.prototype.vulnwatch.controller;
import com.prototype.vulnwatch.service.IntelligencePublicationProgressService;
import java.util.*;
import java.security.Principal;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
@RestController
@RequestMapping("/api/platform/intelligence/candidates/{id}")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class IntelligencePublicationProgressController {
 private final IntelligencePublicationProgressService progress;
 public IntelligencePublicationProgressController(IntelligencePublicationProgressService progress){this.progress=progress;}
 public record Control(String action){}
 @GetMapping("/progress") public Map<String,Object> get(@PathVariable UUID id){return progress.get(id);}
 @PostMapping("/control") public Map<String,Object> control(@PathVariable UUID id,@RequestBody Control request,Principal actor){return progress.control(id,request.action(),actor.getName());}
}
