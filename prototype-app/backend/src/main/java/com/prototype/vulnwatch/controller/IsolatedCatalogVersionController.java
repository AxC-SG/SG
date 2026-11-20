package com.prototype.vulnwatch.controller;
import com.prototype.vulnwatch.service.IsolatedCatalogVersionService;
import com.prototype.vulnwatch.service.CandidateProjectionBuilder;
import java.util.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/platform/intelligence/projection-versions")
@PreAuthorize("hasRole('PLATFORM_OWNER')")
@ConditionalOnProperty(name="app.intelligence.isolated-catalog.enabled",havingValue="true")
public class IsolatedCatalogVersionController {
 private final IsolatedCatalogVersionService service;
 private final CandidateProjectionBuilder builder;
 public IsolatedCatalogVersionController(IsolatedCatalogVersionService service,CandidateProjectionBuilder builder){this.service=service;this.builder=builder;}
 @PostMapping("/from-candidate/{candidate}") public UUID start(@PathVariable UUID candidate){return builder.start(candidate);}
 @PostMapping("/{id}/step") public Map<String,Object> step(@PathVariable UUID id){return builder.step(id);}
 @GetMapping("/{id}") public Map<String,Object> status(@PathVariable UUID id){return builder.status(id);}
 @GetMapping("/{id}/records") public List<Map<String,Object>> browse(@PathVariable UUID id,@RequestParam(defaultValue="0") long after,@RequestParam(defaultValue="100") int limit){return builder.browse(id,after,limit);}
 @GetMapping("/active/records") public List<Map<String,Object>> active(@RequestParam(defaultValue="0") long after,@RequestParam(defaultValue="100") int limit){return service.readActive(after,limit);}
 public record Create(UUID id,long count){}
 public record Batch(long token,long cursor,List<IsolatedCatalogVersionService.Row> rows){}
 @PostMapping public void create(@RequestBody Create r){service.create(r.id(),r.count());}
 @PostMapping("/{id}/claim") public long claim(@PathVariable UUID id){return service.claim(id);}
 @PostMapping("/{id}/batches") public long append(@PathVariable UUID id,@RequestBody Batch r){return service.append(id,r.token(),r.cursor(),r.rows());}
 @PostMapping("/{id}/ready") public void ready(@PathVariable UUID id,@RequestParam long token){service.ready(id,token);}
 @PostMapping("/{id}/activate") public void activate(@PathVariable UUID id){service.activate(id);}
 @PostMapping("/{id}/cancel") public void cancel(@PathVariable UUID id){service.cancel(id);}
}
