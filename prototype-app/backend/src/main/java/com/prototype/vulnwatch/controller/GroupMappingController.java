package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.ChangeResult;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.GroupRow;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.Impact;
import com.prototype.vulnwatch.service.ownership.GroupTeamMappingService.Mapping;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Group-to-team mappings (Phase 0B contract §1.8). Reads need VIEW_OWNERSHIP; previews and changes need MAP_GROUPS.
 * A change needs the token from a preview of its impact.
 */
@RestController
@RequestMapping("/api/ownership/group-mappings")
public class GroupMappingController {

    public record PreviewRequest(UUID externalGroupId, UUID teamId) { }

    public record ActivateRequest(UUID externalGroupId, UUID teamId, String reason, String previewToken, Boolean confirmLarge) { }

    public record RetireRequest(String reason, String previewToken, Boolean confirmLarge) { }

    private final GroupTeamMappingService mappings;
    private final RequestActorService actors;

    public GroupMappingController(GroupTeamMappingService mappings, RequestActorService actors) {
        this.mappings = mappings;
        this.actors = actors;
    }

    @GetMapping
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<Mapping> list(@RequestParam(required = false) String state, @RequestParam(defaultValue = "100") int limit) {
        return mappings.mappings(state, limit);
    }

    @GetMapping("/groups")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<GroupRow> groups(@RequestParam(required = false) String q, @RequestParam(defaultValue = "50") int limit) {
        return mappings.groups(q, limit);
    }

    @PostMapping("/preview")
    @PreAuthorize("@ownershipAuthorization.can('MAP_GROUPS')")
    public Impact preview(@RequestBody PreviewRequest req) {
        return mappings.preview(req.externalGroupId(), req.teamId(), actor());
    }

    @PostMapping
    @PreAuthorize("@ownershipAuthorization.can('MAP_GROUPS')")
    public ResponseEntity<ChangeResult> activate(@RequestBody ActivateRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(mappings.activate(req.externalGroupId(), req.teamId(), req.reason(),
                req.previewToken(), Boolean.TRUE.equals(req.confirmLarge()), actor()));
    }

    @PostMapping("/{id}/retire")
    @PreAuthorize("@ownershipAuthorization.can('MAP_GROUPS')")
    public ChangeResult retire(@PathVariable UUID id, @RequestBody(required = false) RetireRequest req) {
        return mappings.retire(id, req == null ? null : req.reason(), req == null ? null : req.previewToken(),
                req != null && Boolean.TRUE.equals(req.confirmLarge()), actor());
    }

    @PostMapping("/{id}/dismiss")
    @PreAuthorize("@ownershipAuthorization.can('MAP_GROUPS')")
    public Mapping dismiss(@PathVariable UUID id) {
        return mappings.dismiss(id, actor());
    }

    private String actor() {
        return actors.currentActor().userId();
    }
}
