package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.InventorySubjectAdapter;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService.Explanation;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService.Preview;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorization;
import com.prototype.vulnwatch.service.ownership.OwnershipSubjectService;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Subject ownership explanation and manual assignment (plan §8.4). {@code {id}} is the subject's source object ID;
 * for inventory assets that is the asset ID. Clients cannot register arbitrary subjects: a write resolves an existing
 * asset or an already-registered subject.
 */
@RestController
@RequestMapping("/api/ownership/subjects/{type}/{id}")
public class OwnershipSubjectController {

    public record AssignRequest(UUID teamId, String reason, Instant expiresAt) { }

    public record PreviewRequest(UUID teamId) { }

    public record RevokeRequest(String reason) { }

    private static final Set<String> ASSET_TYPES = Set.of("APPLICATION", "HOST", "CONTAINER_IMAGE", "CLOUD_RESOURCE");

    private final OwnershipSubjectService subjects;
    private final InventorySubjectAdapter inventory;
    private final ManualAssignmentService assignments;
    private final OwnershipAuthorization authorization;
    private final RequestActorService actors;

    public OwnershipSubjectController(OwnershipSubjectService subjects, InventorySubjectAdapter inventory,
                                      ManualAssignmentService assignments, OwnershipAuthorization authorization,
                                      RequestActorService actors) {
        this.subjects = subjects;
        this.inventory = inventory;
        this.assignments = assignments;
        this.authorization = authorization;
        this.actors = actors;
    }

    @GetMapping
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public Explanation explanation(@PathVariable String type, @PathVariable String id) {
        UUID subject = subjects.find(type(type), id, null).map(OwnershipSubjectService.Subject::id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "No ownership is recorded for this subject yet"));
        return assignments.explain(subject);
    }

    @PostMapping("/manual-assignment/preview")
    @PreAuthorize("@ownershipAuthorization.can('MANUAL_ASSIGN')")
    public Preview preview(@PathVariable String type, @PathVariable String id, @RequestBody PreviewRequest req) {
        return assignments.preview(resolveForWrite(type(type), id), req.teamId());
    }

    @PostMapping("/manual-assignment")
    @PreAuthorize("@ownershipAuthorization.can('MANUAL_ASSIGN')")
    public ResponseEntity<Preview> assign(@PathVariable String type, @PathVariable String id, @RequestBody AssignRequest req,
                                          @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {
        String subjectType = type(type);
        String actor = actors.currentActor().userId();
        UUID analyst = assignments.analystPrincipal(actor, authorization.isAdmin()).orElse(null);
        Preview result = assignments.assign(resolveForWrite(subjectType, id), subjectType, req.teamId(), req.reason(), req.expiresAt(),
                idempotencyKey, actor, analyst);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/manual-assignment/revoke")
    @PreAuthorize("@ownershipAuthorization.can('REVOKE_ASSIGNMENT')")
    public ResponseEntity<Void> revoke(@PathVariable String type, @PathVariable String id, @RequestBody(required = false) RevokeRequest req) {
        String subjectType = type(type);
        UUID subject = subjects.find(subjectType, id, null).map(OwnershipSubjectService.Subject::id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership subject not found"));
        assignments.revoke(subject, subjectType, actors.currentActor().userId(), req == null ? null : req.reason());
        return ResponseEntity.noContent().build();
    }

    private UUID resolveForWrite(String subjectType, String id) {
        if (ASSET_TYPES.contains(subjectType)) {
            try {
                UUID assetId = UUID.fromString(id);
                return inventory.subjectForAsset(assetId)
                        .filter(subject -> subjects.find(subjectType, id, null).map(s -> s.id().equals(subject)).orElse(false))
                        .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Asset not found"));
            } catch (IllegalArgumentException ex) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Asset not found");
            }
        }
        return subjects.find(subjectType, id, null).map(OwnershipSubjectService.Subject::id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership subject not found"));
    }

    private static String type(String value) {
        String type = value == null ? "" : value.toUpperCase(Locale.ROOT).replace('-', '_');
        try {
            com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.domainFor(type);
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown subject type");
        }
        return type;
    }
}
