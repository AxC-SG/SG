package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService.Explanation;
import com.prototype.vulnwatch.service.ownership.ManualAssignmentService.Preview;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorization;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
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
 * Assign owner on one BOM or CBOM occurrence row (Phase 0B §3.7): explanation, a preview of the findings an assignment
 * would change, the assignment and its revocation. The row ID is the occurrence's table row (a software component row or
 * a CBOM component row), never a package or software identity, so an assignment never applies to every occurrence of a
 * package. Manual assignment on occurrences needs {@code CLOUD_BOM} to be CANONICAL (409 otherwise), and a row that has
 * no registered occurrence yet is 404.
 */
@RestController
@RequestMapping("/api/ownership/occurrences/{table}/{rowId}")
public class OwnershipOccurrenceController {

    public record AssignRequest(UUID teamId, String reason, Instant expiresAt) { }

    public record PreviewRequest(UUID teamId) { }

    public record RevokeRequest(String reason) { }

    private static final String SUBJECT_TYPE = "COMPONENT_OCCURRENCE";

    private final JdbcTemplate jdbc;
    private final ManualAssignmentService assignments;
    private final OwnershipAuthorization authorization;
    private final RequestActorService actors;

    public OwnershipOccurrenceController(JdbcTemplate jdbc, ManualAssignmentService assignments, OwnershipAuthorization authorization,
                                         RequestActorService actors) {
        this.jdbc = jdbc;
        this.assignments = assignments;
        this.authorization = authorization;
        this.actors = actors;
    }

    @GetMapping
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public Explanation explanation(@PathVariable String table, @PathVariable UUID rowId) {
        return assignments.explain(subject(table, rowId));
    }

    @PostMapping("/manual-assignment/preview")
    @PreAuthorize("@ownershipAuthorization.can('MANUAL_ASSIGN')")
    public Preview preview(@PathVariable String table, @PathVariable UUID rowId, @RequestBody PreviewRequest req) {
        return assignments.preview(subject(table, rowId), req.teamId());
    }

    @PostMapping("/manual-assignment")
    @PreAuthorize("@ownershipAuthorization.can('MANUAL_ASSIGN')")
    public ResponseEntity<Preview> assign(@PathVariable String table, @PathVariable UUID rowId, @RequestBody AssignRequest req,
                                          @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey) {
        UUID subject = subject(table, rowId);
        String actor = actors.currentActor().userId();
        UUID analyst = assignments.analystPrincipal(actor, authorization.isAdmin()).orElse(null);
        Preview result = assignments.assign(subject, SUBJECT_TYPE, req.teamId(), req.reason(), req.expiresAt(), idempotencyKey, actor, analyst);
        return ResponseEntity.status(HttpStatus.CREATED).body(result);
    }

    @PostMapping("/manual-assignment/revoke")
    @PreAuthorize("@ownershipAuthorization.can('REVOKE_ASSIGNMENT')")
    public ResponseEntity<Void> revoke(@PathVariable String table, @PathVariable UUID rowId, @RequestBody(required = false) RevokeRequest req) {
        assignments.revoke(subject(table, rowId), SUBJECT_TYPE, actors.currentActor().userId(), req == null ? null : req.reason());
        return ResponseEntity.noContent().build();
    }

    /** The occurrence subject linked to the row; the table name is a fixed allow-list, never interpolated input. */
    private UUID subject(String table, UUID rowId) {
        String name = switch (table == null ? "" : table) {
            case "inventory-components" -> "inventory_components";
            case "cbom-components" -> "cbom_components";
            default -> throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown occurrence table");
        };
        List<UUID> ids = jdbc.queryForList("SELECT ownership_subject_id FROM " + name + " WHERE id = ? AND ownership_subject_id IS NOT NULL",
                UUID.class, rowId);
        if (ids.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "This row has no registered ownership occurrence yet");
        }
        return ids.get(0);
    }
}
