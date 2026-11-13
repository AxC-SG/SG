package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService;
import com.prototype.vulnwatch.service.ownership.OwnershipCutoverService;
import com.prototype.vulnwatch.service.ownership.OwnershipCutoverService.Qualification;
import com.prototype.vulnwatch.service.ownership.OwnershipReviewService;
import com.prototype.vulnwatch.service.ownership.OwnershipReviewService.ReviewItem;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService.Alias;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService.Team;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Teams, aliases, review items and tenant encryption setup (plan §8.3). */
@RestController
@RequestMapping("/api/ownership")
public class OwnershipAdminController {

    public record TeamRequest(String name, UUID parentTeamId, String ticketAssignmentGroup, String status, Long version) { }

    public record AliasRequest(String alias, String sourceKind) { }

    public record ReviewCloseRequest(String state, String note) { }

    public record EncryptionStatus(boolean ready, String reason) { }

    public record AuthorityRequest(String state, String reportHash) { }

    private final TeamNamespaceService teams;
    private final OwnershipReviewService reviews;
    private final TenantKeyRegistry keys;
    private final RequestActorService actors;
    private final AuditEventService audit;
    private final OwnershipCutoverService cutover;

    public OwnershipAdminController(TeamNamespaceService teams, OwnershipReviewService reviews, TenantKeyRegistry keys,
                                    RequestActorService actors, AuditEventService audit, OwnershipCutoverService cutover) {
        this.teams = teams;
        this.reviews = reviews;
        this.keys = keys;
        this.actors = actors;
        this.audit = audit;
        this.cutover = cutover;
    }

    @GetMapping("/teams")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<Team> teams(@RequestParam(value = "q", defaultValue = "") String prefix, @RequestParam(required = false) String status,
                            @RequestParam(defaultValue = "50") int limit, @RequestParam(defaultValue = "0") int offset) {
        return teams.list(prefix, status == null ? null : status.toUpperCase(Locale.ROOT), limit, offset);
    }

    @GetMapping("/teams/{id}")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public Team team(@PathVariable UUID id) {
        return teams.team(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Team not found"));
    }

    @PostMapping("/teams")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_TEAMS')")
    public ResponseEntity<Team> createTeam(@RequestBody TeamRequest req) {
        return ResponseEntity.status(HttpStatus.CREATED).body(teams.createTeam(req.name(), req.parentTeamId(), req.ticketAssignmentGroup(), actor()));
    }

    /** Applies rename, parent/ticket-group and status changes in that order. {@code parentTeamId} and {@code ticketAssignmentGroup} are replaced as given (null clears); send the current values to keep them. */
    @PatchMapping("/teams/{id}")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_TEAMS')")
    public Team updateTeam(@PathVariable UUID id, @RequestBody TeamRequest req) {
        if (req.version() == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "version is required");
        String actor = actor();
        Team current = team(id);
        if (current.version() != req.version()) throw new ResponseStatusException(HttpStatus.CONFLICT, "The team changed since it was loaded; reload and try again");
        if (req.name() != null && !req.name().strip().equals(current.name())) current = teams.renameTeam(id, req.name(), current.version(), actor);
        current = teams.updateTeam(id, req.parentTeamId(), req.ticketAssignmentGroup(), current.version(), actor);
        if (req.status() != null && !req.status().equalsIgnoreCase(current.status())) {
            current = teams.setStatus(id, req.status().toUpperCase(Locale.ROOT), current.version(), actor);
        }
        return current;
    }

    @GetMapping("/teams/{id}/aliases")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<Alias> aliases(@PathVariable UUID id) {
        team(id);
        return teams.aliases(id);
    }

    @PostMapping("/teams/{id}/aliases")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_TEAMS')")
    public ResponseEntity<Alias> addAlias(@PathVariable UUID id, @RequestBody AliasRequest req) {
        String kind = req.sourceKind() == null ? "MANUAL" : req.sourceKind().toUpperCase(Locale.ROOT);
        return ResponseEntity.status(HttpStatus.CREATED).body(teams.addAlias(id, req.alias(), kind, null, actor()));
    }

    @DeleteMapping("/teams/{id}/aliases/{aliasId}")
    @PreAuthorize("@ownershipAuthorization.can('WRITE_TEAMS')")
    public ResponseEntity<Void> removeAlias(@PathVariable UUID id, @PathVariable UUID aliasId) {
        teams.removeAlias(id, aliasId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/review-items")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<ReviewItem> reviewItems(@RequestParam(defaultValue = "OPEN") String state, @RequestParam(required = false) String type,
                                        @RequestParam(defaultValue = "50") int limit, @RequestParam(defaultValue = "0") int offset) {
        return reviews.list(state.toUpperCase(Locale.ROOT), type == null ? null : type.toUpperCase(Locale.ROOT), limit, offset);
    }

    @PatchMapping("/review-items/{id}")
    @PreAuthorize("@ownershipAuthorization.can('RESOLVE_REVIEW')")
    public ResponseEntity<Void> closeReviewItem(@PathVariable UUID id, @RequestBody ReviewCloseRequest req) {
        reviews.close(id, req.state() == null ? "" : req.state().toUpperCase(Locale.ROOT), req.note(), actor());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/encryption")
    @PreAuthorize("@ownershipAuthorization.can('MANAGE_ENCRYPTION')")
    public EncryptionStatus encryption() {
        TenantKeyRegistry.Readiness readiness = keys.readiness(TenantContext.getCurrentTenantId());
        return new EncryptionStatus(readiness.ready(), readiness.reason() == null ? null : readiness.reason().name());
    }

    /**
     * Creates the tenant's data key so directory and connector-secret writes can start. Idempotent. Fails with 503
     * while no key wrapper is configured (deployed environments until the KMS spike passes).
     */
    @PostMapping("/encryption/provision")
    @PreAuthorize("@ownershipAuthorization.can('MANAGE_ENCRYPTION')")
    public EncryptionStatus provisionEncryption() {
        UUID tenant = TenantContext.getCurrentTenantId();
        try {
            int version = keys.provision(tenant);
            audit.record("ownership.tenant_key.provisioned", "tenant", tenant.toString(), "{\"keyVersion\":" + version + "}");
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not available in this environment");
        }
        return encryption();
    }

    @GetMapping("/authority/{domain}/qualification")
    @PreAuthorize("@ownershipAuthorization.can('MANAGE_AUTHORITY')")
    public Qualification qualification(@PathVariable String domain) {
        return cutover.qualify(domain(domain));
    }

    /** LEGACY→DARK, DARK→LEGACY (no-go) or DARK→CANONICAL (go; requires the reviewed {@code reportHash}). */
    @PostMapping("/authority/{domain}")
    @PreAuthorize("@ownershipAuthorization.can('MANAGE_AUTHORITY')")
    public Qualification transition(@PathVariable String domain, @RequestBody AuthorityRequest req) {
        OwnershipAuthorityService.State target;
        try {
            target = OwnershipAuthorityService.State.valueOf(req.state() == null ? "" : req.state().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown authority state");
        }
        return cutover.transition(domain(domain), target, req.reportHash(), actor());
    }

    private static OwnershipAuthorityService.Domain domain(String value) {
        try {
            return OwnershipAuthorityService.Domain.valueOf(value.toUpperCase(Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown ownership domain");
        }
    }

    private String actor() {
        return actors.currentActor().userId();
    }
}
