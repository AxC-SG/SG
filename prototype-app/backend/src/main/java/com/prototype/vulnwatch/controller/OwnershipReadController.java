package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Coverage;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Inventory and finding ownership reads for the UI consumer waves (plan §8.3, §8.6, §15.4). Every response uses the
 * domain-aware envelope; filters take stable team IDs, never owner names.
 */
@RestController
@RequestMapping("/api/ownership")
public class OwnershipReadController {

    private static final Set<String> STATUSES = Set.of("OWNED", "UNOWNED", "CONFLICT");

    private final OwnershipReadAdapter reads;

    public OwnershipReadController(OwnershipReadAdapter reads) {
        this.reads = reads;
    }

    @GetMapping("/assets")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<Summary> assets(@RequestParam("ids") List<UUID> ids) {
        return reads.forAssets(ids);
    }

    @GetMapping("/findings")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<Summary> findings(@RequestParam("ids") List<UUID> ids) {
        return reads.forFindings(ids);
    }

    @GetMapping("/assets/filter")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<UUID> filterAssets(@RequestParam(required = false) UUID ownerTeamId, @RequestParam(required = false) String status,
                                   @RequestParam(required = false) UUID after, @RequestParam(defaultValue = "100") int limit) {
        return reads.filter(Consumer.INVENTORY, ownerTeamId, status(status), limit, after);
    }

    @GetMapping("/findings/filter")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public List<UUID> filterFindings(@RequestParam(required = false) UUID ownerTeamId, @RequestParam(required = false) String status,
                                     @RequestParam(required = false) UUID after, @RequestParam(defaultValue = "100") int limit) {
        return reads.filter(Consumer.FINDINGS, ownerTeamId, status(status), limit, after);
    }

    @GetMapping("/coverage")
    @PreAuthorize("@ownershipAuthorization.can('VIEW_OWNERSHIP')")
    public Coverage coverage(@RequestParam(defaultValue = "INVENTORY") String consumer) {
        String c = consumer.toUpperCase(Locale.ROOT);
        if (!c.equals("INVENTORY") && !c.equals("FINDINGS")) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown consumer");
        return reads.coverage(Consumer.valueOf(c));
    }

    private static String status(String value) {
        if (value == null || value.isBlank()) return null;
        String s = value.toUpperCase(Locale.ROOT);
        if (!STATUSES.contains(s)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown ownership status");
        return s;
    }
}
