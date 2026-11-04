package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.AuditEventService;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Audited compatibility tombstone for clients still calling the removed direct-accept route. */
@RestController
@RequestMapping("/api/bom/cbom")
public class LegacyCbomAcceptController {
    private final AuditEventService auditEventService;

    public LegacyCbomAcceptController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @PostMapping("/findings/{findingId}/accept")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN','CREATOR')")
    public ResponseEntity<Map<String, Object>> acceptRemoved(@PathVariable UUID findingId) {
        auditEventService.record("cbom.legacy_accept.removed_call", "cbom_finding", findingId.toString(),
                "{\"replacement\":\"/api/findings/{canonicalFindingId}/suppression-requests\"}", "DENIED");
        return ResponseEntity.status(HttpStatus.GONE)
                .header("Deprecation", "true")
                .header("Sunset", "Mon, 02 Nov 2026 00:00:00 GMT")
                .body(Map.of(
                        "code", "LEGACY_CBOM_ACCEPT_REMOVED",
                        "error", "Direct CBOM acceptance has been removed",
                        "replacement", "/api/findings/{canonicalFindingId}/suppression-requests"
                ));
    }
}
