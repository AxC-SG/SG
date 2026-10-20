package com.prototype.vulnwatch.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** The existing administrative purge stays contained until its full repair is qualified. */
public final class ManualTenantDeletionPolicy {

    private ManualTenantDeletionPolicy() {
    }

    public static void requirePermitted() {
        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Tenant deletion is temporarily unavailable. Tenant expiry and access controls remain available.");
    }
}
