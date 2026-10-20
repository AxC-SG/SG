package com.prototype.vulnwatch.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Pilot containment. Re-enablement requires complete authoritative collection qualification. */
public final class GenericAzureDiscoveryPolicy {
    public static final String MESSAGE = "Generic Azure discovery is disabled for the pilot; existing inventory is retained";
    private GenericAzureDiscoveryPolicy() {}
    public static boolean available() { return false; }
    public static void requireAvailable() {
        throw new ResponseStatusException(HttpStatus.GONE, MESSAGE);
    }
}
