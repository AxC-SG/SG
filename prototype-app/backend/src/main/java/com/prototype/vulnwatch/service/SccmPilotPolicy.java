package com.prototype.vulnwatch.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Live JDBC and fixture substitution require a separate, explicit re-enablement change. */
public final class SccmPilotPolicy {
    private SccmPilotPolicy() { }

    public static void requireEnabled() {
        throw new ResponseStatusException(HttpStatus.GONE, "SCCM live JDBC is disabled for the assisted pilot");
    }
}
