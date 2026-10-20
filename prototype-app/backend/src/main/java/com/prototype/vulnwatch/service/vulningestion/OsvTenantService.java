package com.prototype.vulnwatch.service.vulningestion;

import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Platform OSV intelligence remains supported; tenant correlation is unfinished. */
@Service
public class OsvTenantService {
    // Deliberately has no scheduling annotation and performs no work for stale job callers.
    public void correlateOsvForAllEnabledTenants() {
    }

    public void correlateOsvAdvisoriesForTenant(UUID tenantId) {
        throw new ResponseStatusException(HttpStatus.GONE, "OSV_TENANT_CORRELATION_UNAVAILABLE");
    }
}
