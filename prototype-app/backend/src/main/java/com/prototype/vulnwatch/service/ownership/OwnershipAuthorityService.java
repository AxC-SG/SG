package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.TenantContext;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only lookup of which writer is authoritative for a tenant's ownership domain (design §8, plan §15.3).
 * A missing row means LEGACY. Canonical writers call {@link #requireCanonicalWrites}; readers use {@link #stateFor}
 * to choose between the canonical envelope and the legacy-pending-migration label.
 */
@Service
public class OwnershipAuthorityService {

    public enum Domain { CORE, CLOUD_BOM, AI_GRID }

    public enum State { LEGACY, DARK, CANONICAL }

    private static final Map<String, Domain> DOMAIN_BY_SUBJECT_TYPE = Map.of(
            "APPLICATION", Domain.CORE, "HOST", Domain.CORE,
            "CONTAINER_IMAGE", Domain.CLOUD_BOM, "CLOUD_ACCOUNT", Domain.CLOUD_BOM, "CLOUD_RESOURCE", Domain.CLOUD_BOM,
            "COMPONENT_OCCURRENCE", Domain.CLOUD_BOM, "AI_SYSTEM", Domain.AI_GRID, "AI_ARTIFACT", Domain.AI_GRID);

    private final JdbcTemplate jdbc;

    public OwnershipAuthorityService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public static Domain domainFor(String subjectType) {
        Domain domain = DOMAIN_BY_SUBJECT_TYPE.get(subjectType);
        if (domain == null) throw new IllegalArgumentException("Unknown subject type");
        return domain;
    }

    @Transactional(readOnly = true)
    public State stateFor(Domain domain) {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Authority lookups require a tenant context");
        List<String> rows = jdbc.queryForList("SELECT state FROM platform.ownership_domain_authority WHERE tenant_id = ? AND domain = ?",
                String.class, tenant, domain.name());
        return rows.isEmpty() ? State.LEGACY : State.valueOf(rows.get(0));
    }

    /**
     * User-facing canonical mutations (manual assignment, revocation) are accepted only once the domain is CANONICAL
     * (plan §15.3 step 5, §15.4): LEGACY and DARK subjects are rejected with 409.
     */
    public void requireCanonicalWrites(String subjectType) {
        if (stateFor(domainFor(subjectType)) != State.CANONICAL) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Ownership for this subject is still managed by the legacy model; canonical changes are not accepted yet");
        }
    }

    /** Producers publish claims in DARK (shadow qualification, invisible to readers) and CANONICAL, never in LEGACY. */
    public boolean producersMayPublish(Domain domain) {
        return stateFor(domain) != State.LEGACY;
    }
}
