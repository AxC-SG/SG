package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.TenantContext;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Read side of the group-to-team mapping (Phase 0B contract §1.8). Resolves a CMDB {@code support_group} value that is a
 * {@code sys_user_group} {@code sys_id} through an active, explicit mapping of a ServiceNow identity source on the same
 * instance as the tenant's CMDB connector. Writes nothing; {@link GroupTeamMappingService} is the writer.
 *
 * <p>Until tenant V24 keeps the reference {@code sys_id} beside the display name, the CMDB sync stores a {@code sys_id}
 * only when an admin's field list leaves out the display value; a name still resolves by exact team name or alias.
 */
@Component
public class GroupMappingResolver {

    private static final Pattern SYS_ID = Pattern.compile("(?i)[0-9a-f]{32}");

    private final JdbcTemplate jdbc;
    private final TenantDataCipher cipher;

    public GroupMappingResolver(JdbcTemplate jdbc, TenantDataCipher cipher) {
        this.jdbc = jdbc;
        this.cipher = cipher;
    }

    /** The tenant's CMDB connector instance as {@code https://host}, or null when there is none. */
    public String cmdbInstance() {
        List<String> urls = jdbc.queryForList(
                "SELECT base_url FROM servicenow_cmdb_configs WHERE lower(source_system) = 'servicenow' AND base_url IS NOT NULL LIMIT 1", String.class);
        return urls.isEmpty() ? null : instanceOf(urls.get(0));
    }

    /**
     * The team an active MANUAL or CSV mapping assigns to the group {@code value} names, when {@code value} is a
     * {@code sys_id} and a ServiceNow identity source on {@code instance} has seen that group. Empty when nothing maps
     * or when sources on the same instance map it to different teams.
     */
    public Optional<UUID> teamForGroup(String value, String instance) {
        if (value == null || instance == null || !SYS_ID.matcher(value.strip()).matches()) return Optional.empty();
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null || !cipher.readiness(tenant).ready()) return Optional.empty();
        byte[] index = cipher.blindIndex(tenant, DirectoryService.P_EXTERNAL_ID, value.strip().toLowerCase(Locale.ROOT));
        List<UUID> teams = jdbc.queryForList("""
                SELECT DISTINCT m.team_id FROM external_group_team_mapping m
                  JOIN external_group e ON e.id = m.external_group_id
                  JOIN identity_source s ON s.id = e.source_id
                  JOIN team t ON t.id = m.team_id
                 WHERE m.state = 'ACTIVE' AND m.provenance IN ('MANUAL','CSV') AND t.status = 'ACTIVE'
                   AND s.kind = 'SERVICENOW' AND s.scope_config ->> 'instanceUrl' = ? AND e.external_id_index = ?
                """, UUID.class, instance, index);
        return teams.size() == 1 ? Optional.of(teams.get(0)) : Optional.empty();
    }

    /** {@code https://host} in lower case, the form identity sources store; null when the value is not a URL. */
    static String instanceOf(String url) {
        try {
            URI uri = URI.create(url.strip());
            return uri.getHost() == null ? null : "https://" + uri.getHost().toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }
}
