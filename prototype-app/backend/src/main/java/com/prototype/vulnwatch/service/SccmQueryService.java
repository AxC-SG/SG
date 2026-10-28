package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SccmAuthType;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Extracts hardware/software inventory rows from an SCCM SQL Server database.
 *
 * <p>A JDBC connection is opened directly via {@link DriverManager} (not a Spring DataSource)
 * because connection details are stored per-tenant in the database, not in application.yml.
 * Every connection first passes {@link SccmJdbcPolicy}, so a tenant can only reach a database
 * host the operator has approved, with SQL Server authentication and a vetted URL.
 */
@Service
public class SccmQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(SccmQueryService.class);
    private final CredentialEncryptionService credentialEncryptionService;
    private final SccmJdbcPolicy jdbcPolicy;

    public SccmQueryService(CredentialEncryptionService credentialEncryptionService, SccmJdbcPolicy jdbcPolicy) {
        this.credentialEncryptionService = credentialEncryptionService;
        this.jdbcPolicy = jdbcPolicy;
    }

    /**
     * Full JOIN query used for production syncs. Fetches all active hosts with their installed
     * software from the two primary SCCM views.
     */
    static final String INSTALL_SQL = """
            SELECT
                CAST(sys.ResourceID AS VARCHAR(50))       AS sys_id,
                sys.Name0                                 AS computer_name,
                sys.Domain0                               AS domain,
                sys.Operating_System_Name_and0            AS os_name,
                sys.User_Name0                            AS last_user,
                sw.DisplayName0                           AS display_name,
                sw.Publisher0                             AS publisher,
                sw.Version0                               AS version,
                CONVERT(VARCHAR(10), sw.InstallDate0, 23) AS install_date,
                sw.ProductID0                             AS version_evidence
            FROM v_R_System sys
            INNER JOIN v_GS_INSTALLED_SOFTWARE sw ON sys.ResourceID = sw.ResourceID
            WHERE sys.Active0 = 1
              AND sys.Obsolete0 = 0
              AND sw.DisplayName0 IS NOT NULL
              AND sw.DisplayName0 != ''
            ORDER BY sys.Name0, sw.DisplayName0
            """;

    /** Lightweight query used by connection-test to verify that the system view is reachable. */
    static final String TEST_SQL =
            "SELECT TOP 5 CAST(ResourceID AS VARCHAR(50)) AS sys_id, Name0 AS computer_name "
            + "FROM v_R_System WHERE Active0 = 1";

    // ── Public API ─────────────────────────────────────────────────────────────────────────────

    /**
     * Fetches install rows for the given config from the tenant's SCCM database.
     *
     * <p>Each row map contains the keys expected by {@code CmdbInventoryIngestionRunner}:
     * {@code computer_name}, {@code sys_id}, {@code display_name}, {@code publisher},
     * {@code version}, {@code install_date}, {@code version_evidence}.
     */
    public List<Map<String, String>> fetchInstallRows(SccmCmdbConfig config) throws Exception {
        LOG.info("SCCM: executing install query against {}", safeJdbcUrl(config.getJdbcUrl()));
        return executeQuery(config, INSTALL_SQL);
    }

    /**
     * Derives discovery rows from the set of distinct (publisher, product) pairs found in
     * {@code installRows}.  The primary key is {@code lower(publisher) + "::" + lower(display_name)}.
     */
    public List<Map<String, String>> buildDiscoveryRows(List<Map<String, String>> installRows) {
        Set<String> seen = new LinkedHashSet<>();
        List<Map<String, String>> rows = new ArrayList<>();
        for (Map<String, String> row : installRows) {
            String publisher = blankToEmpty(row.get("publisher"));
            String displayName = blankToEmpty(row.get("display_name"));
            if (displayName.isEmpty()) {
                continue;
            }
            String pk = publisher.toLowerCase(Locale.ROOT) + "::" + displayName.toLowerCase(Locale.ROOT);
            if (seen.add(pk)) {
                Map<String, String> discovery = new LinkedHashMap<>();
                discovery.put("primary_key", pk);
                discovery.put("display_name", displayName);
                discovery.put("normalized_product", displayName);
                discovery.put("normalized_publisher", publisher);
                discovery.put("normalized_version", blankToEmpty(row.get("version")));
                discovery.put("normalization_status", "SCCM_DERIVED");
                discovery.put("approved", "false");
                discovery.put("low_confidence", "true");
                rows.add(discovery);
            }
        }
        return rows;
    }

    /**
     * Tests connectivity and verifies that the two key SCCM views are reachable.
     *
     * @return a two-element boolean array: {@code [systemViewReachable, softwareViewReachable]}
     */
    public boolean[] testConnection(SccmCmdbConfig config) {
        boolean systemOk = false;
        boolean softwareOk = false;
        try (Connection conn = openConnection(config)) {
            try (Statement stmt = conn.createStatement()) {
                stmt.setQueryTimeout(Math.max(5, config.getQueryTimeoutSeconds() == null ? 30 : config.getQueryTimeoutSeconds()));
                try (ResultSet rs = stmt.executeQuery(TEST_SQL)) {
                    systemOk = true;
                }
            }
            // Quick probe of the software view
            try (Statement stmt = conn.createStatement()) {
                stmt.setQueryTimeout(Math.max(5, config.getQueryTimeoutSeconds() == null ? 30 : config.getQueryTimeoutSeconds()));
                try (ResultSet rs = stmt.executeQuery(
                        "SELECT TOP 1 ResourceID FROM v_GS_INSTALLED_SOFTWARE WHERE DisplayName0 IS NOT NULL")) {
                    softwareOk = true;
                }
            }
        } catch (Exception e) {
            LOG.warn("SCCM connection test failed: {}", e.getMessage());
        }
        return new boolean[]{systemOk, softwareOk};
    }

    /** Rows from a fixed query, and whether the row cap cut the result short. */
    public record QueryRows(List<Map<String, String>> rows, boolean truncated) {}

    /**
     * Runs one of the caller's fixed SQL statements (never tenant input) through the same
     * policy-checked connection as inventory sync, stopping at {@code maxRows}.
     */
    public QueryRows queryRows(SccmCmdbConfig config, String sql, int maxRows) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        boolean truncated = false;
        try (Connection conn = openConnection(config);
             Statement stmt = conn.createStatement()) {
            stmt.setFetchSize(config.getFetchSize() == null ? 500 : Math.max(1, config.getFetchSize()));
            stmt.setQueryTimeout(config.getQueryTimeoutSeconds() == null ? 120 : Math.max(1, config.getQueryTimeoutSeconds()));
            stmt.setMaxRows(maxRows + 1);
            try (ResultSet rs = stmt.executeQuery(sql)) {
                ResultSetMetaData meta = rs.getMetaData();
                int colCount = meta.getColumnCount();
                while (rs.next()) {
                    if (rows.size() >= maxRows) {
                        truncated = true;
                        break;
                    }
                    Map<String, String> row = new LinkedHashMap<>();
                    for (int i = 1; i <= colCount; i++) {
                        String value = rs.getString(i);
                        if (value != null) {
                            row.put(meta.getColumnLabel(i).toLowerCase(Locale.ROOT), value.trim());
                        }
                    }
                    rows.add(row);
                }
            }
        }
        return new QueryRows(rows, truncated);
    }

    // ── Private helpers ────────────────────────────────────────────────────────────────────────

    private List<Map<String, String>> executeQuery(SccmCmdbConfig config, String sql) throws Exception {
        List<Map<String, String>> rows = new ArrayList<>();
        try (Connection conn = openConnection(config);
             Statement stmt = conn.createStatement()) {
            stmt.setFetchSize(config.getFetchSize() == null ? 500 : Math.max(1, config.getFetchSize()));
            stmt.setQueryTimeout(config.getQueryTimeoutSeconds() == null ? 120 : Math.max(1, config.getQueryTimeoutSeconds()));
            try (ResultSet rs = stmt.executeQuery(sql)) {
                ResultSetMetaData meta = rs.getMetaData();
                int colCount = meta.getColumnCount();
                while (rs.next()) {
                    Map<String, String> row = new LinkedHashMap<>();
                    for (int i = 1; i <= colCount; i++) {
                        String colName = meta.getColumnLabel(i).toLowerCase(Locale.ROOT);
                        String value = rs.getString(i);
                        if (value != null) {
                            row.put(colName, value.trim());
                        }
                    }
                    rows.add(row);
                }
            }
        }
        LOG.info("SCCM query returned {} rows", rows.size());
        return rows;
    }

    private Connection openConnection(SccmCmdbConfig config) throws Exception {
        // Re-checked on every connection: the allowlist, or what the host resolves to, may have
        // changed since the configuration was saved.
        SccmJdbcPolicy.ValidatedUrl target = jdbcPolicy.validate(config.getJdbcUrl());
        jdbcPolicy.assertSafeTarget(target.host());
        if (config.getAuthType() == SccmAuthType.WINDOWS_AUTH) {
            // Integrated authentication would present the backend host's own identity to a
            // tenant-chosen server, so one tenant could act with credentials that are not theirs.
            throw new IllegalStateException(
                    "Windows integrated authentication is not supported; use SQL Server authentication");
        }
        String username = config.getUsername();
        String password = credentialEncryptionService.decrypt(config.getCredentialSecret());
        if (username == null || username.isBlank()) {
            throw new IllegalStateException("SCCM username is required for SQL_AUTH");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("SCCM password/secret is required for SQL_AUTH");
        }
        Properties props = new Properties();
        props.setProperty("user", username.trim());
        props.setProperty("password", password);
        // Bound the connect phase; an unreachable host must not hold a worker for the driver default.
        props.setProperty("loginTimeout", "15");
        return DriverManager.getConnection(target.url(), props);
    }

    private String blankToEmpty(String value) {
        return value == null ? "" : value.trim();
    }

    private String safeJdbcUrl(String url) {
        if (url == null || url.isBlank()) {
            return "(not configured)";
        }
        // Strip any embedded password from the URL for logging
        return url.replaceAll("(?i)(password|pwd)=[^;]+", "$1=***");
    }
}
