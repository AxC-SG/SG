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
 * <p>In MOCK mode no real SQL Server connection is attempted; realistic fixture rows are returned
 * instead, allowing the rest of the ingestion pipeline to be exercised without infrastructure.
 *
 * <p>In LIVE mode a JDBC connection is opened directly via {@link DriverManager} (not a Spring
 * DataSource) because connection details are stored per-tenant in the database, not in
 * application.yml.
 */
@Service
public class SccmQueryService {

    private static final Logger LOG = LoggerFactory.getLogger(SccmQueryService.class);
    private final CredentialEncryptionService credentialEncryptionService;

    public SccmQueryService(CredentialEncryptionService credentialEncryptionService) {
        this.credentialEncryptionService = credentialEncryptionService;
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
     * Fetches install rows for the given config.  Returns mock data when {@code mockMode} is true.
     *
     * <p>Each row map contains the keys expected by {@code CmdbInventoryIngestionRunner}:
     * {@code computer_name}, {@code sys_id}, {@code display_name}, {@code publisher},
     * {@code version}, {@code install_date}, {@code version_evidence}.
     */
    public List<Map<String, String>> fetchInstallRows(SccmCmdbConfig config) throws Exception {
        SccmPilotPolicy.requireEnabled();
        LOG.info("SCCM live mode: executing install query against {}", safeJdbcUrl(config.getJdbcUrl()));
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
        SccmPilotPolicy.requireEnabled();
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
        SccmPilotPolicy.requireEnabled();
        String url = config.getJdbcUrl();
        if (url == null || url.isBlank()) {
            throw new IllegalStateException("SCCM JDBC URL is not configured");
        }
        Properties props = new Properties();
        if (config.getAuthType() == SccmAuthType.WINDOWS_AUTH) {
            props.setProperty("integratedSecurity", "true");
            props.setProperty("authenticationScheme", "NativeAuthentication");
        } else {
            String username = config.getUsername();
            String password = credentialEncryptionService.decrypt(config.getCredentialSecret());
            if (username == null || username.isBlank()) {
                throw new IllegalStateException("SCCM username is required for SQL_AUTH");
            }
            if (password == null || password.isBlank()) {
                throw new IllegalStateException("SCCM password/secret is required for SQL_AUTH");
            }
            props.setProperty("user", username.trim());
            props.setProperty("password", password);
        }
        return DriverManager.getConnection(url.trim(), props);
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
