package com.prototype.vulnwatch.tools;

import com.prototype.vulnwatch.migration.ProviderCredentialMigrator;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import java.net.URI;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Standalone offline maintenance entry point; never initializes the application or schedulers. */
public final class ProviderCredentialMigrationTool {
    private static final Logger LOG = LoggerFactory.getLogger(ProviderCredentialMigrationTool.class);
    private ProviderCredentialMigrationTool() { }

    public static void main(String[] args) {
        boolean apply = Arrays.asList(args).contains("--apply");
        if (args.length > 1 || (args.length == 1 && !apply && !"--dry-run".equals(args[0]))) {
            throw new IllegalArgumentException("Use --dry-run (default) or --apply");
        }
        try {
            String url = required("DB_URL");
            String expected = required("EXPECTED_DB_NAME");
            URI parsed = URI.create(url.startsWith("jdbc:") ? url.substring(5) : "");
            if (!"postgresql".equals(parsed.getScheme()) || parsed.getUserInfo() != null
                    || parsed.getQuery() != null || !('/' + expected).equals(parsed.getPath())) {
                throw new IllegalArgumentException("Invalid migration database configuration");
            }
            CredentialEncryptionService encryption = new CredentialEncryptionService(
                    required("APP_CREDENTIAL_ENCRYPTION_KEY"),
                    System.getenv().getOrDefault("APP_CREDENTIAL_ENCRYPTION_KEY_ID", "primary"),
                    System.getenv().getOrDefault("APP_CREDENTIAL_ENCRYPTION_PREVIOUS_KEYS", ""));
            try (Connection connection = DriverManager.getConnection(url, required("DB_USERNAME"), required("DB_PASSWORD"))) {
                try (var statement = connection.createStatement(); var result = statement.executeQuery(
                        "select current_database(), rolsuper or rolbypassrls from pg_roles where rolname=current_user")) {
                    if (!result.next() || !expected.equals(result.getString(1)) || !result.getBoolean(2)) {
                        throw new IllegalStateException("Use a separately authorized migration role with RLS bypass");
                    }
                }
                ProviderCredentialMigrator.Summary result = new ProviderCredentialMigrator(encryption).migrate(connection, apply);
                LOG.info("Provider credential migration completed: applied={}, inspected={}, changed={}",
                        result.applied(), result.inspected(), result.changed());
            }
        } catch (SQLException | RuntimeException failure) {
            // Never print driver diagnostics, JDBC credentials, stored values or encryption keys.
            throw new IllegalStateException("Provider credential migration failed; verify configuration and retained key versions");
        }
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing migration configuration");
        return value;
    }
}
