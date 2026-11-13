package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class MigrationCatalogTest {

    private static final Path MIGRATION_DIR = Path.of("src/main/resources/db/migration/postgres_reset");
    private static final Path TENANT_MIGRATION_DIR = Path.of("src/main/resources/db/migration/tenant");
    private static final Pattern VERSION_PATTERN = Pattern.compile("^V(\\d+)__.+\\.sql$");

    @Test
    void packagedCatalogResolvesPlatformAndTenantTargetsIndependently() {
        PackagedMigrationCatalog.Targets targets = PackagedMigrationCatalog.resolve();

        assertEquals(16, targets.platformTarget());
        assertEquals(23, targets.tenantTarget());
    }

    @Test
    void migrationsHaveUniqueVersionsMeaningfulSqlAndNoUnexpectedDuplicateBodies() throws IOException {
        List<MigrationFile> migrations = Files.list(MIGRATION_DIR)
                .filter(path -> path.getFileName().toString().endsWith(".sql"))
                .map(MigrationCatalogTest::toMigrationFile)
                .sorted(Comparator.comparing(MigrationFile::version))
                .toList();

        Map<String, List<String>> filesByVersion = new LinkedHashMap<>();
        Map<String, List<String>> filesByNormalizedSql = new LinkedHashMap<>();
        List<String> unexpectedCommentOnly = new ArrayList<>();

        for (MigrationFile migration : migrations) {
            filesByVersion.computeIfAbsent(migration.version(), ignored -> new ArrayList<>())
                    .add(migration.fileName());

            if (migration.normalizedSql().isBlank()) {
                unexpectedCommentOnly.add(migration.fileName());
                continue;
            }

            filesByNormalizedSql.computeIfAbsent(migration.normalizedSql(), ignored -> new ArrayList<>())
                    .add(migration.version());
        }

        List<String> duplicateVersions = filesByVersion.entrySet().stream()
                .filter(entry -> entry.getValue().size() > 1)
                .map(entry -> entry.getKey() + " -> " + entry.getValue())
                .toList();
        assertTrue(duplicateVersions.isEmpty(), "Duplicate Flyway versions found: " + duplicateVersions);

        assertTrue(
                unexpectedCommentOnly.isEmpty(),
                "Comment-only or whitespace-only migrations found: " + unexpectedCommentOnly
        );

        List<String> unexpectedDuplicateBodies = new ArrayList<>();
        for (List<String> versions : filesByNormalizedSql.values()) {
            if (versions.size() <= 1) {
                continue;
            }
            Set<String> duplicateSet = Set.copyOf(versions);
            unexpectedDuplicateBodies.add(duplicateSet.toString());
        }

        assertTrue(
                unexpectedDuplicateBodies.isEmpty(),
                "Unexpected duplicate migration bodies found: " + unexpectedDuplicateBodies
        );
        assertTrue(!migrations.isEmpty(), "Expected at least one migration in the reset catalog.");
        assertCatalogIsValid(TENANT_MIGRATION_DIR);
    }

    @Test
    void developmentCatalogsPreserveV1AndIncludeForwardTenantMigrations() throws IOException {
        try (var platform = Files.list(MIGRATION_DIR); var tenant = Files.list(TENANT_MIGRATION_DIR)) {
            assertEquals(List.of("V10__cbom_rule_rollout_leases.sql", "V11__managed_browser_sessions.sql", "V12__managed_invitation_attempts.sql", "V13__managed_operator_enrollment.sql", "V14__standard_enrollment_policy.sql", "V15__connector_schedule_progress.sql", "V16__tenant_data_keys_and_ownership_authority.sql", "V1__platform_schema.sql", "V2__invitation_token_hashes.sql", "V3__durable_work_and_delivery.sql", "V4__feed_continuity_watermarks.sql", "V5__scheduled_sync_occurrences.sql", "V6__rollout_assessment_waiting.sql", "V7__reserved_internal_tenant_and_setup_delivery.sql", "V8__reviewed_intelligence_publication.sql", "V9__bom_ingest_api_keys.sql"), platform
                    .filter(path -> path.toString().endsWith(".sql"))
                    .map(path -> path.getFileName().toString()).sorted().toList());
            assertEquals(List.of("V10__crypto_finding_kind.sql", "V11__finding_suppression_requests.sql", "V12__cbom_assessment_foundation.sql", "V13__canonical_finding_verification.sql", "V14__cbom_relationships.sql", "V15__cbom_rule_package_lifecycle.sql", "V16__cbom_visibility_and_reports.sql", "V17__crypto_remediation_operations.sql", "V18__cbom_contradiction_review.sql", "V19__cbom_ci_gates.sql", "V1__tenant_schema.sql", "V20__durable_bom_uploads.sql", "V21__identity_and_teams.sql", "V22__ownership_core.sql", "V23__ownership_projection_columns.sql", "V2__ai_bom_correlation_evidence.sql", "V3__credential_and_invitation_boundaries.sql", "V4__owned_durable_work.sql", "V5__bounded_retention_progress.sql", "V6__intelligence_revision_and_finding_eligibility.sql", "V7__ticketing_framework.sql", "V8__gcp_cloud_discovery.sql", "V9__fix_intelligence_and_patch_management.sql"), tenant
                    .filter(path -> path.toString().endsWith(".sql"))
                    .map(path -> path.getFileName().toString()).sorted().toList());
        }
        String tenant = Files.readString(TENANT_MIGRATION_DIR.resolve("V1__tenant_schema.sql"));
        assertTrue(tenant.contains("${tenantSchema}"));
        assertTrue(tenant.contains("${tenantId}"));
        assertTrue(!tenant.contains("tenant_default"));
        assertTrue(!tenant.contains("e5fe0d29-1d64-4175-8ce6-c34f42b214cc"));
    }

    private static void assertCatalogIsValid(Path directory) throws IOException {
        List<MigrationFile> migrations = Files.list(directory)
                .filter(path -> path.getFileName().toString().endsWith(".sql"))
                .map(MigrationCatalogTest::toMigrationFile)
                .toList();
        assertTrue(!migrations.isEmpty(), "Expected at least one tenant migration.");
        assertTrue(migrations.stream().map(MigrationFile::version).distinct().count() == migrations.size(),
                "Duplicate tenant migration versions found.");
        assertTrue(migrations.stream().allMatch(migration -> !migration.normalizedSql().isBlank()),
                "Tenant migrations must contain substantive SQL.");
    }

    private static MigrationFile toMigrationFile(Path path) {
        String fileName = path.getFileName().toString();
        Matcher matcher = VERSION_PATTERN.matcher(fileName);
        if (!matcher.matches()) {
            fail("Unexpected migration filename: " + fileName);
        }
        try {
            String sql = Files.readString(path, StandardCharsets.UTF_8);
            return new MigrationFile(matcher.group(1), fileName, normalizeSql(sql));
        } catch (IOException exception) {
            throw new IllegalStateException("Failed to read migration " + fileName, exception);
        }
    }

    private static String normalizeSql(String sql) {
        String withoutBlockComments = sql.replaceAll("(?s)/\\*.*?\\*/", " ");
        String withoutLineComments = withoutBlockComments.replaceAll("(?m)--.*$", " ");
        return withoutLineComments
                .replaceAll("\\s+", " ")
                .trim();
    }

    private record MigrationFile(String version, String fileName, String normalizedSql) {
    }
}
