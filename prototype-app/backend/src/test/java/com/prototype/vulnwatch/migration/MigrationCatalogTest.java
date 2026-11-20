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

        assertEquals(27, targets.platformTarget());
        assertEquals(75, targets.tenantTarget());
    }

    // The configured range is intersected with the binary's own, so a stale configured bound
    // leaves no supported version and every tenant-scoped job refuses to run (lab, 2026-11-15:
    // "supported range V23..V20" after the V21-V23 migrations). Move these with the tenant head.
    @Test
    void configuredTenantSchemaRangeMatchesTheBinary() throws IOException {
        int target = PackagedMigrationCatalog.resolve().tenantTarget();
        assertEquals(target, com.prototype.vulnwatch.service.TenantSchemaCompatibility.REQUIRED_MINIMUM);
        assertEquals(target, com.prototype.vulnwatch.service.TenantSchemaCompatibility.SUPPORTED_MAXIMUM);

        String base = Files.readString(Path.of("src/main/resources/application.yml"));
        assertEquals(List.of(String.valueOf(target)), configured(base, "minimum-compatible-schema-version: \\$\\{APP_MINIMUM_TENANT_SCHEMA_VERSION:(\\d+)}"));
        assertEquals(List.of(String.valueOf(target)), configured(base, "maximum-compatible-schema-version: \\$\\{APP_MAXIMUM_TENANT_SCHEMA_VERSION:(\\d+)}"));

        String prod = Files.readString(Path.of("src/main/resources/application-prod.yml"));
        for (String bound : configured(prod, "(?:minimum|maximum)-compatible-schema-version: (\\d+)")) {
            assertEquals(String.valueOf(target), bound, "application-prod.yml tenant schema bound");
        }
    }

    private static List<String> configured(String yaml, String regex) {
        List<String> values = new ArrayList<>();
        Matcher matcher = Pattern.compile(regex).matcher(yaml);
        while (matcher.find()) {
            values.add(matcher.group(1));
        }
        return values;
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
            assertEquals(List.of("V10__cbom_rule_rollout_leases.sql", "V11__managed_browser_sessions.sql", "V12__managed_invitation_attempts.sql", "V13__managed_operator_enrollment.sql", "V14__standard_enrollment_policy.sql", "V15__connector_schedule_progress.sql", "V16__tenant_data_keys_and_ownership_authority.sql", "V17__tenant_catalog_build_queue.sql", "V18__feed_coverage_observations.sql", "V19__observation_cvss_version.sql", "V1__platform_schema.sql", "V20__nvd_observed_interval_ids.sql", "V21__nvd_interval_manifest_marker.sql", "V22__candidate_canonical_pagination_index.sql", "V23__publication_progress.sql", "V24__intelligence_import_profiles.sql", "V25__isolated_catalog_versions.sql", "V26__intelligence_import_profile_schedules.sql", "V27__projection_candidate_builder.sql", "V2__invitation_token_hashes.sql", "V3__durable_work_and_delivery.sql", "V4__feed_continuity_watermarks.sql", "V5__scheduled_sync_occurrences.sql", "V6__rollout_assessment_waiting.sql", "V7__reserved_internal_tenant_and_setup_delivery.sql", "V8__reviewed_intelligence_publication.sql", "V9__bom_ingest_api_keys.sql"), platform
                    .filter(path -> path.toString().endsWith(".sql"))
                    .map(path -> path.getFileName().toString()).sorted().toList());
            assertEquals(List.of("V10__crypto_finding_kind.sql", "V11__finding_suppression_requests.sql", "V12__cbom_assessment_foundation.sql", "V13__canonical_finding_verification.sql", "V14__cbom_relationships.sql", "V15__cbom_rule_package_lifecycle.sql", "V16__cbom_visibility_and_reports.sql", "V17__crypto_remediation_operations.sql", "V18__cbom_contradiction_review.sql", "V19__cbom_ci_gates.sql", "V1__tenant_schema.sql", "V20__durable_bom_uploads.sql", "V21__identity_and_teams.sql", "V22__ownership_core.sql", "V23__ownership_projection_columns.sql", "V24__ownership_release_2_schema.sql", "V25__cloud_tags_text.sql", "V26__campaign_ledger.sql", "V27__campaign_software_scope.sql", "V28__tenant_intelligence_catalog_policy_versions.sql", "V29__catalog_override_history.sql", "V2__ai_bom_correlation_evidence.sql", "V30__catalog_shadow_builds.sql", "V3__credential_and_invitation_boundaries.sql", "V4__owned_durable_work.sql", "V5__bounded_retention_progress.sql", "V6__intelligence_revision_and_finding_eligibility.sql", "V72__repair_skipped_tenant_contracts.sql", "V73__repair_ai_security_digest_contract.sql", "V74__repair_ai_security_digest_constraints.sql", "V75__repair_agent_deployment_settings.sql", "V7__ticketing_framework.sql", "V8__gcp_cloud_discovery.sql", "V9__fix_intelligence_and_patch_management.sql"), tenant
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
