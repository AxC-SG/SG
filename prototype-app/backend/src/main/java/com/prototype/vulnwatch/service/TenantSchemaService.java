package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaService {

    private final JdbcTemplate platformJdbcTemplate;
    private final String defaultSchemaName;

    @Value("${app.tenancy.enforce-schema-version:false}")
    private boolean enforceSchemaVersion;

    @Value("${app.tenancy.minimum-compatible-schema-version:20}")
    private int minimumCompatibleSchemaVersion = TenantSchemaCompatibility.REQUIRED_MINIMUM;

    @Value("${app.tenancy.maximum-compatible-schema-version:20}")
    private int maximumCompatibleSchemaVersion = TenantSchemaCompatibility.SUPPORTED_MAXIMUM;

    public TenantSchemaService(
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate,
            @Value("${app.tenancy.default-schema:tenant_default}") String defaultSchemaName
    ) {
        this.platformJdbcTemplate = platformJdbcTemplate;
        this.defaultSchemaName = defaultSchemaName;
    }

    public String defaultSchemaName() {
        return defaultSchemaName;
    }

    public String normalizeSchemaName(String schemaName) {
        return sanitizeSchemaName(schemaName);
    }

    public String schemaNameForTenant(Tenant tenant) {
        if (tenant == null || tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()) {
            return defaultSchemaName;
        }
        return sanitizeSchemaName(tenant.getSchemaName());
    }

    public String deriveSchemaName(String slug) {
        String base = slug == null || slug.isBlank() ? defaultSchemaName : "tenant_" + slug.trim().toLowerCase();
        return sanitizeSchemaName(base);
    }

    public void ensureSchemaExists(String schemaName) {
        assertSchemaReady(schemaName);
    }

    public boolean schemaExists(String schemaName) {
        Boolean exists = platformJdbcTemplate.queryForObject(
                "select exists (select 1 from pg_namespace where nspname = ?)",
                Boolean.class,
                sanitizeSchemaName(schemaName));
        return Boolean.TRUE.equals(exists);
    }

    /**
     * Schema DDL is allowed only for the schema owner or a superuser. The
     * permanent production web service uses neither and must leave cleanup to
     * the controlled migration owner.
     */
    public boolean canDropTenantSchema(String schemaName) {
        Boolean allowed = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from pg_namespace n
                    join pg_roles r on r.oid = n.nspowner
                    where n.nspname = ?
                      and (
                          current_setting('is_superuser') = 'on'
                          or r.rolname = current_user
                      )
                )
                """, Boolean.class, sanitizeSchemaName(schemaName));
        return Boolean.TRUE.equals(allowed);
    }

    /** Verifies availability only. Ordinary request paths must never perform tenant DDL. */
    public void assertSchemaReady(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (!schemaExists(normalized)) {
            throw new IllegalStateException("Tenant schema is not provisioned: " + normalized);
        }
        if (!enforceSchemaVersion) {
            return;
        }
        List<SchemaProjection> projections = platformJdbcTemplate.query("""
                select current_version, status
                from platform.tenant_schema_versions
                where schema_name = ?
                """, (rs, rowNum) -> new SchemaProjection(rs.getInt("current_version"), rs.getString("status")),
                normalized);
        if (projections.isEmpty()) {
            throw new IllegalStateException("Tenant schema has no readiness projection: " + normalized);
        }
        if (projections.size() > 1) {
            throw new IllegalStateException("Tenant schema has duplicate readiness projections: " + normalized);
        }
        SchemaProjection projection = projections.get(0);
        if (!"CURRENT".equals(projection.status())) {
            throw new IllegalStateException("Tenant schema is not CURRENT: " + normalized
                    + " (status=" + projection.status() + ")");
        }
        if (!TenantSchemaCompatibility.supports(projection.currentVersion(),minimumCompatibleSchemaVersion,maximumCompatibleSchemaVersion)) {
            throw new IllegalStateException("Tenant schema is outside this release's supported range V"
                    + Math.max(TenantSchemaCompatibility.REQUIRED_MINIMUM,minimumCompatibleSchemaVersion)+"..V"
                    + Math.min(TenantSchemaCompatibility.SUPPORTED_MAXIMUM,maximumCompatibleSchemaVersion)+": "+normalized
                    + " (current=V"+projection.currentVersion()+")");
        }
    }

    /**
     * Repairs additive drift only. Incompatible type/nullability/default changes are
     * detected by the control plane fingerprint and require an operator decision.
     */
    public void reconcileSafeDifferences(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized)) {
            return;
        }
        platformJdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            try (var statement = connection.createStatement()) {
                for (String tableName : tenantTableNames(defaultSchemaName)) {
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS %s.%s
                            (LIKE %s.%s INCLUDING CONSTRAINTS INCLUDING GENERATED INCLUDING IDENTITY INCLUDING STORAGE INCLUDING COMMENTS)
                            """.formatted(
                            quotedIdentifier(normalized), quotedIdentifier(tableName),
                            quotedIdentifier(defaultSchemaName), quotedIdentifier(tableName)));
                }
                for (SequenceDefinition sequence : tenantSequenceDefinitions(defaultSchemaName)) {
                    statement.execute(createSequenceSql(normalized, sequence));
                }
            }
            return null;
        });
        List<MissingColumnDefinition> missingColumns = platformJdbcTemplate.query("""
                select source.table_name,
                       source.column_name,
                       source.data_type,
                       source.column_default,
                       source.is_nullable
                from (
                    select c.table_name,
                           c.column_name,
                           format_type(a.atttypid, a.atttypmod) as data_type,
                           c.column_default,
                           c.is_nullable
                    from information_schema.columns c
                    join pg_namespace n on n.nspname = c.table_schema
                    join pg_class cl on cl.relnamespace = n.oid and cl.relname = c.table_name
                    join pg_attribute a on a.attrelid = cl.oid and a.attname = c.column_name
                    where c.table_schema = ? and a.attnum > 0 and not a.attisdropped
                ) source
                left join information_schema.columns target
                  on target.table_schema = ?
                 and target.table_name = source.table_name
                 and target.column_name = source.column_name
                where target.column_name is null
                  and source.table_name not in ('tenant_schema_history', 'flyway_schema_history')
                order by source.table_name, source.column_name
                """, (rs, rowNum) -> new MissingColumnDefinition(
                rs.getString("table_name"),
                rs.getString("column_name"),
                rs.getString("data_type"),
                rs.getString("column_default"),
                "YES".equalsIgnoreCase(rs.getString("is_nullable"))
        ), defaultSchemaName, normalized);
        for (MissingColumnDefinition column : missingColumns) {
            String defaultClause = column.defaultExpression() == null ? ""
                    : " DEFAULT " + rewrittenDefaultExpression(normalized, column.defaultExpression());
            String nullClause = column.nullable() ? "" : " NOT NULL";
            platformJdbcTemplate.execute("ALTER TABLE " + quotedIdentifier(normalized) + "."
                    + quotedIdentifier(column.tableName()) + " ADD COLUMN IF NOT EXISTS "
                    + quotedIdentifier(column.columnName()) + " " + column.dataType()
                    + defaultClause + nullClause);
        }
        provisionTenantSchema(normalized);
    }

    public void resetTenantSchema(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            return;
        }
        dropTenantSchema(normalized);
        provisionSchemaFromTemplate(normalized);
    }

    public void provisionSchemaFromTemplate(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (schemaExists(normalized)) {
            throw new IllegalStateException("Tenant schema already exists: " + normalized);
        }
        provisionOrReconcileSchemaFromTemplate(normalized);
    }

    /** Creates an empty tenant schema so the tenant Flyway V1 is authoritative. */
    public void provisionEmptySchema(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            throw new IllegalArgumentException("Refusing to provision protected schema: " + normalized);
        }
        if (!schemaExists(normalized)) {
            platformJdbcTemplate.execute("CREATE SCHEMA " + quotedIdentifier(normalized));
        }
    }

    public void provisionOrReconcileSchemaFromTemplate(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            throw new IllegalArgumentException("Refusing to provision protected schema: " + normalized);
        }
        platformJdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            assertPrivilegedProvisioningRole();
            try (var lock = connection.prepareStatement("select pg_advisory_lock(hashtext(?))")) {
                lock.setString(1, "tenant-provision:" + normalized);
                lock.execute();
            }
            try {
                if (!schemaExists(normalized)) {
                    platformJdbcTemplate.execute("CREATE SCHEMA " + quotedIdentifier(normalized));
                }
                reconcileSafeDifferences(normalized);
            } finally {
                try (var unlock = connection.prepareStatement("select pg_advisory_unlock(hashtext(?))")) {
                    unlock.setString(1, "tenant-provision:" + normalized);
                    unlock.execute();
                }
            }
            return null;
        });
    }

    private void assertPrivilegedProvisioningRole() {
        Boolean ownsTemplateOrIsSuperuser = platformJdbcTemplate.queryForObject("""
                select current_setting('is_superuser') = 'on'
                    or exists (
                        select 1
                        from pg_namespace n
                        join pg_roles r on r.oid = n.nspowner
                        where n.nspname = ?
                          and r.rolname = current_user
                    )
                """, Boolean.class, defaultSchemaName);
        if (!Boolean.TRUE.equals(ownsTemplateOrIsSuperuser)) {
            throw new IllegalStateException(
                    "Tenant schema provisioning requires the migration owner role; runtime roles may not execute DDL");
        }
    }

    public void dropTenantSchema(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            return;
        }
        platformJdbcTemplate.execute("DROP SCHEMA IF EXISTS " + quotedIdentifier(normalized) + " CASCADE");
    }

    private String sanitizeSchemaName(String schemaName) {
        String normalized = schemaName == null || schemaName.isBlank() ? defaultSchemaName : schemaName.trim().toLowerCase();
        normalized = normalized.replaceAll("[^a-z0-9_]+", "_");
        normalized = normalized.replaceAll("^[^a-z]+", "tenant_");
        return normalized;
    }

    private void provisionTenantSchema(String targetSchema) {
        if (defaultSchemaName.equals(targetSchema) || "platform".equals(targetSchema)) {
            return;
        }

        List<String> sourceTables = tenantTableNames(defaultSchemaName);
        if (sourceTables.isEmpty()) {
            return;
        }

        List<SequenceDefinition> sourceSequences = tenantSequenceDefinitions(defaultSchemaName);
        List<ColumnDefaultDefinition> sourceDefaults = columnDefaults(defaultSchemaName);
        List<ForeignKeyDefinition> sourceForeignKeys = foreignKeys(defaultSchemaName);
        List<TableConstraintDefinition> sourceTableConstraints = tableConstraints(defaultSchemaName);
        List<IndexDefinition> sourceIndexes = standaloneIndexes(defaultSchemaName);
        Set<String> targetForeignKeyNames = foreignKeys(targetSchema).stream()
                .map(ForeignKeyDefinition::constraintName)
                .collect(Collectors.toSet());
        Set<String> targetConstraintDefinitions = tableConstraints(targetSchema).stream()
                .map(constraint -> constraint.tableName() + "|" + constraint.definition())
                .collect(Collectors.toSet());
        Set<String> targetIndexNames = standaloneIndexes(targetSchema).stream()
                .map(IndexDefinition::indexName)
                .collect(Collectors.toSet());
        List<String> rlsTables = rlsProtectedTenantTableNames(defaultSchemaName);
        Map<String, PolicyDefinition> expectedPolicies = expectedTenantIsolationPolicies(targetSchema, rlsTables);
        Map<String, PolicyDefinition> targetPolicies = tenantIsolationPolicies(targetSchema);

        platformJdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            String originalSearchPath;
            try (var currentSearchPath = connection.createStatement();
                 var result = currentSearchPath.executeQuery("SHOW search_path")) {
                result.next();
                originalSearchPath = result.getString(1);
            }
            try (var searchPath = connection.prepareStatement("SELECT set_config('search_path', ?, FALSE)")) {
                searchPath.setString(1, targetSchema + ",platform");
                searchPath.execute();
            }

            try (var statement = connection.createStatement()) {
                for (String tableName : sourceTables) {
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS %s.%s
                            (LIKE %s.%s INCLUDING CONSTRAINTS INCLUDING GENERATED INCLUDING IDENTITY INCLUDING STORAGE INCLUDING COMMENTS)
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(tableName),
                            quotedIdentifier(defaultSchemaName),
                            quotedIdentifier(tableName)
                    ));
                }

                for (SequenceDefinition sequence : sourceSequences) {
                    statement.execute(createSequenceSql(targetSchema, sequence));
                }

                for (ColumnDefaultDefinition defaultDefinition : sourceDefaults) {
                    statement.execute("""
                            ALTER TABLE %s.%s
                            ALTER COLUMN %s SET DEFAULT %s
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(defaultDefinition.tableName()),
                            quotedIdentifier(defaultDefinition.columnName()),
                            rewrittenDefaultExpression(targetSchema, defaultDefinition.defaultExpression())
                    ));
                }

                for (TableConstraintDefinition constraint : sourceTableConstraints) {
                    if (targetConstraintDefinitions.contains(constraint.tableName() + "|" + constraint.definition())) {
                        continue;
                    }
                    statement.execute("ALTER TABLE " + quotedIdentifier(targetSchema) + "."
                            + quotedIdentifier(constraint.tableName()) + " ADD CONSTRAINT "
                            + quotedIdentifier(constraint.constraintName()) + " " + constraint.definition());
                }

                for (ForeignKeyDefinition foreignKey : sourceForeignKeys) {
                    if (targetForeignKeyNames.contains(foreignKey.constraintName())) {
                        continue;
                    }
                    statement.execute("""
                            ALTER TABLE %s.%s
                            ADD CONSTRAINT %s %s
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(foreignKey.tableName()),
                            quotedIdentifier(foreignKey.constraintName()),
                            rewriteForeignKeyDefinition(targetSchema, foreignKey.definition())
                    ));
                }

                for (IndexDefinition index : sourceIndexes) {
                    if (targetIndexNames.contains(index.indexName())) {
                        continue;
                    }
                    statement.execute(rewriteIndexDefinition(targetSchema, index.definition()));
                }

                for (String tableName : rlsTables) {
                    statement.execute("""
                            ALTER TABLE %s.%s ENABLE ROW LEVEL SECURITY
                            """.formatted(quotedIdentifier(targetSchema), quotedIdentifier(tableName)));
                    statement.execute("""
                            ALTER TABLE %s.%s FORCE ROW LEVEL SECURITY
                            """.formatted(quotedIdentifier(targetSchema), quotedIdentifier(tableName)));
                    PolicyDefinition expected = expectedPolicies.get(tableName);
                    // A policy that already matches the template is left alone: dropping and recreating it
                    // would briefly leave the table without its tenant-pinned predicate.
                    if (expected.equals(targetPolicies.get(tableName))) {
                        continue;
                    }
                    statement.execute("""
                            DROP POLICY IF EXISTS tenant_isolation ON %s.%s
                            """.formatted(quotedIdentifier(targetSchema), quotedIdentifier(tableName)));
                    statement.execute(expected.createStatement(quotedIdentifier(targetSchema), quotedIdentifier(tableName)));
                }
            } finally {
                try (var restoreSearchPath = connection.prepareStatement("SELECT set_config('search_path', ?, FALSE)")) {
                    restoreSearchPath.setString(1, originalSearchPath);
                    restoreSearchPath.execute();
                }
            }
            return null;
        });
    }

    /**
     * The template's tenant_isolation policies, re-pinned to the target tenant. Tenant V1 pins most
     * policies to its own tenant id as well as the session tenant; copying that pin keeps a schema from
     * accepting another tenant's rows. Fails closed when a pin cannot be mapped to the target tenant.
     */
    private Map<String, PolicyDefinition> expectedTenantIsolationPolicies(String targetSchema, List<String> rlsTables) {
        Map<String, PolicyDefinition> templatePolicies = tenantIsolationPolicies(defaultSchemaName);
        UUID templateTenantId = registeredTenantId(defaultSchemaName);
        UUID targetTenantId = registeredTenantId(targetSchema);
        Map<String, PolicyDefinition> expected = new HashMap<>();
        for (String tableName : rlsTables) {
            PolicyDefinition template = templatePolicies.get(tableName);
            expected.put(tableName, template == null
                    ? PolicyDefinition.UNPINNED
                    : template.repinned(defaultSchemaName, templateTenantId, targetSchema, targetTenantId, tableName));
        }
        return expected;
    }

    private Map<String, PolicyDefinition> tenantIsolationPolicies(String schemaName) {
        Map<String, PolicyDefinition> policies = new HashMap<>();
        platformJdbcTemplate.query("""
                SELECT tablename, permissive, cmd, array_to_string(roles, ',') AS roles, qual, with_check
                FROM pg_policies
                WHERE schemaname = ? AND policyname = 'tenant_isolation'
                """, (RowCallbackHandler) row -> policies.put(row.getString("tablename"), new PolicyDefinition(
                row.getString("permissive"), row.getString("cmd"), row.getString("roles"),
                row.getString("qual"), row.getString("with_check"))), schemaName);
        return policies;
    }

    private UUID registeredTenantId(String schemaName) {
        List<UUID> ids = platformJdbcTemplate.queryForList(
                "SELECT id FROM platform.tenants WHERE schema_name = ?", UUID.class, schemaName);
        return ids.size() == 1 ? ids.get(0) : null;
    }

    private List<String> rlsProtectedTenantTableNames(String schemaName) {
        return platformJdbcTemplate.queryForList("""
                SELECT c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = ?
                  AND c.relkind IN ('r', 'p')
                  AND c.relrowsecurity
                ORDER BY c.relname
                """, String.class, schemaName);
    }

    private List<String> tenantTableNames(String schemaName) {
        return platformJdbcTemplate.queryForList("""
                SELECT tablename
                FROM pg_tables
                WHERE schemaname = ?
                  AND tablename NOT IN ('flyway_schema_history', 'tenant_schema_history', 'sync_runs')
                ORDER BY tablename
                """, String.class, schemaName);
    }

    private List<SequenceDefinition> tenantSequenceDefinitions(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT sequence_name,
                       data_type,
                       start_value,
                       minimum_value,
                       maximum_value,
                       increment,
                       cycle_option
                FROM information_schema.sequences
                WHERE sequence_schema = ?
                ORDER BY sequence_name
                """, sequenceDefinitionMapper(), schemaName);
    }

    private List<ColumnDefaultDefinition> columnDefaults(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT table_name,
                       column_name,
                       column_default
                FROM information_schema.columns
                WHERE table_schema = ?
                  AND column_default IS NOT NULL
                  AND table_name NOT IN ('flyway_schema_history', 'tenant_schema_history', 'sync_runs')
                ORDER BY table_name, ordinal_position
                """, columnDefaultMapper(), schemaName);
    }

    private List<ForeignKeyDefinition> foreignKeys(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT rel.relname AS table_name,
                       con.conname AS constraint_name,
                       pg_get_constraintdef(con.oid) AS definition
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
                WHERE nsp.nspname = ?
                  AND con.contype = 'f'
                  AND rel.relname NOT IN ('flyway_schema_history', 'tenant_schema_history')
                ORDER BY rel.relname, con.conname
                """, foreignKeyMapper(), schemaName);
    }

    private List<TableConstraintDefinition> tableConstraints(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT rel.relname AS table_name,
                       con.conname AS constraint_name,
                       pg_get_constraintdef(con.oid) AS definition
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
                WHERE nsp.nspname = ?
                  AND con.contype IN ('p', 'u')
                  AND rel.relname NOT IN ('flyway_schema_history', 'tenant_schema_history')
                ORDER BY rel.relname, con.conname
                """, (rs, rowNum) -> new TableConstraintDefinition(
                rs.getString("table_name"),
                rs.getString("constraint_name"),
                rs.getString("definition")
        ), schemaName);
    }

    private List<IndexDefinition> standaloneIndexes(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT tab.relname AS table_name,
                       idx.relname AS index_name,
                       pg_get_indexdef(idx.oid) AS definition
                FROM pg_index i
                JOIN pg_class idx ON idx.oid = i.indexrelid
                JOIN pg_class tab ON tab.oid = i.indrelid
                JOIN pg_namespace nsp ON nsp.oid = tab.relnamespace
                WHERE nsp.nspname = ?
                  AND tab.relname NOT IN ('flyway_schema_history', 'tenant_schema_history')
                  AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = idx.oid)
                ORDER BY idx.relname
                """, (rs, rowNum) -> new IndexDefinition(
                rs.getString("table_name"),
                rs.getString("index_name"),
                rs.getString("definition")
        ), schemaName);
    }

    private RowMapper<SequenceDefinition> sequenceDefinitionMapper() {
        return (resultSet, rowNum) -> new SequenceDefinition(
                resultSet.getString("sequence_name"),
                resultSet.getString("data_type"),
                resultSet.getString("start_value"),
                resultSet.getString("minimum_value"),
                resultSet.getString("maximum_value"),
                resultSet.getString("increment"),
                "YES".equalsIgnoreCase(resultSet.getString("cycle_option"))
        );
    }

    private RowMapper<ColumnDefaultDefinition> columnDefaultMapper() {
        return (resultSet, rowNum) -> new ColumnDefaultDefinition(
                resultSet.getString("table_name"),
                resultSet.getString("column_name"),
                resultSet.getString("column_default")
        );
    }

    private RowMapper<ForeignKeyDefinition> foreignKeyMapper() {
        return (resultSet, rowNum) -> new ForeignKeyDefinition(
                resultSet.getString("table_name"),
                resultSet.getString("constraint_name"),
                resultSet.getString("definition")
        );
    }

    private String createSequenceSql(String targetSchema, SequenceDefinition definition) {
        return """
                CREATE SEQUENCE IF NOT EXISTS %s.%s
                AS %s
                INCREMENT BY %s
                MINVALUE %s
                MAXVALUE %s
                START WITH %s
                %s
                """.formatted(
                quotedIdentifier(targetSchema),
                quotedIdentifier(definition.sequenceName()),
                definition.dataType(),
                definition.incrementBy(),
                definition.minValue(),
                definition.maxValue(),
                definition.startValue(),
                definition.cycle() ? "CYCLE" : "NO CYCLE"
        );
    }

    private String rewrittenDefaultExpression(String targetSchema, String expression) {
        return expression.replace(defaultSchemaName + ".", targetSchema + ".");
    }

    private String rewriteForeignKeyDefinition(String targetSchema, String definition) {
        if (defaultSchemaName.equals(targetSchema)) {
            return definition;
        }
        return definition
                .replace("REFERENCES " + defaultSchemaName + ".", "REFERENCES " + targetSchema + ".")
                .replace("REFERENCES " + quotedIdentifier(defaultSchemaName) + ".",
                        "REFERENCES " + quotedIdentifier(targetSchema) + ".");
    }

    private String rewriteIndexDefinition(String targetSchema, String definition) {
        return definition
                .replace(" ON " + defaultSchemaName + ".", " ON " + quotedIdentifier(targetSchema) + ".")
                .replace(" ON " + quotedIdentifier(defaultSchemaName) + ".", " ON " + quotedIdentifier(targetSchema) + ".");
    }

    private static String quotedIdentifier(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private record SequenceDefinition(
            String sequenceName,
            String dataType,
            String startValue,
            String minValue,
            String maxValue,
            String incrementBy,
            boolean cycle
    ) {
    }

    private record ColumnDefaultDefinition(String tableName, String columnName, String defaultExpression) {
    }

    private record ForeignKeyDefinition(String tableName, String constraintName, String definition) {
    }

    private record TableConstraintDefinition(String tableName, String constraintName, String definition) {
    }

    private record PolicyDefinition(String permissive, String command, String roles, String using, String withCheck) {
        private static final Pattern UUID_LITERAL = Pattern.compile(
                "'([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})'::uuid");
        private static final String SESSION_TENANT = "(NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid";
        /** Used only when the template table has no tenant_isolation policy to copy. */
        static final PolicyDefinition UNPINNED = new PolicyDefinition("PERMISSIVE", "ALL", "public",
                "(tenant_id = " + SESSION_TENANT + ")", "(tenant_id = " + SESSION_TENANT + ")");

        PolicyDefinition repinned(String templateSchema, UUID templateTenantId, String targetSchema, UUID targetTenantId, String tableName) {
            return new PolicyDefinition(permissive, command, roles,
                    repin(using, templateSchema, templateTenantId, targetSchema, targetTenantId, tableName),
                    repin(withCheck, templateSchema, templateTenantId, targetSchema, targetTenantId, tableName));
        }

        private static String repin(String expression, String templateSchema, UUID templateTenantId,
                                    String targetSchema, UUID targetTenantId, String tableName) {
            if (expression == null) {
                return null;
            }
            String rewritten = expression.replace(templateSchema + ".", targetSchema + ".");
            Matcher pins = UUID_LITERAL.matcher(rewritten);
            if (!pins.find()) {
                return rewritten;
            }
            if (templateTenantId == null || targetTenantId == null) {
                throw new IllegalStateException("Cannot re-pin tenant_isolation on " + targetSchema + "." + tableName
                        + ": the template and target schemas must each map to exactly one registered tenant");
            }
            rewritten = rewritten.replace("'" + templateTenantId + "'::uuid", "'" + targetTenantId + "'::uuid");
            Matcher remaining = UUID_LITERAL.matcher(rewritten);
            while (remaining.find()) {
                if (!remaining.group(1).equalsIgnoreCase(targetTenantId.toString())) {
                    throw new IllegalStateException("Unexpected tenant pin in template policy on " + tableName);
                }
            }
            return rewritten;
        }

        String createStatement(String quotedSchema, String quotedTable) {
            String grantees = Arrays.stream(roles.split(","))
                    .map(role -> "public".equals(role) ? "PUBLIC" : quotedIdentifier(role))
                    .collect(Collectors.joining(", "));
            return "CREATE POLICY tenant_isolation ON " + quotedSchema + "." + quotedTable
                    + " AS " + permissive + " FOR " + command + " TO " + grantees
                    + (using == null ? "" : " USING (" + using + ")")
                    + (withCheck == null ? "" : " WITH CHECK (" + withCheck + ")");
        }
    }

    private record IndexDefinition(String tableName, String indexName, String definition) {
    }

    private record MissingColumnDefinition(
            String tableName,
            String columnName,
            String dataType,
            String defaultExpression,
            boolean nullable
    ) {
    }

    private record SchemaProjection(int currentVersion, String status) {
    }
}
