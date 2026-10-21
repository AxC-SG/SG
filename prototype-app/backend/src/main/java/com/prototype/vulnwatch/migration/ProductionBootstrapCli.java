package com.prototype.vulnwatch.migration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.service.TenantSchemaService;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

/** Production-only bootstrap entry point. Does not initialize Spring or JPA. */
public final class ProductionBootstrapCli {

    private static final PackagedMigrationCatalog.Targets MIGRATION_TARGETS = PackagedMigrationCatalog.resolve();
    private static final String DEFAULT_TENANT_NAME = "Default Workspace";
    private static final String DEFAULT_TENANT_SLUG = "default-workspace";
    private static final String DEFAULT_TENANT_SCHEMA = "tenant_default";
    private static final String LOCK_NAME = "scout-production-bootstrap";
    private static final UUID DEFAULT_TENANT_ID = UUID.nameUUIDFromBytes(
            "scout-default-tenant".getBytes(StandardCharsets.UTF_8));

    private ProductionBootstrapCli() {
    }

    public static void main(String[] args) throws Exception {
        UUID runId = UUID.randomUUID();
        Instant startedAt = Instant.now();
        List<Phase> phases = new ArrayList<>();
        boolean success = false;
        String failureCode = null;
        String failureMessage = null;
        try {
            Config config = validatedConfig();
            try (Connection connection = ownerConnection(config)) {
                verifyOwnerPreflight(connection, config);
                phases.add(Phase.success("database_preflight", "configuration and connectivity verified"));
                acquireLock(connection);
                try {
                    if (config.reportOnly()) {
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("report_only_owner_verification", "complete"));
                    } else {
                        int platformVersion = runPlatformMigrations(config);
                        provisionRuntimeRole(connection, config.runtimeDbUsername(), config.runtimeDbPassword());
                        phases.add(Phase.success("platform_migrations", "version=" + platformVersion));
                        if (config.platformOwnerBootstrapEnabled()) {
                            reconcilePlatformOwner(connection, config);
                            phases.add(Phase.success("platform_owner_identity", "configured"));
                        }
                        TenantSchema defaultTenant = ensureDefaultTenant(connection);
                        phases.add(Phase.success("default_tenant_registration", defaultTenant.schemaName()));
                        migrateTenant(config, defaultTenant);
                        String templateChecksum = fingerprint(connection, defaultTenant.schemaName());
                        grantAndVerifySchema(connection,config.runtimeDbUsername(),defaultTenant.schemaName());
                        markCurrent(connection, defaultTenant, templateChecksum, runId);
                        phases.add(Phase.success("default_tenant_migration",
                                "version=" + MIGRATION_TARGETS.tenantTarget()));
                        BootstrapResult tenantResult = migrateExistingAndProvisioningTenants(
                                connection, config, defaultTenant, templateChecksum, runId);
                        phases.addAll(tenantResult.phases());
                        if (!tenantResult.success()) {
                            throw new BootstrapFailure("tenant_provisioning_failed", "Tenant provisioning failed");
                        }
                        provisionRuntimeRole(connection, config.runtimeDbUsername(), config.runtimeDbPassword());
                        phases.add(Phase.success("runtime_role_provisioning", config.runtimeDbUsername()));
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("owner_verification", "complete"));
                        if (config.platformOwnerSetupLinkEnabled()) {
                            PlatformOwnerSetupLinkIssuer.DeliverySummary delivery =
                                    platformOwnerSetupLinkIssuer(config).issue(
                                            connection,
                                            config.platformOwnerSetupEmail(),
                                            config.platformOwnerSetupAppBaseUrl(),
                                            config.platformOwnerSetupTokenTtlMinutes(),
                                            config.platformOwnerSetupAllowReissue(),
                                            runId);
                            phases.add(Phase.success(
                                    "platform_owner_setup_email",
                                    "delivered; expiresAt=" + delivery.expiresAt()));
                        }
                    }
                } finally {
                    releaseLock(connection);
                }
            }
            verifyRuntimeConnection(config);
            phases.add(Phase.success("runtime_verification", "complete"));
            success = true;
        } catch (BootstrapFailure ex) {
            failureCode = ex.code();
            failureMessage = sanitize(ex.getMessage());
            phases.add(Phase.failed(failureCode, failureMessage));
        } catch (Exception ex) {
            failureCode = "bootstrap_failed";
            failureMessage = sanitize(ex.getMessage());
            phases.add(Phase.failed(failureCode, failureMessage));
        }
        Instant completedAt = Instant.now();
        System.out.println(report(runId, startedAt, completedAt, success, failureCode, failureMessage, phases));
        if (!success) {
            throw new BootstrapFailure(failureCode == null ? "bootstrap_failed" : failureCode,
                    failureMessage == null ? "Production bootstrap failed" : failureMessage);
        }
    }

    private static Config validatedConfig() {
        try {
            Config config = Config.fromEnvironment();
            URI uri = URI.create(config.dbUrl().substring("jdbc:".length()));
            if (!"postgresql".equals(uri.getScheme()) || uri.getUserInfo() != null || uri.getHost() == null
                    || uri.getPort() < 1 || uri.getPort() > 65535 || uri.getPath() == null
                    || uri.getPath().length() < 2 || uri.getPath().substring(1).contains("/")) {
                throw new IllegalArgumentException("DB_URL must be jdbc:postgresql://host:port/database");
            }
            if (!uri.getPath().substring(1).equals(config.expectedDatabase())) {
                throw new IllegalArgumentException("DB_URL database does not match EXPECTED_DB_NAME");
            }
            return config;
        } catch (RuntimeException ex) {
            throw new BootstrapFailure("preflight_db_config", sanitize(ex.getMessage()));
        }
    }

    private static Connection ownerConnection(Config config) {
        try {
            DriverManager.setLoginTimeout(10);
            return DriverManager.getConnection(config.dbUrl(), config.dbUsername(), config.dbPassword());
        } catch (SQLException ex) {
            throw new BootstrapFailure("preflight_db_connectivity", "Unable to connect to configured database");
        }
    }

    private static void verifyOwnerPreflight(Connection connection, Config config) {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select current_user, current_database()")) {
            if (!result.next()) {
                throw new SQLException("Database identity query returned no row");
            }
            if (!config.dbUsername().equals(result.getString(1))) {
                throw new BootstrapFailure("preflight_db_config", "Connected database user does not match DB_USERNAME");
            }
            if (!config.expectedDatabase().equals(result.getString(2))) {
                throw new BootstrapFailure("preflight_db_config",
                        "Connected database does not match EXPECTED_DB_NAME");
            }
        } catch (BootstrapFailure ex) {
            throw ex;
        } catch (SQLException ex) {
            throw new BootstrapFailure("preflight_db_connectivity", "Unable to verify database identity");
        }
    }

    private static int runPlatformMigrations(Config config) {
        Flyway flyway = Flyway.configure()
                .dataSource(config.dbUrl(), config.dbUsername(), config.dbPassword())
                .schemas("public")
                .defaultSchema("public")
                .table("flyway_schema_history")
                .locations("classpath:db/migration/postgres_reset")
                .baselineOnMigrate(false)
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load();
        flyway.migrate();
        int actualVersion = Integer.parseInt(flyway.info().current().getVersion().getVersion());
        if (actualVersion != MIGRATION_TARGETS.platformTarget()) {
            throw new BootstrapFailure("platform_target_mismatch", "Platform migration finished at V"
                    + actualVersion + " but packaged target is V" + MIGRATION_TARGETS.platformTarget());
        }
        return actualVersion;
    }

    private static PlatformOwnerSetupLinkIssuer platformOwnerSetupLinkIssuer(Config config) {
        ResendEmailClient emailClient = new ResendEmailClient(
                new ObjectMapper(),
                config.resendBaseUrl(),
                config.resendApiKey(),
                config.resendFromEmail(),
                config.resendFromDomain());
        return new PlatformOwnerSetupLinkIssuer(emailClient);
    }

    private static void reconcilePlatformOwner(Connection connection, Config config) throws SQLException {
        String email = config.platformOwnerBootstrapEmail().trim().toLowerCase();
        String externalSubject = config.platformOwnerBootstrapExternalSubject().isBlank()
                ? email
                : config.platformOwnerBootstrapExternalSubject().trim();
        UUID subjectMatch = findUserBySubject(connection, externalSubject);
        UUID emailMatch = findUserByEmail(connection, email);
        if (subjectMatch != null && emailMatch != null && !subjectMatch.equals(emailMatch)) {
            throw new BootstrapFailure(
                    "platform_owner_identity_conflict",
                    "Platform owner subject and email match different users");
        }
        UUID userId = subjectMatch != null ? subjectMatch : emailMatch;
        if (userId == null) {
            userId = UUID.randomUUID();
            try (PreparedStatement insert = connection.prepareStatement("""
                    insert into platform.app_users (
                        id, created_at, display_name, email, external_subject,
                        platform_owner, status, updated_at
                    ) values (?, now(), ?, ?, ?, true, 'ACTIVE', now())
                    """)) {
                insert.setObject(1, userId);
                insert.setString(2, config.platformOwnerBootstrapDisplayName());
                insert.setString(3, email);
                insert.setString(4, externalSubject);
                insert.executeUpdate();
            }
        } else {
            try (PreparedStatement update = connection.prepareStatement("""
                    update platform.app_users
                    set display_name = ?,
                        email = ?,
                        external_subject = ?,
                        platform_owner = true,
                        status = 'ACTIVE',
                        updated_at = now()
                    where id = ?
                    """)) {
                update.setString(1, config.platformOwnerBootstrapDisplayName());
                update.setString(2, email);
                update.setString(3, externalSubject);
                update.setObject(4, userId);
                if (update.executeUpdate() != 1) {
                    throw new BootstrapFailure(
                            "platform_owner_identity_update_failed",
                            "Platform owner identity update did not affect one row");
                }
            }
        }
        try (PreparedStatement role = connection.prepareStatement("""
                insert into platform.app_user_global_roles (id, app_user_id, role, created_at)
                values (?, ?, 'PLATFORM_OWNER', now())
                on conflict (app_user_id, role) do nothing
                """)) {
            role.setObject(1, UUID.randomUUID());
            role.setObject(2, userId);
            role.executeUpdate();
        }
    }

    private static UUID findUserBySubject(Connection connection, String externalSubject) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                select id
                from platform.app_users
                where external_subject = ?
                order by created_at
                limit 2
                """)) {
            statement.setString(1, externalSubject);
            return singleUserId(statement);
        }
    }

    private static UUID findUserByEmail(Connection connection, String email) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                select id
                from platform.app_users
                where lower(email) = ?
                order by created_at
                limit 2
                """)) {
            statement.setString(1, email);
            return singleUserId(statement);
        }
    }

    private static UUID singleUserId(PreparedStatement statement) throws SQLException {
        try (ResultSet result = statement.executeQuery()) {
            if (!result.next()) {
                return null;
            }
            UUID userId = result.getObject("id", UUID.class);
            if (result.next()) {
                throw new BootstrapFailure(
                        "platform_owner_identity_duplicate",
                        "Multiple users match the configured platform owner identity");
            }
            return userId;
        }
    }

    private static TenantSchema ensureDefaultTenant(Connection connection) throws SQLException {
        try (PreparedStatement select = connection.prepareStatement("""
                select id, schema_name
                from platform.tenants
                where lower(name) = lower(?) or schema_name = ?
                order by case when schema_name = ? then 0 else 1 end, created_at
                limit 1
                """)) {
            select.setString(1, DEFAULT_TENANT_NAME);
            select.setString(2, DEFAULT_TENANT_SCHEMA);
            select.setString(3, DEFAULT_TENANT_SCHEMA);
            try (ResultSet result = select.executeQuery()) {
                if (result.next()) {
                    UUID tenantId = result.getObject("id", UUID.class);
                    try (PreparedStatement update = connection.prepareStatement("""
                            update platform.tenants
                            set name = ?, slug = ?, schema_name = ?, status = 'ACTIVE', updated_at = now()
                            where id = ?
                            """)) {
                        update.setString(1, DEFAULT_TENANT_NAME);
                        update.setString(2, DEFAULT_TENANT_SLUG);
                        update.setString(3, DEFAULT_TENANT_SCHEMA);
                        update.setObject(4, tenantId);
                        update.executeUpdate();
                    }
                    return new TenantSchema(tenantId, DEFAULT_TENANT_SCHEMA, "ACTIVE");
                }
            }
        }
        try (PreparedStatement insert = connection.prepareStatement("""
                insert into platform.tenants (
                    id, name, slug, schema_name, status, plan_code,
                    created_at, updated_at, max_connector_count,
                    max_service_account_count, max_daily_sbom_uploads,
                    max_export_rows, max_daily_exposure_refreshes
                ) values (?, ?, ?, ?, 'ACTIVE', 'ENTERPRISE', now(), now(), 10, 25, 100, 50000, 25)
                """)) {
            insert.setObject(1, DEFAULT_TENANT_ID);
            insert.setString(2, DEFAULT_TENANT_NAME);
            insert.setString(3, DEFAULT_TENANT_SLUG);
            insert.setString(4, DEFAULT_TENANT_SCHEMA);
            insert.executeUpdate();
        }
        return new TenantSchema(DEFAULT_TENANT_ID, DEFAULT_TENANT_SCHEMA, "ACTIVE");
    }

    private static BootstrapResult migrateExistingAndProvisioningTenants(
            Connection connection,
            Config config,
            TenantSchema defaultTenant,
            String templateChecksum,
            UUID runId
    ) throws Exception {
        List<Phase> phases = new ArrayList<>();
        List<TenantSchema> activeTenants = tenants(connection, "ACTIVE").stream()
                .filter(tenant -> !tenant.tenantId().equals(defaultTenant.tenantId()))
                .toList();
        if (!activeTenants.isEmpty()) {
            TenantSchema canary = activeTenants.get(0);
            migrateAndMark(connection, config, canary, templateChecksum, runId);
            phases.add(Phase.success("tenant_canary_migration", canary.schemaName()));
        }
        for (int offset = 1; offset < activeTenants.size(); offset += 10) {
            List<TenantSchema> batch = activeTenants.subList(offset, Math.min(offset + 10, activeTenants.size()));
            for (TenantSchema tenant : batch) {
                migrateAndMark(connection, config, tenant, templateChecksum, runId);
            }
            phases.add(Phase.success("tenant_batch_migration", "count=" + batch.size()));
        }

        List<TenantSchema> pending = tenants(connection, "PROVISIONING");
        for (TenantSchema tenant : pending) {
            try {
                provisionTenantSchema(connection, tenant.schemaName());
                migrateAndMark(connection, config, tenant, templateChecksum, runId);
                setTenantStatus(connection, tenant.tenantId(), "ACTIVE");
                phases.add(Phase.success("tenant_provisioning", tenant.schemaName()));
            } catch (Exception ex) {
                markFailure(connection, tenant, "PROVISIONING_FAILED", "PROVISIONING_FAILED", rootMessage(ex), runId);
                setTenantStatus(connection, tenant.tenantId(), "PROVISIONING_FAILED");
                phases.add(Phase.failed(
                        "tenant_provisioning_failed",
                        tenant.schemaName() + ": " + sanitize(rootMessage(ex))));
                return new BootstrapResult(false, phases);
            }
        }
        return new BootstrapResult(true, phases);
    }

    private static void migrateAndMark(
            Connection connection,
            Config config,
            TenantSchema tenant,
            String templateChecksum,
            UUID runId
    ) throws Exception {
        migrateTenant(config, tenant);
        String tenantChecksum = fingerprint(connection, tenant.schemaName());
        if (!templateChecksum.equals(tenantChecksum)) {
            throw new BootstrapFailure(
                    "tenant_schema_drift",
                    "Tenant schema does not match the migrated template: " + tenant.schemaName()
                            + " expected=" + templateChecksum + " actual=" + tenantChecksum);
        }
        grantAndVerifySchema(connection,config.runtimeDbUsername(),tenant.schemaName());
        markCurrent(connection, tenant, tenantChecksum, runId);
    }

    private static void migrateTenant(Config config, TenantSchema tenant) {
        Flyway flyway = tenantFlyway(config, tenant);
        flyway.migrate();
        int actualVersion = Integer.parseInt(flyway.info().current().getVersion().getVersion());
        if (actualVersion != MIGRATION_TARGETS.tenantTarget()) {
            throw new BootstrapFailure("tenant_target_mismatch", "Tenant migration finished at V"
                    + actualVersion + " but packaged target is V" + MIGRATION_TARGETS.tenantTarget());
        }
    }

    private static Flyway tenantFlyway(Config config, TenantSchema tenant) {
        return Flyway.configure()
                .dataSource(config.dbUrl(), config.dbUsername(), config.dbPassword())
                .schemas(tenant.schemaName())
                .defaultSchema(tenant.schemaName())
                .table("tenant_schema_history")
                .locations("classpath:db/migration/tenant")
                .placeholders(java.util.Map.of(
                        "tenantId", tenant.tenantId().toString(),
                        "tenantSchema", tenant.schemaName()))
                .callbacks(new TenantSearchPathFlywayCallback(tenant.schemaName()))
                .validateOnMigrate(true)
                .outOfOrder(false)
                .initSql("SET search_path TO " + quotedIdentifier(tenant.schemaName())
                        + ", public; SET statement_timeout = '5min'")
                .load();
    }

    private static void provisionTenantSchema(Connection connection, String schemaName) throws SQLException {
        if (DEFAULT_TENANT_SCHEMA.equals(schemaName) || "platform".equals(schemaName)) {
            throw new IllegalArgumentException("Refusing to provision protected schema: " + schemaName);
        }
        try (Statement statement = connection.createStatement()) {
            statement.execute("drop schema if exists " + quotedIdentifier(schemaName) + " cascade");
        }
        SingleConnectionDataSource dataSource = new SingleConnectionDataSource(connection, true);
        TenantSchemaService schemaService = new TenantSchemaService(
                new JdbcTemplate(dataSource), DEFAULT_TENANT_SCHEMA);
        // New tenants must start empty so tenant Flyway owns the V1 baseline and
        // records its own history. Cloning tenant_default leaves a non-empty
        // schema without history, which Flyway correctly refuses to migrate.
        schemaService.provisionEmptySchema(schemaName);
    }

    private static List<TenantSchema> tenants(Connection connection, String status) throws SQLException {
        List<TenantSchema> tenants = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                select id, schema_name, status
                from platform.tenants
                where deleted_at is null
                  and purged_at is null
                  and upper(status) = ?
                order by created_at, schema_name
                """)) {
            statement.setString(1, status);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    tenants.add(new TenantSchema(
                            result.getObject("id", UUID.class),
                            result.getString("schema_name"),
                            result.getString("status")));
                }
            }
        }
        return tenants;
    }

    private static void markCurrent(Connection connection, TenantSchema tenant, String checksum, UUID runId) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenant_schema_versions (
                    tenant_id, schema_name, current_version, target_version, status,
                    structural_checksum, migration_started_at, migration_completed_at,
                    last_successful_version, failure_code, failure_message, updated_at, migration_run_id
                ) values (?, ?, ?, ?, 'CURRENT', ?, now(), now(), ?, null, null, now(), ?)
                on conflict (tenant_id) do update set
                    schema_name = excluded.schema_name,
                    current_version = excluded.current_version,
                    target_version = excluded.target_version,
                    status = 'CURRENT',
                    structural_checksum = excluded.structural_checksum,
                    migration_completed_at = now(),
                    last_successful_version = excluded.last_successful_version,
                    failure_code = null,
                    failure_message = null,
                    updated_at = now(),
                    migration_run_id = excluded.migration_run_id
                """)) {
            statement.setObject(1, tenant.tenantId());
            statement.setString(2, tenant.schemaName());
            statement.setInt(3, MIGRATION_TARGETS.tenantTarget());
            statement.setInt(4, MIGRATION_TARGETS.tenantTarget());
            statement.setString(5, checksum);
            statement.setInt(6, MIGRATION_TARGETS.tenantTarget());
            statement.setObject(7, runId);
            statement.executeUpdate();
        }
    }

    private static void markFailure(
            Connection connection,
            TenantSchema tenant,
            String status,
            String code,
            String message,
            UUID runId
    ) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenant_schema_versions (
                    tenant_id, schema_name, current_version, target_version, status,
                    structural_checksum, migration_started_at, migration_completed_at,
                    last_successful_version, failure_code, failure_message, updated_at, migration_run_id
                ) values (?, ?, 0, ?, ?, null, now(), now(), 0, ?, ?, now(), ?)
                on conflict (tenant_id) do update set
                    schema_name = excluded.schema_name,
                    status = excluded.status,
                    failure_code = excluded.failure_code,
                    failure_message = excluded.failure_message,
                    updated_at = now(),
                    migration_run_id = excluded.migration_run_id
                """)) {
            statement.setObject(1, tenant.tenantId());
            statement.setString(2, tenant.schemaName());
            statement.setInt(3, MIGRATION_TARGETS.tenantTarget());
            statement.setString(4, status);
            statement.setString(5, code);
            statement.setString(6, sanitize(message));
            statement.setObject(7, runId);
            statement.executeUpdate();
        }
    }

    private static void setTenantStatus(Connection connection, UUID tenantId, String status) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                update platform.tenants
                set status = ?, updated_at = now()
                where id = ?
                """)) {
            statement.setString(1, status);
            statement.setObject(2, tenantId);
            statement.executeUpdate();
        }
    }

    private static void provisionRuntimeRole(Connection connection, String role, String password) throws SQLException {
        String quotedRole = quotedIdentifier(role);
        try (Statement statement = connection.createStatement()) {
            statement.execute("""
                    do $$
                    begin
                        if not exists (select 1 from pg_roles where rolname = %s) then
                            execute 'create role ' || %s || ' login noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls';
                        end if;
                    end
                    $$
                    """.formatted(quotedLiteral(role), quotedLiteral(quotedRole)));
            requireZero(connection, """
                    select count(*)
                    from pg_roles
                    where rolname = ?
                      and (rolsuper or rolcreatedb or rolcreaterole or rolreplication or rolbypassrls)
                    """, "runtime role has immutable unsafe attributes", role);
            statement.execute("alter role " + quotedRole
                    + " with login noinherit password "
                    + quotedLiteral(password));
            statement.execute("grant connect on database " + quotedIdentifier(connection.getCatalog()) + " to " + quotedRole);
            statement.execute("revoke create on database " + quotedIdentifier(connection.getCatalog()) + " from " + quotedRole);
            statement.execute("revoke create on schema public from " + quotedRole);
        }
        for (String schema : protectedSchemas(connection)) grantAndVerifySchema(connection,role,schema);
        try (Statement statement=connection.createStatement()) {
            statement.execute("grant usage on schema public to "+quotedRole);
            statement.execute("grant select,insert,update,delete on public.github_security_advisories, public.github_advisory_sync_state to "+quotedRole);
        }
    }

    private static void grantAndVerifySchema(Connection connection,String role,String schema) throws SQLException {
        String quotedRole=quotedIdentifier(role),quotedSchema=quotedIdentifier(schema);
        try (Statement statement=connection.createStatement()) {
            statement.execute("grant usage on schema "+quotedSchema+" to "+quotedRole);
            statement.execute("grant select,insert,update,delete on all tables in schema "+quotedSchema+" to "+quotedRole);
            statement.execute("grant usage,select on all sequences in schema "+quotedSchema+" to "+quotedRole);
            statement.execute("revoke create on schema "+quotedSchema+" from "+quotedRole);
            statement.execute("alter default privileges for role "+quotedIdentifier(currentUser(connection))+" in schema "+quotedSchema+" grant select,insert,update,delete on tables to "+quotedRole);
            statement.execute("alter default privileges for role "+quotedIdentifier(currentUser(connection))+" in schema "+quotedSchema+" grant usage,select on sequences to "+quotedRole);
        }
        requireZero(connection,"""
                select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
                where n.nspname=? and c.relkind in ('r','p')
                  and not has_table_privilege(?,c.oid,'SELECT,INSERT,UPDATE,DELETE')
                ""","runtime schema grants incomplete",schema,role);
    }

    private static void verifyControlPlane(Connection connection, String runtimeRole) throws Exception {
        requireZero(connection, """
                select count(*)
                from public.flyway_schema_history
                where not success
                """, "failed platform flyway rows");
        requireMinimum(connection, """
                select coalesce(max(version::integer), 0)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$'
                """, MIGRATION_TARGETS.platformTarget(), "platform version");
        requireZero(connection, """
                select count(*)
                from pg_roles
                where rolname = ?
                  and (rolsuper or rolinherit or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls)
                """, "unsafe runtime role attributes", runtimeRole);
        requireZero(connection, """
                with recursive memberships(roleid) as (
                    select m.roleid
                    from pg_auth_members m
                    join pg_roles me on me.oid = m.member
                    where me.rolname = ?
                    union
                    select m.roleid
                    from pg_auth_members m
                    join memberships inherited on inherited.roleid = m.member
                )
                select count(*)
                from memberships m
                join pg_roles r on r.oid = m.roleid
                where r.rolsuper or r.rolbypassrls or r.rolcreaterole or r.rolcreatedb
                """, "runtime role can assume an unsafe role", runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                join pg_roles r on r.oid = c.relowner
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind in ('r', 'p')
                  and r.rolname = ?
                """, "runtime role owns protected tables", runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_namespace n
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and has_schema_privilege(?, n.oid, 'CREATE')
                """, "runtime role has protected-schema DDL privileges", runtimeRole);
        requireZero(connection, """
                select case when has_database_privilege(?, current_database(), 'CREATE') then 1 else 0 end
                """, "runtime role has database CREATE privilege", runtimeRole);
        requireZero(connection, """
                select count(*)
                from platform.tenants t
                join pg_namespace n on n.nspname = t.schema_name
                join pg_class c on c.relnamespace = n.oid and c.relkind in ('r', 'p')
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                  and c.relname not in ('tenant_schema_history', 'flyway_schema_history', 'demo_requests')
                  and (
                      not c.relrowsecurity
                      or not c.relforcerowsecurity
                      or not exists (
                          select 1 from pg_policy p
                          where p.polrelid = c.oid
                            and p.polname = 'tenant_isolation'
                            and pg_get_expr(p.polqual, p.polrelid) like '%app.current_tenant_id%'
                            and pg_get_expr(p.polwithcheck, p.polrelid) like '%app.current_tenant_id%'
                      )
                  )
                """, "active tenant tables have incomplete RLS coverage");
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind in ('r', 'p')
                  and not (
                      has_table_privilege(?, c.oid, 'SELECT')
                      and has_table_privilege(?, c.oid, 'INSERT')
                      and has_table_privilege(?, c.oid, 'UPDATE')
                      and has_table_privilege(?, c.oid, 'DELETE')
                  )
                """, "runtime role is missing required table DML privileges",
                runtimeRole, runtimeRole, runtimeRole, runtimeRole);
        requireZero(connection, """
                select count(*)
                from pg_class c
                join pg_namespace n on n.oid = c.relnamespace
                where (n.nspname in ('platform', 'tenant_default') or n.nspname ~ '^tenant_')
                  and c.relkind = 'S'
                  and not (
                      has_sequence_privilege(?, c.oid, 'USAGE')
                      and has_sequence_privilege(?, c.oid, 'SELECT')
                  )
                """, "runtime role is missing required sequence privileges", runtimeRole, runtimeRole);
        requireZero(connection, """
                select count(*)
                from platform.tenants t
                left join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                  and (v.tenant_id is null or v.status <> 'CURRENT'
                       or v.current_version < %d or v.last_successful_version < %d)
                """.formatted(MIGRATION_TARGETS.tenantTarget(), MIGRATION_TARGETS.tenantTarget()),
                "active tenants missing current schema projection");
        verifyActiveTenantSchemaState(connection);
    }

    private static void verifyActiveTenantSchemaState(Connection connection) throws Exception {
        String templateChecksum = fingerprint(connection, DEFAULT_TENANT_SCHEMA);
        try (PreparedStatement statement = connection.prepareStatement("""
                select t.schema_name, v.structural_checksum
                from platform.tenants t
                join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.deleted_at is null
                  and upper(t.status) = 'ACTIVE'
                order by t.schema_name
                """);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                String schemaName = result.getString("schema_name");
                String recordedChecksum = result.getString("structural_checksum");
                requireMinimum(connection, """
                        select count(*)
                        from %s.tenant_schema_history
                        where version = '%d' and success
                        """.formatted(quotedIdentifier(schemaName), MIGRATION_TARGETS.tenantTarget()),
                        1, schemaName + " tenant migration version");
                String actualChecksum = fingerprint(connection, schemaName);
                if (recordedChecksum == null
                        || !recordedChecksum.equals(actualChecksum)
                        || !templateChecksum.equals(actualChecksum)) {
                    throw new BootstrapFailure(
                            "verification_failed",
                            "active tenant schema checksum mismatch: " + schemaName);
                }
            }
        }
    }

    private static void verifyRuntimeConnection(Config config) throws SQLException {
        try (Connection connection = DriverManager.getConnection(
                config.dbUrl(), config.runtimeDbUsername(), config.runtimeDbPassword())) {
            if (!connection.getCatalog().equals(config.expectedDatabase())) {
                throw new BootstrapFailure("verification_failed", "runtime connection targets an unexpected database");
            }
            requireZero(connection, "select case when current_user = ? then 0 else 1 end",
                    "runtime role mismatch", config.runtimeDbUsername());
            requireZero(connection, """
                    select count(*)
                    from pg_roles
                    where rolname = current_user
                      and (rolsuper or rolinherit or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls)
                    """, "runtime role is unsafe");
            verifyRuntimeDdlDenied(connection);
        }
    }

    private static void verifyRuntimeDdlDenied(Connection connection) throws SQLException {
        requireZero(connection,"""
                select count(*) from pg_namespace where (nspname='platform' or nspname='public' or starts_with(nspname,'tenant_'))
                    and has_schema_privilege(current_user,oid,'CREATE')
                ""","runtime role can create protected tables");
        requireZero(connection,"select case when has_database_privilege(current_user,current_database(),'CREATE') then 1 else 0 end",
                "runtime role can create schemas");
    }

    private static void requireZero(Connection connection, String sql, String description, Object... params)
            throws SQLException {
        long value = queryLong(connection, sql, params);
        if (value != 0) {
            throw new BootstrapFailure("verification_failed", description + ": " + value);
        }
    }

    private static void requireMinimum(Connection connection, String sql, int minimum, String description)
            throws SQLException {
        long value = queryLong(connection, sql);
        if (value < minimum) {
            throw new BootstrapFailure("verification_failed", description + " is " + value);
        }
    }

    private static long queryLong(Connection connection, String sql, Object... params) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) {
                statement.setObject(i + 1, params[i]);
            }
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return 0;
                }
                return result.getLong(1);
            }
        }
    }

    private static int platformVersion(Connection connection) throws SQLException {
        return (int) queryLong(connection, """
                select coalesce(max(version::integer), 0)
                from public.flyway_schema_history
                where version ~ '^[0-9]+$'
                """);
    }

    private static List<String> protectedSchemas(Connection connection) throws SQLException {
        List<String> schemas = new ArrayList<>();
        try (PreparedStatement statement = connection.prepareStatement("""
                select nspname
                from pg_namespace
                where nspname in ('platform', 'tenant_default') or nspname ~ '^tenant_'
                order by nspname
                """);
             ResultSet result = statement.executeQuery()) {
            while (result.next()) {
                schemas.add(result.getString(1));
            }
        }
        return schemas;
    }

    private static String currentUser(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("select current_user")) {
            result.next();
            return result.getString(1);
        }
    }

    private static String fingerprint(Connection connection, String schemaName) throws Exception {
        return TenantSchemaFingerprint.of(connection, schemaName);
    }

    private static void acquireLock(Connection connection) throws SQLException {
        Instant deadline = Instant.now().plusSeconds(30);
        while (Instant.now().isBefore(deadline)) {
            try (PreparedStatement statement = connection.prepareStatement("select pg_try_advisory_lock(hashtext(?))")) {
                statement.setString(1, LOCK_NAME);
                try (ResultSet result = statement.executeQuery()) {
                    if (result.next() && result.getBoolean(1)) {
                        return;
                    }
                }
            }
            try {
                Thread.sleep(250);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new BootstrapFailure("lock_interrupted", "Interrupted while waiting for bootstrap lock");
            }
        }
        throw new BootstrapFailure("lock_timeout", "Timed out waiting for bootstrap lock");
    }

    private static void releaseLock(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("select pg_advisory_unlock(hashtext(?))")) {
            statement.setString(1, LOCK_NAME);
            statement.execute();
        }
    }

    private static String quotedIdentifier(String value) {
        if (value == null || value.indexOf('\u0000') >= 0) {
            throw new IllegalArgumentException("Unsafe SQL identifier");
        }
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private static String quotedLiteral(String value) {
        if (value == null) {
            return "null";
        }
        return "'" + value.replace("'", "''") + "'";
    }

    private static String sanitize(String message) {
        if (message == null) {
            return null;
        }
        String sanitized = message
                .replaceAll("(?i)(password|secret|token|key)=\\S+", "$1=[REDACTED]")
                .replaceAll("jdbc:postgresql://[^\\s,}]+", "jdbc:postgresql://[REDACTED]");
        return sanitized.substring(0, Math.min(1000, sanitized.length()));
    }

    private static String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current.getMessage() == null ? current.getClass().getSimpleName() : current.getMessage();
    }

    private static String report(
            UUID runId,
            Instant startedAt,
            Instant completedAt,
            boolean success,
            String failureCode,
            String failureMessage,
            List<Phase> phases
    ) {
        StringBuilder json = new StringBuilder();
        json.append('{')
                .append("\"runId\":\"").append(runId).append("\",")
                .append("\"startedAt\":\"").append(startedAt).append("\",")
                .append("\"completedAt\":\"").append(completedAt).append("\",")
                .append("\"success\":").append(success).append(',')
                .append("\"failureCode\":").append(jsonString(failureCode)).append(',')
                .append("\"failureMessage\":").append(jsonString(failureMessage)).append(',')
                .append("\"phases\":[");
        for (int i = 0; i < phases.size(); i++) {
            Phase phase = phases.get(i);
            if (i > 0) {
                json.append(',');
            }
            json.append('{')
                    .append("\"name\":\"").append(escape(phase.name())).append("\",")
                    .append("\"success\":").append(phase.success()).append(',')
                    .append("\"message\":").append(jsonString(phase.message()))
                    .append('}');
        }
        json.append("]}");
        return "production_bootstrap_report=" + json;
    }

    private static String jsonString(String value) {
        return value == null ? "null" : "\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private record Config(
            String dbUrl,
            String dbUsername,
            String dbPassword,
            String runtimeDbUsername,
            String runtimeDbPassword,
            String expectedDatabase,
            boolean reportOnly,
            boolean platformOwnerBootstrapEnabled,
            String platformOwnerBootstrapEmail,
            String platformOwnerBootstrapExternalSubject,
            String platformOwnerBootstrapDisplayName,
            boolean platformOwnerSetupLinkEnabled,
            String platformOwnerSetupEmail,
            String platformOwnerSetupAppBaseUrl,
            int platformOwnerSetupTokenTtlMinutes,
            boolean platformOwnerSetupAllowReissue,
            String resendBaseUrl,
            String resendApiKey,
            String resendFromEmail,
            String resendFromDomain
    ) {
        static Config fromEnvironment() {
            String dbUrl = boundedJdbcUrl(required("DB_URL"));
            boolean setupLinkEnabled = Boolean.parseBoolean(env("PLATFORM_OWNER_SETUP_LINK_ENABLED", "false"));
            boolean ownerBootstrapEnabled = Boolean.parseBoolean(
                    env("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED", "false")) || setupLinkEnabled;
            String ownerBootstrapEmail = ownerBootstrapEnabled
                    ? requiredWithFallback(
                            "PLATFORM_OWNER_SETUP_EMAIL",
                            "APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL")
                    : "";
            int setupTokenTtlMinutes = integerEnv("PLATFORM_OWNER_SETUP_TOKEN_TTL_MINUTES", 30, 5, 1440);
            return new Config(
                    dbUrl,
                    required("DB_USERNAME"),
                    required("DB_PASSWORD"),
                    env("RUNTIME_DB_USERNAME", "scout_runtime"),
                    required("RUNTIME_DB_PASSWORD"),
                    env("EXPECTED_DB_NAME", databaseName(dbUrl)),
                    Boolean.parseBoolean(env(
                            "BOOTSTRAP_REPORT_ONLY",
                            env("APP_SCHEMA_MIGRATION_REPORT_ONLY", "false"))),
                    ownerBootstrapEnabled,
                    ownerBootstrapEmail,
                    env("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EXTERNAL_SUBJECT", ownerBootstrapEmail),
                    env("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_DISPLAY_NAME", ownerBootstrapEmail),
                    setupLinkEnabled,
                    setupLinkEnabled ? ownerBootstrapEmail : "",
                    env("PLATFORM_OWNER_SETUP_APP_BASE_URL", env("APP_DEMO_APP_BASE_URL", "https://scoutgrid.io")),
                    setupTokenTtlMinutes,
                    Boolean.parseBoolean(env("PLATFORM_OWNER_SETUP_ALLOW_REISSUE", "false")),
                    env("RESEND_BASE_URL", "https://api.resend.com"),
                    setupLinkEnabled ? required("RESEND_API_KEY") : "",
                    setupLinkEnabled ? required("RESEND_FROM_EMAIL") : "",
                    setupLinkEnabled ? required("RESEND_FROM_DOMAIN") : "");
        }
    }

    private static String databaseName(String jdbcUrl) {
        int queryIndex = jdbcUrl.indexOf('?');
        String withoutQuery = queryIndex >= 0 ? jdbcUrl.substring(0, queryIndex) : jdbcUrl;
        int slashIndex = withoutQuery.lastIndexOf('/');
        if (slashIndex < 0 || slashIndex == withoutQuery.length() - 1) {
            throw new IllegalArgumentException("DB_URL must include a database name");
        }
        return withoutQuery.substring(slashIndex + 1);
    }

    private static String boundedJdbcUrl(String jdbcUrl) {
        java.util.Set<String> configuredTimeouts = new java.util.HashSet<>();
        int query = jdbcUrl.indexOf('?');
        if (query >= 0) {
            for (String parameter : jdbcUrl.substring(query + 1).split("&")) {
                String[] pair = parameter.split("=", 2);
                String name = java.net.URLDecoder.decode(pair[0], java.nio.charset.StandardCharsets.UTF_8);
                if (!name.equalsIgnoreCase("connectTimeout") && !name.equalsIgnoreCase("socketTimeout")) continue;
                if (!java.util.Set.of("connectTimeout", "socketTimeout").contains(name)
                        || !configuredTimeouts.add(name) || pair.length != 2) {
                    throw new IllegalArgumentException("JDBC timeouts require unique canonical parameter names");
                }
                String value = java.net.URLDecoder.decode(pair[1], java.nio.charset.StandardCharsets.UTF_8);
                try {
                    if (!value.matches("[0-9]+") || Integer.parseInt(value) <= 0) throw new NumberFormatException();
                } catch (NumberFormatException invalid) {
                    throw new IllegalArgumentException("JDBC connect/socket timeouts must be positive integer seconds");
                }
            }
        }
        String bounded = jdbcUrl;
        String separator = jdbcUrl.contains("?") ? "&" : "?";
        if (!configuredTimeouts.contains("connectTimeout")) {
            bounded += separator + "connectTimeout=10";
            separator = "&";
        }
        if (!configuredTimeouts.contains("socketTimeout")) {
            bounded += separator + "socketTimeout=30";
        }
        return bounded;
    }

    private record TenantSchema(UUID tenantId, String schemaName, String status) {
    }

    private record BootstrapResult(boolean success, List<Phase> phases) {
    }

    private record Phase(String name, boolean success, String message) {
        static Phase success(String name, String message) {
            return new Phase(name, true, sanitize(message));
        }

        static Phase failed(String name, String message) {
            return new Phase(name, false, sanitize(message));
        }
    }

    private static class BootstrapFailure extends RuntimeException {
        private final String code;

        BootstrapFailure(String code, String message) {
            super(message);
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    private static String required(String name) {
        if (System.getProperties().containsKey(name)) {
            return System.getProperty(name, "");
        }
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }

    private static String env(String name, String defaultValue) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            value = System.getenv(name);
        }
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static String requiredWithFallback(String name, String fallbackName) {
        String value = env(name, "");
        if (!value.isBlank()) {
            return value;
        }
        return required(fallbackName);
    }

    private static int integerEnv(String name, int defaultValue, int minimum, int maximum) {
        String rawValue = env(name, Integer.toString(defaultValue));
        try {
            int value = Integer.parseInt(rawValue);
            if (value < minimum || value > maximum) {
                throw new IllegalStateException(
                        name + " must be between " + minimum + " and " + maximum);
            }
            return value;
        } catch (NumberFormatException ex) {
            throw new IllegalStateException(name + " must be an integer", ex);
        }
    }
}
