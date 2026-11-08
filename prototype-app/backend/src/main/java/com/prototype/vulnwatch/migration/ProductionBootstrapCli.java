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
    private static final String DEFAULT_TENANT_NAME = "SG Internal";
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
            var onboarding = StandardRequestOnboarding.Command.parse(args);
            var standardRequest = onboarding == null ? StandardTenantEnrollment.Request.parse(args) : null;
            Config config = validatedConfig();
            if ((onboarding != null || standardRequest != null) && (config.reportOnly() || config.platformOwnerBootstrapEnabled()
                    || config.managedOperators() != null)) {
                throw new BootstrapFailure("conflicting_modes",
                        "Standard tenant provisioning requires a task without installation or report-only inputs");
            }
            try (Connection connection = ownerConnection(config)) {
                verifyOwnerPreflight(connection, config);
                phases.add(Phase.success("database_preflight", "configuration and connectivity verified"));
                acquireLock(connection);
                try {
                    if (onboarding != null) {
                        runStandardOnboarding(connection, config, onboarding, runId, phases);
                    } else if (standardRequest != null) {
                        provisionStandardTenant(connection, config, standardRequest, runId, phases);
                    } else if (config.reportOnly()) {
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("report_only_owner_verification", "complete"));
                    } else {
                        int platformVersion = runPlatformMigrations(config);
                        StandardTenantEnrollment.configure(connection, config.standardCustomerLimit());
                        provisionRuntimeRole(connection, config);
                        phases.add(Phase.success("platform_migrations", "version=" + platformVersion));
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
                        provisionRuntimeRole(connection, config);
                        phases.add(Phase.success("runtime_role_provisioning", config.runtimeDbUsername()));
                        verifyControlPlane(connection, config.runtimeDbUsername());
                        phases.add(Phase.success("owner_verification", "complete"));
                        if (config.platformOwnerBootstrapEnabled() || config.managedOperators() != null) {
                            String result = bootstrapInstallationIdentities(connection, config, defaultTenant.tenantId());
                            phases.add(Phase.success("installation_identities", result));
                        }
                    }
                    if (standardRequest == null && onboarding == null) {
                        verifyRuntimeConnection(config);
                    }
                } finally {
                    releaseLock(connection);
                }
            }
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

    private static void runStandardOnboarding(Connection connection, Config config,
            StandardRequestOnboarding.Command command, UUID runId, List<Phase> phases) throws Exception {
        if (platformVersion(connection) != MIGRATION_TARGETS.platformTarget() || !ManagedOperatorEnrollment.exists(connection)) {
            throw new BootstrapFailure("standard_onboarding_preflight", "Run the matching managed Standard bootstrap first");
        }
        StandardTenantEnrollment.requireCapacityPolicy(connection, config.standardCustomerLimit());
        String issuer = env("APP_JWT_ISSUER_URI", "");
        if (!issuer.matches("https://cognito-idp\\.([a-z0-9-]+)\\.amazonaws\\.com/\\1_[A-Za-z0-9]+")
                || queryLong(connection, """
                    select count(*) from platform.managed_operator_enrollment e
                    join platform.managed_identities i on i.id in (e.owner_binding_id, e.admin_binding_id)
                    where i.issuer = ?
                    """, issuer) == 0) {
            throw new BootstrapFailure("standard_onboarding_preflight", "Standard onboarding requires the configured Cognito issuer");
        }
        if (command.action() == StandardRequestOnboarding.Action.PROVISION) {
            var request = StandardRequestOnboarding.load(connection, command.requestId());
            try {
                provisionStandardTenant(connection, config, request.workspace(), runId, phases);
            } catch (Exception failure) {
                try {
                    StandardRequestOnboarding.recordProvisioning(connection, request, false);
                } catch (SQLException recordFailure) {
                    failure.addSuppressed(recordFailure);
                }
                throw new BootstrapFailure("standard_request_provisioning_failed", "Inspect the task and retry the approved request");
            }
            StandardRequestOnboarding.recordProvisioning(connection, request, true);
            return;
        }
        StandardRequestOnboarding.finish(connection, command, issuer, MIGRATION_TARGETS.tenantTarget());
        String phase = switch (command.action()) {
            case LINK_ADMIN -> "standard_admin_link_verified";
            case RECORD_EMAIL -> "standard_setup_submission_recorded";
            case RECORD_EMAIL_FAILURE -> "standard_setup_failure_recorded";
            case PROVISION -> throw new IllegalStateException("Workspace provisioning was already handled");
        };
        phases.add(Phase.success(phase, "request_id=" + command.requestId()));
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
        return new PlatformOwnerSetupLinkIssuer(emailClient,
                new com.prototype.vulnwatch.service.CredentialEncryptionService(
                        config.credentialEncryptionKey(), config.credentialEncryptionKeyId(), ""));
    }

    private static String bootstrapInstallationIdentities(Connection connection, Config config, UUID tenantId) throws SQLException {
        boolean original = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            String result;
            if (config.managedOperators() != null) {
                boolean enrolled = ManagedOperatorEnrollment.enroll(connection, config.managedOperators(), tenantId);
                result = enrolled ? "managed operator links committed" : "recorded managed operator links verified";
            } else {
                if (ManagedOperatorEnrollment.exists(connection)) {
                    throw new IllegalStateException("Local setup is unavailable on a managed operator installation");
                }
                bootstrapLocalInstallationIdentities(connection, config, tenantId);
                result = "verified; setup delivery intents committed";
            }
            connection.commit();
            return result;
        } catch (SQLException failure) {
            connection.rollback();
            if (config.managedOperators() != null) {
                throw new BootstrapFailure("managed_operator_enrollment_failed", "Managed operator enrollment database operation failed");
            }
            throw failure;
        } catch (RuntimeException failure) {
            connection.rollback();
            throw failure;
        } finally {
            connection.setAutoCommit(original);
        }
    }

    private static void bootstrapLocalInstallationIdentities(Connection connection, Config config, UUID tenantId) throws SQLException {
        String ownerEmail = config.platformOwnerBootstrapEmail().trim().toLowerCase(java.util.Locale.ROOT);
        String adminEmail = config.internalAdminEmail().trim().toLowerCase(java.util.Locale.ROOT);
        if (ownerEmail.equals(adminEmail)) {
            throw new IllegalArgumentException("Owner and internal administrator require distinct email aliases");
        }
        UUID owner = reconcileIdentity(connection, ownerEmail, config.platformOwnerBootstrapExternalSubject(), true, tenantId);
        UUID admin = reconcileIdentity(connection, adminEmail, adminEmail, false, tenantId);
        PlatformOwnerSetupLinkIssuer issuer = platformOwnerSetupLinkIssuer(config);
        issuer.enqueue(connection, owner, null, "PLATFORM_OWNER_SETUP", ownerEmail,
                config.platformOwnerSetupAppBaseUrl(), config.platformOwnerSetupTokenTtlMinutes(), config.platformOwnerSetupAllowReissue());
        issuer.enqueue(connection, admin, tenantId, "INTERNAL_ADMIN_SETUP", adminEmail,
                config.platformOwnerSetupAppBaseUrl(), config.platformOwnerSetupTokenTtlMinutes(), config.internalAdminSetupAllowReissue());
        recordInstallationAudit(connection, tenantId, owner, admin, "LOCAL");
    }

    static void recordInstallationAudit(Connection connection, UUID tenantId, UUID owner, UUID admin, String mode) throws SQLException {
        try (var audit = connection.prepareStatement("""
                insert into platform.intelligence_audit_events (id, action, actor, detail)
                values (?, 'INSTALLATION_VERIFIED', 'system:installation',
                    jsonb_build_object('ownerId', ?::text, 'internalAdminId', ?::text, 'tenantId', ?::text, 'mode', ?::text))
                """)) {
            audit.setObject(1, UUID.randomUUID());
            audit.setString(2, owner.toString());
            audit.setString(3, admin.toString());
            audit.setString(4, tenantId.toString());
            audit.setString(5, mode);
            audit.executeUpdate();
        }
    }

    static UUID reconcileIdentity(Connection connection, String email, String subject, boolean owner, UUID tenantId) throws SQLException {
        if (subject == null || subject.isBlank()) subject = email;
        UUID bySubject = findUserBySubject(connection, subject);
        UUID byEmail = findUserByEmail(connection, email);
        if (bySubject != null && byEmail != null && !bySubject.equals(byEmail))
            throw new IllegalStateException("Configured subject and email match different identities");
        UUID id = bySubject != null ? bySubject : byEmail;
        if (id != null) {
            try (var select = connection.prepareStatement("select email,external_subject,platform_owner,status from platform.app_users where id=? for update")) {
                select.setObject(1,id);
                try (var row=select.executeQuery()) {
                    if (!row.next() || !email.equalsIgnoreCase(row.getString(1)) || !subject.equals(row.getString(2))
                            || owner != row.getBoolean(3) || !"ACTIVE".equals(row.getString(4)))
                        throw new IllegalStateException("Existing identity conflicts with installation authority");
                }
            }
            try (var select=connection.prepareStatement("select tenant_id,role,status,provenance from platform.tenant_memberships where user_id=?")) {
                select.setObject(1,id);
                try (var rows=select.executeQuery()) {
                    while(rows.next()) {
                        boolean retiredBridge="PLAYGROUND_BOOTSTRAP".equals(rows.getString(4)) && !"ACTIVE".equals(rows.getString(3));
                        boolean validAdmin=!owner && tenantId.equals(rows.getObject(1,UUID.class)) && "TENANT_ADMIN".equals(rows.getString(2))
                                && "ACTIVE".equals(rows.getString(3)) && "INSTALLATION_BOOTSTRAP".equals(rows.getString(4));
                        if (!retiredBridge && !validAdmin) throw new IllegalStateException("Existing identity has conflicting tenant membership");
                    }
                }
            }
            try(var select=connection.prepareStatement("select role from platform.app_user_global_roles where app_user_id=?")) {
                select.setObject(1,id);
                try(var rows=select.executeQuery()) {
                    while(rows.next()) if(!owner || !"PLATFORM_OWNER".equals(rows.getString(1)))
                        throw new IllegalStateException("Existing identity has conflicting global authority");
                }
            }
        } else {
            id=UUID.randomUUID();
            try(var insert=connection.prepareStatement("insert into platform.app_users(id,created_at,updated_at,display_name,email,external_subject,platform_owner,status) values(?,now(),now(),?,?,?,?, 'ACTIVE')")) {
                insert.setObject(1,id); insert.setString(2,email); insert.setString(3,email); insert.setString(4,subject); insert.setBoolean(5,owner); insert.executeUpdate();
            }
        }
        if(owner) {
            try(var insert=connection.prepareStatement("insert into platform.app_user_global_roles(id,app_user_id,role,created_at) values(?,?,'PLATFORM_OWNER',now()) on conflict(app_user_id,role) do nothing")) {
                insert.setObject(1,UUID.randomUUID());insert.setObject(2,id);insert.executeUpdate();
            }
        } else {
            try(var insert=connection.prepareStatement("insert into platform.tenant_memberships(id,user_id,tenant_id,role,status,provenance,created_at,updated_at) values(?,?,?,'TENANT_ADMIN','ACTIVE','INSTALLATION_BOOTSTRAP',now(),now()) on conflict do nothing")) {
                insert.setObject(1,UUID.randomUUID());insert.setObject(2,id);insert.setObject(3,tenantId);insert.executeUpdate();
            }
        }
        return id;
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
        try (var select=connection.prepareStatement("select id,schema_name,classification from platform.tenants where schema_name=? or classification='INTERNAL'")) {
            select.setString(1,DEFAULT_TENANT_SCHEMA);
            try(var row=select.executeQuery()) {
                if(row.next()) {
                    UUID id=row.getObject(1,UUID.class);
                    if(!DEFAULT_TENANT_SCHEMA.equals(row.getString(2)) || !"INTERNAL".equals(row.getString(3)) || row.next())
                        throw new IllegalStateException("Conflicting SG Internal schema mapping");
                    return new TenantSchema(id,DEFAULT_TENANT_SCHEMA,"ACTIVE");
                }
            }
        }
        try(var insert=connection.prepareStatement("""
                insert into platform.tenants(id,name,slug,schema_name,classification,status,plan_code,created_at,updated_at,
                    max_connector_count,max_service_account_count,max_daily_sbom_uploads,max_export_rows,max_daily_exposure_refreshes)
                values(?,?,?,?,'INTERNAL','ACTIVE','ENTERPRISE',now(),now(),1000,1000,10000,1000000,10000)
                """)) {
            insert.setObject(1,DEFAULT_TENANT_ID);insert.setString(2,DEFAULT_TENANT_NAME);insert.setString(3,DEFAULT_TENANT_SLUG);
            insert.setString(4,DEFAULT_TENANT_SCHEMA);insert.executeUpdate();
        }
        return new TenantSchema(DEFAULT_TENANT_ID,DEFAULT_TENANT_SCHEMA,"ACTIVE");
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

        if (config.standardCustomerLimit() != 0) {
            return new BootstrapResult(true, phases);
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

    private static void provisionStandardTenant(
            Connection connection, Config config, StandardTenantEnrollment.Request request, UUID runId,
            List<Phase> phases
    ) throws Exception {
        if (platformVersion(connection) != MIGRATION_TARGETS.platformTarget()) {
            throw new BootstrapFailure("platform_target_mismatch", "Run the matching Standard bootstrap first");
        }
        StandardTenantEnrollment.requireCapacityPolicy(connection, config.standardCustomerLimit());
        String status = StandardTenantEnrollment.reserve(connection, request, config.standardCustomerLimit());
        var tenant = new TenantSchema(request.id(), request.schema(), status);
        phases.add(Phase.success("standard_tenant_reserved", "tenant_id=" + request.id()));
        if ("ACTIVE".equals(status)) {
            verifyActiveTenantSchemaState(connection);
            verifyStandardRuntime(config, tenant);
            phases.add(Phase.success("standard_tenant_already_active", "tenant_id=" + request.id()));
            return;
        }
        try {
            if (queryLong(connection, "select count(*) from pg_namespace where nspname = ?", tenant.schemaName()) != 1) {
                throw new BootstrapFailure("standard_schema_missing", "The reserved tenant schema is missing");
            }
            migrateTenant(config, tenant);
            String checksum = fingerprint(connection, tenant.schemaName());
            if (!checksum.equals(fingerprint(connection, DEFAULT_TENANT_SCHEMA))) {
                throw new BootstrapFailure("tenant_schema_drift", "Reserved schema differs from SG Internal");
            }
            grantAndVerifySchema(connection, config.runtimeDbUsername(), tenant.schemaName());
            verifyStandardRuntime(config, tenant);
            StandardTenantEnrollment.requireCapacityPolicy(connection, config.standardCustomerLimit());
            finishStandardProvisioning(connection, tenant, checksum, runId);
        } catch (Exception ex) {
            try {
                finishStandardProvisioning(connection, tenant, null, runId);
            } catch (SQLException recordFailure) {
                ex.addSuppressed(recordFailure);
            }
            throw ex;
        }
        phases.add(Phase.success("standard_tenant_activated", "tenant_id=" + request.id()));
    }

    private static void finishStandardProvisioning(Connection connection, TenantSchema tenant, String checksum, UUID runId)
            throws SQLException {
        connection.setAutoCommit(false);
        try (var statement = connection.prepareStatement("""
                update platform.tenants set status = ?, updated_at = now()
                where id = ? and schema_name = ? and deleted_at is null and classification = 'CUSTOMER'
                  and status in ('PROVISIONING', 'PROVISIONING_FAILED')
                """)) {
            statement.setString(1, checksum == null ? "PROVISIONING_FAILED" : "ACTIVE");
            statement.setObject(2, tenant.tenantId());
            statement.setString(3, tenant.schemaName());
            if (statement.executeUpdate() != 1) {
                throw new SQLException("Standard tenant reservation changed before completion");
            }
            if (checksum == null) {
                markFailure(connection, tenant, "PROVISIONING_FAILED", "STANDARD_PROVISIONING_FAILED",
                        "Inspect the exit-once task report and retry the same reservation.", runId);
            } else {
                markCurrent(connection, tenant, checksum, runId);
            }
            connection.commit();
        } catch (SQLException ex) {
            connection.rollback();
            throw ex;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private static void verifyStandardRuntime(Config config, TenantSchema tenant) throws SQLException {
        try (Connection connection = runtimeConnection(config)) {
            verifyRuntimeDdlDenied(connection);
            String budgetCount = "select count(*) from " + quotedIdentifier(tenant.schemaName()) + ".ai_grid_budget_config";
            requireZero(connection, budgetCount, "tenant rows visible without tenant context");
            try (var context = connection.prepareStatement("select set_config('app.current_tenant_id', ?, false)")) {
                context.setString(1, tenant.tenantId().toString());
                context.execute();
            }
            if (queryLong(connection, budgetCount + " where tenant_id = ?", tenant.tenantId()) != 1) {
                throw new BootstrapFailure("verification_failed", "Runtime cannot read the reserved tenant budget seed");
            }
        }
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

    private static void provisionRuntimeRole(Connection connection, Config config) throws SQLException {
        String role = config.runtimeDbUsername();
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
            String connectionLimit = config.runtimeDbConnectionLimit() == 0
                    ? "" : " connection limit " + config.runtimeDbConnectionLimit();
            statement.execute("alter role " + quotedRole + " with login noinherit password "
                    + quotedLiteral(config.runtimeDbPassword()) + connectionLimit);
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
        try (Connection connection = runtimeConnection(config)) {
            verifyRuntimeDdlDenied(connection);
        }
    }

    private static Connection runtimeConnection(Config config) throws SQLException {
        Connection connection = DriverManager.getConnection(
                config.dbUrl(), config.runtimeDbUsername(), config.runtimeDbPassword());
        try {
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
            if (config.runtimeDbConnectionLimit() > 0) {
                requireZero(connection, """
                        select count(*) from pg_roles where rolname = current_user and rolconnlimit <> ?
                        """, "runtime connection limit does not match the Standard fleet budget",
                        config.runtimeDbConnectionLimit());
            }
            return connection;
        } catch (RuntimeException | SQLException ex) {
            connection.close();
            throw ex;
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
            int standardCustomerLimit,
            int runtimeDbConnectionLimit,
            boolean reportOnly,
            ManagedOperatorEnrollment.Spec managedOperators,
            boolean platformOwnerBootstrapEnabled,
            String platformOwnerBootstrapEmail,
            String platformOwnerBootstrapExternalSubject,
            String platformOwnerBootstrapDisplayName,
            boolean platformOwnerSetupLinkEnabled,
            String platformOwnerSetupEmail,
            String platformOwnerSetupAppBaseUrl,
            int platformOwnerSetupTokenTtlMinutes,
            boolean platformOwnerSetupAllowReissue,
            String internalAdminEmail,
            boolean internalAdminSetupAllowReissue,
            String credentialEncryptionKey,
            String credentialEncryptionKeyId,
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
            boolean reportOnly = Boolean.parseBoolean(env("BOOTSTRAP_REPORT_ONLY",
                    env("APP_SCHEMA_MIGRATION_REPORT_ONLY", "false")));
            var managedOperators = ManagedOperatorEnrollment.configured(name -> env(name, ""), ownerBootstrapEnabled, reportOnly);
            int standardCustomerLimit = switch (env("APP_STANDARD_CUSTOMER_LIMIT", "")) {
                case "" -> 0;
                case "3" -> 3;
                case "10" -> 10;
                default -> throw new IllegalArgumentException("APP_STANDARD_CUSTOMER_LIMIT must be 3 or 10");
            };
            int runtimeDbConnectionLimit = env("APP_STANDARD_RUNTIME_DB_CONNECTION_LIMIT", "").isEmpty() ? 0
                    : integerEnv("APP_STANDARD_RUNTIME_DB_CONNECTION_LIMIT", 1, 1, Integer.MAX_VALUE);
            if (runtimeDbConnectionLimit > 0 && standardCustomerLimit == 0) {
                throw new IllegalArgumentException("A runtime DB connection limit requires a Standard customer limit");
            }
            String ownerBootstrapEmail = ownerBootstrapEnabled
                    ? requiredWithFallback(
                            "PLATFORM_OWNER_SETUP_EMAIL",
                            "APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL")
                    : "";
            String internalAdminEmail = ownerBootstrapEnabled ? required("SG_INTERNAL_ADMIN_EMAIL") : "";
            if (ownerBootstrapEnabled && (ownerBootstrapEmail.equalsIgnoreCase(internalAdminEmail)
                    || !ownerBootstrapEmail.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")
                    || !internalAdminEmail.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+"))) {
                throw new IllegalArgumentException("Bootstrap requires two distinct valid email aliases");
            }
            int setupTokenTtlMinutes = integerEnv("PLATFORM_OWNER_SETUP_TOKEN_TTL_MINUTES", 30, 5, 1440);
            return new Config(
                    dbUrl,
                    required("DB_USERNAME"),
                    required("DB_PASSWORD"),
                    env("RUNTIME_DB_USERNAME", "scout_runtime"),
                    required("RUNTIME_DB_PASSWORD"),
                    env("EXPECTED_DB_NAME", databaseName(dbUrl)),
                    standardCustomerLimit,
                    runtimeDbConnectionLimit,
                    reportOnly,
                    managedOperators,
                    ownerBootstrapEnabled,
                    ownerBootstrapEmail,
                    env("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EXTERNAL_SUBJECT", ownerBootstrapEmail),
                    env("APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_DISPLAY_NAME", ownerBootstrapEmail),
                    setupLinkEnabled,
                    setupLinkEnabled ? ownerBootstrapEmail : "",
                    env("PLATFORM_OWNER_SETUP_APP_BASE_URL", env("APP_DEMO_APP_BASE_URL", "https://scoutgrid.io")),
                    setupTokenTtlMinutes,
                    Boolean.parseBoolean(env("PLATFORM_OWNER_SETUP_ALLOW_REISSUE", "false")),
                    internalAdminEmail,
                    Boolean.parseBoolean(env("SG_INTERNAL_ADMIN_SETUP_ALLOW_REISSUE","false")),
                    ownerBootstrapEnabled ? required("APP_CREDENTIAL_ENCRYPTION_KEY") : "",
                    env("APP_CREDENTIAL_ENCRYPTION_KEY_ID", "primary"),
                    env("RESEND_BASE_URL", "https://api.resend.com"),
                    env("RESEND_API_KEY", ""),
                    env("RESEND_FROM_EMAIL", ""),
                    env("RESEND_FROM_DOMAIN", "scoutgrid.io"));
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
