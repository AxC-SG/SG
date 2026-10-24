package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class DemoTenantPurgeService {

    private static final int PURGE_ERROR_MAX_LENGTH = 2000;
    private static final int FAILURE_AUDIT_ERROR_MAX_LENGTH = 512;

    private final TenantRepository tenantRepository;
    private final AppUserRepository appUserRepository;
    private final JdbcTemplate resetJdbcTemplate;
    private final AuditEventService auditEventService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSchemaService tenantSchemaService;
    private final DemoTenantPurgePlanner demoTenantPurgePlanner;

    public DemoTenantPurgeService(
            TenantRepository tenantRepository,
            AppUserRepository appUserRepository,
            @Qualifier("prototypeResetJdbcTemplate")
            JdbcTemplate resetJdbcTemplate,
            AuditEventService auditEventService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSchemaService tenantSchemaService,
            DemoTenantPurgePlanner demoTenantPurgePlanner
    ) {
        this.tenantRepository = tenantRepository;
        this.appUserRepository = appUserRepository;
        this.resetJdbcTemplate = resetJdbcTemplate;
        this.auditEventService = auditEventService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSchemaService = tenantSchemaService;
        this.demoTenantPurgePlanner = demoTenantPurgePlanner;
    }

    @Transactional
    public void processExpiredTenant(UUID tenantId, Instant now) {
        // Re-read eligibility under the registry lock. Competing sweeps and
        // expiry extensions serialize here; the transition and audit commit together.
        Tenant tenant = tenantRepository.findByIdForUpdate(tenantId).orElse(null);
        if (!demoTenantPurgePlanner.isEligibleForAutomaticPurge(tenant, now)) {
            return;
        }
        if (tenant.getExpiredAt() != null) {
            return;
        }
        markExpired(tenant, now);
    }

    public void deleteTenant(UUID tenantId, Instant now) {
        ManualTenantDeletionPolicy.requirePermitted();
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Unknown tenant: " + tenantId));
        if (tenant.isInternal()) {
            throw new ResponseStatusException(BAD_REQUEST, "Default workspace cannot be deleted");
        }
        if (tenant.getPurgedAt() != null || "DELETED".equalsIgnoreCase(tenant.getStatus())) {
            return;
        }
        purgeTenantInternal(tenant, now, normalizedFailureStatus(tenant), "tenant.deleted", "tenant.delete_failed");
    }

    private void purgeTenantInternal(
            Tenant tenant,
            Instant now,
            String failureStatus,
            String successAuditAction,
            String failureAuditAction
    ) {
        List<UUID> memberUserIds = resetJdbcTemplate.query(
                "select distinct user_id from platform.tenant_memberships where tenant_id = ?",
                (rs, rowNum) -> UUID.fromString(rs.getString(1)),
                tenant.getId());

        tenant.setStatus("PURGING");
        tenant.setPurgeStatus("IN_PROGRESS");
        tenant.setPurgeStartedAt(tenant.getPurgeStartedAt() == null ? now : tenant.getPurgeStartedAt());
        tenant.setPurgeError(null);
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);

        try {
            purgeTenantRows(tenant);
            scrubDemoUserCredentials(memberUserIds, now);
            auditEventService.record(successAuditAction, "tenant", tenant.getId().toString(), null);
            deleteTenantRegistryRow(tenant.getId());
        } catch (RuntimeException ex) {
            updateTenantFailureState(tenant, failureStatus, ex);
            auditEventService.record(
                    failureAuditAction,
                    "tenant",
                    tenant.getId().toString(),
                    "{\"error\":\"" + escapeJson(truncate(ex.getMessage(), FAILURE_AUDIT_ERROR_MAX_LENGTH)) + "\"}");
            throw new ResponseStatusException(BAD_REQUEST, "Tenant delete failed: " + truncate(ex.getMessage(), 500), ex);
        }
    }

    private void markExpired(Tenant tenant, Instant now) {
        if (tenant.getExpiredAt() == null) {
            tenant.setExpiredAt(now);
        }
        if ("ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            tenant.setStatus("EXPIRED");
        }
        if (tenant.getSuspendedAt() == null) {
            tenant.setSuspendedAt(now);
        }
        tenant.setUpdatedAt(now);
        tenantRepository.save(tenant);
        auditEventService.record("demo.tenant.expired", "tenant", tenant.getId().toString(), null);
    }

    private void purgeTenantRows(Tenant tenant) {
        UUID tenantId = tenant.getId();
        // Only the schema owner or a superuser may perform this cleanup. The
        // permanent production web service uses a restricted runtime role, while
        // owner-controlled local/integration runs can still remove their schemas.
        if (tenantSchemaService.canDropTenantSchema(tenant.getSchemaName())) {
            tenantSchemaService.dropTenantSchema(tenant.getSchemaName());
        }
        purgeSharedTenantRows(tenantId);
        purgeDemoLifecycleRows(tenantId);
    }

    private void purgeDemoLifecycleRows(UUID tenantId) {
        // These shared lifecycle tables live outside platform, so platform FK
        // discovery cannot find them. The raw pool still enforces invite RLS;
        // scope cleanup to the deleted tenant on the same connection and restore
        // its previous context before returning it to the pool.
        resetJdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            String previousTenantId;
            try (PreparedStatement statement = connection.prepareStatement(
                    "select current_setting('app.current_tenant_id', true)");
                 ResultSet result = statement.executeQuery()) {
                result.next();
                previousTenantId = result.getString(1);
            }
            try (PreparedStatement context = connection.prepareStatement(
                    "select set_config('app.current_tenant_id', ?, false)")) {
                try {
                    context.setString(1, tenantId.toString());
                    context.execute();
                    try (PreparedStatement invites = connection.prepareStatement(
                            "delete from tenant_default.demo_invites where tenant_id = ?");
                         PreparedStatement requests = connection.prepareStatement(
                            "update tenant_default.demo_requests set tenant_id = null where tenant_id = ?")) {
                        invites.setObject(1, tenantId);
                        invites.executeUpdate();
                        requests.setObject(1, tenantId);
                        requests.executeUpdate();
                    }
                } finally {
                    context.setString(1, previousTenantId == null ? "" : previousTenantId);
                    context.execute();
                }
            }
            return null;
        });
    }

    private void deleteTenantRegistryRow(UUID tenantId) {
        resetJdbcTemplate.update("delete from platform.tenants where id = ?", tenantId);
    }

    private void purgeSharedTenantRows(UUID tenantId) {
        // Memberships are the direct tenant dependency that must be removed
        // before the registry row. Keep this explicit even if metadata-based
        // discovery is incomplete under a restricted production role.
        resetJdbcTemplate.update(
                "delete from platform.tenant_memberships where tenant_id = ?",
                tenantId);
        // information_schema.constraint_column_usage hides referenced columns
        // from non-owner roles. PostgreSQL catalogs also expose these FKs to the
        // restricted runtime role that performs deletion in production.
        List<String> tableNames = resetJdbcTemplate.queryForList("""
                select distinct format('%I.%I', namespace.nspname, dependent.relname)
                from pg_constraint fk
                join pg_class dependent on dependent.oid = fk.conrelid
                join pg_namespace namespace on namespace.oid = dependent.relnamespace
                join pg_attribute column_info
                  on column_info.attrelid = dependent.oid
                 and column_info.attnum = any(fk.conkey)
                where fk.contype = 'f'
                  and fk.confrelid = 'platform.tenants'::regclass
                  and namespace.nspname = 'platform'
                  and column_info.attname = 'tenant_id'
                order by 1 desc
                """, String.class);
        for (String tableName : tableNames) {
            if (!hasText(tableName)
                    || "platform.tenants".equalsIgnoreCase(tableName)
                    || "platform.tenant_memberships".equalsIgnoreCase(tableName)) {
                continue;
            }
            resetJdbcTemplate.update("delete from " + tableName + " where tenant_id = ?", tenantId);
        }
    }

    private void scrubDemoUserCredentials(List<UUID> userIds, Instant now) {
        for (UUID userId : userIds) {
            Integer remainingMemberships = resetJdbcTemplate.queryForObject(
                    "select count(*) from platform.tenant_memberships where user_id = ?",
                    Integer.class,
                    userId
            );
            boolean deactivateUser = remainingMemberships != null && remainingMemberships == 0;
            appUserRepository.findById(userId).ifPresent(user -> {
                if (user.isPlatformOwner()) {
                    return;
                }
                user.setPasswordHash(null);
                user.setPasswordSetAt(null);
                user.setPasswordSetupTokenHash(null);
                user.setPasswordSetupTokenExpiresAt(null);
                if (deactivateUser) {
                    user.setStatus("INACTIVE");
                }
                user.setUpdatedAt(now);
                appUserRepository.save(user);
            });
        }
    }

    private String truncate(String value, int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return value;
        }
        return value.substring(0, maxLength);
    }

    private String escapeJson(String value) {
        return value == null ? ""
                : value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String normalizedFailureStatus(Tenant tenant) {
        if (tenant == null || tenant.getStatus() == null || tenant.getStatus().isBlank()) {
            return "ACTIVE";
        }
        return tenant.getStatus().trim().toUpperCase();
    }

    private void updateTenantFailureState(Tenant tenant, String failureStatus, RuntimeException ex) {
        if (tenant == null || tenant.getId() == null || !tenantRepository.existsById(tenant.getId())) {
            return;
        }
        tenant.setStatus(failureStatus);
        tenant.setPurgeStatus("FAILED");
        tenant.setPurgeError(truncate(ex.getMessage(), PURGE_ERROR_MAX_LENGTH));
        tenant.setUpdatedAt(Instant.now());
        tenantRepository.save(tenant);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

}
