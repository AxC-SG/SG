package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AuditEventService {
    public static final List<String> PLATFORM_USER_AUDIT_ACTIONS = List.of(
            "platform.user.role.granted",
            "platform.user.role.revoked",
            "platform.user.setup_issued",
            "platform.user.setup_completed",
            "tenant.deleted",
            "tenant.delete_failed",
            "tenant.delete.requested",
            "tenant.provisioning.requested",
            "tenant.owner.credential_provisioned",
            "tenant.owner.credential_recovered"
    );

    private final AuditEventRepository auditEventRepository;
    private final TenantRepository tenantRepository;
    private final RequestActorService requestActorService;
    private final TransactionTemplate platformAuditTransactions;

    /** Constructor used by focused unit tests that do not start Spring transactions. */
    public AuditEventService(
            AuditEventRepository auditEventRepository,
            TenantRepository tenantRepository,
            RequestActorService requestActorService
    ) {
        this.auditEventRepository = auditEventRepository;
        this.tenantRepository = tenantRepository;
        this.requestActorService = requestActorService;
        this.platformAuditTransactions = null;
    }

    @Autowired
    public AuditEventService(
            AuditEventRepository auditEventRepository,
            TenantRepository tenantRepository,
            RequestActorService requestActorService,
            @Qualifier("transactionManager") PlatformTransactionManager transactionManager
    ) {
        this.auditEventRepository = auditEventRepository;
        this.tenantRepository = tenantRepository;
        this.requestActorService = requestActorService;
        this.platformAuditTransactions = new TransactionTemplate(transactionManager);
        this.platformAuditTransactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public void record(String action, String targetType, String targetId, String detailsJson) {
        record(action, targetType, targetId, detailsJson, "SUCCESS");
    }

    public void record(String action, String targetType, String targetId, String detailsJson, String outcome) {
        RequestActor actor = requestActorService.currentActor();
        Runnable persist = () -> persistEvent(
                resolveTenantId(actor, action),
                actor.userId(),
                actor.roles().stream().findFirst().orElse(null),
                action,
                targetType,
                targetId,
                detailsJson,
                outcome);
        if (PLATFORM_USER_AUDIT_ACTIONS.contains(action)) {
            TenantContext.runAsPreAuthentication(() -> executePlatformAudit(persist));
        } else {
            persist.run();
        }
    }

    public void recordExplicitActor(
            UUID tenantId,
            String actorSubject,
            String actorRole,
            String action,
            String targetType,
            String targetId,
            String detailsJson,
            String outcome
    ) {
        if (PLATFORM_USER_AUDIT_ACTIONS.contains(action)) {
            TenantContext.runAsPreAuthentication(() -> executePlatformAudit(() -> persistEvent(
                    null, actorSubject, actorRole, action, targetType, targetId, detailsJson, outcome)));
        } else {
            persistEvent(tenantId, actorSubject, actorRole, action, targetType, targetId, detailsJson, outcome);
        }
    }

    private void executePlatformAudit(Runnable persist) {
        if (platformAuditTransactions == null) {
            persist.run();
            return;
        }
        platformAuditTransactions.executeWithoutResult(status -> persist.run());
    }

    private void persistEvent(
            UUID tenantId,
            String actorSubject,
            String actorRole,
            String action,
            String targetType,
            String targetId,
            String detailsJson,
            String outcome
    ) {
        AuditEvent event = new AuditEvent();
        if (tenantId != null) {
            tenantRepository.findById(tenantId).ifPresent(event::setTenant);
        }
        event.setActorSubject(actorSubject);
        event.setActorRole(actorRole);
        event.setAction(action);
        event.setTargetType(targetType);
        event.setTargetId(targetId);
        event.setDetailsJson(detailsJson);
        event.setOutcome(outcome);
        event.setRequestId(MDC.get("requestId"));
        auditEventRepository.save(event);
    }

    private UUID resolveTenantId(RequestActor actor, String action) {
        if (actor == null) {
            return null;
        }
        if (PLATFORM_USER_AUDIT_ACTIONS.contains(action)) {
            return null;
        }
        return actor.tenantId();
    }

    @Transactional
    public void recordTenantExposureRefresh(Tenant tenant, String endpoint, TenantExposureRefreshResponse response) {
        OrgSpecificCveExposureRecomputeResponse refresh = response == null ? null : response.refresh();
        String detailsJson = "{"
                + "\"operation\":\"tenant_exposure_refresh\","
                + "\"source\":\"central_vulnerability_repository\","
                + "\"endpoint\":\"" + escapeJson(endpoint) + "\","
                + "\"status\":\"" + escapeJson(response == null ? null : response.status()) + "\","
                + "\"message\":\"" + escapeJson(response == null ? null : response.message()) + "\","
                + "\"refreshScope\":\"" + escapeJson(refresh == null ? null : refresh.scope()) + "\","
                + "\"activeComponentCount\":" + number(refresh == null ? null : refresh.activeComponentCount()) + ","
                + "\"correlatedExposureCount\":" + number(refresh == null ? null : refresh.correlatedExposureCount()) + ","
                + "\"stateRowsChanged\":" + number(refresh == null ? null : refresh.stateRowsChanged()) + ","
                + "\"exposureStateRowCount\":" + number(refresh == null ? null : refresh.exposureStateRowCount()) + ","
                + "\"openFindingsCount\":" + number(refresh == null ? null : refresh.openFindingsCount()) + ","
                + "\"refreshedAt\":\"" + escapeJson(response == null || response.refreshedAt() == null ? null : response.refreshedAt().toString()) + "\""
                + "}";
        record("tenant.org_cves.refresh", "tenant", tenant == null ? null : tenant.getId().toString(), detailsJson);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> listForTenant(UUID tenantId) {
        return auditEventRepository.findTop100ByTenantIdOrderByOccurredAtDesc(tenantId);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> listAllForTenant(UUID tenantId) {
        return auditEventRepository.findByTenantIdOrderByOccurredAtDesc(tenantId);
    }

    @Transactional(readOnly = true)
    public List<AuditEvent> listPlatformUserEvents() {
        return auditEventRepository.findByTenantIsNullAndTargetTypeAndActionInOrderByOccurredAtDesc(
                "app_user",
                PLATFORM_USER_AUDIT_ACTIONS
        );
    }

    public String toCsv(List<AuditEvent> events) {
        StringBuilder csv = new StringBuilder("occurredAt,tenantId,actorSubject,actorRole,action,targetType,targetId,outcome,requestId,detailsJson\n");
        for (AuditEvent event : events) {
            csv.append(csv(event.getOccurredAt()))
                    .append(',')
                    .append(csv(event.getTenant() == null ? null : event.getTenant().getId()))
                    .append(',')
                    .append(csv(event.getActorSubject()))
                    .append(',')
                    .append(csv(event.getActorRole()))
                    .append(',')
                    .append(csv(event.getAction()))
                    .append(',')
                    .append(csv(event.getTargetType()))
                    .append(',')
                    .append(csv(event.getTargetId()))
                    .append(',')
                    .append(csv(event.getOutcome()))
                    .append(',')
                    .append(csv(event.getRequestId()))
                    .append(',')
                    .append(csv(event.getDetailsJson()))
                    .append('\n');
        }
        return csv.toString();
    }

    @Transactional(readOnly = true)
    public Map<String, Object> supportBundle(UUID tenantId) {
        List<AuditEvent> events = listForTenant(tenantId);
        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("generatedAt", Instant.now());
        bundle.put("tenantId", tenantId);
        bundle.put("recentAuditEventCount", events.size());
        bundle.put("recentAuditEvents", events.stream().map(event -> Map.of(
                "occurredAt", event.getOccurredAt(),
                "actorSubject", nullToEmpty(event.getActorSubject()),
                "action", nullToEmpty(event.getAction()),
                "targetType", nullToEmpty(event.getTargetType()),
                "targetId", nullToEmpty(event.getTargetId()),
                "outcome", nullToEmpty(event.getOutcome()),
                "requestId", nullToEmpty(event.getRequestId())
        )).toList());
        return bundle;
    }

    private String number(Number value) {
        return value == null ? "null" : value.toString();
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String csv(Object value) {
        String text = value == null ? "" : value.toString();
        int firstMeaningful = 0;
        while (firstMeaningful < text.length()
                && isSpreadsheetIgnorablePrefix(text.charAt(firstMeaningful))) {
            firstMeaningful++;
        }
        boolean controlPrefix = !text.isEmpty() && (text.charAt(0) == '\t'
                || text.charAt(0) == '\r' || text.charAt(0) == '\n');
        boolean formulaPrefix = firstMeaningful < text.length()
                && "=+-@".indexOf(text.charAt(firstMeaningful)) >= 0;
        if (controlPrefix || formulaPrefix) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private static boolean isSpreadsheetIgnorablePrefix(char value) {
        return Character.isWhitespace(value) || Character.isSpaceChar(value)
                || Character.isISOControl(value) || value == '\uFEFF' || value == '\u200B';
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
