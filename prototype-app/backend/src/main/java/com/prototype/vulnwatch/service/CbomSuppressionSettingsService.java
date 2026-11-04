package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CbomTenantSettings;
import com.prototype.vulnwatch.dto.CbomSuppressionSettingsRequest;
import com.prototype.vulnwatch.dto.CbomSuppressionSettingsResponse;
import com.prototype.vulnwatch.repo.CbomTenantSettingsRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CbomSuppressionSettingsService {
    private final CbomTenantSettingsRepository repository;
    private final RequestActorService actorService;
    private final AuditEventService auditEventService;

    public CbomSuppressionSettingsService(
            CbomTenantSettingsRepository repository,
            RequestActorService actorService,
            AuditEventService auditEventService
    ) {
        this.repository = repository;
        this.actorService = actorService;
        this.auditEventService = auditEventService;
    }

    @Transactional(readOnly = true)
    public CbomSuppressionSettingsResponse get() {
        RequestActor actor = requireTenantAdmin();
        return response(repository.findById(actor.tenantId()).orElseGet(() -> defaults(actor)));
    }

    @Transactional
    public CbomSuppressionSettingsResponse update(CbomSuppressionSettingsRequest request) {
        RequestActor actor = requireTenantAdmin();
        CbomTenantSettings settings = repository.findById(actor.tenantId()).orElseGet(() -> defaults(actor));
        if (request.requireDistinctSuppressionApprover() != null) {
            settings.setRequireDistinctSuppressionApprover(request.requireDistinctSuppressionApprover());
        }
        settings.setSuppressionRequestDeadlineDays(shorter("suppressionRequestDeadlineDays",
                request.suppressionRequestDeadlineDays(), settings.getSuppressionRequestDeadlineDays(), 14));
        settings.setLowSuppressionMaxDays(shorter("lowSuppressionMaxDays",
                request.lowSuppressionMaxDays(), settings.getLowSuppressionMaxDays(), 365));
        settings.setMediumSuppressionMaxDays(shorter("mediumSuppressionMaxDays",
                request.mediumSuppressionMaxDays(), settings.getMediumSuppressionMaxDays(), 180));
        settings.setHighSuppressionMaxDays(shorter("highSuppressionMaxDays",
                request.highSuppressionMaxDays(), settings.getHighSuppressionMaxDays(), 90));
        settings.setCriticalSuppressionMaxDays(shorter("criticalSuppressionMaxDays",
                request.criticalSuppressionMaxDays(), settings.getCriticalSuppressionMaxDays(), 30));
        settings.setUpdatedBy(actor.userId());
        settings.touch();
        settings = repository.save(settings);
        auditEventService.record("cbom.suppression_settings.updated", "tenant", actor.tenantId().toString(),
                "{\"distinctApprover\":" + settings.isRequireDistinctSuppressionApprover() + "}");
        return response(settings);
    }

    private int shorter(String field, Integer requested, int current, int applicationMaximum) {
        if (requested == null) return current;
        if (requested < 1 || requested > applicationMaximum) {
            throw new IllegalArgumentException(field + " must be between 1 and " + applicationMaximum);
        }
        // Only tenant admins can change these values, and they can never exceed application maxima.
        return requested;
    }

    private CbomTenantSettings defaults(RequestActor actor) {
        CbomTenantSettings settings = new CbomTenantSettings();
        settings.setTenantId(actor.tenantId());
        settings.setUpdatedBy(actor.userId());
        return settings;
    }

    private RequestActor requireTenantAdmin() {
        RequestActor actor = actorService.currentActor();
        if (actor == null || actor.tenantId() == null || !actor.hasRole("TENANT_ADMIN")
                || !actor.hasDirectTenantMembership()) {
            throw new CryptoSuppressionPolicyException("TENANT_ADMIN_REQUIRED",
                    "A directly assigned tenant administrator is required");
        }
        return actor;
    }

    private CbomSuppressionSettingsResponse response(CbomTenantSettings value) {
        return new CbomSuppressionSettingsResponse(value.getTenantId(), value.isRequireDistinctSuppressionApprover(),
                value.getSuppressionRequestDeadlineDays(), value.getLowSuppressionMaxDays(),
                value.getMediumSuppressionMaxDays(), value.getHighSuppressionMaxDays(),
                value.getCriticalSuppressionMaxDays(), value.getUpdatedBy(), value.getUpdatedAt(), value.getVersion());
    }
}
