package com.prototype.vulnwatch.security;

import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessMode;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class SensitiveTenantActionInterceptor implements HandlerInterceptor {

    private final RequestActorService requestActorService;
    private final TenantSupportGrantService tenantSupportGrantService;

    public SensitiveTenantActionInterceptor(
            RequestActorService requestActorService,
            TenantSupportGrantService tenantSupportGrantService
    ) {
        this.requestActorService = requestActorService;
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if ("/api/auth/tenant-context".equals(request.getRequestURI())) {
            return true;
        }
        if (!(handler instanceof HandlerMethod) || !isWriteMethod(request.getMethod())) {
            return true;
        }
        RequestActor actor = requestActorService.currentActor();
        TenantAccessMode accessMode = actor.accessMode();
        if (accessMode == TenantAccessMode.SERVICE_ACCOUNT && actor.hasRole("SERVICE_ACCOUNT")) {
            return true;
        }
        if (accessMode == null || actor.hasDirectTenantMembership()) {
            return true;
        }
        if (actor.tenantId() == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Platform owner tenant context is required");
        }
        if (accessMode != TenantAccessMode.SUPPORT_WRITE_ENABLED) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This support session is read-only");
        }
        var grant = tenantSupportGrantService.requireActiveGrantForWrite(actor.userId(), actor.tenantId());
        if (actor.accessReferenceId() == null || !actor.accessReferenceId().equals(grant.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Support authorization changed; sign in again");
        }
        return true;
    }

    private boolean isWriteMethod(String method) {
        return "POST".equalsIgnoreCase(method)
                || "PUT".equalsIgnoreCase(method)
                || "PATCH".equalsIgnoreCase(method)
                || "DELETE".equalsIgnoreCase(method);
    }
}
