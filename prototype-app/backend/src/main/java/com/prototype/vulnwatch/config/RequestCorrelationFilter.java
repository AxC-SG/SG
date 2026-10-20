package com.prototype.vulnwatch.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RequestCorrelationFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_HEADER = "X-Request-ID";
    public static final String SERVER_TIMING_HEADER = "Server-Timing";
    public static final String REQUEST_ID_MDC_KEY = "requestId";
    public static final String METHOD_MDC_KEY = "httpMethod";
    public static final String PATH_MDC_KEY = "httpPath";
    public static final String TENANT_ID_MDC_KEY = "tenantId";
    public static final String ACTOR_ID_MDC_KEY = "actorId";
    public static final String ACTOR_ROLES_MDC_KEY = "actorRoles";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String requestId = resolveRequestId(request);
        long startedAtNs = System.nanoTime();
        try {
            MDC.put(REQUEST_ID_MDC_KEY, requestId);
            MDC.put(METHOD_MDC_KEY, request.getMethod());
            MDC.put(PATH_MDC_KEY, request.getRequestURI());
            response.setHeader(REQUEST_ID_HEADER, requestId);
            filterChain.doFilter(request, response);
        } finally {
            appendServerTiming(response, startedAtNs);
            clearRequestContext();
        }
    }

    private void appendServerTiming(HttpServletResponse response, long startedAtNs) {
        double durationMs = (System.nanoTime() - startedAtNs) / 1_000_000.0;
        String metric = "app;dur=" + String.format(Locale.ROOT, "%.1f", durationMs);
        String existing = response.getHeader(SERVER_TIMING_HEADER);
        if (existing == null || existing.isBlank()) {
            response.setHeader(SERVER_TIMING_HEADER, metric);
            return;
        }
        response.setHeader(SERVER_TIMING_HEADER, existing + ", " + metric);
    }

    private String resolveRequestId(HttpServletRequest request) {
        String provided = request.getHeader(REQUEST_ID_HEADER);
        if (provided != null && isSafeRequestId(provided)) {
            return provided.trim();
        }
        return UUID.randomUUID().toString();
    }

    private boolean isSafeRequestId(String value) {
        String trimmed = value.trim();
        if (trimmed.isBlank() || trimmed.length() > 128) {
            return false;
        }
        // The identifier is echoed in a header, stored in audit rows and exported to CSV.
        // Keep it opaque and bounded; formula prefixes and whitespace are not identifiers.
        return value.equals(trimmed) && trimmed.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    }

    private void clearRequestContext() {
        MDC.remove(REQUEST_ID_MDC_KEY);
        MDC.remove(METHOD_MDC_KEY);
        MDC.remove(PATH_MDC_KEY);
        MDC.remove(TENANT_ID_MDC_KEY);
        MDC.remove(ACTOR_ID_MDC_KEY);
        MDC.remove(ACTOR_ROLES_MDC_KEY);
    }
}
