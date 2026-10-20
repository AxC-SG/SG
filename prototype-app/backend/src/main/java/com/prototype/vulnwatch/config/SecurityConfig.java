package com.prototype.vulnwatch.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final RequestMatcher HEADER_AUTH_CSRF_BYPASS = request ->
            !"/api/auth/setup-password".equals(request.getRequestURI())
                    && Boolean.TRUE.equals(request.getAttribute(ApiKeyAuthenticationFilter.VERIFIED_HEADER_AUTH));

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ApiKeyAuthenticationFilter apiKeyAuthenticationFilter,
            RequestCorrelationFilter requestCorrelationFilter,
            TenantStatusFilter tenantStatusFilter,
            @Value("${app.security.headers.content-security-policy:default-src 'none'; frame-ancestors 'none'}") String contentSecurityPolicy,
            @Value("${app.security.headers.permissions-policy:camera=(), microphone=(), geolocation=(), payment=()}") String permissionsPolicy
    ) throws Exception {
        http
                // Without this, Spring Security rejects a request before the MVC CORS handling
                // runs, so 401 and 403 responses carry no Access-Control-Allow-Origin. A browser
                // then blocks the response body and reports a generic network failure, so every
                // auth problem surfaces in the UI as "Failed to fetch" with the real reason
                // invisible. Reuses the origins configured in WebConfig; it adds no permissions.
                .cors(org.springframework.security.config.Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .requireCsrfProtectionMatcher(request ->
                                CsrfFilter.DEFAULT_CSRF_MATCHER.matches(request) && !HEADER_AUTH_CSRF_BYPASS.matches(request))
                        .ignoringRequestMatchers(
                                "/actuator/**",
                                "/api/auth/login",
                                "/api/auth/setup-session",
                                "/api/auth/context",
                                "/api/me",
                                "/api/demo-requests",
                                "/api/demo-invites/**",
                                "/api/tenant-invites/**"))
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .headers(headers -> headers
                        .contentTypeOptions(contentType -> {})
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                        .contentSecurityPolicy(csp -> csp.policyDirectives(contentSecurityPolicy))
                        .addHeaderWriter(new StaticHeadersWriter("Permissions-Policy", permissionsPolicy)))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/readiness", "/actuator/health/liveness", "/actuator/info").permitAll()
                        .requestMatchers("/actuator/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/auth/setup-password", "/api/auth/setup-session").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/demo-requests").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/demo-invites/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/demo-invites/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/tenant-invites/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/tenant-invites/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/operations/quality/**", "/api/operations/software-identities/search")
                        .hasAnyRole("PLATFORM_OWNER", "TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR")
                        .requestMatchers("/api/platform/**").hasRole("PLATFORM_OWNER")
                        .requestMatchers("/api/operations/**").hasRole("PLATFORM_OWNER")
                        .requestMatchers("/api/fix-intelligence", "/api/fix-intelligence/**").denyAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .addFilterBefore(apiKeyAuthenticationFilter, CsrfFilter.class)
                .addFilterAfter(requestCorrelationFilter, ApiKeyAuthenticationFilter.class)
                .addFilterAfter(tenantStatusFilter, RequestCorrelationFilter.class);

        return http.build();
    }

    private static boolean hasHeader(HttpServletRequest request, String headerName) {
        String value = request.getHeader(headerName);
        return value != null && !value.isBlank();
    }
}
