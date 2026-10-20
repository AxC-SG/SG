package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.TestPersonaResponse;
import com.prototype.vulnwatch.dto.TestPersonaTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TestPersonaService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TenantRepository tenantRepository;
    private final AppUserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final boolean enabled;
    private final String hmacSecret;
    private final long tokenTtlMinutes;
    private final List<PersonaSpec> personas = List.of(
            new PersonaSpec("platform-owner", "Platform Owner", "persona-platform-owner", null, null, Set.of("PLATFORM_OWNER")),
            new PersonaSpec("tenant-a-admin", "Tenant A Admin", "persona-tenant-a-admin", "customer-a", "Customer A", Set.of("TENANT_ADMIN")),
            new PersonaSpec("tenant-b-admin", "Tenant B Admin", "persona-tenant-b-admin", "customer-b", "Customer B", Set.of("TENANT_ADMIN")),
            new PersonaSpec("tenant-a-inventory-admin", "Tenant A Inventory Admin", "persona-tenant-a-inventory-admin", "customer-a", "Customer A", Set.of("INVENTORY_ADMIN")),
            new PersonaSpec("tenant-a-security-analyst", "Tenant A Security Analyst", "persona-tenant-a-security-analyst", "customer-a", "Customer A", Set.of("SECURITY_ANALYST")),
            new PersonaSpec("tenant-a-auditor", "Tenant A Auditor", "persona-tenant-a-auditor", "customer-a", "Customer A", Set.of("READ_ONLY_AUDITOR"))
    );

    public TestPersonaService(
            TenantRepository tenantRepository,
            AppUserRepository userRepository,
            TenantMembershipRepository membershipRepository,
            @Value("${app.test-personas.enabled:false}") boolean enabled,
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.test-personas.token-ttl-minutes:60}") long tokenTtlMinutes
    ) {
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.enabled = enabled;
        this.hmacSecret = hmacSecret;
        this.tokenTtlMinutes = tokenTtlMinutes;
    }

    public List<TestPersonaResponse> listPersonas() {
        requireEnabled();
        return personas.stream().map(this::toResponse).toList();
    }

    @Transactional
    public TestPersonaTokenResponse issueToken(String personaKey) {
        requireEnabled();
        if (hmacSecret == null || hmacSecret.isBlank()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "APP_JWT_HMAC_SECRET is required for backend-backed test personas");
        }
        PersonaSpec persona = personas.stream()
                .filter(candidate -> candidate.key().equals(personaKey))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown test persona"));
        Tenant tenant = persona.tenantSlug() == null ? null : ensureTenant(persona.tenantSlug(), persona.tenantName());
        AppUser user = ensureUser(persona);
        if (tenant != null) {
            ensureMembership(tenant, user, persona.roles().stream().findFirst().orElse("SECURITY_ANALYST"));
        }

        Instant now = Instant.now();
        Instant expiresAt = now.plus(Math.max(1, tokenTtlMinutes), ChronoUnit.MINUTES);
        return new TestPersonaTokenResponse(
                signToken(persona, tenant, now, expiresAt),
                "Bearer",
                expiresAt,
                toResponse(persona));
    }

    private void requireEnabled() {
        if (!enabled) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Test personas are disabled");
        }
    }

    private Tenant ensureTenant(String slug, String name) {
        return tenantRepository.findBySlugIgnoreCase(slug).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(name);
            tenant.setSlug(slug);
            tenant.setStatus("ACTIVE");
            tenant.setPlanCode("phase-1-test");
            return tenantRepository.save(tenant);
        });
    }

    private AppUser ensureUser(PersonaSpec persona) {
        return userRepository.findByExternalSubject(persona.subject()).map(user -> {
            user.setEmail(persona.subject() + "@example.test");
            user.setDisplayName(persona.label());
            user.setStatus("ACTIVE");
            if (persona.roles().contains("PLATFORM_OWNER")) {
                user.setPlatformOwner(true);
            }
            user.setUpdatedAt(Instant.now());
            return userRepository.save(user);
        }).orElseGet(() -> {
            AppUser user = new AppUser();
            user.setExternalSubject(persona.subject());
            user.setEmail(persona.subject() + "@example.test");
            user.setDisplayName(persona.label());
            user.setPlatformOwner(persona.roles().contains("PLATFORM_OWNER"));
            return userRepository.save(user);
        });
    }

    private void ensureMembership(Tenant tenant, AppUser user, String role) {
        String tenantRole = TenantRolePolicy.forAssignment(role);
        membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                user.getExternalSubject(),
                tenant.getId(),
                "ACTIVE"
        ).ifPresentOrElse(existing -> {
            existing.setRole(tenantRole);
            existing.setUpdatedAt(Instant.now());
            membershipRepository.save(existing);
        }, () -> {
            TenantMembership membership = new TenantMembership();
            membership.setTenant(tenant);
            membership.setUser(user);
            membership.setRole(tenantRole);
            membershipRepository.save(membership);
        });
    }

    private String signToken(PersonaSpec persona, Tenant tenant, Instant issuedAt, Instant expiresAt) {
        try {
            String header = json(Map.of("alg", "HS256", "typ", "JWT"));
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("sub", persona.subject());
            claims.put("email", persona.subject() + "@example.test");
            claims.put("name", persona.label());
            claims.put("roles", persona.roles());
            claims.put("iat", issuedAt.getEpochSecond());
            claims.put("exp", expiresAt.getEpochSecond());
            if (tenant != null) {
                claims.put("tenant_id", tenant.getId().toString());
                claims.put("tenant_slug", tenant.getSlug());
            }
            String unsigned = base64Url(header.getBytes(StandardCharsets.UTF_8))
                    + "."
                    + base64Url(json(claims).getBytes(StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return unsigned + "." + base64Url(mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to mint test persona token");
        }
    }

    private String json(Object value) throws Exception {
        return MAPPER.writeValueAsString(value);
    }

    private String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private TestPersonaResponse toResponse(PersonaSpec persona) {
        return new TestPersonaResponse(
                persona.key(),
                persona.label(),
                persona.subject(),
                persona.tenantSlug(),
                persona.tenantName(),
                persona.roles());
    }

    private record PersonaSpec(
            String key,
            String label,
            String subject,
            String tenantSlug,
            String tenantName,
            Set<String> roles
    ) {
    }
}
