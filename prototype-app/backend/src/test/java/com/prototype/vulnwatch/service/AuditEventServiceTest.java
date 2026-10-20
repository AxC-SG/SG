package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OrgSpecificCveExposureRecomputeResponse;
import com.prototype.vulnwatch.dto.TenantExposureRefreshResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuditEventServiceTest {

    @Mock
    AuditEventRepository auditEventRepository;
    @Mock
    TenantRepository tenantRepository;
    @Mock
    RequestActorService requestActorService;

    @ParameterizedTest
    @ValueSource(strings = {"=SUM(A1:A2)", "+cmd", "-1+2", "@SUM(A1)", " =SUM(A1)", "\tordinary", "\rordinary", "\nordinary", "\uFEFF=SUM(A1)", "\u200B@SUM(A1)", "\u00a0+cmd", "\u0001=SUM(A1)"})
    void csvNeutralizesUntrustedFormulaAndControlPrefixes(String supplied) {
        AuditEvent event = new AuditEvent();
        event.setActorSubject(supplied);
        event.setRequestId(supplied);
        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);

        String csv = service.toCsv(java.util.List.of(event));

        assertTrue(csv.contains("\"'" + supplied + "\""));
        assertEquals(2, csv.split(java.util.regex.Pattern.quote("\"'" + supplied + "\""), -1).length - 1);
    }

    @Test
    void csvPreservesQuotedMultilineTextAndOrdinaryIdentifiers() {
        AuditEvent event = new AuditEvent();
        event.setActorSubject("analyst@example.com");
        event.setRequestId("req-123:abc");
        event.setDetailsJson("ordinary \"quoted\" text\nsecond line");
        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);

        String csv = service.toCsv(java.util.List.of(event));

        assertTrue(csv.contains("\"analyst@example.com\""));
        assertTrue(csv.contains("\"req-123:abc\""));
        assertTrue(csv.contains("\"ordinary \"\"quoted\"\" text\nsecond line\""));
    }

    @Test
    void recordTenantExposureRefreshPersistsOperationalDetails() {
        UUID tenantId = UUID.fromString("00000000-0000-0000-0000-000000000001");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "analyst@example.com",
                false,
                tenantId,
                "Acme",
                Set.of("TENANT_ADMIN")));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);
        OrgSpecificCveExposureRecomputeResponse refresh = new OrgSpecificCveExposureRecomputeResponse(
                "targeted",
                4L,
                3,
                2,
                8L,
                1L,
                Instant.parse("2026-04-10T12:00:00Z"));
        TenantExposureRefreshResponse response = new TenantExposureRefreshResponse(
                tenantId,
                "completed",
                "Tenant exposure refreshed from the current central vulnerability repository.",
                refresh,
                Instant.parse("2026-04-10T12:00:01Z"));

        service.recordTenantExposureRefresh(tenant, "/api/vuln-repo/org-cves/refresh", response);

        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository).save(eventCaptor.capture());
        AuditEvent event = eventCaptor.getValue();
        assertEquals("tenant.org_cves.refresh", event.getAction());
        assertEquals("tenant", event.getTargetType());
        assertEquals(tenantId.toString(), event.getTargetId());
        assertEquals("analyst@example.com", event.getActorSubject());
        assertEquals("TENANT_ADMIN", event.getActorRole());
        assertTrue(event.getDetailsJson().contains("\"source\":\"central_vulnerability_repository\""));
        assertTrue(event.getDetailsJson().contains("\"endpoint\":\"/api/vuln-repo/org-cves/refresh\""));
        assertTrue(event.getDetailsJson().contains("\"activeComponentCount\":4"));
        assertTrue(event.getDetailsJson().contains("\"stateRowsChanged\":2"));
        assertTrue(event.getDetailsJson().contains("\"openFindingsCount\":1"));
    }

    @Test
    void listPlatformUserEventsReturnsPlatformScopedIdentityAuditOnly() {
        AuditEvent event = new AuditEvent();
        event.setAction("platform.user.setup_completed");
        event.setTargetType("app_user");
        event.setTargetId("user-1");
        when(auditEventRepository.findByTenantIsNullAndTargetTypeAndActionInOrderByOccurredAtDesc(
                "app_user",
                AuditEventService.PLATFORM_USER_AUDIT_ACTIONS
        )).thenReturn(java.util.List.of(event));

        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);

        var events = service.listPlatformUserEvents();

        assertEquals(1, events.size());
        assertEquals("platform.user.setup_completed", events.get(0).getAction());
    }

    @Test
    void platformUserAuditEventsRemainPlatformScopedEvenDuringTenantContext() {
        UUID tenantId = UUID.fromString("00000000-0000-0000-0000-000000000002");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "owner@example.com",
                true,
                tenantId,
                "Acme",
                Set.of("PLATFORM_OWNER")));

        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);

        service.record("platform.user.setup_issued", "app_user", "user-1", null);

        ArgumentCaptor<AuditEvent> eventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditEventRepository).save(eventCaptor.capture());
        AuditEvent event = eventCaptor.getValue();
        assertEquals("platform.user.setup_issued", event.getAction());
        assertNull(event.getTenant());
    }

    @Test
    void tenantOwnerCredentialAuditUsesPreAuthenticationPlatformPath() {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "owner@example.com", true, null, null, Set.of("PLATFORM_OWNER")));
        when(auditEventRepository.save(any(AuditEvent.class))).thenAnswer(invocation -> {
            assertTrue(TenantContext.isPreAuthenticationContext());
            return invocation.getArgument(0);
        });

        AuditEventService service = new AuditEventService(auditEventRepository, tenantRepository, requestActorService);
        service.record("tenant.owner.credential_recovered", "tenant", "tenant-1", "{\"credentialUpdated\":true}");

        verify(auditEventRepository).save(any(AuditEvent.class));
    }
}
