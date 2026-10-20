package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoSetupLinkResponse;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class DemoLifecycleServiceTest {

    @Mock
    private DemoRequestRepository demoRequestRepository;
    @Mock
    private DemoInviteRepository demoInviteRepository;
    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantService tenantService;
    @Mock
    private IdentityAdministrationService identityAdministrationService;
    @Mock
    private LocalCredentialAuthService localCredentialAuthService;
    @Mock
    private DemoInviteEmailService demoInviteEmailService;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private SbomUploadRepository sbomUploadRepository;
    @Mock
    private DemoTenantPurgeService demoTenantPurgeService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Test
    void synchronousDemoProvisioningActivatesPendingTenantWhenEnabled() {
        Tenant tenant = provisionedTenant();
        tenant.setStatus("PROVISIONING");
        doAnswer(invocation -> {
            tenant.setStatus("ACTIVE");
            return null;
        }).when(tenantSchemaMigrationService).provisionNewTenant(tenant);

        DemoLifecycleService service = service();
        service.setTenantSchemaMigrationService(tenantSchemaMigrationService);
        ReflectionTestUtils.setField(service, "synchronousTenantProvisioningEnabled", true);

        ReflectionTestUtils.invokeMethod(service, "provisionTenantSchemaSynchronouslyWhenEnabled", tenant);

        assertEquals("ACTIVE", tenant.getStatus());
        verify(tenantSchemaMigrationService).provisionNewTenant(tenant);
    }

    @Test
    void resendRunsOutsideJpaTransactionForSynchronousSchemaProvisioning() throws NoSuchMethodException {
        var transaction = DemoLifecycleService.class
                .getMethod("resendInvite", UUID.class)
                .getAnnotation(org.springframework.transaction.annotation.Transactional.class);

        assertNotNull(transaction);
        assertEquals(Propagation.NOT_SUPPORTED, transaction.propagation());
    }

    @Test
    void approveMarksRequestAndInviteSentWhenEmailDeliverySucceeds() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.existsByNameIgnoreCase("Example Co")).thenReturn(false);
        when(tenantRepository.existsBySlugIgnoreCase("example-co")).thenReturn(false);
        when(tenantService.createTenant("Example Co", "example-co", TenantService.DEFAULT_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("SENT", response.status());
        assertEquals("INVITE_SENT", response.bootstrapStatus());
        assertNotNull(response.tenantId());
        assertEquals(TenantService.DEFAULT_PLAN_CODE, response.provisionedPlanCode());
        assertEquals("SENT", response.latestInvite().status());
        assertNotNull(response.latestInvite().lastSentAt());
        assertEquals(TenantService.DEFAULT_PLAN_CODE, tenant.getPlanCode());
        verify(demoInviteEmailService).sendInvite(eq(request), any(DemoInvite.class));
    }

    @Test
    void approveCanRequestDemoDataForTheProvisionedTenant() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.existsByNameIgnoreCase("Example Co")).thenReturn(false);
        when(tenantRepository.existsBySlugIgnoreCase("example-co")).thenReturn(false);
        when(tenantService.createTenant(
                "Example Co",
                "example-co",
                TenantService.DEFAULT_PLAN_CODE,
                "demo-request:" + request.getId(),
                true))
                .thenAnswer(invocation -> {
                    tenant.setDemoSource(DemoDatasetProvisioningService.REQUESTED_MARKER);
                    return tenant;
                });
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        DemoRequestResponse response = service().approve(
                request.getId(),
                "platform-owner@example.com",
                true);

        assertEquals("SENT", response.status());
        assertEquals(DemoDatasetProvisioningService.REQUESTED_MARKER, tenant.getDemoSource());
        verify(tenantService).createTenant(
                "Example Co",
                "example-co",
                TenantService.DEFAULT_PLAN_CODE,
                "demo-request:" + request.getId(),
                true);
    }

    @Test
    void createRequestRecordsAnonymousAuditActor() {
        DemoRequestCreateRequest request = new DemoRequestCreateRequest(
                "Casey Example",
                "Casey@example.com",
                "Example Co",
                "Security Lead",
                "1-100",
                "SBOM validation",
                "Please follow up",
                true,
                "captcha-token"
        );
        when(demoRequestRepository.findFirstByEmailIgnoreCaseAndStatusInOrderByRequestedAtDesc(
                eq("casey@example.com"),
                eq(List.of("PENDING", "QUEUED", "SENT", "ERROR", "DELIVERY_UNKNOWN", "DELIVERY_ERROR"))))
                .thenReturn(Optional.empty());
        when(demoRequestRepository.saveAndFlush(any(DemoRequest.class))).thenAnswer(invocation -> {
            DemoRequest saved = invocation.getArgument(0);
            ReflectionTestUtils.setField(saved, "id", UUID.randomUUID());
            return saved;
        });
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(any(UUID.class))).thenReturn(List.of());

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.createRequest(request);

        assertEquals("casey@example.com", response.email());
        verify(auditEventService).recordExplicitActor(
                eq(null),
                eq("casey@example.com"),
                eq("ANONYMOUS"),
                eq("demo.request.created"),
                eq("demo_request"),
                eq(response.id().toString()),
                eq("{\"email\":\"casey@example.com\"}"),
                eq("SUCCESS"));
        verify(auditEventService, never()).record(
                eq("demo.request.created"),
                eq("demo_request"),
                any(),
                any());
    }

    @Test
    void createRequestRejectsFreeEmailProviders() {
        DemoRequestCreateRequest request = new DemoRequestCreateRequest(
                "Casey Example",
                "casey@gmail.com",
                "Example Co",
                "Security Lead",
                "11-50",
                "Product demo",
                null,
                true,
                "captcha-token");

        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> service().createRequest(request));

        assertEquals("CORPORATE_EMAIL_REQUIRED", error.getCode());
        verifyNoInteractions(demoRequestRepository);
    }

    @Test
    void approveSetsDemoTenantExpiryToSevenDaysFromProvisioning() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.existsByNameIgnoreCase("Example Co")).thenReturn(false);
        when(tenantRepository.existsBySlugIgnoreCase("example-co")).thenReturn(false);
        when(tenantService.createTenant("Example Co", "example-co", TenantService.DEFAULT_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        Instant beforeApproval = Instant.now();
        DemoLifecycleService service = service();
        service.approve(request.getId(), "platform-owner@example.com");
        Instant afterApproval = Instant.now();

        assertNotNull(tenant.getDemoExpiresAt());
        assertTrue(!tenant.getDemoExpiresAt().isBefore(beforeApproval.plus(7, ChronoUnit.DAYS)));
        assertTrue(!tenant.getDemoExpiresAt().isAfter(afterApproval.plus(7, ChronoUnit.DAYS)));
    }

    @Test
    void approveUsesUniqueTenantNameWhenCompanyAlreadyExists() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        tenant.setName("Example Co (2)");
        tenant.setSlug("example-co-2");
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.existsByNameIgnoreCase("Example Co")).thenReturn(true);
        when(tenantRepository.existsByNameIgnoreCase("Example Co (2)")).thenReturn(false);
        when(tenantRepository.existsBySlugIgnoreCase("example-co")).thenReturn(true);
        when(tenantRepository.existsBySlugIgnoreCase("example-co-2")).thenReturn(false);
        when(tenantService.createTenant("Example Co (2)", "example-co-2", TenantService.DEFAULT_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("SENT", response.status());
        assertEquals("INVITE_SENT", response.bootstrapStatus());
        assertEquals("Example Co (2)", response.latestInvite().tenantName());
        assertEquals(TenantService.DEFAULT_PLAN_CODE, response.provisionedPlanCode());
    }

    @Test
    void approveMarksRequestAndInviteErrorWhenEmailDeliveryIsNotConfigured() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.existsByNameIgnoreCase("Example Co")).thenReturn(false);
        when(tenantRepository.existsBySlugIgnoreCase("example-co")).thenReturn(false);
        when(tenantService.createTenant("Example Co", "example-co", TenantService.DEFAULT_PLAN_CODE, "demo-request:" + request.getId()))
                .thenReturn(tenant);
        when(tenantRepository.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.skipped("Resend delivery is not configured"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("ERROR", response.status());
        assertEquals("CREATED", response.bootstrapStatus());
        assertEquals(TenantService.DEFAULT_PLAN_CODE, response.provisionedPlanCode());
        assertEquals("ERROR", response.latestInvite().status());
        assertNull(response.latestInvite().lastSentAt());
        verify(demoInviteEmailService).sendInvite(eq(request), any(DemoInvite.class));
    }

    @Test
    void statusForTenantKeepsDemoLifecycleButAllowsAiActions() {
        Tenant tenant = provisionedTenant();
        tenant.setDemoExpiresAt(java.time.Instant.now().plusSeconds(86400));
        tenant.setDemoSource("REQUEST_REVIEW");

        when(sbomUploadRepository.countByUploadedAtGreaterThanEqual(any())).thenReturn(2L);

        DemoLifecycleService service = service();
        var response = service.statusForTenant(tenant);

        assertTrue(response.demo());
        assertEquals(TenantService.DEFAULT_PLAN_CODE, response.planCode());
        assertEquals(Boolean.TRUE, response.demoCapabilities().get("aiActions"));
    }

    @Test
    void enterpriseDemoTenantIsRecognizedAsDemoByLifecycleFields() {
        Tenant tenant = provisionedTenant();
        tenant.setDemoExpiresAt(java.time.Instant.now().plusSeconds(86400));
        tenant.setDemoSource("REQUEST_REVIEW");

        DemoLifecycleService service = service();

        assertTrue(service.isDemoTenant(tenant));
        assertDoesNotThrow(() -> service.assertDemoAllowsAiAction(tenant));
    }

    @Test
    void validateInviteReturnsDeliveryErrorWhenInviteExistsButEmailWasNotSent() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(java.time.Instant.now().plusSeconds(86400));

        DemoInvite invite = new DemoInvite();
        ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
        invite.setRequest(request);
        invite.setTenant(tenant);
        invite.setEmail(request.getEmail());
        invite.setToken("invite-token-123");
        lenient().when(demoInviteRepository.findByTokenHashForUpdate(invite.getTokenHash())).thenReturn(Optional.of(invite));
        invite.setStatus("ERROR");
        invite.setExpiresAt(java.time.Instant.now().plusSeconds(86400));

        when(demoInviteRepository.findByTokenHash(InvitationTokens.hash("invite-token-123"))).thenReturn(Optional.of(invite));

        DemoLifecycleService service = service();
        DemoInviteValidationResponse response = service.validateInvite("invite-token-123");

        assertTrue(response.valid());
        assertEquals("DELIVERY_ERROR", response.status());
        assertTrue(response.message().contains("Email delivery failed"));
    }

    @Test
    void acceptInviteRecordsPreAuthenticationAuditWithoutTenantAttribution() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        DemoInvite invite = new DemoInvite();
        ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
        invite.setRequest(request);
        invite.setTenant(tenant);
        invite.setEmail(request.getEmail());
        invite.setToken("invite-token-123");
        lenient().when(demoInviteRepository.findByTokenHashForUpdate(invite.getTokenHash())).thenReturn(Optional.of(invite));
        invite.setStatus("SENT");
        invite.setExpiresAt(Instant.now().plus(1, ChronoUnit.DAYS));

        when(demoInviteRepository.save(invite)).thenReturn(invite);
        when(demoRequestRepository.save(request)).thenReturn(request);
        when(localCredentialAuthService.issuePasswordSetupToken(request.getEmail())).thenReturn("setup-token");

        DemoInviteValidationResponse response = service().acceptInvite("invite-token-123");

        assertEquals("ACCEPTED", response.status());
        assertEquals("setup-token", response.setupToken());
        verify(auditEventService).recordExplicitActor(
                eq(null),
                eq(request.getEmail()),
                eq("ANONYMOUS"),
                eq("demo.invite.accepted"),
                eq("demo_invite"),
                eq(invite.getId().toString()),
                eq("{\"tenantId\":\"" + tenant.getId() + "\"}"),
                eq("SUCCESS"));
    }

    @Test
    void approveBlocksDuplicateAffiliationBeforeProvisioning() {
        DemoRequest request = pendingRequest();
        AppUser lockedUser = new AppUser();
        lockedUser.setExternalSubject(request.getEmail());
        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(identityAdministrationService.loadOrCreateLockedUser(request.getEmail(), request.getEmail(), request.getFullName()))
                .thenReturn(lockedUser);
        doAnswer(invocation -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "This user already has active access to another tenant");
        }).when(identityAdministrationService).assertEligibleForTenantMembership(lockedUser, null);
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DemoLifecycleService service = service();

        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> service.approve(request.getId(), "platform-owner@example.com")
        );

        assertEquals("DEMO_BOOTSTRAP_DUPLICATE_AFFILIATION", error.getCode());
        assertEquals("BLOCKED_DUPLICATE_AFFILIATION", request.getBootstrapStatus());
        assertEquals("ERROR", request.getStatus());
    }

    @Test
    void approveBlocksDuplicateAffiliationWhenRequestAlreadyTargetsProvisionedTenant() {
        DemoRequest request = pendingRequest();
        Tenant tenant = provisionedTenant();
        AppUser lockedUser = new AppUser();
        lockedUser.setExternalSubject(request.getEmail());
        request.setTenantId(tenant.getId());

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(identityAdministrationService.loadOrCreateLockedUser(request.getEmail(), request.getEmail(), request.getFullName()))
                .thenReturn(lockedUser);
        doAnswer(invocation -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "This user already has active access to another tenant");
        }).when(identityAdministrationService).assertEligibleForTenantMembership(lockedUser, tenant.getId());
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));

        DemoLifecycleService service = service();

        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> service.approve(request.getId(), "platform-owner@example.com")
        );

        assertEquals("DEMO_BOOTSTRAP_DUPLICATE_AFFILIATION", error.getCode());
        assertEquals("BLOCKED_DUPLICATE_AFFILIATION", request.getBootstrapStatus());
        assertEquals("ERROR", request.getStatus());
    }

    @Test
    void approveRecoversPartiallyProvisionedRequestByCreatingInvite() {
        DemoRequest request = pendingRequest();
        request.setTenantId(UUID.randomUUID());
        Tenant tenant = provisionedTenant();
        tenant.setId(request.getTenantId());
        AtomicReference<DemoInvite> latestInvite = new AtomicReference<>();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findById(request.getTenantId())).thenReturn(Optional.of(tenant));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId()))
                .thenAnswer(invocation -> latestInvite.get() == null ? List.of() : List.of(latestInvite.get()));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> {
            DemoInvite invite = invocation.getArgument(0);
            if (invite.getId() == null) {
                ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
            }
            latestInvite.set(invite);
            return invite;
        });
        when(demoRequestRepository.save(any(DemoRequest.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(demoInviteEmailService.sendInvite(eq(request), any(DemoInvite.class)))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-789"));

        DemoLifecycleService service = service();
        DemoRequestResponse response = service.approve(request.getId(), "platform-owner@example.com");

        assertEquals("SENT", response.status());
        assertEquals("SENT", response.latestInvite().status());
        verify(demoInviteEmailService).sendInvite(eq(request), any(DemoInvite.class));
    }

    @Test
    void resendInviteRetriesDeliveryForExistingInvite() {
        DemoRequest request = pendingRequest();
        request.setStatus("PROVISIONED");
        Tenant tenant = provisionedTenant();
        request.setTenantId(tenant.getId());

        DemoInvite existingInvite = new DemoInvite();
        ReflectionTestUtils.setField(existingInvite, "id", UUID.randomUUID());
        existingInvite.setRequest(request);
        existingInvite.setTenant(tenant);
        existingInvite.setEmail(request.getEmail());
        existingInvite.setToken("invite-token-123");
        existingInvite.setStatus("READY");
        existingInvite.setExpiresAt(java.time.Instant.now().plusSeconds(86400));

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId())).thenReturn(List.of(existingInvite));
        when(demoInviteRepository.findByTokenHashForUpdate(existingInvite.getTokenHash())).thenReturn(Optional.of(existingInvite));
        DemoInvite detachedSaveResult = new DemoInvite();
        ReflectionTestUtils.setField(detachedSaveResult, "id", existingInvite.getId());
        detachedSaveResult.setStatus("SENT");
        when(demoInviteRepository.save(existingInvite)).thenReturn(detachedSaveResult);
        when(demoInviteEmailService.sendInvite(request, existingInvite))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-456"));

        DemoLifecycleService service = service();
        DemoInviteResponse response = service.resendInvite(request.getId());

        assertEquals("SENT", response.status());
        assertNotNull(response.lastSentAt());
        assertEquals(request.getId(), response.requestId());
        assertEquals(tenant.getId(), response.tenantId());
        assertEquals(tenant.getName(), response.tenantName());
        assertEquals("INVITE_SENT", request.getBootstrapStatus());
        verify(demoInviteEmailService).sendInvite(request, existingInvite);
        verify(demoRequestRepository).save(request);
    }

    @Test
    void resendInviteRejectsAlreadyAcceptedInvite() {
        DemoRequest request = pendingRequest();
        request.setStatus("SENT");
        request.setBootstrapStatus("INVITE_SENT");
        Tenant tenant = provisionedTenant();
        request.setTenantId(tenant.getId());

        DemoInvite acceptedInvite = new DemoInvite();
        ReflectionTestUtils.setField(acceptedInvite, "id", UUID.randomUUID());
        acceptedInvite.setRequest(request);
        acceptedInvite.setTenant(tenant);
        acceptedInvite.setEmail(request.getEmail());
        acceptedInvite.setToken("invite-token-accepted");
        acceptedInvite.setStatus("ACCEPTED");
        acceptedInvite.setAcceptedAt(java.time.Instant.now());
        acceptedInvite.setExpiresAt(java.time.Instant.now().plusSeconds(86400));

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId())).thenReturn(List.of(acceptedInvite));
        when(demoInviteRepository.findByTokenHashForUpdate(acceptedInvite.getTokenHash())).thenReturn(Optional.of(acceptedInvite));

        DemoLifecycleService service = service();
        DemoAccessException ex = assertThrows(
                DemoAccessException.class,
                () -> service.resendInvite(request.getId())
        );
        assertEquals("DEMO_INVITE_ALREADY_ACCEPTED", ex.getCode());
    }

    @Test
    void issueSetupLinkMarksInviteAcceptedAndReturnsSetupUrl() {
        DemoRequest request = pendingRequest();
        request.setStatus("PROVISIONED");
        Tenant tenant = provisionedTenant();
        request.setTenantId(tenant.getId());

        DemoInvite existingInvite = new DemoInvite();
        ReflectionTestUtils.setField(existingInvite, "id", UUID.randomUUID());
        existingInvite.setRequest(request);
        existingInvite.setTenant(tenant);
        existingInvite.setEmail(request.getEmail());
        existingInvite.setToken("invite-token-123");
        existingInvite.setStatus("SENT");
        existingInvite.setExpiresAt(java.time.Instant.now().plusSeconds(86400));

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(request.getId())).thenReturn(List.of(existingInvite));
        when(demoInviteRepository.save(any(DemoInvite.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(localCredentialAuthService.issuePasswordSetupToken(request.getEmail())).thenReturn("setup-token-123");
        when(tenantLifecycleGuardService.isTenantAccessible(tenant)).thenReturn(true);

        DemoLifecycleService service = service();
        DemoSetupLinkResponse response = service.issueSetupLink(request.getId(), "platform-owner@example.com");

        assertEquals("ACCEPTED", response.inviteStatus());
        assertNotNull(existingInvite.getAcceptedAt());
        assertEquals("https://app.example.com/setup#token=setup-token-123&email=alex%40example.com", response.setupUrl());
        verify(localCredentialAuthService).issuePasswordSetupToken(request.getEmail());
    }

    @Test
    void deleteRequestRemovesNonProvisionedQueueItem() {
        DemoRequest request = pendingRequest();

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));

        DemoLifecycleService service = service();
        service.deleteRequest(request.getId(), "platform-owner@example.com");

        verify(demoInviteRepository).deleteByRequest_Id(request.getId());
        verify(demoRequestRepository).delete(request);
    }

    @Test
    void deleteRequestRemovesProvisionedQueueItemButKeepsTenantUntouched() {
        DemoRequest request = pendingRequest();
        request.setStatus("PROVISIONED");
        request.setTenantId(UUID.randomUUID());

        when(demoRequestRepository.findById(request.getId())).thenReturn(Optional.of(request));

        DemoLifecycleService service = service();
        service.deleteRequest(request.getId(), "platform-owner@example.com");

        verify(demoInviteRepository).deleteByRequest_Id(request.getId());
        verify(demoRequestRepository).delete(request);
    }

    @Test
    void expireDemoTenantsPurgesTenantsWhoseSevenDayWindowHasElapsed() {
        Tenant expiredTenant = provisionedTenant();
        expiredTenant.setDemoExpiresAt(Instant.now().minus(1, ChronoUnit.MINUTES));

        when(tenantRepository.findByDemoExpiresAtBeforeAndPurgedAtIsNullOrderByDemoExpiresAtAsc(any(Instant.class)))
                .thenReturn(List.of(expiredTenant));

        DemoLifecycleService service = service();
        service.expireDemoTenants();

        verify(demoTenantPurgeService).processExpiredTenant(eq(expiredTenant.getId()), any(Instant.class));
    }

    private DemoLifecycleService service() {
        org.springframework.transaction.support.TransactionTemplate inviteTransactions = org.mockito.Mockito.mock(org.springframework.transaction.support.TransactionTemplate.class);
        org.mockito.Mockito.lenient().when(inviteTransactions.execute(org.mockito.ArgumentMatchers.any())).thenAnswer(invocation ->
                ((org.springframework.transaction.support.TransactionCallback<?>) invocation.getArgument(0)).doInTransaction(null));
        org.mockito.Mockito.lenient().when(demoRequestRepository.findByIdForUpdate(org.mockito.ArgumentMatchers.any())).thenAnswer(invocation ->
                demoRequestRepository.findById(invocation.getArgument(0)));
        lenient().doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        return new DemoLifecycleService(
                demoRequestRepository,
                demoInviteRepository,
                tenantRepository,
                tenantService,
                identityAdministrationService,
                localCredentialAuthService,
                demoInviteEmailService,
                auditEventService,
                sbomUploadRepository,
                demoTenantPurgeService,
                tenantLifecycleGuardService,
                tenantSchemaExecutionService,
                "https://app.example.com",
                inviteTransactions
        );
    }

    private com.prototype.vulnwatch.domain.TenantMembership membershipFor(Tenant tenant) {
        com.prototype.vulnwatch.domain.TenantMembership membership = new com.prototype.vulnwatch.domain.TenantMembership();
        membership.setTenant(tenant);
        membership.setRole("TENANT_ADMIN");
        membership.setStatus("ACTIVE");
        return membership;
    }

    private DemoRequest pendingRequest() {
        DemoRequest request = new DemoRequest();
        ReflectionTestUtils.setField(request, "id", UUID.randomUUID());
        request.setEmail("alex@example.com");
        request.setFullName("Alex Rivera");
        request.setCompany("Example Co");
        request.setStatus("PENDING");
        return request;
    }

    private Tenant provisionedTenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Example Co");
        tenant.setSlug("example-co");
        tenant.setPlanCode(TenantService.DEFAULT_PLAN_CODE);
        return tenant;
    }

}
