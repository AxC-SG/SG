package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.DemoInvite;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoSetupLinkResponse;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.repo.DemoInviteRepository;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.security.SecureRandom;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class DemoLifecycleService {
    public static final String DEMO_PLAN_CODE = "DEMO";
    private static final String DEMO_SOURCE_REQUEST_REVIEW = "REQUEST_REVIEW";
    private static final List<String> ACTIVE_REQUEST_STATUSES = List.of("PENDING", "QUEUED", "SENT", "ERROR", "DELIVERY_UNKNOWN", "DELIVERY_ERROR");
    private static final ObjectMapper AUDIT_JSON = new ObjectMapper();

    private final DemoRequestRepository demoRequestRepository;
    private final DemoInviteRepository demoInviteRepository;
    private final TenantRepository tenantRepository;
    private final TenantService tenantService;
    private final IdentityAdministrationService identityAdministrationService;
    private final LocalCredentialAuthService localCredentialAuthService;
    private final DemoInviteEmailService demoInviteEmailService;
    private final AuditEventService auditEventService;
    private final SbomUploadRepository sbomUploadRepository;
    private final DemoTenantPurgeService demoTenantPurgeService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final SecureRandom secureRandom = new SecureRandom();
    private final String appBaseUrl;
    private final TransactionTemplate transactionTemplate;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private TenantSchemaMigrationService tenantSchemaMigrationService;
    private JdbcTemplate jdbcTemplate;
    @Value("${app.demo.synchronous-tenant-provisioning-enabled:false}")
    private boolean synchronousTenantProvisioningEnabled;
    @Value("${app.security.managed-auth.enabled:false}")
    private boolean managedAuthEnabled;

    public DemoLifecycleService(
            DemoRequestRepository demoRequestRepository,
            DemoInviteRepository demoInviteRepository,
            TenantRepository tenantRepository,
            TenantService tenantService,
            IdentityAdministrationService identityAdministrationService,
            LocalCredentialAuthService localCredentialAuthService,
            DemoInviteEmailService demoInviteEmailService,
            AuditEventService auditEventService,
            SbomUploadRepository sbomUploadRepository,
            DemoTenantPurgeService demoTenantPurgeService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl,
            TransactionTemplate transactionTemplate
    ) {
        this.demoRequestRepository = demoRequestRepository;
        this.demoInviteRepository = demoInviteRepository;
        this.tenantRepository = tenantRepository;
        this.tenantService = tenantService;
        this.identityAdministrationService = identityAdministrationService;
        this.localCredentialAuthService = localCredentialAuthService;
        this.demoInviteEmailService = demoInviteEmailService;
        this.auditEventService = auditEventService;
        this.sbomUploadRepository = sbomUploadRepository;
        this.demoTenantPurgeService = demoTenantPurgeService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.transactionTemplate = transactionTemplate;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setJdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTenantSchemaMigrationService(TenantSchemaMigrationService tenantSchemaMigrationService) {
        this.tenantSchemaMigrationService = tenantSchemaMigrationService;
    }

    @Transactional
    public DemoRequestResponse createRequest(DemoRequestCreateRequest request) {
        String email = DemoRequestInputPolicy.requiredSingleLine(request.email(), "email").toLowerCase(java.util.Locale.ROOT);
        CorporateEmailPolicy.requireCorporateEmail(email);
        var existingRequest = demoRequestRepository.findFirstByEmailIgnoreCaseAndStatusInOrderByRequestedAtDesc(email, ACTIVE_REQUEST_STATUSES);
        if (existingRequest.isPresent()) {
            return toRequestResponse(existingRequest.get());
        }
        DemoRequest demoRequest = new DemoRequest();
        demoRequest.setEmail(email);
        demoRequest.setFullName(DemoRequestInputPolicy.requiredSingleLine(request.fullName(), "fullName"));
        demoRequest.setCompany(DemoRequestInputPolicy.requiredSingleLine(request.company(), "company"));
        demoRequest.setRoleTitle(DemoRequestInputPolicy.optionalSingleLine(request.roleTitle(), "roleTitle"));
        demoRequest.setCompanySize(DemoRequestInputPolicy.companySize(request.companySize()));
        demoRequest.setUseCase(DemoRequestInputPolicy.useCase(request.useCase()));
        demoRequest.setNotes(DemoRequestInputPolicy.optionalNotes(request.notes()));
        DemoRequest saved;
        try {
            saved = demoRequestRepository.saveAndFlush(demoRequest);
        } catch (DataIntegrityViolationException duplicateActiveRequest) {
            if (!exceptionChainContains(duplicateActiveRequest, "uk_demo_requests_active_email")) {
                throw duplicateActiveRequest;
            }
            throw new DuplicateDemoRequestException(duplicateActiveRequest);
        }
        auditEventService.recordExplicitActor(
                null,
                email,
                "ANONYMOUS",
                "demo.request.created",
                "demo_request",
                saved.getId().toString(),
                auditJson(Map.of("email", email)),
                "SUCCESS");
        return toRequestResponse(saved);
    }

    private String auditJson(Map<String, ?> details) {
        try {
            return AUDIT_JSON.writeValueAsString(details);
        } catch (JsonProcessingException impossibleForScalarDetails) {
            throw new IllegalStateException("Failed to serialize audit details", impossibleForScalarDetails);
        }
    }

    private boolean exceptionChainContains(Throwable failure, String marker) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current.getMessage() != null && current.getMessage().contains(marker)) {
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public List<DemoRequestResponse> listRequests() {
        return demoRequestRepository.findAllByOrderByRequestedAtDesc().stream()
                .map(this::toRequestResponse)
                .toList();
    }

    // Tenant provisioning performs DDL on a separate connection. Do not keep platform-row
    // locks open around it or PostgreSQL can wait on this request's own transaction.
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DemoRequestResponse approve(UUID requestId, String actor) {
        return approve(requestId, actor, false);
    }

    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DemoRequestResponse approve(UUID requestId, String actor, boolean addDemoData) {
        if (managedAuthEnabled) {
            if (TenantContext.getCurrentTenantId() != null) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Return to platform scope to approve Standard onboarding");
            }
            if (addDemoData) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Standard onboarding cannot seed demo data");
            }
            return transactionTemplate.execute(status -> approveStandardRequest(requestId, actor));
        }
        DemoRequest request = getRequest(requestId);
        requireUncommittedRequest(request);
        Tenant tenant;
        if (request.getTenantId() != null) {
            tenant = tenantRepository.findById(request.getTenantId())
                    .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + request.getTenantId()));
            assertBootstrapEligibility(request, actor, tenant.getId());
        } else {
            tenant = demoRequestRepository
                    .findFirstByEmailIgnoreCaseAndTenantIdIsNotNullOrderByRequestedAtAsc(request.getEmail())
                    .flatMap(prior -> tenantRepository.findById(prior.getTenantId()))
                    .map(existingTenant -> {
                        assertBootstrapEligibility(request, actor, existingTenant.getId());
                        return existingTenant;
                    })
                    .orElseGet(() -> provisionTenant(request, actor, addDemoData));
        }
        if (addDemoData && !DemoDatasetProvisioningService.isRequested(tenant)) {
            tenant.setDemoSource(DemoDatasetProvisioningService.REQUESTED_MARKER);
            tenant.setUpdatedAt(Instant.now());
            tenant = tenantRepository.save(tenant);
        }
        provisionTenantSchemaSynchronouslyWhenEnabled(tenant);
        request.setBootstrapStatus("CREATED");

        Tenant inviteTenant = tenant;
        return transactionTemplate.execute(status -> {
            demoRequestRepository.findByIdForUpdate(requestId).orElseThrow();
            DemoInvite invite = latestInvite(requestId);
            if (invite == null) {
                invite = createInvite(request, inviteTenant);
            }
            if (invite.getAcceptedAt() == null && !"ACCEPTED".equalsIgnoreCase(invite.getStatus())) {
                invite = demoInviteRepository.findByTokenHashForUpdate(invite.getTokenHash()).orElse(invite);
                rotateInvite(invite);
                invite = deliverInvite(invite, request);
                request.setStatus(requestStatusForInvite(invite));
                if ("SENT".equalsIgnoreCase(invite.getStatus())) {
                    request.setBootstrapStatus("INVITE_SENT");
                }
            } else if (request.getStatus() == null || request.getStatus().isBlank() || "PENDING".equalsIgnoreCase(request.getStatus())) {
                request.setStatus("SENT");
                request.setBootstrapStatus("INVITE_ACCEPTED");
            }
            request.setDecidedAt(Instant.now());
            request.setDecidedBy(trimToNull(actor));
            request.setTenantId(inviteTenant.getId());
            demoRequestRepository.save(request);
            auditEventService.record("demo.request.approved", "demo_request", request.getId().toString(),
                    "{\"tenantId\":\"" + inviteTenant.getId() + "\",\"inviteId\":\"" + invite.getId() + "\"}");
            return toRequestResponse(request);
        });
    }

    private DemoRequestResponse approveStandardRequest(UUID requestId, String actor) {
        DemoRequest request = getRequestForUpdate(requestId);
        if (isStandardRequest(request)) {
            return toRequestResponse(request);
        }
        if (!"PENDING".equals(request.getStatus()) || request.getTenantId() != null || latestInvite(requestId) != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Only a pending request can start Standard onboarding");
        }
        request.setStatus("QUEUED");
        request.setBootstrapStatus("STANDARD_APPROVED");
        request.setDecidedAt(Instant.now());
        request.setDecidedBy(requireText(actor, "approver"));
        auditEventService.record("demo.request.standard_approved", "demo_request", requestId.toString(), null);
        return toRequestResponse(request);
    }

    @Transactional
    public DemoRequestResponse reject(UUID requestId, String reason, String actor) {
        DemoRequest request = getRequestForUpdate(requestId);
        requireUncommittedRequest(request);
        request.setStatus("REJECTED");
        request.setBootstrapStatus("REJECTED");
        request.setDecidedAt(Instant.now());
        request.setDecidedBy(trimToNull(actor));
        request.setRejectionReason(trimToNull(reason));
        auditEventService.record("demo.request.rejected", "demo_request", request.getId().toString(), null);
        return toRequestResponse(demoRequestRepository.save(request));
    }

    // Local synchronous provisioning performs DDL on separate connections. Keep
    // the resend request outside a JPA transaction so it cannot deadlock against
    // locks held by its own tenant/invite reads.
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public DemoInviteResponse resendInvite(UUID requestId) {
        requireLocalDemoSetup();
        DemoRequest request = getRequest(requestId);
        requireUncommittedRequest(request);
        if (request.getTenantId() == null) {
            throw new DemoAccessException("DEMO_INVITE_INVALID", "Demo request has not been provisioned yet", HttpStatus.BAD_REQUEST);
        }
        Tenant tenant = tenantRepository.findById(request.getTenantId())
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + request.getTenantId()));
        provisionTenantSchemaSynchronouslyWhenEnabled(tenant);
        return transactionTemplate.execute(status -> {
            demoRequestRepository.findByIdForUpdate(requestId).orElseThrow();
            DemoInvite invite = latestInvite(requestId);
            if (invite == null) {
                invite = createInvite(request, tenant);
            } else {
                invite = demoInviteRepository.findByTokenHashForUpdate(invite.getTokenHash()).orElseThrow();
                // DDL completed before this short transaction; use explicitly loaded associations
                // for delivery and conversion while the invitation lock is held.
                invite.setRequest(request);
                invite.setTenant(tenant);
            }
            if ("ACCEPTED".equalsIgnoreCase(invite.getStatus()) || invite.getAcceptedAt() != null) {
                throw new DemoAccessException("DEMO_INVITE_ALREADY_ACCEPTED", "This invite has already been accepted and cannot be resent", HttpStatus.CONFLICT);
            }
            rotateInvite(invite);
            invite = deliverInvite(invite, request);
            request.setStatus(requestStatusForInvite(invite));
            request.setBootstrapStatus("SENT".equalsIgnoreCase(invite.getStatus()) ? "INVITE_SENT" : "CREATED");
            demoRequestRepository.save(request);
            auditEventService.record("demo.invite.resent", "demo_invite", invite.getId().toString(), null);
            return toInviteResponse(invite);
        });
    }

    @Transactional
    public DemoSetupLinkResponse issueSetupLink(UUID requestId, String actor) {
        requireLocalDemoSetup();
        DemoRequest request = demoRequestRepository.findByIdForUpdate(requestId).orElseThrow();
        requireUncommittedRequest(request);
        if (request.getTenantId() == null) {
            throw new DemoAccessException("DEMO_SETUP_NOT_READY", "Demo request must be provisioned before password setup can be issued", HttpStatus.CONFLICT);
        }
        Tenant tenant = tenantRepository.findById(request.getTenantId())
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + request.getTenantId()));
        if (!tenantLifecycleGuardService.isTenantAccessible(tenant)) {
            throw new DemoAccessException("DEMO_TENANT_EXPIRED", "Demo tenant has expired", HttpStatus.GONE);
        }
        DemoInvite invite = latestInvite(requestId);
        if (invite == null) {
            invite = createInvite(request, tenant);
        }
        invite = demoInviteRepository.findByTokenHashForUpdate(invite.getTokenHash()).orElse(invite);
        if (invite.getAcceptedAt() == null) {
            invite.setAcceptedAt(Instant.now());
        }
        invite.setStatus("ACCEPTED");
        invite = demoInviteRepository.save(invite);
        request.setBootstrapStatus("INVITE_ACCEPTED");
        demoRequestRepository.save(request);

        String setupToken = localCredentialAuthService.issuePasswordSetupToken(invite.getEmail());
        auditEventService.record(
                "demo.invite.setup_issued_by_platform",
                "demo_invite",
                invite.getId().toString(),
                "{\"requestId\":\"" + requestId + "\",\"actor\":\"" + escapeJson(trimToNull(actor)) + "\"}");
        return new DemoSetupLinkResponse(
                request.getId(),
                invite.getId(),
                tenant.getId(),
                tenant.getName(),
                invite.getEmail(),
                invite.getStatus(),
                invite.getExpiresAt(),
                invite.getToken() == null ? null : appBaseUrl + "/invite#token=" + invite.getToken(),
                appBaseUrl + "/setup#token=" + setupToken + "&email=" + java.net.URLEncoder.encode(invite.getEmail(), java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    @Transactional
    public void deleteRequest(UUID requestId, String actor) {
        DemoRequest request = getRequestForUpdate(requestId);
        requireUncommittedRequest(request);
        if (request.getTenantId() != null) {
            deleteInvitesOwnedByProvisionedTenant(requestId, request.getTenantId());
        }
        demoInviteRepository.deleteByRequest_Id(requestId);
        demoRequestRepository.delete(request);
        auditEventService.record(
                "demo.request.deleted",
                "demo_request",
                requestId.toString(),
                "{\"actor\":\"" + escapeJson(trimToNull(actor)) + "\"}");
    }

    // Shared demo invites carry the provisioned customer's tenant ID, so forced RLS hides
    // them from the platform-scope queue connection and the request's FK delete fails.
    // Bind the customer tenant on this transaction's connection only for this request's
    // invites, then restore the previous context before the request row is removed.
    private void deleteInvitesOwnedByProvisionedTenant(UUID requestId, UUID tenantId) {
        jdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            String previousTenantId;
            try (PreparedStatement current = connection.prepareStatement(
                    "select current_setting('app.current_tenant_id', true)");
                 ResultSet result = current.executeQuery()) {
                result.next();
                previousTenantId = result.getString(1);
            }
            try (PreparedStatement context = connection.prepareStatement(
                    "select set_config('app.current_tenant_id', ?, false)")) {
                try {
                    context.setString(1, tenantId.toString());
                    context.execute();
                    try (PreparedStatement invites = connection.prepareStatement(
                            "delete from demo_invites where request_id = ? and tenant_id = ?")) {
                        invites.setObject(1, requestId);
                        invites.setObject(2, tenantId);
                        invites.executeUpdate();
                    }
                } finally {
                    context.setString(1, previousTenantId == null ? "" : previousTenantId);
                    context.execute();
                }
            }
            return null;
        });
    }

    @Transactional(readOnly = true)
    public DemoInviteValidationResponse validateInvite(String token) {
        DemoInvite invite = findInvite(token);
        return inviteValidationResponse(invite, null, null);
    }

    @Transactional
    public DemoInviteValidationResponse acceptInvite(String token) {
        demoInviteRepository.findRequestIdByTokenHash(InvitationTokens.hash(token))
                .ifPresent(requestId -> demoRequestRepository.findByIdForUpdate(requestId).orElseThrow());
        DemoInvite invite = demoInviteRepository.findByTokenHashForUpdate(InvitationTokens.hash(token))
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo invite not found", HttpStatus.NOT_FOUND));
        DemoInviteValidationResponse validation = inviteValidationResponse(invite, null, null);
        if (!validation.valid()) {
            throw new DemoAccessException("DEMO_INVITE_INVALID", validation.message(), HttpStatus.BAD_REQUEST);
        }
        invite.setStatus("ACCEPTED");
        invite.setAcceptedAt(Instant.now());
        demoInviteRepository.save(invite);
        if (invite.getRequest() != null) {
            invite.getRequest().setBootstrapStatus("INVITE_ACCEPTED");
            demoRequestRepository.save(invite.getRequest());
        }
        String setupToken = localCredentialAuthService.issuePasswordSetupToken(invite.getEmail());
        // Demo onboarding is centralized in tenant_default. Keep its anonymous audit
        // row in the pre-auth partition; the referenced tenant remains in detailsJson.
        auditEventService.recordExplicitActor(
                null,
                invite.getEmail(),
                "ANONYMOUS",
                "demo.invite.accepted",
                "demo_invite",
                invite.getId().toString(),
                "{\"tenantId\":\"" + invite.getTenant().getId() + "\"}",
                "SUCCESS");
        return inviteValidationResponse(invite, "Invite accepted", setupToken);
    }

    public DemoStatusResponse statusForTenant(Tenant tenant) {
        boolean demo = isDemoTenant(tenant);
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
        long uploads = tenantSchemaExecutionService.run(tenant, () -> sbomUploadRepository.countByUploadedAtGreaterThanEqual(since));
        return new DemoStatusResponse(
                demo,
                tenant.getPlanCode(),
                tenant.getDemoExpiresAt(),
                daysRemaining(tenant.getDemoExpiresAt()),
                Map.of(
                        "sbomUpload", demo,
                        "liveConnectors", true,
                        "aiActions", true,
                        "exports", true
                ),
                Map.of(
                        "dailySbomUploads", uploads,
                        "maxDailySbomUploads", safeLong(tenant.getMaxDailySbomUploads()),
                        "maxDailyExposureRefreshes", safeLong(tenant.getMaxDailyExposureRefreshes()),
                        "maxExportRows", safeLong(tenant.getMaxExportRows())
                )
        );
    }

    public void assertDemoAllowsLiveConnector(Tenant tenant) {
        // Inventory connectors are temporarily enabled for demo tenants.
    }

    public void assertDemoAllowsAiAction(Tenant tenant) {
        // Demo tenants now provision with Enterprise-equivalent access by default.
    }

    public void assertCanUploadSbom(Tenant tenant) {
        if (!isDemoTenant(tenant)) {
            return;
        }
        int max = tenant.getMaxDailySbomUploads() == null ? 0 : Math.max(0, tenant.getMaxDailySbomUploads());
        long current = tenantSchemaExecutionService.run(
                tenant,
                () -> sbomUploadRepository.countByUploadedAtGreaterThanEqual(Instant.now().minus(24, ChronoUnit.HOURS))
        );
        if (current >= max) {
            throw new DemoAccessException("DEMO_QUOTA_EXCEEDED", "Demo SBOM upload limit reached for the last 24 hours", HttpStatus.TOO_MANY_REQUESTS);
        }
    }

    public boolean isDemoTenant(Tenant tenant) {
        return tenant != null && !tenant.isInternal()
                && ((tenant.getDemoExpiresAt() != null)
                || (tenant.getDemoSource() != null && !tenant.getDemoSource().isBlank())
                || DEMO_PLAN_CODE.equalsIgnoreCase(tenant.getPlanCode()));
    }

    @Scheduled(zone = "UTC", cron = "${app.demo.expiration-cron:0 10 * * * *}")
    public void expireDemoTenants() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("demo-lifecycle.expire-demo-tenants")) {
            return;
        }
        Instant now = Instant.now();
        for (Tenant tenant : tenantRepository.findByDemoExpiresAtBeforeAndPurgedAtIsNullOrderByDemoExpiresAtAsc(now)) {
            demoTenantPurgeService.processExpiredTenant(tenant.getId(), now);
        }
    }

    private Tenant provisionTenant(DemoRequest request, String actor, boolean addDemoData) {
        AppUser bootstrapUser = assertBootstrapEligibility(request, actor, null);
        String baseName = requireText(request.getCompany(), "company");
        String nameCandidate = baseName;
        int nameSuffix = 2;
        while (tenantRepository.existsByNameIgnoreCase(nameCandidate)) {
            nameCandidate = baseName + " (" + nameSuffix++ + ")";
        }

        String slug = normalizeSlug(baseName);
        String candidate = slug;
        int suffix = 2;
        while (tenantRepository.existsBySlugIgnoreCase(candidate)) {
            candidate = slug + "-" + suffix++;
        }
        Tenant tenant = addDemoData
                ? tenantService.createTenant(
                        nameCandidate,
                        candidate,
                        TenantService.DEFAULT_PLAN_CODE,
                        "demo-request:" + request.getId(),
                        true)
                : tenantService.createTenant(
                        nameCandidate,
                        candidate,
                        TenantService.DEFAULT_PLAN_CODE,
                        "demo-request:" + request.getId());
        Instant expiresAt = Instant.now().plus(7, ChronoUnit.DAYS);
        tenant.setDemoExpiresAt(expiresAt);
        tenant.setDemoCreatedBy(trimToNull(actor));
        if (!addDemoData) {
            tenant.setDemoSource(DEMO_SOURCE_REQUEST_REVIEW);
        }
        tenant.setDemoOwnerEmail(request.getEmail());
        tenant.setMaxConnectorCount(25);
        tenant.setMaxServiceAccountCount(0);
        tenant.setMaxDailySbomUploads(5);
        tenant.setMaxDailyExposureRefreshes(3);
        tenant.setMaxExportRows(1000);
        Tenant saved = tenantRepository.save(tenant);
        identityAdministrationService.assertEligibleForTenantMembership(bootstrapUser, saved.getId());
        identityAdministrationService.addMember(saved.getId(), request.getEmail(), request.getEmail(), request.getFullName(), "TENANT_ADMIN");
        return saved;
    }

    private AppUser assertBootstrapEligibility(DemoRequest request, String actor, UUID tenantId) {
        try {
            AppUser user = identityAdministrationService.loadOrCreateLockedUser(
                    request.getEmail(),
                    request.getEmail(),
                    request.getFullName());
            identityAdministrationService.assertEligibleForTenantMembership(user, tenantId);
            return user;
        } catch (ResponseStatusException ex) {
            if (ex.getStatusCode() == HttpStatus.CONFLICT) {
                request.setStatus("ERROR");
                request.setBootstrapStatus("BLOCKED_DUPLICATE_AFFILIATION");
                request.setDecidedAt(Instant.now());
                request.setDecidedBy(trimToNull(actor));
                demoRequestRepository.save(request);
                throw new DemoAccessException(
                        "DEMO_BOOTSTRAP_DUPLICATE_AFFILIATION",
                        "This email already has active access to another tenant",
                        HttpStatus.CONFLICT
                );
            }
            throw ex;
        }
    }

    private DemoInvite createInvite(DemoRequest request, Tenant tenant) {
        DemoInvite invite = new DemoInvite();
        invite.setRequest(request);
        invite.setTenant(tenant);
        invite.setEmail(request.getEmail());
        invite.setToken(newToken());
        invite.setStatus("READY");
        Instant defaultExpiry = Instant.now().plus(7, ChronoUnit.DAYS);
        Instant tenantExpiry = tenant.getDemoExpiresAt();
        invite.setExpiresAt(tenantExpiry != null && tenantExpiry.isBefore(defaultExpiry) ? tenantExpiry : defaultExpiry);
        return demoInviteRepository.save(invite);
    }

    private void rotateInvite(DemoInvite invite) {
        invite.setToken(newToken());
        Instant expiry = Instant.now().plus(7, ChronoUnit.DAYS);
        Instant tenantExpiry = invite.getTenant().getDemoExpiresAt();
        invite.setExpiresAt(tenantExpiry != null && tenantExpiry.isBefore(expiry) ? tenantExpiry : expiry);
    }

    private void provisionTenantSchemaSynchronouslyWhenEnabled(Tenant tenant) {
        if (!synchronousTenantProvisioningEnabled
                || tenant == null
                || !"PROVISIONING".equalsIgnoreCase(tenant.getStatus())) {
            return;
        }
        if (tenantSchemaMigrationService == null) {
            throw new IllegalStateException("Synchronous demo tenant provisioning is enabled but unavailable");
        }
        tenantSchemaMigrationService.provisionNewTenant(tenant);
    }

    private DemoInvite deliverInvite(DemoInvite invite, DemoRequest request) {
        ResendEmailClient.DeliveryResult deliveryResult = demoInviteEmailService.sendInvite(request, invite);
        if (deliveryResult.state() == ResendEmailClient.DeliveryState.QUEUED) {
            invite.setStatus("QUEUED");
            auditEventService.record("demo.invite.email.queued","demo_invite",invite.getId().toString(),null);
        } else if (deliveryResult.state() == ResendEmailClient.DeliveryState.SENT) {
            invite.setStatus("SENT");
            invite.setLastSentAt(Instant.now());
            auditEventService.record("demo.invite.email.sent", "demo_invite", invite.getId().toString(), null);
        } else {
            invite.setStatus("ERROR");
            String reasonJson = deliveryResult.detail() != null
                    ? "{\"reason\":\"" + escapeJson(deliveryResult.detail()) + "\"}"
                    : null;
            if (deliveryResult.state() == ResendEmailClient.DeliveryState.SKIPPED) {
                auditEventService.record("demo.invite.email.skipped", "demo_invite", invite.getId().toString(), reasonJson);
            } else {
                auditEventService.record("demo.invite.email.failed", "demo_invite", invite.getId().toString(), reasonJson);
            }
        }
        // Keep the initialized instance. For an existing invite, save() delegates to
        // EntityManager.merge() and may return a detached copy once the repository
        // transaction closes. Serializing that copy can trigger lazy-load failures.
        demoInviteRepository.save(invite);
        return invite;
    }

    private String requestStatusForInvite(DemoInvite invite) {
        return java.util.Set.of("SENT","QUEUED","DELIVERY_UNKNOWN").contains(invite.getStatus()) ? invite.getStatus() : "ERROR";
    }

    private DemoRequest getRequest(UUID requestId) {
        return demoRequestRepository.findById(requestId)
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo request not found", HttpStatus.NOT_FOUND));
    }

    private DemoRequest getRequestForUpdate(UUID requestId) {
        return demoRequestRepository.findByIdForUpdate(requestId)
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo request not found", HttpStatus.NOT_FOUND));
    }

    private boolean isStandardRequest(DemoRequest request) {
        return request.getBootstrapStatus() != null && request.getBootstrapStatus().startsWith("STANDARD_");
    }

    private void requireUncommittedRequest(DemoRequest request) {
        if (isStandardRequest(request)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Approved Standard onboarding must be managed through the workspace lifecycle");
        }
    }

    private void requireLocalDemoSetup() {
        if (managedAuthEnabled) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Use the managed password setup process");
        }
    }

    private DemoInvite findInvite(String token) {
        return demoInviteRepository.findByTokenHash(InvitationTokens.hash(requireText(token, "token")))
                .orElseThrow(() -> new DemoAccessException("DEMO_INVITE_INVALID", "Demo invite not found", HttpStatus.NOT_FOUND));
    }

    private DemoInviteValidationResponse inviteValidationResponse(DemoInvite invite, String overrideMessage, String setupToken) {
        Instant now = Instant.now();
        Tenant tenant = invite.getTenant();
        boolean deliveryError = "ERROR".equalsIgnoreCase(invite.getStatus());
        boolean tenantExpired = tenant.getDemoExpiresAt() != null && !tenant.getDemoExpiresAt().isAfter(now);
        boolean tenantRemoved = "DELETED".equalsIgnoreCase(tenant.getStatus()) || tenant.getPurgedAt() != null;
        boolean inviteExpired = !invite.getExpiresAt().isAfter(now);
        boolean accepted = invite.getAcceptedAt() != null || "ACCEPTED".equalsIgnoreCase(invite.getStatus());
        boolean valid = !tenantRemoved && !tenantExpired && !inviteExpired && !accepted && "ACTIVE".equalsIgnoreCase(tenant.getStatus());
        String status = tenantRemoved
                ? "TENANT_REMOVED"
                : tenantExpired
                ? "TENANT_EXPIRED"
                : inviteExpired
                        ? "INVITE_EXPIRED"
                        : accepted
                                ? "ACCEPTED"
                                : deliveryError && valid
                                        ? "DELIVERY_ERROR"
                                        : valid ? "VALID" : "INVALID";
        String message = overrideMessage != null ? overrideMessage : switch (status) {
            case "VALID" -> "Invite is ready";
            case "DELIVERY_ERROR" ->
                    "Email delivery failed, but this invite link is still valid. Continue here to set the tenant password manually.";
            case "ACCEPTED" -> "Invite has already been accepted";
            case "TENANT_REMOVED" -> "Demo tenant has already been removed";
            case "TENANT_EXPIRED" -> "Demo tenant has expired";
            case "INVITE_EXPIRED" -> "Demo invite has expired";
            default -> "Demo invite is not active";
        };
        return new DemoInviteValidationResponse(
                valid,
                status,
                invite.getEmail(),
                tenant.getId(),
                tenant.getName(),
                tenant.getDemoExpiresAt(),
                invite.getExpiresAt(),
                appBaseUrl + "/login",
                message,
                setupToken);
    }

    private DemoRequestResponse toRequestResponse(DemoRequest request) {
        String provisionedPlanCode = request.getTenantId() == null
                ? TenantService.DEFAULT_PLAN_CODE
                : tenantRepository.findById(request.getTenantId())
                .map(Tenant::getPlanCode)
                .orElse(TenantService.DEFAULT_PLAN_CODE);
        return new DemoRequestResponse(
                request.getId(),
                request.getEmail(),
                request.getFullName(),
                request.getCompany(),
                request.getRoleTitle(),
                request.getCompanySize(),
                request.getUseCase(),
                request.getNotes(),
                request.getStatus(),
                request.getRequestedAt(),
                request.getDecidedAt(),
                request.getDecidedBy(),
                request.getRejectionReason(),
                request.getBootstrapStatus(),
                request.getTenantId(),
                provisionedPlanCode,
                latestInviteResponse(request.getId())
        );
    }

    private DemoInviteResponse latestInviteResponse(UUID requestId) {
        DemoInvite invite = latestInvite(requestId);
        return invite == null ? null : toInviteResponse(invite);
    }

    private DemoInvite latestInvite(UUID requestId) {
        return demoInviteRepository.findByRequest_IdOrderByCreatedAtDesc(requestId).stream()
                .max(Comparator.comparing(DemoInvite::getCreatedAt))
                .orElse(null);
    }

    private DemoInviteResponse toInviteResponse(DemoInvite invite) {
        return new DemoInviteResponse(
                invite.getId(),
                invite.getRequest() == null ? null : invite.getRequest().getId(),
                invite.getTenant().getId(),
                invite.getTenant().getName(),
                invite.getEmail(),
                invite.getStatus(),
                invite.getExpiresAt(),
                invite.getAcceptedAt(),
                invite.getLastSentAt(),
                invite.getToken() == null ? null : appBaseUrl + "/invite#token=" + invite.getToken()
        );
    }

    private Long daysRemaining(Instant expiresAt) {
        if (expiresAt == null) {
            return null;
        }
        long hours = Instant.now().until(expiresAt, ChronoUnit.HOURS);
        return Math.max(0, (hours + 23) / 24);
    }

    private long safeLong(Integer value) {
        return value == null ? 0L : value.longValue();
    }

    private String newToken() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String normalizeSlug(String value) {
        String slug = requireText(value, "company")
                .toLowerCase()
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
        return slug.isBlank() ? "demo" : slug;
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String escapeJson(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
