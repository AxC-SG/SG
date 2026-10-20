package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TurnstileVerificationService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class DemoLifecycleControllerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void inviteAcceptanceRunsInExplicitPreAuthenticationContext() {
        DemoLifecycleService lifecycleService = mock(DemoLifecycleService.class);
        DemoInviteValidationResponse accepted = new DemoInviteValidationResponse(
                false, "ACCEPTED", "alex@example.com", null, "Example", null, null, "/login", "Accepted", "setup-token");
        when(lifecycleService.acceptInvite("invite-token")).thenAnswer(invocation -> {
            assertThat(TenantContext.isPreAuthenticationContext()).isTrue();
            assertThat(TenantContext.isPlatformContext()).isFalse();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            return accepted;
        });
        DemoLifecycleController controller = new DemoLifecycleController(
                lifecycleService,
                mock(RequestActorService.class),
                mock(TurnstileVerificationService.class),
                mock(WorkspaceService.class),
                mock(PasswordSetupCookieService.class),
                mock(PublicEndpointRateLimiter.class));

        controller.acceptInvite(new com.prototype.vulnwatch.dto.InvitationTokenRequest("invite-token"), new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
        assertThat(TenantContext.getCurrentTenantId()).isNull();
    }

    @Test
    void demoRequestVerifiesCaptchaBeforeEnteringPreAuthenticationContext() {
        DemoLifecycleService lifecycleService = mock(DemoLifecycleService.class);
        TurnstileVerificationService turnstileService = mock(TurnstileVerificationService.class);
        DemoLifecycleController controller = new DemoLifecycleController(
                lifecycleService,
                mock(RequestActorService.class),
                turnstileService,
                mock(WorkspaceService.class),
                mock(PasswordSetupCookieService.class),
                mock(PublicEndpointRateLimiter.class));
        DemoRequestCreateRequest request = new DemoRequestCreateRequest(
                "Alex Rivera",
                "alex@example.com",
                "Example Co",
                "Security Lead",
                "101-1000",
                "SBOM validation",
                null,
                true,
                "captcha-token");

        controller.createRequest(request, new MockHttpServletRequest());

        verify(turnstileService).verifyDemoRequest("captcha-token", null);
        verify(lifecycleService).createRequest(request);
        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
    }
}
