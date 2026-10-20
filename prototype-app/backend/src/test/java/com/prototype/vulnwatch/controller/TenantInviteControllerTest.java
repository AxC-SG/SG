package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class TenantInviteControllerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void inviteAcceptanceRunsInExplicitPreAuthenticationContext() {
        TenantUserInviteService inviteService = mock(TenantUserInviteService.class);
        TenantInviteValidationResponse accepted = new TenantInviteValidationResponse(
                false, "ACCEPTED", "alex@example.com", null, "Example", "Alex", "TENANT_ADMIN", null, "Accepted", "setup-token");
        when(inviteService.acceptInvite("invite-token")).thenAnswer(invocation -> {
            assertThat(TenantContext.isPreAuthenticationContext()).isTrue();
            assertThat(TenantContext.isPlatformContext()).isFalse();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            return accepted;
        });
        TenantInviteController controller = new TenantInviteController(
                inviteService,
                mock(PasswordSetupCookieService.class),
                mock(PublicEndpointRateLimiter.class));

        controller.accept(new com.prototype.vulnwatch.dto.InvitationTokenRequest("invite-token"), new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(TenantContext.isPreAuthenticationContext()).isFalse();
        assertThat(TenantContext.getCurrentTenantId()).isNull();
    }
}
