package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class DemoInviteEmailServiceTest {

    @Mock
    private InvitationEmailOutboxService resendEmailClient;

    @Test
    void sendInviteUsesValidationPasswordSetupFlow() {
        when(resendEmailClient.enqueue(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any()))
                .thenReturn(ResendEmailClient.DeliveryResult.sent("email-123"));

        DemoInviteEmailService service = new DemoInviteEmailService(
                resendEmailClient,
                "https://app.example.com"
        );

        DemoRequest request = new DemoRequest();
        ReflectionTestUtils.setField(request, "id", UUID.randomUUID());
        request.setEmail("alex@example.com");
        request.setFullName("Alex Rivera");
        request.setCompany("Example Co");

        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Example Co");
        tenant.setSlug("example-co");
        tenant.setDemoExpiresAt(Instant.parse("2026-05-20T10:00:00Z"));

        DemoInvite invite = new DemoInvite();
        ReflectionTestUtils.setField(invite, "id", UUID.randomUUID());
        invite.setTenant(tenant);
        invite.setEmail("alex@example.com");
        invite.setToken("invite-token-123");
        invite.setExpiresAt(Instant.parse("2026-05-18T10:00:00Z"));

        service.sendInvite(request, invite);

        ArgumentCaptor<ResendEmailClient.EmailMessage> messageCaptor = forClass(ResendEmailClient.EmailMessage.class);
        verify(resendEmailClient).enqueue(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.any(),messageCaptor.capture());
        ResendEmailClient.EmailMessage message = messageCaptor.getValue();
        assertEquals("alex@example.com", message.to());
        assertTrue(message.subject().contains("Welcome to Scout.ai"));
        assertTrue(message.html().contains("/invite#token=invite-token-123"));
        assertTrue(message.html().contains("/login"));
        assertTrue(message.text().contains("activation link"));
        assertTrue(message.text().contains("Activation link expires:"));
        assertTrue(message.text().contains("inventory connectors workspace"));
    }
}
