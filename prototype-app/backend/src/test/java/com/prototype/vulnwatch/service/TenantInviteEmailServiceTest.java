package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class TenantInviteEmailServiceTest {

    private final InvitationEmailOutboxService resendEmailClient = org.mockito.Mockito.mock(InvitationEmailOutboxService.class);

    @Test
    void sendInvite_buildsExpectedMessageWithTrimmedBaseUrlAndTags() {
        TenantInviteEmailService service = new TenantInviteEmailService(resendEmailClient, "https://app.scout.ai///");
        TenantUserInvite invite = invite("Alice Example", "alice@example.com");
        when(resendEmailClient.enqueue(any(), any(), any(), any(), any())).thenReturn(ResendEmailClient.DeliveryResult.sent("provider-123"));

        ResendEmailClient.DeliveryResult result = service.sendInvite(invite);

        assertEquals(ResendEmailClient.DeliveryState.SENT, result.state());
        ArgumentCaptor<ResendEmailClient.EmailMessage> captor = ArgumentCaptor.forClass(ResendEmailClient.EmailMessage.class);
        verify(resendEmailClient).enqueue(any(), any(), any(), any(), captor.capture());
        ResendEmailClient.EmailMessage message = captor.getValue();
        assertEquals("alice@example.com", message.to());
        assertEquals("You have been invited to Acme Corp on Scout.ai", message.subject());
        assertEquals(invite.getId().toString(), message.idempotencyKey());
        assertEquals("tenant_user_invite", message.tags().get("flow"));
        assertEquals(invite.getTenant().getId().toString(), message.tags().get("tenant_id"));
        assertEquals(invite.getId().toString(), message.tags().get("invite_id"));
        assertTrue(message.html().contains("https://app.scout.ai/tenant-invite#token=token-123"));
        assertTrue(message.html().contains("https://app.scout.ai/login"));
        assertTrue(message.html().contains("Invite expires:</strong>"));
        assertTrue(message.html().contains("2026"));
        assertTrue(message.text().contains("Hello Alice Example,"));
        assertTrue(message.text().contains("Accept your invite: https://app.scout.ai/tenant-invite#token=token-123"));
    }

    @Test
    void sendInvite_usesEmailAsDisplayNameAndEscapesHtmlWhenNameMissing() {
        TenantInviteEmailService service = new TenantInviteEmailService(resendEmailClient, "");
        TenantUserInvite invite = invite("  ", "sam<&>@example.com");
        when(resendEmailClient.enqueue(any(), any(), any(), any(), any())).thenReturn(ResendEmailClient.DeliveryResult.skipped("not configured"));

        service.sendInvite(invite);

        ArgumentCaptor<ResendEmailClient.EmailMessage> captor = ArgumentCaptor.forClass(ResendEmailClient.EmailMessage.class);
        verify(resendEmailClient).enqueue(any(), any(), any(), any(), captor.capture());
        ResendEmailClient.EmailMessage message = captor.getValue();
        assertTrue(message.html().contains("Hello sam&lt;&amp;&gt;@example.com,"));
        assertTrue(message.html().contains("http://localhost:5173/tenant-invite#token=token-123"));
        assertTrue(message.text().contains("Hello sam<&>@example.com,"));
    }

    private static TenantUserInvite invite(String displayName, String email) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000111"));
        tenant.setName("Acme Corp");

        TenantUserInvite invite = new TenantUserInvite();
        invite.setId(UUID.fromString("00000000-0000-0000-0000-000000000222"));
        invite.setTenant(tenant);
        invite.setToken("token-123");
        invite.setEmail(email);
        invite.setDisplayName(displayName);
        invite.setExpiresAt(Instant.parse("2026-01-02T03:04:05Z"));
        return invite;
    }
}
