package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TenantInviteEmailService {

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("MMM d, yyyy 'at' h:mm a 'UTC'").withZone(ZoneOffset.UTC);

    private final InvitationEmailOutboxService outbox;
    private final String appBaseUrl;

    public TenantInviteEmailService(
            InvitationEmailOutboxService outbox,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl
    ) {
        this.outbox = outbox;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    public ResendEmailClient.DeliveryResult sendInvite(TenantUserInvite invite) {
        String inviteUrl = appBaseUrl + "/tenant-invite#token=" + invite.getToken();
        String loginUrl = appBaseUrl + "/login";
        String displayName = invite.getDisplayName() == null || invite.getDisplayName().isBlank()
                ? invite.getEmail()
                : invite.getDisplayName().trim();
        String tenantName = invite.getTenant().getName();
        String subject = "You have been invited to " + tenantName + " on Scout.ai";

        Map<String, String> tags = new LinkedHashMap<>();
        tags.put("flow", "tenant_user_invite");
        tags.put("tenant_id", invite.getTenant().getId().toString());
        tags.put("invite_id", invite.getId().toString());

        return outbox.enqueue(invite.getTenant().getId(),"TENANT_INVITE",invite.getId(),invite.getTokenHash(),new ResendEmailClient.EmailMessage(
                invite.getEmail(),
                subject,
                htmlBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt()),
                textBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt()),
                tags,
                invite.getId().toString()
        ));
    }

    private String htmlBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt
    ) {
        StringBuilder body = new StringBuilder();
        body.append("<p>Hello ").append(escape(displayName)).append(",</p>");
        body.append("<p>You have been invited to the <strong>").append(escape(tenantName)).append("</strong> workspace in Scout.ai.</p>");
        body.append("<p><a href=\"").append(inviteUrl).append("\">Accept your invite</a></p>");
        body.append("<ul>");
        body.append("<li><strong>Invite link:</strong> <a href=\"").append(inviteUrl).append("\">").append(inviteUrl).append("</a></li>");
        body.append("<li><strong>Invite expires:</strong> ").append(formatInstant(inviteExpiresAt)).append("</li>");
        body.append("<li><strong>Login portal:</strong> <a href=\"").append(loginUrl).append("\">").append(loginUrl).append("</a></li>");
        body.append("</ul>");
        body.append("<p>After accepting, you will set your password and sign in with this email address.</p>");
        return body.toString();
    }

    private String textBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt
    ) {
        return "Hello " + displayName + ",\n\n"
                + "You have been invited to the " + tenantName + " workspace in Scout.ai.\n\n"
                + "Accept your invite: " + inviteUrl + "\n"
                + "Invite expires: " + formatInstant(inviteExpiresAt) + "\n"
                + "Login portal: " + loginUrl + "\n\n"
                + "After accepting, you will set your password and sign in with this email address.\n";
    }

    private String formatInstant(Instant value) {
        return value == null ? "Not set" : DATE_TIME_FORMATTER.format(value);
    }

    private String escape(String value) {
        return value
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}
