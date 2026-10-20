package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.DemoInvite;
import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DemoInviteEmailService {

    private static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("MMM d, yyyy 'at' h:mm a 'UTC'").withZone(ZoneOffset.UTC);

    private final InvitationEmailOutboxService outbox;
    private final String appBaseUrl;

    public DemoInviteEmailService(
            InvitationEmailOutboxService outbox,
            @Value("${app.demo.app-base-url:http://localhost:5173}") String appBaseUrl
    ) {
        this.outbox = outbox;
        this.appBaseUrl = appBaseUrl == null || appBaseUrl.isBlank() ? "http://localhost:5173" : appBaseUrl.replaceAll("/+$", "");
    }

    public ResendEmailClient.DeliveryResult sendInvite(DemoRequest request, DemoInvite invite) {
        Tenant tenant = invite.getTenant();
        String inviteUrl = appBaseUrl + "/invite#token=" + invite.getToken();
        String loginUrl = appBaseUrl + "/login";
        String displayName = request.getFullName() == null || request.getFullName().isBlank() ? request.getEmail() : request.getFullName().trim();
        String tenantName = tenant.getName();
        String subject = "Welcome to Scout.ai: activate your " + tenantName + " workspace";

        Map<String, String> tags = new LinkedHashMap<>();
        tags.put("flow", "demo_validation");
        tags.put("tenant_id", tenant.getId().toString());
        if (request.getId() != null) {
            tags.put("request_id", request.getId().toString());
        }

        return outbox.enqueue(invite.getTenant().getId(),"DEMO_INVITE",invite.getId(),invite.getTokenHash(),new ResendEmailClient.EmailMessage(
                invite.getEmail(),
                subject,
                htmlBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt(), tenant.getDemoExpiresAt()),
                textBody(displayName, tenantName, inviteUrl, loginUrl, invite.getExpiresAt(), tenant.getDemoExpiresAt()),
                tags,
                null
        ));
    }

    private String htmlBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt,
            Instant demoExpiresAt
    ) {
        StringBuilder body = new StringBuilder();
        body.append("<p>Welcome to Scout.ai, ").append(escape(displayName)).append(".</p>");
        body.append("<p>Your demo workspace for <strong>").append(escape(tenantName)).append("</strong> is ready.</p>");
        body.append("<p>Use the activation link below to create your tenant admin password and finish setup.</p>");
        body.append("<p><a href=\"").append(inviteUrl).append("\" target=\"_blank\" rel=\"noopener noreferrer\">Activate your workspace</a></p>");
        body.append("<p>Open the activation link in a separate browser tab to finish password setup.</p>");
        body.append("<ul>");
        body.append("<li><strong>Activation link:</strong> ").append("<a href=\"").append(inviteUrl).append("\" target=\"_blank\" rel=\"noopener noreferrer\">").append(inviteUrl).append("</a></li>");
        body.append("<li><strong>Activation link expires:</strong> ").append(formatInstant(inviteExpiresAt)).append("</li>");
        body.append("<li><strong>Shared login portal:</strong> <a href=\"").append(loginUrl).append("\" target=\"_blank\" rel=\"noopener noreferrer\">").append(loginUrl).append("</a></li>");
        body.append("<li><strong>Validation workspace access through:</strong> ").append(formatInstant(demoExpiresAt)).append("</li>");
        body.append("</ul>");
        body.append("<p>After activation:</p>");
        body.append("<ul>");
        body.append("<li>Return to the shared login portal and sign in with your email address and the password you created</li>");
        body.append("<li>You will land in the inventory connectors workspace for initial setup</li>");
        body.append("<li>Your access remains limited to the ").append(escape(tenantName)).append(" tenant demo workspace</li>");
        body.append("</ul>");
        body.append("<p>If the activation link expires, contact us and we will send you a new one.</p>");
        return body.toString();
    }

    private String textBody(
            String displayName,
            String tenantName,
            String inviteUrl,
            String loginUrl,
            Instant inviteExpiresAt,
            Instant demoExpiresAt
    ) {
        return "Welcome to Scout.ai, " + displayName + ".\n\n"
                + "Your demo workspace for " + tenantName + " is ready.\n\n"
                + "Use the activation link below to create your tenant admin password and finish setup.\n\n"
                + "Activate your workspace: " + inviteUrl + "\n"
                + "Open the activation link in a separate browser tab to finish password setup.\n"
                + "Activation link expires: " + formatInstant(inviteExpiresAt) + "\n"
                + "Shared login portal: " + loginUrl + "\n"
                + "Validation workspace access through: " + formatInstant(demoExpiresAt) + "\n\n"
                + "After activation:\n"
                + "- Return to the shared login portal and sign in with your email address and the password you created\n"
                + "- You will land in the inventory connectors workspace for initial setup\n"
                + "- Your access remains limited to the " + tenantName + " tenant demo workspace\n\n"
                + "If the activation link expires, contact us and we will send you a new one.\n";
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
