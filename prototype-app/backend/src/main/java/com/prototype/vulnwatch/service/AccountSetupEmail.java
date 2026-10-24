package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/** Shared by the privileged CLI and runtime; contains no authority or tenant metadata. */
public final class AccountSetupEmail {
    private AccountSetupEmail() { }

    public static ResendEmailClient.EmailMessage message(String email, String baseUrl, String token, Instant expiresAt) {
        URI base = URI.create(baseUrl.trim());
        if (base.getHost() == null || base.getUserInfo() != null || base.getQuery() != null || base.getFragment() != null
                || !("https".equals(base.getScheme()) || ("http".equals(base.getScheme()) && "localhost".equals(base.getHost())))) {
            throw new IllegalArgumentException("Account setup base URL must use HTTPS (HTTP localhost is allowed)");
        }
        String url = base.toString().replaceAll("/+$", "") + "/setup#token=" + token;
        String expiry = DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC).format(expiresAt);
        String text = "Hello,\n\nYou have been invited to set up an SG account.\n\nComplete account setup: " + url
                + "\n\nThis link expires at " + expiry + " and can be used once. Do not forward this email or share the link."
                + "\n\nIf you were not expecting this invitation, leave the link unused and contact your administrator through your usual channel.\n\nSG";
        String html = "<html lang=\"en\"><body><p>Hello,</p><p>You have been invited to set up an SG account.</p>"
                + "<p><a href=\"" + url.replace("&", "&amp;").replace("\"", "&quot;")
                + "\">Complete account setup</a></p><p>This link expires at " + expiry
                + " and can be used once. Do not forward this email or share the link.</p>"
                + "<p>If you were not expecting this invitation, leave the link unused and contact your administrator through your usual channel.</p><p>SG</p></body></html>";
        return new ResendEmailClient.EmailMessage(email, "Complete your SG account setup", html, text, Map.of(), null);
    }
}
