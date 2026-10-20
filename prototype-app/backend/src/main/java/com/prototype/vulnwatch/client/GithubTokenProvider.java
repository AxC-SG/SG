package com.prototype.vulnwatch.client;

import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

@Component
public class GithubTokenProvider {

    private static final String DEFAULT_LOCAL_TOKEN_PATH = "./secrets/github-api-token";

    private static final ThreadLocal<String> OVERRIDE_TOKEN = new ThreadLocal<>();

    private final Path localTokenPath;

    @Value("${app.github.api-token:}")
    private String apiToken;

    @Value("${app.github.api-token-file:}")
    private String apiTokenFile;

    public GithubTokenProvider() {
        this(Path.of(DEFAULT_LOCAL_TOKEN_PATH));
    }

    GithubTokenProvider(Path localTokenPath) {
        this.localTokenPath = localTokenPath;
    }

    @PostConstruct
    void validateConfiguredTokenFile() {
        if (apiTokenFile == null || apiTokenFile.isBlank()) {
            return;
        }
        readRequiredSecret(Path.of(apiTokenFile.trim()), "GitHub API token file");
    }

    /** Customer runs are explicitly anonymous or tenant-authenticated; neither can inherit feed credentials. */
    public TokenScope customerCredentials(String token) {
        String previous = OVERRIDE_TOKEN.get();
        OVERRIDE_TOKEN.set(token == null ? "" : token.trim());
        return () -> {
            if (previous == null) OVERRIDE_TOKEN.remove();
            else OVERRIDE_TOKEN.set(previous);
        };
    }

    public interface TokenScope extends AutoCloseable {
        @Override void close();
    }

    public String currentToken() {
        String token = OVERRIDE_TOKEN.get();
        return token == null ? "" : token;
    }

    public String platformFeedToken() {
        if (apiTokenFile != null && !apiTokenFile.isBlank()) {
            return readRequiredSecret(Path.of(apiTokenFile.trim()), "GitHub API token file");
        }
        String localToken = readOptionalSecret(localTokenPath);
        if (!localToken.isBlank()) {
            return localToken;
        }
        return apiToken == null ? "" : apiToken.trim();
    }

    public boolean hasToken() {
        return !currentToken().isBlank();
    }

    public void applyBearerAuth(HttpHeaders headers) {
        String token = currentToken();
        if (!token.isBlank()) {
            headers.setBearerAuth(token);
        }
    }

    public void applyPlatformFeedBearerAuth(HttpHeaders headers) {
        String token = platformFeedToken();
        if (!token.isBlank()) headers.setBearerAuth(token);
    }

    public String configurationHint() {
        return "Configure a tenant GitHub source credential for private repositories or GHCR; public repository runs use anonymous access.";
    }

    private String readRequiredSecret(Path path, String label) {
        try {
            return Files.readString(path).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read " + label, e);
        }
    }

    private String readOptionalSecret(Path path) {
        if (!Files.isRegularFile(path)) {
            return "";
        }
        try {
            return Files.readString(path).trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read local GitHub API token file", e);
        }
    }
}
