package com.prototype.vulnwatch.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Arrays;
import java.util.List;
import java.util.function.LongSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Fixed-window, process-local controls: independent processes and restarts have separate counters. */
@Component
public class PublicEndpointRateLimiter {

    private final Cache<String, WindowCounter> counters = Caffeine.newBuilder()
            .maximumSize(100_000)
            .expireAfterAccess(Duration.ofHours(2))
            .build();
    private final boolean enabled;
    private final boolean trustProxyHeaders;
    private final List<IpAddressMatcher> trustedProxies;
    private final LongSupplier clock;

    @Autowired
    public PublicEndpointRateLimiter(
            @Value("${app.security.public-rate-limit.enabled:true}") boolean enabled,
            @Value("${app.security.public-rate-limit.trust-proxy-headers:false}") boolean trustProxyHeaders,
            @Value("${app.security.public-rate-limit.trusted-proxy-cidrs:}") String trustedProxyCidrs
    ) {
        this(enabled, trustProxyHeaders, trustedProxyCidrs, System::currentTimeMillis);
    }

    public PublicEndpointRateLimiter(boolean enabled, boolean trustProxyHeaders) {
        this(enabled, trustProxyHeaders, "", System::currentTimeMillis);
    }

    PublicEndpointRateLimiter(boolean enabled, boolean trustProxyHeaders, String trustedProxyCidrs, LongSupplier clock) {
        this.enabled = enabled;
        this.trustProxyHeaders = trustProxyHeaders;
        this.clock = clock;
        this.trustedProxies = Arrays.stream(trustedProxyCidrs.split(","))
                .map(String::trim).filter(value -> !value.isEmpty())
                .map(PublicEndpointRateLimiter::trustedProxy).toList();
    }

    public void checkRegistration(HttpServletRequest request, String email) {
        checkGlobal("registration");
        check("registration:ip:" + clientIp(request), 10, Duration.ofMinutes(15));
        check("registration:email:" + fingerprint(email), 3, Duration.ofHours(1));
    }

    public void checkLogin(HttpServletRequest request, String email) {
        checkGlobal("login");
        check("login:ip:" + clientIp(request), 30, Duration.ofMinutes(15));
        check("login:email:" + fingerprint(email), 10, Duration.ofMinutes(15));
    }

    public void checkInvite(HttpServletRequest request, String token) {
        checkGlobal("invite");
        check("invite:ip:" + clientIp(request), 60, Duration.ofMinutes(15));
        check("invite:token:" + fingerprint(token), 10, Duration.ofMinutes(15));
    }

    public void checkSetupSession(HttpServletRequest request, String token) {
        checkGlobal("setup-session");
        check("setup-session:ip:" + clientIp(request), 20, Duration.ofMinutes(15));
        check("setup-session:token:" + fingerprint(token), 5, Duration.ofMinutes(15));
    }

    public void checkPasswordSetup(HttpServletRequest request, String sessionToken) {
        checkGlobal("setup-password");
        check("setup-password:ip:" + clientIp(request), 20, Duration.ofMinutes(15));
        check("setup-password:session:" + fingerprint(sessionToken), 5, Duration.ofMinutes(15));
    }

    private void checkGlobal(String flow) {
        check(flow + ":global", 300, Duration.ofMinutes(1));
    }

    private void check(String key, int limit, Duration window) {
        if (!enabled) {
            return;
        }
        long now = clock.getAsLong();
        WindowCounter counter = counters.get(key, ignored -> new WindowCounter(now + window.toMillis()));
        long retryAfterMillis;
        synchronized (counter) {
            if (now >= counter.resetAtMillis) {
                counter.count = 0;
                counter.resetAtMillis = now + window.toMillis();
            }
            counter.count++;
            if (counter.count <= limit) {
                return;
            }
            retryAfterMillis = counter.resetAtMillis - now;
        }
        throw new PublicRateLimitException((retryAfterMillis + 999) / 1000);
    }

    public String clientIp(HttpServletRequest request) {
        String peer = numericAddress(request.getRemoteAddr());
        if (peer == null) return "unknown";
        if (!trustProxyHeaders || !isTrusted(peer)) return peer;
        // CF-Connecting-IP and Forwarded are ignored. Walk from the socket peer
        // only while each hop belongs to the explicitly configured proxy chain.
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.length() > 4096) return peer;
        String[] hops = forwarded.split(",", -1);
        if (hops.length > 32) return peer;
        String current = peer;
        for (int index = hops.length - 1; index >= 0 && isTrusted(current); index--) {
            String next = numericAddress(hops[index].trim());
            if (next == null) return peer;
            current = next;
        }
        return current;
    }

    private boolean isTrusted(String address) {
        return trustedProxies.stream().anyMatch(proxy -> proxy.matches(address));
    }

    private static IpAddressMatcher trustedProxy(String value) {
        String[] parts = value.split("/", -1);
        String address = numericAddress(parts[0]);
        if (parts.length > 2 || address == null
                || (parts.length == 2 && (!parts[1].matches("[0-9]{1,3}") || Integer.parseInt(parts[1]) == 0
                    || Integer.parseInt(parts[1]) > (address.contains(":") ? 128 : 32)))) {
            throw new IllegalStateException("Trusted proxy entries must be explicit IP addresses or bounded CIDRs.");
        }
        try {
            return new IpAddressMatcher(value);
        } catch (IllegalArgumentException invalidCidr) {
            throw new IllegalStateException("Invalid trusted proxy CIDR.", invalidCidr);
        }
    }

    private static String numericAddress(String value) {
        if (value == null || !value.matches("[0-9a-fA-F:.]{2,64}")) return null;
        if (!value.contains(":")) {
            String[] octets = value.split("\\.", -1);
            if (octets.length != 4) return null;
            for (String octet : octets) {
                if (!octet.matches("[0-9]{1,3}") || Integer.parseInt(octet) > 255) return null;
            }
        }
        try {
            return InetAddress.getByName(value).getHostAddress().toLowerCase(Locale.ROOT);
        } catch (java.net.UnknownHostException invalidAddress) {
            return null;
        }
    }

    private String fingerprint(String value) {
        String normalized = value == null ? "missing" : value.trim().toLowerCase(Locale.ROOT);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static final class WindowCounter {
        private int count;
        private long resetAtMillis;

        private WindowCounter(long resetAtMillis) {
            this.resetAtMillis = resetAtMillis;
        }
    }
}
