package com.prototype.vulnwatch.client.http;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Admission policy for tenant-supplied BigFix server URLs.
 *
 * <p>BigFix runs on the customer's network (usually port 52311), so {@link OutboundHostPolicy}
 * — public addresses on 443 only — cannot be used. Instead the operator lists the approved hosts
 * in {@code BIGFIX_ALLOWED_HOSTS}; private ranges are allowed, while loopback, link-local, cloud
 * metadata and multicast addresses never are. The check runs at save time and again in the
 * transport's resolver for every connection, so a DNS change cannot redirect a sync.
 */
@Component
public class BigFixHostPolicy {

    private final Set<String> allowedHosts;
    private final Function<String, InetAddress[]> resolver;

    @Autowired
    public BigFixHostPolicy(@Value("${app.patch.bigfix.allowed-hosts:}") String allowedHosts) {
        this(allowedHosts, host -> {
            try {
                return InetAddress.getAllByName(host);
            } catch (UnknownHostException ex) {
                throw new IllegalArgumentException("BigFix server host could not be resolved", ex);
            }
        });
    }

    BigFixHostPolicy(String allowedHosts, Function<String, InetAddress[]> resolver) {
        Set<String> hosts = new HashSet<>();
        if (allowedHosts != null) {
            for (String host : allowedHosts.split("[,;]")) {
                String normalized = host.trim().toLowerCase(Locale.ROOT);
                if (!normalized.isEmpty() && !normalized.contains("*")) hosts.add(normalized);
            }
        }
        this.allowedHosts = Set.copyOf(hosts);
        this.resolver = resolver;
    }

    /**
     * The normalized server base URL ({@code https://host[:port]}), or an operator-facing reason.
     * Paths, queries, user info and IP literals are refused.
     */
    public URI validateBaseUrl(String baseUrl) {
        URI uri;
        try {
            uri = new URI(baseUrl == null ? "" : baseUrl.trim());
        } catch (Exception malformed) {
            throw new IllegalArgumentException("BigFix server URL is not a valid URL");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("BigFix server URL must use https");
        }
        if (uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || (uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !"/".equals(uri.getRawPath()))) {
            throw new IllegalArgumentException("BigFix server URL must be just https://host[:port]");
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty() || host.contains(":") || host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            throw new IllegalArgumentException("BigFix server URL must name a host, not an IP address");
        }
        if (!allowedHosts.contains(host)) {
            throw new IllegalArgumentException(
                    "BigFix server host is not approved for this deployment. Ask an operator to add it to BIGFIX_ALLOWED_HOSTS.");
        }
        int port = uri.getPort() == -1 ? 52311 : uri.getPort();
        return URI.create("https://" + host + ":" + port);
    }

    /** The addresses the transport may connect to; re-checked on every connection. */
    public InetAddress[] resolveForConnection(String host) {
        String normalized = host == null ? "" : host.toLowerCase(Locale.ROOT);
        if (!allowedHosts.contains(normalized)) {
            throw new IllegalArgumentException("BigFix server host is not approved");
        }
        InetAddress[] addresses = resolver.apply(normalized);
        if (addresses == null || addresses.length == 0 || Arrays.stream(addresses).anyMatch(BigFixHostPolicy::isForbidden)) {
            throw new IllegalArgumentException("BigFix server host resolves to an address that is not permitted");
        }
        return addresses.clone();
    }

    static boolean isForbidden(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int a = bytes[0] & 0xff;
            int b = bytes[1] & 0xff;
            int c = bytes[2] & 0xff;
            int d = bytes[3] & 0xff;
            return a == 0 || a >= 240
                    || (a == 169 && b == 254) // link-local / cloud metadata
                    || (a == 100 && b == 100 && c == 100 && d == 200); // Alibaba metadata
        }
        // AWS IPv6 metadata endpoint fd00:ec2::254.
        return (bytes[0] & 0xff) == 0xfd && bytes[1] == 0 && (bytes[2] & 0xff) == 0x0e && (bytes[3] & 0xff) == 0xc2;
    }
}
