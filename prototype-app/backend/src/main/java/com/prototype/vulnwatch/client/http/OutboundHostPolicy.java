package com.prototype.vulnwatch.client.http;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Central SSRF policy for all outbound provider requests. */
public final class OutboundHostPolicy {
    private static final String DEFAULT_ALLOWLIST = String.join(";",
            "github=api.github.com",
            "nvd=services.nvd.nist.gov",
            "epss=api.first.org",
            "eol=endoflife.date",
            "openai=api.openai.com",
            "resend=api.resend.com",
            "turnstile=challenges.cloudflare.com",
            "kev=www.cisa.gov",
            "jvn=jvndb.jvn.jp",
            "euvd=euvdservices.enisa.europa.eu",
            "osv=api.osv.dev",
            "msrc=api.msrc.microsoft.com",
            "azure-management=management.azure.com",
            "gcp=cloudasset.googleapis.com,compute.googleapis.com,osconfig.googleapis.com,cloudresourcemanager.googleapis.com",
            "intune=graph.microsoft.com,login.microsoftonline.com",
            "csaf-microsoft=msrc.microsoft.com",
            "csaf-redhat=security.access.redhat.com",
            "csaf-cisa=www.cisa.gov"
    );

    private final Map<String, Set<String>> allowedHosts;
    private final Function<String, InetAddress[]> resolver;

    public OutboundHostPolicy(String configuredAllowlist) {
        this(configuredAllowlist, host -> {
            try {
                return InetAddress.getAllByName(host);
            } catch (java.net.UnknownHostException ex) {
                throw new IllegalArgumentException("Outbound hostname could not be resolved", ex);
            }
        });
    }

    OutboundHostPolicy(String configuredAllowlist, Function<String, InetAddress[]> resolver) {
        this.allowedHosts = parseAllowlist(configuredAllowlist == null || configuredAllowlist.isBlank()
                ? DEFAULT_ALLOWLIST : configuredAllowlist);
        this.resolver = resolver;
    }

    public static OutboundHostPolicy forTests() {
        return new OutboundHostPolicy(
                "test=example.test;github=example.test,api.github.com;nvd=example.test,services.nvd.nist.gov;epss=example.test;eol=example.test,endoflife.date;"
                        + "openai=example.test;resend=example.test;kev=example.test;jvn=example.test;"
                        + "euvd=example.test;servicenow=example.test;jira=example.test;sbom-endpoint=example.test;gcp=cloudasset.googleapis.com,compute.googleapis.com,osconfig.googleapis.com,cloudresourcemanager.googleapis.com;"
                        + "intune=graph.microsoft.com,login.microsoftonline.com;"
                        + "csaf-test=example.test;paced=example.test;euvd=example.test,euvdservices.enisa.europa.eu",
                host -> {
                    try {
                        return new InetAddress[]{InetAddress.getByAddress(host, new byte[]{93, (byte) 184, (byte) 216, 34})};
                    } catch (java.net.UnknownHostException ex) {
                        throw new IllegalStateException(ex);
                    }
                });
    }

    public void validate(String providerKey, URI uri) {
        String host = validateCommon(uri);
        Set<String> providerHosts = allowedHosts.getOrDefault(normalizeProvider(providerKey), Set.of());
        if (!providerHosts.contains(host)) {
            throw new IllegalArgumentException("Outbound hostname is not allowlisted for provider " + providerKey);
        }
        resolveAndValidate(host);
    }

    /** Validates clients that do not have a provider-specific policy at the call site. */
    public void validateAny(URI uri) {
        String host = validateCommon(uri);
        if (allowedHosts.values().stream().noneMatch(hosts -> hosts.contains(host))) {
            throw new IllegalArgumentException("Outbound hostname is not allowlisted");
        }
        resolveAndValidate(host);
    }

    private String validateCommon(URI uri) {
        if (uri == null || !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("Outbound requests must use HTTPS");
        }
        if (uri.getUserInfo() != null || uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("Outbound URL must have a hostname and no user info");
        }
        if (uri.getPort() != -1 && uri.getPort() != 443) {
            throw new IllegalArgumentException("Outbound HTTPS URLs must use port 443");
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (isIpLiteral(host)) {
            throw new IllegalArgumentException("Outbound IP literals are not allowed");
        }
        return host;
    }

    private void resolveAndValidate(String host) {
        resolveForConnection(host);
    }

    /** The transport must use these exact checked addresses, rather than resolve again. */
    public InetAddress[] resolveForConnection(String host) {
        if (host == null || allowedHosts.values().stream().noneMatch(hosts -> hosts.contains(host.toLowerCase(Locale.ROOT)))) {
            throw new IllegalArgumentException("Outbound hostname is not allowlisted");
        }
        InetAddress[] addresses = resolver.apply(host);
        if (addresses == null || addresses.length == 0 || Arrays.stream(addresses).anyMatch(OutboundHostPolicy::isBlockedAddress)) {
            throw new IllegalArgumentException("Outbound hostname resolves to a blocked address");
        }
        return addresses.clone();
    }

    private static Map<String, Set<String>> parseAllowlist(String raw) {
        Map<String, Set<String>> result = new HashMap<>();
        for (String entry : raw.split(";")) {
            String[] parts = entry.split("=", 2);
            if (parts.length != 2) continue;
            Set<String> hosts = new HashSet<>();
            for (String host : parts[1].split(",")) {
                String normalized = host.trim().toLowerCase(Locale.ROOT);
                if (!normalized.isBlank() && !isIpLiteral(normalized) && !normalized.contains("*")) {
                    hosts.add(normalized);
                }
            }
            result.put(normalizeProvider(parts[0]), Set.copyOf(hosts));
        }
        return Map.copyOf(result);
    }

    private static String normalizeProvider(String providerKey) {
        return providerKey == null ? "" : providerKey.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isIpLiteral(String host) {
        if (host.contains(":")) return true;
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private static boolean isBlockedAddress(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            int a = bytes[0] & 0xff;
            int b = bytes[1] & 0xff;
            int c = bytes[2] & 0xff;
            int d = bytes[3] & 0xff;
            return (a == 100 && b >= 64 && b <= 127) // carrier-grade NAT
                    || a == 0 || a >= 240
                    || (a == 169 && b == 254) // link-local / metadata
                    || (a == 192 && b == 0 && c == 0)
                    || (a == 192 && b == 0 && c == 2)
                    || (a == 192 && b == 88 && c == 99)
                    || (a == 198 && b == 51 && c == 100)
                    || (a == 203 && b == 0 && c == 113)
                    || (a == 198 && (b == 18 || b == 19))
                    || (a == 100 && b == 100 && c == 100 && d == 200); // Alibaba metadata
        }
        if (address instanceof Inet6Address && bytes.length == 16) {
            // Only global unicast is usable. This excludes ULA, NAT64, compatible/
            // mapped IPv4, link-local, and other special forms regardless of JDK classification.
            if ((bytes[0] & 0xe0) != 0x20) return true;
            // Teredo, benchmarking, ORCHID and documentation prefixes are not provider destinations.
            if ((bytes[0] & 0xff) == 0x20 && (bytes[1] & 0xff) == 0x01) {
                int third = bytes[2] & 0xff;
                int fourth = bytes[3] & 0xff;
                if ((third == 0 && fourth <= 0x2f) || (third == 0x0d && fourth == 0xb8)) return true;
            }
            // 6to4 embeds an IPv4 destination; reject transition routing entirely.
            if ((bytes[0] & 0xff) == 0x20 && (bytes[1] & 0xff) == 0x02) return true;
            boolean mapped = true;
            for (int i = 0; i < 10; i++) mapped &= bytes[i] == 0;
            mapped &= (bytes[10] & 0xff) == 0xff && (bytes[11] & 0xff) == 0xff;
            if (mapped) {
                byte[] ipv4 = Arrays.copyOfRange(bytes, 12, 16);
                return isBlockedAddress(toIpv4(ipv4));
            }
        }
        return false;
    }

    private static InetAddress toIpv4(byte[] bytes) {
        try {
            return InetAddress.getByAddress(bytes);
        } catch (java.net.UnknownHostException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
