package com.prototype.vulnwatch.service;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Admission policy for the tenant-supplied SCCM SQL Server JDBC URL.
 *
 * <p>A JDBC URL is not just an address: drivers read connection properties from it that can load
 * classes, read files or open arbitrary sockets. The URL is therefore never passed through as
 * given. It must be a plain {@code jdbc:sqlserver://host[:port]} URL whose host the operator has
 * approved in {@code SCCM_ALLOWED_HOSTS}, carrying only a short list of inert connection
 * properties. Credentials never belong in the URL — they are stored encrypted and supplied
 * separately.
 *
 * <p>{@code OutboundHostPolicy} cannot be reused here: it is HTTPS-only on port 443 and refuses
 * private addresses, whereas an SCCM database is a SQL Server on an internal network. This policy
 * keeps the explicit host allowlist, but allows private ranges and refuses the addresses that are
 * never a legitimate database (loopback, link-local and cloud metadata, multicast).
 */
@Component
public class SccmJdbcPolicy {

    private static final String PREFIX = "jdbc:sqlserver://";
    private static final Pattern AUTHORITY = Pattern.compile("^([A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)(?::(\\d{1,5}))?$");
    private static final Pattern PROPERTY = Pattern.compile("^([A-Za-z]{1,40})=([A-Za-z0-9_.-]{1,128})$");
    private static final Set<String> ALLOWED_PROPERTIES = Set.of(
            "databasename", "encrypt", "trustservercertificate", "hostnameincertificate", "logintimeout");
    private static final Set<String> BOOLEAN_PROPERTIES = Set.of("trustservercertificate");

    private final Set<String> allowedHosts;
    private final Function<String, InetAddress[]> resolver;

    @Autowired
    public SccmJdbcPolicy(@Value("${app.sccm.allowed-hosts:}") String allowedHosts) {
        this(allowedHosts, host -> {
            try {
                return InetAddress.getAllByName(host);
            } catch (UnknownHostException ex) {
                throw new IllegalArgumentException("SCCM database host could not be resolved", ex);
            }
        });
    }

    SccmJdbcPolicy(String allowedHosts, Function<String, InetAddress[]> resolver) {
        Set<String> hosts = new HashSet<>();
        if (allowedHosts != null) {
            for (String host : allowedHosts.split("[,;]")) {
                String normalized = host.trim().toLowerCase(Locale.ROOT);
                if (!normalized.isEmpty() && !normalized.contains("*")) {
                    hosts.add(normalized);
                }
            }
        }
        this.allowedHosts = Set.copyOf(hosts);
        this.resolver = resolver;
    }

    /** A URL that passed the policy, with the parts the caller needs to connect and to report. */
    public record ValidatedUrl(String url, String host, int port, String database) {
    }

    /**
     * @throws IllegalArgumentException with an operator-facing message when the URL is not
     *         acceptable; the message never echoes the rejected URL's properties
     */
    public ValidatedUrl validate(String jdbcUrl) {
        if (jdbcUrl == null || jdbcUrl.isBlank()) {
            throw new IllegalArgumentException("SCCM JDBC URL is required");
        }
        String trimmed = jdbcUrl.trim();
        if (trimmed.length() > 1000 || !trimmed.regionMatches(true, 0, PREFIX, 0, PREFIX.length())) {
            throw new IllegalArgumentException(
                    "SCCM JDBC URL must start with jdbc:sqlserver:// (only SQL Server is supported)");
        }
        String rest = trimmed.substring(PREFIX.length());
        int firstSemicolon = rest.indexOf(';');
        String authority = firstSemicolon < 0 ? rest : rest.substring(0, firstSemicolon);
        String properties = firstSemicolon < 0 ? "" : rest.substring(firstSemicolon + 1);

        Matcher matcher = AUTHORITY.matcher(authority);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                    "SCCM JDBC URL host must be a plain host name or address with an optional port; "
                            + "named instances and extra path segments are not supported");
        }
        String host = matcher.group(1).toLowerCase(Locale.ROOT);
        int port = matcher.group(2) == null ? 1433 : Integer.parseInt(matcher.group(2));
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("SCCM JDBC URL port must be between 1 and 65535");
        }
        if (!allowedHosts.contains(host)) {
            throw new IllegalArgumentException(
                    "SCCM database host is not approved for this deployment. Ask an operator to add it to "
                            + "SCCM_ALLOWED_HOSTS.");
        }

        Map<String, String> seen = new LinkedHashMap<>();
        for (String property : properties.split(";")) {
            if (property.isBlank()) {
                continue;
            }
            Matcher pair = PROPERTY.matcher(property.trim());
            if (!pair.matches()) {
                throw new IllegalArgumentException("SCCM JDBC URL contains a malformed connection property");
            }
            String key = pair.group(1).toLowerCase(Locale.ROOT);
            String value = pair.group(2);
            if (!ALLOWED_PROPERTIES.contains(key)) {
                throw new IllegalArgumentException("SCCM JDBC URL property '" + pair.group(1)
                        + "' is not allowed. Permitted: databaseName, encrypt, trustServerCertificate, "
                        + "hostNameInCertificate, loginTimeout");
            }
            if (seen.put(key, value) != null) {
                throw new IllegalArgumentException("SCCM JDBC URL repeats the '" + pair.group(1) + "' property");
            }
            if (BOOLEAN_PROPERTIES.contains(key) && !value.matches("(?i)true|false")) {
                throw new IllegalArgumentException("SCCM JDBC URL property '" + pair.group(1) + "' must be true or false");
            }
            if ("encrypt".equals(key) && !value.matches("(?i)true|false|strict")) {
                throw new IllegalArgumentException("SCCM JDBC URL property 'encrypt' must be true, false or strict");
            }
            if ("logintimeout".equals(key) && !value.matches("\\d{1,2}")) {
                throw new IllegalArgumentException("SCCM JDBC URL property 'loginTimeout' must be a number of seconds");
            }
        }
        return new ValidatedUrl(trimmed, host, port, seen.get("databasename"));
    }

    /**
     * Refuses a host that currently resolves to an address no database should be reached at.
     * Called at connection time as well as at save time, because DNS can change in between.
     */
    public void assertSafeTarget(String host) {
        InetAddress[] addresses = resolver.apply(host);
        if (addresses == null || addresses.length == 0 || Arrays.stream(addresses).anyMatch(SccmJdbcPolicy::isForbidden)) {
            throw new IllegalArgumentException("SCCM database host resolves to an address that is not permitted");
        }
    }

    private static boolean isForbidden(InetAddress address) {
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
                    || (a == 169 && b == 254)
                    || (a == 100 && b == 100 && c == 100 && d == 200); // Alibaba metadata
        }
        return false;
    }
}
