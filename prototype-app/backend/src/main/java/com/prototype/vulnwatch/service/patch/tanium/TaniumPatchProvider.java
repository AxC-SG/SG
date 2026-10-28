package com.prototype.vulnwatch.service.patch.tanium;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchProvider;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Tanium Cloud through the Gateway GraphQL API.
 *
 * <p>Endpoints are paged with their Tanium Patch sensor readings: "Patch - Available Patches"
 * (applicable, not installed → MISSING) and "Patch - Installed Patches" (→ INSTALLED). Patch
 * deployment schedules are not read yet, so Tanium reports MISSING / INSTALLED only.
 */
@Component
public class TaniumPatchProvider implements PatchProvider {

    static final int PAGE_SIZE = 200;
    static final int MAX_PAGES = 1_000;
    static final String AVAILABLE_SENSOR = "Patch - Available Patches";
    static final String INSTALLED_SENSOR = "Patch - Installed Patches";

    static final String ENDPOINTS = """
            query ScoutPatchEndpoints($first: Int, $after: Cursor, $sensors: [EndpointSensorRef!]!) {
              endpoints(first: $first, after: $after) {
                edges { node { id name serialNumber os { name platform }
                  sensorReadings(sensors: $sensors) { columns { name values sensor { name } } } } }
                pageInfo { hasNextPage endCursor }
              }
            }""";
    static final String PROBE = """
            query ScoutPatchProbe($first: Int) {
              endpoints(first: $first) { edges { node { id } } }
            }""";

    private final TaniumGateway gateway;

    public TaniumPatchProvider(TaniumGateway gateway) {
        this.gateway = gateway;
    }

    @Override
    public PatchProviderType type() {
        return PatchProviderType.TANIUM;
    }

    @Override
    public void validate(PatchConnectorConfig config, boolean secretPresent) {
        config.setBaseUrl(TaniumGateway.validateBaseUrl(config.getBaseUrl()).toString());
        if (!secretPresent) throw new IllegalArgumentException("A Tanium API token is required");
        config.setDirectoryId(null);
        config.setClientId(null);
        config.setUsername(null);
    }

    @Override
    public PatchConnectionResult test(Tenant tenant, PatchConnectorConfig config, String secret) {
        URI base;
        try {
            base = TaniumGateway.validateBaseUrl(config.getBaseUrl());
            gateway.query(base, secret, PROBE, Map.of("first", 1));
        } catch (RuntimeException failure) {
            return PatchConnectionResult.failed(failure.getMessage());
        }
        List<PatchConnectionResult.Check> checks = new ArrayList<>();
        checks.add(new PatchConnectionResult.Check("API token and endpoints", true, true, null));
        try {
            gateway.query(base, secret, ENDPOINTS, variables(1, null));
            checks.add(new PatchConnectionResult.Check("Tanium Patch sensor readings", true, true, null));
        } catch (RuntimeException failure) {
            checks.add(new PatchConnectionResult.Check("Tanium Patch sensor readings", false, true, failure.getMessage()));
        }
        return PatchConnectionResult.of(checks, "Tanium Cloud patch data is reachable.");
    }

    @Override
    public PatchSnapshot fetch(Tenant tenant, PatchConnectorConfig config, String secret) {
        URI base = TaniumGateway.validateBaseUrl(config.getBaseUrl());
        List<JsonNode> nodes = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        String after = null;
        boolean complete = true;
        for (int page = 0; ; page++) {
            if (page >= MAX_PAGES) {
                warnings.add("Tanium endpoints exceeded the import limit; this run is partial");
                complete = false;
                break;
            }
            JsonNode endpoints = gateway.query(base, secret, ENDPOINTS, variables(PAGE_SIZE, after)).path("endpoints");
            endpoints.path("edges").forEach(edge -> nodes.add(edge.path("node")));
            JsonNode pageInfo = endpoints.path("pageInfo");
            if (!pageInfo.path("hasNextPage").asBoolean(false)) break;
            String next = pageInfo.path("endCursor").asText(null);
            if (next == null || next.equals(after)) {
                warnings.add("Tanium paging stopped without a new cursor; this run is partial");
                complete = false;
                break;
            }
            after = next;
        }
        return TaniumMapper.snapshot(nodes, complete, warnings);
    }

    static Map<String, Object> variables(int first, String after) {
        Map<String, Object> variables = new LinkedHashMap<>();
        variables.put("first", first);
        variables.put("after", after);
        variables.put("sensors", List.of(Map.of("name", AVAILABLE_SENSOR), Map.of("name", INSTALLED_SENSOR)));
        return variables;
    }

    /** Pure mapping from Gateway endpoint nodes to the provider-neutral snapshot. */
    static final class TaniumMapper {

        private static final Pattern KB = Pattern.compile("(?:KB)?(\\d{6,8})", Pattern.CASE_INSENSITIVE);
        private static final Pattern CVE = Pattern.compile("CVE-\\d{4}-\\d{4,}", Pattern.CASE_INSENSITIVE);

        private TaniumMapper() { }

        static PatchSnapshot snapshot(List<JsonNode> nodes, boolean complete, List<String> warnings) {
            List<PatchSnapshot.Device> devices = new ArrayList<>();
            Map<String, PatchSnapshot.Patch> patches = new LinkedHashMap<>();
            Map<String, PatchSnapshot.Status> statuses = new HashMap<>();
            for (JsonNode node : nodes) {
                String id = text(node, "id");
                if (id == null) continue;
                String osName = text(node.path("os"), "name");
                devices.add(new PatchSnapshot.Device(id, text(node, "name"), text(node, "serialNumber"), osName));
                FixRecord.Ecosystem ecosystem = ecosystem(text(node.path("os"), "platform"), osName);
                Map<String, List<Map<String, String>>> rows = rowsBySensor(node.path("sensorReadings").path("columns"));
                for (Map<String, String> row : rows.getOrDefault(INSTALLED_SENSOR, List.of())) {
                    PatchSnapshot.Patch patch = patch(row, ecosystem);
                    if (patch == null) continue;
                    patches.putIfAbsent(patch.externalId(), patch);
                    statuses.put(id + "|" + patch.externalId(), new PatchSnapshot.Status(id, patch.externalId(),
                            FixAssetStatus.INSTALLED, null, null, null, date(column(row, "Install Date", "Installed Date")), null));
                }
                for (Map<String, String> row : rows.getOrDefault(AVAILABLE_SENSOR, List.of())) {
                    PatchSnapshot.Patch patch = patch(row, ecosystem);
                    if (patch == null) continue;
                    patches.putIfAbsent(patch.externalId(), patch);
                    // Installed wins if a patch is reported both ways in one reading.
                    statuses.putIfAbsent(id + "|" + patch.externalId(), new PatchSnapshot.Status(id, patch.externalId(),
                            FixAssetStatus.MISSING, null, null, null, null, null));
                }
            }
            return new PatchSnapshot(devices, new ArrayList<>(patches.values()), List.of(),
                    new ArrayList<>(statuses.values()), complete, warnings);
        }

        /** Columns are parallel arrays per sensor; zip them into rows keyed by lower-case column name. */
        static Map<String, List<Map<String, String>>> rowsBySensor(JsonNode columns) {
            Map<String, Map<String, List<String>>> bySensor = new LinkedHashMap<>();
            for (JsonNode column : columns) {
                String sensor = text(column.path("sensor"), "name");
                String name = text(column, "name");
                if (sensor == null || name == null) continue;
                List<String> values = new ArrayList<>();
                column.path("values").forEach(value -> values.add(value.isNull() ? null : value.asText()));
                bySensor.computeIfAbsent(sensor, key -> new LinkedHashMap<>()).put(name.toLowerCase(Locale.ROOT), values);
            }
            Map<String, List<Map<String, String>>> result = new HashMap<>();
            bySensor.forEach((sensor, cols) -> {
                int count = cols.values().stream().mapToInt(List::size).max().orElse(0);
                List<Map<String, String>> rows = new ArrayList<>();
                for (int i = 0; i < count; i++) {
                    Map<String, String> row = new HashMap<>();
                    for (Map.Entry<String, List<String>> col : cols.entrySet()) {
                        row.put(col.getKey(), i < col.getValue().size() ? col.getValue().get(i) : null);
                    }
                    rows.add(row);
                }
                result.put(sensor, rows);
            });
            return result;
        }

        static PatchSnapshot.Patch patch(Map<String, String> row, FixRecord.Ecosystem ecosystem) {
            String title = column(row, "Title", "Name");
            // Tanium reports "[no results]" / "[current result unavailable]" placeholders.
            if (title == null || title.startsWith("[")) return null;
            String kb = kb(column(row, "KB Articles", "KB Article", "KB"));
            String externalId = kb != null ? "KB" + kb : title.length() <= 255 ? title : title.substring(0, 255);
            String severity = column(row, "Severity");
            return new PatchSnapshot.Patch(externalId, kb, column(row, "Bulletins", "Bulletin"), title,
                    kb != null ? "Microsoft" : null, null, column(row, "Classification", "Category"),
                    severity, normalizeSeverity(severity), kb != null ? FixRecord.Ecosystem.WINDOWS : ecosystem,
                    date(column(row, "Release Date")), false, null, cves(column(row, "CVE IDs", "CVEs", "CVE")));
        }

        static String normalizeSeverity(String value) {
            return switch (value == null ? "" : value.trim().toLowerCase(Locale.ROOT)) {
                case "critical" -> "CRITICAL";
                case "important", "high" -> "HIGH";
                case "moderate", "medium" -> "MEDIUM";
                case "low" -> "LOW";
                default -> null;
            };
        }

        static FixRecord.Ecosystem ecosystem(String platform, String osName) {
            String value = ((platform == null ? "" : platform) + " " + (osName == null ? "" : osName)).toLowerCase(Locale.ROOT);
            if (value.contains("windows")) return FixRecord.Ecosystem.WINDOWS;
            if (value.contains("mac")) return FixRecord.Ecosystem.MACOS;
            if (value.contains("linux") || value.contains("red hat") || value.contains("ubuntu")) return FixRecord.Ecosystem.LINUX;
            return FixRecord.Ecosystem.CROSS_PLATFORM;
        }

        static String kb(String value) {
            if (value == null) return null;
            Matcher matcher = KB.matcher(value);
            return matcher.find() ? matcher.group(1) : null;
        }

        static List<String> cves(String value) {
            Set<String> result = new LinkedHashSet<>();
            Matcher matcher = CVE.matcher(value == null ? "" : value);
            while (matcher.find() && result.size() < 500) result.add(matcher.group().toUpperCase(Locale.ROOT));
            return List.copyOf(result);
        }

        static Instant date(String value) {
            if (value == null || value.isBlank() || value.startsWith("[")) return null;
            String trimmed = value.trim();
            try {
                return OffsetDateTime.parse(trimmed).toInstant();
            } catch (Exception notOffset) {
                try {
                    return LocalDate.parse(trimmed.length() >= 10 ? trimmed.substring(0, 10) : trimmed)
                            .atStartOfDay(ZoneOffset.UTC).toInstant();
                } catch (Exception unparseable) {
                    return null;
                }
            }
        }

        private static String column(Map<String, String> row, String... names) {
            for (String name : names) {
                String value = row.get(name.toLowerCase(Locale.ROOT));
                if (value != null && !value.isBlank()) return value.trim();
            }
            return null;
        }

        private static String text(JsonNode node, String field) {
            JsonNode value = node.path(field);
            if (value.isMissingNode() || value.isNull()) return null;
            String text = value.asText();
            return text.isBlank() ? null : text;
        }
    }
}
