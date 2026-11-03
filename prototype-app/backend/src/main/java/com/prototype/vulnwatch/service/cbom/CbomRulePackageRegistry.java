package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

/**
 * Immutable, application-packaged CBOM rule packages (ADR-0001). Loads the release index, verifies
 * every package's schema and canonical digest at startup, and exposes the release-configured
 * rollout stage and deprecation/retirement dates. Tenants choose among these packages; they never
 * supply rule content.
 */
@Component
public class CbomRulePackageRegistry {

    public enum Stage { OBSERVE, CANARY, BATCHED, GENERAL }

    /** Evaluator majors this binary can execute. */
    public static final Set<Integer> SUPPORTED_EVALUATOR_MAJORS = Set.of(1);
    /** Minimum notice a pinned tenant gets between deprecation and retirement. */
    public static final Duration MINIMUM_DEPRECATION_NOTICE = Duration.ofDays(90);
    private static final Pattern SEMVER = Pattern.compile("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$");
    private static final Set<String> MODES = Set.of("mandatory", "enabled", "optional");

    public record Rule(String id, int version, String mode) {
        public boolean mandatory() { return "mandatory".equals(mode); }
    }

    public record Parameter(String type, int defaultValue, int min, int max) { }

    public record RulePackage(String packageId, String version, String title, int evaluatorMajor,
            String evaluatorVersion, List<Rule> rules, Map<String, Parameter> parameters, String digest,
            Instant releasedAt, Stage stage, Instant deprecatedAt, Instant retiresAt) {
        public String key() { return packageId + "@" + version; }
        public boolean deprecated(Instant now) { return deprecatedAt != null && !now.isBefore(deprecatedAt); }
        public boolean retired(Instant now) { return retiresAt != null && !now.isBefore(retiresAt); }
        public Set<String> mandatoryRuleIds() {
            Set<String> ids = new LinkedHashSet<>();
            for (Rule rule : rules) if (rule.mandatory()) ids.add(rule.id());
            return ids;
        }
        /** True when every supplied parameter is declared and within this package's hard bounds. */
        public boolean accepts(Map<String, Integer> values) {
            if (values == null) return true;
            for (var entry : values.entrySet()) {
                Parameter parameter = parameters.get(entry.getKey());
                if (parameter == null || entry.getValue() == null
                        || entry.getValue() < parameter.min() || entry.getValue() > parameter.max()) return false;
            }
            return true;
        }
        public Map<String, Integer> defaults() {
            Map<String, Integer> values = new LinkedHashMap<>();
            parameters.forEach((name, parameter) -> values.put(name, parameter.defaultValue()));
            return values;
        }
    }

    private final List<RulePackage> packages;

    @org.springframework.beans.factory.annotation.Autowired
    public CbomRulePackageRegistry(ObjectMapper mapper,
            @Value("${app.cbom.rules.index:classpath:cbom-rules/index.json}") String indexLocation,
            @Value("${app.cbom.rules.rollout.stage-overrides:}") String stageOverrides) {
        this(mapper, new DefaultResourceLoader(), indexLocation, stageOverrides);
    }

    CbomRulePackageRegistry(ObjectMapper mapper, ResourceLoader loader, String indexLocation, String stageOverrides) {
        this.packages = load(mapper, loader, indexLocation, parseOverrides(stageOverrides));
    }

    public List<RulePackage> all() { return packages; }

    public Optional<RulePackage> find(String packageId, String version) {
        return packages.stream().filter(p -> p.packageId().equals(packageId) && p.version().equals(version)).findFirst();
    }

    /** Newest released version of a package regardless of stage (the rollout target). */
    public Optional<RulePackage> newest(String packageId) {
        return packages.stream().filter(p -> p.packageId().equals(packageId)).max(VERSION_ORDER);
    }

    /** The original baseline version of a package: what an unreconciled tenant was assessed with. */
    public Optional<RulePackage> oldest(String packageId) {
        return packages.stream().filter(p -> p.packageId().equals(packageId)).min(VERSION_ORDER);
    }

    /** Newest GENERAL-stage version: the effective default for a tenant the rollout has not reached. */
    public Optional<RulePackage> generalDefault(String packageId, Instant now) {
        return packages.stream().filter(p -> p.packageId().equals(packageId))
                .filter(p -> p.stage() == Stage.GENERAL && !p.retired(now)).max(VERSION_ORDER);
    }

    /**
     * Lowest supported version above {@code from} on the same evaluator major whose parameter schema
     * accepts the tenant configuration and whose mandatory rules are a superset of {@code from}'s.
     */
    public Optional<RulePackage> lowestCompatibleUpgrade(RulePackage from, Map<String, Integer> parameters, Instant now) {
        return packages.stream()
                .filter(p -> p.packageId().equals(from.packageId()))
                .filter(p -> VERSION_ORDER.compare(p, from) > 0)
                .filter(p -> !p.retired(now))
                .filter(p -> p.evaluatorMajor() == from.evaluatorMajor())
                .filter(p -> p.accepts(parameters))
                .filter(p -> p.mandatoryRuleIds().containsAll(from.mandatoryRuleIds()))
                .min(VERSION_ORDER);
    }

    public static final Comparator<RulePackage> VERSION_ORDER = Comparator.comparing(RulePackage::version, CbomRulePackageRegistry::compareVersions);

    public static int compareVersions(String left, String right) {
        String[] a = left.split("\\."), b = right.split("\\.");
        for (int i = 0; i < 3; i++) {
            int cmp = Integer.compare(Integer.parseInt(a[i]), Integer.parseInt(b[i]));
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    /** Canonical digest of what the evaluator executes: one {@code id:version:mode} line per rule. */
    public static String digest(List<Rule> rules) {
        List<String> lines = new ArrayList<>();
        for (Rule rule : rules) lines.add(rule.id() + ":" + rule.version() + ":" + rule.mode());
        try {
            return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(String.join("\n", lines).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Stage> parseOverrides(String value) {
        Map<String, Stage> overrides = new LinkedHashMap<>();
        if (value == null || value.isBlank()) return overrides;
        for (String part : value.split(",")) {
            String[] pair = part.trim().split("=");
            if (pair.length != 2) throw new IllegalStateException("Invalid CBOM rollout stage override: " + part);
            overrides.put(pair[0].trim(), Stage.valueOf(pair[1].trim().toUpperCase(Locale.ROOT)));
        }
        return overrides;
    }

    private static List<RulePackage> load(ObjectMapper mapper, ResourceLoader loader, String indexLocation, Map<String, Stage> overrides) {
        JsonNode index = read(mapper, loader, indexLocation);
        String base = indexLocation.substring(0, indexLocation.lastIndexOf('/') + 1);
        List<RulePackage> loaded = new ArrayList<>();
        Set<String> keys = new LinkedHashSet<>();
        for (JsonNode entry : required(index, "packages", indexLocation)) {
            String packageId = text(entry, "packageId", indexLocation);
            String version = text(entry, "version", indexLocation);
            String where = packageId + "@" + version;
            if (!SEMVER.matcher(version).matches()) throw invalid(where, "version is not semantic MAJOR.MINOR.PATCH");
            if (!keys.add(where)) throw invalid(where, "duplicate package version");
            JsonNode body = read(mapper, loader, base + text(entry, "resource", where));
            if (!packageId.equals(text(body, "packageId", where)) || !version.equals(text(body, "version", where))) {
                throw invalid(where, "package file identity does not match the release index");
            }
            int major = required(body, "evaluatorMajor", where).asInt();
            if (!SUPPORTED_EVALUATOR_MAJORS.contains(major)) throw invalid(where, "unsupported evaluator major " + major);
            List<Rule> rules = new ArrayList<>();
            Set<String> ruleIds = new LinkedHashSet<>();
            for (JsonNode rule : required(body, "rules", where)) {
                String id = text(rule, "id", where);
                String mode = text(rule, "mode", where);
                if (!MODES.contains(mode)) throw invalid(where, "rule " + id + " has unsupported mode " + mode);
                if (!ruleIds.add(id)) throw invalid(where, "duplicate rule " + id);
                rules.add(new Rule(id, required(rule, "version", where).asInt(), mode));
            }
            if (rules.isEmpty()) throw invalid(where, "package declares no rules");
            Map<String, Parameter> parameters = new LinkedHashMap<>();
            required(body, "parameters", where).fields().forEachRemaining(field -> {
                JsonNode p = field.getValue();
                Parameter parameter = new Parameter(text(p, "type", where), required(p, "default", where).asInt(),
                        required(p, "min", where).asInt(), required(p, "max", where).asInt());
                if (!"integer".equals(parameter.type()) || parameter.min() > parameter.defaultValue()
                        || parameter.defaultValue() > parameter.max()) {
                    throw invalid(where, "parameter " + field.getKey() + " has an invalid schema or default");
                }
                parameters.put(field.getKey(), parameter);
            });
            String digest = digest(rules);
            if (!digest.equals(text(entry, "digest", where))) {
                throw invalid(where, "digest mismatch: packaged content changed after release (computed " + digest + ")");
            }
            Instant deprecatedAt = instant(entry, "deprecatedAt");
            Instant retiresAt = instant(entry, "retiresAt");
            if (retiresAt != null && (deprecatedAt == null || retiresAt.isBefore(deprecatedAt.plus(MINIMUM_DEPRECATION_NOTICE)))) {
                throw invalid(where, "retirement requires deprecation at least 90 days earlier");
            }
            Stage stage = overrides.getOrDefault(where, Stage.valueOf(text(entry, "rolloutStage", where)));
            loaded.add(new RulePackage(packageId, version, text(body, "title", where), major,
                    text(body, "evaluatorVersion", where), List.copyOf(rules), Map.copyOf(parameters), digest,
                    instant(entry, "releasedAt"), stage, deprecatedAt, retiresAt));
        }
        for (String key : overrides.keySet()) {
            if (!keys.contains(key)) throw new IllegalStateException("CBOM rollout stage override names an unknown package: " + key);
        }
        if (loaded.isEmpty()) throw new IllegalStateException("No CBOM rule packages are packaged");
        loaded.sort(Comparator.comparing(RulePackage::packageId).thenComparing(VERSION_ORDER));
        return List.copyOf(loaded);
    }

    private static JsonNode read(ObjectMapper mapper, ResourceLoader loader, String location) {
        try (InputStream in = loader.getResource(location).getInputStream()) {
            return mapper.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read CBOM rule package resource " + location, e);
        }
    }

    private static JsonNode required(JsonNode node, String field, String where) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) throw invalid(where, "missing " + field);
        return value;
    }

    private static String text(JsonNode node, String field, String where) {
        String value = required(node, field, where).asText();
        if (value.isBlank()) throw invalid(where, "blank " + field);
        return value;
    }

    private static Instant instant(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : Instant.parse(value.asText());
    }

    private static IllegalStateException invalid(String where, String reason) {
        return new IllegalStateException("Invalid CBOM rule package " + where + ": " + reason);
    }
}
