package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Detects secret material in a submitted CBOM before anything is persisted.
 *
 * <p>Two detector classes exist. <b>Structural</b> detectors recognise unambiguous private-key
 * and credential formats and always reject. <b>Heuristic</b> detectors look for secret-named
 * fields carrying literal values; they run in warning-only mode until the GA gate in the CBOM
 * plan (section 5.1) passes, because legitimate CBOMs name key-custody fields. Set
 * {@code app.cbom.secret-detection.heuristic-mode=BLOCK} only after that gate is met.
 *
 * <p>Results carry a stable detector code and a JSON pointer, never the matched value.
 */
@Service
public class CbomSecretDetector {

    public enum Mode { WARN, BLOCK }

    public record Detection(String code, String jsonPointer, boolean structural) { }

    public record ScanResult(List<Detection> blocking, List<Detection> warnings) {
        public boolean rejected() { return !blocking.isEmpty(); }
    }

    /** Thrown before persistence. The message names detector codes and pointers only. */
    public static class SecretBearingCbomException extends IOException {
        private final transient List<Detection> detections;
        public SecretBearingCbomException(List<Detection> detections) {
            super("Secret-bearing CBOM rejected before persistence (" + describe(detections) + ")");
            this.detections = List.copyOf(detections);
        }
        public List<Detection> detections() { return detections; }
    }

    private static final Map<String, Pattern> STRUCTURAL = Map.of(
            "PRIVATE_KEY_PEM", Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
            "PGP_PRIVATE_KEY_BLOCK", Pattern.compile("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            "AWS_ACCESS_KEY_ID", Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
            "GITHUB_TOKEN", Pattern.compile("\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\\b|\\bgithub_pat_[A-Za-z0-9_]{60,}\\b"),
            "SLACK_TOKEN", Pattern.compile("\\bxox[abprs]-[A-Za-z0-9-]{10,}\\b"),
            "GOOGLE_API_KEY", Pattern.compile("\\bAIza[0-9A-Za-z_-]{35}\\b"),
            "STRIPE_SECRET_KEY", Pattern.compile("\\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\\b"));

    /** Field/property names whose literal value is likely secret: the normalised name ends with one of these. */
    private static final Pattern SECRET_FIELD = Pattern.compile(
            "^.*(privatekey|secretvalue|secret|password|passwd|accesstoken|refreshtoken|apikey|apisecret|secretkey|keymaterial)$");
    /** Values that reference a secret rather than contain one. */
    private static final Pattern REFERENCE_VALUE = Pattern.compile(
            "(?i)^(?:\\$\\{[^}]+}|\\{\\{[^}]+}}|(?:vault|env|arn|kms|hsm|secretsmanager|azurekeyvault|gcpsm|ref|urn|file|pkcs11|https?)[:/].*"
                    + "|(?:redacted|masked|none|null|n/?a|unknown|not[ _-]?applicable|\\*+|x+|<[^>]+>))$");
    private static final Pattern XML_SECRET_ELEMENT = Pattern.compile(
            "(?is)<(privateKey|secretValue|clientSecret|password|accessToken|apiKey)>\\s*([^<\\s][^<]{7,})</");
    /** CycloneDX related-crypto-material types whose {@code value} is the secret itself. */
    private static final java.util.Set<String> SECRET_MATERIAL_TYPES = java.util.Set.of(
            "private-key", "secret-key", "shared-secret", "password", "credential", "token", "seed");
    private static final int MIN_LITERAL_LENGTH = 8;
    private static final int MAX_DETECTIONS = 50;

    private final ObjectMapper mapper = new ObjectMapper();
    private Mode heuristicMode = Mode.WARN;

    @Value("${app.cbom.secret-detection.heuristic-mode:WARN}")
    public void setHeuristicMode(String value) {
        heuristicMode = value == null ? Mode.WARN : Mode.valueOf(value.trim().toUpperCase(Locale.ROOT));
    }

    public Mode heuristicMode() { return heuristicMode; }

    /** Rejects on any blocking detection; returns heuristic warnings when not blocking. */
    public ScanResult rejectSecretBearing(byte[] content) throws IOException {
        ScanResult result = scan(content);
        if (result.rejected()) throw new SecretBearingCbomException(result.blocking());
        return result;
    }

    public ScanResult scan(byte[] content) {
        String text = new String(content, StandardCharsets.UTF_8);
        List<Detection> detections = new ArrayList<>();
        JsonNode root = parseJson(text);
        if (root != null) {
            walk(root, "", detections);
        } else {
            scanRaw(text, detections);
        }
        List<Detection> blocking = new ArrayList<>();
        List<Detection> warnings = new ArrayList<>();
        for (Detection detection : detections) {
            if (detection.structural() || heuristicMode == Mode.BLOCK) blocking.add(detection);
            else warnings.add(detection);
        }
        return new ScanResult(List.copyOf(blocking), List.copyOf(warnings));
    }

    private void walk(JsonNode node, String pointer, List<Detection> out) {
        if (out.size() >= MAX_DETECTIONS) return;
        if (node.isObject()) {
            JsonNode type = node.get("type");
            JsonNode literal = node.get("value");
            if (type != null && type.isTextual() && SECRET_MATERIAL_TYPES.contains(type.asText().toLowerCase(Locale.ROOT))
                    && literal != null && literal.isTextual() && isLiteral(literal.asText(), true)) {
                out.add(new Detection("CDX_SECRET_MATERIAL_VALUE", pointer + "/value", true));
            }
            JsonNode propertyName = node.get("name");
            if (propertyName != null && propertyName.isTextual() && isSecretField(propertyName.asText())
                    && literal != null && literal.isTextual() && isLiteralSecret(literal.asText())) {
                out.add(new Detection("SECRET_FIELD_LITERAL", pointer + "/value", false));
            }
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                String child = pointer + "/" + escape(field.getKey());
                JsonNode value = field.getValue();
                if (value.isTextual() && isSecretField(field.getKey()) && isLiteralSecret(value.asText())) {
                    out.add(new Detection("SECRET_FIELD_LITERAL", child, false));
                }
                walk(value, child, out);
            }
        } else if (node.isArray()) {
            for (int index = 0; index < node.size(); index++) walk(node.get(index), pointer + "/" + index, out);
        } else if (node.isTextual()) {
            structural(node.asText(), pointer.isEmpty() ? "/" : pointer, out);
        }
    }

    private void scanRaw(String text, List<Detection> out) {
        structural(text, null, out);
        var matcher = XML_SECRET_ELEMENT.matcher(text);
        while (matcher.find() && out.size() < MAX_DETECTIONS) {
            if (isLiteralSecret(matcher.group(2).trim())) out.add(new Detection("SECRET_FIELD_LITERAL", null, false));
        }
    }

    private void structural(String value, String pointer, List<Detection> out) {
        STRUCTURAL.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            if (out.size() < MAX_DETECTIONS && entry.getValue().matcher(value).find()) {
                out.add(new Detection(entry.getKey(), pointer, true));
            }
        });
    }

    private boolean isSecretField(String name) {
        return SECRET_FIELD.matcher(name.toLowerCase(Locale.ROOT).replaceAll("[^a-z]", "")).matches();
    }

    private boolean isLiteralSecret(String value) { return isLiteral(value, false); }

    /** A literal (not a reference or placeholder) of at least the minimum length. */
    private boolean isLiteral(String value, boolean allowSpaces) {
        String trimmed = value == null ? "" : value.trim();
        return trimmed.length() >= MIN_LITERAL_LENGTH && (allowSpaces || !trimmed.contains(" "))
                && !REFERENCE_VALUE.matcher(trimmed).matches();
    }

    private JsonNode parseJson(String text) {
        String trimmed = text.stripLeading();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return null;
        try { return mapper.readTree(trimmed); } catch (IOException notJson) { return null; }
    }

    private static String escape(String key) { return key.replace("~", "~0").replace("/", "~1"); }

    static String describe(List<Detection> detections) {
        StringBuilder text = new StringBuilder();
        for (Detection detection : detections.subList(0, Math.min(5, detections.size()))) {
            if (!text.isEmpty()) text.append(", ");
            text.append("detector ").append(detection.code());
            if (detection.jsonPointer() != null) text.append(" at ").append(detection.jsonPointer());
        }
        if (detections.size() > 5) text.append(", +").append(detections.size() - 5).append(" more");
        return text.toString();
    }
}
