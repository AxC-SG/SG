package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Secret-detector tests, including the maintained GA corpus gate from the CBOM plan (section 5.1):
 * 100% detection of the seeded forbidden corpus and zero detections across the valid
 * public-cryptographic-material corpus. The design-partner false-rejection sample (below 0.5%)
 * is an external gate and is why heuristic detectors stay warning-only by default.
 */
class CbomSecretDetectorTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final java.util.Random RANDOM = new java.util.Random(20261103L);
    private static Map<String, String> tokens;
    private static JsonNode corpus;

    private final CbomSecretDetector detector = new CbomSecretDetector();

    @BeforeAll
    static void loadCorpus() throws Exception {
        tokens = generatedTokens();
        try (InputStream in = CbomSecretDetectorTest.class.getResourceAsStream("/cbom/secret-detector/corpus.json")) {
            corpus = MAPPER.readTree(in);
        }
    }

    @Test
    void detectsEverySeededForbiddenSecretWithItsExpectedCode() throws Exception {
        List<String> missed = new ArrayList<>();
        for (JsonNode entry : corpus.get("forbidden")) {
            byte[] document = render(entry.get("document"));
            var result = detector.scan(document);
            String expected = entry.get("expect").asText();
            boolean structural = entry.get("structural").asBoolean();
            var pool = structural ? result.blocking() : result.warnings();
            if (pool.stream().noneMatch(d -> d.code().equals(expected) && d.structural() == structural)) {
                missed.add(entry.get("id").asText());
            }
        }
        assertThat(missed).as("forbidden corpus entries not detected").isEmpty();
        assertThat(corpus.get("forbidden").size()).isGreaterThanOrEqualTo(15);
    }

    @Test
    void producesNoDetectionAcrossTheValidCorpusEvenInBlockingMode() throws Exception {
        detector.setHeuristicMode("BLOCK");
        List<String> falseDetections = new ArrayList<>();
        for (JsonNode entry : corpus.get("valid")) {
            var result = detector.scan(render(entry.get("document")));
            if (result.rejected() || !result.warnings().isEmpty()) {
                falseDetections.add(entry.get("id").asText() + "=" + result.blocking() + result.warnings());
            }
        }
        assertThat(falseDetections).as("valid corpus entries falsely detected").isEmpty();
    }

    @Test
    void heuristicDetectionsWarnByDefaultAndBlockOnlyWhenEnabled() throws Exception {
        byte[] document = ("{\"components\":[{\"name\":\"oauth\",\"client_secret\":\"" + tokens.get("BASE64_32") + "\"}]}")
                .getBytes(StandardCharsets.UTF_8);
        assertThat(detector.heuristicMode()).isEqualTo(CbomSecretDetector.Mode.WARN);
        var warned = detector.rejectSecretBearing(document);
        assertThat(warned.warnings()).singleElement().satisfies(d -> {
            assertThat(d.code()).isEqualTo("SECRET_FIELD_LITERAL");
            assertThat(d.jsonPointer()).isEqualTo("/components/0/client_secret");
        });

        detector.setHeuristicMode("BLOCK");
        assertThatThrownBy(() -> detector.rejectSecretBearing(document))
                .isInstanceOf(CbomSecretDetector.SecretBearingCbomException.class)
                .hasMessageContaining("SECRET_FIELD_LITERAL");
    }

    @Test
    void rejectsPrivateMaterialWithCodeAndPointerButNeverEchoesTheValue() throws Exception {
        String pem = tokens.get("PKCS8_PRIVATE_PEM");
        String body = pem.split("\n")[1];
        byte[] document = MAPPER.writeValueAsBytes(Map.of("components", List.of(Map.of("name", "k", "description", pem))));
        assertThatThrownBy(() -> detector.rejectSecretBearing(document))
                .isInstanceOf(CbomSecretDetector.SecretBearingCbomException.class)
                .hasMessageContaining("before persistence")
                .hasMessageContaining("PRIVATE_KEY_PEM at /components/0/description")
                .hasMessageNotContaining(body);
    }

    @Test
    void scansNonJsonDocumentsWithoutPointers() {
        String xml = "<bom><components><component><password>" + tokens.get("HEX_24") + "</password></component></components></bom>";
        var result = detector.scan(xml.getBytes(StandardCharsets.UTF_8));
        assertThat(result.warnings()).singleElement().satisfies(d -> assertThat(d.jsonPointer()).isNull());
        String xmlKey = "<bom><note>" + tokens.get("RSA_PRIVATE_PEM") + "</note></bom>";
        assertThat(detector.scan(xmlKey.getBytes(StandardCharsets.UTF_8)).rejected()).isTrue();
    }

    @Test
    void permitsDescriptionsThatOnlyDiscussSecrets() {
        String safe = "{\"description\":\"Private keys are stored in a managed HSM\",\"components\":[]}";
        assertThatCode(() -> detector.rejectSecretBearing(safe.getBytes(StandardCharsets.UTF_8))).doesNotThrowAnyException();
    }

    private static byte[] render(JsonNode template) throws Exception {
        String text = MAPPER.writeValueAsString(template);
        for (var token : tokens.entrySet()) {
            text = text.replace("@@" + token.getKey() + "@@", MAPPER.writeValueAsString(token.getValue()).replaceAll("^\"|\"$", ""));
        }
        assertThat(text).doesNotContain("@@");
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** Secret-shaped values are built at run time; header literals are split so no fixture is secret-shaped. */
    private static Map<String, String> generatedTokens() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        var pair = generator.generateKeyPair();
        String dash = "-----";
        Map<String, String> values = new LinkedHashMap<>();
        values.put("PKCS8_PRIVATE_PEM", pem(dash + "BEGIN " + "PRIVATE KEY" + dash, pair.getPrivate().getEncoded(), dash + "END PRIVATE KEY" + dash));
        values.put("RSA_PRIVATE_PEM", pem(dash + "BEGIN RSA " + "PRIVATE KEY" + dash, pair.getPrivate().getEncoded(), dash + "END RSA PRIVATE KEY" + dash));
        values.put("ENCRYPTED_PRIVATE_PEM", pem(dash + "BEGIN ENCRYPTED " + "PRIVATE KEY" + dash, random(256), dash + "END ENCRYPTED PRIVATE KEY" + dash));
        values.put("PGP_PRIVATE_BLOCK", pem(dash + "BEGIN PGP " + "PRIVATE KEY BLOCK" + dash, random(256), dash + "END PGP PRIVATE KEY BLOCK" + dash));
        values.put("RSA_PUBLIC_PEM", pem(dash + "BEGIN PUBLIC KEY" + dash, pair.getPublic().getEncoded(), dash + "END PUBLIC KEY" + dash));
        values.put("CERT_PEM", pem(dash + "BEGIN CERTIFICATE" + dash, random(600), dash + "END CERTIFICATE" + dash));
        values.put("AWS_KEY_ID", "AK" + "IA" + upperAlnum(16));
        values.put("GITHUB_TOKEN", "gh" + "p_" + alnum(36));
        values.put("SLACK_TOKEN", "xo" + "xb-" + digits(12) + "-" + alnum(24));
        values.put("GOOGLE_KEY", "AI" + "za" + alnum(35));
        values.put("STRIPE_KEY", "sk" + "_live_" + alnum(24));
        values.put("BASE64_64", Base64.getEncoder().encodeToString(random(48)));
        values.put("BASE64_32", Base64.getEncoder().withoutPadding().encodeToString(random(24)));
        values.put("HEX_24", HexFormat.of().formatHex(random(12)));
        values.put("SHA256_HEX", HexFormat.of().formatHex(random(32)));
        values.put("PASSPHRASE", "correct horse " + alnum(6) + " staple");
        return values;
    }

    private static String pem(String header, byte[] body, String footer) {
        return header + "\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(body) + "\n" + footer;
    }

    private static byte[] random(int size) { byte[] bytes = new byte[size]; RANDOM.nextBytes(bytes); return bytes; }
    private static String alnum(int size) { return pick("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", size); }
    private static String upperAlnum(int size) { return pick("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", size); }
    private static String digits(int size) { return pick("0123456789", size); }
    private static String pick(String alphabet, int size) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < size; i++) out.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        return out.toString();
    }
}
