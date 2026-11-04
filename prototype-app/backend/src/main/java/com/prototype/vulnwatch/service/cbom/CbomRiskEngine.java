package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomRiskClass;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class CbomRiskEngine {

    private static final Set<String> WEAK_PRIMITIVES = Set.of("md5", "sha1", "sha-1", "des", "3des", "rc4");
    private static final Set<String> DEPRECATED_PROTOCOLS = Set.of("ssl", "ssl2", "ssl3", "tls1.0", "tls1", "tls1.1", "tlsv1", "tlsv1.0", "tlsv1.1");

    private final ObjectMapper objectMapper;

    public CbomRiskEngine(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Tenant-tunable thresholds from the effective rule package. {@link #DEFAULTS} reproduces the
     * baseline package exactly; tenant values are validated against the package's hard bounds.
     */
    public record RuleParameters(int minimumRsaBits, int certificateExpiryWarningDays) {
        public static RuleParameters from(Map<String, Integer> values) {
            if (values == null) return DEFAULTS;
            return new RuleParameters(values.getOrDefault("minimumRsaBits", DEFAULTS.minimumRsaBits()),
                    values.getOrDefault("certificateExpiryWarningDays", DEFAULTS.certificateExpiryWarningDays()));
        }
    }

    public static final RuleParameters DEFAULTS = new RuleParameters(2048, 90);

    public List<CbomRiskFinding> evaluate(CbomComponent component) {
        return evaluate(component, DEFAULTS);
    }

    public List<CbomRiskFinding> evaluate(CbomComponent component, RuleParameters parameters) {
        RuleParameters p = parameters == null ? DEFAULTS : parameters;
        List<CbomRiskFinding> findings = new ArrayList<>();
        CbomAssetType assetType = component.getAssetType() == null ? CbomAssetType.UNKNOWN : component.getAssetType();
        switch (assetType) {
            case ALGORITHM -> runAlgorithmRules(component, findings, p);
            case CERTIFICATE -> runCertificateRules(component, findings, p);
            case PROTOCOL -> runProtocolRules(component, findings);
            case RELATED_CRYPTO_MATERIAL -> runMaterialRules(component, findings);
            case UNKNOWN -> runGenericRules(component, findings);
        }
        return findings;
    }

    private void runAlgorithmRules(CbomComponent component, List<CbomRiskFinding> findings, RuleParameters p) {
        String primitive = norm(component.getPrimitive());
        if (WEAK_PRIMITIVES.contains(primitive)) {
            findings.add(finding(component, "CBOM-WEAK-ALGO", CbomRiskClass.WEAK_ALGORITHM, CbomRiskSeverity.HIGH,
                    "Weak cryptographic primitive",
                    "The component uses " + component.getPrimitive() + ", which is not suitable for new cryptographic use.",
                    "primitive", component.getPrimitive(),
                    "Replace with a modern primitive such as AES-GCM, SHA-256/SHA-384, or an approved signature algorithm."));
        }
        if ("rsa".equals(primitive) && component.getKeySize() != null && component.getKeySize() < p.minimumRsaBits()) {
            findings.add(finding(component, "CBOM-RSA-SMALL-KEY", CbomRiskClass.KEY_MANAGEMENT, CbomRiskSeverity.HIGH,
                    "RSA key size below " + p.minimumRsaBits() + " bits",
                    p.minimumRsaBits() == DEFAULTS.minimumRsaBits()
                            ? "RSA keys below 2048 bits are below common minimum security baselines."
                            : "RSA keys below " + p.minimumRsaBits() + " bits are below this workspace's minimum key size.",
                    "keySize", component.getKeySize(),
                    "Rotate to RSA-2048 or stronger, or an approved elliptic-curve/post-quantum alternative."));
        }
        if (CbomQuantumClassifier.isQuantumVulnerablePrimitive(primitive)) {
            findings.add(finding(component, "CBOM-QUANTUM-VULNERABLE", CbomRiskClass.QUANTUM_VULNERABLE, CbomRiskSeverity.MEDIUM,
                    "Quantum-vulnerable asymmetric cryptography",
                    "This asymmetric primitive is vulnerable to future cryptographically relevant quantum computers.",
                    "primitive", component.getPrimitive(),
                    "Track migration plans and prefer hybrid or post-quantum schemes where supported."));
        }
    }

    private void runCertificateRules(CbomComponent component, List<CbomRiskFinding> findings, RuleParameters p) {
        if (component.getNotAfter() != null) {
            LocalDate today = LocalDate.now();
            if (component.getNotAfter().isBefore(today)) {
                findings.add(finding(component, "CBOM-CERT-EXPIRED", CbomRiskClass.CERT_EXPIRY, CbomRiskSeverity.CRITICAL,
                        "Certificate is expired",
                        "The certificate expiry date is in the past.",
                        "notAfter", component.getNotAfter(),
                        "Replace or renew the certificate immediately."));
            } else if (!component.getNotAfter().isAfter(today.plusDays(p.certificateExpiryWarningDays()))) {
                findings.add(finding(component, "CBOM-CERT-EXPIRING", CbomRiskClass.CERT_EXPIRY, CbomRiskSeverity.MEDIUM,
                        "Certificate expires within " + p.certificateExpiryWarningDays() + " days",
                        "The certificate is approaching expiry.",
                        "notAfter", component.getNotAfter(),
                        "Schedule certificate renewal before expiry."));
            }
        }
        String signature = norm(component.getSignatureAlgorithm());
        if (signature.contains("sha1") || signature.contains("md5")) {
            findings.add(finding(component, "CBOM-CERT-WEAK-SIGNATURE", CbomRiskClass.WEAK_ALGORITHM, CbomRiskSeverity.HIGH,
                    "Weak certificate signature algorithm",
                    "The certificate uses a weak signature algorithm.",
                    "signatureAlgorithm", component.getSignatureAlgorithm(),
                    "Reissue the certificate with SHA-256 or stronger signature algorithms."));
        }
    }

    private void runProtocolRules(CbomComponent component, List<CbomRiskFinding> findings) {
        String version = norm(component.getProtocolVersion()).replace(" ", "");
        String primitive = norm(component.getPrimitive());
        if (DEPRECATED_PROTOCOLS.contains(version) || DEPRECATED_PROTOCOLS.contains(primitive + version)) {
            findings.add(finding(component, "CBOM-DEPRECATED-PROTOCOL", CbomRiskClass.DEPRECATED_PROTOCOL, CbomRiskSeverity.HIGH,
                    "Deprecated cryptographic protocol",
                    "The protocol version is no longer considered safe for production use.",
                    "protocolVersion", component.getProtocolVersion(),
                    "Disable deprecated protocols and require TLS 1.2 or TLS 1.3 as appropriate."));
        }
    }

    private void runMaterialRules(CbomComponent component, List<CbomRiskFinding> findings) {
        String type = norm(component.getComponentType());
        String state = norm(component.getState());
        String storage = norm(component.getStorageLocation());
        if (state.contains("compromised")) {
            findings.add(finding(component, "CBOM-MATERIAL-COMPROMISED", CbomRiskClass.CREDENTIAL_EXPOSURE, CbomRiskSeverity.CRITICAL,
                    "Cryptographic material is marked compromised",
                    "The CBOM marks this key, secret, or credential as compromised.",
                    "state", component.getState(),
                    "Revoke, rotate, and investigate all dependent systems."));
        }
        if ((type.contains("credential") || type.contains("private") || type.contains("secret") || type.contains("key"))
                && storage.contains("env")) {
            findings.add(finding(component, "CBOM-SECRET-ENV-STORAGE", CbomRiskClass.STORAGE_RISK, CbomRiskSeverity.MEDIUM,
                    "Sensitive material stored in environment variables",
                    "Environment variables can leak through logs, process dumps, and platform metadata.",
                    "storageLocation", component.getStorageLocation(),
                    "Move sensitive material to a managed secret store with rotation and audit controls."));
        }
        if ((type.contains("credential") || type.contains("secret") || type.contains("key")) && isBlank(component.getUsedIn())) {
            findings.add(finding(component, "CBOM-MISSING-USAGE", CbomRiskClass.MISSING_ROTATION, CbomRiskSeverity.LOW,
                    "Cryptographic material usage is not documented",
                    "The CBOM does not identify where this material is used.",
                    "usedIn", component.getUsedIn(),
                    "Document consuming systems so rotation and incident response can be targeted."));
        }
    }

    private void runGenericRules(CbomComponent component, List<CbomRiskFinding> findings) {
        String primitive = norm(component.getPrimitive());
        if (WEAK_PRIMITIVES.contains(primitive)) {
            findings.add(finding(component, "CBOM-WEAK-CRYPTO", CbomRiskClass.WEAK_ALGORITHM, CbomRiskSeverity.HIGH,
                    "Weak cryptographic asset",
                    "The CBOM contains a weak cryptographic primitive.",
                    "primitive", component.getPrimitive(),
                    "Replace with a modern approved primitive."));
        }
    }

    private CbomRiskFinding finding(
            CbomComponent component,
            String ruleId,
            CbomRiskClass riskClass,
            CbomRiskSeverity severity,
            String title,
            String detail,
            String evidenceField,
            Object evidenceValue,
            String recommendation
    ) {
        CbomRiskFinding finding = new CbomRiskFinding();
        finding.setTenant(component.getTenant());
        finding.setComponent(component);
        finding.setRuleId(ruleId);
        finding.setRuleVersion("1");
        finding.setRiskClass(riskClass);
        finding.setSeverity(severity);
        finding.setTitle(title);
        finding.setDetail(detail);
        finding.setEvidence(writeEvidence(evidenceField, evidenceValue));
        finding.setRecommendation(recommendation);
        finding.setFindingFingerprint(fingerprint(ruleId, component.getComponentFingerprint(), evidenceField, String.valueOf(evidenceValue)));
        return finding;
    }

    private String writeEvidence(String field, Object value) {
        try {
            return objectMapper.writeValueAsString(Map.of("field", field, "value", value == null ? "" : value));
        } catch (Exception e) {
            return "{\"field\":\"" + field + "\"}";
        }
    }

    private String fingerprint(String... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(String.join("|", parts).getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder("sha256:");
            for (byte b : hash) builder.append(String.format("%02x", b));
            return builder.toString();
        } catch (Exception e) {
            return String.join("|", parts);
        }
    }

    private String norm(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
