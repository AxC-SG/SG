package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.service.cbom.CbomQuantumClassifier.Readiness;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class CbomQuantumClassifierTest {

    @Test
    void symmetricHashMacAndKdfAlgorithmsAreQuantumSafeNotUnknown() {
        assertThat(own(algorithm("AES-GCM", "ae", "256", null))).isEqualTo(Readiness.QUANTUM_SAFE);
        assertThat(own(algorithm("HMAC-SHA-256", "mac", "256", null))).isEqualTo(Readiness.QUANTUM_SAFE);
        assertThat(own(algorithm("SHA-256", "hash", "256", null))).isEqualTo(Readiness.QUANTUM_SAFE);
        assertThat(own(algorithm("bcrypt", "kdf", "cost-10", null))).isEqualTo(Readiness.QUANTUM_SAFE);
        assertThat(CbomQuantumClassifier.classifyOwn(algorithm("AES-128-CBC", "block-cipher", null, null)).reason())
                .contains("prefer 256-bit keys");
    }

    @Test
    void asymmetricAlgorithmsAndCurvesAreQuantumVulnerable() {
        assertThat(own(algorithm("RSA-2048", "rsa", null, null))).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        assertThat(own(algorithm("ECDSA P-256", "signature", null, null))).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        assertThat(own(algorithm("Key agreement", "key-agree", null, "secp256r1"))).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        assertThat(own(algorithm("X25519", "key-agree", null, null))).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        CbomComponent certificate = component("edge cert", CbomAssetType.CERTIFICATE);
        certificate.setSignatureAlgorithm("sha256WithRSAEncryption");
        assertThat(own(certificate)).isEqualTo(Readiness.QUANTUM_VULNERABLE);
    }

    @Test
    void postQuantumAndHybridSchemesArePqcReadyAndBrokenAlgorithmsAreClassicallyWeak() {
        assertThat(own(algorithm("ML-KEM-768", "kem", "768", null))).isEqualTo(Readiness.PQC_READY);
        assertThat(CbomQuantumClassifier.classifyOwn(algorithm("X25519MLKEM768", "kem", null, null)).reason()).startsWith("Hybrid");
        assertThat(own(algorithm("ML-DSA-65", "signature", null, null))).isEqualTo(Readiness.PQC_READY);
        assertThat(own(algorithm("SHA-1", "hash", null, null))).isEqualTo(Readiness.CLASSICALLY_WEAK);
        assertThat(own(algorithm("3DES", "block-cipher", null, null))).isEqualTo(Readiness.CLASSICALLY_WEAK);
        CbomComponent certificate = component("legacy cert", CbomAssetType.CERTIFICATE);
        certificate.setSignatureAlgorithm("sha1WithRSAEncryption");
        assertThat(own(certificate)).isEqualTo(Readiness.CLASSICALLY_WEAK);
    }

    @Test
    void keysAndProtocolsTakeTheOutcomeOfTheAlgorithmsTheyUse() {
        CbomComponent aes = algorithm("AES-GCM", "ae", "256", null);
        CbomComponent rsa = algorithm("RSA-3072", "rsa", null, null);
        CbomComponent symmetricKey = component("Credential encryption key", CbomAssetType.RELATED_CRYPTO_MATERIAL);
        symmetricKey.setComponentType("secret-key");
        CbomComponent privateKey = component("Signing key", CbomAssetType.RELATED_CRYPTO_MATERIAL);
        privateKey.setComponentType("private-key");
        CbomComponent tls = component("TLS (outbound HTTPS)", CbomAssetType.PROTOCOL);
        CbomComponent jwt = component("JWT (HS256)", CbomAssetType.PROTOCOL);
        Map<UUID, CbomComponent> byId = Map.of(aes.getId(), aes, rsa.getId(), rsa, privateKey.getId(), privateKey, tls.getId(), tls);
        Map<UUID, List<UUID>> uses = Map.of(privateKey.getId(), List.of(rsa.getId()), tls.getId(), List.of(aes.getId(), rsa.getId()));

        assertThat(CbomQuantumClassifier.classify(symmetricKey, uses, byId).readiness()).isEqualTo(Readiness.QUANTUM_SAFE);
        CbomComponent passwordDigest = component("Local password verifier", CbomAssetType.RELATED_CRYPTO_MATERIAL);
        passwordDigest.setComponentType("digest");
        assertThat(CbomQuantumClassifier.classify(passwordDigest, uses, byId).readiness()).isEqualTo(Readiness.QUANTUM_SAFE);
        CbomQuantumClassifier.Result signing = CbomQuantumClassifier.classify(privateKey, uses, byId);
        assertThat(signing.readiness()).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        assertThat(signing.reason()).startsWith("Uses RSA-3072");
        assertThat(CbomQuantumClassifier.classify(tls, uses, byId).readiness()).isEqualTo(Readiness.QUANTUM_VULNERABLE);
        assertThat(CbomQuantumClassifier.classify(jwt, uses, byId).readiness()).isEqualTo(Readiness.QUANTUM_SAFE);
        CbomQuantumClassifier.Result bareTls = CbomQuantumClassifier.classify(component("TLS", CbomAssetType.PROTOCOL), Map.of(), Map.of());
        assertThat(bareTls.readiness()).isEqualTo(Readiness.UNKNOWN);
        assertThat(bareTls.reason()).contains("no cipher suites");
    }

    @Test
    void aSafeOutcomeNeedsEveryUsedAlgorithmDecided() {
        CbomComponent aes = algorithm("AES-GCM", "ae", "256", null);
        CbomComponent mystery = component("Vendor cipher", CbomAssetType.ALGORITHM);
        CbomComponent protocol = component("Custom protocol", CbomAssetType.PROTOCOL);
        Map<UUID, CbomComponent> byId = Map.of(aes.getId(), aes, mystery.getId(), mystery);
        Map<UUID, List<UUID>> uses = Map.of(protocol.getId(), List.of(aes.getId(), mystery.getId()));
        assertThat(CbomQuantumClassifier.classify(protocol, uses, byId).readiness()).isEqualTo(Readiness.UNKNOWN);
    }

    @Test
    void theRuleAndTheCountsShareTheVulnerablePrimitiveList() {
        assertThat(CbomQuantumClassifier.isQuantumVulnerablePrimitive("ECDH")).isTrue();
        assertThat(CbomQuantumClassifier.isQuantumVulnerablePrimitive("x25519")).isTrue();
        assertThat(CbomQuantumClassifier.isQuantumVulnerablePrimitive("ae")).isFalse();
    }

    private static Readiness own(CbomComponent component) {
        return CbomQuantumClassifier.classifyOwn(component).readiness();
    }

    private static CbomComponent algorithm(String name, String primitive, String parameterSet, String curve) {
        CbomComponent component = component(name, CbomAssetType.ALGORITHM);
        component.setPrimitive(primitive);
        component.setParameterSetIdentifier(parameterSet);
        component.setCurve(curve);
        return component;
    }

    private static CbomComponent component(String name, CbomAssetType type) {
        CbomComponent component = new CbomComponent();
        ReflectionTestUtils.setField(component, "id", UUID.randomUUID());
        component.setName(name);
        component.setAssetType(type);
        return component;
    }
}
