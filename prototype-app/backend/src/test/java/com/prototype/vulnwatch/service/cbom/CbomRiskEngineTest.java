package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomRiskClass;
import org.junit.jupiter.api.Test;

class CbomRiskEngineTest {

    private final CbomRiskEngine riskEngine = new CbomRiskEngine(new ObjectMapper());

    @Test
    void flagsSmallRsaAsKeyManagementAndQuantumRisk() {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.ALGORITHM);
        component.setComponentFingerprint("test");
        component.setName("RSA-1024");
        component.setPrimitive("RSA");
        component.setKeySize(1024);

        var findings = riskEngine.evaluate(component);

        assertThat(findings).extracting("riskClass")
                .contains(CbomRiskClass.KEY_MANAGEMENT, CbomRiskClass.QUANTUM_VULNERABLE);
    }

    @Test
    void doesNotFlagModernSymmetricAlgorithm() {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.ALGORITHM);
        component.setComponentFingerprint("test");
        component.setName("AES-256-GCM");
        component.setPrimitive("AES");
        component.setKeySize(256);

        var findings = riskEngine.evaluate(component);

        assertThat(findings).isEmpty();
    }

    @Test
    void defaultsReproduceTheBaselineThresholds() {
        var defaults = riskEngine.evaluate(rsa(2047));
        assertThat(defaults).extracting("ruleId").contains("CBOM-RSA-SMALL-KEY");
        assertThat(defaults).extracting("title").contains("RSA key size below 2048 bits");
        assertThat(riskEngine.evaluate(rsa(2048))).extracting("ruleId").doesNotContain("CBOM-RSA-SMALL-KEY");
        assertThat(riskEngine.evaluate(certificate(89))).extracting("title").contains("Certificate expires within 90 days");
        assertThat(riskEngine.evaluate(certificate(91))).extracting("ruleId").doesNotContain("CBOM-CERT-EXPIRING");
    }

    @Test
    void tenantParametersChangeTheThresholdsAndTheExplanation() {
        var strict = new CbomRiskEngine.RuleParameters(3072, 30);
        var rsa = riskEngine.evaluate(rsa(2048), strict);
        assertThat(rsa).extracting("title").contains("RSA key size below 3072 bits");
        assertThat(rsa).extracting("detail").contains("RSA keys below 3072 bits are below this workspace's minimum key size.");
        assertThat(riskEngine.evaluate(certificate(60), strict)).extracting("ruleId").doesNotContain("CBOM-CERT-EXPIRING");
        assertThat(riskEngine.evaluate(certificate(20), strict)).extracting("title").contains("Certificate expires within 30 days");
        assertThat(riskEngine.evaluate(certificate(-1), strict)).extracting("ruleId").contains("CBOM-CERT-EXPIRED");
    }

    private static CbomComponent rsa(int bits) {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.ALGORITHM);
        component.setComponentFingerprint("rsa-" + bits);
        component.setName("RSA-" + bits);
        component.setPrimitive("RSA");
        component.setKeySize(bits);
        return component;
    }

    private static CbomComponent certificate(int daysToExpiry) {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.CERTIFICATE);
        component.setComponentFingerprint("cert-" + daysToExpiry);
        component.setName("edge certificate");
        component.setSignatureAlgorithm("sha256WithRSAEncryption");
        component.setNotAfter(java.time.LocalDate.now().plusDays(daysToExpiry));
        return component;
    }
}
