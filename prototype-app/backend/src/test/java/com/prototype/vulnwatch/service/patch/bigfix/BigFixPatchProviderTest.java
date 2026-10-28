package com.prototype.vulnwatch.service.patch.bigfix;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.http.BigFixHostPolicy;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import com.prototype.vulnwatch.service.patch.bigfix.BigFixPatchProvider.BigFixMapper;
import java.net.InetAddress;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class BigFixPatchProviderTest {

    private static final String BASE = "https://bigfix.corp.example.com:52311";

    @Test
    void parsesTuplesAndSingleAnswers() {
        String xml = """
                <?xml version="1.0" encoding="UTF-8"?>
                <BESAPI><Query Resource="x"><Result>
                  <Tuple><Answer type="string">101</Answer><Answer type="string">WS-01</Answer><Answer type="string">Win11</Answer></Tuple>
                  <Tuple><Answer type="string">102</Answer><Answer type="string">WS-02 &amp; co</Answer><Answer type="string"></Answer></Tuple>
                </Result><Evaluation><Time>1ms</Time></Evaluation></Query></BESAPI>""";
        BigFixQueryParser.Rows rows = BigFixQueryParser.parse(xml, 10);
        assertThat(rows.rows()).containsExactly(List.of("101", "WS-01", "Win11"), List.of("102", "WS-02 & co", ""));
        assertThat(rows.truncated()).isFalse();

        BigFixQueryParser.Rows single = BigFixQueryParser.parse(
                "<BESAPI><Query><Result><Answer type=\"integer\">42</Answer></Result></Query></BESAPI>", 10);
        assertThat(single.rows()).containsExactly(List.of("42"));
    }

    @Test
    void capsRowsAndReportsTruncation() {
        String xml = "<BESAPI><Query><Result><Answer>1</Answer><Answer>2</Answer><Answer>3</Answer></Result></Query></BESAPI>";
        BigFixQueryParser.Rows rows = BigFixQueryParser.parse(xml, 2);
        assertThat(rows.rows()).hasSize(2);
        assertThat(rows.truncated()).isTrue();
    }

    @Test
    void refusesDtdsAndExternalEntities() {
        String xxe = """
                <?xml version="1.0"?>
                <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
                <BESAPI><Query><Result><Answer>&x;</Answer></Result></Query></BESAPI>""";
        assertThatThrownBy(() -> BigFixQueryParser.parse(xxe, 10)).isInstanceOf(BigFixQueryParser.QueryFailedException.class);
    }

    @Test
    void surfacesRelevanceErrors() {
        String xml = "<BESAPI><Query><Result/><Error>Singular expression refers to nonexistent object.</Error></Query></BESAPI>";
        assertThatThrownBy(() -> BigFixQueryParser.parse(xml, 10)).hasMessageContaining("nonexistent object");
    }

    @Test
    void mapsFixletsResultsAndActions() {
        PatchSnapshot snapshot = BigFixMapper.snapshot(
                List.of(List.of("101", "WS-01", "Win11 10.0.22631"), List.of("102", "web-1", "Linux Red Hat Enterprise Server 9")),
                List.of(
                        List.of("5001", "Enterprise Security", "MS26-OCT: Cumulative Update for Windows 11 - KB5066666",
                                "Critical", "CVE-2026-1111, cve-2026-2222", "Tue, 14 Oct 2026", "Security Update"),
                        List.of("7001", "Patches for RHEL 9", "RHSA-2026:1234: openssl Security Update (Superseded)",
                                "Important", "CVE-2026-3333", "Mon, 06 Oct 2026", "Security Advisory")),
                List.of(
                        List.of("5001", "Enterprise Security", "101", "True", ""),
                        List.of("7001", "Patches for RHEL 9", "102", "False", "Wed, 15 Oct 2026 08:00:00 +0000")),
                List.of(List.of("9001", "Deploy KB5066666", "Open", "Thu, 16 Oct 2026 01:00:00 +0000", "5001", "Enterprise Security")),
                List.of(List.of("9001", "101", "Pending Restart")),
                true, List.of());

        assertThat(snapshot.patches()).hasSize(2);
        PatchSnapshot.Patch windows = snapshot.patches().get(0);
        assertThat(windows.externalId()).isEqualTo("Enterprise Security/5001");
        assertThat(windows.kbArticle()).isEqualTo("5066666");
        assertThat(windows.severity()).isEqualTo("CRITICAL");
        assertThat(windows.ecosystem()).isEqualTo(FixRecord.Ecosystem.WINDOWS);
        assertThat(windows.cves()).containsExactly("CVE-2026-1111", "CVE-2026-2222");
        assertThat(windows.releaseDate()).isEqualTo(Instant.parse("2026-10-14T00:00:00Z"));
        PatchSnapshot.Patch rhel = snapshot.patches().get(1);
        assertThat(rhel.ecosystem()).isEqualTo(FixRecord.Ecosystem.LINUX);
        assertThat(rhel.superseded()).isTrue();

        assertThat(snapshot.statuses()).anySatisfy(status -> {
            assertThat(status.deviceExternalId()).isEqualTo("101");
            assertThat(status.status()).isEqualTo(FixAssetStatus.PENDING_REBOOT);
            assertThat(status.deploymentExternalId()).isEqualTo("9001");
        });
        assertThat(snapshot.statuses()).anySatisfy(status -> {
            assertThat(status.deviceExternalId()).isEqualTo("102");
            assertThat(status.status()).isEqualTo(FixAssetStatus.INSTALLED);
            assertThat(status.installedAt()).isEqualTo(Instant.parse("2026-10-15T08:00:00Z"));
        });
        assertThat(snapshot.deployments()).singleElement().extracting(PatchSnapshot.Deployment::startsAt)
                .isEqualTo(Instant.parse("2026-10-16T01:00:00Z"));
    }

    @Test
    void actionStatusesMapToDeploymentStates() {
        assertThat(BigFixMapper.actionStatus("Fixed")).isEqualTo(FixAssetStatus.INSTALLED);
        assertThat(BigFixMapper.actionStatus("Running")).isEqualTo(FixAssetStatus.IN_PROGRESS);
        assertThat(BigFixMapper.actionStatus("Waiting")).isEqualTo(FixAssetStatus.SCHEDULED);
        assertThat(BigFixMapper.actionStatus("Download Failed")).isEqualTo(FixAssetStatus.FAILED);
        assertThat(BigFixMapper.actionStatus("Not Relevant")).isNull();
    }

    @Test
    void hostPolicyAllowsOnlyApprovedHostsOnSafeAddresses() throws Exception {
        BigFixHostPolicyAccess policy = new BigFixHostPolicyAccess("bigfix.corp.example.com", "10.1.2.3");
        assertThat(policy.get().validateBaseUrl("https://BIGFIX.corp.example.com")).isEqualTo(URI.create(BASE));
        assertThat(policy.get().validateBaseUrl("https://bigfix.corp.example.com:443/")).isEqualTo(URI.create("https://bigfix.corp.example.com:443"));
        assertThat(policy.get().resolveForConnection("bigfix.corp.example.com")).hasSize(1);

        assertThatThrownBy(() -> policy.get().validateBaseUrl("http://bigfix.corp.example.com")).hasMessageContaining("https");
        assertThatThrownBy(() -> policy.get().validateBaseUrl("https://other.example.com")).hasMessageContaining("BIGFIX_ALLOWED_HOSTS");
        assertThatThrownBy(() -> policy.get().validateBaseUrl("https://bigfix.corp.example.com/api?x=1")).hasMessageContaining("host[:port]");
        assertThatThrownBy(() -> policy.get().validateBaseUrl("https://user:pw@bigfix.corp.example.com")).hasMessageContaining("host[:port]");

        for (String forbidden : List.of("127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1")) {
            BigFixHostPolicyAccess metadata = new BigFixHostPolicyAccess("bigfix.corp.example.com", forbidden);
            assertThatThrownBy(() -> metadata.get().resolveForConnection("bigfix.corp.example.com"))
                    .as(forbidden).hasMessageContaining("not permitted");
        }
        assertThatThrownBy(() -> new BigFixHostPolicyAccess("", "10.1.2.3").get().validateBaseUrl(BASE))
                .hasMessageContaining("not approved");
    }

    @Test
    void validateNormalizesTheUrlAndRequiresOperatorCredentials() {
        BigFixPatchProvider provider = new BigFixPatchProvider(mock(BigFixApi.class),
                new BigFixHostPolicyAccess("bigfix.corp.example.com", "10.1.2.3").get());
        PatchConnectorConfig config = config();
        config.setBaseUrl("https://bigfix.corp.example.com/");
        provider.validate(config, true);
        assertThat(config.getBaseUrl()).isEqualTo(BASE);

        config.setUsername("bad:name");
        assertThatThrownBy(() -> provider.validate(config, true)).hasMessageContaining("username");
        assertThatThrownBy(() -> provider.validate(config(), false)).hasMessageContaining("password");
    }

    @Test
    void connectionTestReportsEachCheck() {
        BigFixApi api = mock(BigFixApi.class);
        when(api.query(any(), anyString(), anyString(), eq("number of bes computers"), anyInt()))
                .thenReturn(new BigFixQueryParser.Rows(List.of(List.of("250")), false));
        when(api.query(any(), anyString(), anyString(), org.mockito.ArgumentMatchers.startsWith("number of bes fixlets"), anyInt()))
                .thenReturn(new BigFixQueryParser.Rows(List.of(List.of("0")), false));
        when(api.query(any(), anyString(), anyString(), org.mockito.ArgumentMatchers.startsWith("number of bes actions"), anyInt()))
                .thenThrow(new IllegalStateException("BigFix query failed (HTTP 403)"));
        BigFixPatchProvider provider = new BigFixPatchProvider(api, new BigFixHostPolicyAccess("bigfix.corp.example.com", "10.1.2.3").get());

        PatchConnectionResult result = provider.test(null, config(), "pw");

        assertThat(result.status()).isEqualTo("FAILED");
        assertThat(result.message()).contains("Patch Fixlets");
        assertThat(result.checks()).extracting(PatchConnectionResult.Check::name)
                .containsExactly("Operator sign-in", "Computers", "Patch Fixlets in patch sites", "Open patch actions");
    }

    @Test
    void connectionTestFailsCleanlyOnBadCredentials() {
        BigFixApi api = mock(BigFixApi.class);
        doThrow(new IllegalStateException("BigFix rejected the operator credentials (HTTP 401)"))
                .when(api).login(any(), anyString(), anyString());
        BigFixPatchProvider provider = new BigFixPatchProvider(api, new BigFixHostPolicyAccess("bigfix.corp.example.com", "10.1.2.3").get());
        assertThat(provider.test(null, config(), "pw").message()).contains("HTTP 401");
    }

    @Test
    void relevanceTemplatesAreConstants() {
        // Tenant data never reaches relevance: the fetch path only ever sends these templates.
        for (String relevance : List.of(BigFixPatchProvider.DEVICES, BigFixPatchProvider.PATCHES, BigFixPatchProvider.STATES,
                BigFixPatchProvider.ACTIONS, BigFixPatchProvider.ACTION_RESULTS)) {
            assertThat(relevance).doesNotContain("%s").doesNotContain("{");
        }
    }

    private static PatchConnectorConfig config() {
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setBaseUrl(BASE);
        config.setUsername("scout-readonly");
        return config;
    }

    /** Builds the policy with a fixed resolver through its package-private test constructor. */
    private static final class BigFixHostPolicyAccess {
        private final BigFixHostPolicy policy;

        BigFixHostPolicyAccess(String hosts, String address) {
            this.policy = com.prototype.vulnwatch.client.http.BigFixTestPolicies.withResolver(hosts, host -> {
                try {
                    return new InetAddress[]{InetAddress.getByName(address)};
                } catch (java.net.UnknownHostException impossible) {
                    throw new IllegalStateException(impossible);
                }
            });
        }

        BigFixHostPolicy get() {
            return policy;
        }
    }
}
