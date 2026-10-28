package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.prototype.vulnwatch.domain.SccmAuthType;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SccmQueryServiceTest {

    private final CredentialEncryptionService encryption = mock(CredentialEncryptionService.class);
    private final SccmQueryService queries = new SccmQueryService(encryption, new SccmJdbcPolicy("sccm.corp.example"));

    private static SccmCmdbConfig config(String url, SccmAuthType authType) {
        SccmCmdbConfig config = new SccmCmdbConfig();
        config.setJdbcUrl(url);
        config.setAuthType(authType);
        config.setUsername("svc-scout");
        config.setCredentialSecret("encrypted");
        return config;
    }

    @Test
    void anUnapprovedHostIsRejectedBeforeCredentialsAreDecrypted() {
        assertThrows(IllegalArgumentException.class,
                () -> queries.fetchInstallRows(config("jdbc:sqlserver://other.example", SccmAuthType.SQL_AUTH)));
        verifyNoInteractions(encryption);
    }

    @Test
    void aRejectedConnectionReportsBothViewsUnreachable() {
        boolean[] result = queries.testConnection(config("jdbc:postgresql://sccm.corp.example/db", SccmAuthType.SQL_AUTH));

        assertFalse(result[0]);
        assertFalse(result[1]);
        verifyNoInteractions(encryption);
    }

    @Test
    void discoveryRowsAreDerivedOncePerPublisherAndProduct() {
        List<Map<String, String>> install = List.of(
                Map.of("publisher", "Google LLC", "display_name", "Google Chrome", "version", "117"),
                Map.of("publisher", "google llc", "display_name", "GOOGLE CHROME", "version", "118"),
                Map.of("publisher", "Microsoft", "display_name", ""));

        var discovery = queries.buildDiscoveryRows(install);

        assertEquals(1, discovery.size());
        assertEquals("google llc::google chrome", discovery.get(0).get("primary_key"));
    }
}
