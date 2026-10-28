package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.SccmAuthType;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SccmCmdbConfigRequest;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;

class SccmCmdbConfigServiceTest {

    private static final String URL = "jdbc:sqlserver://sccm.corp.example:1433;databaseName=CM_P01;encrypt=true";

    private final SccmCmdbConfigRepository repository = mock(SccmCmdbConfigRepository.class);
    private final SccmQueryService queries = mock(SccmQueryService.class);
    private final TenantQuotaService quota = mock(TenantQuotaService.class);
    private final CredentialEncryptionService encryption =
            new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private SccmCmdbConfigService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        service = new SccmCmdbConfigService(repository, queries, quota, encryption,
                new SccmJdbcPolicy("sccm.corp.example"));
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")).thenReturn(Optional.empty());
        when(repository.save(any(SccmCmdbConfig.class))).thenAnswer(call -> call.getArgument(0));
    }

    private static SccmCmdbConfigRequest request(String url, String authType, Boolean mock, String secret) {
        return new SccmCmdbConfigRequest(url, authType, "svc-scout", secret, "P01", "CM_P01", 500, 120, mock, true, false, 1440);
    }

    @Test
    void saveEncryptsThePasswordAndStoresAValidatedUrl() {
        var response = service.save(tenant, request(URL, "SQL_AUTH", false, "s3cret"));

        var saved = ArgumentCaptor.forClass(SccmCmdbConfig.class);
        verify(repository).save(saved.capture());
        SccmCmdbConfig config = saved.getValue();
        assertNotEquals("s3cret", config.getCredentialSecret());
        assertEquals("s3cret", encryption.decrypt(config.getCredentialSecret()));
        assertEquals(URL, config.getJdbcUrl());
        assertFalse(config.isMockMode());
        assertTrue(response.configured());
        assertTrue(response.hasCredential());
        verify(quota).assertCanCreateConnector(tenant, "sccm");
    }

    @Test
    void mockModeCannotBeTurnedOn() {
        var error = assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, request(URL, "SQL_AUTH", true, "s3cret")));

        assertEquals(400, error.getStatusCode().value());
        verify(repository, never()).save(any());
    }

    @Test
    void windowsIntegratedAuthIsRejectedBecauseItWouldUseTheBackendIdentity() {
        var error = assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, request(URL, "WINDOWS_AUTH", false, null)));

        assertEquals(400, error.getStatusCode().value());
        verify(repository, never()).save(any());
    }

    @Test
    void anUnapprovedHostOrUnsafePropertyIsRejectedBeforeAnythingIsStored() {
        for (String url : new String[]{"jdbc:sqlserver://internal-db.example", URL + ";socketFactoryClass=evil.Factory"}) {
            var error = assertThrows(ResponseStatusException.class,
                    () -> service.save(tenant, request(url, "SQL_AUTH", false, "s3cret")));
            assertEquals(400, error.getStatusCode().value());
        }
        verify(repository, never()).save(any());
    }

    @Test
    void savingWithoutAPasswordKeepsTheStoredOne() {
        SccmCmdbConfig existing = new SccmCmdbConfig();
        existing.setTenant(tenant);
        existing.setSourceSystem("sccm");
        existing.setCredentialSecret(encryption.encrypt("kept"));
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")).thenReturn(Optional.of(existing));

        service.save(tenant, request(URL, "SQL_AUTH", false, null));

        assertEquals("kept", encryption.decrypt(existing.getCredentialSecret()));
    }

    @Test
    void testRefusesAnUnapprovedHostWithoutOpeningAConnection() {
        SccmCmdbConfig existing = new SccmCmdbConfig();
        existing.setTenant(tenant);
        existing.setSourceSystem("sccm");
        existing.setJdbcUrl("jdbc:sqlserver://moved.example");
        existing.setAuthType(SccmAuthType.SQL_AUTH);
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")).thenReturn(Optional.of(existing));

        var error = assertThrows(ResponseStatusException.class, () -> service.test(tenant));

        assertEquals(400, error.getStatusCode().value());
        verifyNoInteractions(queries);
    }
}
