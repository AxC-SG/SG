package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class SccmPilotContainmentTest {
    @Test
    void disabledSaveAndTestNeverReachTheJdbcQueryOrPersistenceBoundary() {
        SccmCmdbConfigRepository configs = mock(SccmCmdbConfigRepository.class);
        SccmQueryService queries = mock(SccmQueryService.class);
        SccmCmdbConfigService service = new SccmCmdbConfigService(configs, queries,
                mock(TenantQuotaService.class), mock(CredentialEncryptionService.class));
        assertThrows(ResponseStatusException.class, () -> service.save(new Tenant(), null));
        assertThrows(ResponseStatusException.class, () -> service.test(new Tenant()));
        verifyNoInteractions(configs, queries);
    }

    @Test
    void queuedAndDirectQueriesRejectLiveAndMockModesBeforeConnectingOrReturningFixtures() {
        CredentialEncryptionService encryption = mock(CredentialEncryptionService.class);
        SccmQueryService queries = new SccmQueryService(encryption);
        for (boolean mockMode : new boolean[]{false, true}) {
            SccmCmdbConfig config = new SccmCmdbConfig();
            config.setMockMode(mockMode);
            config.setJdbcUrl("jdbc:unsupported:must-not-connect");
            assertThrows(ResponseStatusException.class, () -> queries.fetchInstallRows(config));
            assertThrows(ResponseStatusException.class, () -> queries.testConnection(config));
        }
        verifyNoInteractions(encryption);
    }
}
