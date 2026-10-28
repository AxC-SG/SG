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

import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.JiraAuthType;
import com.prototype.vulnwatch.domain.JiraTicketingConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.JiraTicketingConfigRequest;
import com.prototype.vulnwatch.repo.JiraTicketingConfigRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class JiraTicketingConfigServiceTest {

    private static final String KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    private final JiraTicketingConfigRepository repository = mock(JiraTicketingConfigRepository.class);
    private final OutboundHttpClient outbound = mock(OutboundHttpClient.class);
    private final TenantQuotaService quota = mock(TenantQuotaService.class);
    private final OutboundHostPolicy hostPolicy = OutboundHostPolicy.forTests();
    private final CredentialEncryptionService encryption = new CredentialEncryptionService(KEY);
    private JiraTicketingConfigService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        service = new JiraTicketingConfigService(
                repository, outbound, mock(OutboundPolicyFactory.class), quota, encryption, hostPolicy);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(repository.findByTenant_Id(tenant.getId())).thenReturn(Optional.empty());
        when(repository.save(any(JiraTicketingConfig.class))).thenAnswer(call -> call.getArgument(0));
    }

    private static JiraTicketingConfigRequest request(String secret) {
        return request("https://example.test/", secret);
    }

    private static JiraTicketingConfigRequest request(String baseUrl, String secret) {
        return new JiraTicketingConfigRequest(baseUrl, "BASIC", "svc@acme.test", secret,
                "sec", null, null, null, null, null);
    }

    @Test
    void saveEncryptsTheTokenNormalisesInputAndNeverReturnsTheSecret() {
        var response = service.save(tenant, request(" tok-secret "));

        var saved = org.mockito.ArgumentCaptor.forClass(JiraTicketingConfig.class);
        verify(repository).save(saved.capture());
        JiraTicketingConfig config = saved.getValue();
        assertNotEquals("tok-secret", config.getCredentialSecret(), "the token must be stored encrypted");
        assertEquals("tok-secret", encryption.decrypt(config.getCredentialSecret()));
        assertEquals("https://example.test", config.getBaseUrl(), "trailing slash would double up in request paths");
        assertEquals("SEC", config.getProjectKey());
        assertEquals("Task", config.getIssueTypeName());
        assertEquals(JiraAuthType.BASIC, config.getAuthType());
        assertTrue(response.hasCredentialSecret());
        assertFalse(response.toString().contains("tok-secret"));
        verify(quota).assertCanCreateConnector(tenant, "jira");
    }

    @Test
    void savingWithoutATokenKeepsTheStoredOne() {
        JiraTicketingConfig existing = new JiraTicketingConfig();
        existing.setTenant(tenant);
        existing.setCredentialSecret(encryption.encrypt("kept-token"));
        when(repository.findByTenant_Id(tenant.getId())).thenReturn(Optional.of(existing));

        service.save(tenant, request(null));

        assertEquals("kept-token", encryption.decrypt(existing.getCredentialSecret()));
        verify(quota, never()).assertCanCreateConnector(any(), any());
    }

    @Test
    void firstSaveWithoutATokenIsRejected() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, request(null)));

        assertEquals(400, error.getStatusCode().value());
        verify(repository, never()).save(any());
    }

    @Test
    void hostOutsideTheOutboundAllowlistIsRejectedBeforeAnythingIsStored() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, request("https://not-allowlisted.example.org", "tok-secret")));

        assertEquals(400, error.getStatusCode().value());
        assertTrue(error.getReason().contains("HTTP_OUTBOUND_ALLOWED_HOSTS"));
        verify(repository, never()).save(any());
    }

    @Test
    void testingAnUnconfiguredConnectorMakesNoOutboundCall() {
        ResponseStatusException error = assertThrows(ResponseStatusException.class, () -> service.test(tenant));

        assertEquals(400, error.getStatusCode().value());
        verifyNoInteractions(outbound);
    }

    @Test
    void aDisabledConnectorIsNotReadyForTicketingSoServiceNowCanTakeOverAgain() {
        service.save(tenant, request("tok-secret"));
        var saved = org.mockito.ArgumentCaptor.forClass(JiraTicketingConfig.class);
        verify(repository).save(saved.capture());
        JiraTicketingConfig config = saved.getValue();
        when(repository.findByTenant_Id(tenant.getId())).thenReturn(Optional.of(config));

        assertTrue(service.isReadyForTicketing(tenant));
        config.setEnabled(false);
        assertFalse(service.isReadyForTicketing(tenant));
    }

    @Test
    void noConfigRowMeansNotReadyAndThereIsNoEnvironmentFallback() {
        assertFalse(service.isReadyForTicketing(tenant));
        assertTrue(service.resolveRuntimeConfig(tenant).isEmpty());
    }
}
