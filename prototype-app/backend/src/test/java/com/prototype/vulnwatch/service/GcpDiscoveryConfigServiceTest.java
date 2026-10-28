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
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GcpDiscoveryConfigRequest;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;

class GcpDiscoveryConfigServiceTest {

    static final String KEY = "{\"type\":\"service_account\",\"project_id\":\"acme-prod\",\"private_key_id\":\"abc123\","
            + "\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nMIIfake\\n-----END PRIVATE KEY-----\\n\","
            + "\"client_email\":\"scout-reader@acme-prod.iam.gserviceaccount.com\","
            + "\"token_uri\":\"https://oauth2.googleapis.com/token\"}";

    private final GcpDiscoveryConfigRepository repo = mock(GcpDiscoveryConfigRepository.class);
    private final GcpDiscoveryTargetRepository targets = mock(GcpDiscoveryTargetRepository.class);
    private final TenantQuotaService quota = mock(TenantQuotaService.class);
    private final CredentialEncryptionService encryption =
            new CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    private GcpDiscoveryConfigService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")).thenReturn(Optional.empty());
        when(repo.save(any(GcpDiscoveryConfig.class))).thenAnswer(call -> call.getArgument(0));
        service = new GcpDiscoveryConfigService(repo, targets, quota, encryption, new ObjectMapper());
    }

    @Test
    void saveEncryptsTheCustomerKeyReadsItsIdentityAndNeverReturnsIt() {
        var response = service.save(tenant, new GcpDiscoveryConfigRequest(KEY, true, true, 30));

        var saved = ArgumentCaptor.forClass(GcpDiscoveryConfig.class);
        verify(repo).save(saved.capture());
        assertNotEquals(KEY, saved.getValue().getCredentialSecret());
        assertEquals(KEY, encryption.decrypt(saved.getValue().getCredentialSecret()));
        assertEquals("scout-reader@acme-prod.iam.gserviceaccount.com", response.serviceAccountEmail());
        assertEquals("acme-prod", response.keyProjectId());
        assertTrue(response.hasCredential());
        assertEquals(60, response.intervalMinutes(), "intervals below an hour are raised to the minimum");
        assertFalse(response.toString().contains("PRIVATE KEY"));
        verify(quota).assertCanCreateConnector(tenant, "gcp");
    }

    @Test
    void theFirstSaveAddsTheKeysOwnProjectAsATarget() {
        service.save(tenant, new GcpDiscoveryConfigRequest(KEY, null, null, null));

        var target = ArgumentCaptor.forClass(GcpDiscoveryTarget.class);
        verify(targets).save(target.capture());
        assertEquals("acme-prod", target.getValue().getProjectId());
        assertEquals(tenant, target.getValue().getTenant());
    }

    @Test
    void savingWithoutAKeyKeepsTheStoredOneAndAddsNoTarget() {
        GcpDiscoveryConfig existing = new GcpDiscoveryConfig();
        existing.setTenant(tenant);
        existing.setCredentialSecret(encryption.encrypt(KEY));
        existing.setServiceAccountEmail("scout-reader@acme-prod.iam.gserviceaccount.com");
        when(repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")).thenReturn(Optional.of(existing));

        service.save(tenant, new GcpDiscoveryConfigRequest(null, false, null, null));

        assertEquals(KEY, encryption.decrypt(existing.getCredentialSecret()));
        assertFalse(existing.isEnabled());
        verify(targets, never()).save(any());
        verify(quota, never()).assertCanCreateConnector(any(), any());
    }

    @Test
    void theFirstSaveRequiresAKeyAndInvalidKeysAreRejectedBeforeAnythingIsStored() {
        assertEquals(400, assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, new GcpDiscoveryConfigRequest(null, null, null, null))).getStatusCode().value());
        String redirected = KEY.replace("https://oauth2.googleapis.com/token", "http://169.254.169.254/token");
        assertEquals(400, assertThrows(ResponseStatusException.class,
                () -> service.save(tenant, new GcpDiscoveryConfigRequest(redirected, null, null, null))).getStatusCode().value());
        verify(repo, never()).save(any());
    }

    @Test
    void aConnectorWithoutAKeyCannotBeUsed() {
        GcpDiscoveryConfig config = new GcpDiscoveryConfig();
        config.setTenant(tenant);

        assertFalse(service.hasCredential(config));
        assertThrows(IllegalStateException.class, () -> service.credentialJson(config));
    }
}
