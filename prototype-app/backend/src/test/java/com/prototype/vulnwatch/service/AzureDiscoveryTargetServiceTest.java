package com.prototype.vulnwatch.service;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.*;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
class AzureDiscoveryTargetServiceTest {
 @Test void everyMutationAndTargetTestIsBlockedBeforeReadingCredentialsOrCallingProvider() {
  var configs=mock(AzureDiscoveryConfigRepository.class); var targets=mock(AzureDiscoveryTargetRepository.class);
  var assets=mock(AssetRepository.class); var provider=mock(AzureDiscoveryClient.class);
  var quota=mock(TenantQuotaService.class); var crypto=mock(CredentialEncryptionService.class);
  var service=new AzureDiscoveryTargetService(configs,targets,assets,provider,new ObjectMapper(),quota,crypto);
  var tenant=new Tenant(); tenant.setId(UUID.randomUUID()); UUID targetId=UUID.randomUUID();
  for(Runnable action:java.util.List.<Runnable>of(()->service.create(tenant,null),()->service.update(tenant,targetId,null),
      ()->service.delete(tenant,targetId),()->service.test(tenant,targetId),()->service.ensureLegacyTarget(null))) {
   assertEquals(410,assertThrows(ResponseStatusException.class,action::run).getStatusCode().value());
  }
  verifyNoInteractions(configs,targets,assets,provider,quota,crypto);
 }
}
