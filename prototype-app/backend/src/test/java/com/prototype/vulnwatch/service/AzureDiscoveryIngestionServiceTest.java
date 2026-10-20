package com.prototype.vulnwatch.service;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
class AzureDiscoveryIngestionServiceTest {
 @Test void evenAlreadyCollectedPartialOrEmptyRecordsCannotChangeExistingActivity() {
  var assets=mock(AssetRepository.class); var cis=mock(CiRepository.class);
  var execution=mock(TenantSchemaExecutionService.class);
  var service=new AzureDiscoveryIngestionService(assets,cis,execution,new ObjectMapper());
  var existing=new Asset(); existing.setState(AssetState.ACTIVE);
  var record=new AzureResourceRecord("sub","/subscriptions/sub/resource","resource","type","group","region",null,null,Map.of());
  for(var records:List.of(List.<AzureResourceRecord>of(),List.of(record))) {
   assertEquals(410,assertThrows(ResponseStatusException.class,
     ()->service.ingestAll(records,new AzureDiscoveryConfig(),new Tenant(),Instant.now(),"sub")).getStatusCode().value());
  }
  assertEquals(AssetState.ACTIVE,existing.getState()); verifyNoInteractions(assets,cis,execution);
 }
}
