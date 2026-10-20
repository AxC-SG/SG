package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AzureDiscoveryClientTest {
    @Test
    void hostileContinuationCannotReceiveBearerToken() {
        var template = new org.springframework.web.client.RestTemplate();
        var server = org.springframework.test.web.client.MockRestServiceServer.bindTo(template).build();
        server.expect(org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo("https://management.azure.com/subscriptions/sub-1/resources?api-version=2021-04-01"))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess("{\"value\":[],\"nextLink\":\"https://attacker.example/resources\"}", org.springframework.http.MediaType.APPLICATION_JSON));
        var credential = org.mockito.Mockito.mock(com.azure.core.credential.TokenCredential.class);
        org.mockito.Mockito.when(credential.getToken(org.mockito.ArgumentMatchers.any()))
                .thenReturn(reactor.core.publisher.Mono.just(new com.azure.core.credential.AccessToken("sentinel", java.time.OffsetDateTime.now().plusHours(1))));
        var guarded = new AzureDiscoveryClient(objectMapper, new com.prototype.vulnwatch.client.http.AzureManagementTransport(template), 2, 1000, 10000);
        var result = guarded.fetchResources(credential, "sub-1", List.of());
        assertTrue(result.error().contains("approved management endpoint"));
        org.mockito.Mockito.verify(credential, org.mockito.Mockito.times(1)).getToken(org.mockito.ArgumentMatchers.any());
        server.verify();
    }

    @Test
    void loopingContinuationAndOversizeResponseRemainIncomplete() {
        for (boolean oversized : List.of(false, true)) {
            var template = new org.springframework.web.client.RestTemplate();
            var server = org.springframework.test.web.client.MockRestServiceServer.bindTo(template).build();
            String url = "https://management.azure.com/subscriptions/sub-1/resources?api-version=2021-04-01";
            String body = oversized ? "x".repeat(101) : "{\"value\":[],\"nextLink\":\"" + url + "\"}";
            server.expect(org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo(url))
                    .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess(body, org.springframework.http.MediaType.APPLICATION_JSON));
            var credential = org.mockito.Mockito.mock(com.azure.core.credential.TokenCredential.class);
            org.mockito.Mockito.when(credential.getToken(org.mockito.ArgumentMatchers.any()))
                    .thenReturn(reactor.core.publisher.Mono.just(new com.azure.core.credential.AccessToken("sentinel", java.time.OffsetDateTime.now().plusHours(1))));
            var result = new AzureDiscoveryClient(objectMapper, new com.prototype.vulnwatch.client.http.AzureManagementTransport(template), 2, oversized ? 100 : 1000, 10000)
                    .fetchResources(credential, "sub-1", List.of());
            assertTrue(result.error() != null);
            server.verify();
        }
    }

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AzureDiscoveryClient client = new AzureDiscoveryClient(objectMapper);

    @Test
    void matchesRegion_returnsTrueWhenRegionListEmpty() {
        boolean matches = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "eastus2", List.of());
        assertTrue(matches);
    }

    @Test
    void matchesRegion_filtersOutNonSelectedRegionCaseInsensitively() {
        boolean matchesSelected = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "EastUS2", List.of("eastus2", "westus2"));
        boolean matchesUnselected = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "northeurope", List.of("eastus2", "westus2"));

        assertTrue(matchesSelected);
        assertFalse(matchesUnselected);
    }

    @Test
    void matchesRegion_treatsBlankLocationAsAlwaysMatching() {
        boolean matches = ReflectionTestUtils.invokeMethod(client, "matchesRegion", null, List.of("eastus2"));
        assertTrue(matches);
    }

    @Test
    void toRecord_extractsResourceGroupAndTagsFromArmJson() throws Exception {
        JsonNode value = objectMapper.readTree("""
                {
                  "id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
                  "name": "vm-1",
                  "type": "Microsoft.Compute/virtualMachines",
                  "location": "eastus2",
                  "kind": "",
                  "properties": { "provisioningState": "Succeeded" },
                  "tags": { "env": "prod" }
                }
                """);

        AzureResourceRecord record = ReflectionTestUtils.invokeMethod(client, "toRecord", "sub-1", value);

        assertEquals("sub-1", record.subscriptionId());
        assertEquals("vm-1", record.name());
        assertEquals("Microsoft.Compute/virtualMachines", record.resourceType());
        assertEquals("rg1", record.resourceGroup());
        assertEquals("eastus2", record.location());
        assertEquals("Succeeded", record.provisioningState());
        assertEquals("prod", record.tags().get("env"));
    }

    @Test
    void toRecord_fallsBackToTrailingIdSegmentWhenNameMissing() throws Exception {
        JsonNode value = objectMapper.readTree("""
                {
                  "id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2"
                }
                """);

        AzureResourceRecord record = ReflectionTestUtils.invokeMethod(client, "toRecord", "sub-1", value);

        assertEquals("vm-2", record.name());
    }
}
