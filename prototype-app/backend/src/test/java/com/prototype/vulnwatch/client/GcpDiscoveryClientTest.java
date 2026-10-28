package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class GcpDiscoveryClientTest {

    private MockRestServiceServer server;
    private GcpDiscoveryClient client;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        client = new GcpDiscoveryClient(
                new OutboundHttpClient(restTemplate, OutboundHostPolicy.forTests()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 0, 0, 0, false, false)),
                new ObjectMapper());
    }

    @Test
    void listsInstancesAcrossPagesWithTheTenantToken() {
        server.expect(requestTo("https://compute.googleapis.com/compute/v1/projects/acme-prod/aggregated/instances?maxResults=500&returnPartialSuccess=true"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer tenant-token"))
                .andRespond(withSuccess("""
                        {"items":{"zones/us-central1-a":{"instances":[{"id":"111","name":"web-1",
                          "zone":"https://www.googleapis.com/compute/v1/projects/acme-prod/zones/us-central1-a",
                          "machineType":"https://www.googleapis.com/compute/v1/projects/acme-prod/zones/us-central1-a/machineTypes/e2-medium",
                          "status":"RUNNING","labels":{"env":"prod"},"creationTimestamp":"2026-01-02T03:04:05.000-08:00",
                          "networkInterfaces":[{"network":"https://x/networks/default","subnetwork":"https://x/subnetworks/default"}],
                          "serviceAccounts":[{"email":"vm@acme"}]}]},
                          "zones/europe-west1-b":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}},
                         "nextPageToken":"p2"}""", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://compute.googleapis.com/compute/v1/projects/acme-prod/aggregated/instances?maxResults=500&returnPartialSuccess=true&pageToken=p2"))
                .andRespond(withSuccess("""
                        {"items":{"zones/us-east1-c":{"instances":[{"id":"222","name":"db-1",
                          "zone":"projects/acme-prod/zones/us-east1-c","status":"TERMINATED"}]}}}""", MediaType.APPLICATION_JSON));

        var result = client.listInstances("tenant-token", "acme-prod");

        assertTrue(result.complete());
        assertEquals(2, result.records().size());
        var web = result.records().get(0);
        assertEquals("//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/111", web.identifier());
        assertEquals("us-central1", web.region());
        assertEquals("e2-medium", web.machineType());
        assertEquals("default", web.network());
        assertEquals(Map.of("env", "prod"), web.labels());
        assertEquals("2026-01-02T11:04:05Z", web.createdAt().toString());
        assertTrue(web.hasServiceAccount());
        server.verify();
    }

    @Test
    void unreachableZonesMakeTheListingIncomplete() {
        server.expect(ExpectedCount.once(), requestTo(org.hamcrest.Matchers.startsWith("https://compute.googleapis.com/")))
                .andRespond(withSuccess("""
                        {"items":{},"unreachables":["zones/asia-east1-a"]}""", MediaType.APPLICATION_JSON));

        var result = client.listInstances("t", "acme-prod");

        assertFalse(result.complete(), "a listing that missed a zone must never drive stale marking");
        assertEquals("unreachable", result.errors().get("zones/asia-east1-a"));
    }

    @Test
    void aPermissionErrorIsReportedNotThrownAndIsIncomplete() {
        server.expect(requestTo(org.hamcrest.Matchers.startsWith("https://compute.googleapis.com/")))
                .andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":{\"code\":403,\"message\":\"Required 'compute.instances.list' permission\"}}"));

        var result = client.listInstances("t", "acme-prod");

        assertFalse(result.complete());
        assertTrue(result.errors().get("compute").contains("HTTP 403"));
        assertTrue(result.errors().get("compute").contains("compute.instances.list"));
    }

    @Test
    void parsesInstalledPackagesFromVmManagerForEachZone() {
        server.expect(requestTo("https://osconfig.googleapis.com/v1/projects/acme-prod/locations/us-central1-a/instances/-/inventories?view=FULL&pageSize=100"))
                .andRespond(withSuccess("""
                        {"inventories":[{"name":"projects/123/locations/us-central1-a/instances/111/inventory",
                          "updateTime":"2026-02-01T00:00:00Z",
                          "items":{
                            "a":{"type":"INSTALLED_PACKAGE","installedPackage":{"aptPackage":{"packageName":"openssl","version":"3.0.2"}}},
                            "b":{"type":"INSTALLED_PACKAGE","installedPackage":{"windowsApplication":{"displayName":"7-Zip","displayVersion":"23.01","publisher":"Igor Pavlov"}}},
                            "c":{"type":"AVAILABLE_PACKAGE","installedPackage":{"aptPackage":{"packageName":"ignored"}}}}}]}""",
                        MediaType.APPLICATION_JSON));

        var result = client.listInventories("t", "acme-prod", List.of("us-central1-a", "../escape"));

        List<Map<String, String>> rows = result.packagesByInstanceId().get("111");
        assertEquals(2, rows.size());
        assertTrue(rows.contains(Map.of("display_name", "openssl", "publisher", "", "version", "3.0.2")));
        assertTrue(rows.contains(Map.of("display_name", "7-Zip", "publisher", "Igor Pavlov", "version", "23.01")));
        assertEquals("2026-02-01T00:00:00Z", result.capturedAtByInstanceId().get("111").toString());
        server.verify();
    }

    @Test
    void searchesOnlyTheRequestedAssetTypesAndMapsThemToScoutKeys() {
        server.expect(requestTo("https://cloudasset.googleapis.com/v1/projects/acme-prod:searchAllResources?pageSize=500"
                        + "&assetTypes=container.googleapis.com%2FCluster&assetTypes=storage.googleapis.com%2FBucket"))
                .andRespond(withSuccess("""
                        {"results":[
                          {"name":"//container.googleapis.com/projects/acme-prod/locations/us-central1/clusters/main",
                           "assetType":"container.googleapis.com/Cluster","displayName":"main","location":"us-central1",
                           "state":"RUNNING","labels":{"team":"platform"},"createTime":"2026-01-01T00:00:00Z"},
                          {"name":"//unexpected","assetType":"unexpected.googleapis.com/Thing"}]}""",
                        MediaType.APPLICATION_JSON));

        var result = client.searchResources("t", "acme-prod", Map.of(
                "GKE_CLUSTER", List.of("container.googleapis.com/Cluster"),
                "STORAGE_BUCKET", List.of("storage.googleapis.com/Bucket")));

        assertTrue(result.complete());
        assertEquals(1, result.records().size());
        assertEquals("GKE_CLUSTER", result.records().get(0).resourceType());
        assertEquals("us-central1", result.records().get(0).location());
    }

    @Test
    void returnsThePermissionsTheProjectGrants() {
        server.expect(requestTo("https://cloudresourcemanager.googleapis.com/v1/projects/acme-prod:testIamPermissions"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withSuccess("{\"permissions\":[\"resourcemanager.projects.get\"]}", MediaType.APPLICATION_JSON));

        Set<String> granted = client.testPermissions("t", "acme-prod",
                List.of("resourcemanager.projects.get", "compute.instances.list"));

        assertEquals(Set.of("resourcemanager.projects.get"), granted);
    }

    @Test
    void instanceIdIsReadFromTheInventoryName() {
        assertEquals("456", GcpDiscoveryClient.instanceIdFromInventoryName("projects/1/locations/z/instances/456/inventory"));
        assertEquals(null, GcpDiscoveryClient.instanceIdFromInventoryName("projects/1/locations/z/instances/name/inventory"));
    }
}
