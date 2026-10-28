package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@PostgresControllerIntegrationTest
class CloudResourceControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cloud_resource_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private TenantService tenantService;
    @Autowired private AssetRepository assetRepository;

    @BeforeEach
    void seed() {
        if (assetRepository.findByIdentifier("//storage.googleapis.com/acme_100%-logs").isPresent()) {
            return;
        }
        Tenant tenant = tenantService.getDefaultTenant();
        save(tenant, "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "aws-web", AssetType.HOST, "aws",
                "123456789012", "us-east-1", "EC2", AssetState.ACTIVE, null);
        save(tenant, "//compute.googleapis.com/projects/acme-prod/zones/us-central1-a/instances/1", "gcp-web",
                AssetType.HOST, "gcp", "acme-prod", "us-central1", "COMPUTE_INSTANCE", AssetState.ACTIVE, "{\"env\":\"prod\"}");
        save(tenant, "//storage.googleapis.com/acme_100%-logs", "acme_100%-logs", AssetType.CLOUD_RESOURCE, "gcp",
                "acme-prod", "us", "STORAGE_BUCKET", AssetState.INACTIVE, null);
        save(tenant, "repo:acme/app", "app", AssetType.APPLICATION, null, null, null, null, AssetState.ACTIVE, null);
    }

    private void save(Tenant tenant, String identifier, String name, AssetType type, String provider, String account,
                      String region, String resourceType, AssetState state, String tags) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setIdentifier(identifier);
        asset.setName(name);
        asset.setType(type);
        asset.setCloudProvider(provider);
        asset.setCloudAccountId(account);
        asset.setCloudRegion(region);
        asset.setCloudResourceType(resourceType);
        asset.setCloudTagsJson(tags);
        asset.setState(state);
        assetRepository.save(asset);
    }

    @Test
    void listsOnlyCloudDiscoveredAssetsWithFacetsAcrossProviders() throws Exception {
        mockMvc.perform(authedGet("/api/cloud-resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(3))
                .andExpect(jsonPath("$.facets.providers.length()").value(2))
                .andExpect(jsonPath("$.facets.providers[0].value").value("gcp"))
                .andExpect(jsonPath("$.facets.providers[0].count").value(2));
    }

    @Test
    void filtersByProviderTypeAndStateAndReturnsLabels() throws Exception {
        mockMvc.perform(authedGet("/api/cloud-resources").param("provider", "GCP").param("resourceType", "compute_instance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].name").value("gcp-web"))
                .andExpect(jsonPath("$.items[0].labels.env").value("prod"));
        mockMvc.perform(authedGet("/api/cloud-resources").param("state", "inactive"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1))
                .andExpect(jsonPath("$.items[0].assetType").value("CLOUD_RESOURCE"));
    }

    @Test
    void searchTreatsWildcardCharactersLiterally() throws Exception {
        mockMvc.perform(authedGet("/api/cloud-resources").param("search", "100%"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1));
        mockMvc.perform(authedGet("/api/cloud-resources").param("search", "%"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalItems").value(1));
    }

    @Test
    void rejectsAnUnknownStateAndCapsThePageSize() throws Exception {
        mockMvc.perform(authedGet("/api/cloud-resources").param("state", "everything"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(authedGet("/api/cloud-resources").param("size", "100000"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.size").value(200));
    }
}
