package com.prototype.vulnwatch.aisecurity.azure;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class AiSecurityAzureCredentialExpiryService {

    private static final Logger LOG = LoggerFactory.getLogger(AiSecurityAzureCredentialExpiryService.class);

    private final TenantService tenants;
    private final AiSecurityAzureCredentialService credentials;
    private BackgroundTaskExecutionPolicy backgroundPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public AiSecurityAzureCredentialExpiryService(
            TenantService tenants,
            AiSecurityAzureCredentialService credentials
    ) {
        this.tenants = tenants;
        this.credentials = credentials;
    }

    @Autowired
    void setBackgroundPolicy(BackgroundTaskExecutionPolicy backgroundPolicy) {
        this.backgroundPolicy = backgroundPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundPolicy;
    }

    @Scheduled(zone = "UTC", cron = "${app.ai-security.azure.credential-expiry-cron:0 20 2 * * *}")
    public void sweep() {
        if (!backgroundPolicy.allowsBackgroundTask("ai-security.azure-credential-expiry")) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            for (Tenant tenant : tenants.listActiveTenants()) {
                try {
                    credentials.processExpiryWarnings(tenant);
                } catch (Exception exception) {
                    LOG.warn("Azure AI credential expiry sweep failed for tenant {}: {}",
                            tenant.getId(), exception.getMessage());
                }
            }
        });
    }
}
