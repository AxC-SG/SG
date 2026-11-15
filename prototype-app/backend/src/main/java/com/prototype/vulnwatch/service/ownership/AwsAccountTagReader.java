package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsOrganizationsClient;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.AwsDiscoveryConfigService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.AccountRead;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

/**
 * Reads AWS account tags for the cloud ownership producer (Phase 0B §2.2.1). Once per discovery run, after it
 * committed, one {@code ListTagsForResource} per observed account through the optional Organizations role. Runs only
 * while the producer is enabled, the account input is on and a role is configured. A failed or denied read yields no
 * values for that account, which leaves its claims untouched. Configuration and its test live in
 * {@link CloudOwnershipSourceService}; this class never writes.
 */
@Component
public class AwsAccountTagReader {

    public record Configuration(AwsDiscoveryConfig runtimeConfig, String roleArn, String externalId) { }

    static final String EXTERNAL_ID_PURPOSE = "aws.organizations.external_id";
    private static final Logger LOG = LoggerFactory.getLogger(AwsAccountTagReader.class);

    private final JdbcTemplate jdbc;
    private final TenantWorkRunner runner;
    private final AwsDiscoveryConfigRepository configs;
    private final AwsDiscoveryConfigService configService;
    private final AwsOrganizationsClient organizations;
    private final TenantDataCipher cipher;
    private final boolean enabled;

    public AwsAccountTagReader(JdbcTemplate jdbc, TenantWorkRunner runner, AwsDiscoveryConfigRepository configs,
                               AwsDiscoveryConfigService configService, AwsOrganizationsClient organizations, TenantDataCipher cipher,
                               @Value("${app.ownership.cloud.producer-enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.runner = runner;
        this.configs = configs;
        this.configService = configService;
        this.organizations = organizations;
        this.cipher = cipher;
        this.enabled = enabled;
    }

    /** Account reads for the run; empty when account tags are not in use. Never throws. */
    public List<AccountRead> read(UUID tenantId, Collection<String> accountIds) {
        if (!enabled || accountIds.isEmpty()) return List.of();
        Optional<Configuration> configuration;
        try {
            configuration = runner.runScoped(tenantId, () -> accountInputOn() ? configuration() : Optional.<Configuration>empty());
        } catch (RuntimeException failure) {
            LOG.warn("AWS account tags are not read for tenant {}: {}", tenantId, failure.getMessage());
            return List.of();
        }
        if (configuration.isEmpty()) return List.of();
        AwsCredentialsProvider credentials;
        try {
            credentials = credentials(configuration.get());
        } catch (RuntimeException failure) {
            LOG.warn("AWS Organizations role could not be used for tenant {}: {}", tenantId, failure.getMessage());
            return accountIds.stream().distinct().map(id -> new AccountRead(id, null)).toList();
        }
        List<AccountRead> reads = new ArrayList<>();
        for (String accountId : accountIds.stream().distinct().toList()) {
            try {
                reads.add(new AccountRead(accountId, organizations.accountTags(credentials, accountId)));
            } catch (RuntimeException failure) {
                LOG.warn("AWS account tags for {} could not be read: {}", accountId, failure.getMessage());
                reads.add(new AccountRead(accountId, null));
            }
        }
        return reads;
    }

    /**
     * The tenant's Organizations role with the connector's decrypted base identity, inside the caller's tenant
     * context and transaction. Empty when no role is configured. Fails when the tenant key cannot decrypt.
     */
    public Optional<Configuration> configuration() {
        Optional<AwsDiscoveryConfig> config = configs.findAll().stream().findFirst();
        if (config.isEmpty()) return Optional.empty();
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT organizations_role_arn, organizations_external_id FROM aws_discovery_configs WHERE id = ?", config.get().getId());
        String roleArn = rows.isEmpty() ? null : (String) rows.get(0).get("organizations_role_arn");
        if (roleArn == null || roleArn.isBlank()) return Optional.empty();
        String stored = (String) rows.get(0).get("organizations_external_id");
        String externalId = stored == null ? null : cipher.decrypt(TenantContext.getCurrentTenantId(), EXTERNAL_ID_PURPOSE, stored);
        return Optional.of(new Configuration(configService.configWithDecryptedCredential(config.get()), roleArn, externalId));
    }

    AwsCredentialsProvider credentials(Configuration configuration) {
        return AwsCredentialProvider.forOrganizations(configuration.runtimeConfig(), configuration.roleArn(), configuration.externalId());
    }

    private boolean accountInputOn() {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT bool_or(ownership_account_input_enabled) FROM aws_discovery_configs", Boolean.class));
    }
}
