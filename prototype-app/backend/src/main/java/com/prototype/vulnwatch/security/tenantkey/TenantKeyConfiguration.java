package com.prototype.vulnwatch.security.tenantkey;

import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Tenant key wiring. The wrapper is disabled by default: with no wrapper every PII write and
 * identity-source enablement fails closed. {@code local} is accepted only in local/test runtimes;
 * the KMS wrapper is added once the Phase 0A KMS spike passes.
 */
@Configuration
public class TenantKeyConfiguration {

    @Bean
    @ConditionalOnProperty(name = "app.security.tenant-keys.wrapper", havingValue = "local")
    KeyWrapper localTenantKeyWrapper(
            @Value("${app.environment:}") String environment,
            @Value("${app.security.tenant-keys.local-master-key:}") String masterKey) {
        return new LocalKeyWrapper(environment, masterKey);
    }

    @Bean
    TenantKeyStore tenantKeyStore(JdbcTemplate jdbc, TransactionTemplate tx) {
        return new JdbcTenantKeyStore(jdbc, tx);
    }

    @Bean
    TenantKeyRegistry tenantKeyRegistry(
            TenantKeyStore store,
            ObjectProvider<KeyWrapper> wrapper,
            @Value("${app.security.tenant-keys.cache-ttl:PT10M}") Duration ttl,
            @Value("${app.security.tenant-keys.cache-max-keys:10000}") long maxKeys) {
        return new TenantKeyRegistry(store, wrapper.getIfAvailable(), ttl, maxKeys);
    }

    @Bean
    TenantDataCipher tenantDataCipher(TenantKeyRegistry registry) {
        return new AesGcmTenantDataCipher(registry);
    }
}
