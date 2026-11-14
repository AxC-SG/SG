package com.prototype.vulnwatch.config;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Configuration;

/**
 * Enables Spring caching (the Caffeine-backed caches configured under {@code spring.cache}).
 *
 * <p>Kept off {@code VulnWatchApplication} so test slices such as {@code @WebMvcTest}, which
 * load the application class but not ordinary configuration classes, do not require a
 * {@code CacheManager}. Spring Boot 4 slices no longer supply one implicitly.
 */
@Configuration(proxyBeanMethods = false)
@EnableCaching
public class CachingConfig {
}
