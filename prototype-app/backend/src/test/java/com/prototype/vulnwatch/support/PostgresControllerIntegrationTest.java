package com.prototype.vulnwatch.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Controller-layer Postgres integration test. Same as
 * {@link PostgresIntegrationTest} plus {@code @AutoConfigureMockMvc} so the
 * test class can autowire {@link org.springframework.test.web.servlet.MockMvc}.
 *
 * <p>Use with {@link AuthRequest} for authenticated request building so the
 * {@code X-API-Key} / {@code X-Creator-Key} / {@code X-User-ID} headers don't
 * have to be repeated on every call.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(properties = {
        "app.security.api-key=" + PostgresITSupport.API_KEY,
        "app.security.creator-key=" + PostgresITSupport.CREATOR_KEY,
        "app.correlation.backfill-targets-on-startup=false",
        // TenantResolutionFilter runs before ApiKeyAuthenticationFilter so API key
        // auth never gets a chance to set TenantContext. Disable the strict
        // require-tenant-context guard so the filter falls back to the default
        // workspace tenant instead of throwing FORBIDDEN on every POST/PUT.
        "app.tenancy.require-tenant-context=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
public @interface PostgresControllerIntegrationTest {
}
