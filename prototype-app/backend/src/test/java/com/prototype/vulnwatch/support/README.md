# Postgres integration test scaffolding

This package provides the standard pieces every Postgres IT in this codebase
should use. The goal is: a new IT class is ~50 lines, not ~250.

## Naming and gating

- File name **must** end with `PostgresIntegrationTest.java` so Surefire skips
  it and Failsafe picks it up.
- Run with `mvn -Ppostgres-it verify`. Locally, that profile sets
  `-Drun.postgres.it=true`, which the composed annotations gate on.

## Parallel execution in CI

CI (`-Pci-postgres-it`) runs integration classes in three JVMs at once against one
PostgreSQL server (`it.forkCount`; local runs keep one JVM, override with
`-Dit.forkCount=N`). Databases and roles are cluster-wide, so a new class must:

- pass a key to `LocalPostgresTestDatabase.provision` that no other class uses, because
  provisioning drops and recreates `vulnwatch_it_<key>`;
- give any role it creates a name no other class uses (a class-specific constant or a
  random suffix), never a shared name such as `scout_runtime`.

The Spring context cache is capped at `it.context.cache.maxSize` (3). Each class has its
own database URL, so contexts are rarely shared between classes.

## Pieces

| Piece | When to use |
|---|---|
| `@PostgresIntegrationTest` | Service- or repo-layer test (no MockMvc). |
| `@PostgresControllerIntegrationTest` | Anything that exercises a controller via `MockMvc`. |
| `LocalPostgresTestDatabase.provision(key)` | One per class. The `key` becomes `vulnwatch_it_<key>` — keep it unique per class. |
| `PostgresITSupport.registerDatabaseProperties(...)` | Call from a static `@DynamicPropertySource` method. |
| `AuthRequest.authedGet/Post/Put/Delete/Multipart` | Replaces `.header("X-API-Key", ...)`. |
| `AuthRequest.asPlatformOwner` / `asAnalyst` / `asTenantAnalyst` | Add the creator / user / tenant headers when the endpoint requires them. |

## Minimal controller-IT skeleton

```java
package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@PostgresControllerIntegrationTest
class FooControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("foo_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void listEndpointReturnsOk() throws Exception {
        mockMvc.perform(authedGet("/api/foo"))
                .andExpect(status().isOk());
    }
}
```

## Conventions for new ITs

- **One DB per class.** `LocalPostgresTestDatabase.provision` is idempotent and
  drops/recreates the database — keep keys unique to avoid flaky cross-class
  pollution.
- **Don't add `@Transactional` to controller tests.** HTTP requests run in their
  own transactions; class-level `@Transactional` does not roll them back and
  causes confusing leaks. Use `@Transactional` only on service- or repo-layer
  tests.
- **Don't repeat header chains.** If you write
  `.header("X-API-Key", "test-api-key")` more than once in a test, switch to
  `AuthRequest`.
- **Mock outbound HTTP** with `MockRestServiceServer.bindTo(restTemplate)` — see
  `ApiContractGoldenPostgresIntegrationTest` for a working example.
- **One assertion theme per test method.** A controller smoke test that
  exercises GET + filter + paging + auth in a single method is a maintenance
  trap when one of those drifts.

## Existing tests that pre-date this scaffolding

Tests in `service/`, `repo/`, `contract/`, `security/` packages still use the
expanded form. They work — don't touch them just to migrate. New tests should
use the scaffolding; migrate old ones opportunistically when you're already in
the file for another reason.

## Findings workspace scale validation

- Use `FindingWorkspaceProjectionPostgresIntegrationTest` for repeatable high-volume
  findings projection validation.
- Run with:
  `mvn -Ppostgres-it -Dtest=FindingWorkspaceProjectionPostgresIntegrationTest verify`
- That suite seeds a larger synthetic findings tenant, refreshes the projection,
  and exercises cursor paging plus projection-backed read timings.
