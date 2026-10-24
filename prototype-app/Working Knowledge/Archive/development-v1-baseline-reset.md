# Development V1 baseline reset

The customer explicitly authorized discarding development data and consolidating every numbered migration into fresh V1 baselines on 2026-10-12. This is the reset record used by the existing migration-integrity guard for its one-time V1-only exception. Future migrations remain append-only, starting at V2 independently in each line.

- Platform: `backend/src/main/resources/db/migration/postgres_reset/V1__platform_schema.sql`, 74 public/platform tables and migration-owned catalog seeds; creates the empty `tenant_default` schema.
- Tenant: `backend/src/main/resources/db/migration/tenant/V1__tenant_schema.sql`, 145 tenant tables, constraints, indexes, forced RLS, and the tenant budget seed; parameterized with `${tenantSchema}` and `${tenantId}`.
- Previous platform V1–V10 and tenant V1–V17 SQL was applied to a new disposable PostgreSQL database before exporting the final schemas and seed rows. No application/customer database was used as the dump source. No customer data or old Flyway history is included.
- The baselines include GitHub advisories/OSV, AI-BOM integration, agent deployment metadata, harm-assessment baselines, and runtime exclusion. No AGCF-RT distributions are seeded; existing runtime-mode distributions are unavailable/DISABLED/PAUSED/unpinned; runtime evidence and source tables start empty.

## Adoption

Stop old application/worker instances, recreate the intended development database, run `mvn clean` to discard stale packaged SQL, and use the existing platform bootstrap and tenant control-plane provisioning. The platform history is `public.flyway_schema_history`; each tenant has its own `tenant_schema_history`. Both migrate to version 1. Do not use `flyway:repair`, baseline-on-migrate, or replay V1 over existing tables to adopt this reset. No shared/production database reset is implied by this code change.

## Validation

`MigrationCatalogTest`, `FlywayMigrationVersioningTest`, and `PostgresResetMigrationGuardTest` verify the sole V1 files and independent targets. PostgreSQL migration integration tests verify fresh platform/bootstrap, arbitrary tenant provisioning, schema parity, lifecycle defaults/constraints, seed bindings, and disabled/empty runtime scope. `ProductionBootstrapCliPostgresIntegrationTest` also checks the complete bootstrap and restricted runtime role. Tests run against disposable databases.

The reset verification passed 1,136 unit tests, 17 PostgreSQL integration tests, coverage, and SpotBugs. The known AWS collector-certification test mismatch was excluded. Independent schema-only and seed-row exports of a V1 install matched the original fully migrated disposable source exactly (excluding Flyway history). Migration validation, diff whitespace checks, and the secrets scan also passed.
