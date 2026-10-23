# VulnWatch Database

Last updated: 2026-10-21 (scoped migration/readiness guidance)

> **Historical version labels:** ~70 section notes below cite pre-reset migration numbers (e.g. "Added in V44", "V40/V41"). Those histories were consolidated into the V1 baselines; the current post-reset heads are platform V8 and tenant V6. Read older labels as provenance, not as files that exist.

The runtime database is PostgreSQL with two independent Flyway lines, each consolidated into a complete V1 development baseline: `postgres_reset/V1__platform_schema.sql` and `tenant/V1__tenant_schema.sql`. They include current AI Grid, AI-BOM, GitHub advisory/OSV, deployment metadata, harm-baseline schema, and runtime exclusion. Tenant migrations are applied once per schema by `TenantSchemaMigrationService` / `ProductionBootstrapCli`. Historical version references below describe when features were introduced; their SQL is now incorporated in V1. Use fresh disposable local databases and remove stale packaged resources with `mvn clean`. Existing shared/deployed histories need read-only inspection and a separately authorized transition; do not reset them or use `flyway:repair` to adopt this reset.

---

## Overview

- **Database name (local):** `vulnwatch`
- **JDBC URL default:** `jdbc:postgresql://localhost:5432/vulnwatch`
- **Migration directories:** `backend/src/main/resources/db/migration/postgres_reset/` (platform/`public` schema) and `backend/src/main/resources/db/migration/tenant/` (per-tenant schema, applied by the tenant schema control plane, not by the application's own startup Flyway run)
- **Flyway baselines:** `postgres_reset/V1__platform_schema.sql` and `tenant/V1__tenant_schema.sql`; current heads are platform V8 (`V8__reviewed_intelligence_publication.sql`) and tenant V6 (`V6__intelligence_revision_and_finding_eligibility.sql`); next platform change is V9, next tenant change is V7
- **Replay rule:** V1 baselines bootstrap fresh databases only; all applied files are immutable and no baseline or later migration may be replayed manually against existing state
- **`ddl-auto`:** `none` (Flyway owns all DDL; Hibernate never creates or alters tables)

---

## Schema Structure

The database is split into two PostgreSQL schemas:

| Schema | Purpose |
|---|---|
| `platform` | Shared, cross-tenant data: tenants, users, global vulnerabilities, software identities, EOL catalog |
| `tenant_default` | Template for per-tenant operational data: assets, inventory, findings, org CVE records, connectors, policies |

At runtime, `TenantAwareDataSource` sets PostgreSQL session variables on every connection:
```sql
SELECT set_config('app.current_tenant_id', '<uuid>', FALSE);
SELECT set_config('search_path', '<tenant_schema>,platform', FALSE);
```

JPA queries normally use the schema selected on connection acquisition. Search path is routing, not the isolation boundary: forced RLS, current tenant context and a restricted runtime role are also required. Platform work is explicit (`platform,public`); missing required tenant context uses a sentinel. Reset failures/unfinished transactions cause eviction/abort; `TenantSchemaExecutionService` rejects tenant/schema switching through its runner during an active transaction; platform scope must also be established before the transaction.

The application service has template-clone support; the deployed standalone bootstrap creates/migrates tenant schemas and verifies runtime grants before ACTIVE. The long-running deployed API owns no DDL. Startup/readiness check shared structures and per-request tenant compatibility without migrating.

---

## Platform Schema Tables

### `platform.tenants`

Stores every registered tenant (organization).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `name` | `varchar(255)` | NOT NULL; unique |
| `schema_name` | `varchar(255)` | NOT NULL; unique |
| `slug` | `varchar(255)` | unique |
| `status` | `varchar(255)` | NOT NULL |
| `plan_code` | `varchar(255)` | NOT NULL |
| `billing_ref` | `varchar(255)` | |
| `max_connector_count` | `integer` | NOT NULL |
| `max_daily_exposure_refreshes` | `integer` | NOT NULL |
| `max_daily_sbom_uploads` | `integer` | NOT NULL |
| `max_export_rows` | `integer` | NOT NULL |
| `max_service_account_count` | `integer` | NOT NULL |
| `demo_created_by` / `demo_owner_email` / `demo_source` | `varchar(255)` | |
| `demo_expires_at` | `timestamptz` | |
| `expired_at` / `suspended_at` | `timestamptz` | |
| `purge_status` / `purge_error` | `varchar(255)` | |
| `purge_started_at` / `purged_at` / `deleted_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `platform.app_users`

Platform-level user accounts. Supports both OAuth (`external_subject`) and local password auth.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `external_subject` | `varchar(255)` | NOT NULL; unique |
| `email` | `varchar(255)` | |
| `display_name` | `varchar(255)` | |
| `platform_owner` | `boolean` | NOT NULL |
| `status` | `varchar(255)` | NOT NULL |
| `password_hash` | `varchar(255)` | bcrypt hash for local credential auth |
| `password_set_at` | `timestamptz` | |
| `password_setup_token_hash` | `varchar(255)` | one-time setup token (hashed) |
| `password_setup_token_expires_at` | `timestamptz` | |
| `last_seen_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `platform.tenant_memberships`

Links users to tenants with one of TENANT_ADMIN, INVENTORY_ADMIN, SECURITY_ANALYST or READ_ONLY_AUDITOR. `TenantRolePolicy` rejects platform/machine/unknown roles at assignment and authorization, including legacy stored values.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK → `platform.tenants(id)` |
| `user_id` | `uuid` | FK → `platform.app_users(id)` |
| `invited_by` | `uuid` | FK → `platform.app_users(id)` |
| `role` | `varchar(255)` | NOT NULL |
| `status` | `varchar(255)` | NOT NULL |
| `provenance` | `varchar(32)` | NOT NULL; `MANUAL`, `TENANT_INVITE`, or `PLAYGROUND_BOOTSTRAP` |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique index: `(user_id, tenant_id)`.

---

### `platform.app_user_global_roles`

Platform-wide roles for users (e.g., PLATFORM_OWNER).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `app_user_id` | `uuid` | FK → `platform.app_users(id)` |
| `role` | `varchar(64)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

Unique constraint: `(app_user_id, role)`. Index: `idx_app_user_global_roles_role` on `(role)`.

---

### `platform.tenant_support_grants`

Platform-owner support access grants with expiry and audit trail.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK → `platform.tenants(id)` |
| `granted_by` | `uuid` | FK → `platform.app_users(id)`, NOT NULL |
| `accepted_by` / `revoked_by` | `uuid` | FK → `platform.app_users(id)` |
| `invited_platform_subject` | `varchar(255)` | NOT NULL |
| `access_mode` | `varchar(255)` | NOT NULL |
| `scope` / `reason` | `varchar(255)` | |
| `status` | `varchar(255)` | NOT NULL |
| `expires_at` | `timestamptz` | NULL only when non-expiring support access is explicitly enabled |
| `requested_at` | `timestamptz` | NOT NULL |
| `accepted_at` / `revoked_at` / `updated_at` | `timestamptz` | |

Indexes: `idx_tenant_support_grants_subject_status_expires` on `(invited_platform_subject, status, expires_at)`, `idx_tenant_support_grants_tenant_requested` on `(tenant_id, requested_at)`.

---

### `platform.tenant_entitlement_overrides`

Per-tenant overrides of default entitlements (e.g. enable a beta feature, adjust a plan limit). Added in V38.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `entitlement_key` | `varchar(128)` | NOT NULL |
| `enabled` | `boolean` | NOT NULL |
| `config_json` | `jsonb` | Feature-specific configuration |
| `reason` | `varchar(500)` | Admin note explaining the override |
| `expires_at` | `timestamptz` | NULL = permanent |
| `created_by` | `uuid` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, entitlement_key)`. Index: `(tenant_id)`.

---

### `platform.tenant_schema_versions`

Operational projection of each tenant's per-schema Flyway state, populated by `TenantSchemaMigrationService` / `ProductionBootstrapCli`. The `tenant` migration line's own `<schema>.tenant_schema_history` table (one per tenant schema) remains the authoritative Flyway record; this table is a queryable rollup across all tenants for the platform console and the readiness health indicator. The packaged tenant target and required compatibility floor are both `6`; configuration cannot lower that floor or admit versions above the supported maximum of `6`.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | `uuid` | PK; FK → `platform.tenants(id)` ON DELETE CASCADE |
| `schema_name` | `varchar(120)` | NOT NULL, UNIQUE |
| `current_version` | `integer` | NOT NULL DEFAULT 0 |
| `target_version` | `integer` | NOT NULL; current packaged tenant target is `3` |
| `status` | `varchar(24)` | `PENDING`, `MIGRATING`, `CURRENT`, `FAILED`, `DRIFTED`, `PROVISIONING_FAILED` |
| `structural_checksum` | `varchar(64)` | SHA-256 of the schema's normalized column/constraint/index/sequence/RLS-policy fingerprint |
| `migration_started_at` / `migration_completed_at` | `timestamptz` | |
| `last_successful_version` | `integer` | NOT NULL DEFAULT 0; never regresses |
| `failure_code` / `failure_message` | `varchar` | Set on `FAILED`/`DRIFTED`/`PROVISIONING_FAILED`; message is sanitized (secrets redacted, truncated to 1000 chars) |
| `migration_run_id` | `uuid` | Correlates rows written by the same migration run |

Index: `(status, current_version)`. See [Tenant Schema Control Plane](#tenant-schema-control-plane) below.

---

### `platform.vulnerabilities`

Master vulnerability (CVE) catalog. Platform-wide; shared across all tenants.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `external_id` | `varchar(50)` | NOT NULL; unique (CVE ID) |
| `source` | `varchar(20)` | NOT NULL (NVD, GHSA, etc.) |
| `title` | `varchar(500)` | NOT NULL |
| `description_snippet` | `varchar(500)` | |
| `description_archive_key` | `varchar(200)` | Retained historical archive reference; current local file access is unavailable |
| `cvss_score` | `double precision` | |
| `severity` | `varchar(20)` | NOT NULL |
| `epss_score` | `double precision` | |
| `in_kev` | `boolean` | NOT NULL |
| `cvss_vector` | `varchar(300)` | |
| `cvss_version` | `varchar(20)` | |
| `attack_vector` / `attack_complexity` / `privileges_required` / `user_interaction` / `cvss_scope` | `varchar(20)` | |
| `exploitability_score` / `impact_score` | `double precision` | |
| `cwe_ids` | `varchar(200)` | |
| `source_identifier` | `varchar(255)` | |
| `vuln_status` | `varchar(80)` | |
| `kev_date_added` / `kev_due_date` | `date` | |
| `kev_required_action` | `varchar(500)` | |
| `references_json` | `text` | |
| `raw_payload_archive_key` | `varchar(200)` | |
| `published_at` / `last_modified_at` / `epss_updated_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vulnerabilities_severity`, `idx_vulnerabilities_in_kev`, `idx_vulnerabilities_epss`, `idx_vulnerabilities_published`, `idx_vulnerabilities_external_cvss_lastmod_updated`, `idx_vulnerabilities_cvss_lastmod_updated`.

---

### `platform.software_identities`

Canonical software product identities (deduplicated across all tenants).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `canonical_key` | `varchar(400)` | NOT NULL; unique |
| `display_name` | `varchar(300)` | NOT NULL |
| `vendor` / `product` | `varchar(255)` | |
| `product_hash` | `varchar(255)` | |
| `purl` | `varchar(1200)` | |
| `cpe23` | `varchar(1200)` | |
| `vendor_product_id` | `varchar(255)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Index: `idx_software_identity_key` on `(canonical_key)`.

---

### `platform.software_identifiers`

Alternative identifier records (CPE, PURL, SWID, etc.) attached to a software identity.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `id_type` | `varchar(40)` | NOT NULL |
| `normalized_value` | `varchar(1000)` | NOT NULL |
| `raw_value` | `varchar(1000)` | |
| `source` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `provenance_note` | `varchar(500)` | |
| `verified` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(software_identity_id, id_type, normalized_value)`. Indexes: `idx_software_identifier_type_value` on `(id_type, normalized_value)`, `idx_software_identifier_identity` on `(software_identity_id)`.

---

### `platform.cpe_dim`

Parsed/normalized CPE dimension table. One row per unique CPE string.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `raw_cpe` | `varchar(1200)` | NOT NULL |
| `normalized_cpe` | `varchar(1200)` | NOT NULL; unique |
| `part` / `vendor` / `product` | `varchar(500)` | NOT NULL |
| `version` / `update` / `edition` / `language` / `sw_edition` / `target_sw` / `target_hw` / `other` | `varchar(500)` | |
| `cpe_key` | `varchar(1000)` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_cpe_dim_key` on `(cpe_key)`, `idx_cpe_dim_normalized` on `(normalized_cpe)`.

---

### `platform.vulnerability_intel_summary`

Read-model projection: one row per vulnerability. Backs the Vulnerability Intelligence feed UI (`/vuln-repo/vulnerabilities`).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)`; unique |
| `external_id` | `varchar(255)` | NOT NULL |
| `title` | `varchar(255)` | NOT NULL |
| `description_snippet` | `varchar(220)` | |
| `severity` | `varchar(255)` | NOT NULL |
| `cvss_score` / `epss_score` | `double precision` | |
| `in_kev` | `boolean` | NOT NULL |
| `vuln_status` | `varchar(255)` | |
| `source_count` | `integer` | NOT NULL |
| `published_at` / `last_modified_at` / `summary_updated_at` / `updated_at` / `created_at` | `timestamptz` | |

Indexes: `idx_vintel_summary_external_id`, `idx_vintel_summary_severity`, `idx_vintel_summary_in_kev`, `idx_vintel_summary_vuln_status`, `idx_vintel_summary_external_cvss_lastmod_updated`.

---

### `platform.vulnerability_intel_summary_sources`

Which source systems contributed data to each `vulnerability_intel_summary` row.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | NOT NULL |
| `source_system` | `varchar(80)` | NOT NULL |

Unique: `(vulnerability_id, source_system)`.

---

### `platform.vulnerability_intel_observations`

Raw observation records from each source system (NVD, GHSA, CSAF, etc.) for a given CVE.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `source_system` | `varchar(80)` | NOT NULL |
| `source_record_id` | `varchar(255)` | NOT NULL |
| `source_url` | `varchar(1200)` | |
| `title` / `description` / `severity` | various | |
| `cvss_score` / `cvss_vector` / `epss_score` | various | |
| `in_kev` | `boolean` | |
| `vuln_status` | `varchar(120)` | |
| `cwe_ids` | `varchar(2000)` | |
| `references_json` / `raw_payload` | `text` | |
| `payload_hash` | `varchar(128)` | |
| `published_at` / `last_modified_at` / `observed_at` / `last_seen_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(source_system, source_record_id)`. Indexes: `idx_vuln_intel_obs_vulnerability`, `idx_vuln_intel_obs_source`, `idx_vuln_intel_obs_last_seen`.

---

### `platform.vulnerability_intel_relations`

Relationships between observations (e.g., CSAF document → CVE observation).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `from_observation_id` / `to_observation_id` | `uuid` | FK → `platform.vulnerability_intel_observations(id)` |
| `relation_type` | `varchar(80)` | NOT NULL |
| `source_system` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `verified` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(from_observation_id, to_observation_id, relation_type, source_system)`.

---

### `platform.vulnerability_targets`

Affected software targets for each vulnerability (CPE nodes, package ranges, version bounds).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `target_type` | `varchar(40)` | NOT NULL |
| `raw_target` | `varchar(1200)` | |
| `normalized_target_key` | `varchar(500)` | NOT NULL |
| `ecosystem` / `namespace` / `package_name` | various | |
| `version_exact` / `version_start` / `version_end` / `fixed` / `introduced` | `varchar(255)` | |
| `start_inclusive` / `end_inclusive` | `boolean` | |
| `version_scheme` | `varchar(40)` | NOT NULL |
| `constraint_type` | `varchar(40)` | |
| `cpe` | `varchar(1200)` | |
| `cpe_wildcard_score` | `integer` | |
| `qualifier_*` fields (part, vendor, product, etc.) | `varchar(255)` | |
| `qualifiers_json` | `text` | |
| `source` | `varchar(80)` | NOT NULL |
| `kb_version` | `varchar(120)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vuln_target_vuln`, `idx_vuln_target_type_key`, `idx_vuln_target_package`, `idx_vuln_target_identity`, `idx_vuln_target_cpe_id`, `idx_vuln_target_type_cpe_id`.

---

### `platform.vex_assertions`

VEX (Vulnerability Exploitability eXchange) statements from vendors (Microsoft CSAF, Red Hat CSAF). Governs applicability overrides.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `observation_id` | `uuid` | FK → `platform.vulnerability_intel_observations(id)` |
| `target_id` | `uuid` | FK → `platform.vulnerability_targets(id)`; unique |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `source_system` | `varchar(80)` | NOT NULL |
| `provider` | `varchar(120)` | NOT NULL |
| `document_id` | `varchar(255)` | NOT NULL |
| `statement_key` | `varchar(512)` | NOT NULL |
| `status` | `varchar(64)` | NOT NULL |
| `trust_tier` | `varchar(40)` | NOT NULL |
| `freshness` | `varchar(40)` | NOT NULL |
| `normalized_product_key` | `varchar(500)` | NOT NULL |
| `version_exact` / `version_start` / `version_end` / `fixed_version` | `varchar(255)` | |
| `ecosystem` / `namespace` / `package_name` | various | |
| `raw_target` / `evidence_json` | `text` | |
| `published_at` / `last_seen_at` / `created_at` / `updated_at` | `timestamptz` | |

Unique: `(vulnerability_id, source_system, document_id, statement_key)`. Indexes: `idx_vex_assertions_vulnerability`, `idx_vex_assertions_source`, `idx_vex_assertions_target`, `idx_vex_assertions_identity`, `idx_vex_assertions_cpe`.

---

### `platform.vulnerability_rules`

Simplified matching rules derived from NVD/GHSA configuration nodes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `ecosystem` / `package_name` | `varchar(255)` | NOT NULL |
| `cpe` / `cpe_product` / `cpe_vendor` | `varchar(255)` | |
| `version_exact` / `version_start` / `version_end` | `varchar(255)` | |
| `version_start_inclusive` / `version_end_inclusive` | `boolean` | |
| `created_at` | `timestamptz` | NOT NULL |

Indexes: `idx_vuln_rules_vulnerability`, `idx_vuln_rules_ecosystem_package`.

---

### `platform.vulnerability_config_expr`

NVD CPE configuration expression tree nodes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `config_index` / `node_path` / `parent_path` | various | NOT NULL |
| `operator` | `varchar(32)` | |
| `negate` | `boolean` | NOT NULL |
| `child_node_count` / `match_criteria_count` | `integer` | |
| `expr_json` | `text` | |
| `source` | `varchar(40)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

---

### `platform.eol_product_catalog`

End-of-life product catalog from endoflife.date API.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `slug` | `varchar(200)` | NOT NULL; unique |
| `cpe_vendor` / `cpe_product` | `varchar(200)` | |
| `purl_type` / `purl_namespace` | `varchar(200)` | |
| `display_name` | `varchar(200)` | |
| `aliases` | `text` | |
| `last_modified` | `varchar(50)` | |
| `last_fetched_at` / `created_at` / `updated_at` | `timestamptz` | |

Indexes: `idx_eol_catalog_cpe` on `(cpe_vendor, cpe_product)`, `idx_eol_catalog_purl` on `(purl_type, purl_namespace)`.

---

### `platform.eol_release`

Per-product release cycle data from endoflife.date.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `product_slug` | `varchar(200)` | NOT NULL |
| `cycle` | `varchar(100)` | NOT NULL |
| `release_date` / `eol_date` / `support_end_date` / `extended_support_date` / `latest_release_date` / `security_support_date` | `date` | |
| `eol_boolean` | `boolean` | |
| `latest_version` | `varchar(100)` | |
| `is_lts` / `is_eol` | `boolean` | NOT NULL |
| `is_eoas` / `is_eoes` | `boolean` | |
| `official_source_url` | `varchar(500)` | |
| `support_phase` | `varchar(30)` | |
| `discontinued` | `boolean` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(product_slug, cycle)`. Index: `idx_eol_release_product_slug`, `idx_eol_release_is_eol`.

---

### `platform.software_eol_mapping`

Resolved mapping between a software identity canonical key and an EOL product slug.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `software_identity_id` | `uuid` | |
| `normalized_key` | `varchar(500)` | NOT NULL; unique |
| `eol_slug` | `varchar(200)` | |
| `match_confidence` | `varchar(20)` | |
| `match_method` | `varchar(50)` | |
| `confirmed` | `boolean` | NOT NULL |
| `confirmed_by` / `confirmed_at` | various | |
| `previous_slug` | `varchar(200)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Indexes: `idx_software_eol_mapping_identity`, `idx_software_eol_mapping_slug`.

---

### `platform.identity_links`

Graph edges connecting `software_identifier` nodes across identity resolution.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `from_identifier_id` / `to_identifier_id` | `uuid` | FK → `platform.software_identifiers(id)` |
| `link_type` | `varchar(80)` | NOT NULL |
| `match_rule` | `varchar(40)` | |
| `source` | `varchar(80)` | NOT NULL |
| `confidence` | `double precision` | |
| `verified` | `boolean` | NOT NULL |
| `verified_at` | `timestamptz` | |
| `last_seen_at` / `created_at` / `updated_at` | `timestamptz` | |

Unique: `(from_identifier_id, to_identifier_id, link_type, source)`. Indexes: `idx_identity_links_from`, `idx_identity_links_to`.

---

## Tenant Schema Tables (`tenant_default`)

All tables below live in `tenant_default` (or the active tenant's schema). All have `tenant_id uuid NOT NULL FK → platform.tenants(id)`.

---

### `assets`

Every discoverable asset (application, host, container image, cloud resource).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `identifier` | `varchar(255)` | NOT NULL; unique with `tenant_id` |
| `name` | `varchar(255)` | NOT NULL |
| `type` | `varchar(255)` | NOT NULL; CHECK IN (`APPLICATION`, `HOST`, `CONTAINER_IMAGE`, `CLOUD_RESOURCE`) |
| `state` | `varchar(255)` | NOT NULL; CHECK IN (`ACTIVE`, `INACTIVE`, `RETIRED`, `DECOMMISSIONED`) |
| `business_criticality` | `varchar(255)` | NOT NULL; CHECK IN (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `environment` / `owner_email` / `owner_team` / `department` | `varchar(255)` | |
| `cloud_provider` / `cloud_region` / `cloud_account_id` / `cloud_arn` / `cloud_resource_type` | `varchar(255)` | |
| `cloud_instance_type` / `cloud_subnet_id` / `cloud_vpc_id` | `varchar(255)` | |
| `cloud_launch_time` | `timestamptz` | |
| `cloud_tags_json` | `varchar(255)` | |
| `image_digest` / `image_tag` / `image_repository` | `varchar(255)` | Container image fields |
| `ssm_managed` | `boolean` | AWS SSM managed flag |
| `ssm_ping_status` | `varchar(255)` | |
| `ssm_last_ping_at` / `ssm_inventory_last_captured_at` | `timestamptz` | |
| `ssm_inventory_available` / `missing_iam_instance_profile` | `boolean` | |
| `last_cmdb_sync_at` / `last_inventory_at` | `timestamptz` | |
| `created_at` | `timestamptz` | NOT NULL |

Index: `idx_assets_tenant_id`.

---

### `sbom_uploads`

Tracks every SBOM document ingestion attempt.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `asset_id` | `uuid` | FK → `assets(id)` |
| `tenant_id` | `uuid` | FK |
| `format` | `varchar(255)` | CHECK IN (`CYCLONEDX`, `SPDX`, `HOST_INVENTORY`, `UNKNOWN`) |
| `status` | `varchar(255)` | CHECK IN (`IN_PROGRESS`, `SUCCESS`, `FAILURE`) |
| `original_filename` | `varchar(255)` | NOT NULL |
| `content_sha256` | `varchar(255)` | |
| `component_count` / `findings_generated` / `fetch_status_code` | `integer` | |
| `source_endpoint` / `source_reference` / `ingestion_source_system` / `ingestion_source_type` | `varchar(255)` | |
| `evidence_json` | `text` | |
| `uploaded_at` | `timestamptz` | NOT NULL |

Indexes: `idx_sbom_upload_asset_uploaded`, `idx_sbom_upload_tenant_uploaded`.

---

### `inventory_components`

Individual software components discovered within an asset's SBOM.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `asset_id` | `uuid` | FK → `assets(id)` |
| `sbom_upload_id` | `uuid` | FK → `sbom_uploads(id)` |
| `software_identity_id` | `uuid` | FK → `platform.software_identities(id)` |
| `manual_identity_id` | `uuid` | FK (for manually overridden identity) |
| `tenant_id` | `uuid` | FK |
| `purl` | `varchar(255)` | NOT NULL |
| `normalized_purl` | `varchar(255)` | |
| `package_name` | `varchar(255)` | NOT NULL |
| `normalized_name` / `version` / `normalized_version` | `varchar(255)` | |
| `ecosystem` | `varchar(255)` | NOT NULL |
| `coord_key` / `component_digest` | `varchar(255)` | |
| `component_status` | `varchar(255)` | CHECK IN (`ACTIVE`, `RETIRED`) |
| `is_eol` | `boolean` | |
| `eol_slug` / `eol_cycle` | `varchar(255)` | |
| `eol_date` / `eol_support_end_date` | `date` | |
| `eol_checked_at` | `timestamptz` | |
| `support_phase` | `varchar(255)` | |
| `manual_identity_reason` | `varchar(400)` | |
| `manual_identity_confirmed_by` | `varchar(255)` | |
| `manual_identity_confirmed_at` | `timestamptz` | |
| `ingested_at` / `last_observed_at` | `timestamptz` | NOT NULL |
| `retired_at` | `timestamptz` | |

Indexes: `idx_inventory_tenant_asset`, `idx_inventory_sbom_upload`, `idx_inventory_software_identity`, `idx_inventory_component_digest`, `idx_inventory_coord_key_tenant`, `idx_inventory_norm_purl_tenant`.

---

### `inventory_component_cpe_map`

Maps each inventory component to one or more CPE dimension rows (drives CPE-based correlation).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `component_id` | `uuid` | FK → `inventory_components(id)` |
| `cpe_id` | `uuid` | FK → `platform.cpe_dim(id)` |
| `tenant_id` | `uuid` | FK |
| `observed_version` | `varchar(255)` | |
| `first_seen_at` / `last_seen_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, component_id, cpe_id)`. Indexes: `idx_iccm_tenant_cpe`, `idx_iccm_tenant_component`.

---

### `component_vulnerability_states`

**Central correlation truth table.** One row per `(component, vulnerability)` pair per tenant.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `component_id` | `uuid` | FK → `inventory_components(id)` |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `applicability_state` | `varchar(40)` | NOT NULL |
| `applicability_reason` / `applicability_reason_detail` | text | |
| `impact_state` | `varchar(40)` | NOT NULL |
| `impact_reason` / `impact_reason_detail` | text | |
| `eligible_for_finding` | `boolean` | NOT NULL |
| `confidence_score` | `double precision` | |
| `matched_by` | `varchar(120)` | |
| `matched_vex_assertion_id` | `uuid` | |
| `vex_status` / `vex_freshness` / `vex_provider` / `vex_source` | `varchar(*)` | |
| `vex_target_id` | `uuid` | |
| `analyst_disposition` | `varchar(40)` | |
| `analyst_reason` | `text` | |
| `analyst_updated_at` / `analyst_updated_by` | various | |
| `precedence_reason` | `varchar(120)` | |
| `trace_json` | `text` | |
| `last_evaluated_at` / `state_changed_at` | `timestamptz` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, component_id, vulnerability_id)`. Indexes: `idx_comp_vuln_state_tenant_component_vuln`, `idx_comp_vuln_state_tenant_applicability`, `idx_comp_vuln_state_tenant_eligible`, `idx_comp_vuln_state_tenant_impact`.

---

### `findings`

Analyst-visible finding records. One row per `(component, vulnerability)` pair that passes eligibility.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `asset_id` | `uuid` | FK → `assets(id)`; nullable as of V44 — a finding may link a component without a resolved asset |
| `component_id` | `uuid` | FK → `inventory_components(id)`; nullable as of V44 — supports findings linked directly to an asset with no component |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `display_id` | `varchar(16)` | NOT NULL (e.g. `F-001234`) |
| `status` | `varchar(255)` | CHECK IN (`OPEN`, `RESOLVED`, `SUPPRESSED`, `AUTO_CLOSED`) |
| `decision_state` | `varchar(255)` | NOT NULL |
| `creation_source` | `varchar(255)` | CHECK IN (`MANUAL`, `AUTOMATIC`) |
| `matched_by` | `varchar(255)` | NOT NULL |
| `confidence_score` | `double precision` | |
| `risk_score` | `double precision` | NOT NULL |
| `severity_override` | `varchar(16)` | |
| `due_at` | `timestamptz` | |
| `assigned_to` / `assigned_by` | `varchar(255)` | |
| `assigned_at` | `timestamptz` | |
| `owner_group` | `varchar(255)` | |
| `evidence` | `jsonb` | |
| `first_observed_at` / `last_observed_at` | `timestamptz` | |
| `incident_id` / `incident_status` | `varchar(64)` | ServiceNow integration |
| `suppressed_by_rule_id` | `uuid` | |
| `suppressed_by_rule_name` / `suppression_reason` | various | |
| `suppressed_until` | `timestamptz` | |
| `vex_freshness` / `vex_provider` / `vex_status` | `varchar(*)` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(component_id, vulnerability_id)`. Indexes: `idx_findings_tenant_status_updated`, `idx_findings_tenant_component_vuln`, `idx_findings_asset_id`, `idx_findings_vulnerability_id`, `idx_findings_vulnerability_status`.

**`finding_kind`** (tenant `V1__tenant_schema.sql`, not shown above): `varchar`, defaulted/backfilled to `VULNERABILITY`, also `AI_POSTURE`/`AI_EXPOSURE`/`AI_RUNTIME` for the AI Security/AI Grid pipeline (see below). The uniqueness above is really `uk_findings_component_vulnerability` — one finding per resolved component/vulnerability pair regardless of how many documents or declared AI resources reference it. `finding_subjects` (added `V48`, see "AI Security / AI Grid Tables") gained a third `subject_type='AI_RESOURCE'`/`subject_role='AFFECTED_AI_RESOURCE'` combination with Milestone 3 part 5.1 — no migration needed, since `finding_subjects` carries no check constraint on those columns — recording that a `VULNERABILITY` finding transitively affects a declared AI-BOM resource. See "AI-BOM Declared Resources" below for the `ai_bom_resource_vulnerability_links` table that also records this, and [business-logic-guide.md](business-logic-guide.md) for `FindingsFilter.findingKind`/`affectedAiResourceId`/`hasAffectedAiResource`.

---

### `finding_list_projection` / `finding_workspace_projection_status`

Added in V44 (tenant migration line). Legacy migrations V3/V4 had created equivalent projection tables in the shared `public` schema; V44 repairs that by giving every tenant its own schema-local, RLS-protected copy (`FORCE ROW LEVEL SECURITY` + a `tenant_isolation` policy on `tenant_id`), rebuildable from `findings` at any time. `finding_list_projection` is a flattened, index-heavy read model of open/tracked findings (severity, status, owner, SLA due date, VEX status, incident linkage) built for the Findings table UI; `finding_workspace_projection_status` tracks the last rebuild (timestamp, row counts, duration) per tenant.

| Column (`finding_list_projection`) | Type | Notes |
|---|---|---|
| `finding_id` | `uuid` | PK |
| `display_id`, `severity`, `status`, `decision_state`, `creation_source`, `match_method` | `varchar` | |
| `vex_status` / `vex_freshness` / `vex_provider` | `varchar` | |
| `confidence_score` / `risk_score` | `double precision` | `risk_score` NOT NULL |
| `vulnerability_id`, `package_name`, `ecosystem` | `varchar` | |
| `owner_group`, `assigned_to`, `incident_id`, `asset_name`, `support_group` | `varchar` | |
| `due_at`, `suppressed_until` | `timestamptz` | |
| `patch_available` | `boolean` | NOT NULL |
| `created_at` / `updated_at` / `first_observed_at` | `timestamptz` | |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |

Indexes cover `(status, due_at)`, `(assigned_to, status)`, `(owner_group, status)`, `(incident_id, status)`, `(suppressed_until, status)`, `(updated_at, finding_id)`, `(severity, status)`, `(support_group, status)`, `(patch_available, status)`.

---

### `finding_events`

Immutable audit trail for all finding state changes.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `finding_id` | `uuid` | FK → `findings(id)` |
| `event_type` | `varchar(255)` | NOT NULL |
| `summary` | `varchar(255)` | NOT NULL |
| `actor` | `varchar(255)` | NOT NULL |
| `details_json` | `jsonb` | |
| `created_at` | `timestamptz` | NOT NULL |

Index: `idx_finding_events_finding_created`.

---

### `finding_comments`

User-authored comments on findings.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `finding_id` | `uuid` | FK → `findings(id)` |
| `author` | `varchar(255)` | NOT NULL |
| `body` | `varchar(255)` | NOT NULL |
| `created_at` | `timestamptz` | NOT NULL |

---

### `finding_delta_queue`

Async work queue driving incremental finding recomputation. Drained every 2 seconds in batches of 100.

| Column | Type | Notes |
|---|---|---|
| `id` | `bigint` | GENERATED BY DEFAULT AS IDENTITY PK |
| `dedupe_key` | `varchar(700)` | NOT NULL |
| `event_type` | `varchar(30)` | NOT NULL |
| `status` | `varchar(20)` | NOT NULL; DEFAULT `PENDING` |
| `tenant_id` / `component_id` / `vulnerability_id` | `uuid` | |
| `source_key` / `source_tag` | `varchar(*)` | |
| `attempt_count` / `max_attempts` | `integer` | NOT NULL; defaults 0 / 3 |
| `enqueued_at` / `visible_after` | `timestamptz` | NOT NULL; DEFAULT `now()` |
| `processing_started_at` / `completed_at` | `timestamptz` | |
| `error_message` | `text` | |

Indexes: `idx_fdq_dedupe_pending` (unique partial WHERE `status = 'PENDING'`), `idx_fdq_pending_visible` (partial WHERE `status = 'PENDING'`).

---

### `org_cve_records`

**CVE Assessment Workbench backing table.** One row per `(tenant, vulnerability)`. Backs `/vuln-repo/org-cves`.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `vulnerability_id` | `uuid` | FK → `platform.vulnerabilities(id)` |
| `external_id` | `varchar(255)` | NOT NULL |
| `applicability_state` | `varchar(255)` | CHECK IN (`APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`) |
| `impact_state` | `varchar(255)` | |
| `org_impact` | `varchar(255)` | CHECK IN (`NONE`, `LOW`, `MEDIUM`, `HIGH`) |
| `impacted` | `boolean` | NOT NULL |
| `cvss_score` / `epss_score` | `double precision` | |
| `severity` | `varchar(255)` | NOT NULL |
| `in_kev` | `boolean` | NOT NULL |
| `matched_asset_count` / `matched_component_count` / `matched_software_count` | `bigint` | NOT NULL |
| `applicable_component_count` / `impacted_component_count` / `fixed_component_count` | `bigint` | NOT NULL |
| `not_affected_component_count` / `under_investigation_component_count` / `unknown_component_count` / `no_patch_component_count` | `bigint` | NOT NULL |
| `eol_component_count` / `eos_component_count` | `bigint` | NOT NULL |
| `suppressed_at` | `timestamptz` | |
| `suppressed_by` / `suppressed_by_rule_id` / `suppressed_by_rule_name` | various | |
| `suppressed_until` / `suppression_reason` | various | |
| `last_evaluated_at` | `timestamptz` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, vulnerability_id)`. Indexes: `idx_org_cve_record_tenant_applicability`, `idx_org_cve_record_tenant_external_id`, `idx_org_cve_record_tenant_impacted`, `idx_org_cve_record_tenant_vulnerability`.

---

### `org_cve_ai_artifacts`

Persisted AI-generated outputs for a CVE record.

| Column | Type | Notes |
|---|---|---|
| `org_cve_record_id` | `uuid` | PK; FK → `org_cve_records(id)` |
| `ai_actions_json` | `jsonb` | |
| `ai_actions_generated_at` | `timestamptz` | |
| `ai_solution_json` | `jsonb` | |
| `ai_solution_generated_at` | `timestamptz` | |
| `investigation_summary_output_json` / `investigation_summary_input_json` | `jsonb` | |
| `investigation_summary_mode` | `varchar(255)` | |
| `investigation_summary_generated_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `risk_policies`

One row per tenant. Controls finding generation mode, SLA, auto-close, triage weights, and custom scoring.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK; unique |
| `finding_generation_mode` | `varchar(20)` | CHECK IN (`AUTO`, `MANUAL`) |
| `critical_threshold` / `high_threshold` | `double precision` | NOT NULL |
| `critical_sla_days` / `high_sla_days` / `medium_sla_days` / `low_sla_days` | `integer` | NOT NULL |
| `asset_critical_sla_multiplier` / `asset_high_sla_multiplier` / `asset_medium_sla_multiplier` / `asset_low_sla_multiplier` | `double precision` | NOT NULL |
| `auto_close_enabled` | `boolean` | NOT NULL |
| `auto_close_after_days` | `integer` | NOT NULL |
| `auto_close_asset_identifier` | `varchar(255)` | |
| `findings_score_config` | `jsonb` | Custom attribute-based scoring rules |
| `updated_at` | `timestamptz` | NOT NULL |

---

### `suppression_rules`

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `name` | `varchar(255)` | NOT NULL |
| `record_type` | `varchar(255)` | CHECK IN (`CVE`, `FINDING`) |
| `state` | `varchar(255)` | CHECK IN (`DRAFT`, `APPROVED`, `IN_REVIEW`, `REJECTED`, `EXPIRED`) |
| `condition_logic` | `varchar(255)` | NOT NULL |
| `conditions_json` | `jsonb` | NOT NULL |
| `reason` | `varchar(255)` | |
| `valid_from` / `valid_to` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `ownership_rules`

Rule-based finding ownership assignment.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `name` | `varchar(255)` | NOT NULL |
| `user_group` | `varchar(255)` | NOT NULL |
| `condition_json` | `text` | NOT NULL |
| `execution_order` | `integer` | NOT NULL |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

---

### `vulnerability_source_filter_configs`

Per-tenant, per-source configuration for which feeds participate in correlation.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | FK |
| `source_system` | `varchar(255)` | NOT NULL |
| `enabled_for_correlation` | `boolean` | NOT NULL |
| `filters_json` | `text` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

Unique: `(tenant_id, source_system)`.

---

### `aws_discovery_configs` / `aws_discovery_targets`

AWS EC2 discovery connector configuration and multi-account targets.

`aws_discovery_configs`: one row per tenant. Fields include `auth_type` (CHECK IN `INSTANCE_METADATA`, `ACCESS_KEY`, `CROSS_ACCOUNT_ROLE`), `aws_account_id`, `access_key_id`, `credential_secret` (encrypted), `cross_account_role_arn`, `external_id`, `regions_json`, `resource_types_json`, `enabled`, `auto_sync_enabled`, `interval_minutes`.

`aws_discovery_targets`: sub-entries per config for multi-account discovery. Fields include `account_id`, `account_name`, `role_arn`, `external_id`, `regions_json`, `resource_types_json`, `enabled`.

---

### `azure_discovery_configs` / `azure_discovery_targets`

Azure cloud discovery connector configuration and multi-subscription targets. Added in V40/V41 — mirrors the AWS discovery tables; newer and less exercised in production.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `source_system` | `varchar(80)` | NOT NULL; default `'azure'` |
| `auth_type` | `varchar(32)` | NOT NULL; CHECK IN (`CLIENT_SECRET`, `MANAGED_IDENTITY`) |
| `azure_tenant_id` | `varchar(128)` | Azure AD tenant ID |
| `client_id` | `varchar(255)` | Service principal client ID |
| `client_secret` | `text` | Encrypted service principal secret |
| `subscription_ids_json` | `text` | NOT NULL; default `'[]'` |
| `regions_json` | `text` | NOT NULL; default `'["eastus2"]'` |
| `enabled` / `auto_sync_enabled` | `boolean` | NOT NULL |
| `interval_minutes` | `integer` | NOT NULL; default `1440` |
| `last_test_status` / `last_test_message` | various | |
| `last_tested_at` / `last_sync_at` | `timestamptz` | |
| `created_at` / `updated_at` | `timestamptz` | NOT NULL |

`azure_discovery_targets`: per-subscription sub-entries. Fields: `config_id` (FK), `subscription_id`, `subscription_name`, `enabled`, `regions_json`, `last_test_status`/`message`/`tested_at`, `last_sync_at`.

Unique: `azure_discovery_configs(tenant_id, source_system)`; `azure_discovery_targets(config_id, subscription_id)`.

---

### `sccm_cmdb_configs`

SCCM/MECM CMDB connector configuration.

Fields: `auth_type` (CHECK IN `SQL_AUTH`, `WINDOWS_AUTH`), `database_name`, `jdbc_url`, `username`, `credential_secret` (encrypted), `site_code`, `fetch_size`, `interval_minutes`, `query_timeout_seconds`, `enabled`, `auto_sync_enabled`, `mock_mode`.

---

### `servicenow_cmdb_configs`

ServiceNow CMDB connector configuration.

Fields: `auth_type` (CHECK IN `BASIC`, `BEARER`), `base_url`, `username`, `credential_secret` (encrypted), `ci_table`, `discovery_model_table`, `install_table`, `discovery_fields`, `install_fields`, `discovery_query`, `install_query`, `page_size`, `interval_minutes`, `enabled`, `auto_sync_enabled`.

---

### `github_sbom_sources`

Scheduled GitHub SBOM ingestion jobs.

Fields: `name`, `owner`, `repo`, `path`, `asset_identifier`, `asset_name`, `asset_type`, `frequency`, `interval_minutes`, `enabled`, `last_run_at`, `last_run_status`, `last_error`.

---

### `cis` / `ci_aliases`

`cis`: Configuration Items synced from ServiceNow CMDB. FK → `assets(id)`. Fields include `sys_id` (unique with `tenant_id`), `display_name`, `business_criticality`, `environment`, CMDB sync timestamps.

`ci_aliases`: Alternative names for a CI. Unique: `(tenant_id, normalized_alias_name, source_system)`.

---

### `software_instances`

Software installed on a CI (from ServiceNow/SCCM discovery). Links CI → SoftwareIdentity → InventoryComponent.

---

### `software_identity_metadata`

Custom per-tenant metadata attached to a software identity (owner, licensing, support group, recommendation). Added in V39.

| Column | Type | Notes |
|---|---|---|
| `tenant_id` | `uuid` | NOT NULL; part of composite PK; FK → `platform.tenants(id)` |
| `software_identity_id` | `uuid` | NOT NULL; part of composite PK; FK → `platform.software_identities(id)` |
| `owner` | `text` | Software owner/team |
| `licensed` | `text` | NOT NULL; default `'Unknown'` |
| `license_type` | `text` | e.g. `MIT`, `Commercial` |
| `support_group` | `text` | Internal support/SRE group |
| `recommendation` | `text` | Custom recommendation text |
| `recommendation_updated_at` | `timestamptz` | |
| `updated_at` | `timestamptz` | NOT NULL |

PK: `(tenant_id, software_identity_id)`.

---

### `discovery_models`

Software discovery model records from SCCM/ServiceNow. Fields: `primary_key` (unique with `tenant_id`), `normalized_product` / `publisher` / `version`, `ml_model_version`, `normalization_status`, `product_hash` / `version_hash`, `approved`.

---

### `software_inventory_items`

Flattened inventory view for reporting. One row per unique component per asset. Fields: `purl`, `package_name`, `version`, `ecosystem`, `component_status`, `first_seen_at`, `last_observed_at`, `synced_at`.

---

### `sync_runs`

Audit log for all sync job executions.

Fields: `sync_type`, `run_scope`, `status`, `records_fetched` / `inserted` / `updated` / `failed`, `started_at`, `completed_at`, `error_message`, `metadata_json`. Moved to the `platform` schema in a later migration (`move_sync_runs_to_platform`) — despite living alongside tenant tables in this doc for grouping purposes, confirm current schema location before writing cross-schema queries.

---

### `ingestion_jobs`

Tracks asynchronous ingestion job status (SBOM uploads, config imports, asset discovery runs). Backs `IngestionJobController` (`/api/ingestion-jobs`).

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` | PK |
| `tenant_id` | `uuid` | NOT NULL; FK → `platform.tenants(id)` |
| `job_type` | `varchar(80)` | NOT NULL; e.g. `SBOM_INGESTION`, `CONFIG_IMPORT`, `AI_SECURITY_AWS_BEDROCK`, `AI_SECURITY_AZURE_DISCOVERY` |
| `source_type` | `varchar(80)` | NOT NULL; e.g. `GITHUB`, `ARTIFACTORY` |
| `asset_identifier` | `varchar(500)` | NOT NULL |
| `status` | `varchar(32)` | NOT NULL; CHECK IN (`QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`) |
| `requested_by` | `varchar(255)` | |
| `requested_at` / `started_at` / `completed_at` | `timestamptz` | |
| `attempt_count` | `integer` | NOT NULL; default `0` |
| `dedupe_key` | `varchar(700)` | NOT NULL |
| `payload_json` / `result_json` | `text` | |
| `failure_code` / `failure_message` | various | |
| `visible_at` | `timestamptz` | NOT NULL; default `now()` |
| `sbom_upload_id` | `uuid` | FK → `sbom_uploads(id)` if SBOM-related |

Unique (partial): `dedupe_key` WHERE `status IN ('QUEUED','RUNNING')`. Indexes: `(status, visible_at, id)`, `(requested_at DESC, id DESC)`, `(asset_identifier, status)`.

---

### `service_accounts`

API service accounts scoped to a tenant.

Fields: `key_id` (unique), `name`, `role`, `status`, `last_used_at`. This is JWT authorization registry metadata: an ACTIVE same-tenant SERVICE_ACCOUNT entry constrains a verified subject; `key_id` is not a standalone credential.

---

### `audit_events`

Platform-wide audit log. Every security-relevant action appended here.

Fields: `actor_user_id`, `occurred_at`, `actor_subject`, `actor_role`, `action`, `target_type`, `target_id`, `request_id`, `source_ip`, `outcome`, `details_json` (jsonb).

---

### `fix_records`

AI-generated or analyst-authored remediation recommendations for a CVE.

Fields: `cve_id`, `fix_type`, `recommendation_source`, `summary`, `description`, `os_hint`, `related_cve_ids` / `software_entities` / `source_urls` (jsonb), `generated_at`.

---

### Remediation Campaigns

Backs `CampaignController` (`/api/campaigns`) and the `/vuln-repo/campaigns` frontend. Not covered in earlier drafts of this doc.

**`campaigns`** — one row per campaign. Fields: `tenant_id`, `name`, `summary`, `status` (DRAFT/ACTIVE/PAUSED/BLOCKED/IN_REVIEW/CLOSED/CANCELLED), `created_by`, `due_at`, `started_at`, `paused_at`, `closed_at`, `created_at`/`updated_at`. Index: `(tenant_id, status, updated_at DESC)`.

**`campaign_vulnerabilities`** — CVEs linked to a campaign. FK `campaign_id` → `campaigns(id)` ON DELETE CASCADE, FK `vulnerability_id` → `platform.vulnerabilities(id)`, `external_id`, `title`, `severity` snapshot. Unique: `(campaign_id, external_id)`.

**`campaign_exceptions`** — per-finding/asset exception requests within a campaign. Fields: `campaign_id` (FK, cascade), `finding_display_id`, `asset_name`, `package_name`, `title`, `reason`, `status` (PENDING/APPROVED/REJECTED), `requested_by`/`requested_at`, `decision_due_at`, `decisioned_by`/`decisioned_at`.

**`campaign_notify_groups`** — notification subscriptions. Fields: `campaign_id` (FK, cascade), `group_name`, `role_label`, `trigger_summary`, `group_email`, `notifications_paused`.

**`campaign_watchlist_entries`** — manual watchlist subscribers. Fields: `campaign_id` (FK, cascade), `entry_type` (INDIVIDUAL/GROUP/POLICY), `label`, `email`, `trigger_policy`, `active`.

**`campaign_notes`** — free-form discussion notes. Fields: `campaign_id` (FK, cascade), `author`, `body`, `created_at`.

**`campaign_activities`** — system-generated activity log. Fields: `campaign_id` (FK, cascade), `activity_type`, `actor`, `body`, `metadata_json`, `created_at`.

**`campaign_delivery_attempts`** — notification delivery audit log. Fields: `campaign_id` (FK, cascade), `target_type`, `target_label`/`target_address`, `subject`, `delivery_state` (QUEUED/SENT/FAILED/BOUNCED), `provider_message_id`, `detail`.

---

### BOM / CBOM

Backs `BomController` (`/api/bom`) and `CbomController` (`/api/bom/cbom`). These are the original per-document tables from before the AI-BOM → AI Grid integration; see "BOM Common Lifecycle" and "AI-BOM Declared Resources" immediately below for the source/completeness/contribution/declared-resource tables that integration added on top of them.

**`bom_ingestion_records`** — one row per ingested BOM document. Key fields: `tenant_id`, `sbom_upload_id`/`asset_id` (optional links), `bom_type` (SBOM/CBOM/HBOM), `format`/`format_version`/`spec_family`, `serial_number`, `supplier`, `source_type` (URL/UPLOAD/API)/`source_system`/`source_reference`, `component_count`, `status` (ACTIVE/SUPERSEDED/ARCHIVED), `superseded_by`/`previous_bom_id` (self-referencing), `checksum_sha256`, `ingested_at`/`ingested_by`. Indexes on `(tenant_id, bom_type, status)`, `(tenant_id, ingested_at DESC)`, `(tenant_id, source_system)`.

**`bom_components`** — components extracted from a BOM. Fields: `bom_id` (FK), `tenant_id`, `name`/`version`/`purl`/`cpe`/`license`/`supplier`, `component_type`, `category` (MATCHED/UNMATCHED), `is_active`, `bom_ref`, `group_name`, `hashes`/`properties`/`external_references` (jsonb), `workflow_status` (DISCOVERED/INVESTIGATING/RESOLVED). Indexes on `purl` and `cpe` (partial, WHERE NOT NULL).

**`bom_component_evidence`** — provenance for a component's presence. Fields: `bom_component_id`/`bom_id` (FK, cascade), `evidence_type` (MANIFEST/SCAN/DECLARATION), `evidence_key`/`evidence_value`, `source_system`/`source_reference`.

**`bom_component_vulnerability_links`** — matches a BOM component to a known vulnerability. Fields: `bom_component_id`/`bom_id` (FK, cascade), `vulnerability_key` (CVE/GHSA ID), `vulnerability_source`, `relation_type`, `match_source`, `match_confidence` (0–100), `direct_match`, `correlation_evidence_json`.

**`bom_component_workflows`** — remediation/investigation workflow per component-vulnerability pair. Fields: `bom_component_id`/`vulnerability_link_id` (FK, cascade), `workflow_type` (INVESTIGATION/REMEDIATION), `workflow_status` (DISCOVERED/IN_PROGRESS/RESOLVED/REJECTED), `workflow_reason`, `investigation_key`, `finding_id`, `started_at`/`updated_at`/`closed_at`.

---

### BOM Common Lifecycle (tenant `V4`, `V6`)

Shared infrastructure introduced for the AI-BOM → AI Grid integration (Milestone 1) that SBOM, AI-BOM, vendor-BOM, and CBOM ingestion all now go through — a stable logical source, an auditable completeness assertion, and a source-scoped contribution ledger, none of which existed before this work (a document upload used to replace-by-inference on asset+supplier alone, with no way to withdraw one source's support without looking like the component had vanished).

**`bom_sources`** (`V4`) — a stable logical source that outlives any individual document version. Fields: `tenant_id`, `bom_type`, `asset_id` (nullable until resolved), `supplier`, `source_reference`, `source_key` (deterministic identity for scheduled/automated callers, so a re-run replaces its own source rather than accumulating one per run; null for manual uploads), `current_bom_id`, `revision` (monotonic per source; keys Milestone 2 projection work so obsolete work can be discarded rather than reprocessed), `completeness` (`PARTIAL` default / `COMPLETE_ASSET_SOFTWARE`), `state` (`ACTIVE` / `HELD_ENTITLEMENT` / `DEFERRED` — see "AI-BOM Declared Resources" below for the latter two). Indexes on `(tenant_id, asset_id, bom_type)` and `(tenant_id, state)`.

**`bom_source_completeness_assertions`** — append-only record of a completeness claim: `source_id`, `bom_id` (the document version the assertion accompanied), `completeness`, `asset_scope_json`, `asserted_by`, `asserted_at`. Asserting `COMPLETE_ASSET_SOFTWARE` is what later authorizes retiring a component on replacement; every replacement must repeat the assertion rather than inheriting the previous one. Authorization-gated at the API layer, not the schema.

**`bom_component_contributions`** — one row per (source, inventory component) standing claim of presence; this is the mapping the pipeline previously discarded entirely (a BOM-to-inventory match was recomputed at ingest and never stored). Fields: `source_id`, `bom_id`, `bom_component_id` (nullable for backfilled rows that reconstruct the link without identifying the original BOM component), `inventory_component_id`, `resolved_identity_key`, `contribution_state` (`SUPPORTED` default / `WITHDRAWN` / conflict states — see `BomContributionState`), `authoritative_absence` (boolean; set only when a replacement under an asserted complete scope omitted the component — the sole path to component retirement), `first_contributed_at`/`last_contributed_at`, `withdrawn_at`. Unique on `(tenant_id, source_id, inventory_component_id)`. Indexes support "every claim standing against a component" (`(tenant_id, inventory_component_id, contribution_state)`) and "every claim a source carries" (`(tenant_id, source_id, contribution_state)`) lookups.

**`bom_asset_backfill_state`** — per-asset migration gate: `state` (`PENDING` / `BACKFILLED` / `FAILED`), `attempt_count`, `backfilled_at`, `failure_message`. Until an asset is `BACKFILLED`, its components are treated as `LEGACY_UNKNOWN` evidence state and no absence may be inferred from missing contribution rows — the guard ships in the same migration as the schema it protects so it can never lag behind.

**`bom_component_relationships`** (`V6`) — the dependency/composition edges a BOM document declares between its own components, recorded verbatim and deliberately *not* interpreted (a CycloneDX `dependsOn` edge states one component depends on another; it does not state a model was trained on a dataset or a dataset is served at inference time — inferring that would manufacture a provenance claim the document never made). Fields: `bom_id`, `source_ref`/`target_ref` (bom-ref strings as they appear in the document — kept as text rather than resolved to component ids, since a document may reference a ref it never defines and dropping those edges would silently lose declared structure), `source_component_id`/`target_component_id` (resolved when possible), `relationship_type` (`DEPENDS_ON` / `COMPOSED_OF`). Unique on `(tenant_id, bom_id, source_ref, target_ref, relationship_type)`. This is what Milestone 3 part 5.1's transitive-dependency correlation (below) walks.

---

### AI-BOM Declared Resources (tenant `V7`–`V11`, platform `V5`)

The models and datasets an uploaded AI-BOM declares, kept deliberately separate from `ai_security_artifacts` (a connector-observed cloud resource) — a declaration is not a deployment, and the AI Grid policy-assessment pipeline must never evaluate a document's claim as though it were observed provider configuration. Backs `AiBomDeclaredResourceController` (`/api/bom/declared-resources`) and the `/inventory/ai/declared-resources[/:resourceId]` frontend pages.

**`ai_bom_declared_resources`** (`V7`, widened `V11`) — one row per declared model/dataset. Fields: `source_id` (FK `bom_sources`, cascade), `bom_id`/`bom_component_id` (the document version and BOM component that last declared it), `resource_kind` (`MODEL` / `DATASET`), `name`, `version`, `identity_kind` (`DIGEST` / `VERSIONED_IDENTIFIER` / `SOURCE_SCOPED_REF`, descending trustworthiness — a display name is never an identity, since two unrelated models are routinely both called "classifier"), `identity_value`, `deployment_state` (`UNVERIFIED` default / `LINKED` / `AMBIGUOUS`), `linked_artifact_id` (FK `ai_security_artifacts`, `ON DELETE SET NULL`), `link_method` (`DIGEST_MATCH` / `VERSIONED_IDENTIFIER_MATCH` / `REVIEWED`), `link_reviewed_by`/`link_reviewed_at`, `proposed_artifact_id`/`proposed_by`/`proposed_at` (`V11` — a reviewer's not-yet-confirmed candidate mapping, kept separate from the `linked_*` columns because those require `deployment_state='LINKED'`), `attributes_json`. Unique on `(tenant_id, source_id, identity_value)` — the same model declared by two sources stays two declarations until something actually establishes equivalence. Check constraints enforce: `LINKED` requires both `linked_artifact_id` and `link_method` non-null (and vice versa, so a link is always explainable); `link_method='REVIEWED'` requires `link_reviewed_by` (an automatic match must not claim a reviewer); the `V11` proposal columns are all-or-nothing together. A partial index on `deployment_state <> 'LINKED'` drives the unlinked/ambiguous coverage queue.

Automatic linking (`AiBomDeploymentLinkingService`) only matches `MODEL` resources identified by `VERSIONED_IDENTIFIER` against `ai_security_artifacts` by name (+ version when the candidate exposes one); two same-named candidates with no matching version become `AMBIGUOUS` rather than a guess. `DIGEST`-identified and `DATASET` resources, and any `SOURCE_SCOPED_REF` resource, have no automatic match path — only the reviewed propose/approve workflow (`AiBomResourceMappingService`) can link them. Propose (role `SECURITY_ANALYST`+) stages `proposed_artifact_id` after checking the artifact exists for the tenant; approve (role `INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR` — narrower than propose) promotes it to `linked_artifact_id`/`link_method='REVIEWED'`/`link_reviewed_by`; remove clears everything back to `UNVERIFIED`. Each mutation is a `@SensitiveTenantAction` with an explicit `audit_events` row.

**`ai_bom_resource_vulnerability_links`** (historical `V10` provenance; lifecycle added by post-reset tenant `V2`) — source-scoped associations to canonical software `VULNERABILITY` findings. `status` is `ACTIVE` or `RETIRED`, independent of finding workflow status; confirmation/retirement timestamps, a reason, and lifecycle history retain the association's audit trail. The existing `(tenant_id, declared_resource_id, finding_id)` uniqueness remains intact. `AiBomCorrelationReconciler` atomically maintains link/path/gap rows and their `AFFECTED_AI_RESOURCE` subjects, without creating, reopening, or resolving a finding.

**`ai_bom_correlation_paths`** (tenant `V2`) — multiple supporting paths per association, with source/BOM revision, ordered component/relationship IDs, stable reference/relationship keys, terminal inventory component, match method, fingerprint, lifecycle, and historical evidence. Uniqueness on `(tenant_id, declared_resource_id, link_id, fingerprint)` makes repeated delivery idempotent. Both dependency edge types are traversed, with path-local cycle guards and configurable depth/node/edge/path limits.

**`ai_bom_correlation_gaps`** (tenant `V2`) — unresolved uncertainty keyed by source-scoped resource and reason, optionally naming a component/reference; a finding or link is not required. Recomputed gaps retain identity, disappear from current readers when resolved, and can protect prior support when absence cannot be established. The two new tables enforce tenant RLS. V1 remains unchanged; the independent packaged targets are now platform V8 and tenant V6.

**`ai_bom_provenance_facts`** (`V8`) — durable storage for the `provenance.ai_bom_present` fact (registered in the platform fact catalog by `postgres_reset/V5`), deliberately not `ai_grid_facts` (that table requires a connector-observed artifact/snapshot/run, which a BOM-only asset never has). Fields: `asset_id`, `source_id`, `bom_id` (the document version that produced the projection), `fact_key` (default `provenance.ai_bom_present`), `value_boolean`, `evidence_class` (default `BOM_DOCUMENT`, distinct from provider-configuration evidence classes — a document assertion must not satisfy a policy meaning to require observed configuration), `bom_format`, `spec_version`, `document_ingested_at`, `projected_at`, `projection_version`. Unique on `(tenant_id, asset_id, fact_key)`. The platform-side fact definition (`postgres_reset/V1__platform_schema.sql`) registers `provenance.ai_bom_present` with `allowed_workflow_uses_json=["COVERAGE_CONTEXT"]` and deliberately *not* `POSTURE_FINDING` — a document's existence is not a posture claim, and allowing it as a finding input would enable the BOM coverage policies that are meant to stay disabled (see `business-logic-guide.md`).

**`ai_bom_projection_receipts`** (`V8`) — durable completed-work receipt, since a job's queued/running dedupe only prevents duplicate *queued* work; a receipt is what stops a redelivered or re-claimed job from projecting the same source revision twice after the real work already finished. Fields: `source_id`, `source_revision`, `operation`, `projection_version`, `completed_at`. Unique on `(tenant_id, source_id, source_revision, operation, projection_version)`.

**`ai_bom_projection_admissions`** (`V9`) — daily admission budget for AI-BOM projection, deliberately not `ai_grid_budget_admissions` (that table is keyed by a connector `run_id` and tracks cadence rules for recurring scheduled scans, neither of which apply to a document-upload-triggered job — a different provider label alone would not isolate the budgets from each other). Fields: `tenant_id`, `admission_date` (composite PK), `admitted_count`, `throttled_count`, `updated_at`. Default daily limit is 100 (`app.ai-bom.projection.daily-admission-limit`), excluded from connector scan-count usage. `AiBomProjectionSchedulingService` additionally caps queued/running jobs at 100 per tenant (`app.ai-bom.projection.max-queued-per-tenant`) and coalesces overflow as durable per-source dirty state, surfaced as a `DEFERRED` `bom_sources.state` rather than dropped.

Non-entitled tenants keep ordinary BOM ingestion and vulnerability processing; their sources are marked `HELD_ENTITLEMENT` instead of enqueuing a job per upload, and on entitlement grant each held source's latest revision is scheduled through the bounded queue.

---

### Read-Model Projections (Tenant Schema)

| Table | Purpose |
|---|---|
| `software_identity_summary` | Per-identity aggregation (asset/component/version counts, EOL breakdown) — backs Software Identities view |
| `quality_issue_projection` | Data quality issues by domain/severity — backs Operations Quality view |
| `dashboard_noise_reduction_projection` | Single-row-per-tenant CVE noise reduction counts |
| `software_identity_cluster_link` | Bulk normalization override links (source_type + source_key → canonical identity) |

---

### `applicability_assessments`

Manual applicability assessment records attached to a CVE. Fields include `vulnerability_id`, `status`, `final_result`, `assessed_by`, `detection_method`, `confidence_level`, `software_detected`, `vulnerable_version_present`, `current_version`, `fixed_version`, `justification`, `completed_at`.

---

### `investigations` / `investigation_activities` / `investigation_attachments`

Investigation lifecycle for a CVE within a tenant. Activities are append-only event log entries. Attachments reference `storage_path` for uploaded files.

---

### `demo_requests` / `demo_invites`

`demo_requests`: public demo access requests. Fields: company, email, full_name, company_size, role_title, use_case, notes, status, decided_at/by, rejection_reason, tenant_id.

`demo_invites`: current `token_hash` (SHA-256 digest, unique), cleared legacy raw token, email/status/expiry/acceptance/sent timestamps and request/tenant FKs. Tenant V3 migrates shared invitation digests in the default lifecycle schema with the conflict guard restored; no bearer is exposed by current invite DTOs.

---

## AI Security / AI Grid Tables

Backs the `com.prototype.vulnwatch.aisecurity` module (19 controllers, 71 services — see [business-logic-guide.md](business-logic-guide.md#ai-security--ai-grid-pipeline) and [architecture.md](architecture.md)) and the `/findings/ai`, `/policies`, `/inventory/ai` frontend routes. Two generations coexist: a legacy **AI Security** catalog (hardcoded ~14-policy checklist) and the newer, platform-governed **AI Grid** pipeline that has superseded it for policy evaluation (legacy findings and policy selections were migrated into the canonical/governed tables). Unlike every other table in this document, **none of these tables have a JPA `@Entity` or Spring Data repository** — all reads/writes go through `JdbcTemplate`/`NamedParameterJdbcTemplate` in the `aisecurity.service` classes directly.

**A note on the version numbers below:** a one-time migration-history reset consolidated the prior numbered history into `postgres_reset/V1__platform_schema.sql` and `tenant/V1__tenant_schema.sql` (see "Tenant Schema Control Plane" further down). Historical `V<n>` citations describe pre-reset provenance; current post-reset V2 additions are called out explicitly.

Historical module checkpoints used platform/tenant V3 and later V5/V11 before the development reset. Those are provenance, not current packaged targets or deployed-upgrade proof. `MigrationCatalogTest` now pins independent platform V8 / tenant V6; required tenant range is V6–V6, next platform V9 / tenant V7. Post-reset tenant V2 is AI-BOM correlation evidence, V3 invitation boundaries, V4 owned work/delivery, and V5 bounded retention progress.

### Tenant schema tables (pre-reset provenance: `V45`–`V64`)

#### Deferred runtime storage

The fresh tenant V1 retains typed runtime tables but contains no runtime evidence or sources. Runtime admission, collection, evaluation, and customer surfaces are out of scope. Historical identity-upgrade/preflight descriptions below are deferred/pre-reset design, not current migration steps. Use fresh disposable local fixtures; preserve existing shared/deployed state pending read-only history inspection and an authorized transition rehearsal.

**Shared AI inventory infrastructure** (`V45`, `V46`, `V62`–`V64`): `ai_security_connector_configs` (AWS Bedrock / Azure AI connector config, credentials encrypted), `ai_security_azure_credential_profiles` (client-secret/workload-federation/managed-identity, active + pending rotation), `ai_security_artifacts` (discovered AI resources — agents, models, guardrails, knowledge bases, MCP servers; carries PII scan status/source/info-types added in `V62`/`V64`), `ai_security_artifact_sources`, `ai_security_relationships`, `ai_security_snapshot_scopes`, and `ai_security_observation_receipts` (idempotency for ingested observation chunks). Tenant policy configuration and legacy findings were retired in `V65`; AI Grid and canonical findings are their sole owners.

**AI Grid core pipeline** (`V48`–`V57`): `ai_grid_snapshot_bodies`/`_manifests` (immutable, hash-deduped artifact snapshots), `ai_grid_facts` (versioned facts derived from snapshots — the input to policy evaluation), `ai_grid_artifact_classifications`, `ai_grid_policy_selections`/`_history` (tenant's REQUIRED/ENABLED/PREVIEW/DISABLED choice per governed policy), `ai_grid_assessments` (policy evaluation results: PASS/FAIL/NO_DECISION/ERROR/NOT_APPLICABLE), `ai_grid_coverage_gaps`, `ai_grid_systems`/`_system_revisions`/`_system_memberships` (agent-rooted AI system grouping with lineage), `ai_grid_system_lineage_events`/`_participants`, `ai_grid_system_membership_decisions`/`_overrides` (`V56`/`V57`), `ai_grid_outbox`, `ai_grid_owner_history` (ownership resolution audit trail), `ai_grid_run_metrics`/`_run_scope_metrics` (per-run economics/utility telemetry), `ai_grid_relationship_snapshots` (`V51`), `ai_grid_policy_readiness`, `ai_grid_setup_actions` (prioritized onboarding queue, `V52`), `ai_grid_current_coverage_state`/`_artifacts`, `ai_grid_current_expected_candidates` (materialized "current epoch" union of latest complete scans, `V53`). The core `findings` table gained `finding_subjects`/`finding_reviews` (`V48`) to generalize beyond CVE-shaped findings to `AI_POSTURE`/`AI_EXPOSURE` kinds.

**Historical pre-reset tenant V2 runtime approvals (folded into reset V1):** `ai_grid_approved_agent_manifests` binds a tenant-approved agent version to an immutable manifest digest and component array; `ai_grid_component_allowlists` records approved/revoked provider component digests. Both tables have forced RLS and tenant-isolation policies. V2 also adds not-yet-validated check constraints for the normalized `ai_agent_executions.approval_state` and `policy_state` vocabularies. These retained objects do not enable runtime; current post-reset tenant V2 has a different purpose.

**Historical pre-reset tenant V3 runtime contract (deferred storage):** widens `ai_agent_executions` with ~15 typed, policy-addressable columns — `environment_digest`, `deployment_digest`, `acting_identity_digest`, `delegated_identity_digest`, `identity_digest_key_version` (all HMAC-safe references, not raw identifiers), `termination_reason`, `evidence_source`, `evidence_class`, `evidence_confidence` (0–1, checked), `step_count` (≥0, checked), `spend_currency`/`spend_unit`, `collected_at`, `provider_event_time`, `delivery_latency_ms` (≥0, checked). Widens `ai_agent_execution_events` with the event-scoped decision contract — `producer_id`, `provider_event_digest`, `digest_key_version`, `ingested_at`, `action_category` (`READ`/`WRITE`/`DELETE`/`SEND`/`EXECUTE`/`ADMIN`/`PAYMENT`/`PUBLISH`/`OTHER`), `target_class` (`INTERNAL`/`EXTERNAL`/`PUBLIC`/`SENSITIVE_STORE`/`CODE_RUNTIME`/`IDENTITY_SYSTEM`/`FINANCIAL_SYSTEM`/`UNKNOWN`), `tool_digest`/`tool_version_digest`/`target_digest`/`action_correlation_digest`, `data_sensitivity` (`PUBLIC`/`INTERNAL`/`CONFIDENTIAL`/`RESTRICTED`/`UNKNOWN`), `data_operation` (`READ`/`WRITE`/`DELETE`/`TRANSFORM`/`TRANSMIT`/`NONE`/`UNKNOWN`), `approval_state` (`APPROVED`/`DENIED`/`REQUIRED`/`NOT_REQUIRED`/`BYPASSED`/`UNKNOWN`), `policy_state` (`ALLOWED`/`DENIED`/`BLOCKED`/`NOT_EVALUATED`/`UNKNOWN`), `decision_reason`, `enforcement_point`, `action_outcome` (`SUCCEEDED`/`FAILED`/`DENIED`/`BLOCKED`/`CANCELLED`/`UNKNOWN`), `evidence_class` — each a closed, uppercase, invalid-fails-ingestion enum. A partial unique index dedupes events on `(tenant_id, producer_id, provider_event_digest, digest_key_version)` when all three are present; a partial index on consequential `action_category` values speeds the Program 2 fill-rate queries. `ai_agent_execution_receipts.connector_id` becomes nullable because governed telemetry-adapter batches have no connector.

Historical pre-reset tenant V3 tables (retained schema; no active runtime ingestion/read path): `ai_runtime_evidence_producers` (one row per registered adapter producer — `producer_id` PK, bound `tenant_id`, `service_account_id`, `provider`, `producer_type` restricted to `RUNTIME_EVIDENCE_PRODUCER`, `submitted_evidence_class`, `certification_state` `UNCERTIFIED`/`CERTIFIED`/`REVOKED`, `certified_evidence_families_json`, `status` `ACTIVE`/`INACTIVE`/`REVOKED`); `ai_runtime_source_configurations` (`source_id` PK, `source_kind` `PROVIDER_CONNECTOR`/`TELEMETRY_ADAPTER`, `required_for_program_gate` — seeded with `AZURE_FOUNDRY_RUNTIME` and `COPILOT_STUDIO_RUNTIME`, both `PROVIDER_CONNECTOR`/`required_for_program_gate=true`, read by `AiGridRuntimeTelemetryReadinessService` instead of a hardcoded provider list); `ai_runtime_quota_windows` (per tenant/source rolling window — accepted/rejected event and byte counts, `quota_state` `AVAILABLE`/`SOFT_LIMIT`/`EXHAUSTED`); `ai_runtime_ingestion_receipts` (per-batch admission outcome — `status` `ACCEPTED`/`PROCESSING`/`COMPLETED`/`REJECTED`/`FAILED`, accepted/duplicate/quarantined counts, `reason_code`, linked `ingestion_job_id`, read back via `GET /api/ai-security/runtime-ingestion/receipts/{receiptId}`). All four are RLS-forced with a `tenant_isolation` policy. `ai_grid_budget_config` gains `runtime_quota_window_seconds`/`rolling_runtime_event_limit`/`rolling_runtime_byte_limit`. `findings.finding_kind` widens to add `AI_RUNTIME` — the runtime evaluator's own finding kind, distinct from `AI_POSTURE`/`AI_EXPOSURE`. `ai_grid_assessments`' uniqueness moves from `(tenant_id, run_id, policy_id, subject_type)` to `uq_ai_grid_assessments_evaluation_identity` `(tenant_id, run_id, policy_id, subject_type, subject_id, fingerprint)` so a runtime evaluation's per-execution/per-group subjects can each hold their own row.

**Budget, retention, and evidence trust** (`V50`, `V54`, `V55`, `V59`): `ai_grid_budget_config` (daily scan/API-call/byte/processing limits, seeded OBSERVE mode), `ai_grid_scan_cadence_rules`, `ai_grid_budget_admissions`/`_alerts` (`V54` adds environment/criticality scope), `ai_grid_retention_policies` (seeded HOT/ARCHIVE/RESTRICTED_EVIDENCE classes), `ai_grid_evidence_holds`, `ai_grid_retention_decisions`, `ai_grid_retention_purge_audit` (`V55` — durable audit surviving snapshot-body deletion). `ai_grid_host_context_facts` (`V56`; `producer_id` added `V59`) holds CIEM/DSPM/ASM/runtime evidence from trusted external producers, ingested via `AiGridEvidenceIngestionController` (`ROLE_SERVICE_ACCOUNT` only) — and, since the AWS connector-maturity work, the `activity.*` facts from the `SCOUT_AWS_ACTIVITY` producer. That activity query design is historical: current activity producers/fact families and customer activity reads are retired; historical activity cannot affect exposure priority. Static host-context evidence remains under producer/principal, confidence, freshness and tenant controls.

**R2 exposure correlation** (`V56`, `V57`): `ai_grid_exposure_paths`/`_observations`/`_associations`/`_dispositions` (cross-system exposure hypotheses promoted to "validated" only on exact, freshness-checked facts; disposition = accept/false-positive), `ai_grid_exposure_executions` (binds a correlation result to the exact material/epoch that produced it, for deterministic replay verification).

### Platform schema tables (pre-reset provenance: `V47`–`V73`)

Governance-only — no tenant data. `platform.ai_grid_policy_distribution` (`V67` provenance; rollout stage GA/canary/paused/retired, canary tenant list, pinned version) is the sole policy-distribution control. `ai_grid_technology_versions`, `ai_grid_fact_definitions`, `ai_grid_policy_versions` (`V50`, `V51`, `V70` provenance; the immutable policy package catalog — lifecycle state, `native_kinds_json`/`scope_resolution`, `parameter_definitions_json`) and `ai_grid_correlation_versions`/`_correlation_precision_reviews` hold canonical correlation templates. Release/certification governance uses `ai_grid_answer_key_environments`/`_cases`/`_runs`/`_results`, precision-review tables, release decisions, gate evidence, and immutable release manifest items. `ai_grid_policy_candidates` is the RICE-style intake backlog for future policy authoring. The one-time AI Grid reset log/service is not present in the clean-start baseline.

**Historical pre-reset platform V2 framework contract (now reset V1):** `platform.ai_grid_frameworks` and `platform.ai_grid_framework_controls` are the authoritative registry for OWASP GenAI LLM Top 10 2026, OWASP Agentic Top 10 2026, and CSA AICM 1.1 reporting. `platform.ai_grid_runtime_field_definitions` is the allowlist of typed execution/event columns that runtime predicates may reference; diagnostic/extension JSON is intentionally absent. The immutable SQL function `platform.ai_grid_policy_visible_to_tenant(available, rollout_stage, canary_ids, tenant_id)` centralizes the GA or tenant-listed CANARY/DEV visibility rule used by catalog and coverage queries.

**Historical pre-reset platform V3 runtime evaluation contract (deferred):** widens `ai_grid_policy_versions.evaluation_mode` to add `RUNTIME_FACTS`, `RUNTIME_SEQUENCE`, `RUNTIME_AGGREGATE`, and the bounded meta-mode `RUNTIME_COVERAGE`; widens `evaluation_subject` to add `EXECUTION`. Adds `physical_column` (boolean) to `ai_grid_runtime_field_definitions` and ~19 new `execution.*`/`event.*` field rows sourced from the tenant V3 columns above (three — `execution.version_approval_state`, `execution.version_lifecycle_state`, `event.component_approval_state` — are derived/non-physical). Inserts five new `ai_grid_resource_family_definitions` rows (`RUNTIME_EXECUTIONS`, `RUNTIME_EVENT_DECISIONS`, `RUNTIME_COMPONENT_USE`, `RUNTIME_DATA_HANDLING`, `RUNTIME_AUTONOMY_CONTROLS`) and matching `ai_grid_capability_definitions` rows (`RUNTIME_EXECUTION_METADATA`, `RUNTIME_VERSION_CORRELATION`, `RUNTIME_EVENT_DECISIONS`, `RUNTIME_ACTION_OUTCOMES`, `RUNTIME_TOOL_CORRELATION`, `RUNTIME_DATA_CLASSIFICATION`, plus four `optional=true` wave-2C capabilities — `RUNTIME_HANDOFF_EVIDENCE`, `RUNTIME_MEMORY_EVIDENCE`, `RUNTIME_PROVENANCE_EVIDENCE`, `RUNTIME_CONTAINMENT_EVIDENCE` — that stay unsupported pending an authoritative evidence source). These rows are what let an unsupported runtime evidence family report a named `NOT_ASSESSED` capability gap instead of silently passing.

### Known anomalies

Historical pre-reset guard/version mismatches no longer describe the current catalog. Current migration files retain their guard comments; packaged heads are platform V8 / tenant V6. The required tenant floor/maximum is V6–V6. Historical runtime tables/vocabularies are retained, but runtime producers, activity facts, ingestion/readiness/receipt reads and evaluation remain excluded; retained schema is not collection permission.

The last observed deployed backend predates the reset. Actual deployed histories remain unverified; fresh local V5→V6 results establish only that reset-history transition. Preserve applied files/history and rehearse a separately authorized data-preserving transition and rollback/roll-forward on a representative clone; see [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

## Supplemental Table Reference

Tables below were added after the sections above were written and are documented from the V1/V2 baseline DDL. Column lists show type, `NOT NULL` (`*`) and non-trivial defaults; all tenant-schema tables carry `tenant_id` with the standard RLS posture. Constraint details (CHECK enums, indexes) live in the migration files.

### Vulnerability advisory sources

**`advisory_equivalences`** (`platform` schema) — Cross-source equivalence map linking one NVD CVE to its GHSA/OSV ids and CWE ids, with a confidence score, reason, and optional human verification.

- Columns: `id` uuid*, `nvd_cve_id` varchar(50), `ghsa_id` varchar(50), `osv_id` varchar(50), `cwe_ids` jsonb, `equivalence_confidence` numeric(3,2), `equivalence_reason` varchar(100), `discovered_at` timestamp, `verified_at` timestamp, `verified_by_user_id` uuid, `notes` text, `created_at` timestamp, `updated_at` timestamp
- PK: `id`

**`advisory_source_registrations`** (`public` schema) — Registry of enabled advisory feed sources (`source_type`, JSON config, sync interval, last/next sync times).

- Columns: `id` uuid*, `source_type` varchar(50)*, `is_enabled` boolean = true, `source_config` jsonb, `sync_interval_hours` integer = 1, `last_sync_at` timestamp, `next_sync_at` timestamp, `created_at` timestamp, `updated_at` timestamp
- PK: `id`
- Unique: `source_type`

**`github_security_advisories`** (`public` schema) — Global GHSA advisory cache: package/ecosystem, affected and fixed version ranges, severity/CVSS, withdrawn and applicability flags, `sync_hash` for change detection.

- Columns: `id` uuid*, `ghsa_id` varchar(20)*, `cve_id` varchar(20), `title` varchar(500)*, `description` text, `severity` varchar(20)*, `cvss_score` numeric(3,1), `cvss_vector` varchar(100), `ecosystem` varchar(50)*, `package_name` varchar(255)*, `affected_versions_start` varchar(50), `affected_versions_end` varchar(50), `affected_versions_pattern` varchar(500), `fixed_versions` text, `github_advisory_url` varchar(500), `published_at` timestamp*, `updated_at` timestamp, `withdrawn_at` timestamp, `first_synced_at` timestamp, `last_synced_at` timestamp, `is_applicable` boolean = true, `sync_hash` varchar(64), `created_at` timestamp
- PK: `id`
- Unique: `ghsa_id`

**`github_advisory_sync_state`** (`public` schema) — Per-`sync_type` GHSA sync cursor and health: last full/incremental sync, cursor, counts, duration, consecutive errors.

- Columns: `id` uuid*, `sync_type` varchar(50), `status` varchar(20) = 'IDLE', `last_full_sync_at` timestamp, `last_incremental_sync_at` timestamp, `next_scheduled_sync_at` timestamp, `last_cursor` varchar(1000), `sync_complete` boolean = false, `advisories_synced` integer = 0, `advisories_newly_found` integer = 0, `advisories_updated` integer = 0, `sync_duration_ms` integer, `last_error` varchar(1000), `consecutive_errors` integer = 0, `created_at` timestamp, `updated_at` timestamp
- PK: `id`
- Unique: `sync_type`

**`osv_advisories`** (`platform` schema) — Global OSV advisory store: ecosystem/package, CVSS v3, affected ranges, references, raw `osv_data`, withdrawn/synced timestamps.

- Columns: `id` uuid*, `osv_id` varchar(50)*, `ecosystem` varchar(50)*, `package_name` varchar(500)*, `summary` text*, `details` text, `severity` varchar(20), `cvss_v3_score` numeric(3,1), `cvss_v3_vector` varchar(100), `affected_ranges` jsonb*, `published_at` timestamp, `modified_at` timestamp, `withdrawn_at` timestamp, `reference_data` jsonb, `osv_data` jsonb*, `source` varchar(50)*, `created_at` timestamp, `updated_at` timestamp, `synced_at` timestamp
- PK: `id`
- Unique: `osv_id`

**`tenant_ghsa_integrations`** (tenant schema) — Per-tenant GHSA switch: enabled/disabled times and auto-create-finding, auto-correlate, and low-severity options.

- Columns: `id` uuid*, `tenant_id` uuid*, `is_enabled` boolean = false, `enabled_at` timestamp, `disabled_at` timestamp, `auto_create_findings` boolean = true, `auto_correlate_components` boolean = true, `create_finding_for_low_severity` boolean = false, `reason_enabled` varchar(255), `enabled_by_user_id` uuid, `created_at` timestamp, `updated_at` timestamp
- PK: `id`
- Unique: `tenant_id`
- FK: `tenant_id` → `tenants.id`

**`tenant_ghsa_subscriptions`** (tenant schema) — Which GHSA advisories a tenant follows (`subscription_reason`, active flag, subscribe/unsubscribe times).

- Columns: `id` uuid*, `tenant_id` uuid*, `advisory_id` uuid*, `subscription_reason` varchar(100), `is_active` boolean = true, `subscribed_at` timestamp, `unsubscribed_at` timestamp, `created_at` timestamp
- PK: `id`
- Unique: `tenant_id, advisory_id`
- FK: `tenant_id` → `tenants.id`

**`tenant_github_repository_component_advisories`** (tenant schema) — Per-tenant match of a GitHub SBOM source component to an advisory: affected flag, installed version vulnerable-range result, linked finding, recommended fixed version, alert timestamps.

- Columns: `id` uuid*, `tenant_id` uuid*, `github_source_id` uuid*, `component_id` varchar(500)*, `advisory_id` uuid*, `is_affected` boolean*, `installed_version` varchar(50)*, `is_installed_version_vulnerable` boolean*, `vulnerable_range_reason` varchar(255), `finding_id` uuid, `finding_kind` varchar(50), `recommended_fixed_version` varchar(50), `upgrade_available` boolean, `discovered_at` timestamp, `first_alert_sent_at` timestamp, `last_alert_sent_at` timestamp, `created_at` timestamp, `updated_at` timestamp
- PK: `id`
- FK: `github_source_id` → `github_sbom_sources.id`, `finding_id` → `findings.id`, `tenant_id` → `tenants.id`

### Findings, investigations, and queues

**`investigation_runbook`** (tenant schema) — Per-CVE analyst runbook state: task states, agent suggestions, false-positive overrides, log entries, lead analyst, agent confidence and run metadata.

- Columns: `id` uuid*, `tenant_id` uuid*, `cve_external_id` varchar(50)*, `task_states` jsonb* = '[]', `agent_suggestions` jsonb* = '{}', `fp_overrides` jsonb* = '[]', `log_entries` jsonb* = '[]', `lead_analyst` varchar(100), `agent_confidence` jsonb, `agent_run_meta` jsonb, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, cve_external_id`
- FK: `tenant_id` → `tenants.id`

**`personal_finding_queues`** (`platform` schema) — Saved personal findings queues per user (`queue_key`, title, `filter_json`, display order, default flag). Platform-schema table keyed by `tenant_id`.

- Columns: `id` uuid*, `tenant_id` uuid*, `owner_user_id` uuid*, `queue_key` varchar(120)*, `title` varchar(160)*, `description` varchar(500), `filter_json` text*, `display_order` integer*, `is_default` boolean*, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, owner_user_id, queue_key`; `tenant_id, owner_user_id, title`; `tenant_id, owner_user_id`
- FK: `owner_user_id` → `app_users.id`, `tenant_id` → `tenants.id`

**`finding_queue_preferences`** (`platform` schema) — Per-user default queue reference for the findings page.

- Columns: `id` uuid*, `tenant_id` uuid*, `owner_user_id` uuid*, `default_queue_ref` varchar(160)*, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, owner_user_id`
- FK: `owner_user_id` → `app_users.id`, `tenant_id` → `tenants.id`

### Tenancy, plans, and entitlements

**`tenant_user_invites`** (`platform` schema) — Current tenant invitation authority uses unique SHA-256 `token_hash`, clears the legacy raw `token`, restricts role assignment via `TenantRolePolicy`, and serializes token acceptance/rotation. Platform V2 applies digest storage; platform V3 adds separate delivery intent. The following column list records the V1 snapshot, not the current bearer-storage contract.

- Columns: `id` uuid*, `tenant_id` uuid*, `invited_by` uuid, `email` varchar(320)*, `display_name` varchar(255), `external_subject` varchar(320)*, `role` varchar(64)*, `status` varchar(32)*, `token` varchar(96)*, `provider_message_id` varchar(255), `delivery_detail` varchar(500), `expires_at` timestamptz*, `accepted_at` timestamptz, `last_sent_at` timestamptz, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `token`
- FK: `invited_by` → `app_users.id`, `tenant_id` → `tenants.id`

**`plan_definitions`** (`platform` schema) — Catalog of plans (`code`, display name, status).

- Columns: `code` varchar(64)*, `display_name` varchar(120)*, `status` varchar(32)*, `description` varchar(500), `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `code`

**`entitlement_definitions`** (`platform` schema) — Catalog of entitlement keys (e.g. `ai.security`) with category and value type.

- Columns: `key` varchar(128)*, `category` varchar(64)*, `value_type` varchar(32)*, `description` varchar(500), `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `key`

**`plan_entitlements`** (`platform` schema) — Which entitlements each plan grants, with an `enabled` flag and optional `config_json`.

- Columns: `plan_code` varchar(64)*, `entitlement_key` varchar(128)*, `enabled` boolean*, `config_json` jsonb, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `plan_code, entitlement_key`
- FK: `entitlement_key` → `entitlement_definitions.key`, `plan_code` → `plan_definitions.code`

### CBOM (cryptographic BOM) projections

**`cbom_components`** (tenant schema) — Cryptographic components from CBOM documents per asset: algorithm/primitive, key size, curve, protocol, certificate fields, risk score, active flag, stable `component_fingerprint`.

- Columns: `id` uuid*, `tenant_id` uuid*, `asset_id` uuid, `source_bom_id` uuid*, `bom_ref` text, `component_fingerprint` text*, `name` text*, `description` text, `asset_type` varchar(60)*, `component_type` text, `primitive` text, `parameter_set_identifier` text, `key_size` integer, `curve` text, `padding` text, `protocol_version` text, `state` text, `format` text, `storage_location` text, `transmission` text, `sensitivity` text, `used_in` text, `not_before` date, `not_after` date, `issuer` text, `subject` text, `serial_number` text, `signature_algorithm` text, `key_usage` text, `risk_score` numeric(4,2), `active` boolean* = true, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, source_bom_id, component_fingerprint`
- FK: `asset_id` → `assets.id`, `source_bom_id` → `bom_ingestion_records.id`, `tenant_id` → `tenants.id`

**`cbom_risk_findings`** (tenant schema) — Rule-driven crypto risk findings per CBOM component (`rule_id`/`rule_version`, `finding_fingerprint`, risk class, severity, evidence, status, first/last seen, withdrawal).

- Columns: `id` uuid*, `tenant_id` uuid*, `cbom_component_id` uuid*, `rule_id` varchar(100)*, `rule_version` varchar(20)* = '1', `finding_fingerprint` text*, `risk_class` varchar(80)*, `severity` varchar(20)*, `title` text*, `detail` text, `evidence` jsonb, `recommendation` text, `status` varchar(20)* = 'OPEN', `first_seen_at` timestamptz*, `last_seen_at` timestamptz*, `resolved_at` timestamptz, `created_at` timestamptz*, `evidence_state` varchar(24)*, `withdrawn_at` timestamptz
- PK: `id`
- Unique: `tenant_id, cbom_component_id, finding_fingerprint`
- FK: `cbom_component_id` → `cbom_components.id`, `tenant_id` → `tenants.id`

**`cbom_posture_summary`** (tenant schema) — Per-asset CBOM rollup: component and severity counts, quantum-vulnerable/weak-algorithm/expiring-cert counts, posture score.

- Columns: `id` uuid*, `tenant_id` uuid*, `asset_id` uuid*, `last_source_bom_id` uuid, `total_components` integer* = 0, `critical_findings` integer* = 0, `high_findings` integer* = 0, `medium_findings` integer* = 0, `low_findings` integer* = 0, `info_findings` integer* = 0, `accepted_findings` integer* = 0, `quantum_vulnerable` integer* = 0, `weak_algorithms` integer* = 0, `expiring_certs` integer* = 0, `posture_score` numeric(4,2), `last_evaluated_at` timestamptz
- PK: `id`
- Unique: `tenant_id, asset_id`
- FK: `asset_id` → `assets.id`, `last_source_bom_id` → `bom_ingestion_records.id`, `tenant_id` → `tenants.id`

### AI Security connectors and artifact integrity

**`ai_security_connector_feature_flags`** (tenant schema) — Per-tenant connector feature flags with a `kill_switch`.

- Columns: `tenant_id` uuid*, `feature_key` varchar(128)*, `enabled` boolean* = false, `kill_switch` boolean* = false, `updated_at` timestamptz*, `updated_by` varchar(255), `created_at` timestamptz*
- PK: `tenant_id, feature_key`
- FK: `tenant_id` → `tenants.id`

**`ai_security_copilot_studio_configs`** (tenant schema) — Microsoft Copilot Studio connector config: organization URL, credential profile, discovery/execution toggles, kill switch, schedule cron, allowed Dataverse hosts.

- Columns: `id` uuid*, `tenant_id` uuid*, `organization_url` varchar(512)*, `credential_profile_id` uuid*, `discovery_enabled` boolean* = false, `execution_enabled` boolean* = false, `kill_switch` boolean* = false, `schedule_cron` varchar(128)*, `created_at` timestamptz*, `updated_at` timestamptz*, `allowed_dataverse_hosts_json` jsonb* = '[]'
- PK: `id`
- Unique: `tenant_id, organization_url`
- FK: `credential_profile_id` → `ai_security_azure_credential_profiles.id`, `tenant_id` → `tenants.id`

**`ai_security_artifact_attribute_ownership`** (tenant schema) — Records which scan scope last observed each artifact attribute (`scope_key`, `attribute_key`), so partial-scope scans do not clobber attributes.

- Columns: `tenant_id` uuid*, `artifact_id` uuid*, `scope_key` varchar(255)*, `attribute_key` varchar(255)*, `observed_at` timestamptz*
- PK: `tenant_id, artifact_id, scope_key, attribute_key`
- FK: `artifact_id` → `ai_security_artifacts.id`

**`ai_security_artifact_digest_baselines`** (tenant schema) — Approved digest baselines per artifact and digest kind (algorithm, key version, approval status, approver, revocation).

- Columns: `id` uuid*, `tenant_id` uuid*, `artifact_id` uuid*, `digest_kind` varchar(64)*, `algorithm` varchar(64)*, `key_version` varchar(64)*, `approved_digest` text*, `approval_status` varchar(32)*, `approved_by` varchar(255), `approved_at` timestamptz, `revoked_by` varchar(255), `revoked_at` timestamptz, `source_run_id` uuid, `created_at` timestamptz*, `updated_at` timestamptz*, `approval_reference_verified` boolean* = false
- PK: `id`
- Unique: `tenant_id, artifact_id, digest_kind`
- FK: `artifact_id` → `ai_security_artifacts.id`, `tenant_id` → `tenants.id`

**`ai_security_artifact_digest_observations`** (tenant schema) — Latest observed digest per artifact/kind and its comparison outcome against the baseline.

- Columns: `tenant_id` uuid*, `artifact_id` uuid*, `digest_kind` varchar(64)*, `algorithm` varchar(64)*, `key_version` varchar(64)*, `observed_digest` text*, `comparison_outcome` varchar(64)*, `source_run_id` uuid*, `observed_at` timestamptz*
- PK: `tenant_id, artifact_id, digest_kind`
- FK: `artifact_id` → `ai_security_artifacts.id`, `tenant_id` → `tenants.id`

**`ai_security_baseline_history`** (tenant schema) — Append-only audit of baseline approve/revoke actions (actor, source run, approved value).

- Columns: `id` uuid*, `tenant_id` uuid*, `artifact_id` uuid*, `digest_kind` varchar(64)*, `action` varchar(32)*, `actor` varchar(255), `source_run_id` uuid, `algorithm` varchar(64), `key_version` varchar(64), `approved_value` text, `approval_reference_verified` boolean* = false, `recorded_at` timestamptz*
- PK: `id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `tenant_id` → `tenants.id`

### AI agent runtime storage (deferred)

**`ai_agent_deployment_settings`** (tenant schema) — Per-tenant deployment-freshness window in hours (1–8760).

- Columns: `tenant_id` uuid*, `freshness_hours` integer* = 24
- PK: `tenant_id`

**`ai_agent_execution_cursors`** (tenant schema) — Per connector/source/scope collection cursor with lookback and overlap days.

- Columns: `id` uuid*, `tenant_id` uuid*, `connector_id` uuid*, `source` varchar(64)*, `scope_key` varchar(512)*, `provider_timestamp` timestamptz, `provider_stable_digest` varchar(512), `lookback_days` integer* = 30, `overlap_days` integer* = 3, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, connector_id, source, scope_key`
- FK: `tenant_id` → `tenants.id`

**`ai_agent_execution_participants`** (tenant schema) — Artifacts (MODEL/TOOL/PROMPT/COMPONENT) that participated in an execution. Runtime collection is out of scope in this release, so these runtime tables hold no evidence.

- Columns: `id` uuid*, `tenant_id` uuid*, `execution_id` uuid*, `artifact_id` uuid*, `participant_role` varchar(32)*, `evidence_time` timestamptz*, `created_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, execution_id, artifact_id, participant_role`
- FK: `artifact_id` → `ai_security_artifacts.id`, `execution_id` → `ai_agent_executions.id`, `tenant_id` → `tenants.id`

### AI Grid: coverage, snapshots, and budgets

**`ai_grid_snapshot_manifests`** (tenant schema) — Per-run manifest rows tying an artifact and scope to an immutable snapshot body (`body_id`, schema version, connector config).

- Columns: `id` uuid*, `tenant_id` uuid*, `run_id` uuid*, `artifact_id` uuid*, `scope_key` varchar(512)*, `body_id` uuid*, `schema_version` varchar(32)*, `observed_at` timestamptz*, `created_at` timestamptz*, `connector_config_id` uuid
- PK: `id`
- Unique: `tenant_id, run_id, artifact_id, scope_key`
- FK: `artifact_id` → `ai_security_artifacts.id`, `body_id` → `ai_grid_snapshot_bodies.id`, `connector_config_id` → `ai_security_connector_configs.id`, `tenant_id` → `tenants.id`

**`ai_grid_capability_manifests`** (tenant schema) — Per-run registered connector capabilities with required scope keys; `REGISTERED` then `FINALIZED`.

- Columns: `id` uuid*, `tenant_id` uuid*, `run_id` uuid*, `provider` varchar(32)*, `connector_id` uuid*, `account_id` varchar(255)*, `region` varchar(128)*, `capability_id` varchar(128)*, `required_scope_keys_json` jsonb*, `status` varchar(32)*, `created_at` timestamptz*, `finalized_at` timestamptz
- PK: `id`
- Unique: `tenant_id, run_id, provider, account_id, region, capability_id`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_capability_observations`** (tenant schema) — Observed capability status per run/provider/account/region/resource family, with reason code, expiry, and evidence scopes.

- Columns: `id` uuid*, `tenant_id` uuid*, `run_id` uuid*, `provider` varchar(32)*, `capability_id` varchar(128)*, `connector` varchar(128)*, `account_id` varchar(255)*, `region` varchar(128)*, `resource_family` varchar(128)*, `connector_version` varchar(64), `observed_at` timestamptz*, `expires_at` timestamptz, `status` varchar(32)*, `detail` text, `reason_code` varchar(64), `evidence_scopes_json` jsonb* = '[]'
- PK: `id`
- Unique: `tenant_id, run_id, provider, capability_id, account_id, region`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_current_coverage_artifacts`** (tenant schema) — Current-coverage epoch projection: one row per artifact visible in the latest coverage epoch, with provider/account/region, type, technology, environment, owner.

- Columns: `tenant_id` uuid*, `epoch_id` uuid*, `artifact_id` uuid*, `source_run_id` uuid*, `snapshot_manifest_id` uuid*, `provider` varchar(32)*, `account_id` varchar(64)*, `region` varchar(64)*, `resource_family` varchar(128)*, `artifact_type` varchar(64)*, `native_kind` varchar(128)*, `technology_id` varchar(128)*, `environment` varchar(64)*, `owner_name` varchar(255)* = 'UNOWNED', `observed_at` timestamptz*
- PK: `tenant_id, artifact_id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `snapshot_manifest_id` → `ai_grid_snapshot_manifests.id`, `tenant_id` → `tenants.id`

**`ai_grid_run_scope_metrics`** (tenant schema) — Per-run, per-scope processing duration in ms.

- Columns: `id` uuid*, `tenant_id` uuid*, `run_id` uuid*, `scope_key` varchar(512)*, `processing_duration_ms` bigint*, `recorded_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, run_id, scope_key`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_budget_alerts`** (tenant schema) — Budget threshold alerts (`WARNING`/`EXCEEDED`) with observed vs limit values and `OPEN`/`ACKNOWLEDGED`/`RESOLVED` status.

- Columns: `id` uuid*, `tenant_id` uuid*, `run_id` uuid, `metric` varchar(64)*, `level` varchar(32)*, `observed_value` bigint*, `limit_value` bigint*, `status` varchar(32)* = 'OPEN', `first_observed_at` timestamptz*, `last_observed_at` timestamptz*, `acknowledged_by` varchar(255), `acknowledged_at` timestamptz
- PK: `id`
- Unique: `tenant_id, metric`
- FK: `tenant_id` → `tenants.id`

### AI Grid: systems and exposure correlation

**`ai_grid_system_revisions`** (tenant schema) — Immutable revisions of an AI system's membership (`membership_hash`, source, rationale, validity window, coverage epoch).

- Columns: `id` uuid*, `tenant_id` uuid*, `system_id` uuid*, `revision` integer*, `membership_hash` varchar(64)*, `source` varchar(32)*, `rationale` text*, `created_at` timestamptz*, `run_id` uuid, `valid_from` timestamptz*, `valid_until` timestamptz, `coverage_epoch_id` uuid
- PK: `id`
- Unique: `tenant_id, system_id, revision`
- FK: `system_id` → `ai_grid_systems.id`, `tenant_id` → `tenants.id`

**`ai_grid_system_memberships`** (tenant schema) — Artifact membership in a system revision with state, confidence method/value, and evidence.

- Columns: `id` uuid*, `tenant_id` uuid*, `system_revision_id` uuid*, `artifact_id` uuid*, `membership_state` varchar(32)*, `confidence_method` varchar(128)*, `confidence_method_version` varchar(32)*, `confidence` double precision*, `evidence_json` jsonb* = '{}', `valid_from` timestamptz*, `valid_until` timestamptz, `decided_by` varchar(255), `decided_at` timestamptz
- PK: `id`
- Unique: `tenant_id, system_revision_id, artifact_id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `system_revision_id` → `ai_grid_system_revisions.id`, `tenant_id` → `tenants.id`

**`ai_grid_system_membership_overrides`** (tenant schema) — Analyst membership decisions per system/artifact with reason and actor.

- Columns: `tenant_id` uuid*, `system_id` uuid*, `artifact_id` uuid*, `decision` varchar(16)*, `reason` text*, `actor` varchar(255)*, `decided_at` timestamptz*
- PK: `tenant_id, system_id, artifact_id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `system_id` → `ai_grid_systems.id`, `tenant_id` → `tenants.id`

**`ai_grid_system_lineage_participants`** (tenant schema) — System revisions participating in a lineage event, with role.

- Columns: `id` uuid*, `tenant_id` uuid*, `event_id` uuid*, `system_id` uuid*, `system_revision_id` uuid, `participant_role` varchar(16)*
- PK: `id`
- Unique: `tenant_id, event_id, system_id, participant_role`
- FK: `event_id` → `ai_grid_system_lineage_events.id`, `system_id` → `ai_grid_systems.id`, `system_revision_id` → `ai_grid_system_revisions.id`, `tenant_id` → `tenants.id`

**`ai_grid_exposure_observations`** (tenant schema) — Observations of an exposure path per run: state, entry artifact, system revision, path and evidence JSON, temporal validity, confidence, correlation digest.

- Columns: `id` uuid*, `tenant_id` uuid*, `exposure_path_id` uuid*, `run_id` uuid*, `state` varchar(32)*, `entry_artifact_id` uuid, `system_id` uuid, `system_revision_id` uuid, `path_json` jsonb*, `evidence_json` jsonb*, `temporal_valid_from` timestamptz*, `temporal_valid_until` timestamptz, `confidence` double precision, `observed_at` timestamptz*, `coverage_epoch_id` uuid, `correlation_material_digest` varchar(64)
- PK: `id`
- FK: `entry_artifact_id` → `ai_security_artifacts.id`, `exposure_path_id` → `ai_grid_exposure_paths.id`, `system_id` → `ai_grid_systems.id`, `system_revision_id` → `ai_grid_system_revisions.id`, `tenant_id` → `tenants.id`

**`ai_grid_exposure_associations`** (tenant schema) — Systems/artifacts associated with an exposure path, with role.

- Columns: `id` uuid*, `tenant_id` uuid*, `exposure_path_id` uuid*, `system_id` uuid, `system_revision_id` uuid, `artifact_id` uuid, `association_role` varchar(32)*
- PK: `id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `exposure_path_id` → `ai_grid_exposure_paths.id`, `system_id` → `ai_grid_systems.id`, `system_revision_id` → `ai_grid_system_revisions.id`, `tenant_id` → `tenants.id`

**`ai_grid_exposure_dispositions`** (tenant schema) — Analyst dispositions on an exposure path (accept/false-positive) with reason and actor.

- Columns: `id` uuid*, `tenant_id` uuid*, `exposure_path_id` uuid*, `disposition` varchar(32)*, `reason` text*, `actor` varchar(255)*, `created_at` timestamptz*
- PK: `id`
- FK: `exposure_path_id` → `ai_grid_exposure_paths.id`, `tenant_id` → `tenants.id`

### AI Grid: tenant policy configuration

**`ai_grid_policy_scopes`** (tenant schema) — Per-tenant policy scope: mode, condition logic, and `conditions_json`.

- Columns: `policy_id` varchar(128)*, `tenant_id` uuid*, `mode` varchar(32)* = 'ALL', `condition_logic` varchar(8)* = 'AND', `conditions_json` jsonb* = '[]', `updated_by` varchar(255)*, `updated_at` timestamptz*
- PK: `policy_id`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_policy_parameters`** (tenant schema) — Per-tenant policy parameter overrides (`parameters_json`).

- Columns: `policy_id` varchar(128)*, `tenant_id` uuid*, `parameters_json` jsonb* = '{}', `updated_by` varchar(255)*, `updated_at` timestamptz*
- PK: `policy_id`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_policy_artifact_overrides`** (tenant schema) — Per-artifact include/exclude override for a policy, with reason.

- Columns: `id` uuid*, `tenant_id` uuid*, `policy_id` varchar(128)*, `artifact_id` uuid*, `override` varchar(16)*, `reason` text, `created_by` varchar(255)*, `created_at` timestamptz*, `updated_at` timestamptz*
- PK: `id`
- Unique: `tenant_id, policy_id, artifact_id`
- FK: `artifact_id` → `ai_security_artifacts.id`, `tenant_id` → `tenants.id`

**`ai_grid_policy_selection_history`** (tenant schema) — Audit of tenant policy enable/disable selection changes (previous, new, actor, reason).

- Columns: `id` uuid*, `tenant_id` uuid*, `policy_id` varchar(128)*, `previous_selection` varchar(32), `selection` varchar(32)*, `actor` varchar(255)*, `reason` text, `changed_at` timestamptz*
- PK: `id`
- FK: `tenant_id` → `tenants.id`

### AI Grid: platform policy rollout and deprecation

**`ai_grid_policy_rollouts`** (`platform` schema) — Platform rollout of a policy version (previous/new version, package digest, distribution snapshot, status, release decision link).

- Columns: `id` uuid*, `release_id` varchar(128)*, `release_type` varchar(64)*, `policy_id` varchar(128)*, `previous_version` varchar(32), `new_version` varchar(32)*, `package_digest` varchar(64)*, `distribution_snapshot_json` jsonb*, `status` varchar(32)* = 'PENDING', `created_at` timestamptz*, `started_at` timestamptz, `completed_at` timestamptz, `approved_package_digest` varchar(64), `release_decision_id` uuid
- PK: `id`
- Unique: `release_id, policy_id, new_version`

**`ai_grid_policy_rollout_tasks`** (`platform` schema) — Per-tenant rollout work items drained by `AiGridPolicyRolloutService` (status, attempts, retry time, source/assessment run ids).

- Columns: `id` uuid*, `rollout_id` uuid*, `tenant_id` uuid*, `status` varchar(32)* = 'PENDING', `attempts` integer* = 0, `next_retry_at` timestamptz, `source_snapshot_run_id` uuid, `assessment_run_id` uuid, `failure_detail` text, `created_at` timestamptz*, `started_at` timestamptz, `completed_at` timestamptz, `updated_at` timestamptz*
- PK: `id`
- Unique: `rollout_id, tenant_id`
- FK: `rollout_id` → `ai_grid_policy_rollouts.id`, `tenant_id` → `tenants.id`

**`ai_grid_policy_deprecations`** (`platform` schema) — Policy deprecation records with optional successor policy and idempotency key.

- Columns: `id` uuid*, `policy_id` varchar(128)*, `policy_version` varchar(32)*, `reason` text*, `successor_policy_id` varchar(128), `deprecated_by` varchar(255)*, `deprecated_at` timestamptz*, `idempotency_key` varchar(128)*
- PK: `id`
- Unique: `idempotency_key`; `policy_id, policy_version`

**`ai_grid_policy_deprecation_tasks`** (`platform` schema) — Per-tenant deprecation work items drained by `AiGridPolicyDeprecationService`.

- Columns: `id` uuid*, `deprecation_id` uuid*, `tenant_id` uuid*, `state` varchar(32)* = 'PENDING', `attempts` integer* = 0, `next_retry_at` timestamptz, `failure_detail` text, `created_at` timestamptz*, `started_at` timestamptz, `completed_at` timestamptz, `updated_at` timestamptz*
- PK: `id`
- Unique: `deprecation_id, tenant_id`
- FK: `deprecation_id` → `ai_grid_policy_deprecations.id`, `tenant_id` → `tenants.id`

**`ai_grid_policy_inactivation_tasks`** (`platform` schema) — Per-tenant policy inactivation work items with retry state.

- Columns: `id` uuid*, `policy_id` varchar(128)*, `tenant_id` uuid*, `reason` varchar(64)*, `status` varchar(32)* = 'PENDING', `attempts` integer* = 0, `next_retry_at` timestamptz, `failure_detail` text, `queued_at` timestamptz*, `started_at` timestamptz, `completed_at` timestamptz, `updated_at` timestamptz*
- PK: `id`
- Unique: `policy_id, tenant_id`
- FK: `tenant_id` → `tenants.id`

**`ai_grid_policy_replacements`** (`platform` schema) — Predecessor → successor policy mapping within a release family.

- Columns: `predecessor_policy_id` varchar(128)*, `successor_policy_id` varchar(128)*, `release_family` varchar(64)*, `created_at` timestamptz*
- PK: `predecessor_policy_id`
- Unique: `successor_policy_id`

**`ai_grid_policy_dev_deployments`** (`platform` schema) — Records of development deployments of a policy version to specific tenants.

- Columns: `id` uuid*, `policy_id` varchar(128)*, `policy_version` varchar(32)*, `target_tenant_ids_json` jsonb*, `test_note` text*, `deployed_by` varchar(255)*, `deployed_at` timestamptz*
- PK: `id`

### AI Grid: release governance and precision evidence

**`ai_grid_control_objectives`** (`platform` schema) — Control objective catalog (security and remediation intent, owner, lifecycle).

- Columns: `control_objective_id` varchar(128)*, `name` varchar(512)*, `security_intent` text*, `remediation_intent` text*, `owner` varchar(255)*, `lifecycle` varchar(32)*, `created_at` timestamptz*
- PK: `control_objective_id`

**`ai_grid_relationship_definitions`** (`platform` schema) — Catalog of allowed relationship types between artifacts (source, directionality, lifecycle).

- Columns: `relationship_type` varchar(128)*, `source` varchar(64)*, `directional` boolean* = true, `lifecycle` varchar(32)* = 'ACTIVE', `description` text*
- PK: `relationship_type`

**`ai_grid_policy_release_decisions`** (`platform` schema) — `APPROVED`/`BLOCKED` decisions for a policy version, referencing the answer-key run and precision review, with package digest and revocation fields.

- Columns: `id` uuid*, `policy_id` varchar(128)*, `policy_version` varchar(32)*, `decision` varchar(32)*, `answer_key_run_id` uuid, `precision_review_id` uuid, `reason` text*, `decided_by` varchar(255)*, `decided_at` timestamptz*, `package_digest` varchar(64), `revoked_at` timestamptz, `revoked_by` varchar(255), `revocation_reason` text, `approved_package_digest` varchar(128)
- PK: `id`
- FK: `answer_key_run_id` → `ai_grid_answer_key_runs.id`, `precision_review_id` → `ai_grid_precision_reviews.id`

**`ai_grid_policy_release_bindings`** (`platform` schema) — Binds an approval decision to an approved package digest, distribution snapshot, and target tenants; can be revoked.

- Columns: `id` uuid*, `approval_decision_id` uuid*, `policy_id` varchar(128)*, `policy_version` varchar(32)*, `approved_package_digest` varchar(128)*, `distribution_snapshot_json` jsonb*, `target_tenant_ids_json` jsonb*, `bound_by` varchar(255)*, `bound_at` timestamptz*, `state` varchar(32)* = 'ACTIVE', `revoked_at` timestamptz, `revoked_by` varchar(255), `revocation_reason` text
- PK: `id`
- Unique: `policy_id, policy_version, approved_package_digest`; `approval_decision_id`
- FK: `approval_decision_id` → `ai_grid_policy_release_decisions.id`

**`ai_grid_release_decisions`** (`platform` schema) — Release-level `APPROVED`/`BLOCKED` decisions with a gate snapshot.

- Columns: `id` uuid*, `release_id` varchar(32)*, `decision` varchar(16)*, `gate_snapshot_json` jsonb*, `reason` text*, `decided_by` varchar(255)*, `decided_at` timestamptz*
- PK: `id`

**`ai_grid_release_gate_evidence`** (`platform` schema) — Gate evidence per release and gate code (status, reference, validity, material digest).

- Columns: `id` uuid*, `release_id` varchar(32)*, `gate_code` varchar(96)*, `status` varchar(16)*, `evidence_reference` text*, `rationale` text*, `valid_until` timestamptz*, `recorded_by` varchar(255)*, `recorded_at` timestamptz*, `material_digest` varchar(64)
- PK: `id`

**`ai_grid_release_manifest_items`** (`platform` schema) — Policies/subjects included in a release manifest, by type, id, and version.

- Columns: `release_id` varchar(32)*, `subject_type` varchar(32)*, `subject_id` varchar(128)*, `subject_version` varchar(32)*, `created_at` timestamptz*
- PK: `release_id, subject_type, subject_id, subject_version`

**`ai_grid_phase_1_preview_release`** (`platform` schema) — Single-row-per-release-family preview state: manifest digest, policy count, internal tenant, approved cohort.

- Columns: `release_family` varchar(64)*, `manifest_digest` varchar(64)*, `total_policies` integer*, `state` varchar(32)* = 'PAUSED', `internal_tenant_id` uuid, `approved_cohort_json` jsonb* = '[]', `last_approved_cohort_json` jsonb* = '[]', `approved_by` varchar(255), `approved_at` timestamptz, `updated_at` timestamptz*
- PK: `release_family`

**`ai_grid_phase_1_preview_gate_evidence`** (`platform` schema) — Preview gate results keyed by `gate_key`.

- Columns: `gate_key` varchar(64)*, `status` varchar(16)* = 'PENDING', `evidence_ref` varchar(1024), `results_json` jsonb* = '{}', `recorded_by` varchar(255), `recorded_at` timestamptz*
- PK: `gate_key`

**`ai_grid_phase_1_release_gate_evidence`** (`platform` schema) — Phase-1 release gate evidence history.

- Columns: `id` uuid*, `gate_key` varchar(64)*, `status` varchar(16)*, `evidence_json` jsonb*, `recorded_by` varchar(255)*, `recorded_at` timestamptz*
- PK: `id`

**`ai_grid_answer_key_cases`** (`platform` schema) — Labeled expected outcomes (applicability, decision, finding) per policy version used to validate policies.

- Columns: `id` uuid*, `environment_id` uuid*, `case_key` varchar(160)*, `scenario` varchar(32)*, `policy_id` varchar(128), `policy_version` varchar(32), `expected_applicability` varchar(32), `expected_decision` varchar(32), `expected_finding` boolean, `expected_json` jsonb*, `label_version` varchar(32)*, `rationale` text*, `evidence_reference` text*, `created_by` varchar(255)*, `created_at` timestamptz*
- PK: `id`
- Unique: `environment_id, case_key`
- FK: `environment_id` → `ai_grid_answer_key_environments.id`

**`ai_grid_answer_key_runs`** (`platform` schema) — Answer-key validation runs (catalog digest, matched/total cases, PASS/FAIL, provenance `EXTERNAL_ATTESTATION` or `PLATFORM_RUN_BOUND`).

- Columns: `id` uuid*, `environment_id` uuid*, `catalog_digest` varchar(128)*, `status` varchar(32)*, `total_cases` integer*, `matched_cases` integer*, `executed_by` varchar(255)*, `started_at` timestamptz*, `completed_at` timestamptz*, `source_tenant_id` uuid, `source_run_id` uuid, `provenance_state` varchar(32)*
- PK: `id`
- FK: `environment_id` → `ai_grid_answer_key_environments.id`, `source_tenant_id` → `tenants.id`

**`ai_grid_answer_key_results`** (`platform` schema) — Per-case result of an answer-key run: observed JSON, matched flag, mismatch reason.

- Columns: `id` uuid*, `run_id` uuid*, `case_id` uuid*, `observed_json` jsonb*, `matched` boolean*, `mismatch_reason` text, `created_at` timestamptz*, `source_assessment_id` uuid, `source_decision_fingerprint` varchar(64)
- PK: `id`
- Unique: `run_id, case_id`
- FK: `case_id` → `ai_grid_answer_key_cases.id`, `run_id` → `ai_grid_answer_key_runs.id`

**`ai_grid_precision_reviews`** (`platform` schema) — Statistical precision reviews per policy version: sampling method, minimum sample size, true/false positives, precision and confidence bounds, bias review.

- Columns: `id` uuid*, `policy_id` varchar(128)*, `policy_version` varchar(32)*, `population_definition` text*, `sampling_method` text*, `minimum_sample_size` integer*, `confidence_level` double precision*, `precision_threshold` double precision* = 0.95, `material_change_digest` varchar(128)*, `bias_status` varchar(32)* = 'PENDING', `bias_rationale` text, `bias_reviewed_by` varchar(255), `status` varchar(32)* = 'DRAFT', `resolved_positive_samples` integer* = 0, `true_positives` integer* = 0, `false_positives` integer* = 0, `precision_value` double precision, `confidence_lower` double precision, `confidence_upper` double precision, `finalized_at` timestamptz, `created_by` varchar(255)*, `created_at` timestamptz*, `label_set_version` varchar(32)*, `answer_key_run_id` uuid
- PK: `id`
- Unique: `policy_id, policy_version, material_change_digest`
- FK: `answer_key_run_id` → `ai_grid_answer_key_runs.id`

**`ai_grid_precision_samples`** (`platform` schema) — Samples drawn for a precision review, with observed outcome and provenance.

- Columns: `id` uuid*, `review_id` uuid*, `sample_key` varchar(160)*, `provider` varchar(32)*, `resource_family` varchar(128)*, `severity` varchar(32)*, `observed_outcome` varchar(32)*, `predicted_finding` boolean*, `evidence_reference` text*, `created_at` timestamptz*, `source_tenant_id` uuid, `source_run_id` uuid, `source_assessment_id` uuid, `source_decision_fingerprint` varchar(128), `provenance_state` varchar(32)*
- PK: `id`
- Unique: `review_id, sample_key`; `review_id, source_assessment_id`
- FK: `review_id` → `ai_grid_precision_reviews.id`, `source_tenant_id` → `tenants.id`

**`ai_grid_precision_labels`** (`platform` schema) — Reviewer labels on precision samples.

- Columns: `id` uuid*, `sample_id` uuid*, `reviewer` varchar(255)*, `label` varchar(32)*, `label_version` varchar(32)*, `rationale` text*, `evidence_reference` text*, `created_at` timestamptz*
- PK: `id`
- Unique: `sample_id, reviewer`
- FK: `sample_id` → `ai_grid_precision_samples.id`

**`ai_grid_precision_adjudications`** (`platform` schema) — Final adjudicated label for a sample.

- Columns: `id` uuid*, `sample_id` uuid*, `final_label` varchar(32)*, `rationale` text*, `adjudicated_by` varchar(255)*, `created_at` timestamptz*
- PK: `id`
- Unique: `sample_id`
- FK: `sample_id` → `ai_grid_precision_samples.id`

**`ai_grid_correlation_precision_reviews`** (`platform` schema) — Precision reviews for correlation logic (sample size, accepted samples, precision vs threshold, reviewer).

- Columns: `id` uuid*, `correlation_id` varchar(128)*, `correlation_version` varchar(32)*, `material_digest` varchar(128)*, `sample_size` integer*, `accepted_samples` integer*, `precision_value` double precision*, `precision_threshold` double precision*, `status` varchar(32)*, `evidence_reference` varchar(1024)*, `reviewed_by` varchar(255)*, `reviewed_at` timestamptz*
- PK: `id`
- Unique: `correlation_id, correlation_version, material_digest`
- FK: `correlation_id, correlation_version` → `ai_grid_correlation_versions.correlation_id, version`


## Post-reset prerequisite storage and ownership

| Migration | Current addition / boundary |
|---|---|
| Platform V2 / tenant V3 | Tenant/demo invite digests and cleared raw bearers; existing history retained. Provider ciphertext uses versioned encryption/key IDs in the application, with explicit offline conversion/rekey tooling, never automatic key erasure. |
| Platform V3 | Owned sync/rollout/deprecation coordination and `platform.invitation_email_outbox`: encrypted immutable payload, token-version identity, claim/lease/attempt state, provider outcome and operator reconciliation provenance. |
| Platform V4 | Completed feed-sync watermarks keyed by deterministic scope; partial intervals cannot certify coverage. |
| Platform V5 | Unique scheduled-sync occurrence identity; source intent and occurrence admission are transactional. |
| Platform V6 | Accepts WAITING_FOR_ASSESSMENT and grants bounded legacy unleased-claim recovery grace; does not reset prior applied history. |
| Tenant V4 | Owned ingestion work, separate RLS-forced `campaign_email_outbox`, and operator reconciliation provenance. |
| Tenant V5 | Bounded retention sweep progress/cursor and resumable audit/hold/reference-aware work. |

Current authority is stored in `app_users`, global grants/compatibility state, tenant memberships/support references and the service-account registry. JWT human role claims do not create grants. Only the four customer roles are assignable as membership roles. Explicit tenant context precedes transactions; source effects/queue intent and final ownership checks share commit boundaries.

Invitation and campaign outboxes remain distinct scopes. Bounded attempts and the conservative 23-hour automatic replay cutoff preserve UNKNOWN outcomes for operator reconciliation; provider acceptance never certifies inbox delivery. Retention uses existing policies and holds; this inventory adds no period, storage allowance or deletion deadline. Destructive tenant purge and local archive file operations remain unavailable. See [delivery operations](backend.md#durable-work-scheduling-and-delivery), [cleanup matrix](<../Working Knowledge/AWS/PHASE_3_CLEANUP_MATRIX.md>) and [qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

## Migration Conventions

- File pattern: `V{next}__short_snake_case.sql` in `backend/src/main/resources/db/migration/postgres_reset/` (platform line) or `backend/src/main/resources/db/migration/tenant/` (per-tenant line — see below)
- **Never edit an already-applied migration file.** Add a new migration instead. (Before the one-time migration-history reset, a narrow exception existed for two files needing a schema-qualification fix — that fix is now simply part of the `V1` baselines, so no live exception currently applies; don't treat historical precedent as license to edit an applied migration today.)
- V1 baselines require an empty database/schema and are applied exactly once by Flyway. They must not be replayed as repair scripts. Future changes use V2 onward.
- `flyway.validate-on-migrate: true` in all profiles; `out-of-order: false`.
- `flyway.baseline-on-migrate: false` in all profiles (`application.yml`) — there is currently no local-profile override (only a gitignored `application-local.example.yml` template exists, and it has no Flyway section).

For this development reset, recreate the database and bootstrap both V1s. Do not use Flyway repair to adopt rewritten baselines.

---

## Tenant Schema Control Plane

There are **two independent Flyway migration lines**, never applied by the same Flyway instance:

| Line | Location | Applies to | History table | Notes |
|---|---|---|---|---|
| Platform/reset | `postgres_reset/` | `public` and `platform`, plus an empty `tenant_default` schema | `public.flyway_schema_history` | Each file must open with a `-- migration-guard: platform-only` comment; `PostgresResetMigrationGuardTest` enforces this so tenant-schema DDL can't leak into the shared line by accident. |
| Tenant | `tenant/` | Every tenant schema (`tenant_default` and each `tenant_<id>`), one Flyway run per schema | `<schema>.tenant_schema_history` | Tenant V1 is the reset baseline; this independent line owns tenant DDL and may use `${tenantId}` / `${tenantSchema}` placeholders. The platform-only guard must not be applied to tenant DDL. |

Current latest: platform `V8__reviewed_intelligence_publication.sql` and tenant `V6__intelligence_revision_and_finding_eligibility.sql`, each following its own immutable V1 baseline. The next platform migration is V9 and the next tenant migration is V7. Tenant request compatibility remains V6–V6. Startup/readiness also require the retained platform work structures, the V6 waiting-state constraint, the schedule-occurrence index and the reviewed-intelligence structures; this structural check does not certify deployed migration history or rollback compatibility.

**Rollout mechanics** (`TenantSchemaMigrationService.migrateAll()`, mirrored by `ProductionBootstrapCli` for the standalone production bootstrap path):
1. Hold a Postgres advisory lock (`scout-tenant-schema-migrator` / `scout-production-bootstrap`, 30s timeout) so only one migration run proceeds at a time.
2. Migrate the `tenant_default` template schema first and compute its **structural fingerprint** — a SHA-256 hash over a normalized, schema-name-and-tenant-id-scrubbed dump of every column, constraint, index, sequence, and RLS policy definition (`information_schema` + `pg_catalog` introspection).
3. Migrate one canary tenant, then remaining tenants in batches of 10; each tenant's post-migration fingerprint is compared against the template's — any mismatch fails that tenant as `DRIFTED` and halts the batch rather than silently diverging.
4. Every step (start, success, failure) is recorded to `platform.tenant_schema_versions` via `TenantSchemaStatusService`, which also serves `GET /api/platform/tenant-schema-status` (backing the Platform Console's tenant schema status view) and `TenantSchemaReadinessHealthIndicator` (an actuator health contributor gated behind `app.tenancy.enforce-schema-version=true`; readiness reports the count of incompatible ACTIVE tenants while keeping compatible tenants usable. Missing required platform dependencies make readiness `DOWN` and fail startup when enforcement is enabled; individual inaccessible tenants are rejected at request entry. The required tenant floor and supported maximum are both **V6**).
5. A `report-only` mode (`reportOnly=true` / `BOOTSTRAP_REPORT_ONLY=true`) runs the same fingerprint comparison read-only, for verifying a restored production clone before committing to a real migration.

**RLS enforcement is driven from the tenant line, not the platform line.** The mechanism is now baked directly into `tenant/V1__tenant_schema.sql` and runs once per tenant schema (via the rollout above): for every table in that schema it adds a `tenant_id` column if missing (backfilled to the tenant's own id, `NOT NULL` with a per-tenant default), fails loudly if it finds rows with a *conflicting* `tenant_id`, and enables `FORCE ROW LEVEL SECURITY` with a `tenant_isolation` policy pinned to `app.current_tenant_id`. `demo_requests` and `demo_invites` are explicitly exempted from the row-conflict check (`ProductionSafetyValidator.isSharedLifecycleTable`) because they hold pre-tenant-existence rows; the RLS-*coverage* check (confirming every table actually has RLS enabled) separately excludes only `demo_requests` by name — `audit_events` is not exempted from either check (it has `FORCE ROW LEVEL SECURITY` enabled like any other tenant table). This is the mechanism referenced by "RLS rollout status" in `architecture.md` — `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` (platform line) remains the pre-flight gate confirming the runtime DB role is non-superuser/non-BYPASSRLS before this per-tenant enforcement is allowed to run in production.

**Standalone production bootstrap:** `ProductionBootstrapCli` (`com.prototype.vulnwatch.migration`) is a `main()` entry point that does **not** start Spring/JPA — it runs platform migrations, reconciles the platform-owner identity, registers/migrates the default tenant, migrates all other tenants (canary + batches of 10, drift-checked the same way), provisions/rotates the least-privilege `scout_runtime` Postgres role, verifies the full control-plane invariants (RLS coverage, role privileges, no unsafe attributes, DDL actually denied at runtime), and optionally emails a platform-owner password-setup link via Resend. `backend/scripts/run-render-migration.sh` and `backend/scripts/provision-runtime-role.sql` are the scripts that wrap it in a temporary Render deploy; see [bootstrap wrapper](../backend/scripts/run-render-migration.sh), [runtime grants](../backend/scripts/provision-runtime-role.sql) and [release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>).

---

## Connection Pool (HikariCP)

| Parameter | Default | Production override |
|---|---|---|
| `maximum-pool-size` | 20 | `${DB_MAX_POOL_SIZE:30}` |
| `minimum-idle` | 5 | `${DB_MIN_IDLE:5}` |
| `connection-timeout` | 30,000 ms | |
| `idle-timeout` | 600,000 ms | |
| `max-lifetime` | 1,800,000 ms | |

---

## Dashboard Cache (Caffeine)

- **Cache name:** `dashboard`
- **Maximum size:** 100 entries
- **TTL:** 60 seconds after write (`expireAfterWrite=60s`)
