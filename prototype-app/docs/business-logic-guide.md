# VulnWatch — End-to-End Business Logic Guide

Last updated: 2026-10-28 (UI 2.0 documentation alignment)

**Audience:** Engineers and product stakeholders who need to understand how the platform works end-to-end.

---

## UI 2.0 workflow contract

The migration is complete for tenant, platform and authentication screens. Presentation is shared through UI 2.0; business workflows still use the existing queries, DTOs, enums, mutations and authorization. The `/demo` public site intentionally has its own styling boundary.

New screens follow [the UI development standard](<../Working Knowledge/New UI 2.0/ui-development-standard.md>). Keep domain distinctions visible: queue totals versus narrowed/page-local results, selection versus detail navigation, CVE applicability versus analyst impact, persisted assessments versus local drafts, and roles versus tenant entitlements. Reuse shared presentation without merging these semantics or inventing unsupported actions. Retired Fix Intelligence pages redirect to Findings; contained runtime/provider/patch capabilities remain unavailable.

Changes to shared interaction or presentation patterns require user approval during development after explaining alternatives, pros/cons and how affected screens will converge. See [current migration state](<../Working Knowledge/New UI 2.0/CURRENT_STATE.md>) for historical verification limits.

## Core Concept: What VulnWatch Does

VulnWatch is a vulnerability operations platform. It answers: *"Which of our software components have known vulnerabilities, how bad are they, and what should we do about them?"*

The pipeline is:

```
Inventory IN          →   Vulnerability Intel IN    →   Correlation
(SBOMs, CMDB sync,        (NVD, GHSA, KEV, CSAF,       (CPE join +
 AWS discovery)            EPSS, EUVD, JVN)             version check)
                                                             ↓
                                                      Findings + Workflow
                                                      (triage, assign,
                                                       suppress, resolve)
```

---

## Multi-Tenant Architecture

### Schema-Per-Tenant Isolation

Every tenant gets its own PostgreSQL schema. The `TenantAwareDataSource` wraps HikariCP and sets `search_path = <tenant_schema>,platform` on every connection checkout (platform-context work uses `platform,public`). This means:

- Search path routes ordinary reads; isolation additionally requires forced RLS and a restricted non-owner/non-superuser/non-BYPASSRLS role. Search path alone does not prevent explicitly qualified cross-schema SQL.
- Platform-level tables (`tenants`, `app_users`, `tenant_memberships`, etc.) live in the `platform` schema.
- Per-tenant operational tables (`findings`, `assets`, `inventory_components`, `org_cve_records`, etc.) live in each tenant's schema.

### Tenant Context Flow

1. The servlet `TenantResolutionFilter` supplies explicitly enabled local header/default compatibility before the security chain. `ApiKeyAuthenticationFilter` then validates JWT mode/issuer/audience/access use and installs the revalidated tenant ID/schema before any tenant transaction. Deployed header/default fallback is disabled.
2. Human authority comes from the current ACTIVE user, stored global grants and current membership/support access, not JWT role escalation. `TenantRolePolicy` accepts only TENANT_ADMIN, INVENTORY_ADMIN, SECURITY_ANALYST and READ_ONLY_AUDITOR as membership roles. Tenant claims select a workspace; they cannot authorize it. Machine JWTs additionally require an ACTIVE same-tenant registry entry for the verified subject; the key ID alone cannot authenticate.
3. `TenantStatusFilter`, `TenantLifecycleGuardService` and schema compatibility checks reject unavailable workspaces. Background paths establish context before their transaction (`TenantWorkRunner`); `TenantSchemaExecutionService` rejects tenant/schema switches through its scoped runner during an active transaction; establish platform context before the transaction as well.
4. `TenantAwareDataSource` sets search path and RLS context on acquisition. Platform work uses explicit platform context; missing required tenant context receives a nonmatching sentinel. Physical connections with unfinished transactions or failed reset are discarded.

See [backend authentication and capability rules](backend.md#authentication) for LOCAL/EXTERNAL, public exchanges, CSRF and independent containment.

### Tenant Lifecycle

Tenant creation returns 202/PROVISIONING. The separate schema control plane migrates, grants and verifies before activation; failure leaves PROVISIONING_FAILED and explicit retry is required. The development example can opt into synchronous provisioning on a disposable local database, not a deployed runtime.

`DemoLifecycleService.expireDemoTenants` checks the stored `demoExpiresAt` under a tenant-row lock and commits EXPIRED plus its audit together. It retains schema/data/shared history. Manual destructive deletion remains hard-disabled by `ManualTenantDeletionPolicy`; expiry does not authorize purge. `DemoDatasetProvisioningService` serializes requested seed data and completion markers in one tenant transaction after ACTIVE; it does not promise a new retention period or capacity. Existing TTL/policy values are configuration, not commitments made by this guide.

### Tenant-Authorized Support Access

`TenantSupportAccessController` (its `platform.tenant_support_grants` table lives in the `postgres_reset/V1__platform_schema.sql` baseline) lets a tenant admin grant a time-boxed, break-glass platform-owner access grant (`POST /api/tenants/{tenantId}/support-grants`, `TENANT_ADMIN`), which the invited platform owner then accepts (`POST /api/auth/support-grants/{grantId}/accept`). This is distinct from — and layers on top of — the existing `tenant_support_grants` table and `TenantSupportGrant` lifecycle described elsewhere in this doc; the new piece is that the *tenant* can initiate the grant rather than only the platform owner requesting access.

---

## Inventory Pipeline

### SBOM Ingestion

SBOMs arrive via three paths:
1. **File upload** — `POST /api/bom/upload` with multipart file (`POST /api/bom/fetch` and `POST /api/sbom-fetch` cover URL/endpoint fetch)
2. **Endpoint fetch** — backend pulls SBOM from a configured URL on a schedule
3. **GitHub** — periodic fetch from GitHub dependency graph or GHCR attestation for configured repos

**Processing flow:**
1. Parse SBOM (CycloneDX JSON/XML or SPDX JSON)
2. Normalize each component: name, version, PURL, CPE
3. Resolve or create `SoftwareIdentity` (deduplication by normalized name + ecosystem)
4. Create/update `InventoryComponent` records linking identity to asset
5. Resolve CPEs: match against `cpe_dim` and write `inventory_component_cpe_map`
6. Update `SbomUpload` status (`IN_PROGRESS` → `SUCCESS` or `FAILURE`)

**Deduplication:** Components are deduplicated by `(softwareIdentityId, assetId)`. Re-ingesting the same SBOM updates version and metadata; it does not create duplicate rows.

### CMDB Sync (ServiceNow)

`ServiceNowCmdbSyncService` pulls CI records from ServiceNow CMDB using the configured instance URL and credentials.

**Flow:**
1. Fetch discovery-model rows and software-install rows from the configured ServiceNow tables via the Table API
2. Enrich install rows with their discovery-model data and hand both to `CmdbIngestionService.ingestRows`
3. Create/update `Ci` records, `CiAlias` records for alternative identifiers, `SoftwareInstance`s, and `InventoryComponent`s
4. Write `SyncRun` with outcome metrics

### CMDB Sync (SCCM/MECM)

SCCM/MECM is a live inventory source. `SccmCmdbSyncService` admits one run per configuration under the configuration-row lock, enqueues a durable `SCCM_CMDB` ingestion job, and the worker reads active hosts and their installed software from the tenant's SCCM SQL Server (`v_R_System` joined to `v_GS_INSTALLED_SOFTWARE`), derives discovery rows per publisher and product, and ingests through the shared CMDB pipeline. `SccmJdbcPolicy` gates every connection: only `jdbc:sqlserver://host[:port]` with a short property allowlist, host listed in `SCCM_ALLOWED_HOSTS`, SQL Server authentication, no loopback/link-local/metadata address. No mock inventory substitutes for customer ingestion.

### AWS Discovery

`AwsDiscoveryClient` discovers EC2 instances via AWS Systems Manager (SSM).

**Flow:**
1. Resolve credentials via `AwsCredentialProvider` (IAM role assumption, access keys, or instance profile)
2. For each configured `AwsDiscoveryTarget` (account + region + optional role ARN):
   - Call `DescribeInstanceInformation` via SSM to get managed instance inventory
   - Map instance metadata (instance ID, OS, platform) to Scout `Asset` records (`AwsResourceIngestionService`)
3. Multi-account supported via cross-account role ARN + external ID

**Auth types** (`AwsAuthType` enum): `INSTANCE_METADATA`, `ACCESS_KEY`, `CROSS_ACCOUNT_ROLE`.

### Azure Discovery

Generic Azure discovery is contained by `GenericAzureDiscoveryPolicy` at configuration/test/admission/worker/client boundaries. Saved configurations, subscriptions and inventory are retained; customer settings or entitlements cannot enable collection. The retained static Azure AI/Foundry connector belongs to the separate AI Security pipeline, with its own availability, role, entitlement, kill-switch and evidence-completeness controls.

---

## Vulnerability Intelligence Pipeline

### Sources

| Source | Schedule | Data |
|--------|----------|------|
| NVD | Daily 01:00 + incremental | CVE records, CVSS scores, CPE applicability |
| CISA KEV | Daily 01:00 | Known-exploited CVE list |
| GHSA | Daily 01:15 | GitHub Security Advisories |
| Microsoft CSAF/VEX | Daily 01:45 | Microsoft product VEX assertions |
| Red Hat CSAF/VEX | Daily 01:45 | Red Hat product VEX assertions |
| EPSS | Daily 03:15 | Exploit Prediction Scoring System scores |
| EUVD | Daily 02:00 | EU Vulnerability Database |
| JVN | Daily 02:30 | Japan Vulnerability Notes |
| OSV | Daily 02:45 | OSV advisories (per-tenant correlation 02:50) |

### What Gets Written

- `vulnerabilities` — one row per CVE with CVSS base score, description, published date
- `vulnerability_targets` — CPE match patterns for each CVE (drives correlation)
- `vulnerability_intel_summary` — read-model projection aggregating all intel for a CVE
- `vulnerability_intel_observations` — per-CVE signals (KEV membership, EPSS score, CSAF assertions)
- `vex_assertions` — VEX statements from CSAF documents

### VEX Processing

CSAF documents contain VEX statements asserting whether specific product versions are affected, not affected, fixed, or under investigation. `VexAssertion` entities store these statements. The `VexStalenessRecomputeJob` (daily 02:30) re-evaluates VEX assertions against current inventory to handle document updates.

---

## Correlation Engine

The correlation engine answers: *"Which of our software components match CVE applicability criteria?"*

### CPE-Based Matching

1. `InventoryComponentCpeMap` links each inventory component to normalized CPE 2.3 strings
2. `vulnerability_targets` stores the CPE patterns from NVD (with version range constraints)
3. A join on CPE product + vendor produces candidate matches
4. `ApplicabilityDecisionService` evaluates version constraints (using `VersionScheme`-aware comparison) to confirm or reject each candidate

**Result:** `ComponentVulnerabilityState` records — one row per `(inventoryComponent, vulnerability)` pair with `applicabilityState` (APPLICABLE, NOT_APPLICABLE, UNKNOWN).

### Org CVE Records

`org_cve_records` is a rollup projection: one row per `(tenantId, cveId)`. It aggregates:
- `matchedAssetCount` — distinct assets with applicable software
- `matchedSoftwareCount` — distinct software components matched
- `severity` — CVE severity (default `UNKNOWN`)
- `inKev` — whether the CVE is in CISA KEV
- `epssScore` — current EPSS score
- `orgImpact` — assessed organizational impact (`NONE`, `LOW`, `MEDIUM`, `HIGH`)
- `impactState` — `IMPACTED`, `NOT_IMPACTED`, `FIXED`, `NO_PATCH`, `UNDER_INVESTIGATION`, `UNKNOWN`
- `applicabilityState` — overall state for the org (APPLICABLE, NOT_APPLICABLE, UNKNOWN)

This table drives the **CVE Assessment Workbench** UI.

---

## Finding Lifecycle

### What is a Finding?

A `Finding` represents a specific, actionable security issue: a vulnerability (CVE) that is applicable to an asset in the tenant's inventory and requires a decision.

Findings are created automatically when `ComponentVulnerabilityState` transitions to APPLICABLE (only in `AUTO` generation mode — see below), or manually via `FindingCreationSource.MANUAL`.

### States

```
OPEN ──→ RESOLVED
  ↓  ↘
  ↓    AUTO_CLOSED   (auto-close policy)
SUPPRESSED ──→ OPEN  (when suppression expires)
```

`FindingStatus` enum: `OPEN`, `RESOLVED`, `SUPPRESSED`, `AUTO_CLOSED`. Analyst triage outcomes (affected / not affected / fixed / under investigation / needs review) are carried separately in `FindingDecisionState` (`AFFECTED`, `NOT_AFFECTED`, `FIXED`, `UNDER_INVESTIGATION`, `NEEDS_REVIEW`), and the reason a finding closed in `FindingCloseReason` (e.g. `MANUAL_FIXED`, `MANUAL_FALSE_POSITIVE`, `MANUAL_ACCEPTED_RISK`, `AUTO_NOT_OBSERVED`).

### Finding Events

Every status transition is recorded as a `FindingEvent` with actor, timestamp, and reason. This provides a complete audit trail for each finding.

### Delta Queue

`FindingDeltaQueueEntry` records pending state changes. The drain job processes batches of 100 every 2 seconds, applying changes atomically. This decouples the correlation engine (which produces many changes) from the finding service (which must handle them correctly).

### Finding Generation Modes

`RiskPolicy.findingGenerationMode`:
- `AUTO` — findings created automatically when correlation determines applicability
- `MANUAL` — analysts must explicitly promote an org-CVE record to a finding (the default for a new `RiskPolicy`)

### Auto-Close

The hourly auto-close job (`FindingWorkflowService.autoCloseFindingsByPolicy`) runs per tenant and, when `autoCloseEnabled` and `autoCloseNotObservedEnabled` are set and the run interval (`autoCloseRunIntervalDays`, default 1) has elapsed, moves OPEN findings that were not observed in recent scans to `AUTO_CLOSED` (close reason `AUTO_NOT_OBSERVED`). A finding qualifies once its `autoCloseEligibleAt` has passed and its consecutive-miss count reaches `autoCloseRequiredConsecutiveMisses` (default 2); `autoCloseAssetIdentifier` optionally scopes a run to one asset. `autoCloseEnabled` defaults to false.

---

## Suppression System

`SuppressionRule` entities define conditions under which findings or CVE records are suppressed.

**Lifecycle:** `SuppressionRule.State` is `DRAFT`, `IN_REVIEW`, `APPROVED` (active), `REJECTED`, `EXPIRED`.

**Evaluation:**
1. Only APPROVED rules execute — on demand (`SuppressionRuleService.execute`) and in a nightly midnight re-run across all tenants
2. A FINDING-type rule moves matching OPEN findings to `SUPPRESSED`; a CVE-type rule suppresses matching org CVE records
3. The 15-minute reopen job returns findings whose `suppressedUntil` has passed to `OPEN` and records a `SUPPRESSION_EXPIRED` event
4. Rules are listed/executed in `createdAt` order

**Suppress CVE (org-wide):** `POST /api/cve-detail/{cveId}/suppress` requires a reason and justification, suppresses the tenant's org CVE record directly (`OrgCveRecordService.suppress`, optional expiry from `duration`), and suppresses all existing findings for that CVE; it does not create a `SuppressionRule`. Roles: `TENANT_ADMIN`, `SECURITY_ANALYST`.

---

## Risk Policy

The `RiskPolicy` is a single record per tenant (created on tenant provisioning) that drives multiple behaviors:

| Field group | Effect |
|-------------|--------|
| `criticalSlaDays`/`highSlaDays`/`mediumSlaDays`/`lowSlaDays` (defaults 7/14/30/60), `asset*SlaMultiplier` (0.5/0.75/1.0/1.25), `criticalThreshold`/`highThreshold` (9.0/7.0) | SLA breach calculation on findings |
| `autoClose*` (enabled, after-days, consecutive misses, per-reason toggles, run interval) | Hourly auto-close job behavior |
| `findingGenerationMode` | AUTO vs. MANUAL finding creation |
| `findingsScoreConfig` (JSONB) | Custom attribute-based finding score rules |

The six S.AI `triage*` weights are a frontend/Configurations-page concept (`src/features/configurations/types.ts`, `riskScoring.ts`); they are not fields on the backend `RiskPolicy` entity.

---

## End-of-Life (EOL) Tracking

### Four-Stage Pipeline (Weekly, Sunday)

1. **Catalog refresh** — fetch all products from endoflife.date API → write `EolProductCatalog`
2. **Release data** — fetch release cycles for each product → write `EolRelease`
3. **Slug resolution** — for each unique `SoftwareIdentity`, match to an EOL product slug. `EolSlugResolverService` uses a deterministic four-tier match (CPE, PURL, catalog alias, normalized name against a curated hint map) with EXACT/HIGH/MEDIUM confidence — no LLM call. Confirmed mappings stored in `SoftwareEolMapping`
4. **Denormalization** — write `eol_slug`, `eol_cycle`, `eol_date`, `is_eol` for each `InventoryComponent` based on its version and the matched EOL release data

### Daily Lifecycle Sweep (00:15)

Checks for components that have crossed their EOL date (or entered the near-EOL window) since the last run, updates `is_eol` flags, and enqueues lifecycle deltas on the finding delta queue.

---

## AI Integration (OpenAI)

`OPENAI_ENABLED` (`app.openai.enabled`) defaults **false**. `GenerativeAssistancePolicy` refuses production/preproduction before resolving all four credential aliases; deployed pilot startup rejects enablement. Direct investigation summaries use the same shared gate. Setting a key, entitlement or provider alias cannot bypass containment. The features below describe retained contracts, not pilot enablement.

Deterministic investigation/remediation/upgrade paths remain available with explicit fallback, source and generation-time metadata. Outage or malformed provider output cannot fabricate verified versions/vendor attribution. Historical persisted `OrgCveAiArtifact` results are cached artifacts, not proof of a fresh model call or verified vendor advice. Local generative experiments require explicit local enablement and a key; deployed re-enablement remains separately controlled.

**AI features:**

| Feature | Endpoint | What it does |
|---------|----------|-------------|
| Investigation summary | `POST /api/cve-detail/{cveId}/investigation-ai-summary` (saved result: `GET /api/cve-detail/{cveId}/saved-investigation-summary`) | Generates a natural-language summary of a CVE's impact on the org, citing matched assets |
| AI solution | `GET`/`POST /api/cve-detail/{cveId}/ai-solution` | Generates/returns a persisted remediation solution for the CVE |
| AI actions | `GET`/`POST /api/cve-detail/{cveId}/ai-actions` | Generates/returns persisted recommended actions for the CVE |

`OrgCveAiArtifact` stores `investigationSummaryOutputJson`/`investigationSummaryGeneratedAt`, `aiSolutionJson`/`aiSolutionGeneratedAt`, and `aiActionsJson`/`aiActionsGeneratedAt`.

---

## Ownership Rules

`OwnershipRule` entities define conditions for auto-assigning findings to users or groups. This is the legacy model. It stays in force, and editable as "Legacy rules" in the Ownership & Directory hub, until a tenant's CORE domain cuts over to canonical ownership (below); it is then removed in the ownership cleanup. AI Grid's ownership step also reads these rules.

**Evaluation:**
1. Rules are ordered by `executionOrder` (then `createdAt`)
2. Each rule's `conditionJson` (`{"logic":"AND"|"OR","conditions":[...]}`; field + operator + value) is evaluated against the finding by the same matcher used for suppression rules and the findings score
3. First matching rule sets `finding.ownerGroup` to the rule's `userGroup`
4. Re-evaluated when findings are created or when ownership rules are updated

**Operators** (from `FindingsScoreService`): `=`, `!=`, `>`, `<`, `>=`, `<=` (numeric), `contains`, `not contains`, `exact match`, `is`, `is not`.

**Fields:** table + column attributes of the finding and its related asset/vulnerability/component, as in the Findings Score and Suppression editors.

## Canonical Ownership (Release 1)

Ownership MVP Release 1 (PR #71) resolves each asset, and through it each vulnerability finding, to one accountable **team**. It is built but off by default. The [plan](ownership-capability-mvp-plan.md) defines the product rules; [the Phase 0A design](ownership-phase-0a-design.md) §8.1 records what is built.

**Teams and directory.** Teams have unique names and aliases in one namespace. People and groups come from manual entry or CSV import (preview, then commit of the same file within 30 minutes). Email is only a link hint: two people with the same email are never merged; the import raises an `AMBIGUOUS_IDENTITY` review item. Directory contact details are encrypted per tenant and masked in responses. Directory writes are refused until the tenant's data key is provisioned and ready.

**Claims and resolution.**
1. A source publishes a claim that a team owns a subject. Precedence, highest first: manual assignment, ServiceNow, cloud account/project, AI Grid, cloud tag/label, Entra/Okta.
2. For each subject the highest-precedence eligible claim wins. A direct claim always beats an inherited one.
3. A subject without a direct result inherits from its parent, up to 6 hops. Cycles, missing parents and longer chains produce `CONFLICT` and a review item.
4. A claim is stale after twice its source's sync interval and stops counting after 7 days without being seen again. These thresholds differ from the plan (§12.1 and §12.3) and still need product sign-off.
5. The effective status is `OWNED`, `UNOWNED` or `CONFLICT`. A subject's direct assignment can also be `NONE` (claims exist but none is eligible); it then inherits from its parent.

**Manual assignment.** Tenant and inventory admins can assign any subject. Security analysts can assign only for an open finding assigned to them. A reason is required, expiry is at most 30 days, and the impact preview is capped at 100 descendants or 1,000 findings. Only admins can revoke. Manual assignment needs the subject's domain to be CANONICAL.

**ServiceNow producer.** When enabled, each successful CMDB sync publishes claims from the CI `support_group`. Unchanged claims are re-observed without assignment writes. If more than 20% (minimum 50) of active claims would change or end, publishing pauses and a `PRODUCER_ANOMALY` review item is raised. Claims for missing CIs end only after a complete scan.

**Cutover.** Each domain moves LEGACY → DARK → CANONICAL per tenant:
- **DARK:** the per-minute maintenance job links assets and findings to subjects. Nothing user-facing changes.
- **Qualification:** passes only with zero unlinked assets/findings, an empty re-resolution queue, swept expiries, the current resolver version, no inheritance errors, no open producer anomaly and, with the cache on, no cache backlog. It also reports a legacy-vs-canonical comparison.
- **CANONICAL:** needs the passing report's hash and records who accepted it. The API cannot revert it.

Release 1 covers CORE: APPLICATION and HOST assets and `VULNERABILITY` findings. `CRYPTO` findings and container/cloud assets belong to CLOUD_BOM (Release 2) and AI findings to AI_GRID (Release 3); they keep the legacy display even on a canonical asset.

**What users see.** Asset and finding responses carry the canonical team only when the tenant's read wave is on and the domain is CANONICAL. Otherwise rows show `LEGACY_PENDING_MIGRATION` and today's owner label. Findings gain an Ownership Status column; owner-team and status filters appear once findings ownership is canonical.

---

## ServiceNow Incident Integration

`POST /api/cve-detail/{cveId}/servicenow-incident` creates a ServiceNow incident linked to a finding.

- `incident_id` and `incident_status` are stored on the `Finding` entity
- `FindingIncidentSyncService` runs daily at 07:00 and pulls updated incident states from ServiceNow back into Scout findings
- Integration is not fully bi-directional — Scout reads incident state but does not push finding state changes back to ServiceNow

---

## Remediation Campaigns

`CampaignController` (`/api/campaigns`) — undocumented in earlier drafts of this guide, but a fully shipped feature (frontend at `/vuln-repo/campaigns`, `CampaignsPage`/`CampaignDetailPage`).

A **Campaign** groups findings/CVEs into a tracked remediation effort:

- **Lifecycle:** `DRAFT` → `ACTIVE` → `PAUSED` / `BLOCKED` / `IN_REVIEW` → `CLOSED` / `CANCELLED`.
- **Exceptions:** individual findings/CVEs within a campaign can be marked exempt from the campaign's remediation requirement, with their own status workflow.
- **Notify groups:** teams/individuals subscribed to campaign status changes.
- **Watchlist:** entries tracked for visibility without being formally part of the remediation scope.
- **Notes:** free-form campaign annotations.
- The frontend detail page retains insight UI backed by deterministic/generative policy; deployed generative assistance stays off and can bulk-add assets, CVEs, or software to a campaign.

## Cloud/Container BOM (CBOM)

`BomController` (`/api/bom`) handles general Bill-of-Materials ingestion (fetch by URL or file upload), with dashboard, support-matrix, and lineage views per BOM. `CbomController` (`/api/bom/cbom`) is a specialized branch tracking cloud/container posture: per-asset CBOM posture summaries, components, and risk findings with an analyst accept-finding workflow. The Connect page's `bom-management` connector exposes SBOM, AI-BOM, CBOM, and Vendor-BOM ingestion in one place.

A CBOM keeps its cryptographic assets in `cbom_components` (findings in `cbom_risk_findings`), not `bom_components`. For CBOM records the BOM Inventory item, BOM detail and dashboard `componentCount` therefore come from active `cbom_components` rows. `GET /api/bom/inventory/{bomId}/cbom-assets` (same tenant-reader roles as the other BOM reads; 404 for an unknown or non-CBOM record) lists a CBOM's assets with their linked findings, and the BOM Inventory detail panel shows them in place of the component table. The BOM Components grid also lists each active CBOM asset as a row (ecosystem `crypto`, BOM type CBOM); those rows have no software detail page.

CBOM risk findings are mirrored into the canonical findings list as finding kind `CRYPTO` (tenant V10 widens `findings_kind_check`) by `CbomFindingMirrorService`, so analysts see them beside vulnerability findings, flagged "Crypto". `cbom_risk_findings` stays the source of truth and the mirror is idempotent, keyed by fingerprint `cbom:<cbom finding id>`: an OPEN finding on a live document is OPEN; ACCEPTED becomes SUPPRESSED; a finding the latest evaluation no longer reports is AUTO_CLOSED (`AUTO_NOT_OBSERVED`); a withdrawn or deleted document closes its findings as `AUTO_COMPONENT_REMOVED`, which is never a remediation claim. It runs inline on CBOM ingest, accept and withdrawal, and `CbomFindingMirrorSweep` (`app.cbom.finding-mirror.interval-ms`, default 5 minutes) mirrors findings that predate the kind. A crypto finding has no CVE or inventory component: the list shows its rule id in the vulnerability column and its crypto asset as the package, and the detail page shows a Crypto finding panel instead of CVE lookups. Crypto findings are counted wherever open findings are counted.

## AI-BOM → AI Grid Integration

Lets customers upload AI-BOMs and see declared AI resources and their software vulnerabilities in AI Grid *even without a cloud connector*. Reuses existing software identity resolution, vulnerability correlation, and the canonical `findings` table rather than building a parallel evaluator; deliberately excludes model scanning, new exposure rules, CBOM findings consolidation, and broader package identity normalization. Shipped across three milestones — see [database.md](database.md#bom-common-lifecycle-tenant-v4-v6) and `#ai-bom-declared-resources-tenant-v7v11-platform-v5` for the schema.

### Milestone 1: common BOM lifecycle

Before this work, a document upload replaced-by-inference on asset + supplier alone, and a partial replacement omitting a component looked identical to that component vanishing — there was no way to withdraw one source's support without it reading as "the software is gone." `BomIngestionOrchestrator` now runs every BOM (SBOM, AI-BOM, vendor BOM, CBOM) through one lifecycle: validate → preserve the document → classify components → resolve identity → record the source's contribution → hand off to specialized evaluation (software correlation, declared-AI-inventory recording, or CBOM evaluation, depending on component category).

- **Source identity** (`bom_sources`) is independent of document id/checksum. Uploading with no `sourceId` creates a new independent source; supplying one replaces that source's current version. `completeness` (`PARTIAL` default, or `COMPLETE_ASSET_SOFTWARE`) travels with every upload and every replacement must repeat the assertion (`bom_source_completeness_assertions`) — it is never inherited.
- **Evidence reconciliation** (`bom_component_contributions`) tracks a *standing claim*, separate from a component's `ACTIVE`/`RETIRED` status: `SUPPORTED` (a source currently vouches for it), `CONFLICTING` (a complete replacement asserted absence while another source still reports it — never auto-resolved), `WITHDRAWN` (every claim withdrawn — presence unknown, not disproved), `LEGACY_UNKNOWN` (predates contribution tracking or its asset isn't backfilled yet — never a basis for retirement). Only an `authoritative_absence` (a complete-scope replacement that omitted the component, with no conflicting support) can retire a component, and only through the existing policy-controlled removal workflow. Withdrawal never advances missing-scan counters, changes applicability to "not impacted," refreshes observation timestamps, or counts as remediation.
- **Backfill gate** (`bom_asset_backfill_state`): an asset's components stay `LEGACY_UNKNOWN` until backfilled; missing contribution rows can never justify retirement in the meantime. Ships in the same migration as the schema it protects.
- Asset ingestion is serialized with `pg_try_advisory_xact_lock` — concurrent uploads for the same asset fail fast rather than racing.

### Milestone 2: declared AI inventory and durable projection

Models and datasets extracted from a BOM (component `category = AI_MODEL`) are recorded as **declared resources** (`ai_bom_declared_resources`), not connector-discovered `ai_security_artifacts` — a declaration is a claim a document made, not an observed deployment. Every new declaration starts `deploymentState = UNVERIFIED`; a re-upload of the same document never re-evaluates a resource that's already `LINKED`.

- **Identity, in descending trustworthiness:** an immutable content digest, an explicit versioned identifier (e.g. a purl carrying a version), or a source-scoped reference used when the document offers nothing stronger. A display name is never an identity — two unrelated models are routinely both called "classifier."
- **Automatic deployment linking** (`AiBomDeploymentLinkingService`) only attempts a match for `MODEL` resources identified by a versioned identifier, against `ai_security_artifacts` by name (+ version, when the candidate exposes one). A single unambiguous name match links; two or more same-named candidates with no matching version become `AMBIGUOUS` rather than a guess. Digest-identified resources, dataset resources, and source-scoped-ref resources have no automatic match path at all — see Milestone 3's reviewed mapping workflow below.
- **Declared dependency relationships** (`bom_component_relationships`) are stored verbatim, never interpreted — a CycloneDX `dependsOn` edge from a model to a library states a document-declared dependency, not that the model was trained on it or serves it at inference time.
- **Projection**: an AI-BOM upload's `provenance.ai_bom_present` fact is projected asynchronously (`AiBomProjectionWorker`, backed by `ingestion_jobs` with type `AI_GRID_BOM_PROJECTION`) after the ingest transaction commits, keyed by source revision so a redelivered or out-of-order job can't double-project, and idempotent via `ai_bom_projection_receipts`. The fact lives in its own `ai_bom_provenance_facts` table, not `ai_grid_facts` (which requires a connector-observed artifact/snapshot/run a BOM-only asset never has), with evidence class `BOM_DOCUMENT` (never `CONFIGURATION`) and workflow use `COVERAGE_CONTEXT` (never `POSTURE_FINDING`) — a document's existence is not a posture claim, and treating it as one would enable the BOM coverage policies that are deliberately kept disabled.
- **Budget and entitlement**: AI-BOM projection has its own daily admission budget (100/tenant/day default, `app.ai-bom.projection.daily-admission-limit`) and its own queued/running cap (100/tenant default) — deliberately not shared with `ai_grid_budget_admissions`/cadence rules, which are keyed by a connector `run_id` and don't apply to a document-upload-triggered job. Overflow beyond the cap is coalesced per source into durable dirty-source state and surfaced as `bom_sources.state = DEFERRED` rather than dropped. A tenant without the `ai.security` entitlement keeps ordinary BOM ingestion and vulnerability processing; its sources are marked `HELD_ENTITLEMENT` instead of enqueuing a job per upload, and on entitlement grant each held source's latest revision is scheduled through the same bounded queue.

### Milestone 3 part 5.1: canonical applicability, one authority

The shared component-assessment path remains the sole writer of software vulnerability applicability and remediation state. AI-BOM reconciliation only records a source-scoped association to an existing canonical `VULNERABILITY` finding, including a closed finding when its inventory component remains active. A bounded resolver follows the current document's `DEPENDS_ON`/`COMPOSED_OF` paths and requires an unambiguous ecosystem/namespace/package/version identity. The reconciler atomically maintains path support, ACTIVE/RETIRED association lifecycle, gaps, and secondary `AFFECTED_AI_RESOURCE` subjects. It never changes finding status, owner, due date, suppression, or canonical finding identity/count.

A PARTIAL replacement still withdraws that source's omitted dependency assertions; it does not prove installed software disappeared. Missing versions, ambiguous identity, failed/unavailable reads, and traversal limits retain the affected prior support with a visible gap, while unrelated definite removals can retire independently. Removing the last authoritative path retires its association and secondary subject; restoration reuses association identity and preserves lifecycle history. Source locking coordinates uploads with per-resource transactions, and tenant/resource failures remain isolated. Retirement is disabled by default pending representative tenant observation.

Deliberately not built: a model/dataset's own identity matching a CVE directly. A component declared as a model/dataset stays outside the current shared software inventory pipeline, so there is no `Finding` to bridge to in that case — the pre-existing `bom_component_vulnerability_links` table already records a document-level match without needing one.

### Milestone 3 part 5.2: separate contracts and views

`FindingsFilter`/`FindingsFilterRequest` gained three fields, applied identically by both the JPA-`Specification` path (offset-paginated `GET /api/findings`, via `FindingFilterSpecifications.byFilter`) and the raw-SQL path (`finding_list_projection` — cursor list, `/groups`, `/summary`, `/distributions`, `/backlog-health`, via `FindingProjectionQueryService.buildSqlFilter`) so a client never sees a different answer depending on which endpoint it happened to land on:

- **`findingKind`** — null/empty means every kind (keeps All Findings inclusive by default); the Software Vulnerabilities view selects `VULNERABILITY` explicitly. Never inferred from `vulnerability_id`/`package_name`/`ecosystem`, which the projection overloads with an AI policy id when `finding_kind` isn't `VULNERABILITY`.
- **`affectedAiResourceId`** — restricts to findings transitively affecting one of these declared-resource ids.
- **`hasAffectedAiResource`** — `true`/`false` restricts to findings that do/don't affect any declared AI resource at all; ANDs with `affectedAiResourceId` when both are set.

`FindingResponse.affectedAiResources` (batch-loaded by `AiBomAffectedResourceSummaryService`, two queries regardless of page size — never a join into the findings query itself, which would multiply rows ahead of pagination) is populated only on the paginated list endpoints (`listByTenantPage`/`listByTenantCursor`), not `listByTenant`/`listLatestByTenant`. AI-policy findings keep their own separate `FindingResponse`-shaped DTO (a private nested record in `AiSecurityApiService`) — this was already true before 5.2, nothing changed there.

### Milestone 3 part 5.3: inventory, administration, and the AI Findings split

- **AI Findings** (`/findings/ai`) split into two `fd3-tab`-style tabs: **Policy Violations** (unchanged — the existing `AiSecurityApiService`-backed feed) and **Software Vulnerabilities** (new — `/findings/ai/vulnerabilities`, queries the generic `/findings` endpoint with `findingKind=VULNERABILITY&hasAffectedAiResource=true`). Both open their own kind of finding detail — software findings resolve to the canonical `FindingDetailPage`, policy findings keep `AiFindingDetailPage`.
- **Declared-resource detail** (`/inventory/ai/declared-resources[/:resourceId]`, `AiBomDeclaredResourceController`) shows, per declared resource: which BOM document version declared it, the standing completeness assertion, deployment status, the backing BOM component, whether the declaration is still current in the latest source revision (a `bomId` that no longer matches the source's `currentBomId` — evidence going stale, not necessarily wrong, since AI-BOM resources have no `BomComponentEvidence`/`BomContributionState` of their own to check), projection status, a link to the linked/proposed `ai_security_artifacts` resource, and the findings transitively affecting it (`GET /api/bom/declared-resources/{id}/findings`, the reverse lookup 5.2 deferred here).
- **Coverage setup actions, not policy violations**: unlinked/ambiguous declared resources and entitlement-held/backlog-deferred sources surface as setup work (`GET /api/bom/declared-resources/setup-actions`) computed live from `ai_bom_declared_resources`/`bom_sources` — deliberately not a persisted-and-swept table like AI Grid's own `ai_grid_setup_actions`, since AI-BOM's source tables are already the durable live truth and there's no separate scan-run snapshot to reconcile against.
- **Reviewed mapping — propose/approve/remove** (`AiBomResourceMappingService`): the human-reviewed path the automatic matcher deliberately doesn't perform. *Propose* (role `SECURITY_ANALYST`+) stages a candidate `ai_security_artifacts` id after checking it exists for the tenant, without touching `deploymentState`. *Approve* (role `INVENTORY_ADMIN`/`TENANT_ADMIN`/`CREATOR` — narrower than propose) promotes it to `LINKED`/`link_method=REVIEWED`/`link_reviewed_by`. *Remove* clears any link or pending proposal back to `UNVERIFIED`. Each mutation is a `@SensitiveTenantAction` with an explicit `audit_events` row; the global `SensitiveTenantActionInterceptor` (any write method) also applies its usual support-session restrictions with no extra code needed here.

---

## AI Security / AI Grid Pipeline

Not to be confused with [AI Integration (OpenAI)](#ai-integration-openai) above — that section covers VulnWatch *using* an LLM internally (CVE investigation summaries, AI solutions and actions, campaign insights). This section covers VulnWatch *discovering and governing other systems'* AI/ML resources (Bedrock agents, Azure AI Foundry projects, MCP servers, etc.) as a security posture management capability, entitlement-gated per tenant behind the `ai.security` key (`TenantEntitlementService.AI_SECURITY`). It backs the `/findings/ai`, `/policies`, and `/inventory/ai` frontend routes and lives in its own top-level backend package, `com.prototype.vulnwatch.aisecurity` (19 controllers, 63 services — separate from the main `controller`/`service` packages).

AI Grid is the sole policy and findings generation. It evaluates governed, versioned policies against discovered artifacts; canonical findings retain the host workflow. `AiSecurityController` remains only for shared artifact inventory, graph, discovery-run, and compatibility finding reads.

### Discovery

`AiSecurityJobWorkerService` polls `ingestion_jobs` for `AI_SECURITY_AWS_BEDROCK` / `AI_SECURITY_AZURE_DISCOVERY` job types (every 3s by default) and dispatches to a provider:

- **AWS** (`AwsBedrockDiscoveryService`) — via AWS SDK v2, discovers Bedrock agents/action-groups/knowledge bases/guardrails/models/inference profiles/prompts/flows, AgentCore gateways/targets, and SageMaker domains/endpoints/pipelines; checks IAM policies for wildcard actions, Lambda function-URL auth, and S3 bucket public-access status. Optionally reads *existing* AWS Macie PII classification findings for referenced S3 buckets (`AwsMaciePiiLookupService` — never triggers a new Macie scan). Gated by `AiSecurityAwsAdmissionService` (per account/region semaphores) and the budget service below. One bounded provider-call ceiling plus connector enablement, provider kill switch, retries/semaphores and scan budgets controls the version-rooted definition graph, IAM identity graph and AgentCore static surface inventory — see [AWS deployed-agent graph](#aws-deployed-agent-graph) below.
- **Azure** (`AzureAiDiscoveryService` / `AzureAiManagementClient`) — raw ARM API calls discovering Cognitive Services/AI accounts, Foundry projects/deployments/RAI policies/agents, ML workspaces/endpoints, AI Search services/indexers/knowledge sources, Bot Service, diagnostic settings, RBAC assignments, Storage accounts. `AzureRaiPolicyAnalyzer` conservatively parses RAI content-filter configs. Optionally reads *existing* Microsoft Purview Data Map classification results for Storage accounts (`AzurePurviewClassificationClient` — read-only). Gated by `AiSecurityAzureAdmissionService` and a config-driven kill switch (`AiSecurityAzureKillSwitchService`).

Microsoft Copilot Studio discovery uses the same durable ingestion path as AWS and Azure. `POST /{connectorId}/run` and scheduled discovery both enqueue an `AI_SECURITY_COPILOT_STUDIO` job; `AiSecurityJobWorkerService` claims it under the provider concurrency limit and dispatches `CopilotStudioDiscoveryProvider`. The worker—not the request thread—starts and completes the `SyncRun`, applies the connector kill switch immediately before collection, and records terminal job state for queue visibility. The discovery service also records a tenant budget admission before its Dataverse metadata sweep. It emits the same `ObservationEnvelopeV1` (`provider = MICROSOFT_COPILOT`) into `AiSecurityObservationService` as the other providers.

Both async connectors emit `ObservationEnvelopeV1` chunks (validated, allow-listed-field-only via `AiSecurityMetadataSanitizer` — no prompt bodies, secrets, or free-text PII) which `AiSecurityObservationService` persists idempotently by receipt and, once a scan scope completes, hands to the AI Grid pipeline.

#### AWS deployed-agent graph

AWS posture is derived from the canonical deployed definition graph. Discovery is bounded by the shared provider-call ceiling; connector enablement, kill switches, budgets, concurrency, retries, and separately costed integrations remain operational controls.

```text
AI_AGENT
  ├── HAS_COMPONENT ──> AWS_BEDROCK_AGENT_ALIAS (AI_COMPONENT)
  │                        └── SERVES_VERSION ──> AI_AGENT_VERSION

AI_AGENT_VERSION (AWS_BEDROCK_AGENT_VERSION)
  ├── VERSION_OF ──> AI_AGENT
  ├── USES_MODEL ──> AI_MODEL
  ├── USES_PROMPT ──> AI_PROMPT            (digest only, never the body)
  ├── USES_TOOL ──> AI_TOOL                (AWS_BEDROCK_ACTION_GROUP)
  ├── USES_KNOWLEDGE_BASE ──> KNOWLEDGE_BASE
  ├── USES_GUARDRAIL ──> AI_GUARDRAIL      (exact guardrail version)
  └── ASSUMES_ROLE ──> AWS_IAM_ROLE

AI_TOOL ── IMPLEMENTED_BY ──> AWS_LAMBDA_FUNCTION
```

Semantics worth knowing before extending this:

- **Alias routing is the authority on what is served.** `DRAFT` is collected as a version like any other, but a version counts as deployed only because some alias's `routingConfiguration` points at it. Multiple aliases and multiple served versions per agent are supported — there is no single "active version".
- **Four distinct evidence states** are modelled and must not be conflated in UI or policy copy: *configured* (attached to the definition), *reachable* (an evidence-backed graph path exists), *activity observed* (a governed external source reported activity), *confirmed* (an exposure template's evidence contract is satisfied).
- **Retyping, not re-keying.** AWS prompts, guardrails, action groups, AgentCore runtimes/browsers/code-interpreters/memories and IAM roles moved off `OTHER_AI_ARTIFACT` onto canonical types (`AI_PROMPT`, `AI_GUARDRAIL`, `AI_TOOL`, `AI_COMPONENT`, `SUPPORTING_RESOURCE`) while keeping their provider ARN as `provider_resource_id`, so artifact identity and history survive the change. Provider-native-kind scoping remains authoritative for policy applicability — canonical types were *not* bulk-added to AWS policy packages.
- **No compatibility edges or copied posture facts.** Knowledge bases and roles attach to the served version, and tool implementations attach through `IMPLEMENTED_BY`; agent-level copies and `INVOKES_LAMBDA` are not emitted.
- **No inferred AgentCore edges.** AgentCore runtimes, browsers, code interpreters and memories are inventoried, but no `CONNECTS_TO_MCP` or agent→runtime edge is emitted, because no authoritative control-plane field links a classic Bedrock agent to an AgentCore runtime. Unattached AgentCore resources are meant to surface as coverage/ownership work, not as a guessed relationship.
- **Per-role IAM isolation.** One malformed or unreadable role degrades that role only (`IAM_GLOBAL` → `PARTIAL`, diagnostic `IAM_ROLE_EVIDENCE_PARTIAL`, role ARN hashed); it does not void global IAM evidence.
- **Disabled ≠ empty.** A disabled connector or separately controlled integration emits `DISABLED`; an authoritatively empty list probe emits verified-empty evidence instead of permission remediation.

#### Runtime activity deferred

Collection of execution events, logs, and curated activity summaries is deferred. Activity producers and `activity.*` facts are rejected with `RUNTIME_OUT_OF_SCOPE`; historical activity evidence does not affect exposure priority or appear in customer detail. Static host-context evidence continues. Runtime exclusion detail doc is archived outside the repo.

### AI Grid Pipeline (per completed scope)

`AiGridPipelineService.processCompleteScope()` runs, in order:

1. **Snapshot** (`AiGridSnapshotService`) — commits an immutable, redacted, hash-deduped snapshot of discovered artifacts; derives versioned **facts** from it (the sole input to policy evaluation).
2. **Ownership** (`AiGridOwnershipService`) — resolves CONFIRMED / INFERRED (via `ownership_rules` — the same table used by Configurations → Ownership) / CANDIDATE (tag heuristic) / UNOWNED. Tags never get promoted to authoritative on their own.
3. **System grouping** (`AiGridSystemService`) — derives agent-rooted "AI systems" via bounded breadth-first search (depth 6, fan-out 100) over provider relationships; tracks revisions and split/merge/successor/retirement lineage across scans.
4. **Policy assessment** (`AiGridAssessmentService`) — evaluates each artifact against every policy the tenant has selected REQUIRED/ENABLED/PREVIEW for (via `AiGridPredicateEngine`, a JSON predicate evaluator over facts, with per-tenant scope conditions/exceptions/parameters), producing PASS/FAIL/NO_DECISION/ERROR/NOT_APPLICABLE persistence decisions. Customer reporting derives four states from those values: PASS and FAIL are direct; OUT_OF_SCOPE, CAPABILITY_UNAVAILABLE, and NOT_APPLICABLE become NOT_ASSESSED; incomplete/stale evidence and collection errors become UNKNOWN. The derivation lives in `AiGridFindingService.AssessmentResult.deriveAssessmentState` and is reused by the latest per-policy state-summary API.
5. **Exposure correlation** (`AiGridExposureService`) — an R2-generation bounded graph-traversal engine running six correlation handlers (external sensitive-data access, excessive tool privilege, untrusted autonomous execution, external MCP sensitive access, MCP weak-auth execution, and sensitive retrieval control gap). Hypotheses are promoted to a **validated exposure** only when every supporting fact is exact, evidence-graded, and still fresh; `AiGridExposureFreshnessService` (60s cadence) demotes validated exposures whose supporting evidence has expired.
6. **Coverage & setup** (`AiGridReconciliationService`, `AiGridCoverageService`, `AiGridReadinessService`) — surfaces coverage gaps (unknown technology, no policy coverage, missing assessment, unresolved owner), materializes a deletion-safe "current epoch" view of the latest complete scan per scope, and generates a prioritized tenant setup-action queue. Framework reporting distinguishes breadth from effective coverage, reports PREVIEW separately, emits PARTIAL when only part of a control is decision-ready, and uses the shared platform tenant-visibility function rather than duplicating rollout SQL.
7. **Finding bridge** (`AiGridFindingService` / `AiGridExposureFindingService`) — promotes qualifying policy failures and validated exposures into the canonical `findings` table (`finding_kind = AI_POSTURE` / `AI_EXPOSURE`, `creation_source = AI_SECURITY`), reusing the same `FindingWorkflowService`, SLA logic, and ServiceNow incident creation as CVE findings — there is no separate AI finding table.

Static host-context evidence (from external CIEM/DSPM/ASM tools, or analyst attestation; runtime/activity families remain rejected) can be ingested via `AiGridEvidenceIngestionController` (`ROLE_SERVICE_ACCOUNT` only) and is tracked with confidence/evidence-class rules in `AiGridHostContextService` — it can promote a fact to "validating" status only under those rules, never unconditionally.

### Governance & Release Certification (platform-scoped)

A separate platform-owner-only track gates what AI Grid content ever reaches tenants, mirroring how NVD/GHSA feeds are trusted inputs but with an explicit sign-off step because policy false positives here can misdirect security teams:

- **Policy catalog & distribution** (`AiGridPolicyCatalogService`) — platform imports immutable policy/correlation *versions* into a catalog, then controls rollout via `platform.ai_grid_policy_distribution` (GA / canary / paused / retired, canary tenant list, pinned version). AI Grid is the only runtime authority.
- **Answer-key & precision review** (`AiGridValidationGovernanceService`) — a labeled test-case framework (`ai_grid_answer_key_*`) plus statistical (Wilson-interval) precision/bias review (`ai_grid_precision_reviews`) that a policy version must pass before it can be published.
- **Release certification** (`AiGridR1CertificationService`, `AiGridR2CertificationService`) — combines platform-computed evidence with externally attested operational gates into an immutable release manifest (`ai_grid_release_manifest_items`, update/delete blocked by a database trigger).
- **Portfolio** (`AiGridPolicyPortfolioService`) — reads the registered OWASP GenAI LLM Top 10 2026, OWASP Agentic Top 10 2026, and CSA AICM 1.1 control sets; computes tenant breadth/effective coverage for current or retained historical epochs; and maintains a RICE-scored intake backlog. Package grouping uses `release_family`, not an `AGCF-` naming convention. A mapping counts as effective only when its policy is distributed to the tenant, REQUIRED/ENABLED, applicable, and decision-ready; PREVIEW is visible but excluded from effective coverage.
- **Tenant policy configuration** — AI Grid owns selections, scopes, artifact overrides, and parameters; assessment reads only these governed records.

### Phase 1 Coverage Expansion Status

The infrastructure slice is implemented, but governed content review remains deliberately fail-closed:

- The platform V1 baseline registers framework versions/controls, typed runtime predicate fields, and one reusable tenant-visibility rule (available + GA, or tenant-listed CANARY/DEV). Catalog, selection, and coverage queries use that rule.
- Framework coverage separates mapped breadth from effective coverage, reports PREVIEW independently, includes applicable and decision-ready counts, emits PARTIAL where appropriate, and returns mapping type/rationale/selection/readiness/distribution detail. A paused policy is breadth without effective coverage and carries `POLICY_PAUSED_PENDING_EVIDENCE` rather than a fictional per-subject assessment.
- New mappings use `DIRECT`, `PARTIAL`, or `SUPPORTING`; legacy `INFORMATIVE` values remain readable as supporting compatibility data but should not be authored into new package versions. Mapping-level version comparison—not package-level uniqueness—is the intended grandfathering boundary.
- Runtime predicates are allowed to reference only fields in `platform.ai_grid_runtime_field_definitions`; JSONB diagnostics/extensions are not predicate inputs.
- The tenant V1 baseline includes approved agent-version manifests and component allowlists. Approve/revoke writes and the bulk-enable operation are admin-only sensitive actions. Bulk enable changes only effective selections, audits once, and refreshes projections only when data changed.
- Release compilation/validation resolves columns by COPY header, preserves existing package/distribution digests, and validates the legacy parity artifact structurally. The 21 live legacy policies are not certified for retirement until each row has an explicit successor or no-successor disposition plus evidence, fingerprint, and selection capture; the validator currently reports them as installed but unverified rather than guessing parity.

Program 1 exit also requires tenant schema rollout completion for Wave A tenants. This is separate from the Program 2 entry gate below.

### Operations: Budget, Cadence, and Retention

`AiGridBudgetService` enforces per-tenant daily scan/API-call/byte/processing-time budgets and scan-cadence throttling (new tenants start in an `OBSERVE`-only mode), raising `ai_grid_budget_alerts` on breach. `AiGridRetentionService` classifies evidence into HOT / ARCHIVE / RESTRICTED_EVIDENCE retention tiers, supports legal holds, and runs a purge sweep that leaves a durable audit trail (`ai_grid_retention_purge_audit`) even after the underlying snapshot bodies are deleted. Both are exposed to tenant admins via `AiGridOperationsGovernanceController` (`/api/ai-governance`).

Fresh disposable local fixtures contain no runtime history; preserve historical/shared evidence pending an authorized transition. The tenant V1 baseline carries no runtime execution data; `AiAgentExecutionRetentionService` keeps its `app.ai-security.runtime.retention-cron` trigger but returns immediately while `AiRuntimeScope` excludes runtime.

### Runtime detection deferred

Runtime collection, adapter admission, evaluation, readiness, execution APIs, graph overlays, and `AI_RUNTIME` findings are excluded from this release. All `AGCF-RT-*` distributions are unavailable/paused; tenant overrides are disabled. The tenant V1 baseline starts without runtime records; static policy definitions remain. The adapter scheduler performs no work. Details and rollout were in the runtime-exclusion doc, now archived outside the repo; external pilot shutdown is a separate operational runbook.

### Scheduled Jobs (AI Security / AI Grid)

| Cadence | Job |
|---|---|
| Every 3s (default) | `AiSecurityJobWorkerService` — poll `ingestion_jobs` for AWS, Azure, and Copilot Studio AI discovery jobs |
| Deferred | `AiGridRuntimeIngestionWorker` does not claim telemetry batches |
| Every 60s (default) | `AiGridExposureFreshnessService` — demote validated exposures with expired evidence |
| Daily 02:20 (default) | `AiSecurityAzureCredentialExpiryService` — sweep Azure AI credential profiles for expiry |
| Every 5s (default) | `AiGridPolicyRolloutService` / `AiGridPolicyDeprecationService` — process pending GA/canary distribution and deprecation tasks |

### Known Limitations (AI Security / AI Grid)

- All AI Grid/AI Security tables are accessed via `JdbcTemplate` directly — there are no JPA entities or Spring Data repositories for this module, unlike the rest of the backend.
- Azure discovery is newer and less battle-tested than AWS; a config-driven kill switch (`AiSecurityAzureKillSwitchService`) exists specifically to disable it per tenant/connector/resource-family/policy if needed.
- Macie and Purview integrations are strictly read-only against *existing* classification results — neither path ever triggers a new PII scan.
- `com.prototype.vulnwatch.web.PlatformAdminRequestPaths` (a request-path classifier added alongside recent platform-admin hardening work) has no call site anywhere outside its own unit test as of this writing — likely wired up incompletely; verify before relying on it.
- Runtime telemetry and detection are deferred. Historical policy packages and certification records remain for audit, but collectors, adapter admission, evaluation, and customer runtime surfaces are blocked. Reintroducing runtime requires a separately approved scope and fresh evidence qualification.

## Audit Trail

`AuditEvent` records capture state-changing operations:

- Actual `audit_events` columns: `occurredAt`, `tenant`, `actorUser`/`actorSubject`/`actorRole`, `action`, `targetType`, `targetId`, `requestId`, `sourceIp`, `outcome` (default `SUCCESS`), `detailsJson`
- Stored per tenant (`audit_events` in the tenant schema baseline)
- `RequestCorrelationFilter` injects `requestId` (plus HTTP method/path, tenant ID, actor ID/roles) into MDC

---

## Known Limitations

- GHCR attestation ingestion does not perform cryptographic signature verification.
- SCCM JDBC remains unavailable, including stale queued/manual/test paths; historical sweep code does not authorize collection.
- AWS Discovery is scoped to EC2 instances via SSM only.
- Generic Azure remains unavailable independently of the retained static Azure AI connector.
- S.AI Risk Score and S.AI Priority are computed entirely in the browser — not stored in the database.
- ServiceNow integration is read-heavy (finding → incident creation, then status polling) but not event-driven.
- Multi-tenant schema-per-tenant isolation is implemented (`TenantAwareDataSource`, `TenantSchemaService`, `ProductionSafetyValidator`) and default-tenant fallback does not authorize customer operations. `AiGridPolicyDeprecationService` uses the default tenant only as a platform deprecation audit destination. Row-level security policies are created on every provisioned tenant schema, but full RLS *enforcement* across existing production tenants remains gated behind `ProductionSafetyValidator.validateRuntimeRoleCannotBypassRls()` pending verification that the production/preprod database runtime role is non-superuser and lacks `BYPASSRLS`.
- AI Security / AI Grid (see above) — see its own "Known Limitations" subsection for module-specific caveats (JdbcTemplate-only data access, Azure kill switch, read-only Macie/Purview integration).
- `EntitlementShadowSweepService` computes comparison telemetry in SHADOW and ENFORCE; its existence does not establish the effective deployed mode. Deployed pilot startup requires ENFORCE plus an explicit cohort; corrected decisions use active override → plan → disabled default, with the same effective resolver in the UI snapshot. Outside the cohort legacy allow behavior remains. Wildcards are rejected.
- `FindingDeltaQueueService` has a second scheduled method (`recoverStaleProcessingEntriesOnSchedule`, 1 min by default) beyond the documented 2-second drain — it recovers queue entries stuck in `PROCESSING` after a worker dies mid-batch.

## Current workflow and qualification boundary

See [durable work and delivery](backend.md#durable-work-scheduling-and-delivery) for committed queue intent, attempt ownership/fencing, UTC role guards, bounded recovery and shutdown, and separate encrypted invitation/campaign outboxes. Automatic retry ends at the existing attempt/idempotency limits; UNKNOWN requires operator reconciliation. Provider acceptance is not inbox delivery. Fragment links/POST exchange, hashed invite storage, serialized rotation/acceptance and late-result checks retain current token/lifecycle authority.

Local archives remain unavailable before file access; canonical descriptions and raw payloads stay in PostgreSQL and historical files/references remain untouched. Bounded retention observes existing holds/references and progress/audit rules from the [cleanup matrix](<../Working Knowledge/AWS/PHASE_3_CLEANUP_MATRIX.md>); no additional period or destructive tenant purge is authorized.

**P30 containment:** unsupported Patch Management cards, detail mounts and mock form modules have been retired, removing their input/credential logging. Old query IDs/direct paths cannot mount them. Fix Intelligence and the live patch connectors (`patch-sccm`, `patch-intune`, `patch-bigfix`, `patch-tanium`) replaced them on tenant V9; unfinished tenant OSV/runtime paths retain their independent containment. See [repair evidence](<../Working Knowledge/AWS/DOCUMENTATION_RECONCILIATION.md#p30-frontend-repair>).

Packaged migration heads are platform V6 / tenant V5, with required tenant range V5–V5; next versions are platform V7 / tenant V6. Preserve every applied migration. The last observed deployed backend predates the reset baselines; actual deployed history and a data-preserving upgrade/rollback remain unverified. [Release qualification](<../Working Knowledge/AWS/PHASE_3_RELEASE_QUALIFICATION.md>) requires exact candidate/environment/result/date/reviewer evidence; local tests and reconciled prose do not close the formal register.
