# ScoutGrid application prerequisites: existing inconsistencies and remediation plan


Current source/documentation checkpoint (October 21): [documentation reconciliation and local P30 UI repair](DOCUMENTATION_RECONCILIATION.md). Original defect descriptions and day-zero instructions below record the October 17–18 assessment; use current reconciled runtime guidance for operational behavior. The formal register remains Open/Pending.

Local implementation checkpoint: [Phase 3 status and remaining qualification](PHASE_3_IMPLEMENTATION_STATUS.md). The original completion criteria below remain authoritative; a source change alone does not mark an item complete.
**Prepared:** October 17, 2026. **Scope revised:** October 18, 2026. **Reviewed source:** bd8ecf60cf21cbc56ed7de29fa23237e04d89bbc and the current workspace. **Status:** repair plan; Phase 1 and Phase 2 implementations are in the local workspace, with verification and release boundaries recorded below. No live deployment or configuration changes are recorded.

**Business-facing version:** [Plain-language requirements and acceptance criteria for all 36 items](AWS_APPLICATION_BUSINESS_REQUIREMENTS.md).

## Phase 1 implementation — October 20, 2026

The user authorized Phase 1 implementation, including its authorization and tenant-isolation changes. This covers P01, the urgent P02 containment slice, P03 and P25. Existing document moves and applied database migrations are preserved.

| Item | Local implementation | Regression evidence |
| --- | --- | --- |
| P01 | A shared four-role policy validates membership assignment, invitations, stored membership use and tenant-token issuance. Platform and machine roles cannot become membership roles. Legitimate owners retain selected-workspace access. | [Authorization flows](../../backend/src/test/java/com/prototype/vulnwatch/security/PhaseOneAuthorizationPostgresIntegrationTest.java), [token issuance](../../backend/src/test/java/com/prototype/vulnwatch/service/AuthTokenServiceTest.java). |
| P02 — urgent slice | Authentication uses current stored authority and cannot create owner grants from token claims. Current user/membership state overrides stale claims; inactive users are denied. Owner revocation removes equivalent stored aliases and the compatibility flag. User-row locking and selective profile updates protect concurrent revocation. | [Old credentials, aliases and concurrent revocation](../../backend/src/test/java/com/prototype/vulnwatch/security/PhaseOneAuthorizationPostgresIntegrationTest.java), [JWT authentication](../../backend/src/test/java/com/prototype/vulnwatch/service/JwtTenantAuthenticationServiceTest.java). |
| P03 | AWS, Azure, ServiceNow and SCCM active/latest/status queries use the customer ID. Admission locks the existing customer connector configuration before checking active work or the schedule. Shared intelligence-feed queries are unchanged. | [Real PostgreSQL isolation, scheduling and contention](../../backend/src/test/java/com/prototype/vulnwatch/service/ConnectorSyncTenantScopingPostgresIntegrationTest.java). |
| P25 | Invalid content is checked before asset/source changes; checked failures roll back a document's changes. Existing byte/component ceilings reject excess explicitly. Remote endpoint responses are bounded while reading. GitHub batches preserve accepted documents independently of rejected siblings, including queued execution. | [Upload rollback](../../backend/src/test/java/com/prototype/vulnwatch/service/BomUploadRollbackPostgresIntegrationTest.java), [batch compatibility](../../backend/src/test/java/com/prototype/vulnwatch/service/GithubBatchRollbackPostgresIntegrationTest.java), [input limits](../../backend/src/test/java/com/prototype/vulnwatch/service/BomInputBoundsTest.java). |

Local verification on October 20 passed against changed-source snapshot `2b834f5a6cba7cdb688c9e27af80e3fed9a570000c0bb5fe46a12068f17cd7f7`: backend `mvn -q -o verify` (1,211 passed, five existing OSV skips; coverage and SpotBugs passed), the complete PostgreSQL profile (364 passed, no skips), and frontend lint/typecheck/build/coverage (650 tests passed). Migration guards, secret scanning and diff checks also passed. Verification used disposable source copies/databases and controlled provider responses; all 1,419 backend source/test files matched those copies. This records local code verification and does not mark the release register Verified.

Before release, review existing owner grants and compatibility flags against approved owners, preserve evidence and remove confirmed unauthorized access through the authorized administrative process. Code cannot determine whether an existing grant was created legitimately or by the old vulnerability. Live review, deployment and effective-environment checks remain outstanding; full P02, later phases and pilot re-enablement remain separate work. The changes do not enable disabled capabilities.

P25 preserves the current 50 MiB BOM-byte ceiling, 100,000-component boundary and configured remote-endpoint ceiling (default 5 MiB). The existing multipart/request setting remains unchanged. GitHub API envelope buffering, provider-wide retrieval qualification and production-scale capacity claims are not established by the endpoint-streaming tests.

## Phase 2 implementation — October 20, 2026

The user authorized a new branch and the next phase of fixes. Branch `codex/application-prerequisite-fixes` retains Phase 1 and implements the remaining M1 slice: P02, P04–P09, P15, P22, P30 and P33. Authorization covers the necessary authentication, tenant isolation and build/deployment configuration source changes. It does not authorize live credential rotation, data migration or deployment.

| Item | Local behavior and containment | Evidence entry points |
| --- | --- | --- |
| P02 | Support access requires current stored platform ownership; grant acceptance/revocation serialize. Local sign-in cannot reactivate a disabled identity through an email alias. Old and freshly issued credentials obey current membership, support and user state. | `PhaseOneAuthorizationPostgresIntegrationTest`, `LocalCredentialAuthServiceTest`. |
| P04 | Invalid environment/runtime roles and unsafe production combinations fail before runners or requests execute. Production validation cannot be switched off. | `RuntimeConfigurationValidatorTest`, `ProductionSafetyValidatorTest`, `BackgroundTaskExecutionPolicyTest`. |
| P05 | New provider credentials use versioned AES-GCM; both invitation types store hashes and serialize acceptance/reissue/cancellation. New invitation/setup links use fragments and POST exchange. Old path links require reissue. Additive platform V2 / tenant V3 converts hashes and clears raw invitation values. An offline, explicit-database migration tool provides bounded dry-run/apply/rekey and readback verification. | `CredentialEncryptionServiceTest`, `InvitationTokenPostgresIntegrationTest`, `PhaseTwoUpgradePostgresIntegrationTest`, `SharedInvitationMigrationOwnerPostgresIntegrationTest`, `ProviderCredentialMigrationPostgresIntegrationTest`, invitation frontend tests. |
| P06 | Client identity uses the direct peer and an explicit trusted-proxy chain; public flows have separate global budgets. Existing per-address/email login controls remain. Counters remain process-local. | `PublicEndpointRateLimiterTest`, `PublicEndpointRateLimiterIsolationTest`. |
| P07 | Customer AWS discovery requires a role matching the configured account and a server-issued ExternalId. Admission and execution validate the binding and STS account before enumeration; existing unbound configurations migrate to disabled. | `AwsCustomerBindingTest`, `AiSecurityAwsCredentialBindingTest`, connector tests. |
| P08 | GitHub runs use an explicit customer credential or deliberate anonymous scope; missing GHCR credentials fail clearly. ServiceNow cannot inherit platform/global credentials. SCCM live JDBC is **Contained—disabled** at configuration, test, admission, worker and query boundaries; no mock inventory replaces it. | `GithubTokenProviderTest`, `GithubSbomSourceServiceTest`, `ServiceNowCredentialIsolationTest`, `SccmPilotContainmentTest`, connector PostgreSQL tests. |
| P09 | The socket resolver validates the actual destination addresses; redirects are disabled. IPv6/special-address checks and Azure continuation destination/page/time/byte bounds fail explicitly. OSV/MSRC failures remain unavailable rather than empty clean evidence. | `OutboundHostPolicyTest`, `CheckedOutboundRequestFactoryTest`, `AzureDiscoveryClientTest`, `OsvApiClientTest`. |
| P15 | Tenant switches inside active transactions fail; same-customer nesting remains valid. Direct document ingestion selects context before its transaction and retains per-document rollback and asset locks. Findings analytics delegates transaction ownership to its tenant-scoped projection query. Failed reset, partial context initialization and aborted transactions discard the physical pooled session. | `TenantSchemaExecutionServiceTest`, `TenantAwareDataSourceTest`, `TenantConnectionCleanupPostgresIntegrationTest`, existing upload and batch rollback tests. |
| P22 | Administrative customer deletion is **Contained—disabled** before reads or mutations at all existing service/controller entry points; UI explains the restriction. Normal demo expiry continues. Full shared-user-safe purge remains deferred. | `TenantDeletionPostgresIntegrationTest`, `DemoTenantPurgePostgresIntegrationTest`, `DemoTenantPurgeServiceTest`, `PlatformConsolePage.test.tsx`. |
| P30 | Synthetic Fix Intelligence and unfinished tenant OSV correlation are **Contained—disabled** on the server and UI. Shared intelligence feeds remain supported. Runtime AI collection remains independently excluded. | `UnfinishedCapabilityBoundaryTest`, `OsvTenantServicePostgresIntegrationTest`, frontend navigation tests. |
| P33 | Production builds reject static authentication inputs and scan emitted bundles. Default PII is disabled; telemetry scrubs invitation/setup URLs, requests, user fields and nested error/breadcrumb payloads. | `production-auth-policy.test.mjs`, `telemetryPrivacy.test.ts`, production sentinel build checks. |

**Verification:** local checks passed on October 20 against source snapshot `13c9294bbff624e0aade69d7f37be56037823e0e281460753d77315a03883af3`: backend `mvn -q -o verify` (1,257 passed, five existing OSV skips; coverage and SpotBugs passed); 381 PostgreSQL checks across 87 classes (the full run plus focused reruns after fixture/caller corrections); frontend lint/typecheck/build/coverage (657 passed); production credential/JWT sentinel checks; migration guards, scoped source secret scanning and diff checks. All backend production files match the passing unit-build copy; the evidence manifest covers 1,758 source/configuration files, with no application-source differences from the applicable verification copies. The isolated PostgreSQL server was stopped after verification. Evidence includes baseline failures, confirmed candidate-review findings, final class results and a source manifest. The register stays Open / Pending until its required commit, environment, reviewer and release evidence are recorded. These changes are not a deployed release or completion of P36.

**Release prerequisites:** run the additive migrations through the authorized bootstrap process; reissue legacy invitation/setup links; migrate/rekey retained provider secrets with a separately authorized migration role; reconnect old AWS configurations; configure the actual trusted proxy CIDRs; and review historical owner grants and potentially active local token material without exposing values. Keep prior encryption keys available for retained jobs and backups until their conversion/recovery has been qualified. No live operation is recorded here.

The offline entry point is `com.prototype.vulnwatch.tools.ProviderCredentialMigrationTool`. It accepts `--dry-run` (default) or `--apply`, requires explicit `DB_URL`, `EXPECTED_DB_NAME`, `DB_USERNAME`, `DB_PASSWORD` and `APP_CREDENTIAL_ENCRYPTION_KEY`, and supports `APP_CREDENTIAL_ENCRYPTION_KEY_ID` / `APP_CREDENTIAL_ENCRYPTION_PREVIOUS_KEYS`. It refuses an unexpected database or a role without separately authorized RLS-bypass privileges. It processes at most 100 rows per transaction, verifies rewritten secrets before commit and prints counts only. Run it through the authorized maintenance process, separately from the application runtime; these local tests exercised disposable databases only.

**Deferred containment ownership:** backend/product own SCCM JDBC, synthetic Fix Intelligence and tenant OSV re-enablement, and platform/backend own administrative purge. Revisit only through a separately reviewed implementation and the corresponding acceptance checks. Process-local rate limits still need effective replica/ingress qualification. Database TLS remains P27/M2; P33 covers browser credentials and telemetry.

## Scope and completion boundary

This plan fixes **existing application inconsistencies** in the current Java/React/PostgreSQL application on Render/Vercel. Its location in the AWS documentation folder is historical. Completion means the identified behavior is corrected or explicitly contained and regression evidence passes; it does **not** mean AWS deployment or full enterprise production readiness is complete.

In scope: current authorization, tenant isolation, credentials, invitation exposure, connector identity binding, transaction correctness, existing jobs/schedules, ingestion limits, lifecycle, configuration, safe exports and truthful status/telemetry. Small internal mechanisms such as transactional intent or lease fields are allowed when needed to correct these existing failures; new product capabilities and platform migrations are not.

Out of scope: Cognito/user-pool integration, new browser-cookie/session/workspace architecture, SES or custom-sender Lambda, S3 adapters/buckets, AWS IAM/resource provisioning, IaC, ECS/ALB/RDS/CloudFront implementation, deployment/cutover, new public delivery/bounce webhooks, private collectors, new machine authentication, SAML/SCIM/MFA implementation and a new recommendation provider. The earlier Cognito/server-session preference remains a future architecture decision; it is not a dependency of this repair program.

Correcting the **existing AWS connector** remains in scope: tenant credentials, server-generated ExternalId, account/role checks and tests against controlled provider doubles. Creating AWS resources or customer onboarding stacks does not. Likewise, preserve correct TLS options for the current database and its actual trust anchors; do not introduce RDS-specific certificates or settings.

The 36 IDs are retained for traceability. Only each entry's scoped repair is covered here. Closing that repair must not close broader migration/compliance obligations in the related backlog. Preserve user document moves and current databases; use disposable databases for destructive tests and additive migrations after platform V1 / tenant V2.

## Day-zero containment

These are immediate containment tasks on the current application. **This document records proposed actions; no live settings have been changed or approved by this document.** Record the owner, effective environment, evidence, time, and residual exposure for each action. Distinguish an operator pause from an enforced server block. Existing queued/running work and already issued credentials or invitations must be checked separately; changing admission settings does not automatically cancel them.

| Action and owner | Available mechanism today | Verification and closure |
|---|---|---|
| **Verify API-key authentication is off — security/backend + operator (P04).** | `APP_ALLOW_API_KEY_AUTH=false` is already declared in [render.yaml](../../../render.yaml); [application-prod.yml](../../backend/src/main/resources/application-prod.yml) also disables it. Verify the effective deployed profile/property instead of treating the committed setting as evidence of live state. | Record effective configuration without exposing credentials; verify API-key-only requests cannot authenticate and intended browser authentication still works. Close containment only with evidence from the affected environment. |
| **Pause new demo approvals — platform owner (P01).** | Stop owner approvals and invitation/setup-link issuance operationally. There is no dedicated approval-disable flag in [DemoLifecycleController](../../backend/src/main/java/com/prototype/vulnwatch/controller/DemoLifecycleController.java) (`approve`, lines 83–92). [DemoLifecycleService](../../backend/src/main/java/com/prototype/vulnwatch/service/DemoLifecycleService.java) grants `TENANT_ADMIN` at line 462. | Record the pause and review outstanding invitations and existing admin access. This limits new exposure; it does not fix P01 or revoke existing access. Verified server enforcement requires a narrow endpoint guard or the P01 fix. |
| **Stop tenant deletion — platform owner + backend (P22).** | Operationally stop `DELETE /api/platform/tenants/{tenantId}`. No purge-disable property exists; see [TenantAdministrationController](../../backend/src/main/java/com/prototype/vulnwatch/controller/TenantAdministrationController.java), lines 163–166. Add a narrow server refusal if the endpoint remains reachable. | Verify deletion requests fail before any mutation. Preserve normal demo expiry: [DemoTenantPurgeService](../../backend/src/main/java/com/prototype/vulnwatch/service/DemoTenantPurgeService.java) `processExpiredTenant`, lines 53–61, only marks expiry. Do not disable all scheduling to contain manual deletion. |
| **Establish generative-AI-off — backend + operator (P31).** | Set `OPENAI_ENABLED=false`, but do not claim this alone blocks every call. [OpenAiClient](../../backend/src/main/java/com/prototype/vulnwatch/client/http/OpenAiClient.java) honors it; [CveInvestigationAiSummaryService](../../backend/src/main/java/com/prototype/vulnwatch/service/CveInvestigationAiSummaryService.java) bypasses it at lines 191–202 and accepts key aliases at lines 222–229: `app.openai.api-key`, `OPENAI_API_KEY`, `openai_API_KEY`, `openai.api.key`. Pending the shared guard fix, remove every effective key source/revoke a dedicated key or restrict that endpoint through a verified control. | Exercise every generative entry point with outbound stubs and assert zero provider transmissions. Verify honest deterministic fallback or an explicit unavailable response. Keep static AI inventory and deterministic assessment available. |
| **Contain generic Azure discovery — backend + operator (P17).** | Disable saved generic connector/auto-sync settings as partial containment. There is no global generic-Azure flag. [AzureDiscoverySyncService](../../backend/src/main/java/com/prototype/vulnwatch/service/AzureDiscoverySyncService.java) checks enabled for ordinary sync, but target sync at lines 106–113 and target resolution at 265–270 bypass those checks. `APP_AI_SECURITY_AZURE_ENABLED` governs a separate AI Azure implementation. | Add/verify one server gate covering configuration changes, tests, ordinary/target manual sync, scheduled admission and queued execution. Verify blocked paths make no provider calls and cannot mark existing assets inactive. Record treatment of already running work. |

## Assisted-pilot decisions

These defaults are the planning baseline, not permission to mutate live configuration. A disabled feature is complete for the pilot only when server admission, workers, UI messaging and regression evidence agree; its deferred full repair remains tracked. Record any deviation with its owner and replacement acceptance criteria.

| Decision and owner | Default and bounded prerequisite |
|---|---|
| **SCCM live JDBC — backend/product (P08).** | Disable for the pilot. No global switch exists. Saved `enabled=false` stops normal sync, but [SccmCmdbConfigService](../../backend/src/main/java/com/prototype/vulnwatch/service/SccmCmdbConfigService.java) connection test at lines 72–76 still connects, and save can re-enable at line 173. Guard save/test/sync and queued execution server-side. `SCCM_MOCK_MODE` is fallback configuration, not a kill switch; do not substitute fixtures for customer ingestion. Verify zero JDBC connection attempts while disabled. This does not close the other P08 credential/host-policy defects. |
| **Local archive — backend/product (P24).** | Disable archive migration for the pilot; retain inline database descriptions and payloads. There is only `ARCHIVE_LOCAL_PATH`, no enable flag. The write callsite is the operator [archive migration endpoint](../../backend/src/main/java/com/prototype/vulnwatch/controller/VulnerabilityArchiveController.java), lines 44–46. Pause that operation now; implement a small explicit disabled mode and honest read-unavailable behavior. Verify ingestion keeps inline content and disabled migration creates no files or archive keys. |
| **Generative AI / generic Azure — backend/product (P31/P17).** | Off for the pilot. Re-enablement is a separate explicit decision after the containment and retained-repair checks pass; passing a test does not automatically turn either feature back on. Preserve deterministic AI assessment and the independently implemented static AI Azure capability unless its own finding requires containment. |
| **Entitlement mode — backend/product (P29).** | Use `APP_ENTITLEMENTS_MODE=ENFORCE` for an explicitly named pilot cohort after its entitlement matrix passes regressions; populate the existing enforce-tenant allowlist with those tenants. Use SHADOW only during characterization, not as the final pilot restriction. Do not assume an empty cohort or wildcard is the intended configuration. [TenantEntitlementService](../../backend/src/main/java/com/prototype/vulnwatch/service/TenantEntitlementService.java), lines 61–68 and 157–195, shows `LEGACY` and `SHADOW` permit all entitlements; `ENFORCE` applies only to its allowlist (`*` means all). SHADOW is characterization, not feature denial. Verify allowed and denied server requests plus matching UI state for the chosen cohort. |
| **Unfinished capabilities / audit export — product/backend (P30/P34).** | Keep unfinished OSV tenant correlation, synthetic Fix Intelligence and excluded runtime surfaces disabled. Retain audit export and apply the existing safe-CSV encoding pattern; temporarily block CSV only if that small fix cannot ship safely, retaining authorized JSON access. No new capability, billing system or audit storage is required. |

## Milestones and delivery priority

Day-zero containment starts immediately when separately authorized for the affected environment. It is an overlay across milestones, not another large implementation project. The milestone register retains all 36 IDs; a disabled surface can reach **Contained—disabled** for the pilot while its full repair remains deferred.

| Milestone | Owned prerequisites | Required outcome |
| --- | --- | --- |
| **M1 — Immediate security and data-integrity fixes** | P01–P09, P15, P22, P25, P30, P33 | Independent P01 hotfix; immediate old-token/grant containment; tenant-safe runs, credentials and connections; invitation protection; rejected-upload rollback; unsafe exposed paths contained. |
| **M2 — Existing behavior and recovery consistency** | P10–P14, P16–P21, P23–P24, P26–P29, P31–P32, P34–P35 | Retained processing, schema lifecycle, authentication modes, evidence and cleanup agree with committed state; pilot-disabled capabilities remain blocked. |
| **M3 — Regression qualification and evidence** | P36 | Relevant current-stack checks pass with repair/containment evidence and explicit deferred requirements. |

### First release: P01-HF, without a full P02 dependency

Ship a **P01-only bounded hotfix**, provisionally **about one engineer-day** within the S band, including focused full-filter tests and review. Enforce a tenant-role allowlist at every membership-writing boundary and reject global/system/unknown roles when consuming stored memberships or issuing tenant credentials. Preserve legitimate platform-owner grants and normal tenant access. Do not wait for the complete P02 authorization-version/revocation program or unrelated credential/network work.

A membership-only patch blocks new escalation through that path; it does not invalidate already elevated JWTs or remove persisted global grants. In parallel, review stored membership/global grants and the compatibility owner flag, preserve evidence, and establish which issued credentials must be rejected. Deliver the **narrow P02 slice that stops JWT-driven grant recreation and rejects stale elevated authority**, or a verified restriction of affected access, before calling the privilege boundary contained. Record that slice under P02 rather than expanding P01 into a weeks-long redesign. Full P02 remains separately releasable. If the one-day target cannot be met safely, retain containment and report the concrete blocker; do not omit tests to meet it.

P03 and P25 should also ship as small independent fixes. P15 moves to M1 because tenant connection cleanup affects isolation. P11's cross-transaction publication fix remains M2, with affected mutating paths restricted in M1 where needed. No exposed path waits uncontained merely because its complete repair belongs to M2.

### Delivery tiers, separate from severity

Severity describes potential impact. Delivery tier orders retained repairs after day-zero restrictions; it does not reduce a security finding's severity. All IDs are assigned exactly once below and in the register.

| Tier | IDs | Execution rule |
| --- | --- | --- |
| **1 — Privilege, tenant isolation and exposed security boundaries** | P01–P09, P15, P27–P28, P33 | P01-HF first, then current-credential/grant containment and tenant isolation. Triage credential, configuration, outbound and telemetry exposure in parallel. Retained affected operations stay restricted until their applicable boundary passes. M2 authentication/support qualification does not postpone immediate containment. |
| **2 — Data integrity, accepted work and lifecycle correctness** | P10–P14, P16–P23, P25–P26, P32 | Prioritize rejected-upload rollback, unsafe deletion and source/event atomicity, then ownership/recovery, feed coverage and lifecycle dependencies. Disabled generic Azure does not require rebuilding it before the pilot. |
| **3 — Contained/supporting behavior and release qualification** | P24, P29–P31, P34–P36 | Complete agreed disablement, entitlement configuration, safe export, honest metrics and integrated qualification. P30/P31 restrictions still start on day zero; Tier 3 is not permission to leave unsupported or generative paths exposed. |

### Effort, dependencies and schedule reconciliation

Provisional bands include the regression work for the scoped outcome: **S = 1–3 engineer-days**, **M = 3–7 engineer-days**, **L = 5–15 engineer-days** (one to three working weeks). Split large IDs into bounded PRs; do not apply a full ID's band separately to every PR. Named discovery outputs below must precede estimates for uninspected subpaths. P01 is now S for its bounded hotfix, and P24 is S for the selected archive-disable path. Other bands remain provisional; disabling one subfeature does not erase the rest of its ID.

| Estimate basis | S / M / L counts | Low / midpoint / high engineer-days | Three engineers at five fully productive days/week |
| --- | --- | --- | --- |
| Previous register, before this execution revision | 3 / 21 / 12 | 126 / **231** / 336 | 8.4 / **15.4** / 22.4 idealized weeks |
| Current scoped register, after P01/P24 sizing changes | 5 / 19 / 12 | 122 / **225** / 328 | 8.1 / **15.0** / 21.9 idealized weeks |

The previous midpoint was about 11.6 engineer-months at 20 days/month; the current arithmetic is about 11.3. Neither total is a validated forecast. Shared job/auth changes and final qualification may overlap estimates; confirmed disablement can reduce work, while serial dependencies, review, operations and interruptions increase elapsed time. Do not add overlapping implementation or integration tests twice. Re-estimate by work package after the pilot defaults, inventories and bounded execution design are mapped to concrete PRs.

The earlier **12–14-week GA estimate** was an unvalidated hypothesis for a different scope. It is superseded as a current scheduling basis: even this register's midpoint consumes about **15 idealized weeks with three engineers before separate platform work**. This does not establish a four-month delivery commitment, a requirement to finish every deferred full repair before AWS planning, or an updated GA date. Staffing/start date and a de-duplicated critical path remain unconfirmed.

| Sequence / parallel lane | Dependency and exit |
| --- | --- |
| Immediate authorization | P01-HF independent; narrow P02 old-token/grant containment alongside it; complete P02 follows. |
| Parallel urgent repairs | P03, P25 and current configuration/credential restrictions proceed independently. Coordinate P05/P33 invitation and telemetry contracts. |
| Tenant isolation / lifecycle | Prioritize P15 containment/repair. P19/P20 then establish tested bootstrap/grants; P21/P22/P23 use those boundaries. Keep purge blocked until its applicable checks pass. |
| Existing durable work | One integration owner coordinates the bounded design below before overlapping changes; P10 role guards may ship independently. |
| Pilot features | Apply the explicit defaults above, then finish retained P08/P17/P24/P29–P34 behavior and qualified disabled paths. |
| Qualification | P36 verifies completed repair slices and containment. Deferred connector re-enablement or AWS implementation is not silently added to this program. |

### Bounded design: consistency of existing background work

One backend integration owner coordinates P10/P11/P12/P14/P18, with P32 sharing delivery conventions. Keep their separate IDs, acceptance criteria and reviewable PRs. This repairs retained PostgreSQL processing paths; it does not introduce a broker, generic workflow framework, replacement queue or new execution service.

Reference existing mechanisms: [tenant-scoped transaction boundaries](../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java), [finding delta queue](../../backend/src/main/java/com/prototype/vulnwatch/service/FindingDeltaQueueService.java), and [assessment outbox claims, leases and commit fencing](../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridAssessmentWorker.java). Reuse relevant patterns without moving unrelated job families into one abstraction.

**Contracts to record before overlapping implementation:**

- **Scope and dispatch:** inventory retained producers, consumers, tables and accepted responses. Select tenant context before acquiring a transaction connection. Validate existing runtime roles; pollers/startup callbacks honor them. Accepted work must have recoverable committed intent; an executor callback is only a wake-up optimization. Preserve synchronous upload responses and manual assessment polling.
- **Publication and admission:** source changes and their required event/job intent commit together; rollback publishes nothing. Finding enqueue joins the source transaction; consumer claim/acknowledgment remains separate. Serialize each tenant's configured capacity decision with admission/claim, then atomically update source/run/job state. Specify one capacity/source/job lock order for these affected paths before implementation and use it consistently; preserve unrelated existing resource lock ordering. Conflict-safe deduplication returns the existing logical job without querying an aborted transaction. Scheduled quota denial leaves work eligible and continues independent tenants/sources.
- **Ownership and completion:** claim only supported types. Each recoverable attempt has an ownership token, bounded lease and heartbeat; reclaim only expired attempts. Check ownership in the same transaction as domain mutations and final state, so an expired owner cannot commit late changes. Starting another process cannot reset healthy work. Committed success stays terminal; later audit/metric failures have separate visible retry/failure state.
- **Retry and shutdown:** retries preserve logical identity and avoid duplicate effective database changes; do not claim exactly-once external effects. Stop new claims on shutdown, finish/checkpoint owned work within configured bounds, and leave interrupted accepted work recoverable. Rollout follows its accepted assessment request and rechecks release binding.
- **Email:** P32 uses committed intent, immutable logical delivery identity, bounded retries and honest provider acceptance. Keep platform invitation and tenant campaign scope explicit; do not force one cross-scope outbox/table/consumer. Hash invitation records and encrypt retry-required bearer payloads. Preserve provider idempotency boundaries and reconcile unknown acceptance outside them.

**PR order:** deliver P10 role guards independently; coordinate P11 publication with P18 capacity/dedupe; establish P12 ownership before relying on P14 shutdown/recovery; implement P32 separately against the agreed conventions.

**Required discovery artifacts:** P13 produces a schedule matrix: entrypoint, enablement/role, scope, time zone, existing claim/dedupe/lock, duplicate effect, restart behavior and disposition. P26 produces a cleanup matrix: category, configured policy, entrypoint, batch/transaction bounds, hold/reference/replay checks, audit and retry/overlap behavior. Estimate uninspected repairs after those outputs; the known unbounded retention query can proceed independently.

**Proposed checks, not existing tests:** PostgreSQL barrier tests for commit/rollback visibility, quota-boundary admission, dedupe conflicts, lease expiry/late-owner fencing and terminal-success reporting; a scheduler overlap check for same-occurrence deduplication and independent progress; cleanup batch/hold/resume checks; shutdown fault injection. Separately record current Render service roles/replica counts. Mock-only tests cannot establish these transactional properties.

### Implementation approval gates

The [repository rules](../../CLAUDE.md) explicitly say **“Never-touch list (require explicit approval before changing)”** (lines 395–402). Record the protected change scope and applicable human authorization in each implementation ticket/PR before editing it. Existing explicit authorization covering that scope satisfies the gate; do not request it repeatedly. This document update authorizes planning changes, not protected implementation or live operations. Read-only investigation and documentation can continue.

- **A** — authentication/authorization, including service decisions as well as security filters.
- **T** — tenant scoping/context/isolation.
- **D** — deployment/build infrastructure, Dockerfile and workflows; include the change in the PR description.
- **O** — operator scripts touching running databases or production-like state. A frontend build verifier is not O merely because it lives in `scripts/`.
- **G** — golden contract fixture hashes, only when actually changed; justify the contract change. This is conditional for every ID.

Each detail entry names its applicable gates: **!** means inherent in the scoped repair, **?** means conditional on the actual patch, and **—** means no inherent category. Gates describe protected scope; they do not require editing a particular file. For example, P01 service changes are authorization changes even without a SecurityConfig edit; P24's disabled path does not require a Dockerfile edit. Confirm conditional gates from the concrete patch. Applied migrations remain immutable: use additive migrations, and never infer shared-database reset permission from a gate approval.

## Tracking and preserved contracts

- **Critical:** source path to platform-wide privilege. **High:** material security, integrity, reliability or required control risk. **Moderate:** narrower hardening. Severity is potential impact; the delivery tier controls sequencing. Source findings do not establish deployed exposure, network reachability, credential transmission or observed abuse. Evidence limitations apply throughout; see Appendix A.
- **Basis:** Code is source-established behavior; Config requires actual configuration verification; Qualification is a required proof; Decision is limited to retaining or disabling a broken/unfinished existing surface.
- Start **Open / Pending**. Use **Verified** only with commit, environment, test/run result, date and reviewer. Use **Contained—disabled** with server/UI proof and an owner/revisit trigger. Partial implementation remains Open. No application issue is marked fixed by this documentation update.
- Retain current upload success/error interfaces while fixing rollback, bounded consumption and completeness. A new 202 upload/artifact-store design is excluded. Existing asynchronous fetch/job interfaces remain supported.
- Preserve manual AI policy execution and its frontend pending/running polling. Fix the rollout worker's terminal-state assumption; collection status and assessment status are distinct.
- Preserve existing configured quotas and expose their effective values in tests. Source defaults are one queued/running admission per tenant and ten admissions per 300 seconds; these are not measured capacity or proof of deployment settings. Remove the previous plan's invented five-pending policy.
- Verify current 50 MB multipart / 50 MiB BOM-byte checks and the 100,000 categorized-component boundary without silent truncation. Profile realistic rich documents at their effective byte/component limits. A lower safety bound needs measured justification and an explicit config/release change, not an assumed 10 MiB/25,000-component platform policy.
- Retain existing stricter route/coverage checks. New tenant-count, commercial SLA, RPO/RTO, retention/deletion and SOC 2 promises are not acceptance criteria for this repair program.

Owners: **B** backend, **UI** frontend, **P** platform/operations, **S** security, **Q** quality/reliability, **F** founder/product. Prior task IDs link to [the migration register](<AWS_production-migration-backlog.md>) for context only; that broader backlog does not expand this plan.

### Scoped prerequisite register

| ID / detail | Existing issue | Severity | Tier | Milestone | Owner | Effort | Status | Completion evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [P01](#p01) | Tenant/global role boundary | Critical | 1 | M1 | B, S, Q | S | Open | Pending |
| [P02](#p02) | Revocation and inactive users | High | 1 | M1 | B, S, Q | L | Open | Pending |
| [P03](#p03) | Tenant-scoped sync runs | High | 1 | M1 | B, Q | S | Open | Pending |
| [P04](#p04) | Fail-closed current configuration | High | 1 | M1 | B, P, S | M | Open | Pending |
| [P05](#p05) | Secrets and all invitation tokens | High | 1 | M1 | B, S, P | L | Open | Pending |
| [P06](#p06) | Trusted caller identity | High | 1 | M1 | B, P, S, Q | M | Open | Pending |
| [P07](#p07) | Existing AWS credential binding | High | 1 | M1 | B, P, S, UI | M | Open | Pending |
| [P08](#p08) | Connector credential isolation | High | 1 | M1 | B, S, F | M | Open | Pending |
| [P09](#p09) | Outbound address/request safety | High | 1 | M1 | B, S, Q | L | Open | Pending |
| [P10](#p10) | Existing dispatch and rollout status | High | 2 | M2 | B, P, Q | L | Open | Pending |
| [P11](#p11) | Atomic source/event/job intent | High | 2 | M2 | B, Q | L | Open | Pending |
| [P12](#p12) | Owned interruption recovery | High | 2 | M2 | B, Q | L | Open | Pending |
| [P13](#p13) | Recurring-work coordination | High | 2 | M2 | B, Q | M | Open | Pending |
| [P14](#p14) | Stable results and external effects | High | 2 | M2 | B, Q, P | M | Open | Pending |
| [P15](#p15) | Tenant connection cleanup | High | 1 | M1 | B, S, Q | L | Open | Pending |
| [P16](#p16) | Feed watermark and pagination | High | 2 | M2 | B, Q | L | Open | Pending |
| [P17](#p17) | Incomplete evidence handling | High | 2 | M2 | B, Q | M | Open | Pending |
| [P18](#p18) | Existing quota and dedupe races | High | 2 | M2 | B, P, Q | L | Open | Pending |
| [P19](#p19) | Current DB grants and TLS | High | 2 | M2 | B, P, S, Q | M | Open | Pending |
| [P20](#p20) | Bootstrap/report consistency | High | 2 | M2 | B, P, Q | M | Open | Pending |
| [P21](#p21) | Activation after grants | High | 2 | M2 | B, P, Q | M | Open | Pending |
| [P22](#p22) | Shared-user-safe deletion | High | 2 | M1 | B, P, S, Q | M | Open | Pending |
| [P23](#p23) | Tenant compatibility and readiness | High | 2 | M2 | B, P, Q | L | Open | Pending |
| [P24](#p24) | Truthful local archive behavior | High | 3 | M2 | B, P, Q | S | Open | Pending |
| [P25](#p25) | Upload rollback and bounds | High | 2 | M1 | B, UI, Q | M | Open | Pending |
| [P26](#p26) | Existing cleanup/hold bounds | High | 2 | M2 | F, B, P, S | M | Open | Pending |
| [P27](#p27) | Existing authentication-mode consistency | High | 1 | M2 | B, UI, S | M | Open | Pending |
| [P28](#p28) | Existing support/machine boundaries | High | 1 | M2 | B, S, UI, Q | M | Open | Pending |
| [P29](#p29) | Explicit entitlement behavior | High | 3 | M2 | F, B, Q | M | Open | Pending |
| [P30](#p30) | Truthful capability scope | High | 3 | M1 | F, B, UI, Q | S | Open | Pending |
| [P31](#p31) | AI-off and evidence controls | High | 3 | M2 | B, S, F, Q | M | Open | Pending |
| [P32](#p32) | Existing email delivery consistency | High | 2 | M2 | B, P, Q | L | Open | Pending |
| [P33](#p33) | Frontend and telemetry credentials | High | 1 | M1 | UI, S, Q | M | Open | Pending |
| [P34](#p34) | Safe CSV and audit privileges | Moderate | 3 | M2 | B, S, Q | S | Open | Pending |
| [P35](#p35) | Truthful metric freshness | High | 3 | M2 | B, P, Q | M | Open | Pending |
| [P36](#p36) | Repaired-release qualification | High | 3 | M3 | Q, B, UI, P, S, F | L | Open | Pending |

## A. Existing authorization, credentials and network boundaries

<a id="p01"></a>

### P01 — Separate tenant roles from platform authority

**Severity:** Critical · **Milestone:** M1 · **Owner:** B, S, Q · **Effort:** S

**Delivery tier:** 1 · **Implementation gates:** A!

**Basis:** Code. **Previous tasks:** T28–T30/T61.

Tenant-admin member creation/update accepts role strings without enforcing the tenant-role allowlist. ACTIVE membership roles subsequently become authenticated authorities. Approved demo provisioning assigns TENANT_ADMIN, but an anonymous demo request alone does not provide authenticated access.

**Fix:** ship P01-HF independently: use the tenant-role allowlist at membership create/update/invite/activation and all equivalent write paths; reject global/system/unknown membership roles at stored-role consumption and tenant-token issuance. Keep global-role administration separate from tenant-role normalization and preserve legitimate owner access. Prove platform authority cannot arise from a membership role. Coordinate the narrow P02 old-token/grant containment in the first-release section; the full P02 version/revocation program is not a merge dependency. P28 owns broader service-account role qualification. Review unexpected stored roles and grants without destroying evidence.

**Done when:** the bounded hotfix passes full-filter escalation regressions, invalid stored-role rejection and ordinary tenant/global-owner journeys, including owners with a tenant selected. Its target is about one engineer-day within S, subject to review and discovered callers. Record separately whether already elevated JWTs/grants are contained; do not mark the overall privilege boundary safe merely because new membership writes are rejected. P02 remains Open until its wider revocation/status criteria pass.

**Evidence:** [member endpoints](<../../backend/src/main/java/com/prototype/vulnwatch/controller/TenantAdministrationController.java>) (line 239), [role normalization](<../../backend/src/main/java/com/prototype/vulnwatch/service/IdentityAdministrationService.java>) (line 493), [authority merge](<../../backend/src/main/java/com/prototype/vulnwatch/service/JwtTenantAuthenticationService.java>) (line 112), [demo assignment](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoLifecycleService.java>) (line 462).

<a id="p02"></a>

### P02 — Make revocation and user disabling authoritative

**Severity:** High · **Milestone:** M1 · **Owner:** B, S, Q · **Effort:** L

**Delivery tier:** 1 · **Implementation gates:** A!; T?

**Basis:** Code. **Previous tasks:** T28–T30.

Authentication can recreate PLATFORM_OWNER from a still-valid JWT. Local login and JWT authentication omit an inactive-AppUser check; active membership and tenant-lifecycle checks already exist. Authentication persists token/global roles before merging membership roles: a membership edit plus an ordinary old token does not itself establish persistent ownership. Login while elevated can issue an elevated token that subsequently persists it.

**Fix:** first deliver the narrow privilege-containment slice alongside P01-HF: stop JWT-driven global-grant creation and reject stale elevated authority, preserving legitimate current owner grants. Review both global-role records and the compatibility owner flag, and invalidate affected issued credentials using a verified existing-contract mechanism. Then complete current-authority enforcement, inactive-user checks and next-action revocation for retained auth paths. Add an authorization-version check only where needed; do not require that entire program before P01-HF ships. Preserve membership/support revalidation and use additive migrations if needed.

**Done when:** owner removal, admin demotion, user disabling and membership/support revocation deny the next prohibited action without restoring roles. Test old and newly issued tokens, including the P01 persistence sequence.

**Evidence:** [JWT ordering and persistence](<../../backend/src/main/java/com/prototype/vulnwatch/service/JwtTenantAuthenticationService.java>) (line 88), [local login](<../../backend/src/main/java/com/prototype/vulnwatch/service/LocalCredentialAuthService.java>) (line 85), [membership role issuance](<../../backend/src/main/java/com/prototype/vulnwatch/service/LocalCredentialAuthService.java>) (line 130).

<a id="p03"></a>

### P03 — Scope tenant connector runs and scheduling correctly

**Severity:** High · **Milestone:** M1 · **Owner:** B, Q · **Effort:** S

**Delivery tier:** 1 · **Implementation gates:** T!

**Basis:** Code. **Previous tasks:** T30/T37/T41/T61.

Tenant inventory connectors consult shared platform run history without consistently filtering by tenant. AWS discovery can reuse another tenant's active run ID, suppress an independent run, or calculate its schedule from another tenant's latest execution. Equivalent Azure and CMDB paths need the same correction. Tenant-scoped repository methods already exist.

**Fix:** use those existing methods for tenant admission, active/status and latest-run checks; retain intentionally shared intelligence-feed queries. Include the connector/configuration identity where multiple configurations are supported. Serialize simultaneous admission for the same tenant/configuration using the existing database transaction/locking conventions.

**Done when:** two tenants trigger and schedule independently; neither receives the other's run ID or metadata; concurrent same-configuration triggers return one effective run. Add focused tenant-isolation regressions around the affected services, including their status endpoints and scheduled path.

**Evidence:** [unscoped admission](<../../backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java>) (line 178), [unscoped latest run](<../../backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java>) (line 209), [existing scoped latest method](<../../backend/src/main/java/com/prototype/vulnwatch/repo/SyncRunRepository.java>) (line 19), [existing scoped active method](<../../backend/src/main/java/com/prototype/vulnwatch/repo/SyncRunRepository.java>) (line 60).

<a id="p04"></a>

### P04 — Make production configuration fail closed

**Severity:** High · **Milestone:** M1 · **Owner:** B, P, S · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A!; D?

**Basis:** Config, Code. **Previous tasks:** T13/T15/T31.

Production protections depend on selecting the intended profile/validation flags. API-key authentication defaults on, although the production profile disables it and the gated validator rejects enabling it. With that path enabled, a valid API key and blank creator key grant platform authority. Unknown runtime roles also fall back to all duties.

**Fix:** require explicit intended environment/runtime role and reject unsafe combinations before serving. Preserve existing API-key shutdown and make its validation unavoidable for intended production. Reject personas/mock/bootstrap/header-selection settings where inappropriate. Validate keys by actual algorithm/encoding: AES already requires 32 decoded bytes, whereas the shared strength helper checks character length.

**Done when:** approved existing-runtime configurations start; omitted/unknown roles and dangerous production combinations fail startup. Tests cover validation gates and demonstrate that production cannot enter the API-key owner path.

**Evidence:** [production authentication setting](<../../backend/src/main/resources/application-prod.yml>) (line 34), [gated validator](<../../backend/src/main/java/com/prototype/vulnwatch/config/ProductionSafetyValidator.java>) (line 91), [owner fallback](<../../backend/src/main/java/com/prototype/vulnwatch/config/ApiKeyAuthenticationFilter.java>) (line 112), [runtime fallback](<../../backend/src/main/java/com/prototype/vulnwatch/service/BackgroundTaskExecutionPolicy.java>) (line 58).

<a id="p05"></a>

### P05 — Protect stored secrets and invitation tokens

**Severity:** High · **Milestone:** M1 · **Owner:** B, S, P · **Effort:** L

**Delivery tier:** 1 · **Implementation gates:** A!; O?

**Basis:** Code, Config. **Previous tasks:** T14/T28/T46/T49.

Tenant GitHub credentials and tenant/demo invitation bearer tokens have raw storage paths. Password-setup tokens already use hashes. AES-GCM encryption exists, but plaintext passthrough and an unversioned effective key complicate rotation and recovery. Invitation/setup links also expose tokens in URL paths.

**Fix:** encrypt provider secrets and hash both invitation types using additive migrations with bounded compatibility. Clear raw invitation values after conversion; preserve atomic expiry/single-use/reissue behavior. Retain AES-GCM, reject unintended plaintext and identify encryption-key versions for rotation and backup recovery. Generate new invitation/setup links with fragment tokens and exchange/validate/accept through POST bodies; update email, frontend and API together. Expire/reissue legacy path links or bound compatibility. Review the previously identified local token-shaped material and revoke/rotate it if active, without exposing its value.

**Done when:** no new raw provider/invitation secrets are stored; both invite types pass concurrency/reissue tests; new requests omit tokens from URLs; telemetry/body logs redact them; rotation and recovery preserve authorized decryption.

**Evidence:** [GitHub storage](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 389), [tenant token](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantUserInviteService.java>) (line 77), [demo token](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoLifecycleService.java>) (line 491), [encryption](<../../backend/src/main/java/com/prototype/vulnwatch/service/CredentialEncryptionService.java>) (line 26), [current invitation API](<../../backend/src/main/java/com/prototype/vulnwatch/controller/TenantInviteController.java>) (line 34).

<a id="p06"></a>

### P06 — Correct client identity and public abuse controls

**Severity:** High · **Milestone:** M1 · **Owner:** B, P, S, Q · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A?; D?

**Basis:** Config, Code. **Previous tasks:** T11/T32.

The limiter trusts CF-Connecting-IP when enabled; production also enables framework forwarded-header handling. Its fallback remote address can therefore depend on forwarded headers. Actual spoofability depends on ingress sanitization. Counters are process-local, including a shared global bucket; separate email/token limits already exist.

**Fix:** derive client identity from the existing trusted proxy chain, reject untrusted header influence and protect direct ingress through the current operating configuration. Do not select a universal leftmost/rightmost address. Preserve email/token controls, separate public-flow load shedding where needed, and accurately document process-local limits rather than claiming fleet-wide enforcement.

**Done when:** proposed `PublicEndpointRateLimiterIsolationTest` models trusted and untrusted ingress and rejects forged CF/forwarded values. In a fixed-window fixture, flood registration with distinct IP/email values until its public budget is exhausted; a fresh trusted login IP must still receive the existing 30 checks per 15 minutes across distinct emails, with check 31 denied. A separate email fixture allows 10 checks per 15 minutes and denies check 11. These are current login limits, not new launch quotas; assert the actual effective values if intentionally changed. Verify process-local restart/multiple-process behavior against its documented scope and record the affected Render ingress/profile configuration.

**Evidence:** [client address](<../../backend/src/main/java/com/prototype/vulnwatch/security/PublicEndpointRateLimiter.java>) (line 87), [counters and limits](<../../backend/src/main/java/com/prototype/vulnwatch/security/PublicEndpointRateLimiter.java>) (line 17), [forwarded-header mode](<../../backend/src/main/resources/application-prod.yml>) (line 16).

<a id="p07"></a>

### P07 — Repair existing customer cloud credential binding

**Severity:** High · **Milestone:** M1 · **Owner:** B, P, S, UI · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A!; T!; D?

**Basis:** Code, Config. **Previous tasks:** T47–T49.

Generic AWS configuration accepts account/role/ExternalId inputs without equivalent AI validation. ExternalId is optional. AI credentials can fall back to platform identity when no role is provided; actual caller-account checking occurs in the separate test operation, not worker execution. Generic INSTANCE_METADATA explicitly uses an EC2 provider.

**Fix:** generate and bind a unique server-controlled ExternalId per customer connector; reject arbitrary replacement. Validate account/ARN consistency and authorization at save, trigger and worker boundaries. Reject unintended customer no-role/ambient-platform fallback and verify effective assumed identity before enumeration. Keep credential acquisition explicit and compatible with the existing runtime. These are connector fixes; creating cloud roles, templates or infrastructure is excluded.

**Done when:** controlled-provider tests reject missing roles and wrong tenant/account/ExternalId before enumeration, including when the separate connection-test endpoint was skipped. Valid bindings pass worker identity validation without broadening platform credentials; calling the connection-test endpoint is not a prerequisite. Supplying another ExternalId alone is not treated as proof of access to another account.

**Evidence:** [generic inputs](<../../backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoveryTargetService.java>) (line 156), [optional ID](<../../backend/src/main/java/com/prototype/vulnwatch/client/AwsCredentialProvider.java>) (line 88), [AI credentials](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiSecurityAwsConnectorService.java>) (line 152), [worker execution](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/aws/AwsBedrockDiscoveryService.java>) (line 201).

<a id="p08"></a>

### P08 — Isolate connector credentials and constrain destinations

**Severity:** High · **Milestone:** M1 · **Owner:** B, S, F · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** T!; A?

**Basis:** Code, Decision. **Previous tasks:** T47/T50/T51.

Saved GitHub/GHCR sources set tenant-token overrides; standalone GHCR execution does not. Missing tenant tokens can inherit platform credentials. Exposure depends on permissions/allowlists; the inspected path retrieves metadata and attested SBOMs, not arbitrary package bytes. SCCM uses tenant JDBC destinations. Its runtime fallback result is discarded, unlike active ServiceNow/GitHub credential fallbacks.

**Fix:** pass explicit per-run credential policy: tenant credentials for private data, deliberate anonymous access for supported public repositories, and separately scoped platform-feed credentials. Never substitute platform secrets for absent customer credentials. GHCR currently requires a token; preserve clear rejection when absent. Disable SCCM live JDBC for the assisted pilot at save/test/sync and worker boundaries, including existing queued work; disabled configuration or mock-mode fallback alone is insufficient. Remove misleading unused SCCM fallback behavior. Restricting/qualifying supported live JDBC drivers/protocols/hosts is deferred until explicit re-enablement, not required to implement a new connector now.

**Done when:** saved/standalone/manual/scheduled GitHub paths cannot inherit another trust domain's credentials; anonymous public repository ingestion remains valid and GHCR missing-token errors remain explicit. Consecutive-job tests show no token leakage. Disabled SCCM save/test/sync and queued execution attempt zero live JDBC connections and do not substitute fixture results. Record JDBC as Contained—disabled while the retained credential repairs remain independently tracked.

**Evidence:** [saved override](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 255), [standalone GHCR](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 303), [token fallback](<../../backend/src/main/java/com/prototype/vulnwatch/client/GithubTokenProvider.java>) (line 54), [SCCM use](<../../backend/src/main/java/com/prototype/vulnwatch/service/SccmCmdbSyncService.java>) (line 195), [ServiceNow use](<../../backend/src/main/java/com/prototype/vulnwatch/service/ServiceNowCmdbSyncService.java>) (line 215).

<a id="p09"></a>

### P09 — Complete existing outbound request controls

**Severity:** High · **Milestone:** M1 · **Owner:** B, S, Q · **Effort:** L

**Delivery tier:** 1 · **Implementation gates:** —; D?

**Basis:** Code, Qualification. **Previous tasks:** T12/T49/T52/T61.

Offline policy checks accepted approved-host resolutions to fd00:ec2::254 and IPv4-embedded IPv6 forms while rejecting tested IPv4 private/metadata addresses. Generic Azure continuation lacks equivalent destination/time/page guards. Default provider hosts omit OSV/MSRC, whose failure paths can return empty evidence.

**Fix:** repair IPv6/embedded-address handling and enforce approved destinations at connection time, including DNS changes. Bound continuation scheme/host, time, pages and bytes across retained clients. Correct provider-host configuration and distinguish unavailable/partial retrieval from clean results. Preserve stronger existing AI Azure controls and allowlists.

**Done when:** offline DNS/address/continuation fixtures reject private/special destinations and terminate bounded work; failures remain unavailable rather than negative evidence. No live cloud account or new platform is needed for these regressions.

**Evidence:** [address policy](<../../backend/src/main/java/com/prototype/vulnwatch/client/http/OutboundHostPolicy.java>) (line 102), [IPv6 handling](<../../backend/src/main/java/com/prototype/vulnwatch/client/http/OutboundHostPolicy.java>) (line 135), [Azure continuation](<../../backend/src/main/java/com/prototype/vulnwatch/client/AzureDiscoveryClient.java>) (line 65), [OSV failure](<../../backend/src/main/java/com/prototype/vulnwatch/client/http/OsvApiClient.java>) (line 49), [MSRC retrieval](<../../backend/src/main/java/com/prototype/vulnwatch/client/http/AdvisoryFetchService.java>) (line 58).

## B. Existing work execution, transactions and ingestion

<a id="p10"></a>

### P10 — Make existing execution roles and assessment callers consistent

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** —; T?; D?

**Basis:** Code. **Previous tasks:** T39.

The existing runtime-role policy does not cover every background path, unknown roles become all, and manual connector submission can execute local work after recording an accepted run. Assessment recovery lacks that role guard. Policy rollout immediately treats a pending assessment as failure. Manual policy execution already returns separate collection/assessment states, and its frontend polls pending results correctly.

**Fix:** validate role configuration and apply the existing policy consistently to relevant pollers/startup callbacks. Route accepted background work through the existing durable processing paths, preserving controller contracts. Make rollout retain its accepted assessment request and continue when that request completes; recheck the release binding before completion. Preserve manual execution's existing assessment-status response and polling.

**Done when:** API-role callbacks respect their configured boundary; accepted work survives local dispatch failure. A merged pending assessment and delayed recovery do not falsely fail rollout. Manual execution still reports pending/running/partial/failed/complete correctly; deterministic AI posture remains independent of generative assistance.

**Evidence:** [role fallback](<../../backend/src/main/java/com/prototype/vulnwatch/service/BackgroundTaskExecutionPolicy.java>) (line 58), [assessment dispatch/recovery](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridAssessmentWorker.java>) (line 112), [rollout assumption](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridPolicyRolloutService.java>) (line 113), [manual response fields](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridApiService.java>) (line 740), [existing frontend polling](<../../frontend/src/pages/AiPoliciesPage.tsx>) (line 131).

<a id="p11"></a>

### P11 — Commit accepted intent with its source changes

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** —; T?

**Basis:** Code. **Previous tasks:** T35–T41.

Finding-delta enqueue uses REQUIRES_NEW while inventory writes remain in an outer transaction. A consumer can therefore observe intent before its source commits, or intent can survive source rollback. GitHub source claiming separately commits QUEUED/run state before quota-checked job creation. Several accepted connector runs also rely on local executor submission.

**Fix:** make finding enqueue join the correctly scoped source transaction; retain separate short consumer claim/acknowledgment transactions. Make GitHub quota admission, source/run transition and job insertion atomic. For retained accepted connector actions, persist enough dispatch intent for existing workers/recovery to execute without a surviving request-process lambda. Reuse PostgreSQL job/outbox conventions and existing idempotency constraints.

**Done when:** real PostgreSQL transaction barriers prove events invisible before source commit and absent after rollback. Committed source changes produce their recomputation. Quota denial leaves the source retryable; process loss after acceptance loses no executable work. An after-commit-only insertion does not satisfy atomic publication.

**Evidence:** [delta transaction template](<../../backend/src/main/java/com/prototype/vulnwatch/service/FindingDeltaQueueService.java>) (line 92), [source enqueue](<../../backend/src/main/java/com/prototype/vulnwatch/service/sbomingestion/SbomContentIngestionService.java>) (line 271), [GitHub claim/enqueue split](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 127), [local connector dispatch](<../../backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java>) (line 99).

<a id="p12"></a>

### P12 — Recover interrupted work without resetting healthy executions

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** —; T?

**Basis:** Code. **Previous tasks:** T35/T36/T38.

Startup ingestion recovery fails every RUNNING job it finds without checking age or ownership. Vulnerability recovery scans queued/running shared sync rows across tenant and connector types. Overlapping execution owners can falsely fail healthy work while its original execution continues. The vulnerability worker also marks a queued row RUNNING before checking whether it supports that type.

**Fix:** filter supported work before claiming; preserve accepted queued intent. Replace blanket startup resets with expired-attempt recovery, bounded retry and ownership-checked completion. Reuse the assessment worker's PostgreSQL claim-token, heartbeat and commit-fence pattern where the affected job family lacks ownership. Cover retained governance/demo/source in-flight states; disabled features need no new execution pipeline.

**Done when:** starting another worker does not alter healthy work; interrupted owned work recovers; pre-execution failure/executor rejection leaves a recoverable state. Expired owners cannot commit late state changes or overwrite a reclaimed result. Test both overlapping owners and restart with a single owner.

**Evidence:** [blanket ingestion recovery](<../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java>) (line 376), [shared sync reset](<../../backend/src/main/java/com/prototype/vulnwatch/service/vulningestion/VulnerabilitySyncRunService.java>) (line 181), [claim before type check](<../../backend/src/main/java/com/prototype/vulnwatch/service/vulningestion/VulnerabilityQueuedRunWorkerService.java>) (line 81), [existing lease/commit fencing](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridAssessmentWorker.java>) (line 143).

<a id="p13"></a>

### P13 — Prevent duplicate recurring work on unsafe schedule paths

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** —; D?; O?

**Basis:** Code, Qualification. **Previous tasks:** T40.

Some recurring callbacks can execute independently on multiple eligible processes. Others already use source-row locks and due checks. Applying one global lock to every consumer would discard existing concurrency without identifying which occurrence can actually duplicate.

**Fix:** first produce a checked-in schedule matrix for every retained scheduled entrypoint: class/method, enablement condition, runtime role, tenant/global scope, cron or delay/time zone, existing claim/dedupe/lock, duplicate effect, restart behavior, and retain/fix/disabled disposition. An annotation count is not a count of unsafe jobs; do not assume 46 unlocked callbacks. Record gaps and estimate uninspected repairs after this bounded discovery output. Extend current database locking/deduplication only where overlapping eligible schedulers can duplicate logical work/effects; preserve independent job claims and existing source locks.

**Done when:** the schedule matrix has no unclassified retained entrypoint and identifies the configuration evidence for each enabled path. Proposed `SchedulerOverlapPostgresIntegrationTest` barrier-starts two eligible callers for one due source/time and asserts one effective occurrence, while distinct sources/tenants both progress. A restart-boundary case yields recoverable pending work or an explicit missed-run result. A named `runtime-topology-check` evidence record lists actual Render service names, effective runtime roles, scheduler flags, replica counts, revision and verification date; compare it with the matrix. This record is a current-environment check, not an assumed single-worker guarantee or new infrastructure implementation.

**Evidence:** [catalog scheduled execution](<../../backend/src/main/java/com/prototype/vulnwatch/service/EolRefreshService.java>) (line 250), [existing GitHub source claim lock](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 444), [existing assessment SKIP LOCKED claim](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridAssessmentWorker.java>) (line 151).

<a id="p14"></a>

### P14 — Preserve committed outcomes through later failures and shutdown

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q, P · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** —; T?; D?

**Basis:** Code, Qualification. **Previous tasks:** T41/T42/T46.

Ingestion commits domain changes and SUCCEEDED before recording completion audit/metrics. A later audit exception enters the encompassing catch and can relabel that successful job FAILED. Completion reporting can therefore disagree with durable data. Shutdown and executor rejection also need consistent ownership handling across retained job families.

**Fix:** keep committed domain success terminal. Commit completion audit intent with the outcome, or retry ancillary reporting independently without changing it. Stop new claims during shutdown and safely finish/checkpoint owned work; ownership expiry must not allow an old owner to continue unfenced mutations. Use P32 for email delivery's separate transaction/idempotency repair.

**Done when:** injected postcommit audit failure leaves the job succeeded with observable reporting retry/failure. Pre-execution faults do not strand RUNNING work. SIGTERM at claim, execution and commit boundaries preserves accepted work and truthful status; replay cannot duplicate effective domain changes. Keep and exercise existing graceful shutdown rather than assuming it drains every executor.

**Evidence:** [domain commit followed by audit and broad catch](<../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobWorkerService.java>) (line 137), [existing conditional assessment completion](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridAssessmentWorker.java>) (line 254).

<a id="p15"></a>

### P15 — Fail safely on tenant context and connection cleanup errors

**Severity:** High · **Milestone:** M1 · **Owner:** B, S, Q · **Effort:** L

**Delivery tier:** 1 · **Implementation gates:** T!; A?

**Basis:** Qualification, Config. **Previous tasks:** T18/T61.

Tenant switching inside an active transaction defaults to WARN; an invalid guard value also becomes WARN. Changing thread context does not move an already acquired transactional connection to another tenant. The connection wrapper attempts to reset the tenant setting and search path, but ignores reset failures before returning the connection. This establishes unsafe error handling, not a demonstrated cross-tenant disclosure in the deployed service.

**Fix:** review existing context-before-transaction call sites, correct conflicting switches, validate guard values and use fail-closed behavior. Preserve legitimate same-tenant nesting. Ensure reset-failed or aborted connections are discarded safely through the actual pool rather than reused with uncertain session state. Keep ordinary API access restricted by the existing tenant and RLS controls.

**Done when:** PostgreSQL regressions cover alternating tenants, same-tenant nesting, prohibited cross-tenant nesting, exceptions, aborted transactions and injected reset failures. Subsequent tenant and platform-pool operations inherit no previous tenant setting or search path. Invalid configuration fails explicitly.

**Evidence:** [transaction guard and permissive parsing](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantSchemaExecutionService.java>) (line 97), [ignored reset error](<../../backend/src/main/java/com/prototype/vulnwatch/config/TenantAwareDataSource.java>) (line 119).

<a id="p16"></a>

### P16 — Repair feed gaps and mutation-sensitive pagination

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** —; G?

**Basis:** Code. **Previous tasks:** T36/T52.

NVD incremental sync derives its start from the current time minus a lookback. Downtime longer than that interval can leave a gap; existing full/backfill operations offer recovery but do not make incremental continuity automatic. EPSS advances an offset through stale rows while successful updates remove rows from that result set, allowing eligible rows to be skipped.

**Fix:** persist the last successfully completed NVD interval and resume from it with overlap and existing idempotent upserts; split catch-up into supported bounded windows. Advance completion only after the interval succeeds. Replace EPSS's shrinking-set offsets with stable traversal, such as keyset IDs fixed for a sweep. Missing scores and failed rows need a finite attempt outcome so traversal terminates.

**Done when:** downtime exceeding the lookback, mid-page failure and repeated execution recover every eligible record without false success. EPSS tests include multiple pages, absent scores and failed requests. Feed status distinguishes incomplete/unavailable coverage from successful empty results, and replay updates the existing finding/projection path.

**Evidence:** [time-relative NVD window](<../../backend/src/main/java/com/prototype/vulnwatch/service/vulningestion/NvdSyncService.java>) (line 173), [EPSS offset loop](<../../backend/src/main/java/com/prototype/vulnwatch/service/EpssRefreshService.java>) (line 113), [updates remove stale eligibility](<../../backend/src/main/java/com/prototype/vulnwatch/service/EpssRefreshService.java>) (line 190).

<a id="p17"></a>

### P17 — Preserve absence semantics after incomplete collection

**Severity:** High · **Milestone:** M2 · **Owner:** B, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** —; T?

**Basis:** Code. **Previous tasks:** T43/T49/T52.

Generic Azure discovery returns fetched records plus an error after a later page fails. Its caller ingests those records before handling the error; ingestion then retires unseen assets within observed type/region scopes. Empty results are guarded, but a nonempty partial page can still make existing resources incorrectly INACTIVE. Categorized BOM extraction also stops at its component limit without an explicit incomplete result.

**Fix:** disable generic Azure discovery for the pilot through a server gate covering configuration/test, ordinary and target-specific manual admission, scheduled work and queued execution. Saved enabled/auto-sync flags alone do not cover every path, and the separate AI Azure switch is not a generic-Azure control. Preserve existing assets while blocking collection; record handling of already running work. Apply P25's explicit rejection/completeness handling to retained BOM formats. Full Azure completeness propagation and absence-retirement repair stays deferred behind explicit re-enablement; do not rebuild the connector as a pilot prerequisite.

**Done when:** generic-Azure disabled-path tests make zero provider calls, reject bypassing target/manual/test paths and prevent queued work from changing existing asset activity. Retained over-limit BOM fixtures are rejected rather than silently becoming complete inventories. Mark the connector Contained—disabled, with owner/revisit criteria; P25's retained-format repair still requires its own evidence. Before future re-enablement, page-one success/page-two failure, empty/all-failed and independent subscription/type/region fixtures must preserve unseen assets until a complete authoritative scan succeeds.

**Evidence:** [partial discovery result](<../../backend/src/main/java/com/prototype/vulnwatch/client/AzureDiscoveryClient.java>) (line 65), [ingestion before error handling](<../../backend/src/main/java/com/prototype/vulnwatch/service/AzureDiscoverySyncService.java>) (line 282), [scoped stale retirement](<../../backend/src/main/java/com/prototype/vulnwatch/service/AzureDiscoveryIngestionService.java>) (line 152), [component truncation](<../../backend/src/main/java/com/prototype/vulnwatch/service/BomIngestionOrchestrator.java>) (line 636).

<a id="p18"></a>

### P18 — Enforce existing admission limits atomically

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** —; T?; D?

**Basis:** Code, Qualification. **Previous tasks:** T05, T24/T34/T41/T45.

Quota checks count before insertion; worker admission counts RUNNING jobs before claiming different rows. Concurrent callers can exceed the intended tenant limit despite SKIP LOCKED. The active dedupe-key constraint already exists, but the save/catch fallback may encounter delayed flush errors or query an aborted transaction. Scheduled GitHub runs use the same quota path after committing their source claim.

**Fix:** serialize the existing tenant capacity decision and admission/claim transaction; use conflict-safe insertion or rollback-and-retry for deduplication. Integrate GitHub's atomic source/run/job repair from P11. On scheduled capacity denial, leave the source eligible, record deferral and continue other sources/tenants. Keep configured limits; enforce any retained provider budget across its actual callers, preserving existing database-locked AI budgets. Qualify aggregate pool usage for the actual process count.

**Done when:** synchronized quota-boundary requests and consumers cannot exceed their configured limits; identical requests return one job without failed-transaction reuse or a 500. A saturated tenant does not strand scheduled sources or stop other tenants. Test actual PostgreSQL conflicts; mocked count tests cannot establish these properties.

**Evidence:** [quota counts](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantQuotaService.java>) (line 110), [count then claim](<../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java>) (line 207), [dedupe catch](<../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java>) (line 484), [scheduled path](<../../backend/src/main/java/com/prototype/vulnwatch/service/GithubSbomSourceService.java>) (line 178), [existing atomic AI budget](<../../backend/src/main/java/com/prototype/vulnwatch/service/AiBomProjectionBudgetService.java>) (line 42).

## C. Current database, tenant lifecycle and local storage

<a id="p19"></a>

### P19 — Correct restricted-role grants and the current database transport contract

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, S, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** O!; T?; D?

**Basis:** Code, Config. **Previous tasks:** T17/T18/T19.

Runtime grant scripts and CLI verification omit the two public GHSA tables used by dedicated GHSA APIs. Those retained routes fail under a freshly provisioned restricted role. The main GHSA feed uses platform repositories, so this is not evidence that all GHSA ingestion fails. Separately, the Render migration wrapper replaces DB_URL with its own timeout query. A complete externally supplied TLS URL cannot pass through that wrapper, although runtime configuration and direct CLI invocation already support full JDBC URLs. Actual deployed Render TLS settings remain unverified.

**Fix:** grant and verify only the shared objects needed by retained APIs, or disable the affected legacy routes. Preserve non-owner runtime access and FORCE RLS. Make the wrapper preserve and validate intended JDBC transport options and bounded timeouts. Verify the current Render endpoint's certificate chain and hostname against the appropriate supported trust configuration; use an explicit verified transport contract. A future RDS certificate bundle is outside this fix.

**Done when:** disposable restricted-role tests cover retained public and tenant paths, deny wrong-tenant access and DDL, and prove URL-option preservation. Controlled TLS tests reject untrusted certificates and hostname mismatch; current-environment transport evidence is recorded without exposing credentials.

**Evidence:** [grant scope](<../../backend/scripts/provision-runtime-role.sql>) (line 35), [tenant GHSA route](<../../backend/src/main/java/com/prototype/vulnwatch/controller/GithubAdvisoryTenantController.java>) (line 81), [wrapper overwrite](<../../backend/scripts/run-render-migration.sh>) (line 61), [CLI option preservation](<../../backend/src/main/java/com/prototype/vulnwatch/migration/ProductionBootstrapCli.java>) (line 999).

<a id="p20"></a>

### P20 — Correct existing bootstrap, verification and exit behavior

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** O!; T?; D?

**Basis:** Code, Config. **Previous tasks:** T19/T20/T55.

The Render wrapper intentionally remains alive on a maintenance listener after successful migration and maps termination to exit 0. That behavior must be distinguished from a successful run-once bootstrap. The SQL verifier expects V44, while the packaged catalog currently has platform V1 and tenant V2. CLI report-only avoids migrations but still attempts a protected CREATE probe. Earlier privilege checks normally reject unsafe roles; this remains different from a catalog-only inspection.

**Fix:** distinguish maintenance from run-once behavior, with accurate success/failure/cancellation exits and secret-safe diagnostics. Make verification target-aware and provide a non-mutating inspection path wherever read-only is promised. Reuse the current CLI. Keep owner credentials out of the permanent API/jobs runtime. Preserve applied migrations; add changes to the relevant migration line.

**Done when:** disposable-database tests cover fresh bootstrap, repeat execution, failure, cancellation and report-only inspection without DDL. Packaged-version verification succeeds and stale assumptions are removed. No baseline reset or destructive verification is performed against the existing Render database.

**Evidence:** [maintenance listener](<../../backend/scripts/run-render-migration.sh>) (line 73), [stale verifier](<../../backend/scripts/verify-tenant-migration.sql>) (line 21), [catalog targets](<../../backend/src/test/java/com/prototype/vulnwatch/migration/MigrationCatalogTest.java>) (line 28), [DDL probe](<../../backend/src/main/java/com/prototype/vulnwatch/migration/ProductionBootstrapCli.java>) (line 744).

<a id="p21"></a>

### P21 — Activate a tenant only after its existing bootstrap checks pass

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** T!; O?

**Basis:** Code, Config. **Previous tasks:** T20/T21.

API creation records PROVISIONING and awaits privileged bootstrap. The CLI marks each migrated pending tenant ACTIVE before installing runtime grants after the pending batch. A later tenant's failure can therefore leave an earlier tenant active without the new-schema grants required by the API. Existing lifecycle guards already deny non-active tenants and should remain authoritative.

**Fix:** complete and verify each tenant's schema, version/fingerprint and restricted-runtime grants before marking it ACTIVE. Make existing retry/status behavior idempotent and distinguish migration failure from an accessible tenant. A controlled operator invocation of the repaired CLI is sufficient for this scope; automatic provisioning services and new orchestration are not required.

**Done when:** failures between schema creation, migration, grants and activation leave the tenant inaccessible with an accurate recoverable state. A later batch failure does not expose an earlier ungranted tenant. Retry is safe, and the activated tenant passes a restricted-runtime smoke test without owner credentials.

**Evidence:** [creation state](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantService.java>) (line 85), [early activation](<../../backend/src/main/java/com/prototype/vulnwatch/migration/ProductionBootstrapCli.java>) (line 368), [later grants](<../../backend/src/main/java/com/prototype/vulnwatch/migration/ProductionBootstrapCli.java>) (line 73), [lifecycle guard](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantLifecycleGuardService.java>) (line 25).

<a id="p22"></a>

### P22 — Repair administrative purge without harming shared users

**Severity:** High · **Milestone:** M1 · **Owner:** B, P, S, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** A!; T!; O?

**Basis:** Code. **Previous tasks:** T20/T25.

Tenant deletion is platform-owner administration. The restricted-runtime path can skip schema destruction yet continue shared cleanup. Credential scrubbing clears a non-owner user's global password/setup fields even if memberships in another tenant remain. Failure handling can restore an ACTIVE status after partial cleanup, and success auditing precedes registry deletion. These are defects in the existing lifecycle, not a reason to broaden the normal API database role.

**Fix:** restrict or disable the unsafe administrative route until corrected. Preserve shared users' credentials and other memberships. Fail explicitly when required schema cleanup lacks authority; do not continue as if deletion succeeded. Keep a partially purged tenant inaccessible, make retry behavior explicit and record success only after verified completion. A narrowly controlled privileged operator procedure may replace this route; a new orchestration platform is unnecessary.

**Done when:** deleting tenant A preserves a shared user's tenant B login and privileges. Empty/populated cases, insufficient privileges and injected cleanup failures cause no false success, silently retained schema or reactivated partial tenant. Repeated cleanup completes safely while preserving required audit and holds.

**Evidence:** [purge order](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoTenantPurgeService.java>) (line 95), [conditional schema drop](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoTenantPurgeService.java>) (line 126), [shared credential clearing](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoTenantPurgeService.java>) (line 212), [failure status](<../../backend/src/main/java/com/prototype/vulnwatch/service/DemoTenantPurgeService.java>) (line 260).

<a id="p23"></a>

### P23 — Reconcile startup, readiness and tenant eligibility checks

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** T!; A?; D?

**Basis:** Code, Qualification. **Previous tasks:** T21/T55/T56.

Readiness requires ACTIVE tenants to match the packaged tenant version exactly. Startup instead requires CURRENT with a version floor of 1. Its separate RLS query includes registered schemas without a tenant-status filter, so an incomplete non-active schema can also reject startup. Non-active status alone does not trigger that rejection. Existing request-level schema checks already provide a minimum-compatible-version mechanism.

**Fix:** define one supported compatibility contract for the current application and apply it consistently to startup, readiness and tenant requests. Separate instance dependency failure from an individual tenant's failed provisioning. Keep incompatible or partially built tenants inaccessible and preserve RLS guarantees; ignoring tenant status globally or dropping safety checks is insufficient. Test additive changes and supported prior application behavior against the same disposable database.

**Done when:** current compatible tenants remain usable when another tenant is provisioning, failed or drifted; that tenant's requests fail explicitly. Missing required platform dependencies still remove the instance from serving. Readiness and request eligibility agree, liveness stays separate, and rollback tests respect the documented compatible schema range.

**Evidence:** [exact readiness](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantSchemaStatusService.java>) (line 72), [startup RLS and version checks](<../../backend/src/main/java/com/prototype/vulnwatch/config/ProductionSafetyValidator.java>) (line 274), [existing compatibility guard](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantSchemaService.java>) (line 88).

<a id="p24"></a>

### P24 — Make the existing archive behavior explicit or disable it

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** S

**Delivery tier:** 3 · **Implementation gates:** —; D?

**Basis:** Code. **Previous tasks:** T44.

Vulnerability archives use a configurable local directory. The non-root image does not establish that the default directory is writable. Write errors return null, and missing files also return null, making these states difficult for callers to distinguish from absent optional content. Local files do not establish durability across replacement or sharing between instances.

**Fix:** select the disabled-archive path for the pilot, provisionally S. Pause the existing operator archive migration and add a small explicit server-disabled mode covering archive writes and dependent reads/UI behavior. Preserve inline canonical descriptions/payloads and any existing source content; do not remove references or files as a side effect of disablement. Return an honest unavailable/disabled result for inaccessible historical archive-only content. No filesystem/image permission repair, S3 adapter, shared-storage mechanism or durability promise is required for this selected path.

**Done when:** disabled migration/write entrypoints create no files or archive keys and cannot strip inline content. Existing ingestion and retained reads continue to expose available canonical database fields; historical archive-only content reports unavailable rather than a successful empty result. UI and operator guidance agree, and no hidden job can resume migration. Record Contained—disabled with owner and re-enablement criteria; writable-path/round-trip/durability qualification belongs to any later explicit archive-retention decision. A Dockerfile edit is not assumed.

**Evidence:** [configured local path](<../../backend/src/main/java/com/prototype/vulnwatch/service/VulnerabilityArchiveService.java>) (line 31), [write failure](<../../backend/src/main/java/com/prototype/vulnwatch/service/VulnerabilityArchiveService.java>) (line 50), [filesystem retrieval](<../../backend/src/main/java/com/prototype/vulnwatch/service/VulnerabilityArchiveService.java>) (line 163), [image ownership](<../../backend/Dockerfile>) (line 19).

<a id="p25"></a>

### P25 — Roll back rejected uploads and enforce existing input bounds

**Severity:** High · **Milestone:** M1 · **Owner:** B, UI, Q · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** —; T?

**Basis:** Code, Qualification. **Previous tasks:** T05, T43.

Direct upload/fetched-content entrypoints use plain @Transactional while propagating checked IOException. Asset writes precede format validation; replacement can retire the old version and promote a new pointer before checked no-component failures. These paths can commit partial rejected state under normal Spring rules. Runtime errors, rollback-only transactions and the worker's checked-to-runtime wrapper can instead roll back.

Existing bounds include a 50 MB multipart/request limit, a 50 MiB BOM-byte check and a 100,000-component categorized extraction cutoff. Remote fetching allocates the byte response before checking size, and categorized extraction silently truncates. These controls are not consistent across representations.

**Fix:** apply explicit checked-failure rollback now; validate before mutation and preserve atomic source replacement. Keep existing upload response/processing contracts. Bound remote consumption during reading using the existing byte ceiling, including missing/false Content-Length; consistently reject excess components instead of silently claiming completeness. Bound retained parser traversal and resource use without introducing unqualified replacement limits.

**Done when:** transaction-backed direct-path tests preserve old BOM/components/evidence/source pointers after malformed, unknown-format and empty replacement; invalid new uploads leave no unintended asset. Test actual format-specific bounds and one-over-bound cases, remote chunked/oversized inputs, and finite parser behavior. Document current supported limits and qualification results; new caps or asynchronous uploads require a separate decision.

**Evidence:** [transaction entrypoints](<../../backend/src/main/java/com/prototype/vulnwatch/service/BomIngestionOrchestrator.java>) (line 184), [mutation before validation](<../../backend/src/main/java/com/prototype/vulnwatch/service/BomIngestionOrchestrator.java>) (line 341), [checked replacement failure](<../../backend/src/main/java/com/prototype/vulnwatch/service/BomIngestionOrchestrator.java>) (line 434), [remote allocation](<../../backend/src/main/java/com/prototype/vulnwatch/service/sbomingestion/SbomEndpointFetchService.java>) (line 41), [worker rollback](<../../backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobWorkerService.java>) (line 155).

<a id="p26"></a>

### P26 — Bound existing retention work and preserve configured protections

**Severity:** High · **Milestone:** M2 · **Owner:** F, B, P, S · **Effort:** M

**Delivery tier:** 2 · **Implementation gates:** —; T?; O?

**Basis:** Code, Config, Qualification. **Previous tasks:** T05, T23/T25.

The application already implements retention classes, legal/replay holds and purge auditing. It should not be described as having no retention controls. However, the existing sweep reads all snapshot bodies and the purge query can claim all eligible rows, placing an unbounded amount of work in a transaction. Retention configuration is not evidence that every stored category is actually cleaned up.

**Fix:** produce a checked-in cleanup matrix listing each retained data category/table/artifact, existing policy/config key, entrypoint/role/schedule, batch and transaction bounds, reference/hold/replay checks, audit behavior, overlap/retry behavior and regression coverage. Separate verified defects from uninspected paths; estimate the latter after the matrix. Repair the already verified unbounded AiGridRetentionService sweep/purge independently with bounded selection, stable pagination, transaction duration and retry. Preserve current protections and make disabled/failed/overdue work visible. Honor existing approved policies without inventing retention periods, storage allowances, deletion deadlines or compliance commitments.

**Done when:** every retained cleanup category has a matrix disposition and owner. Proposed `RetentionBatchHoldPostgresIntegrationTest` processes more than two configured batches, injects failure/restart between batches, and verifies bounded claims, forward progress and audit without duplicates or skipped eligible rows. Held, referenced, unexpired and replay-protected evidence survives concurrent cleanup. Report actual batch/transaction bounds from the selected implementation and configuration; do not invent a new business retention policy.

**Evidence:** [unbounded sweep](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridRetentionService.java>) (line 124), [purge selection and auditing](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridRetentionService.java>) (line 182), [hold protection](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridRetentionService.java>) (line 209).

## D. Current authentication and customer-facing behavior

<a id="p27"></a>

### P27 — Make the existing authentication contract coherent

**Severity:** High · **Milestone:** M2 · **Owner:** B, UI, S · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A!; T!; D?

**Basis:** Decision, Code. **Previous tasks:** T03/T26–T31.

Local login/setup/context selection emits HS256 tokens, while an external issuer decoder takes priority when configured. Those settings can make the application reject its own tokens. Audience validation is optional. Current APIs use Bearer JWTs and platform-owner context-switch operations, rather than application server sessions.

**Fix:** retain and repair those existing interfaces: align issuance/validation algorithm, key, issuer/audience and token-purpose rules; reject incompatible decoder/issuer combinations. Preserve tenant access mode/reference claims and revalidate their current membership/support authority. Bind CSRF exemptions to the actual authentication mechanism; retain protection for ambient setup-cookie flows. Do not introduce managed identity, server sessions or workspace redesign in this work.

**Done when:** local login/setup/context selection tokens are accepted by the configured decoder; wrong issuer/audience/algorithm/purpose and revoked access fail; existing browser journeys pass without development header fallbacks. Invalid Bearer credentials never fall back to API keys.

**Evidence:** [issuer](<../../backend/src/main/java/com/prototype/vulnwatch/service/AuthTokenService.java>) (line 98), [decoder priority](<../../backend/src/main/java/com/prototype/vulnwatch/config/JwtDecoderConfig.java>) (line 28), [context API](<../../backend/src/main/java/com/prototype/vulnwatch/controller/LocalAuthController.java>) (line 86), [CSRF rules](<../../backend/src/main/java/com/prototype/vulnwatch/config/SecurityConfig.java>) (line 24).

<a id="p28"></a>

### P28 — Qualify existing support and service-account authorization

**Severity:** High · **Milestone:** M2 · **Owner:** B, S, UI, Q · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A!; T!

**Basis:** Decision, Qualification. **Previous tasks:** T28/T30/X01/X02.

Support grants already constrain tenant, subject, expiry and read/write access; support alone cannot grant tenant administration. Stored scope is not visibly enforced as fine resource/action scope. Service-account registry metadata is not itself a credential verifier, although JWT service-account authorization exists.

**Fix:** preserve and test existing support restrictions, revocation and audit attribution; describe current support as tenant-wide unless finer scope is actually implemented. Constrain service-account roles and ensure retained credential paths bind an active account to its tenant. Disable unsupported authentication paths rather than treating key IDs as secrets. No new machine-auth platform or support-session architecture is required.

**Done when:** expired/revoked/read-only grants cannot perform prohibited operations; support cannot administer membership without direct authorization; deleted/disabled/wrong-tenant service accounts cannot act. Published scope matches enforced behavior.

**Evidence:** [support scope](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantSupportGrantService.java>) (line 111), [administration guard](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantAccessControlService.java>) (line 28), [service-account creation](<../../backend/src/main/java/com/prototype/vulnwatch/service/IdentityAdministrationService.java>) (line 303).

<a id="p29"></a>

### P29 — Make entitlement behavior match intended configuration

**Severity:** High · **Milestone:** M2 · **Owner:** F, B, Q · **Effort:** M

**Delivery tier:** 3 · **Implementation gates:** A?; D?

**Basis:** Config, Decision. **Previous tasks:** T34.

Base configuration defaults to LEGACY; production does not override it. LEGACY returns enabled entitlements, and SHADOW still enforces that legacy result while observing corrected outcomes. ENFORCE can also retain legacy results outside its configured cohort. Invalid modes already fail startup; blank values fall back to LEGACY. Actual deployment overrides were not inspected.

**Fix:** make the pilot baseline explicit: configure ENFORCE for the named pilot-tenant cohort after its existing plan/override matrix passes regression checks, with a deliberate allowlist rather than an assumed empty cohort or wildcard. Use SHADOW only for prior characterization; LEGACY/SHADOW are not access enforcement. Test existing service/API enforcement for retained capabilities. Keep authorization, server feature-disable gates and resource limits independent of optional commercial paywalls; no billing-system implementation is included.

**Done when:** evidence records the effective mode, explicit pilot cohort and intended capability matrix without secrets. Enabled/disabled plans, expired overrides, unknown keys and cohort/non-cohort fixtures behave as specified at reachable service/API boundaries, with matching UI state. Confirm that disabled Azure/JDBC/generative surfaces remain blocked regardless of an entitlement result. No mandatory shadow waiting period or commercial billing project is introduced.

**Evidence:** [base default](<../../backend/src/main/resources/application.yml>) (line 66), [legacy semantics](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantEntitlementService.java>) (line 157), [enforcement cohort](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantEntitlementService.java>) (line 180), [mode parsing](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantEntitlementService.java>) (line 253).

<a id="p30"></a>

### P30 — Remove inconsistent exposure of unfinished existing capabilities

**Severity:** High · **Milestone:** M1 · **Owner:** F, B, UI, Q · **Effort:** S

**Delivery tier:** 3 · **Implementation gates:** A?; D?

**Basis:** Decision, Code. **Previous tasks:** T02/T33/T49.

Fix Intelligence is publicly permitted and returns synthetic data. OSV tenant correlation is a placeholder, and runtime telemetry is explicitly excluded by startup validation. These existing behaviors must agree with reachable APIs, background jobs and UI claims. Static AI analysis and other existing supported workflows can remain; this item does not build replacement capabilities or expand coverage.

**Fix:** disable unfinished OSV tenant-correlation paths and synthetic/unsupported surfaces at the API/service boundary, remove misleading UI entry points and ensure jobs cannot invoke disabled behavior. Keep the existing runtime exclusion effective through ordinary configuration. Describe retained static AI and inventory coverage accurately. Preserve real supported workflows and the protected operational demo-request form where applicable; do not make a hidden endpoint the substitute for server-side disablement.

**Done when:** direct unsupported API calls and scheduled/manual job paths reject or remain inactive, with no synthetic result presented as customer evidence. Existing retained workflows still pass their regression tests. UI, configuration and documentation agree on current behavior, and disabling optional assistance preserves deterministic results rather than introducing a new feature implementation.

**Evidence:** [public synthetic surface](<../../backend/src/main/java/com/prototype/vulnwatch/config/SecurityConfig.java>) (line 81), [OSV correlation placeholder](<../../backend/src/main/java/com/prototype/vulnwatch/service/vulningestion/OsvTenantService.java>) (line 97), [runtime exclusion](<../../backend/src/main/java/com/prototype/vulnwatch/config/ProductionSafetyValidator.java>) (line 85).

<a id="p31"></a>

### P31 — Make optional generative assistance obey its controls

**Severity:** High · **Milestone:** M2 · **Owner:** B, S, F, Q · **Effort:** M

**Delivery tier:** 3 · **Implementation gates:** A?; D?

**Basis:** Code, Qualification. **Previous tasks:** T53.

Investigation summaries bypass the general AI-enabled flag. A remediation prompt requests vendor attribution from model memory when advisory evidence is absent. Existing FixRecord and UpgradeRecommendation fallbacks keep producing guidance with AI unavailable, but generic upgrade text is not a verified version, and FixRecord still fetches advisory/MSRC content before checking AI availability.

**Fix:** keep optional generative assistance off server-side for the pilot. Set and verify the existing AI-enabled control, repair the investigation-summary bypass and cover all effective key aliases; pending that repair, restrict the endpoint or remove effective provider credentials through a separately authorized operation. Preserve deterministic summaries, findings, posture and polling. Remove unsupported vendor attribution and correct misleading fallback wording, including generic upgrade guidance presented as a verified version. Re-enablement and its authorization/budget/payload qualification are a separate explicit decision, not an automatic result of finishing this repair.

**Done when:** disabled and unauthorized calls make no generative-provider request, including the investigation-summary path. Controlled AI-off/outage fixtures produce usable fallback guidance without fabricated evidence or verified-version claims; distinguish metadata timestamps from substantive deterministic output. Advisory retrieval failures remain visible. Existing deterministic assessment polling continues to work; no new model/provider integration is required.

**Evidence:** [summary bypass](<../../backend/src/main/java/com/prototype/vulnwatch/service/CveInvestigationAiSummaryService.java>) (line 191), [attribution instruction](<../../backend/src/main/java/com/prototype/vulnwatch/service/CveAiSolutionService.java>) (line 117), [FixRecord availability/fallback](<../../backend/src/main/java/com/prototype/vulnwatch/service/FixRecordService.java>) (line 373), [generic upgrade fallback](<../../backend/src/main/java/com/prototype/vulnwatch/service/UpgradeRecommendationService.java>) (line 44).

<a id="p32"></a>

### P32 — Repair email transaction boundaries and retry identity

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** L

**Delivery tier:** 2 · **Implementation gates:** A?; T?; O?

**Basis:** Code, Config. **Previous tasks:** T46.

Invite creation/resend sends before its transaction commits. Resend rotates the invitation token but reuses the invite-ID provider key. Campaign keys can collide across distinct same-type events, while demo invites supply no key. Provider idempotency exists; the missing consistency is durable logical delivery identity and its relationship to committed token/event state.

**Fix:** persist committed email intent using the application's PostgreSQL job/outbox conventions and existing delivery records. Give each logical delivery an ID and immutable payload/token-version reference; encrypt any retry-required bearer material while invitation records retain only digests. Retries reuse that identity and payload; deliberate reissue/resend and distinct campaign events get new IDs. Keep the current provider. Add bounded retry, terminal failure and controlled resend through existing application status/operations surfaces; record provider acceptance honestly without claiming confirmed inbox delivery. Reconcile unknown acceptance after the provider's idempotency window rather than retrying blindly.

**Done when:** transaction rollback sends no uncommitted token; process loss and timeout-after-accept reuse the same delivery identity within provider guarantees. Rotated invite resend and distinct same-type campaign events do not collide. Failures/unknown acceptance are visible and recoverable; an invitation never becomes irretrievably unusable because delivery intent was lost. No new bounce webhook or provider migration is required for this repair.

**Evidence:** [transactional invite send](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantUserInviteService.java>) (line 57), [token rotation](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantUserInviteService.java>) (line 87), [reused provider key](<../../backend/src/main/java/com/prototype/vulnwatch/service/TenantInviteEmailService.java>) (line 44), [campaign send/key/save](<../../backend/src/main/java/com/prototype/vulnwatch/service/CampaignService.java>) (line 543), [provider idempotency support](<../../backend/src/main/java/com/prototype/vulnwatch/client/ResendEmailClient.java>) (line 103).

<a id="p33"></a>

### P33 — Remove production client secrets and scrub telemetry

**Severity:** High · **Milestone:** M1 · **Owner:** UI, S, Q · **Effort:** M

**Delivery tier:** 1 · **Implementation gates:** A!; D?

**Basis:** Code, Config. **Previous tasks:** T31/T57.

Static VITE authentication inputs can embed arbitrary credentials; the bundle guard detects selected patterns only. Sentry enables default PII without application scrub hooks. Public invite calls omit the custom timing breadcrumb, but installed default SDK integrations collect current-page/navigation/request URLs containing route tokens. Disabling default PII alone does not scrub these URLs.

**Fix:** remove or development-gate static authentication inputs, strengthen bundle checks and redact credentials/PII in existing telemetry. Coordinate P05 URL repairs; fragments remain visible to JavaScript until removed and still require scrubbing. Preserve existing browser authentication without adding a new session model.

**Done when:** sentinel JWT/arbitrary-key production builds reject/exclude credentials; controlled invitation/setup navigation and error payloads contain no sentinel in URLs, referrers or breadcrumbs; disabled telemetry remains disabled. Validate payloads without exposing real secrets.

**Evidence:** [static inputs](<../../frontend/src/api/client.ts>) (line 678), [Sentry configuration](<../../frontend/src/main.tsx>) (line 9), [token routes](<../../frontend/src/App.tsx>) (line 1422), [bundle guard](<../../frontend/scripts/verify-production-bundle.mjs>) (line 5), [SDK dependency](<../../frontend/package.json>) (line 18).

<a id="p34"></a>

### P34 — Repair unsafe audit export and preserve audit controls

**Severity:** Moderate · **Milestone:** M2 · **Owner:** B, S, Q · **Effort:** S

**Delivery tier:** 3 · **Implementation gates:** A?; T?; O?

**Basis:** Code, Config. **Previous tasks:** T23/T30/T61.

The existing audit CSV exporter escapes quotes but does not neutralize spreadsheet formulas or control prefixes. A caller-supplied request ID can reach an exported field. Audit export already has access checks, and another existing CSV formatter provides stronger handling; the repair should preserve those controls rather than imply that audit access is currently public.

**Fix:** retain authorized audit CSV export and apply the stronger existing safe-encoding pattern to untrusted cells. If this small repair cannot ship safely, temporarily block CSV while keeping authorized JSON access; record that as containment, not the preferred permanent scope. Validate correlation fields and preserve current tenant scoping, append/mutation restrictions and configured cleanup permissions. Do not introduce new compliance retention periods or external audit storage.

**Done when:** for retained CSV, formula/control-prefix variants remain text, ordinary quotes/newlines remain usable, and wrong-tenant export fails. A temporary CSV block is recorded as Contained—disabled and is not evidence that encoding is repaired. Unauthorized audit mutation is denied while approved recording and cleanup still work. Tests include user-controlled fields without real secrets.

**Evidence:** [audit exporter](<../../backend/src/main/java/com/prototype/vulnwatch/service/AuditEventService.java>) (line 190), [quote-only encoding](<../../backend/src/main/java/com/prototype/vulnwatch/service/AuditEventService.java>) (line 252), [request ID input](<../../backend/src/main/java/com/prototype/vulnwatch/config/RequestCorrelationFilter.java>) (line 57), [existing safer formatter](<../../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiSecurityApiService.java>) (line 683).

## E. Existing telemetry and regression qualification

<a id="p35"></a>

### P35 — Make current metrics truthful about role, scope and freshness

**Severity:** High · **Milestone:** M2 · **Owner:** B, P, Q · **Effort:** M

**Delivery tier:** 3 · **Implementation gates:** —; T?; D?

**Basis:** Code, Config, Qualification. **Previous tasks:** T57/T58/T65.

Operational read samples cover only a JVM's recent window. Four freshness gauges initialize to zero and refresh through a scheduler suppressed on API-role instances. Worker refresh traverses every tenant and publishes after the whole loop, so an unready tenant can abort refresh and leave previous/default values. This does not mean every API metric is zero, and not every non-active tenant necessarily fails the check.

**Fix:** expose refresh time, validity and error state; isolate tenant failures and select eligible tenants deliberately. Publish measurements from the role that actually owns them. Label local windows honestly and prevent default or stale values from appearing as a verified healthy fleet. Reuse current metrics and operational endpoints rather than building a new global snapshot service, monitoring platform or cloud alert stack.

**Done when:** known pending work and lag produce correct readings; API/worker roles expose accurate scope. One failed tenant does not conceal the remainder; partial refresh is visibly incomplete/stale. Tests cover startup, failure and recovery, with bounded labels and no secrets or payloads in telemetry.

**Evidence:** [JVM-local sample window](<../../backend/src/main/java/com/prototype/vulnwatch/service/OperationalMetricsService.java>) (line 57), [gauge defaults and whole-loop publication](<../../backend/src/main/java/com/prototype/vulnwatch/service/PerformanceTelemetryService.java>) (line 27), [scheduler role guard](<../../backend/src/main/java/com/prototype/vulnwatch/service/PerformanceTelemetryScheduler.java>) (line 27).

<a id="p36"></a>

### P36 — Verify the repaired current application and update stale guidance

**Severity:** High · **Milestone:** M3 · **Owner:** Q, B, UI, P, S, F · **Effort:** L

**Delivery tier:** 3 · **Implementation gates:** D?; O?; G?

**Basis:** Qualification. **Previous tasks:** T05, T06/T54–T69.

Existing CI, restricted-role tests and scanners do not establish that proposed repairs have passed. This gate covers the current application and documented configuration. Cloud deployment, new identity/storage services, production-scale load, recovery objectives and customer cutover remain separate.

**Fix:** add targeted regressions for repaired behavior and run the relevant existing frontend, backend, PostgreSQL, migration and script gates. Reconcile any remaining catalog/version instructions and moved-document links with source: current packaged heads are independently resolved (now platform V6 and tenant V5), later migrations are append-only, and historical development reset authorization does not permit resetting the shared database. The integrity guard's historical all-V1 exception is already inapplicable with tenant V2; do not invent a current failure caused solely by the moved archive record.

**Done when:** the identified source revision passes applicable CI without weakened coverage thresholds. Evidence includes frontend lint/typecheck/build/tests and credential-bundle checks; backend verification; restricted-role PostgreSQL bootstrap and tenant lifecycle cases; authorization, rollback, concurrency, failure and disabled-capability regressions relevant to each fix; and migration/script checks. Disposable fixtures test destructive cleanup safely. Record configuration assumptions, exclusions, test outputs and reviewer. Update remaining stale guidance as a scoped documentation fix; preserve already corrected guidance. Remaining live Render configuration checks are explicitly listed, and no result is labeled AWS-qualified or production-ready merely because these application checks pass.

**Evidence:** [quality workflow](<../../../.github/workflows/quality.yml>) (line 12), [restricted-role integration tests](<../../backend/src/test/java/com/prototype/vulnwatch/migration/ProductionBootstrapCliPostgresIntegrationTest.java>) (line 194), [catalog](<../../backend/src/test/java/com/prototype/vulnwatch/migration/MigrationCatalogTest.java>) (line 28), [historical reset guard](<../../../.github/scripts/check-migration-integrity.py>) (line 52), [guidance to reconcile](<../../CLAUDE.md>) (line 279).

## Deferred platform work and closure rules

| Area | This plan repairs | Deferred to a separate program |
| --- | --- | --- |
| Identity | Current role/status/revocation and issuer/decoder consistency; current invite/setup/workspace behavior. | Cognito pools, managed login/email, new browser sessions, MFA/SSO and owner recovery under a new provider. |
| Existing AWS connector | Tenant/account/role/ExternalId binding and controlled negative tests. | Cloud identities, permissions deployment, onboarding templates/stacks and live AWS qualification. |
| DB and readiness | Current JDBC options/trust validation, bootstrap, grants, activation and tenant eligibility. | RDS/ALB configuration, infrastructure orchestration and cloud failover. |
| Storage | Truthful current archive IO, bounds, references and explicit disablement if unsafe. | S3 adapters, object infrastructure and shared-storage migration. |
| Application email | Existing email transaction boundary and retry identity, with bounded retries and visible failed/unknown outcomes. | SES migration, custom Cognito sender and new signed delivery/bounce webhook endpoints. |
| Qualification | Current-stack regression, existing performance gates and local interruption/rollback consistency. | AWS provisioning, actual cloud recovery/cutover, contractual availability/capacity and compliance programs. |

Earlier proposed launch sizes, 10 MiB/25,000-component caps, new pending-job limits, 7/30/90-day retention, 1 GiB storage cap, 15-minute RPO/four-hour RTO and certification timelines are **not adopted by this revision**. Preserve current configured contracts; unresolved business/platform requirements remain separately recorded. Do not claim every original production prerequisite is satisfied merely because this smaller repair plan finishes.

## Appendix A — Evidence and verification limits

This revision uses the earlier parallel source review and targeted checks of the supplied feedback. It does not assert an exhaustive new audit on October 18. Reviewed HEAD remains unchanged. No application code, deploy configuration, credentials or live resources were changed by this document edit.

Two offline checks on October 17 compiled the actual OutboundHostPolicy using resolver-injected Java harnesses. No HTTP/cloud requests were made:

| Approved hostname resolved by test to | Actual policy result |
| --- | --- |
| 127.0.0.1 | Rejected |
| 10.0.0.1 | Rejected |
| 169.254.169.254 | Rejected |
| 169.254.170.2 | Rejected |
| fd00:ec2::254 | Accepted — P09 |
| 64:ff9b::a9fe:a9fe | Accepted — P09 |
| ::a9fe:a9fe | Accepted — P09 |
| 2606:4700:4700::1111 | Accepted |

These establish policy classification, not network reachability or credential retrieval. Other findings use source/control-flow inspection and configured framework behavior. Live exposure, exploitation, actual token transmission and observed abuse remain unverified. Full application, load, restore, provider and live configuration tests were not run for this documentation update. Existing hashes, support controls, RLS, restricted-role tests, queue locks and assessment leases remain counterevidence against blanket missing-control claims.

## Appendix B — Catalog and source guidance

Current packaged heads are platform V6 and tenant V5, as asserted by `MigrationCatalogTest`. Platform V6 is the additive rollout-waiting repair from the implementation closure audit. The presence of post-V1 migrations makes the historical all-V1 reset exception inapplicable regardless of the archived record's location. Moving that record does not change this branch of the check; it does not prove all CI passes. Future migrations stay append-only and tests use disposable databases.

Checking remaining current-version and moved-file references in CLAUDE guidance is a documentation consistency task under P36; preserve corrections already made in the workspace. Preserve the user's archived files; do not restore/move them to satisfy stale links. P30 cites the checked-in runtime exclusion rather than relying on an untracked archive.

**Evidence:** [current catalog](<../../backend/src/test/java/com/prototype/vulnwatch/migration/MigrationCatalogTest.java>) (line 28), [integrity reset guard](<../../../.github/scripts/check-migration-integrity.py>) (line 52), [validator reset guard](<../../../.github/scripts/validate-migrations.py>) (line 54), [application guidance](<../../CLAUDE.md>) (line 279), [backend guidance](<../../backend/CLAUDE.md>) (line 119).

Source links are repository-relative for portability; reviewed line numbers appear as prose because local `:line` URL suffixes are not portable Markdown. They are navigation aids, not immutable release evidence. Record exact commits and test artifacts when implementing fixes. Related architecture/backlog documents provide historical context; this revision's scope takes precedence for this repair program.

Related context: [architecture review](<AWS_production-architecture-review.md>), [migration register](<AWS_production-migration-backlog.md>), [second-plan review](<AWS_second-plan-review.md>).
