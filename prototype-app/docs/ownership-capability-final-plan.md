# Ownership Identification and Routing: Clean-Replacement Architecture Plan

Status: final architecture plan for approval. This is the single ownership planning document and supersedes the earlier ownership plan and Phase 0 design. Nothing in this plan is implemented yet.

Product constraint: **Scoutgrid has no customers using the product. Existing ownership data, rules, APIs, UI behavior and workflows do not require compatibility or migration.** Development and demo ownership data may be discarded and reseeded.

Architecture decision: **replace the current ownership implementation outright.** Scoutgrid will retain source observations as claims, calculate one deterministic assignment for each subject and ownership role, and use stable team IDs for display, filtering and routing. The release will not dual-write, shadow legacy results, convert legacy rules, create `LEGACY_TEXT` teams or preserve `findings.owner_group` as a compatibility contract.

## 1. Outcomes and Scope

The capability must answer:

1. What Scoutgrid object is being owned?
2. Which sources asserted an owner, and how trustworthy and fresh is each assertion?
3. Which team or person is the resolved owner, and why did that claim win?
4. How does the resolved team drive finding routing, review and escalation?

In scope:

- Assignable subjects: assets, components, repositories, cloud accounts, applications, AI systems and AI artifacts. Findings do not hold their own assignments; their owner is derived (section 4.6). CVEs and software scopes are aggregated views over owned subjects, not assignable subjects.
- Technical owner, business owner, security champion and escalation roles.
- Claims from CMDB, SCCM, cloud discovery, AI Grid, manual assignments, new ownership policies and later directory/code sources.
- Canonical teams, typed topology, resolution, explainability, review, routing and lifecycle hygiene. People, external groups and directory identity arrive later (Phase 4). Until then every ownership role targets a team and the capability stores no personal data.
- Tenant isolation, PII protection, audit, key management and operational controls.

Out of scope:

- Preserving or converting existing `ownership_rules`, `owner_group` values, AI Grid owner state/history or old ownership UI behavior.
- Using directories to provision authentication, tenant membership, application roles or global authority.
- Customer-hosted synchronization agents and inbound SCIM.
- Making editable cloud tags authoritative without review.

## 2. Current Implementation: Removal Inventory

Current ownership is fragmented and will be removed:

- `ownership_rules` and `/api/ownership-rules`, including bulk and single-rule apply operations.
- Direct `Finding.setOwnerGroup` writers in rule application, workflow editing, AI posture and AI exposure flows.
- SQL updates of `findings.owner_group` from AI Grid confirmation.
- `ownerGroup` in `FindingWorkflowUpdateRequest` and corresponding frontend controls.
- `findings.owner_group` and `finding_list_projection.owner_group`.
- AI Grid `ai_security_artifacts.owner_*` columns and `ai_grid_owner_history`.
- Legacy `OwnershipSummary.authority` and free-text owner contracts.
- Existing ownership configuration UI and tests that assert the removed behavior.

Removal is staged (expand/contract). Phase 1 adds the new model and moves every reader and writer onto it, so the old columns, table and endpoints are unused. They are dropped by a later migration at the end of Phase 2, once the new read UI exists and a repository scan proves nothing reads them.

Asset source facts such as CMDB `owner_email`, `owner_team`, `managed_by` and `support_group` may remain as raw connector facts where another inventory feature uses them. They are not ownership authority. New ingestion runs emit claims from reviewed source mappings; existing values are not backfilled.

Before implementation, complete a mechanical repository inventory covering:

- Every `Finding.setOwnerGroup` call and SQL write of `owner_group`.
- Every read/write of AI Grid owner columns and history.
- Every DTO, filter, saved queue, campaign, ticket, metric, fixture and UI type that uses owner text.
- Demo, migration, ingestion, correlation and backfill code.

Exit: every old writer and consumer has a deletion or replacement entry. A CI architecture test prevents direct ownership writes outside the new ownership service.

## 3. Architectural Principles

1. **Claims are evidence; assignments are decisions.** Source observations are immutable or superseded. Assignments are reproducible resolver output.
2. **One authority from first release.** Only the resolver changes assignments. Consumers read assignments or ownership projections.
3. **Stable IDs, not names.** Team and principal IDs are canonical. Names are display attributes and may change without changing identity.
4. **Teams route work.** A person may be accountable, but operational routing requires a canonical team.
5. **Directory data never grants authority.** Directory groups and membership cannot create Scoutgrid membership or roles.
6. **Topology is a typed graph.** Inheritance is allowed only on reviewed relation types; the model does not force Scoutgrid into a single-parent tree.
7. **Deterministic and explainable.** The same versioned inputs produce the same assignment and explanation.
8. **Incremental processing.** Changed subjects produce bounded resolver and projection work; tenant-wide rebuild is for repair only.
9. **Strict tenant boundaries.** Every table, reference, cache, job and endpoint is tenant-scoped and tested with the runtime role.
10. **No directory dependency for the core.** Teams and non-PII ownership can operate before Okta or Entra is connected.

## 4. Target Domain Model

All tenant tables use `tenant_id NOT NULL DEFAULT '${tenantId}'`, forced RLS, tenant-inclusive unique keys and tenant-inclusive foreign keys.

### 4.1 Canonical ownership directory

| Entity | Purpose and constraints |
|---|---|
| `team` | Canonical accountable unit. Unique normalized name per tenant; optional parent team, business unit, escalation target, notification channels, ticket assignment group and SLA profile. Cycles and excessive depth are rejected. |
| `team_alias` | Normalized source value mapped to a canonical team. Unique `(tenant_id, source_kind, normalized_alias)` and a tenant-inclusive foreign key to `team`. A value that collides with another team's name or alias is rejected, never merged. Reassigning an alias to a different team is a governed, audited action that republishes the claims it affects. |
| `owner_principal` (Phase 4) | A person only. Pseudonymous source-neutral identity with `ACTIVE`, `DEPARTED` or `ANONYMIZED` status, encrypted display fields, manager and optional primary team. It is not an application user or grant. |
| `external_group` (Phase 4) | Source-scoped directory group identity. It is evidence and does not automatically become a team. |
| `external_group_team_mapping` (Phase 4) | Reviewed mapping from an external group to a canonical team with provenance, state and effective window. |
| `team_member` (Phase 4) | Person-to-team relationship used for display, notification and escalation only. It never grants an application role. |
| `identity_source` | Directory connection with provider, encrypted credentials, mappings, scope, cursor, schedule, status and health. Added only when directory integration begins. |

Manager chains provide escalation evidence; they do not synthesize teams.

**Name and alias namespace.** A team name and an alias are in one per-tenant namespace: an alias may not equal a different team's name, and an alias may not be created or moved so that it collides with another team's name or alias for the same source. Because this spans two tables, separate unique constraints are not enough. All writes to `team` names and `team_alias` go through one transactional service that takes a tenant-scoped advisory lock (`pg_advisory_xact_lock` keyed by tenant) and re-checks both tables inside the transaction. The per-table unique constraints remain as a backstop. Direct SQL writes to either table are blocked by the CI writer-control test.

Until Phase 4 there are no principals: every role targets a `team`, and person-valued source data (for example CMDB `owner_email`) is not stored. It is counted as an unmapped value by source so coverage gaps are measurable, and it becomes claims after directory enrichment and a re-ingestion.

### 4.2 Subjects and typed topology

| Entity | Purpose and constraints |
|---|---|
| `ownership_subject` | Stable registry with `subject_type`, `subject_ref`, lifecycle state and display reference. Unique `(tenant_id, subject_type, subject_ref, generation)`. A type adapter verifies the referenced object exists in the same tenant. Lifecycle is `ACTIVE`, `TOMBSTONED` or `PURGED` (6.5). |
| `ownership_subject_edge` | Typed relation between subjects, such as `APPLICATION_CONTAINS_ASSET`, `REPOSITORY_BUILDS_COMPONENT`, `CLOUD_ACCOUNT_HOSTS_ASSET` or `AI_SYSTEM_CONTAINS_ARTIFACT`. Carries inheritance eligibility. Allowed relation types, parents, children and rules are fixed by the topology relation catalog (Appendix C). |

A subject may have multiple parents. Inheritance-enabled edges must remain acyclic and bounded in depth (default maximum 8). Exposure and CVE relationships do not imply ownership inheritance.

### 4.3 Claims, assignments and governance

| Entity | Purpose and constraints |
|---|---|
| `ownership_claim` | Immutable or superseded assertion for one subject and role. Exactly one resolved target is always present: `team_id` (Phases 1 to 3) or, from Phase 4, `team_id` or `principal_id`. Claims never hold unresolved values. A source value that does not match a team or alias exists only as a deduplicated `ownership_review_item`. From Phase 4 the review item may hold a keyed hash and tenant-encrypted copy of an unresolved person value, never the claim. Carries source kind/ref, authority class, confidence, producer version, observation and expiry. |
| `ownership_assignment` | Current resolver decision for `(tenant_id, subject_id, role)`: winning claim, team/principal, explanation, resolver version, input watermark and resolved time. One current row per subject and role. |
| `ownership_change_request` (Phase 2) | Proposal/approval lifecycle for manual assignment, external-group mapping, topology change, policy activation and bulk reassignment. Stores proposer, approver, reason, effective window, impact and snapshot reference. |
| `ownership_event` | Append-only non-PII history of claims, decisions and governed changes. Also emits the standard audit action. Runtime role has `INSERT` and `SELECT`, never update/delete/truncate. Partitioned monthly by `occurred_at` from creation (6.7). |
| `ownership_review_item` | Deduplicated issue: unmapped value/group, ambiguous identity, departed owner, expiring assignment, conflict, orphan or resolver failure. |
| `ownership_setting` (Phase 2) | Tenant bounds for assignment expiry, anonymization, approvals and display policy. Mandatory security audit cannot be disabled. |

Database constraints enforce target XOR, confidence range, valid effective windows, different proposer and approver, legal states and tenant-inclusive references.

### 4.4 New policy model

The old rules are not converted. A new policy model is introduced only after the core resolver is stable:

- `ownership_policy`
- `ownership_policy_version`
- `ownership_policy_approval`
- `ownership_policy_simulation`
- `ownership_assignment_snapshot`

Only an approved, active and effective policy version emits claims. Simulation is tied to the exact policy version and input watermark approved.

### 4.5 Read projections

Ownership is read by stable IDs:

- Finding list projection adds `owner_team_id` and `owner_team_name`.
- Asset, AI Grid, campaign and ticket services read assignments or a subject ownership projection.
- Filters and grouping use `owner_team_id`; names are display-only.
- “Missing owner” means no authoritative `TECHNICAL_OWNER` team assignment.
- A resolved person without a mapped team is visible in the ownership detail but cannot route work; Scoutgrid creates a review item.

There is no new `findings.owner_group` compatibility column.

### 4.6 Finding ownership derivation

Findings are not ownership subjects. Each finding type has a type-specific adapter that identifies the **canonical ownership subject** for the finding: the host asset, cloud resource asset, component, repository or AI artifact the finding is primarily about.

- The adapter returns exactly one of:
  - `CANONICAL_SUBJECT`: one subject, whose assignments the finding uses.
  - `OWNERSHIP_CONFLICT`: several primary subjects resolve to different teams. The finding shows the conflict, is not routed, and a review item is raised.
  - `UNOWNED`: no canonical subject exists, or the subject has no assignment.
- For `CANONICAL_SUBJECT`, projection reads that subject's resolved assignments (`TECHNICAL_OWNER`, `BUSINESS_OWNER`, `SECURITY_CHAMPION`, `ESCALATION`) and nothing else. It never traverses the hierarchy itself. Inheritance, component-over-application-over-asset precedence and conflicts are the resolver's job, expressed through typed edges.
- Secondary evidence subjects (for example other resources named in an AI exposure path) do not affect routing. They appear in the explanation only.

This keeps assignment volume proportional to inventory, not to findings, and keeps derivation logic in one place. A change to a subject republishes only findings whose canonical subject is that subject or an inheriting descendant. CVE-level and software-scope views show the distribution of owners across affected subjects and do not carry their own owner.

## 5. Resolution Contract

Resolution runs independently for each `(subject, role)` using this ordered contract:

1. Eligibility: correct tenant, valid target, effective window and active source lifecycle.
2. Governance: required approval exists and is still effective.
3. Authority class: `MANUAL_ASSIGNMENT`, `CMDB`, `SOURCE_PROVIDED`, `POLICY_DERIVED`, `SOURCE_DERIVED`, `CANDIDATE`.
4. Topology distance: direct beats inherited within the same authority class.
5. Source priority: platform defaults with bounded tenant configuration.
6. Confidence: normalized decimal from 0 through 1.
7. Observation time: newer wins.
8. Stable claim ID: deterministic final tie-breaker.

Authority classes:

| Class | Meaning |
|---|---|
| `MANUAL_ASSIGNMENT` | Approved or permitted assignment by an authorized user, time-bounded |
| `CMDB` | Value from a customer system of record (ServiceNow CMDB, SCCM) |
| `SOURCE_PROVIDED` | Owner explicitly declared by an inventory source for that object (cloud account owner, AI system owner field, repository metadata) |
| `POLICY_DERIVED` | Output of an approved, active ownership policy |
| `SOURCE_DERIVED` | Inferred from structured source fields (for example a team field on a resource) |
| `CANDIDATE` | Unreviewed hint such as an editable cloud tag |

Rules:

- A higher-authority inherited claim may beat a lower-authority direct candidate.
- Candidate claims may be displayed but do not route work until confirmed.
- Expired claims and claims targeting departed people remain evidence but are ineligible.
- Equal winners from multiple inheritance paths create a conflict review item rather than an arbitrary assignment.
- Manual assignment is a time-bounded approved change request that emits a claim; it is not a direct assignment mutation.
- Replaying unchanged inputs writes no assignment or event.
- The resolver records why the winner won and why competing claims lost.
- Manual assignments warn owners and the review queue 30 days before expiry and can be renewed with a new reason. When one lapses, the assignment falls back to the next claim, with an event and a visible "previously assigned" note. An intentionally permanent owner is expressed by correcting the source or by a policy, not by an unexpiring override.

## 6. Processing and Consistency

### 6.1 Claim admission

Producers use a stable idempotency key derived from tenant, producer, source object, subject, role and producer version. Admission validates producer binding, tenant context and the subject adapter, then commits the claim and durable resolution intent in one transaction.

### 6.2 Durable resolution

- Work is partitioned and fenced by tenant and subject.
- Repeated changes coalesce at the highest input watermark.
- The worker locks the assignment key, resolves all roles, writes changed assignments/events and enqueues projection work atomically.
- Retries are idempotent; a stale fence holder cannot publish.
- Poison work becomes an operations/review item and does not discard later work.

### 6.3 Incremental projections

Implement targeted finding projection upsert/delete by finding ID. Ownership changes use subject edges and finding-subject links to identify affected findings and enqueue coalesced projection work.

### 6.4 Hierarchy fan-out

A change to a parent subject or an inheritance edge can affect every descendant and every finding on them. The design bounds that work:

- Inheritance depth is capped. Descendant walks are memoized per resolution batch.
- A parent change enqueues descendant work in bounded chunks, each fenced and idempotent, and coalesces repeated changes.
- **Impact** is the direct subject, its inheriting descendants and the findings affected through them. Each fan-out computes impact before publishing.
- Interactive changes (manual assignment, policy activation, bulk reassignment) above the tenant threshold require approval and show the impact preview. Topology changes always require approval.
- Automated source refreshes are not gated by interactive approval. They follow a separate policy: bounded publication per run, anomaly detection on the size and rate of ownership change, and a per-source kill switch. A run that exceeds its bound pauses and raises a review item.
- In Phase 1 topology is seeded or configured by the platform only. Tenant topology editing begins in Phase 2, after change requests exist.
- Topology edge changes use the same path, and a rejected cycle never partially applies.
- Load tests cover a single application with 10,000 and 100,000 descendants.

The existing tenant-wide projection rebuild remains a repair and qualification operation. Ownership changes never invoke it per assignment or sync page.

Initial certification targets:

| Measure | Target |
|---|---|
| Claim admission API | p95 under 500 ms, excluding provider sync |
| Assignment propagation | 95% visible within 60 seconds |
| Single-subject resolution | p95 under 250 ms worker time |
| 100,000 changed subjects | completes within 60 minutes without blocking reads |
| Incremental projection | no tenant-wide exclusive lock |
| Idempotent replay | zero additional writes on unchanged input |

Load tests use expected and 3x expected tenant sizes before release.

### 6.5 Subject lifecycle and tombstones

When an asset, component, repository, cloud account, AI artifact or application disappears, ownership must not silently persist or leak to a successor:

1. The type adapter marks the subject `TOMBSTONED` when its source object is deleted, or marked inactive by a complete authoritative scan. Partial or failed scans never tombstone.
2. Its claims become ineligible and its edges inactive. Claims are retained as evidence.
3. The resolver recomputes inherited assignments for its descendants and removes the subject's own assignments.
4. Findings whose canonical subject was the tombstoned subject are reprojected as unowned, with a "subject removed" note.
5. Events keep non-PII references.
6. After the tombstone retention period (default 90 days) the subject is `PURGED`: claims, assignments and edges are deleted and events keep only the subject reference.
7. Reuse safety: the subject key includes a `generation`. A new source object that reuses an old natural identifier (repository name, cloud account ID, hostname) gets a new generation and starts with no ownership. Reactivating a tombstoned subject is an explicit adapter decision allowed only when the producer asserts the same underlying object ID, and it resets claim freshness rather than reviving expired claims silently.

### 6.6 Reconciliation

Queues are not enough. Scheduled reconciliation jobs (Appendix F) compare source observations, claims, assignments, subject registry, finding projections, namespace integrity, durable work watermarks and expected RLS policies and grants. Each job states what it repairs automatically and what becomes a review item or operator alert.

### 6.7 Event storage lifecycle

`ownership_event` is partitioned monthly from the migration that creates it.

- Default retention 400 days, per-tenant bounds in section 13. Partitions older than the tenant's retention are dropped whole.
- A separate maintenance role creates upcoming partitions and detaches or drops expired ones through the control plane. The runtime role cannot create, alter, drop or truncate partitions and cannot update or delete rows.
- Metrics and an alert cover missing future partitions, retention lag and maintenance failures.

## 7. Identity Sources and Privacy

Directory integration follows the ownership core. Phases 1 to 3 store no personal data.

| Provider | Mode | Delivery |
|---|---|---|
| CSV | Size-limited people/group/membership/manager import | First identity-enrichment release |
| Entra ID | Microsoft Graph delta pull | After CSV qualification |
| Okta | Users and Groups API pull | With Entra phase |
| LDAP/AD | LDAPS or StartTLS, paged watermark polling | Extended integration phase |
| Ping, Google Workspace, OneLogin, JumpCloud | Provider pull | Extended integration phase |

Identity rules:

- Resolve values only by exact normalized identifiers such as email, UPN or sAMAccountName. No fuzzy matching.
- Mutable identifiers may create reviewable links but never an irreversible destructive merge.
- Deactivation makes related person claims ineligible and creates reassignment work.
- Imported attributes are allow-listed and scope-limited.
- Directory credentials are separate from login SSO.
- External groups require reviewed mapping to canonical teams.

Privacy rules:

- Names, emails, identifiers, manager chains and memberships are PII.
- PII is tenant-encrypted and masked by default; team names are business data.
- A `TENANT_ADMIN` unmask exception is off by default and requires approval by a different active `TENANT_ADMIN`.
- Every unmasked read is always audited once per request with record count and references, never values. This cannot be disabled.
- Departed principals anonymize after the configured window; pseudonymous references remain.
- “Erase now” is an audited sensitive action that preserves referential integrity.
- Exports are role-gated, reason-bound, audited, limited and watermarked.

## 8. Tenant Isolation, Authorization and Key Management

### 8.1 Isolation and roles

- Jobs, caches, indexes, idempotency keys and metrics are tenant-partitioned.
- Jobs fail closed without explicit tenant context.
- Wrong-tenant IDs return 404.
- Platform owners see aggregate status only unless they have current membership or a scoped support grant.
- Support access is time-boxed, scope-checked, masked by default and always audited.
- Machine claim ingestion requires `SERVICE_ACCOUNT`, current same-tenant registration and producer binding.
- Sensitive actions use the existing sensitive-action interceptor and rate limiting.

| Action | Allowed roles |
|---|---|
| Read team ownership and masked explanations | All tenant roles |
| Configure identity sources/mappings | `TENANT_ADMIN` |
| Manage teams and topology | `TENANT_ADMIN`, `INVENTORY_ADMIN` |
| Propose assignment/policy/bulk changes | `SECURITY_ANALYST`, `INVENTORY_ADMIN`, `TENANT_ADMIN` within action scope |
| Approve governed changes | A different `TENANT_ADMIN` when approval is required |
| Ingest machine claims | Bound `SERVICE_ACCOUNT` only |

Every new controller has explicit method authorization and an authorization-matrix integration test.

### 8.2 Approval semantics

- A manual assignment by `SECURITY_ANALYST`, `INVENTORY_ADMIN` or `TENANT_ADMIN` needs no second approval only when its total computed impact (direct subject, inheriting descendants and affected findings) is at or below the tenant threshold. Assigning a large parent therefore needs approval even though it is one subject.
- Approval by a different `TENANT_ADMIN` is always required for topology changes, policy activation and external-group mappings, and for any change whose impact exceeds the threshold.
- Automated producer refreshes follow the source policy in 6.4, not interactive approval.
- A proposer never approves their own change.
- A tenant with one active `TENANT_ADMIN` cannot activate approval-gated changes and cannot enable the PII unmask exception. This is an accepted limitation, shown clearly in the UI.

### 8.3 Tenant encryption

- One AWS KMS symmetric KEK per environment wraps versioned per-tenant DEKs.
- KMS context binds a wrapped DEK to tenant ID and key version.
- `enc:v3:<tenantKeyVersion>:` uses AES-256-GCM with envelope prefix, tenant ID and column purpose in AAD.
- Plaintext DEK cache is short-lived and keyed by tenant and version.
- Local keys are dev/test only and are rejected in deployed profiles.
- KMS outage fails closed for PII/credential writes; non-PII resolver work continues when decryption is unnecessary.
- Annual DEK rotation is resumable; old versions remain decrypt-only until unreferenced.
- Tenant purge destroys wrapped DEKs only at the authorized irreversible purge stage.

Before any PII or connector credential is stored (Phase 4), approve Render-to-AWS short-lived authentication, KMS key policy, failure handling and evidence. Long-lived static AWS keys are not the default design. KMS uses the AWS SDK with fixed environment configuration, not tenant-configured HTTP egress.

## 9. Intentional Breaking Changes

The release deliberately does not preserve existing ownership behavior.

| Area | Breaking change |
|---|---|
| Legacy rules | Stop evaluating legacy rules and remove `/api/ownership-rules`, its apply operations and the old Ownership UI in Phase 1. Remove the entity, repository and service code and drop `ownership_rules` in Phase 2. No conversion. |
| Finding workflow | Remove `ownerGroup` from workflow requests and responses. Manual changes use ownership change requests. |
| Finding model | Add `owner_team_id` and `owner_team_name` to read projections in Phase 1. Drop `findings.owner_group` and the projection column at the end of Phase 2. |
| Finding filters/queues | Replace owner-name filters with stable `ownerTeamId`. Existing saved queues and demo data may be deleted/reseeded. |
| AI Grid | Replace its independent owner resolver and every reader of the owner columns in Phase 1. Drop the columns and history in Phase 2. AI sources emit claims; UI reads assignments. |
| Asset ownership | Raw connector facts are not displayed as resolved ownership until they produce eligible claims. |
| Campaigns/tickets | Phase 1: read the canonical resolved team (stable ID, display name) instead of free text, with no fallback to old owner values. Phase 5 adds new workflow capability (routing, SLA, escalation). |
| `OwnershipSummary` | Replace legacy `authority` and free-text fields with stable IDs, role, authority class, source, confidence, freshness and explanation. |
| Tests/fixtures | Delete tests for removed workflows and build new contract fixtures. No backward-compatible golden response is required. |

## 10. Clean-Replacement Delivery Plan

There is no legacy shadow comparison, conversion job, tenant-by-tenant compatibility mode or rollback to the old workflow. Migrations are staged expand then contract so the product is never left without ownership. Each phase must pass its security and correctness gates.

### Phase 0: Removal map and architecture closure

Phase 0 produces named, reviewed artifacts. Phase 1 does not start until each is approved. The appendices in this document are the initial drafts; Phase 0 validates them against the code and real data and replaces the drafts with approved versions.

| # | Deliverable | Draft |
|---|---|---|
| 1 | Source-to-claim matrix for every producer | Appendix A |
| 2 | Finding-adapter registry for every finding kind and projection | Appendix B |
| 3 | Topology relation catalog | Appendix C |
| 4 | State-transition tables | Appendix D |
| 5 | Initial database constraint and index design | Appendix E |
| 6 | Reconciliation and failure-recovery design | Appendix F |
| 7 | Phase scorecards and accountable roles | Appendix G |
| 8 | Writer and consumer removal ledger: every `Finding.setOwnerGroup` call, SQL `owner_group` write, AI Grid owner column and history reader or writer (`AiGridFindingService`, `AiGridExposureFindingService`, `AiGridCoverageService`, `AiGridReconciliationService`, `AiExposureIntelligenceService`, `AiSecurityApiService`, `AiGridR2CertificationService`, `AiGridOwnershipService`), DTO, filter, saved queue, campaign, ticket, metric, fixture and UI type, each with a delete or replace action and an owner | New, produced from a mechanical scan |
| 9 | Phase 1 authorization matrix: every new endpoint by role | New |
| 10 | Capacity assumptions: expected and maximum subjects, edges, claims, findings per subject, largest parent fan-out, source refresh sizes, event volume | New |
| 11 | V10 qualification scorecard: template, canary and batch rehearsal checks, fingerprint, RLS and grant verification | New |

Also in Phase 0:

- Complete STRIDE review for claim admission, approvals, identity sources and KMS.
- Approve privacy, retention, support-access, immutable-audit and event-retention policy.
- Capture the current tenant/platform migration heads and the release procedure.
- Sample real CMDB, SCCM, cloud and AI Grid data to confirm which source fields carry team values versus person values.

Exit: all eleven deliverables approved; no unresolved direct writer in the ledger.

### Phase 1: Foundation, resolver and source producers (additive)

One additive tenant V10 migration, delivered as five internal milestones behind disabled kill switches. The milestones are staging for deployment safety, not legacy preservation. Until 1D, the new ownership model is disabled and the old implementation remains the sole temporary authority. Milestone 1D switches all readers and writers in one release. No two production authorities operate simultaneously.

**1A. Foundation**

- Tenant V10 (additive only): `team`, `team_alias`, `ownership_subject`, `ownership_subject_edge`, `ownership_claim`, `ownership_assignment`, `ownership_event` (partitioned, 6.7), `ownership_review_item`, and `owner_team_id` and `owner_team_name` on finding and asset read projections. No drops.
- Update `TenantSchemaCompatibility` from V9 to V10.
- Forced RLS, tenant-inclusive keys, runtime and maintenance role grants, fingerprints, purge coverage.
- Team and alias namespace service with advisory locking (4.1) and the bounded `TENANT_ADMIN` import API.
- Subject adapters for each subject type, including tombstone handling (6.5).
- Durable fenced work types, kill switches, metrics and alerts, CI writer-control tests.
- Event partition maintenance, retention metrics and alert, and proof the runtime role cannot mutate events.

**1B. Resolver**

- Deterministic resolver with precedence, inheritance, fan-out controls (6.4), explanations, events and zero-write replay.
- Targeted projection upsert and delete, finding adapters (4.6, Appendix B) and reconciliation jobs (Appendix F).
- Platform-seeded topology only.

**1C. Producers**

- CMDB, SCCM, AWS, GCP and AI Grid claim producers per Appendix A.
- Exact alias lookup. Unmatched values become `UNMAPPED_VALUE` review items. Person-valued data is counted, not stored.
- Source-bounded publication, anomaly detection and per-source kill switches.

**1D. Consumer cutover**

- Rewrite every reader and writer onto the new model: finding create and correlation, AI Grid posture, exposure, coverage, reconciliation and certification, finding filters and saved queues (`ownerTeamId`), and campaigns and tickets, which now read the canonical resolved team instead of free text.
- Stop evaluating legacy rules. Remove `ownerGroup` from the workflow request, and remove the legacy rule and apply endpoints.
- Replace the old Configurations Ownership tab in the same frontend release with a minimal Ownership panel: team and alias import, unmapped-value review list and per-source coverage.
- Read APIs and minimal finding, asset and AI Grid views showing owner team.

**1E. Qualification**

- Scale and fan-out benchmarks, isolation and concurrency suites, removal scans, migration rehearsal, demo reseeding and the scorecard in Appendix G.

Release procedure: V10 is additive, so the previous binary still runs against it. Run tenant V10 through the control plane (template, canary schema, batches), deploy the new binary and frontend, run schema, RLS, resolver and route smoke checks, and reseed demo ownership data.

Exit: every Phase 1 scorecard gate in Appendix G passes.

### Phase 2: Teams, manual assignment, explanation UI and contract

- Team administration, alias and unmapped-value mapping UI, and tenant topology editing through approved change requests.
- Tenant migration (next version): `ownership_change_request` and `ownership_setting`.
- Manual assignment to teams with reason, expiry, impact preview, expiry warnings, renewal and approval when required (8.2).
- Ownership detail and "why" panels on asset, finding and AI Grid views, with a staleness indicator when resolution is paused.
- Platform console exposes per-tenant counts/status only; support reads remain scoped and audited.
- Contract migration (next version): drop `ownership_rules`, `findings.owner_group`, projection owner columns, `ai_security_artifacts.owner_*` and `ai_grid_owner_history`, after a repository and telemetry scan proves nothing reads them. Remove the now-unused entity, repository and service code and remaining fixtures. The old UI and endpoints were already removed in Phase 1.

Release procedure for the contract migration: stop workers and traffic, back up the database for diagnosis, run the control plane, deploy the contract-compatible binary, smoke test. Correct failures with a forward fix.

Exit: all displayed ownership traces to assignments and claims; the old ownership artifacts no longer exist; authorization, UI read-back, visual and accessibility tests pass.

### Phase 3: Policy engine

- Tenant migration (next version): `ownership_policy` tables.
- Versioned policy draft/review/approval/activation lifecycle.
- Dry-run simulation tied to policy and input versions.
- Scope, typed inheritance, effective windows and impact preview.
- Snapshot and forward rollback within the new assignment model.
- Rule-size, expression-complexity and execution-time limits.

Exit: no policy activates without simulation and required approval; rollback republishes a prior new-model assignment snapshot; scale ceiling set from measured tenant sizes.

### Phase 4: Directory enrichment and people

- Add `ownership.directory` entitlement for identity sources only; core ownership remains available to all plans.
- Approve and implement Render-to-AWS KMS authentication. Then add platform V9 `tenant_data_key` with lifecycle controls, `TenantKeyProvider`, deployed-profile KMS validation, deployed KMS configuration, key destruction in purge coverage and key-related metrics. No PII is stored before this point.
- Tenant migration (next version): `owner_principal`, `external_group`, `external_group_team_mapping`, `team_member`, `identity_source` and PII-bearing claim columns.
- Size-limited CSV import first, then Entra Graph delta and Okta pull. Identity sources cannot be created on demo tenants.
- Allowlist entries for `okta` and `entra`, checked outbound transport, provider host validation, no redirects, and private/link-local/metadata blocking.
- Exact identity linking, ambiguity review, deactivation protection, throttling, cursor/retry and source health.
- Person targets for roles, masking, unmask exception, mandatory read audit, anonymization, erase now.
- Re-ingestion converts previously counted person-valued source data into claims.
- Validate Entra and Okta against authorized real test tenants as well as mocked APIs.

Exit: key, privacy, provider, SSRF, isolation and real-tenant qualification pass. Directory outage does not stop non-PII ownership resolution.

### Phase 5: Hygiene and routing

Phase 1 made existing consumers read resolved teams. Phase 5 adds new workflow capability on top:

- Departed owner, stale/expired claim, conflict and orphan detection.
- Coverage, conflict, stale-owner and mean-time-to-own dashboards, and tenant administration and reporting for event retention.
- Automatic finding routing, SLA clocks and escalation up the team hierarchy, accept and reject with reason, notifications and ticket assignment rules.
- Governed bulk reassignment and bounded import/export.

Exit: routing, lifecycle, anonymization, bulk rollback and export security tests pass, and the Phase 5 scorecard in Appendix G passes.

### Phase 6: Extended integrations and hardening

- LDAPS/AD and other directory providers, CODEOWNERS and reviewed cloud-tag producers.
- Existing connector-secret re-encryption with dry run, per-tenant resume and round-trip verification.
- Final penetration test of identity, approval, claim admission and export paths.

Exit: each provider and producer passes isolation, SSRF and injection suites.

## 11. Operational Controls and Forward Recovery

Runtime states apply only to the new architecture:

1. `DISABLED`: feature unavailable; no claims accepted.
2. `ACTIVE`: claims, resolution and projections operate normally.
3. `RESOLUTION_PAUSED`: claims are retained; assignment work queues without publishing.
4. `SYNC_PAUSED`: directory/source sync is paused; current claims retain accurate freshness.

Recovery principles:

- Preserve claims and events during failures.
- Resume idempotent work from durable watermarks.
- Restore a prior new-model assignment snapshot for an erroneous policy or bulk change.
- Use forward migrations and forward code fixes for release defects.
- Never reactivate the removed rules, owner fields or direct writers.

## 12. Testing and Certification

Required suites:

- **Removal:** repository scan proves old endpoints, rule entity/table access, AI owner storage and direct `owner_group` writers are absent.
- **Reconciliation:** each Appendix F job detects seeded drift, repairs what it should and raises review items for the rest.
- **Lifecycle:** subject tombstone, descendant recompute, finding reprojection, reuse of a natural identifier and purge.
- **Namespace:** concurrent team-create, rename and alias-create or reassign requests that would collide never produce a collision, and the loser is rejected cleanly.
- **Resolver:** precedence, multi-parent conflict, candidate, expiry, departure, stable tie-break and zero-write replay tests.
- **Isolation:** two-tenant PostgreSQL tests using the runtime role, forced RLS, wrong-tenant IDs, jobs, caches and ciphertext.
- **Authorization:** every role/endpoint, revoked membership, platform owner without membership, support grants and wrong-producer service accounts.
- **Governance:** change-request transitions, proposer/approver separation, impact threshold and snapshot restore.
- **Projection:** targeted updates, full-rebuild parity, coalescing, crash recovery and no tenant-wide-lock dependency.
- **Security:** SSRF, redirects, private/link-local/metadata targets, oversized imports, malicious expressions, forged claims and IDOR.
- **Privacy:** masking, mandatory read audit, erasure, anonymization, export and purge/crypto-shred.
- **Keys:** tenant/purpose AAD, rotation, cross-tenant decrypt rejection, KMS failure and deployed rejection of local keys.
- **Scale:** expected and 3x subjects, edges, claims, sync changes and finding fan-out, plus a single parent with 10,000 and 100,000 descendants.
- **Contract release:** repository scan and runtime telemetry prove no reader or writer of dropped objects remains before the contract migration.
- **UI:** fixture journeys, visual checks, keyboard/zoom and axe gates.
- **Providers:** mocked API tests plus authorized real-tenant Entra/Okta qualification.

New golden contracts replace old ownership contracts. No compatibility hash or response-shape preservation is required. Documentation updates accompany each phase: `CLAUDE.md`, backend/database/business-logic guides, PII inventory, schedule matrix, runtime topology check and release checklist.

## 13. Tenant Settings and Platform Bounds

| Setting | Default | Bounds | Control |
|---|---|---|---|
| Anonymization window | 90 days | 30–730 | `TENANT_ADMIN`, audited; legal approval before PII release |
| Approval threshold | 100 affected subjects | 1–measured platform ceiling | `TENANT_ADMIN`, audited |
| PII unmask exception | Off | Boolean | Enable requires different `TENANT_ADMIN`; any admin may disable |
| Unmasked-read audit | Always on | Not configurable | Security control |
| Audit retention | 400 days | 90–2,555, subject to policy | `TENANT_ADMIN`, audited |
| Manual assignment expiry | 90 days | Maximum 365 | Reason required; warning 30 days before expiry |
| Inheritance depth | 8 | 1 to 16 | Platform bound, audited |
| Ownership event retention | 400 days | Per policy, 90 to 2,555 | `TENANT_ADMIN`, audited |
| Inheritance relations | Platform allow-list | Tenant may disable, not invent types | Audited |

## 14. Approvals Required

| Item | Decision | Gate |
|---|---|---|
| Phase 0 artifacts | Approve the eleven Phase 0 deliverables | Before Phase 1 |
| Clean replacement | Accept deletion of existing ownership data, rules, APIs, UI flows, saved owner filters and AI owner history | Before Phase 1 |
| Tenant V10 | Approve additive tenant migration and `TenantSchemaCompatibility` update | Before Phase 1 release |
| Team bootstrap | Approve import API limits and alias policy | Before Phase 1 merge |
| Runtime grants | Approve `provision-runtime-role.sql` changes and append-only event proof | Before Phase 1 merge |
| Deployment | Approve feature switches | Before Phase 1 release |
| Contract migration | Approve the schema-incompatible maintenance release and forward-fix recovery | Before Phase 2 contract release |
| Scale | Approve expected sizes and impact ceiling from test evidence | Before Phase 3 activation |
| KMS and platform V9 | Approve short-lived Render-to-AWS authentication, key policy and the `tenant_data_key` migration | Start of Phase 4, before any PII is stored |
| PII/legal | Approve anonymization, erasure SLA and regional obligations | Before Phase 4 |
| CI/browser | Update workflows only if existing gates do not cover new routes | Before affected UI release |

## 15. Completion Criteria

The capability is complete when:

- The old ownership rules, APIs, columns, history, UI and direct writers no longer exist.
- Every displayed or routed owner traces to a current assignment, winning claim and source evidence.
- Stable team IDs drive filtering, routing, campaigns and tickets.
- Conflicting or ambiguous evidence is reviewable rather than silently overwritten.
- Tenant isolation passes with the deployed runtime role.
- Directory membership cannot create Scoutgrid authority.
- Incremental resolution meets the propagation SLO without tenant-wide projection locks.
- Manual assignments, policies and bulk changes are governed, expiring and reversible within the new model.
- PII is encrypted, masked, audited, erasable and covered by approved policy.
- The additive release and the later contract release are each rehearsed successfully through the control-plane procedure.
- Every finding's owner is derived from its subject by the documented path, with no findings stored as subjects.

## 16. Revision Rationale

This revision followed a senior architecture review. Each change and the reason for it:

| Change | Reason |
|---|---|
| Expand/contract migrations. V10 adds only. Legacy endpoints, rule evaluation and old UI are removed in Phase 1. Old columns, the rules table and dead backend code are dropped at the end of Phase 2 | The earlier plan dropped all ownership storage in Phase 1 but delivered producers, UI and policy in later phases. Every finding would have been unowned, tickets would have lost their assignment group, the S.AI missing-owner boost would have fired on everything, and at least eight AI Grid services that read the owner columns would have broken. The extra migration is cheap and removes a long unusable window. |
| Producers (CMDB, SCCM, AWS, GCP, AI Grid) moved into Phase 1 | They replace code that Phase 1 removes. They are the highest-risk part of the work and should be proven before UI polish, not last. |
| New section 4.6: findings are not subjects, owner derived at projection time | The plan never said how a finding gets its owner, and had a contradiction between 4.2 and 6.3. Storing assignments for every finding multiplies volume by the number of findings and roles. Deriving from the affected subject keeps volume proportional to inventory. CVE and software scope become aggregated views because one CVE spans many owners. |
| Phases 1 to 3 are team-only and non-PII. People, external groups, `team_member` and `identity_source` move to Phase 4 | The earlier plan gated KMS before directory sync but shipped a principal directory in Phase 2 and CMDB `owner_email` claims in Phase 3. That stored PII before tenant keys existed. Making the early phases explicitly non-PII removes the contradiction, honors the "no directory dependency for the core" principle and reduces risk. Person values are counted so the coverage gap stays visible. |
| Tables staged per phase instead of about fifteen in V10 | The repository rejects premature abstraction. Change requests, settings, policy and directory tables are not needed to deliver the first usable increment, and a smaller V10 is easier to qualify. |
| New section 6.4: fan-out design, depth cap, bounded chunked work, impact before publish | The SLOs measured changed subjects, not amplification. One application change can touch every descendant asset, component and finding, and a topology edge change has the same cost. |
| New section 8.2: approval semantics | "When required" was undefined and always needed a second `TENANT_ADMIN`, which makes single-admin tenants unable to do anything gated. Stating the thresholds avoids needless approvals on routine assignments and makes the limitation explicit. |
| Authority classes defined | `CMDB`, `SOURCE_PROVIDED` and `SOURCE_DERIVED` were ambiguous and different producers would have classified the same claim differently. |
| Manual assignment expiry warning, renewal and fallback note | Silent reversion to stale CMDB data after 90 days would flip owners without notice. |
| Event partitioning and baseline retention moved to Phase 1; Phase 5 adds tenant administration and reporting | `ownership_event` is append-only and grows without bound from its first release. Audit retention existed but event table growth did not, and partitioning is harder to retrofit onto a populated table. |
| Resolution paused shows a staleness indicator | A paused resolver otherwise leaves stale values displayed as current. |
| Phase order: policy engine is Phase 3, directory is Phase 4, hygiene and routing Phase 5 | Follows from the changes above. Policy depends only on the core. Directory work depends on keys and legal approval and should not block the core. |
| Approval gates renumbered | KMS and PII/legal gates now precede Phase 4. The scale gate precedes Phase 3. A contract-release gate was added. |

Kept from the earlier version because they were correct: the claims and assignments split, the multi-parent typed graph, the resolver comparison tuple, teams as the routing unit, directory data never granting authority, mandatory unmask audit, tenant and purpose bound encryption, incremental projection, and removing shadow and legacy-conversion machinery.

### Second review round

A follow-up review found five remaining inconsistencies. All were accepted:

| Change | Reason |
|---|---|
| Phase 1 team bootstrap: import API for teams and aliases, exact normalized lookup, unmatched values become `UNMAPPED_VALUE` review items, no automatic team creation, no fuzzy matching. `team_alias` added to V10 | Producers emit team claims in Phase 1, but team administration arrived in Phase 2, so there was no way to create the teams the claims target. Silent team creation would recreate the free-text sprawl this work removes. |
| Impact defined as direct subject plus inheriting descendants plus affected findings. Manual assignments skip approval only at or below the threshold. Topology changes always need approval. Automated refreshes use bounded publication, anomaly detection and a source kill switch. Phase 1 topology is platform-seeded | The earlier text said a single-subject assignment needs no approval, yet assigning a parent could affect 100,000 descendants. It also referenced approval machinery (`ownership_change_request`) that does not exist until Phase 2, and human approval cannot gate automated source runs. |
| Finding derivation rewritten: one canonical subject per finding via a type-specific adapter, secondary subjects explanation-only, multi-subject disagreement becomes a conflict, projection reads the subject's assignment without traversing the hierarchy | The old text applied component, application and asset fallback again after the resolver had already applied inheritance, duplicating logic. It also assumed one affected subject, which is false for AI exposure paths. |
| `tenant_data_key`, `TenantKeyProvider`, KMS validation and deployed KMS configuration moved from Phase 1 to Phase 4 | They were built in Phase 1 but unused until Phase 4, contradicting the principle that tables are staged by need. Phases 1 to 3 hold no personal data and need no encryption infrastructure. |
| Old Ownership UI replaced in the Phase 1 frontend release with a minimal panel (team and alias import, unmapped-value review, source coverage). Phase 2 only drops storage and dead code | Phase 1 removed `/api/ownership-rules` while the UI that calls it was removed in Phase 2, leaving a UI calling deleted endpoints. The minimal panel also gives the new review items a surface. |
| Cross-reference corrected to section 8.2 | The rationale cited the wrong section number. |

### Third review round

| Change | Reason |
|---|---|
| Team name and alias collision checks use one serialized transactional service with a tenant-scoped advisory lock, backed by the per-table unique constraints, plus a concurrency test | The collision rule spans `team.name` and `team_alias.normalized_alias`. Two separate unique constraints cannot enforce it, so two concurrent requests could each pass a check and together create a name and alias that collide, making exact lookup ambiguous. |

### Fourth review round

| Change | Reason |
|---|---|
| Phase 0 lists eleven named deliverables, with Appendices A to G as initial drafts | "Approve concepts" was not verifiable. The producer, adapter and topology contracts decide whether Phase 1 can be built, so they must exist and be reviewed first. |
| Phase 1 split into milestones 1A to 1E under one additive V10 | Phase 1 combined schema, resolver, all producers, every reader, AI Grid replacement, projections, import, UI, grants and qualification. Milestones give implementable, testable steps without preserving legacy behavior or creating two authorities. |
| Appendix A: source-to-claim matrix | CMDB, SCCM, AWS, GCP and AI Grid work cannot start without agreed fields, authority, confidence, expiry, idempotency, deletion and full versus delta behavior. |
| Appendix B: finding-adapter registry, built on the existing `finding_subjects` table | Four finding kinds exist (`VULNERABILITY`, `AI_POSTURE`, `AI_EXPOSURE`, `AI_RUNTIME`) and each needs a defined canonical subject and conflict rule. The existing table already records subjects and roles, so reuse it instead of inventing a parallel link. |
| Appendix C: topology relation catalog | Edges cannot be created safely until every allowed relation, its inheritance, deletion and multi-parent behavior and depth are fixed. |
| Event partitioning and retention moved into Phase 1 (6.7) | The table starts growing in Phase 1. Retrofitting partitioning onto a populated append-only table is harder than creating it partitioned. |
| Subject lifecycle, tombstones and generation (6.5) | Disappearing assets and reused identifiers otherwise leave stale owners or hand a new object the old owner. |
| Phase 1 versus Phase 5 clarified | Phase 1 reads resolved teams in existing consumers. Phase 5 adds new routing, SLA and workflow features. This removes the overlap. |
| Reconciliation jobs (6.6, Appendix F) | Queues fail silently in practice. Drift between claims, assignments, projections and RLS needs scheduled detection with defined repair rules. |
| State-transition tables (Appendix D), constraints and indexes (Appendix E) | Implicit lifecycles produce inconsistent code. Fixing them first removes ambiguity. |
| Measurable scorecards and accountable roles (Appendix G) | Qualitative exits cannot be verified, and cross-cutting failures fall between teams without named owners. |

## Appendix A: Source-to-Claim Matrix (initial draft)

Drafted from the current code and finalized in Phase 0 after sampling real data. Where a field may hold a person rather than a team, only an exact alias match to a team creates a claim; otherwise the value is counted as unmapped and nothing is stored.

Common rules for every producer:

- Idempotency key: `tenant | producer | source object id | subject | role | producer version`.
- Alias lookup: exact normalized match to `team.name_key` or `team_alias` for that `source_kind`. No fuzzy matching, no team creation.
- A claim carries the observation time and a source-specific expiry. A claim whose source is absent in a **complete authoritative full sync** expires. Delta runs, partial scans and failed runs never expire claims.
- Producers never create topology edges unless the table says so.

| Producer | Source fields | Subject | Role | Authority | Confidence | Expiry | Full vs delta | May create edges |
|---|---|---|---|---|---|---|---|---|
| ServiceNow CMDB | `support_group` | Asset | `TECHNICAL_OWNER` | `CMDB` | 0.90 | 2 missed full syncs | Full sync expires, delta refreshes | No in Phase 1 (application relationships proposed for Phase 2) |
| ServiceNow CMDB | `owner_team` (department) | Asset | `BUSINESS_OWNER` | `CMDB` | 0.80 | 2 missed full syncs | Same | No |
| ServiceNow CMDB | `managed_by`, `owner_email` | Asset | `TECHNICAL_OWNER` | `SOURCE_DERIVED` | 0.60 | 2 missed full syncs | Same | No. Counted if no alias match; person values are not stored before Phase 4 |
| SCCM/MECM | Collection or primary-user group fields (confirmed in Phase 0) | Asset | `TECHNICAL_OWNER` | `SOURCE_DERIVED` | 0.60 | 2 missed full syncs | Full inventory sync | No |
| AWS discovery | Account owner field | Cloud account | `TECHNICAL_OWNER` | `SOURCE_PROVIDED` | 0.80 | 2 missed full scans | Full scan | Yes: `CLOUD_ACCOUNT_HOSTS_ASSET` |
| AWS discovery | Resource tags (`owner`, `team`) | Asset | `TECHNICAL_OWNER` | `CANDIDATE` | 0.40 | 2 missed full scans | Full scan | No |
| GCP discovery | Project labels (`owner`, `team`) | Cloud account (project) | `TECHNICAL_OWNER` | `CANDIDATE` | 0.40 | 2 missed full scans | Full scan | Yes: `CLOUD_ACCOUNT_HOSTS_ASSET` |
| GCP discovery | Resource labels (`owner`, `team`) | Asset | `TECHNICAL_OWNER` | `CANDIDATE` | 0.40 | 2 missed full scans | Full scan | No |
| AI Grid (Bedrock, Foundry, Copilot Studio) | Declared owner fields | AI artifact, AI system | `TECHNICAL_OWNER` | `SOURCE_PROVIDED` | 0.80 | 2 missed discovery runs | Full discovery | Yes: `AI_SYSTEM_CONTAINS_ARTIFACT` |
| AI Grid (Bedrock, Foundry, Copilot Studio) | Resource tags | AI artifact | `TECHNICAL_OWNER` | `CANDIDATE` | 0.40 | 2 missed discovery runs | Full discovery | No |
| Existing finding `owner_group` text | Not converted | n/a | n/a | n/a | n/a | n/a | n/a | No backfill, per the clean-replacement decision |

Confidence values are starting defaults, bounded per tenant in Phase 3 and calibrated from Phase 0 samples. Deletion of the source object tombstones the subject (6.5).

## Appendix B: Finding-Adapter Registry (initial draft)

Adapters read the existing `finding_subjects` table (columns `subject_type`, `subject_id`, `subject_role`). Phase 0 catalogs the actual `subject_role` values per finding kind and fixes which roles count as primary.

| Finding kind | Canonical subject | Secondary subjects | Conflict condition | Deleted-subject behavior | Reprojection triggers | Required fixtures |
|---|---|---|---|---|---|---|
| `VULNERABILITY` | The component's subject when `component_id` is set, otherwise the asset's subject. The resolver inherits component ownership from its asset | Vulnerability, software identity | Primary subjects resolve to different teams | `UNOWNED` with "subject removed" | Subject assignment or inheriting-descendant change, subject tombstone, finding subject change | Asset-only, component-only, component with inherited owner, conflicting multi-asset |
| `AI_POSTURE` | The AI artifact subject the policy assessed | Policy, evidence resources | Rare, only if multiple primary artifacts disagree | `UNOWNED` | Same as above plus policy re-assessment | Artifact owned directly, inherited from AI system, unowned |
| `AI_EXPOSURE` | The exposed AI system or artifact that is the exposure target | Intermediate path nodes | Multiple primary targets resolve to different teams | `UNOWNED` | Same as above plus exposure evidence refresh | Single owner path, path crossing two teams |
| `AI_RUNTIME` | None. Runtime findings are out of scope and the adapter is not registered. Enabling runtime findings without registering an adapter fails startup | n/a | n/a | n/a | n/a | Guard test |
| Campaign item | Stores the canonical finding's `owner_team_id` when added and reads current assignment when displayed | n/a | n/a | Shows last known team with a stale marker | Finding reprojection | Reassignment during a campaign |
| Ticket | Reads the canonical team at creation time | n/a | n/a | Falls back to the configured default assignment group | n/a | Team without ticket group |

## Appendix C: Topology Relation Catalog (initial draft)

Maximum inheritance depth defaults to 8. A subject may have several parents only where noted. Equal winners from different parents raise a conflict review item. Deleting or tombstoning either end deactivates the edge (6.5). Tenants may disable inheritance for a relation but cannot invent relation types.

| Relation | Parent | Child | Inherits | Multi-parent | Producer |
|---|---|---|---|---|---|
| `APPLICATION_CONTAINS_ASSET` | Application | Asset | Yes | Yes | Platform-seeded in Phase 1, manual and CMDB from Phase 2 |
| `ASSET_CONTAINS_COMPONENT` | Asset | Component | Yes | No (one asset per component instance) | Inventory, derived automatically |
| `CLOUD_ACCOUNT_HOSTS_ASSET` | Cloud account | Asset | Yes | No | AWS, GCP |
| `REPOSITORY_BUILDS_COMPONENT` | Repository | Component | Yes | Yes | GitHub SBOM ingestion |
| `AI_SYSTEM_CONTAINS_ARTIFACT` | AI system | AI artifact | Yes | Yes | AI Grid |
| `EXPOSURE_EVIDENCE` | AI system or artifact | Related resource | No | Yes | AI Grid |

When parents of different relation types disagree, relation-type precedence is a stable platform constant (application over cloud account over repository) and is shown in the explanation. Equal winners within the same relation type are a conflict.

## Appendix D: State Machines (initial draft)

Every transition writes an `ownership_event` and the standard audit action. "Work" is the durable work emitted.

**Change request** (Phase 2)

| From | To | Actor | Precondition | Work | Retry |
|---|---|---|---|---|---|
| `DRAFT` | `PROPOSED` | Proposer | Valid and impact computed | Impact preview | Idempotent |
| `PROPOSED` | `APPROVED` | Different `TENANT_ADMIN` | Approval required and not proposer | None | n/a |
| `PROPOSED` | `REJECTED` | Approver or proposer withdraw | None | None | n/a |
| `APPROVED` | `APPLIED` | System | Window effective, snapshot taken | Claim emission, resolution | Fenced retry |
| `APPLIED` | `EXPIRED` or `REVOKED` | System or admin | Expiry reached or revoke | Re-resolution | Fenced retry |
| `PROPOSED`, `APPROVED` | `CANCELLED` | Proposer | Not yet applied | None | n/a |

**Review item**

| From | To | Actor | Precondition | Work |
|---|---|---|---|---|
| `OPEN` | `ACKNOWLEDGED` | Authorized user | None | None |
| `OPEN`, `ACKNOWLEDGED` | `RESOLVED` | User or system | Underlying condition fixed (for example alias mapped) | Re-resolution of affected subjects |
| `OPEN`, `ACKNOWLEDGED` | `DISMISSED` | `TENANT_ADMIN` | Reason recorded | None |
| `RESOLVED`, `DISMISSED` | `OPEN` | System | Condition recurs | None |

**Policy version** (Phase 3): `DRAFT` to `IN_REVIEW` (author), `IN_REVIEW` to `APPROVED` (different `TENANT_ADMIN`, simulation current), `APPROVED` to `ACTIVE` (activation window, snapshot taken), `ACTIVE` to `SUPERSEDED` or `RETIRED` (admin), `ACTIVE` to `ROLLED_BACK` (admin, restores snapshot). A simulation invalidated by input change returns `APPROVED` to `IN_REVIEW`.

**Identity source** (Phase 4): `DRAFT` to `ENABLED` (`TENANT_ADMIN`, credentials validated), `ENABLED` to `PAUSED` (admin or system, kill switch), `PAUSED` to `ENABLED`, `ENABLED` to `FAILING` (system, repeated errors), `FAILING` to `ENABLED` (successful sync), any to `DISABLED` (admin, retains evidence).

**Durable work**: `PENDING` to `CLAIMED` (worker, fence token issued), `CLAIMED` to `DONE`, `CLAIMED` to `PENDING` (lease expiry or retryable error with backoff), `CLAIMED` to `POISONED` (retry budget exceeded, review item raised). A stale fence token can never move work to `DONE`.

**Subject lifecycle**: `ACTIVE` to `TOMBSTONED` (adapter, source object deleted or complete scan absence), `TOMBSTONED` to `ACTIVE` (adapter, same underlying object ID, resets freshness), `TOMBSTONED` to `PURGED` (system, retention elapsed). A new object with a reused identifier creates a new generation rather than moving any state.

## Appendix E: Database Constraints and Indexes (initial draft)

All tables: `tenant_id` first in every unique key and index, forced RLS, tenant-inclusive foreign keys.

| Table | Constraints | Indexes |
|---|---|---|
| `team` | Unique `(tenant_id, name_key)`, parent same tenant, no self parent, depth enforced by service | `(tenant_id, parent_team_id)` |
| `team_alias` | Unique `(tenant_id, source_kind, normalized_alias)`, FK `(tenant_id, team_id)` | `(tenant_id, team_id)` |
| `ownership_subject` | Unique `(tenant_id, subject_type, subject_ref, generation)`, state check | `(tenant_id, state)`, `(tenant_id, subject_type, subject_ref)` |
| `ownership_subject_edge` | Unique `(tenant_id, relation, parent_id, child_id)`, parent and child same tenant, relation in catalog, no self edge, acyclicity checked in service within the lock | `(tenant_id, child_id)`, `(tenant_id, parent_id)` |
| `ownership_claim` | Target present (`team_id` XOR `principal_id`), confidence 0 to 1, expiry after observation, unique idempotency key | `(tenant_id, subject_id, role)`, `(tenant_id, source_kind, source_ref)`, partial index on non-expired |
| `ownership_assignment` | Unique `(tenant_id, subject_id, role)`, winning claim same tenant | `(tenant_id, team_id)`, `(tenant_id, subject_id)` |
| `ownership_event` | Partitioned by `occurred_at`, no update or delete grants | `(tenant_id, subject_id, occurred_at)` per partition |
| `ownership_review_item` | Unique open item per `(tenant_id, kind, dedupe_key)` | `(tenant_id, kind, status)` |
| Finding list projection | `owner_team_id` FK to `team` | `(tenant_id, owner_team_id, status)` replacing the owner-name index |

Phase 0 reviews these against the capacity assumptions and adds covering indexes for the heaviest queries (resolver subject fetch, fan-out descendant walk, projection by team).

## Appendix F: Reconciliation and Failure Recovery (initial draft)

All jobs are durable, fenced, tenant-partitioned and run in UTC.

| Job | Compares | Automatic repair | Review item or alert |
|---|---|---|---|
| Source vs claims | Last complete source scan vs active claims | Expire claims for objects absent from a complete full scan, re-emit missing claims | Alert if a producer has not completed in its window |
| Claims vs assignments | Eligible claims vs `ownership_assignment` | Re-run resolution for stale assignments | Review item for resolver failures |
| Assignments vs projections | Assignments vs `owner_team_id` in finding and asset projections | Targeted reprojection of mismatches | Alert above a mismatch threshold |
| Subject registry vs source entities | Subjects vs existing assets, components, repositories, accounts, artifacts | Create missing subjects, tombstone orphans per 6.5 | Review item for unexplained orphans |
| Namespace integrity | Team names vs aliases | None, collisions are rejected at write time | Alert and review item on any collision found |
| Durable work watermarks | Input watermarks vs queue state | Re-enqueue lost work | Alert on poison or stuck work |
| RLS and grants | Expected policies, forced RLS and role grants vs catalog | None (security) | High-severity alert |

The full tenant projection rebuild stays a manual repair tool and is never called by these jobs per item.

## Appendix G: Phase Scorecards and Accountable Roles (initial draft)

### Phase 1 scorecard (all must hold)

| Gate | Target |
|---|---|
| Direct ownership writers remaining (writer ledger, CI scan) | 0 |
| Legacy ownership consumers remaining after cutover | 0 |
| Runtime-role isolation failures | 0 |
| Extra writes on resolver replay of unchanged input | 0 |
| Incremental vs full-rebuild projection mismatches | 0 |
| Namespace collision concurrency tests | 100% pass |
| 100,000-descendant fan-out benchmark | Within the defined SLO |
| PII persisted before Phase 4 | 0 |
| Unmatched values that created teams | 0 |
| Runtime role able to mutate `ownership_event` | 0 |
| Event partition maintenance and retention alert | Verified |
| V10 template, canary and batch rehearsal | Pass |
| All Appendix F jobs detect seeded drift | Pass |

### Later phases (summary)

| Phase | Key gates |
|---|---|
| 2 | Old ownership storage and dead code removed (scan = 0 readers), authorization matrix 100%, expiry warning and renewal verified, contract release rehearsed |
| 3 | No policy active without current simulation and approval, rollback restores a prior snapshot exactly, scale ceiling set from measured data |
| 4 | Key, privacy, SSRF, isolation and real-tenant qualification pass, PII stored only after keys exist, erasure and anonymization verified |
| 5 | Routing and escalation correctness, bulk rollback, export authorization, retention administration verified |
| 6 | Each provider and producer passes isolation, SSRF and injection suites, penetration test findings closed |

### Accountable roles

Roles are defined here and named individuals or teams are assigned when Phase 0 is approved.

| Area | Accountable role |
|---|---|
| Resolver and domain model | Ownership domain lead |
| Database migrations, RLS and grants | Data platform lead |
| Connector producers (CMDB, SCCM, AWS, GCP) | Integrations lead |
| Finding adapters and projections | Findings lead |
| AI Grid replacement and producers | AI Grid lead |
| Frontend and accessibility | Frontend lead |
| KMS, privacy and PII | Security and privacy lead |
| Dashboards, alerts and runbooks | SRE lead |
| Phase acceptance | Architecture owner, with the security lead signing off security gates |
