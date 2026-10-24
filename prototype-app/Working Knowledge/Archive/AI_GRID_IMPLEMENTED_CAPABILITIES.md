# AI Grid — implemented capabilities and remaining work

**Consolidated:** 2026-09-26  
**Repository baseline:** `33d3b18`, plus the working-copy documents reviewed on this date.  
**Scope:** Implemented and remaining work across both document sets: AI Grid Phases 1–2, AWS connector maturity, AgentCore evidence, ARISE alignment and migration infrastructure.

## 1. Current state

AI Grid now has the engineering foundation to inventory cloud AI systems and agents, assess configuration and access risks, collect privacy-minimized execution metadata, and evaluate deterministic runtime policies. It extends the existing ScoutGrid/VulnWatch inventory, graph, evidence, policy and finding workflows.

**Phase 1 infrastructure and the governed posture/exposure catalog are implemented. Phase 2 ingestion, evaluation, investigation and policy packages are implemented, but runtime policies remain preview/paused pending live evidence, certification and rollout.** Implementation completion does not establish that every proposed policy, customer outcome or operational release gate has been delivered.

This document consolidates the eleven source documents listed at the end, including the original seven plans and four additional documents, into one implementation and remaining-work record. Their recommendations were treated as planning context, not as instructions to execute. Current source, package predicates and manifests take precedence over older roadmap wording. No production database, live tenant configuration or customer pilot was inspected for this consolidation.

| Area | Implemented state | Release/evidence boundary |
|---|---|---|
| AI inventory and static exposure | AWS, Azure and Copilot discovery, relationships, agent systems, ownership, snapshots, facts and findings | Coverage depends on provider permissions, supported resource kinds and authoritative relationships |
| Policy and framework governance | Versioned catalog, tenant selections, readiness, framework reporting, approved manifests and component allowlists | Catalog presence and framework mapping do not prove effective tenant coverage |
| Runtime foundation | Execution/event ingestion, correlation, HMAC identifiers, capability registry, retention and guarded telemetry adapter | Available provider metadata is narrower than the schema |
| Runtime detection | Four evaluation modes and nine executable runtime packages | All nine packages are `PREVIEW` by default and `PAUSED` for release |
| Runtime investigation | Execution list, timeline, evidence references, finding integration and readiness/operations reporting | Only evidence actually supplied by a qualified source can support a conclusion |
| AI-BOM | Generic AI-BOM ingestion exists | Uploaded AI-BOM evidence is not yet integrated into AI Grid |
| Preventive agent controls | No completed inline agent enforcement established by this review | Collection kill switches are not agent termination or tool blocking |

## 2. Shared platform already in place

The agent-security work reuses these implemented AI Grid capabilities:

- **Tenant and role controls:** the `ai.security` entitlement, tenant-isolated data access and separate platform-owner policy administration.
- **Discovery and processing:** scheduled connector jobs, validated observation envelopes, idempotent observation receipts and complete-scope processing.
- **Evidence:** allowlisted and redacted artifact metadata, immutable hash-deduplicated snapshots, versioned facts and relationship snapshots. Artifact policies evaluate derived facts rather than raw provider payloads.
- **Current inventory:** coverage epochs built from the latest complete scans, with reconciliation rather than a mixture of partial discovery runs.
- **AI systems:** agent-rooted graph grouping, reviewed memberships, revisions and split/merge/successor/retirement lineage.
- **Ownership:** confirmed, inferred, candidate and unowned states, with ownership history.
- **Policy governance:** immutable versions, tenant scopes/conditions/parameters/exceptions, reassessment, answer-key validation, precision review, approvals, canary/GA distribution and release manifests.
- **Exposure evidence:** correlation paths, evidence/freshness checks, hypothesis versus validated-exposure states, analyst disposition and freshness-driven demotion.
- **Analyst workflow:** canonical posture and exposure findings, ownership, review, SLA/workflow and existing ServiceNow incident integration.
- **Operations:** scan/API/byte/processing budgets, cadence controls, setup actions, readiness, assessment metrics, evidence retention classes, legal holds and purge audit records.

Runtime records have their own bounded retention implementation; the snapshot legal-hold mechanism should not be assumed to provide runtime legal-hold support.

## 3. Phase 1 — posture, static agent exposure and governance

### 3.1 Provider inventory and relationships

| Provider | Implemented collection scope relevant to agent security |
|---|---|
| AWS Bedrock / AgentCore / SageMaker | Bedrock agents, action groups, models, guardrails, knowledge bases/data sources, prompts and flows; linked IAM, Lambda and S3 controls; existing Macie classifications; AgentCore gateways/targets and MCP metadata; runtime/version/endpoint/role/workload-identity inventory; browser, Code Interpreter and memory resources; SageMaker resources |
| Azure AI / Foundry | Accounts, projects, deployments, agents and versions, active-version/model/prompt/tool relationships, prompt/tool digests and MCP metadata; RAI configuration; identity/RBAC, network and logging controls; ML, Search, Storage and existing Purview classification metadata; Bot resources |
| Copilot Studio | Bots, versions, prompts, tools and components; component type/version; HMAC-safe definition digests; version-to-prompt/tool/component relationships; a separate metadata-only runtime collection path |

Macie and Purview integrations consume existing classification results. They do not launch native data scans. MCP discovery does not establish that a tool was actually invoked.

AgentCore resource inventory does **not** establish runtime-to-browser, Code-Interpreter, memory, gateway or tool-use relationships. Policies requiring such relationships need authoritative attachment or execution evidence.

### 3.2 Implemented posture and exposure coverage

The static catalog contains **159 distinct policies**: 72 AWS, 75 Azure and 12 multi-cloud correlations. It covers guardrails, identity/privilege, model and tool controls, MCP authentication/trust, sensitive-data paths, storage/retrieval isolation, provenance, network controls and consumption-related configuration.

The Phase 1 package set contains **76 policies**: 38 AWS, 32 Azure and six multi-resource correlations. The six correlation packages express:

| Policy | Risk assessed |
|---|---|
| `AGCF-XSP-001` | External exposure path to sensitive data |
| `AGCF-XSP-002` | High-impact tool path to confirmed sensitive data |
| `AGCF-XSP-003` | Broad identity permissions reaching a high-impact tool |
| `AGCF-XSP-004` | External/unapproved MCP path reaching sensitive data |
| `AGCF-XSP-005` | Autonomous/high-impact execution configuration with weak MCP authentication |
| `AGCF-XSP-006` | Sensitive retrieval without the required guardrail/PII baseline |

These are static, policy-backed exposure conditions. Their names do not imply observation of a successful runtime attack. Missing relationships, stale evidence or unsupported capabilities cannot establish a validated exposure.

### 3.3 Approved definitions and policy administration

Implemented controls include:

- Tenant-approved agent-version manifests and component allowlists, with approve/revoke operations and tenant RLS.
- Digest baselines and metadata-only definition identity, without retaining prompt bodies or tool arguments.
- Admin-restricted sensitive writes, audited bulk policy selection and projection refreshes.
- Correct preservation of `REQUIRED`, `ENABLED`, `PREVIEW` and `DISABLED` platform defaults.
- One baseline version per policy, respecting pinned distribution versions.
- Reseeding that realigns `PLATFORM_DEFAULT` rows and preserves `TENANT_OVERRIDE` rows.
- Phase 1 preview/release-board services and a checked-in answer-key corpus.

These foundations do not by themselves complete the proposed standalone policies for privileged agents without approved guardrails, static prompt/tool drift after approval, unapproved Copilot triggers, or unowned production agents. Those proposals are not counted here as newly shipped policies.

### 3.4 Framework reporting and certification preparation

Framework registration includes `OWASP_GENAI_LLM_TOP_10` version `2026`, `OWASP_AGENTIC_TOP_10` version `2026` and `CSA_AICM` version `1.1`. These are repository catalog identifiers; this consolidation does not independently certify the external framework taxonomy or its mappings.

Coverage reporting distinguishes mapped breadth from effective coverage, exposes mapping type and rationale, separates preview policies, and carries applicability/readiness/distribution context. Paused policies cannot count as effective protection.

A 16-policy evidence-certification wave has new immutable **1.0.1** packages:

- `AGCF-AWS-039`–`042`: effective access.
- `AGCF-AZR-033`–`039`: effective access/RBAC.
- `AGCF-AWS-048`–`050`: vector/retrieval controls.
- `AGCF-AWS-071`–`072`: authoritative MCP authentication.

Platform V4 installs this wave without enabling it. Its packages remain disabled/paused and require answer keys, precision review, independent mapping review, approval and canary rollout. Calling this a certification wave does not mean customer certification has occurred.

The latest static package versions contain **52 direct and 142 partial OWASP LLM mappings**, replacing the older 36-direct figure. CSA mappings remain 102 direct and 223 partial. The static packages still have no Agentic mappings and no LLM08 mappings; registering the framework/control is not the same as completing the proposed mapping backfill. The runtime packages add eight Agentic mapping records, which remain subject to their paused release state.

### 3.5 AWS connector maturity implemented beyond the original baseline

The AWS plan's “current-state constraints” describe an older baseline. Source review confirms these later additions:

- **Deployed definitions:** Bedrock version and alias pagination, `AI_AGENT_VERSION` artifacts, alias components, `VERSION_OF` and `SERVES_VERSION` relationships, version-specific model/tool/prompt/guardrail metadata and knowledge-base links.
- **Canonical assets:** action groups as `AI_TOOL`, instruction/override prompts as `AI_PROMPT` with tenant-keyed digests, guardrails as `AI_GUARDRAIL`, and tool-to-Lambda `IMPLEMENTED_BY` relationships.
- **Alias resolution:** execution ingestion resolves alias routes, reports multi-target routing explicitly and excludes alias components from execution participants.
- **Identity evidence:** supporting IAM role artifacts, version-to-role relationships, managed/inline/trust policy inspection, wildcard/PassRole/NotAction/NotResource indicators, boundary presence and per-role failure diagnostics. These indicators are not a complete IAM authorization simulator.
- **Scope reconciliation:** attribute ownership records allow a complete scope to remove its old keys while preserving other scopes' keys and prior evidence for incomplete scopes.
- **Connector safety:** a read-permission matrix, bounded permission preflight, API/concurrency admission budgets, capability manifests and registration certification tests.
- **Curated activity:** `SCOUT_AWS_ACTIVITY` registers seven advisory fact keys covering invocation, tool/identity use, external actions, sensitive-data access, invocation count and last observation. Confidence/expiry checks, activity API/UI and exposure prioritization are implemented. Activity facts alone do not validate an exposure.

The AgentCore evidence matrix is reflected in the implementation: a qualified runtime is a system root, with provider-backed identity/version/endpoint relationships. Runtime versions are not independent roots. Browsers, Code Interpreter, memory and gateways remain separate resources unless authoritative attachment/use evidence exists. No synthetic Bedrock agent is required to represent an AgentCore runtime.

### 3.6 ARISE foundation already covered

The ARISE plan's Layer 1 largely reuses implemented inventory, ownership, identity and relationship context, evidence freshness, policy applicability, impact preview, platform approval, tenant selection and framework reporting. These are not separate missing subsystems simply because the ARISE document phrases them as future work.

Phase 2 also implements part of its later runtime vision: action metadata, execution correlation, approval/policy/outcome evidence, deterministic sequence/retry checks and investigation. It does not implement the full identity/delegation lifecycle, behavioral intent analysis or in-path enforcement described by ARISE. The proposed 61 strong / 12 partial / 86 unmapped split is an unverified planning estimate, not a certified ARISE catalog.

## 4. Phase 2 — runtime evidence and deterministic detection

### 4.1 Runtime records and ingestion

Implemented execution, event, participant, receipt and cursor storage supports correlation to agents, versions and observed participants. Typed fields cover action/target classes, tool and identity references, policy/approval/outcome states, classifications and bounded usage metrics where a source supplies them.

The common ingestion boundary provides:

- Tenant-scoped HMAC identifiers and digest-key versions.
- Closed enums and governed field validation.
- Idempotency, duplicate handling, overlap/lookback cursors and event ordering.
- Event, metadata-size, pagination and API-call limits.
- Metadata-only collection and rejection of prohibited raw-content fields.
- Bounded retention deletion with child-event cascade.
- Capability observations, connector flags and kill switches.

Azure Foundry and Copilot runtime collectors exist; Azure ML can contribute correlated execution metadata. Basic execution identity/status/time/version/usage collection must be distinguished from authoritative action-level evidence. The existing provider metadata paths cannot populate every action, approval, policy, tool and outcome family; unsupported families are explicitly represented rather than inferred.

### 4.2 Governed telemetry adapter

`POST /api/internal/ai-grid/runtime/{producerId}/v1/batches` accepts bounded metadata batches from registered producers such as frameworks, gateways or enforcement integrations.

Implemented safeguards include service-account authorization, principal-to-producer matching, an active producer registration bound to the request tenant, and certification checks for authoritative evidence. Admission uses the existing ingestion-job infrastructure and returns a receipt; capacity/quota rejection uses `429` with `Retry-After`.

The admission limits are layered: **2 MiB request body**, **100 executions per batch**, then per-execution event and metadata limits. Per-tenant rolling event/byte quotas provide soft degradation and hard rejection. Rejected volume is not silently sampled or truncated. Receipt and quota state feed operational/readiness reporting.

Adapter evidence does not become authoritative merely because it was submitted. Certification and the policy's evidence contract determine how it can be used. Adapters are reported separately and do not replace the two-provider readiness requirement.

### 4.3 Runtime evaluation

Runtime evaluation is separate from the artifact-fact loop and uses normalized runtime tables. The artifact evaluator skips execution-subject policies.

| Mode | Implemented purpose |
|---|---|
| `RUNTIME_FACTS` | Bounded conjunction of execution-field conditions |
| `RUNTIME_SEQUENCE` | Ordered event predicates within explicit duration, lateness and event-count bounds |
| `RUNTIME_AGGREGATE` | Registered metrics over bounded lookback windows and grouping keys |
| `RUNTIME_COVERAGE` | Coverage meta-policy scoped to provider/workspace/capability family/window |

Predicates use the runtime field registry. `execution.approval_state` and `event.approval_state`, for example, are distinct; run-level decisions cannot substitute for action-level decisions. Free-form diagnostics are not policy inputs.

Missing or unsupported evidence yields a non-decision with readiness/reason detail rather than `PASS`. The implementation persists values such as `NO_DECISION` and incomplete-evidence states in the shared assessment model; the plans' `UNKNOWN`/`NOT_ASSESSED` language should not be mistaken for a universal database enum.

Only selected `ENABLED`/`REQUIRED` runtime policies evaluate. Preview and disabled selections remain inert. Qualified failures reconcile into **`AI_RUNTIME` findings**, with deterministic grouping/deduplication and execution/event evidence references. The original roadmap's proposed reuse of `AI_EXPOSURE` for runtime findings has been superseded by this separate finding kind.

### 4.4 Nine implemented runtime policies

All packages below are version **1.0.0**, default **`PREVIEW`**, release status **`PAUSED`**. The descriptions reflect the shipped predicates, including places where implementation is narrower than the planned title.

| Policy | Implemented condition | Mode |
|---|---|---|
| `AGCF-RT-001` | Execution correlation is ambiguous, unresolved or conflicting | Facts |
| `AGCF-RT-002` | Execution version approval state is outside `APPROVED` | Facts |
| `AGCF-RT-003` | Executed version is retired or withdrawn | Facts |
| `AGCF-RT-004` | Required runtime decision telemetry is incomplete, assessed at a bounded provider/workspace/capability/window scope | Coverage |
| `AGCF-RT-005` | Consequential action succeeds with approval state `REQUIRED` or `BYPASSED` | Sequence |
| `AGCF-RT-006` | Consequential action succeeds despite policy state `DENIED` or `BLOCKED` | Sequence |
| `AGCF-RT-007` | Confidential/restricted read precedes external/public write, send or publish whose approval state is not `APPROVED` | Sequence |
| `AGCF-RT-008` | Observed tool digest has component approval state `UNDECLARED` | Sequence |
| `AGCF-RT-009` | Retries grouped by agent exceed a configurable threshold; package default is over 50 in 24 hours | Aggregate |

Important limits: RT-002's predicate checks version approval, not generic endpoint health. RT-007 uses classified operations and approval metadata, not payload inspection or a general declassification engine. RT-008 checks component approval, not every possible tool-version/provenance discrepancy. RT-009 currently selects retries; the wider proposed spend/token/latency detection pack is not nine separately implemented controls. Absent approval telemetry must not be presented as proof of approval bypass.

### 4.5 Investigation and operations

The implemented surfaces provide execution filtering/pagination, timelines, relationship APIs and runtime finding details. Timelines expose available action, target, approval, policy, outcome and evidence-class metadata. Finding evidence records reference matched events and sequence timing.

Readiness and operational services expose source configuration, capability health, decision fill rates, correlation rates and collection/volume/quota diagnostics. The implementation record also documents lag, duplicate/quarantine, budget, retention-backlog and estimated storage-cost reporting; those metrics are operational signals, not proof that a pilot passed.

Key API paths:

- `GET /api/ai-security/executions`
- `GET /api/ai-security/executions/{executionId}/timeline`
- `GET /api/ai-security/executions/{executionId}/relationships`
- `GET /api/ai-runtime-telemetry-readiness`
- `POST /api/internal/ai-grid/runtime/{producerId}/v1/batches`
- `GET /api/ai-security/runtime-ingestion/receipts/{receiptId}`

## 5. Catalog and database baseline

Counts below use the latest checked-in version of each distinct policy, not all version files and not live tenant selections.

| Catalog slice | Policies | Package release state | Default selections |
|---|---:|---|---|
| Static posture/exposure | 159 | 76 GA; 83 paused | 32 required; 24 enabled; 103 disabled |
| Runtime | 9 | 9 paused | 9 preview |
| **Total executable packages** | **168** | **76 GA; 92 paused** | **32 required; 24 enabled; 103 disabled; 9 preview** |
| Runtime Wave 2C declarations | 5 | Pending evidence; no executable package files | Excluded from the 168 total |

GA status and default enablement are different dimensions. Neither proves that a particular tenant has selected a policy or supplied evaluable evidence.

The current packaged migration heads are **platform V4 / tenant V3**. Platform V2 introduced framework coverage/field registration, platform V3 the runtime policy contract, and platform V4 the versioned evidence-certification wave. Tenant V2 added approved manifests/allowlists; tenant V3 added the runtime contract, producer/source registry, receipts and quotas. Actual tenant rollout must be checked through the schema control plane.

The migration reset itself is represented by independent platform/tenant V1 baselines, bootstrap and tenant-migration tooling, structural-fingerprint/RLS checks, and append-only migration integrity checks in pull-request and merge-group CI. The reset note's platform target of V3 is outdated; the compatibility floor remains tenant V1 in configuration while packaged targets are V4/V3. A compatibility floor is not evidence that dependent features are available on an older tenant.

## 6. Not implemented or only partially implemented — both document sets

This section retains the remaining work from all reviewed plans. **Not implemented** means no corresponding implementation was found in the reviewed paths; **partial** means a foundation exists but the full proposed behavior does not. **Operationally unverified** means source code cannot establish deployment, customer certification or outcomes. Intentional exclusions and unsupported provider relationships are listed separately so they are not mistaken for defects or commitments.

### 6.1 Remaining work from the original seven documents

| Planned capability | Status | What remains |
|---|---|---|
| Uploaded AI-BOM → AI Grid bridge | Not implemented | Durable projection jobs/backfill; correct model/dataset/software component typing; bounded projection; verified tenant/provider/model-version links; replacement/deletion reconciliation; BOM-derived facts; model-detail status and unlinked queue. Generic BOM ingestion already exists. |
| AI-BOM coverage policies | Partial; paused | Correct/version AWS-058 and AZR-060 predicates/scopes/evidence freshness; define presence versus completeness; resolve ambiguous provider identities and reassessment scope; certify positive, negative and unknown cases before activation. |
| Additional static agent-risk policies | Not established as shipped additions | Combined privilege-without-approved-guardrail, active-version unapproved-tool/component correlation, definition drift after approval, unapproved Copilot trigger/skill, unowned/stale-owner production agent, and unhealthy declared-component policies. Existing allowlists, ownership, digests and related policies provide parts of the evidence. |
| AgentCore runtime foundation posture policies | Partial | Runtime/role/version/endpoint inventory exists, but the proposed dedicated missing-identity and unhealthy/unapproved-endpoint posture checks are not established as shipped additions. RT-002 checks approval of an observed execution version, not all endpoint health/routing conditions. |
| Framework mapping expansion | Partial | Backfill reviewed Agentic mappings onto static packages and add LLM08 retrieval/vector mappings. Framework registration is complete; full mapping/review is not. |
| Broad runtime telemetry enrichment | Partial | Authoritative provider action, target, acting/delegated identity, approval, policy, tool/version, data-operation and outcome evidence across supported connectors. A typed field or adapter endpoint does not populate missing provider telemetry. |
| Full proposed behavior pack | Partial | RT-001–009 exist, but generic endpoint-health, unexpected delegated-identity/standing-credential, broad tool/version integrity, repeated-action, spend/token/latency policy coverage exceeds the currently shipped predicates. RT-009 currently selects retries. |
| Wave 2C: A2A, memory, provenance and containment | Not implemented as executable packages | RT-010–014 require authenticated/constrained handoff, memory write/isolation/retention, component provenance, and effective stop-control evidence. They exist as pending-evidence declarations only. |
| Custom-agent registration and attestation | Not established | Universal registration/attestation and reconciliation with cloud-discovered agents. The runtime telemetry producer registry is not a universal agent registry. |
| Runtime simulation and human action approval | Partial | Existing artifact impact preview, policy governance and definition approval do not deliver historical action-policy simulation with projected business impact, action-level approval issuance, expiring grants and a real enforcement integration. |
| Prevention, containment and response | Not implemented as general agent controls | Inline allow/deny/redact/pause/terminate, short-lived capability grants, credential revocation, tool/agent quarantine, human-approved response execution and bounded autonomous response. Collector kill switches and manifest revocation do not supply these controls. |
| Behavioral analytics and assurance | Not implemented as proposed | Learned baselines, intent/goal drift, cross-agent anomaly analysis, poisoning detection/rollback, attack-path simulation, agent red-team/evaluation platform, CI assurance gates and assurance scorecards. Deterministic sequence/retry detection is already implemented. |
| Broader evidence/provider coverage from the 74-rule comparison | Partial / unsupported | GCP Vertex AI, Claude Enterprise and Salesforce discovery; secret-to-privilege paths; suspicious-model findings; vulnerable host/container → AI data paths; repository/package/image provenance; exact training/model-data public-write/third-party access paths; notebook privilege/exposure; MCP-to-vulnerable-host relationships. Existing IAM, storage, classification and graph checks do not establish full rule parity. |
| Universal runtime audit/replay guarantees | Not established in full | Complete historical action-chain replay, runtime-specific legal holds, optional forensic-content workflows and high-volume scaling qualifications described by the earlier strategy. Artifact snapshot retention/holds and bounded runtime deletion already exist. |
| Customer validation and commercial outcomes | Operationally unverified | Discovery interviews, design-partner agreements, instrumentation acceptance, recurring customer use, willingness to pay, remediation/renewal results and measured investigation-time improvement. These are not code deliverables or achieved metrics. |

Sources: original brief/prioritized roadmap for long-term scope; customer and coverage plans for static policies/mappings; runtime plan for telemetry/Wave 2C; AI-BOM strategy for the bridge; 74-rule assessment for parity gaps. Existing policy certification and live activation are tracked in section 7 rather than classified as missing code.

### 6.2 Remaining work from the AWS connector maturity plan

| Workstream | Status | Evidence and remaining scope |
|---|---|---|
| Independent AWS rollout flags and kill switches | Partial | Admission limits and connector controls exist, but the reviewed AWS discovery path does not expose the five planned version/taxonomy/identity/AgentCore/activity flags or the complete tenant × connector × region × family kill-switch hierarchy. The shared feature-flag enum currently contains Azure/Copilot features. |
| Fully collector-supplied capability observations | Partial | Capability manifests, reasons, scopes and active-definition checks exist. AWS uses an explicit family-to-capability switch; Azure still uses family substring/prefix inference. The plan's complete migration to collector-supplied observation declarations is not finished. |
| Complete IAM effective authorization semantics | Partial | `rolePolicyFacts` collects policies and emits indicators, including boundary presence. It does not fetch/evaluate the boundary document there or resolve full deny/condition/NotAction/NotResource semantics. Its `effectiveAccessEvidenceComplete` flag must not be interpreted as proof that the plan's full effective-permission contract has been met. |
| Definition integrity for every AWS tool/prompt | Partial | Version instruction/override prompt digests exist. Action-group creation stores ID/state/signature/Lambda metadata but does not compute the proposed API/function-schema digest in `addVersionToolArtifacts`; separately listed managed prompts retain basic ID/version metadata. Complete approval/auth/consequence enrichment and drift-policy certification are not demonstrated for all definitions. |
| Full deployed-version posture acceptance | Partial / needs validation | Version/alias graph construction exists. The full acceptance claim—every served version has exact definition/guardrail evidence, all draft-only findings are consistently labelled, and every changed policy has certified before/after parity—is not established by graph existence alone. |
| Registration certification across every safety dimension | Partial | `AiGridCollectorRegistrationCertificationTest` checks permissions, probes, capabilities, canonical relationships and sanitizer kinds. It does not certify the entire proposed feature-flag/kill-switch and budget/cadence registration matrix or missing-budget startup warning behavior. |
| Complete activity-evidence presentation | Partial | Activity status/count values, timestamp, confidence and expiry are displayed. The detail table does not separately present every proposed source/query reference, explicit observation-window and first/last-observation field. Advisory activity and prioritization themselves are implemented. |
| Autonomous collection of curated AWS activity | Intentionally deferred | The trusted evidence boundary consumes supplied metadata. Continuous CloudWatch ingestion and later bounded provider queries are not part of the completed first-release activity integration. A producer registration is not a deployed SIEM/SOAR or gateway export. |
| Replay, customer canary and GA acceptance | Operationally unverified | Tooling and tests exist; a signed-off corpus delta, real customer canary, artifact-churn/finding/API-cost results and rollback/precision approval for all workstreams were not verified. |

The older plan's prohibition on external execution writes applies to its initial curated-activity design. Later Phase 2 deliberately adds the separately governed runtime batch adapter; this is a scope evolution, not an unimplemented requirement to remove that adapter.

### 6.3 Remaining ARISE-specific scope

| Planned capability | Status | What remains |
|---|---|---|
| Formal ARISE control taxonomy and mapping | Not established | A governed ARISE framework/control registration and reviewed per-policy mapping with implementation evidence. The 61/12/86 estimate is not such a mapping. |
| Complete identity/delegation context | Partial | General ownership, IAM/RBAC and runtime identity fields exist. First-class delegating users/business owners, OAuth-grant/credential lineage, constrained delegation chains, purpose/audience/expiry validation and universal consumer links are not complete. |
| Universal Layer 1 acceptance and reporting | Partial / operationally unverified | No evidence establishes that every tenant agent has confirmed usable ownership/identity, every tool/MCP resource is linked to consumers, or all proposed owner/business-service/credential and framework reporting dimensions are populated. Unsupported relationships must remain explicit gaps. |
| Action authorization and JIT credentials | Not implemented as proposed | Per-call runtime authorization, JIT/secretless credential issuance, token-scope/expiry management, session revocation, step-up approval and enforcement outcomes `ALLOW/BLOCK/REDACT/PAUSE/STEP_UP/RESTRICT_SCOPE/REVOKE/ESCALATE`. Existing connector credential management is a different capability. |
| Extended action-policy context | Partial | Typed action/target/classification/decision evidence exists; business purpose, maximum transaction value, approved delegator, location/time authorization and delegation-chain depth are not implemented as a complete enforcement policy model. |
| Full action-chain and intent analysis | Partial | Metadata-only executions and sequences exist. Full prompt → plan → credential → resource lineage, task-relative intent drift, chain anomalies, mid-run identity/model changes and authenticated A2A behavior remain incomplete. Raw prompt/plan retention is outside the current privacy boundary. |
| Proposed 25–35 ARISE control pack and enforcement integrations | Not implemented as a distinct pack | Nine deterministic runtime packages do not equal the proposed wider identity, delegation, credential, blocking, session, intent and SIEM/SOAR response program. The existing ITSM integration should not be counted as a new ARISE enforcement integration. |

### 6.4 Migration reset and AgentCore matrix: exclusions versus unfinished work

| Document/decision | Classification | Retained conclusion |
|---|---|---|
| Migration baseline reset and append-only CI | Implemented infrastructure | V1 baselines, bootstrap/migration tools, integrity checks and later V2–V4 platform / V2–V3 tenant changes exist. No new reset is required by this review. |
| Actual per-environment reset/upgrade procedure | Operationally unverified | Database export, worker stop, schema bootstrap, checksum/RLS/fingerprint verification, approved reseed and restart must be evidenced for each affected environment. The document's procedure is historical operational guidance, not authorization to execute a reset. |
| Migration note says platform target 3 | Superseded documentation | Current packaged target is platform 4 / tenant 3; tenant compatibility floor 1 remains distinct. This is documentation drift, not missing V4 implementation. |
| AgentCore runtime → identity/version/endpoint | Implemented | Source and tests support runtime-root qualification and these authoritative relationships. The original relationship evidence spike has produced its matrix. |
| AgentCore runtime → gateway/browser/interpreter/memory/tool or classic agent | Intentionally unsupported without evidence | No edge should be inferred from co-location, tags or independent resource IDs. Authoritative provider/harness/runtime evidence and an adapter are prerequisites for expanding this graph. Not drawing those edges is correct current behavior. |
| Native AWS per-run telemetry, raw log lake, discovery mutation, ServiceNow CMDB staging | Intentionally excluded from AWS first release | These are not unfinished first-release requirements. The shared governed runtime adapter is separate, and existing incident integration is not CMDB compatibility. |

## 7. Operational gates and historical coverage limits

These items are retained to prevent implemented foundations from being mistaken for completed customer protection; this is not a renewed delivery roadmap.

**Runtime operational qualification remains outstanding in the latest implementation record.** It reports no configured Foundry runtime endpoint or Copilot pilot, no representative 14-day pilot window, no customer answer-key corpus and no DEV/CANARY/GA promotion. Those live-state statements were not rechecked during this documentation task.

The implemented readiness gate requires two qualifying provider connectors. Each is measured over 14 days with at least 100 executions, at least 95% approval/policy/outcome fill over consequential events, at least 90% agent correlation, and at least 80% version correlation across at least 50 version-applicable executions. Missing configuration, insufficient samples, unsupported capabilities and quota exhaustion produce explicit blockers.

Runtime certification requires at least five policies, including RT-001 and RT-003 and at least two of RT-005/006/008. High/Critical precision must reach the specified 95% bar on representative evidence. Checked-in fixtures and a green build do not establish customer precision or per-producer authority.

The old 74-rule comparison was a historical vendor-rule parity assessment, not 74 native OWASP controls or compliance certification. Its 5 direct / 44 partial / 25 gap result was not reassessed against this implementation, so it is not carried forward as a current coverage score.

## 8. Verification and implementation references

For the initial consolidation, all seven original source documents were read and compared with the current package manifests/predicates, migration catalog, core service paths and relevant UI/docs. The follow-up review also read the four additional source documents and the consolidated record, then inspected AWS discovery/preflight, IAM parsing, capability declarations, scope ownership, activity UI, AgentCore graph contracts and migration CI. The original files had been removed from the working tree by the follow-up review; their previously read contents remain the basis for the original-set comparison. The following checks were run successfully:

- `npm run validate:ai-grid-phase1`: 76 Phase 1 packages and the AWS/Azure permission contracts validated.
- `node prototype-app/scripts/validate-ai-grid-runtime-catalog.mjs`: nine runtime packages and five pending-evidence declarations validated. Its output uses “released” for the nine package entries; their actual release status remains `PAUSED`.
- Latest-version catalog counts and mapping counts were recomputed from package JSON.

The September 25 implementation record reports 947 backend tests, 615 frontend tests, typecheck/lint, JaCoCo/SpotBugs and V2-to-V3/clean-install migration verification passing at that time. Those suites were **not rerun** for this documentation-only consolidation, and that historical report does not verify the subsequent platform V4 rollout.

Repository-relative references below remain valid after the source planning files are removed. In this table, the Java root is `prototype-app/backend/src/main/java/com/prototype/vulnwatch/`.

| Evidence | Repository location |
|---|---|
| AWS connector and permission contracts | `aisecurity/aws/AwsBedrockDiscoveryService.java`, `AwsPolicyPermissionMatrix.java`, `AwsPermissionPreflightService.java` under the Java root |
| Activity evidence and scope ownership | `aisecurity/service/AiGridHostContextService.java`, `AiExposureIntelligenceService.java`, `AiSecurityObservationService.java` under the Java root |
| AWS registration certification | `prototype-app/backend/src/test/java/com/prototype/vulnwatch/aisecurity/aws/AiGridCollectorRegistrationCertificationTest.java` |
| Migration CI | `.github/workflows/quality.yml`, `.github/scripts/check-migration-integrity.py`, `.github/scripts/validate-migrations.py` |
| Static and runtime policies, manifests and wave contracts | `prototype-app/policy-packages/agcf/` |
| Phase 1 answer-key corpus | `prototype-app/certification/agcf-phase-1-answer-key-corpus.json` |
| Discovery, graph, snapshot, fact, capability and governance services | `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/` |
| Manifest/allowlist control plane | `aisecurity/service/AiGridManifestApprovalService.java` under that Java root |
| Default-selection repair | `aisecurity/service/AiGridTenantPolicyDefaultsService.java` under that Java root |
| Runtime ingestion and worker | `aisecurity/service/AiGridRuntimeIngestionService.java`, `AiGridRuntimeIngestionWorker.java` under that Java root |
| Common execution ingestion and retention | `aisecurity/service/AiAgentExecutionIngestionService.java`, `AiAgentExecutionRetentionService.java` under that Java root |
| Runtime evaluator and readiness | `aisecurity/service/AiGridRuntimeEvaluationService.java`, `AiGridRuntimeTelemetryReadinessService.java` under that Java root |
| Platform and tenant migrations | `prototype-app/backend/src/main/resources/db/migration/postgres_reset/` and `tenant/` |
| Migration version assertions | `prototype-app/backend/src/test/java/com/prototype/vulnwatch/migration/MigrationCatalogTest.java` |
| Execution, inventory and finding interfaces | `prototype-app/frontend/src/pages/AiAgentExecutionsPage.tsx`, `AiInventoryPage.tsx`, `AiFindingDetailPage.tsx` |
| Detailed subsystem documentation | `prototype-app/docs/business-logic-guide.md`, `backend.md`, `database.md` |

## 9. Documents consolidated

This implementation record incorporates the implemented scope and necessary limitations from:

1. `AI_GRID_AGENT_SECURITY_BRIEF.md` — original baseline and agent-security delta.
2. `AI_GRID_PRIORITIZED_ROADMAP.md` — phase intent and long-term scope boundaries.
3. `AI_GRID_CUSTOMER_SECURITY_ROADMAP.md` — posture/runtime distinction and customer-facing evidence semantics.
4. `AI_GRID_POLICY_COVERAGE_EXPANSION_PLAN.md` — catalog, framework, manifest and capability expansion.
5. `AI_GRID_PHASE_2_RUNTIME_SECURITY_PLAN.md` — runtime implementation and remaining operational gates.
6. `AI_GRID_OWASP_74_CONTROL_COVERAGE.md` — historical parity context and unsupported capability boundaries.
7. `AI_GRID_AI_BOM_INTEGRATION_STRATEGY.md` — existing BOM support versus the unimplemented Grid bridge.
8. `AWS_CONNECTOR_MATURITY_IMPLEMENTATION_PLAN.md` — deployed AWS graph, identity, safety, activity and remaining acceptance work.
9. `ARISE_COMPLIANCE_PLAN.md` — existing Layer 1 foundation and incomplete identity, delegation, intent and enforcement extensions.
10. `migration-reset.md` — implemented migration reset/control plane, outdated target statement and environment-specific operational verification.
11. `agentcore-api-evidence-matrix.md` — authoritative AgentCore relationships and intentional no-inference boundaries.

`AI_GRID_IMPLEMENTED_CAPABILITIES.md` is the consolidated output reviewed and updated in this follow-up, not a twelfth independent source plan.

The originals are intentionally not linked as dependencies. Proposed timelines and research/reset instructions are not execution requests. Sections 3–5 retain the implemented baseline; section 6 preserves remaining implementation scope across both sets; section 7 separates live qualification from missing code. No source-plan action, deployment or database reset was performed.
