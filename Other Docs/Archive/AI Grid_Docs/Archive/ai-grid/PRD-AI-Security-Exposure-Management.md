# Product Requirements Document — AI Security Exposure Management

**Product:** AI Grid / Scout AI Security  
**Status:** Superseded by `PRD-AI-Grid-Final-Scope.md`  
**Document owner:** Product  
**Last updated:** 2026-08-02  
**Initial release boundary:** AWS Bedrock and ARM-managed Azure AI  
**Long-term direction:** Complete AI Security Exposure Management across cloud, source, SaaS, identity, data, MCP, and runtime surfaces

---

## 1. Summary

AI Grid will expand the current AWS and Azure AI Security pilot into an AI Security Exposure Management platform. It will discover AI systems, explain their identities and dependencies, assess security controls using trustworthy evidence, correlate the conditions that create realistic exposure paths, and route the resulting work through the host platform's ownership, SLA, suppression, and ticketing workflows.

The first production release will focus on managed AI services in AWS Bedrock and Azure AI. It will favor accurate, explainable results over a large policy count and will clearly separate verified facts, derived signals, unknown coverage, control presence, and control effectiveness.

---

## 2. Contacts

| Name | Role | Responsibility / comment |
|---|---|---|
| Karthik Gowri | Product owner | Product scope, priority, release acceptance, and stakeholder alignment |
| TBD | Engineering lead | Architecture, delivery plan, technical quality, and operational readiness |
| TBD | Security architect | Threat model, evidence protection, policy governance, and security acceptance |
| TBD | Design lead | Inventory, exposure, finding, coverage, and compliance experiences |
| TBD | Data/platform lead | Asset graph, identity, data sensitivity, reachability, and host-platform integrations |
| Design partners | Customer advisory group | Validate workflows, result quality, language, and willingness to act |

### Decision owners

| Decision | Accountable role |
|---|---|
| Release boundary and product claims | Product owner |
| Security architecture and tenant isolation | Security architect |
| Data contracts and service boundaries | Engineering lead |
| Policy publication and severity standards | Product owner + Security architect |
| Production release | Product owner + Engineering lead + Security architect |

---

## 3. Background

### 3.1 Current state

The current pilot provides read-only discovery and deterministic policy assessment for AWS Bedrock and Azure AI/Foundry/ML/Search/Bot resources. It already has several important production foundations:

- isolated AI Security backend context;
- disabled-by-default `ai.security` entitlement;
- backend and frontend entitlement gates;
- forced tenant row-level security;
- protected connector credentials, rotation, expiry, and kill switches;
- idempotent and chunked observation ingestion;
- per-scope discovery completeness;
- evidence-gated `NO_DECISION` behavior;
- audited assessment runs;
- inventory, finding, policy, and connector user interfaces.

The pilot remains closer to a provider-specific AI posture product than an exposure-management platform. Policies are hardcoded, artifact types are coarse, findings use a separate workflow, graph relationships are not used for correlation, and effective identity, sensitive-data, verified-reachability, runtime, source, and MCP signals are incomplete or absent.

#### 3.1.1 Verified implementation baseline

This PRD is based on a source-level review completed on 2026-08-02. The implementation is not a disposable prototype. The expansion must preserve its tested security and operational behavior while changing the data, policy, correlation, and workflow layers incrementally.

| Capability | Verified implementation | PRD treatment |
|---|---|---|
| Tenant and access controls | Disabled-by-default `ai.security` entitlement, backend/frontend gates, forced RLS on AI tables, tenant-context execution, role checks, and audit | Preserve and extend to new tables, caches, graph queries, catalog operations, and evidence access |
| AWS and Azure discovery | Bedrock plus Azure AI/Foundry/ML/Search/Bot discovery across 29 catalogued resource families, including regional/global scope semantics | Preserve collectors; close family-specific fact gaps and add future discovery planes through the same provider contract |
| Connector operations | Credential protection and rotation, provider/tenant/connector/family/policy kill switches, permission diagnostics, sync runs, retries, tenant fairness, concurrency limits, and backpressure | Preserve; add replayable pipeline stages, transactional outbox, dead-letter visibility, and stage metrics |
| Observation ingestion | `ObservationEnvelopeV1`, chunking, content-hash replay protection, receipt idempotency, scope completeness, lifecycle deactivation, and sanitized diagnostics | Preserve the contract and validation; add a version-compatible path to immutable snapshots and normalized facts |
| Artifact inventory | Stable tenant/provider/provider-resource identity, native metadata, lifecycle timestamps, and provider/account/region filtering | Preserve artifact identity; add durable AI-system identity, ownership resolution, snapshot history, and richer lifecycle states |
| Technology classification | Provider and native-kind fields exist, but there is no governed technology registry or durable technology-to-policy applicability contract | Add a platform-owned versioned technology registry, classification evidence, aliases, capabilities, and explicit coverage validation |
| Relationships and graph | Typed allowlisted relationships, relationship persistence, artifact-neighborhood and bounded graph APIs, and inventory graph UI | Preserve; improve cross-envelope reconciliation, group bounded AI systems, and add versioned exposure correlation |
| Evidence and facts | Mutable merged `attributes_json`, scope records, envelope content hashes, evaluation evidence copies, and missing-evidence reasons | Migrate to immutable artifact snapshots, typed facts, restricted evidence references, provenance, freshness, and deterministic replay |
| Policy evaluation | Thirteen version-labelled AWS/Azure policies, applicability and completeness checks, `PASS`/`FAIL`/`NO_DECISION`/`NOT_APPLICABLE`, finding reconciliation, and decision-coverage tests | Preserve the safe outcome semantics and use existing tests as references; replace the hardcoded registry/switch with a fresh governed catalog and generic predicate engine. Existing demo policy rows do not require migration. |
| Policy distribution | Platform-owner availability/default controls, tenant enable/disable settings, audit, suppression, and reevaluation | Preserve useful control behavior in the new catalog, but existing demo policy settings and distribution rows may be reset. Add draft/validate/approve/canary/publish/rollback governance. |
| Findings and reviews | Dedicated AI finding table, stable display IDs, evidence, review dispositions, suppress-on-disable, resolve-on-confirmed-pass, APIs, and UI | Create new AI results directly in the canonical host finding workflow. Existing AI demo findings, reviews, IDs, and history may be discarded. |
| User experience | Entitlement-gated inventory, artifact detail, graph, findings, reviews, policy, policy detail, coverage, AWS connector, and Azure connector experiences | Evolve these pages in place; add AI-system, exposure-path, evidence-history, coverage, and canonical workflow views |

#### 3.1.2 Boundaries of the current implementation

The current implementation is strong in secure collection and deterministic provider posture, but it is not yet a complete exposure-management platform:

- `ai_security_artifacts.attributes_json` is merged in place, so it cannot be the authoritative input for historical replay.
- Evaluation rows reference a run and artifact, but not an immutable fact snapshot whose exact inputs can always be reconstructed.
- `AiSecurityPolicyRegistry` and `AiSecurityPolicyEvaluationService` encode policy definitions, applicability markers, and predicates in Java switches.
- Platform policy distribution changes live availability/default state but does not provide authored drafts, independent approval, canary publication, version pinning, or rollback as a catalog transaction.
- Relationships and a bounded graph already exist, but they do not establish stable AI-system membership or run versioned attack-path correlation.
- AI findings have safe lifecycle behavior, but remain separate from the host ownership, SLA, exception, notification, and ticket lifecycle.
- Connector-derived fields mix provider collection with security interpretation; those interpretations need to move gradually into versioned normalizers and derived-fact processors.
- Azure already captures tags for supported resources; expansion work must preserve that path and close AWS and resource-family-specific ownership/tag gaps instead of treating tags as wholly new discovery.
- Technology classification is currently implicit in provider, resource family, native kind, and policy-specific Java checks. A vendor rename or bad mapping can silently prevent policies from applying, so unclassified and unmapped inventory must become visible coverage failures.

### 3.2 Why now

Organizations are adopting managed AI services, agents, tools, model APIs, vector stores, and AI-enabled SaaS faster than security teams can inventory or govern them. Existing cloud posture findings do not explain which cloud resources form an AI system or how identity, data, network access, tools, models, and guardrails combine into meaningful exposure.

The current pilot proves that agentless discovery and tenant-safe ingestion are possible. The next step is to build a trustworthy fact, policy, graph, and workflow layer before adding more providers and hundreds of rules.

### 3.3 Product problem

Security teams cannot reliably answer:

1. What AI systems exist across the organization?
2. Who owns each system?
3. Which identities, tools, models, data stores, networks, and guardrails are connected?
4. Which controls were actually evaluated, and which remain unknown?
5. Which combinations create realistic paths to sensitive impact?
6. What is the smallest action that breaks each path?
7. Has the exposure been assigned, remediated, and verified?

### 3.4 Strategic principle

AI Grid is a consumer and attributor of general security signals, not a replacement for CSPM, CIEM, DSPM, ASM, vulnerability management, or ticketing. It owns the AI-system model, AI-specific facts, AI policy evaluation, exposure correlation, evidence, and AI attribution layer. It should reuse host capabilities where those capabilities already exist.

---

## 4. Objective

### 4.1 Product objective

Enable security teams to find, understand, prioritize, and reduce meaningful AI-system exposure using complete inventory, trustworthy evidence, explainable attack paths, and existing remediation workflows.

### 4.2 Customer outcomes

Customers should be able to:

- maintain an accountable inventory of managed AI systems;
- distinguish secure, insecure, unknown, unavailable, stale, and not-applicable coverage;
- see why an exposure exists and which evidence supports it;
- understand the identity, data, network, model, tool, and guardrail relationships involved;
- prioritize realistic exposure paths instead of isolated configuration findings;
- assign work to the correct owner and measure remediation through closure;
- demonstrate security posture without overstating untested control effectiveness.

### 4.3 Company outcomes

- Extend the host security platform into a fast-growing AI security problem.
- Reuse existing tenant, finding, SLA, suppression, ServiceNow, asset, and governance capabilities.
- Create a reusable fact and policy architecture that supports new AI providers without provider-by-policy code growth.
- Establish a defensible product position based on evidence honesty and remediation closure.

### 4.4 Key Results

#### First production release

1. Achieve at least **95% discovery recall** for supported Bedrock and Azure AI resource families in the seeded answer-key environments.
2. Achieve at least **95% precision per released high- or critical-priority policy family**, measured against reviewed fixtures and design-partner evidence.
3. Return an explicit evaluation state for **100% of applicable critical controls**. Unknown, stale, inaccessible, and incomplete evidence must not count as PASS.
4. Resolve an owner or open an explicit unowned-artifact finding for at least **95% of discovered production AI systems**.
5. Ensure **100% of host findings** retain the exact policy version, fact snapshot, evidence references, tenant, and subject identity that produced them.
6. Demonstrate zero cross-tenant evidence access in automated isolation tests.
7. Keep duplicate host findings below **2%** in seeded shared-dependency and rescan scenarios.
8. Verify that a fixed seeded exposure moves from FAIL to closed only after a complete subsequent assessment confirms PASS.

#### Exposure-management release

1. Provide at least three production-ready correlated exposure types covering reachability, privilege, sensitive data, and autonomous/tool execution.
2. Explain every correlated exposure with entry point, path, affected system, evidence, confidence, blast radius, and remediation breakpoints.
3. Route at least **90% of accepted high-priority exposures** to an accountable owner and SLA workflow.
4. Measure exposure reduction using closure, reopen, stale-evidence, and recurrence rates rather than policy count alone.

### 4.5 North Star Metric

**Percentage of in-scope AI systems with an accountable owner and evidence-backed decisions for every applicable critical exposure control.**

### 4.6 Initial One Metric That Matters

**Decision-complete coverage for Bedrock and Azure critical controls.**

---

## 5. Market Segments

Markets are defined here by the work customers need to complete.

### 5.1 Primary segment — Cloud and exposure-management teams

**Job to be done:** When AI services appear across cloud accounts and subscriptions, identify which systems create meaningful exposure and route the right remediation to the right owner.

**Current alternatives:** Cloud consoles, CSPM findings, spreadsheets, manual reviews, provider-specific dashboards, and broad CNAPP products.

**Pain:** Existing tools show disconnected resources and generic configuration findings. They rarely explain the full AI system or connect AI posture to identity, sensitive data, tools, ownership, and remediation state.

**Why first:** This segment already uses the host platform's inventory and finding workflows and can gain value from the existing AWS/Azure pilot without waiting for every discovery plane.

### 5.2 Secondary segment — AI platform and application owners

**Job to be done:** Before and after deployment, understand whether an AI system has safe identity, data access, network exposure, guardrails, tools, models, and logging.

**Pain:** Teams receive findings without enough evidence, system context, or concrete remediation guidance.

**Need:** System-level views, responsible owner, affected component, verified evidence, and remediation breakpoints.

### 5.3 Secondary segment — Governance, risk, and compliance teams

**Job to be done:** Demonstrate which AI security controls were evaluated, which passed or failed, and where coverage remains incomplete.

**Pain:** Compliance percentages can hide missing resources, unavailable scans, control-presence limitations, and untested behavioral efficacy.

**Need:** Honest denominators, evidence history, exception records, framework mappings, and exports.

### 5.4 Constraints

- Agentless cloud discovery cannot find all shadow, self-hosted, source-only, SaaS, MCP, or runtime AI.
- Configuration checks can prove control presence but not behavioral effectiveness.
- Identity, data sensitivity, and reachability accuracy depend on CIEM, DSPM, and ASM signals.
- Customers will have inconsistent tags and ownership data.
- Provider APIs, schemas, permissions, throttles, and naming will change.

---

## 6. Value Propositions

### 6.1 For cloud security teams

**Before:** Teams review separate AI resources and generic cloud findings with little connection to business ownership or realistic impact.

**How:** AI Grid groups resources into AI systems, combines AI configuration with identity, data, network, tool, and host-security context, and identifies evidence-backed exposure paths.

**After:** Teams prioritize the AI systems that have the clearest paths to sensitive impact and send one actionable unit of work to the right owner.

### 6.2 For AI platform owners

**Before:** Owners receive broad security warnings that do not explain the AI-specific context or the smallest safe correction.

**How:** AI Grid shows the affected system, relationship graph, exact evidence, control state, and remediation breakpoints.

**After:** Owners understand what to change and can verify that the exposure is closed after reassessment.

### 6.3 For governance teams

**Before:** Coverage and compliance reports can make unavailable or untested controls look safe.

**How:** AI Grid preserves PASS, FAIL, NO_DECISION, NOT_APPLICABLE, NO_RESOURCE, DISABLED, ERROR, STALE, and presence-only states throughout APIs, UI, scores, and exports.

**After:** Governance teams can make claims that match the evidence and can clearly disclose coverage gaps.

### 6.4 Differentiation

AI Grid will compete on:

- honest evidence and coverage semantics;
- AI-system attribution rather than generic cloud-resource noise;
- explainable cross-resource exposure paths;
- deep reuse of the host finding and remediation workflow;
- deterministic, replayable evaluation tied to exact policy and evidence versions;
- a bounded initial scope with measurable accuracy.

It will not compete on the raw number of catalog rules.

---

## 7. Solution

### 7.1 Product principles

1. **Evidence before assertion:** Missing, stale, low-confidence, or incomplete evidence must not become PASS.
2. **One AI system, many artifacts:** Inventory and findings must support systems that cross resources, accounts, providers, and owners.
3. **Separate observation from derivation:** Provider facts and computed signals must carry different provenance.
4. **Configuration is not efficacy:** Control-presence findings must be labeled as presence-only.
5. **Exposure before score:** Show the path and evidence before reducing risk to a number.
6. **Workflow, not another silo:** AI findings must use host ownership, SLA, suppression, ticketing, and closure.
7. **Secure control plane:** Policy and fact-schema changes require validation, review, versioning, audit, and rollback.
8. **Read-only by default:** Automated mutation and red-team execution remain outside the initial releases.

### 7.2 Core user flows

#### Flow A — Connect and discover

```text
Administrator enables AI Security entitlement
→ configures a least-privileged AWS or Azure connector
→ validates permissions
→ starts discovery
→ views run health, scope completeness, errors, and stale coverage
→ discovered artifacts are grouped into AI systems
```

#### Flow B — Investigate an AI system

```text
Security analyst opens AI Inventory
→ selects an AI system
→ views owner, criticality, provider resources, identities, tools, models, data, networks, and guardrails
→ reviews observed and derived facts with freshness and confidence
→ opens posture findings or correlated exposures
```

#### Flow C — Remediate an exposure

```text
Analyst opens a correlated exposure
→ sees entry point, attack path, impact, evidence, and remediation breakpoints
→ assigns or confirms owner
→ creates or links a ServiceNow ticket
→ owner remediates a breakpoint
→ reassessment verifies PASS
→ host finding closes with complete evidence history
```

#### Flow D — Review coverage and governance

```text
Governance user opens AI Coverage
→ filters by provider, account, system, owner, framework, and environment
→ sees evaluated pass/fail separately from unknown, unavailable, stale, disabled, and presence-only
→ opens evidence or exceptions
→ exports an auditable report
```

### 7.3 Functional requirements

#### F-01 — Canonical AI inventory and system identity — Must

- Continue discovering supported AI artifacts using provider-native identifiers.
- Retain the current stable tenant/provider/provider-resource artifact identity and define an explicit, tenant-bound canonical key contract around it.
- Group related artifacts into a stable AI system.
- Track first seen, last seen, deleted, stale, and rediscovered states.
- Represent shared dependencies without duplicating the underlying resource.
- Support provider-neutral artifact types while retaining native kind and provider metadata.
- Resolve owner, environment, tags, and business criticality or record why resolution failed.
- Assign each artifact zero or more technology classifications and zero or more capabilities using a versioned, platform-owned technology registry. Designate one primary technology only when the evidence is unambiguous.
- Store the technology ID, registry version, classification method, matched alias/signature, confidence, and observed evidence with the artifact snapshot.
- Treat unknown, ambiguous, retired, or unmapped technologies as visible inventory coverage states; never silently exclude them from assessment.

**Acceptance criteria:**

- Repeated discovery does not create duplicate artifacts.
- Provider display-name changes do not change canonical identity.
- A shared knowledge source can connect to several AI systems.
- Deleted resources are not immediately erased; their lifecycle is auditable.
- A provider or product rename maps to the same stable technology ID through a reviewed alias change.
- Every active artifact appears in exactly one of: classified and assessed, classified but lacking applicable policy coverage, unclassified, ambiguous, or intentionally unsupported.

#### F-01A — Technology registry and inventory-to-policy validation — Must

The platform-owned technology registry is the AI equivalent of a controlled product-identification dictionary. It must store:

- stable technology ID, vendor, product, service, provider, and lifecycle state;
- aliases, provider native kinds, resource families, API identifiers, and classification signatures;
- supported artifact types and capability flags;
- registry version, change notes, author, approver, and effective date;
- replacement technology for renamed, merged, or retired entries;
- the discovery adapters and evidence required to claim support.

Every published policy version must declare applicability using governed references to:

- artifact types, capabilities, required relationships, resource families, and—only when product-specific behavior requires it—one or more technologies or technology groups;
- required facts and fact-schema versions;
- required discovery scopes and completeness states;
- exclusions and explicit not-applicable conditions.

After each complete inventory run, the platform must validate the inventory against the published catalog:

1. Classify every discovered artifact using the registry version captured by the run.
2. Resolve applicable policies in this order: artifact type, capabilities, required relationships, required facts and scopes, then an optional technology constraint.
3. Evaluate every applicable enabled policy or record a specific non-evaluated state.
4. Detect active inventory with no technology mapping, no applicable policy, missing facts, missing scopes, or an obsolete registry mapping.
5. Reconcile expected versus actual evaluation counts per artifact and per technology.
6. Publish a technology × resource-family × control-dimension coverage matrix. The policy catalog must be generated or validated from this matrix, not maintained only as a hand-written list.

**Acceptance criteria:**

- Every active supported artifact has an auditable technology-classification result.
- Every applicable published policy produces exactly one current assessment state per subject and assessment run.
- An artifact with zero applicable policies is reported as `NO_POLICY_COVERAGE`, not as secure or compliant.
- An unclassified artifact is reported as `UNKNOWN_TECHNOLOGY` and enters an accuracy backlog.
- An unknown technology must not block a provider-neutral policy when the artifact type, capabilities, relationships, required facts, and scopes are sufficient.
- A published policy cannot reference an unknown, ambiguous, or incompatible technology, capability, fact, or resource family.
- Registry changes run an impact preview showing artifacts and policy applicability added, removed, or changed before publication.
- Drift checks detect provider families discovered by connectors but absent from the registry or coverage matrix.

#### F-02 — Discovery coverage and connector health — Must

- Preserve the currently supported Bedrock and ARM-managed Azure AI/Foundry/ML/Search/Bot resource families; certify each family before production enablement.
- Record per-family scope status: COMPLETE, PARTIAL, FAILED, UNSUPPORTED, or NOT_CONFIGURED.
- Record missing permission, throttle, provider error, and unsupported-region reasons.
- Expose connector health, last successful run, duration, resource counts, stale coverage, and required permission changes.
- Use least-privileged, short-lived credentials or encrypted credential references.
- Keep connectors read-only.
- Preserve current Azure tag ingestion and add consistent tag, owner, and environment facts where AWS or individual resource-family adapters do not yet supply them.

**Acceptance criteria:**

- A partial family cannot satisfy a policy's complete-evidence requirement.
- Connector failure does not close existing findings.
- Credential expiry or missing permissions creates an operationally actionable coverage state.

#### F-03 — Versioned facts and evidence — Must

Every fact must carry:

- key and typed value;
- state: KNOWN, UNKNOWN, ERROR, or STALE;
- provenance: OBSERVED or DERIVED;
- provider or computation source;
- observed and expiry timestamps;
- confidence where derived;
- input snapshot or fact references;
- schema version.

The platform must:

- store immutable assessment snapshots;
- backfill and dual-write normalized facts while `attributes_json` remains a compatibility field;
- redact secrets and raw prompts;
- separate ordinary facts from restricted evidence;
- encrypt restricted evidence;
- enforce tenant and role authorization;
- define retention, deletion, logging, export, and ticket-sharing rules;
- prevent sensitive raw payloads from appearing in application logs.

#### F-04 — Governed policy catalog — Must

- Reuse the useful availability, tenant enable/disable, audit, suppression, and reevaluation behavior, but do not migrate existing demo policy records or settings.
- Store policy definitions separately from immutable published versions.
- Support lifecycle states: DRAFT, VALIDATED, APPROVED, CANARY, PUBLISHED, RETIRED.
- Require separate author and approver identities for publication.
- Validate fact names, types, operators, scales, and required evidence.
- Validate technology, technology-group, artifact-type, resource-family, capability, scope, and fact references against the published registries.
- Limit predicate depth, node count, value size, and evaluation time.
- Run answer-key tests and tenant-impact previews before publication.
- Support canary tenants, rollback, audit, and tenant version pinning.
- Preserve framework mappings, severity rationale, remediation, and change notes.
- Allow tenants to enable or disable distributed built-in policies.
- Exclude tenant-authored custom policies from the initial releases.

#### F-05 — Deterministic assessment engine — Must

- Evaluate policies only against stored versioned facts.
- Never call provider APIs during policy evaluation.
- Preserve applicability, completeness, unknown, stale, disabled, and error outcomes.
- Store the exact policy version, fact snapshot, inputs, output, and reason code.
- Support deterministic replay.
- Run the new vertical-slice policy against answer-key fixtures and selected old-engine safety cases before cutover.
- Use selected current policies and tests as regression oracles for result-state safety, but do not require preservation or migration of all 13 demo policy definitions.

Evaluation order:

```text
disabled                     → DISABLED
resource absent              → NO_RESOURCE
not applicable               → NOT_APPLICABLE
required scope incomplete    → NO_DECISION
required fact unknown        → NO_DECISION
required fact stale          → STALE
evaluation error             → ERROR
condition true               → FAIL
condition false              → PASS
```

#### F-06 — Identity, reachability, and data context — Must for exposure release

The platform must consume or derive:

- effective privileges;
- secrets and key access;
- cross-account and cross-tenant trust;
- confused-deputy conditions;
- configured public access;
- verified network reachability;
- authentication requirements;
- sensitive-data presence and access;
- training, retrieval, prompt, and output data relationships.

Configured exposure must remain distinct from verified reachability. Derived facts must include confidence, inputs, algorithm version, and expiry.

#### F-07 — AI relationship graph and attack-path correlation — Must for exposure release

Build on the existing typed relationship store, bounded graph API, and inventory graph UI. A separate graph database is not required for initial releases.

Support typed directional relationships such as:

```text
AGENT_USES_MODEL
AGENT_ASSUMES_IDENTITY
AGENT_INVOKES_TOOL
TOOL_INVOKES_FUNCTION
KNOWLEDGE_BASE_READS_DATA_SOURCE
MODEL_TRAINED_FROM_DATASET
ENDPOINT_EXPOSES_MODEL
IDENTITY_CAN_ACCESS_SECRET
```

The correlation engine must:

- operate on bounded AI-system subgraphs;
- use versioned correlation definitions;
- identify entry point, path, root causes, affected system, impact, and remediation breakpoints;
- retain underlying posture findings as evidence;
- avoid creating separate tickets for every node when one root cause can remediate the path;
- recompute only affected graph regions when facts or relationships change.

Initial correlated exposure templates:

1. Internet-reachable AI endpoint + weak authentication + sensitive-data access.
2. Autonomous or tool-enabled agent + overprivileged identity + secret access.
3. Public or cross-boundary entry point + code/tool execution + weak guardrail or approval control.

#### F-08 — Canonical host finding workflow — Must

- Create new AI findings directly in the canonical host workflow. Existing AI demo findings and reviews may be reset; no history backfill or dual workflow is required.
- Add AI_SECURITY as a host finding source.
- Support AI_ARTIFACT, AI_SYSTEM, RELATIONSHIP, and ASSET finding subjects.
- Use a stable tenant-bound fingerprint.
- Create on new FAIL, update on repeated FAIL, and reopen after recurrence.
- Close only after a complete later assessment confirms PASS or the subject is intentionally retired.
- Never close on NO_DECISION, STALE, ERROR, PARTIAL, or failed discovery.
- Preserve suppression, exception, assignment, SLA, ticket, evidence, and policy-version history.
- Support shared dependencies and multi-owner systems without uncontrolled duplication.
- Route through existing ownership, SLA, ServiceNow, notification, and audit services.

#### F-09 — Coverage, posture, and compliance — Must

- Display evaluated PASS and FAIL separately from all unevaluated states.
- Label control-presence results separately from behavioral validation.
- Publish the exact denominator used for every percentage.
- Show coverage by technology, provider, family, environment, account, owner, framework, and policy.
- Show inventory reconciliation counts for `ASSESSED`, `NO_POLICY_COVERAGE`, `UNKNOWN_TECHNOLOGY`, `AMBIGUOUS_TECHNOLOGY`, `MISSING_FACTS`, `INCOMPLETE_SCOPE`, and `UNSUPPORTED`.
- Map applicable policies to OWASP LLM Top 10 and support later MITRE ATLAS and NIST AI RMF reporting.
- Preserve exceptions and evidence history in exports.

The API must return at least:

```json
{
  "evaluatedPass": 0,
  "evaluatedFail": 0,
  "noDecision": 0,
  "notApplicable": 0,
  "noResource": 0,
  "disabled": 0,
  "error": 0,
  "stale": 0,
  "presenceOnly": 0
}
```

#### F-10 — Risk and prioritization — Should

- Keep impact, exploitability, reachability, business criticality, blast radius, confidence, and freshness as separate fields.
- Explain any calculated priority.
- Show high-impact/low-confidence conditions as such rather than silently lowering their severity.
- Allow users to sort by correlated exposure, business criticality, severity, freshness, and confidence.
- Avoid one opaque organization-wide score in the initial release.

#### F-11 — Additional discovery planes — Future

Add in this recommended order:

1. Source and CI discovery for AI SDKs, endpoints, prompts, IaC, agents, and `.mcp.json`.
2. MCP server and tool discovery.
3. SaaS AI administration such as Copilot Studio.
4. Direct model-provider accounts and APIs.
5. Runtime telemetry and unknown-runtime AI assets.
6. Self-hosted AI workloads on compute and Kubernetes.
7. GCP managed AI services.

Each new plane must use the same artifact, fact, evidence, identity, policy, coverage, and finding contracts.

#### F-12 — Platform operations — Must

- Preserve the current provider registry, sync-run lifecycle, receipt idempotency, fair tenant scheduling, concurrency limits, retries, kill switches, and backpressure.
- Introduce transactional outbox events between new pipeline stages without replacing the proven job worker in Release 0.
- Support replay from stored snapshots without repeating provider calls.
- Provide stage-level metrics, dead-letter handling, retry controls, and audit.
- Detect schema, catalog, technology-registry, and connector drift.
- Support safe kill switches per provider, tenant, policy, and pipeline stage.
- Apply backpressure and incremental discovery at scale.

Recommended events:

```text
ARTIFACT_SNAPSHOT_CREATED
FACTS_NORMALIZED
DERIVED_FACTS_UPDATED
POLICY_EVALUATION_COMPLETED
AI_FINDING_CHANGED
AI_EXPOSURE_CHANGED
```

### 7.4 Technology and architecture

#### Processing model

```text
Provider/SaaS/source/runtime collectors
→ ObservationEnvelopeV1
→ canonical artifact identity
→ immutable artifact snapshot
→ versioned technology classification
→ provider-specific normalization
→ observed facts
→ derived fact processors
→ policy applicability resolution
→ deterministic policy evaluation
→ inventory-to-assessment reconciliation
→ posture finding reconciliation
→ graph correlation
→ correlated exposure reconciliation
→ host workflow and reporting
```

#### Initial implementation approach

- Evolve the existing `com.prototype.vulnwatch.aisecurity` bounded context; do not rewrite the pilot.
- Retain `ObservationEnvelopeV1`, discovery completeness, entitlement, RLS, credential, audit, and connector controls.
- Replace the hardcoded policy registry and switch incrementally.
- Use PostgreSQL artifact and relationship tables first. Do not require a graph database until measured traversal needs justify one.
- Keep policy evaluation pure and deterministic.
- Implement derived capabilities as replayable processors.
- Use the host platform for ownership, findings, SLAs, suppression, ServiceNow, and general security signals where available.

#### Existing component modification map

| Existing component | Action | Required change |
|---|---|---|
| `AiSecurityContracts` | Preserve and version | Keep `ObservationEnvelopeV1`; add compatible snapshot/fact contracts and adapters. Introduce a V2 envelope only if an additive V1 extension cannot represent required provenance. |
| `AiSecurityObservationService` | Modify | Retain ownership validation, receipt idempotency, scope safety, relationship allowlisting, and complete-scope deactivation. Add immutable snapshot/fact writes and outbox publication. Do not use latest merged JSON as the authoritative historical input. |
| `AwsBedrockDiscoveryService` and `AzureAiDiscoveryService` | Modify incrementally | Retain provider collection and scope reporting. Move security interpretation such as wildcard privilege or guardrail strength into versioned normalizers after parity tests; keep collectors focused on provider evidence. |
| `AiSecurityResourceFamilyCatalogue` | Preserve | Keep its regional/global completeness semantics and make family/fact-schema compatibility explicit and versioned. |
| Provider/native-kind classification | Add governed replacement | Introduce stable technology IDs and reviewed aliases/signatures. Keep provider/native kind as evidence, not as the only policy-routing key. |
| `AiSecurityPolicyRegistry` | Replace | Use its 13 definitions as reference fixtures where helpful, then remove the hardcoded registry. Existing demo definitions do not need catalog-row migration. |
| `AiSecurityPolicyEvaluationService` | Replace behind a temporary test adapter | Reuse its tests and safe result semantics as an oracle. Build the generic evaluator against versioned facts and retire the switch without a policy-by-policy production-data migration. |
| `AiSecurityPlatformPolicyService` | Extend | Retain platform availability/default distribution and tenant reevaluation; add authored versions, validation, independent approval, canary, publication, pinning, and rollback. |
| `AiSecurityApiService` and `AiSecurityController` | Extend and version | Keep current inventory, graph, finding, policy, run, and scope endpoints during migration. Add AI-system, exposure, fact-history, and coverage endpoints without breaking current UI clients. |
| `AiSecurityJobWorkerService` and sync-run services | Preserve and extend | Retain fair scheduling, provider isolation, retries, sanitization, and backpressure; add stage events, outbox delivery, replay, dead-letter visibility, and affected-subgraph processing. |
| `ai_security_findings` and review services | Retire after reset | Do not migrate demo IDs, reviews, evidence, or history. Create new findings in the host workflow and remove the standalone path after the new vertical slice passes lifecycle tests. |
| Existing AI Security frontend pages | Evolve in place | Preserve routes and entitlement behavior; introduce system grouping, evidence history, exposure paths, canonical assignment/SLA/ticket actions, and transparent result-state views progressively. |

#### Data and behavior migration sequence

1. Add new tables and columns through forward-only migrations; never modify an already-applied migration. Confirm the next tenant and platform migration versions at implementation time.
2. Create immutable `artifact_snapshot`, technology registry/classification, typed `fact`, restricted `evidence_reference`, policy catalog/version, AI-system membership, exposure, and host-finding subject structures under forced RLS.
3. Re-scan or backfill current artifacts into clearly marked baseline snapshots and classified technology records. Normalize only whitelisted, understood fields; an absent or ambiguous legacy field becomes `UNKNOWN`, never an inferred PASS.
4. Reset existing demo AI policy definitions/settings/evaluations and AI finding/review data during the controlled development migration. Connector, tenant-security, audit, and run data are outside this reset unless separately approved.
5. Implement one new catalog policy as the end-to-end vertical slice. Use selected old policies and tests only to verify safe result-state behavior; do not migrate their rows or findings.
6. Switch assessment to the new engine after the vertical slice passes answer-key, replay, isolation, completeness, and finding-lifecycle tests. Roll back by feature flag or policy version without repeating provider discovery.
7. Create new failures directly as host findings and validate open/update/suppress/close/reopen behavior before retiring the standalone AI finding services and pages.
8. Add AI-system membership and correlation over the existing relationship graph. Recompute only affected bounded subgraphs.
9. Retire the hardcoded registry, policy switches, mutable JSON reads for evaluation, and standalone finding workflow after the new consumers pass acceptance tests. No demo policy or finding history migration is required.

No reset or migration step may weaken tenant isolation, expose credentials/evidence, affect non-AI host findings, or translate incomplete evidence into `PASS`.

#### Proposed core services

```text
AiArtifactIdentityService
AiArtifactSnapshotService
AiTechnologyRegistryService
AiTechnologyClassificationService
AiFactNormalizationService
AiDerivedFactOrchestrator
AiPolicyCatalogService
AiPolicyCompiler
AiPolicyApplicabilityService
AiPolicyPredicateEvaluator
AiPolicyEvaluationOrchestrator
AiInventoryAssessmentReconciliationService
AiSystemGraphService
AiExposureCorrelationService
AiFindingReconciliationService
AiCoverageService
```

#### Proposed APIs

```text
GET /api/ai-systems
GET /api/ai-systems/{id}
GET /api/ai-systems/{id}/graph
GET /api/ai-systems/{id}/facts
GET /api/ai-systems/{id}/findings
GET /api/ai-technologies
GET /api/ai-technologies/{id}
GET /api/ai-exposures
GET /api/ai-exposures/{id}
GET /api/ai-coverage
GET /api/ai-coverage/technologies
GET /api/ai-assessment-runs
GET /api/ai-policies
GET /api/ai-policies/{id}/versions
```

Existing `/api/ai-security/**` endpoints may remain as compatibility aliases during migration.
They must remain supported until the shipped frontend and documented integrations have moved to versioned replacements. New APIs should initially be additive; response-breaking changes require a new version or route.

### 7.5 Non-functional requirements

#### Security

- Forced RLS and explicit tenant context for every tenant operation.
- No cross-tenant caches, identifiers, evidence references, or graph traversals.
- Least-privileged read-only connector roles.
- Restricted evidence encryption and role checks.
- No raw prompts, tokens, credentials, or provider secrets in logs.
- Strict platform RBAC for catalog administration.
- Two-person policy publication approval.
- Complete audit for connector, catalog, evidence, finding, suppression, and export actions.

#### Reliability

- At-least-once processing with idempotent consumers.
- No finding closure after incomplete or failed scans.
- Replayable evaluation and correlation.
- Safe retries and dead-letter handling.
- Provider and tenant kill switches.

#### Performance and scale

- Incremental discovery and graph recomputation.
- Bounded predicate and traversal execution.
- Cursor-based inventory and finding APIs.
- No requirement to re-fetch provider configuration for policy replay.
- Establish performance baselines using a tenant with at least 15,000 AI-related resources and dependencies.

#### Explainability

- Every FAIL and exposure must show the facts, evidence, policy/correlation version, path, and reason.
- Every NO_DECISION, ERROR, and STALE result must state the missing or invalid input and recommended next action.

### 7.6 Out of scope for initial releases

- Tenant-authored policies or query-builder UI.
- Automated resource mutation or remediation.
- Behavioral red-team or jailbreak execution.
- Training-time governance beyond observable provider configuration and lineage.
- A complete replacement for CSPM, CIEM, DSPM, ASM, or vulnerability management.
- A requirement to reproduce a competitor's exact catalog size.
- Claims of behavioral protection based only on configuration presence.

### 7.7 Assumptions to validate

1. Customers will value 15–25 accurate, explainable controls more than a larger catalog with many unknown outcomes.
2. Existing host CIEM, DSPM, ASM, asset, and ownership signals can be consumed with stable contracts.
3. Bedrock and Azure are sufficient to prove the provider-neutral fact and system model.
4. Stable AI-system identity can be created from provider identifiers and relationships without excessive manual configuration.
5. Host finding workflows can support non-asset AI subjects without weakening existing behavior.
6. Design partners will accept explicit unknown and presence-only states even when they reduce headline compliance percentages.
7. PostgreSQL is sufficient for initial bounded graph traversal and correlation.

### 7.8 Low-cost validation experiments

| Hypothesis | Experiment | Success signal |
|---|---|---|
| Accurate depth beats policy count | Show design partners 20 evidence-rich controls versus a 60-rule coverage list | Most choose evidence quality and attack-path context |
| System graph improves triage | Prototype one Bedrock agent and one Azure agent exposure path | Analysts identify root cause and owner faster than from isolated findings |
| Coverage honesty builds trust | Compare a simple compliance percentage with the full result-state breakdown | Users understand gaps and prefer the transparent view |
| Host workflow creates value | Route one canary AI finding through ownership, SLA, suppression, ticket, and closure | No manual duplicate workflow is required |
| Identity is stable | Replay renamed, moved, shared, deleted, and rediscovered fixtures | No unexpected duplicate systems or findings |
| Catalog publication is safe | Run a deliberately incorrect draft rule through preview and canary | Impact is detected before broad publication and rollback succeeds |

---

## 8. Release

Release timeframes are relative and depend on team size, host-capability availability, and provider access. Each release is gated by evidence and acceptance criteria rather than a fixed date.

### Release 0 — Contracts and secure foundation

**Goal:** Add trustworthy data and control-plane contracts without destabilizing the working pilot.

Includes:

- verified baseline tests for current tenant isolation, ingestion, scope completeness, graph, policy outcomes, finding lifecycle, connector operations, and coverage gates;
- explicit preservation and compatibility contracts for current artifact identity, observations, relationships, APIs, and UI routes;
- stable AI-system identity built on the current artifact identity;
- immutable snapshots;
- versioned technology registry, aliases, classification evidence, and lifecycle;
- versioned fact contract;
- restricted evidence contract;
- policy definition/version/publication model;
- catalog validation and execution limits;
- finding fingerprint and lifecycle contract;
- answer-key test framework;
- additive schema and legacy baseline backfill;
- dual-write of mutable compatibility records and immutable snapshot/fact records;
- implement one new policy as the complete catalog-to-host-finding vertical slice; use the 13 existing policies only as optional test references;
- generate the first technology × resource-family × control-dimension coverage matrix and reconcile it to the catalog;
- one Bedrock policy in shadow mode.

**Exit criteria:**

- Published policy versions are immutable and rollback works.
- Shadow evaluation is deterministic and replayable.
- Tenant isolation and evidence authorization tests pass.
- No unresolved finding-identity blocker remains.
- Existing AWS/Azure inventory, graph, policy, finding, connector, and run experiences remain operational.
- No baseline reconstruction turns missing legacy evidence into PASS.
- Every active supported artifact has a technology classification and an explicit assessment-coverage state.
- The inventory-to-assessment reconciliation detects deliberately seeded unknown technology, no-policy, missing-fact, and incomplete-scope cases.

### Release 1 — Bedrock and Azure managed-AI posture

**Goal:** Deliver a trustworthy two-provider production posture product.

Includes:

- certify and harden the already implemented Bedrock and Azure discovery families;
- provider normalizers and stable facts;
- approved built-in policies selected from the coverage matrix;
- policy applicability resolved through stable technology, family, type, and capability references;
- answer-key validation followed by controlled cutover;
- owner and criticality;
- host finding workflow integration;
- transparent coverage and compliance UI;
- canary and design-partner rollout.

**Exit criteria:**

- Discovery recall and precision Key Results are met.
- All applicable critical controls return explicit states.
- No unknown or unavailable state appears as PASS.
- Finding open, update, suppress, close, reopen, and ticket flows pass.
- The old AI finding workflow is retired after the new host workflow passes lifecycle and isolation tests; demo history does not need to survive.
- Every released policy meets its own applicability, completeness, accuracy, evidence, and lifecycle acceptance tests. Matching all old demo-policy results is not required.
- For each certified technology, discovered inventory count reconciles with assessed plus explicitly unevaluated counts, with no silent omissions.

### Release 2 — AI exposure context

**Goal:** Add the security context required for meaningful prioritization.

Includes:

- effective permissions and trust analysis;
- sensitive-data attribution;
- configured and verified reachability;
- stronger owner and business criticality resolution;
- freshness and drift handling;
- identity, data, and network facts consumed from host capabilities where possible.
- AI-system membership over the existing artifact and relationship graph.

**Exit criteria:**

- High-value CIEM, DSPM, and reachability facts move from UNKNOWN to decision-capable states.
- Derived facts are replayable and explainable.
- Confidence and freshness are visible and tested.

### Release 3 — Correlated exposure management

**Goal:** Move from isolated posture findings to explainable AI attack paths.

Includes:

- extend the existing typed relationship graph into versioned system-level correlation;
- initial exposure templates;
- blast-radius context;
- root-cause and remediation-breakpoint selection;
- correlated exposure UI and workflow;
- affected-subgraph incremental recomputation.

**Exit criteria:**

- Three initial exposure templates meet precision and explainability gates.
- Shared root causes do not create uncontrolled ticket duplication.
- Analysts can trace every exposure from entry point to impact.
- Fixing a breakpoint closes the correlated exposure after complete reassessment.

### Release 4 — Discovery expansion

**Goal:** Reduce blind spots outside managed cloud control planes.

Recommended sequence:

1. Source and CI.
2. MCP.
3. SaaS AI administration.
4. Direct model providers.
5. Runtime telemetry.
6. Self-hosted workloads.
7. GCP managed AI.

**Exit criteria for each plane:**

- Uses canonical identity, facts, evidence, coverage, findings, and graph contracts.
- Declares its discovery and effectiveness limits.
- Meets plane-specific recall and precision gates.
- Does not weaken tenant isolation or evidence protection.

### Release 5 — Continuous exposure reduction

**Goal:** Make exposure management event-driven and measurable.

Includes:

- cloud-event and runtime-driven updates;
- incremental discovery and graph evaluation;
- remediation verification;
- exposure recurrence tracking;
- risk acceptance and exception expiry;
- executive and governance reporting;
- carefully approved remediation workflows.

Automated resource mutation remains excluded until recommendation precision, permissions, rollback, and customer approval requirements are independently defined.

### Rollout strategy

Every release follows:

```text
development fixtures
→ automated answer-key tests
→ shadow evaluation
→ internal tenant
→ design-partner canary
→ limited availability
→ general availability
```

Kill switches must exist at provider, tenant, policy, and processing-stage levels.

### Release blockers

The product must not advance to broad release if any of these remain true:

- tenant isolation cannot be demonstrated;
- catalog changes are mutable without controlled publication and rollback;
- raw prompts, credentials, or restricted evidence can enter logs or ordinary APIs;
- incomplete discovery can close findings;
- unknown, stale, unavailable, or presence-only controls appear as secure;
- finding identity creates material duplicates or cross-subject lifecycle changes;
- critical policies fail answer-key precision requirements;
- correlated exposures cannot explain their evidence and path.

### Future decisions

- Final retention period for immutable snapshots and restricted evidence.
- Build-versus-consume choices for CIEM, DSPM, and verified reachability.
- Canonical ownership rule for shared dependencies and cross-provider systems.
- When a graph database becomes justified by measured query requirements.
- Whether behavioral control testing becomes a separate product capability.
- Pricing and packaging for discovery planes, exposure correlation, and governance reporting.

---

## Appendix A — Product maturity definition

AI Grid becomes a complete AI Security Exposure Management platform when it can reliably perform all six steps:

1. **Discover:** Find managed, source-defined, SaaS, MCP, direct-provider, self-hosted, and runtime AI systems.
2. **Model:** Connect artifacts, identities, tools, models, data, networks, guardrails, owners, and business context.
3. **Assess:** Produce deterministic and behaviorally honest security results from versioned evidence.
4. **Correlate:** Identify realistic paths from entry point to sensitive impact.
5. **Respond:** Route root-cause work through ownership, SLA, suppression, exception, and ticket workflows.
6. **Verify:** Confirm remediation, detect recurrence and drift, and measure exposure reduction.

Until steps 1–3 are accurate, the product is an AI posture platform. When steps 4–6 are production-ready and continuously operated, it is an AI Security Exposure Management platform.

## Appendix B — Related design artifacts

- [`CLAUDE.md`](CLAUDE.md) — decision memory and current status.
- [`known-limitations.md`](known-limitations.md) — agentless discovery and product limitations.
- [`designs/2026-07-31-vertical-slice-implementation-plan.md`](designs/2026-07-31-vertical-slice-implementation-plan.md) — existing vertical-slice plan.
- [`designs/2026-07-31-accuracy-improvement-requirements.md`](designs/2026-07-31-accuracy-improvement-requirements.md) — verdict quality and structural accuracy.
- [`designs/2026-07-31-phase2-computation-plan.md`](designs/2026-07-31-phase2-computation-plan.md) — observed and derived fact model.
- [`designs/2026-08-01-discovery-prerequisite-epics.md`](designs/2026-08-01-discovery-prerequisite-epics.md) — AWS and Azure collection backlog.
- [`designs/2026-08-01-coverage-matrix.md`](designs/2026-08-01-coverage-matrix.md) — bounded policy completeness method.
- [`designs/2026-08-01-bedrock-azure-policy-catalog.md`](designs/2026-08-01-bedrock-azure-policy-catalog.md) — draft Bedrock and Azure catalog.
