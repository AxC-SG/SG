# AI Grid Decision Audit

**Status:** Current decision baseline  
**Reviewed:** 2026-08-02  
**Primary specification:** [PRD-AI-Grid-Final-Scope.md](PRD-AI-Grid-Final-Scope.md)  
**Sources reviewed:** `CLAUDE.md`, `AI-GRID-DISCUSSIONS.md`, `known-limitations.md`, all files under `designs/` and `evaluations/`, the current implementation, and the updated PRD.

## 1. Purpose

This document records which earlier AI Grid decisions the PRD adopts, changes, defers, supersedes, or intentionally excludes. It also records the latest decision that existing AI policy and finding data is demo data and may be reset.

The final-scope PRD is authoritative for product scope. This audit explains how it was derived. Earlier documents remain useful research but do not override the final PRD when they conflict with it.

## 2. Status definitions

| Status | Meaning |
|---|---|
| Adopted | Included in the PRD without a material change |
| Modified | The intent is retained, but implementation or scope changed |
| Added | Introduced during the implementation and exposure-management review |
| Deferred | Valid direction, but not required in the first releases |
| Superseded | Replaced by a later decision |
| Excluded | Intentionally outside the current PRD |
| Open | Not resolved and requires a product or architecture decision |

Rows marked **Added** are recommendations introduced by the implementation and exposure-management review and are now present in the draft PRD. They should be treated as proposed decisions until the PRD is formally approved. The reset of demo policy and finding data is different: it is an explicit user decision and is authoritative now.

## 3. Current authoritative decisions

### Product and scope

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-01 | Build AI Security Exposure Management, not only a provider posture scanner | Adopted | Summary, Objective, F-06 through F-10, Releases 2–5 |
| D-02 | Start with AWS Bedrock and ARM-managed Azure AI/Foundry/ML/Search/Bot/Content Safety | Adopted | Initial release boundary, F-02, Releases 0–1 |
| D-03 | Bound completeness to a declared provider and technology surface; do not claim “all AI” | Adopted | F-01A, F-02, F-09, release gates |
| D-04 | Scope findings by AI nexus and attribution, not by whether the evidence comes from an AI or general cloud resource | Adopted | Strategic principle, F-06, F-07, F-08 |
| D-05 | Every AI finding must be attributable to an AI artifact, AI system, relationship, or linked asset | Adopted | F-07 and F-08 subject model |
| D-06 | Generic CSPM findings with no AI relationship are outside AI Grid | Excluded | Strategic principle and out-of-scope section |
| D-07 | Wiz is inspiration and an end-state reference, not a product to clone | Modified | Differentiation favors evidence quality and exposure reduction; no commitment to Wiz’s exact schema, API, score, or rule count |
| D-08 | Support both Bedrock and Azure in the first production boundary | Adopted | Supersedes the earlier Bedrock-only release decision |

### Data, inventory, and technology

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-09 | Keep provider collection separate from computation over collected facts | Adopted | F-03, F-06, processing model |
| D-10 | Collect provider primitives and snapshot history, not only fields shaped for the current rules | Adopted | F-02, F-03, observation-service modification |
| D-11 | Distinguish observed facts from derived facts and retain provenance, confidence, inputs, version, and freshness | Adopted | F-03 and F-06 |
| D-12 | Store immutable artifact snapshots so evaluation and replay do not depend on mutable `attributes_json` | Added | F-03, Release 0, data migration sequence |
| D-13 | Use stable tenant/provider/provider-resource artifact identity as the current identity foundation | Adopted | F-01 and component modification map |
| D-14 | Add stable AI-system identity and represent shared dependencies without duplicating resources | Added | F-01 and F-07 |
| D-15 | Save technology as a governed, stable, versioned classification and coverage dimension rather than only a provider/native-kind string | Adopted | F-01A, architecture, Release 0 |
| D-16 | Classify inventory artifacts by zero or more technologies and capabilities with evidence and a registry version; designate a primary technology only when unambiguous | Adopted | F-01 and F-01A |
| D-17 | Treat unknown, ambiguous, retired, or unmapped technology as visible coverage states without blocking provider-neutral policies that have sufficient type, capability, relationship, fact, and scope evidence | Adopted | F-01A and F-09 |
| D-18 | Validate connector-discovered families against the technology registry and coverage matrix to detect silent drift | Adopted and strengthened | F-01A, F-12 |
| D-19 | Collect resource tags and full configuration per supported family | Modified | Azure tag collection already exists and is preserved; AWS and family-specific gaps remain. “Full configuration” means an approved, redacted primitive set, not unrestricted payload retention. |
| D-20 | Resolve owner, environment, tags, and criticality or explicitly record failure | Adopted | F-01, Key Results, Releases 1–2 |

### Policy engine and catalog

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-21 | Replace the hardcoded policy list and Java switch with a data-driven policy engine | Adopted | F-04, F-05, component modification map |
| D-22 | Build one complete data-driven vertical slice before loading catalog breadth | Adopted | Release 0 |
| D-23 | Use a curated, platform-owned built-in policy catalog | Adopted | F-04 |
| D-24 | Tenants may enable or disable distributed built-in policies | Adopted | F-04 |
| D-25 | Do not provide tenant-authored policies, a public query builder, or a customer fact-schema editor initially | Excluded | F-04 and out-of-scope section |
| D-26 | Published policy versions are immutable and governed through draft, validation, approval, canary, publication, rollback, and retirement | Added | F-04, Release 0 |
| D-27 | Policy applicability is driven first by artifact type, capabilities, relationships, facts, and scope completeness; technology is a governed optional constraint for genuinely product-specific controls | Adopted | F-01A, F-04, F-05 |
| D-28 | After every complete inventory run, reconcile expected applicable policy assessments against actual assessment states | Added | F-01A and F-09 |
| D-29 | An artifact with no applicable policy is `NO_POLICY_COVERAGE`, not secure | Adopted and strengthened | F-01A and F-09 |
| D-30 | Derive catalog completeness from a technology/resource-family × control-dimension matrix rather than a hand-maintained list | Adopted and broadened | F-01A and Release 0 |
| D-31 | The 62-policy Bedrock/Azure matrix is the current candidate superset, not a commitment to ship all 62 in Release 1 | Modified | The PRD releases only policies that meet fact, accuracy, evidence, and coverage gates |
| D-32 | The existing 13 policies are reference fixtures, not records that must be migrated | Modified by latest user decision | Release 0 and component modification map |

### Decision and coverage semantics

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-33 | Policy evaluation is deterministic and must not call provider APIs | Adopted | F-05 |
| D-34 | Missing or incomplete evidence never produces PASS | Adopted | F-02, F-03, F-05, release gates |
| D-35 | Preserve explicit PASS, FAIL, NO_DECISION, NOT_APPLICABLE, NO_RESOURCE, DISABLED, ERROR, and STALE states | Adopted and expanded | F-05 and F-09 |
| D-36 | `NO_DECISION` is useful and drives an accuracy backlog rather than being hidden | Adopted | F-05, F-09, Release 1 |
| D-37 | Every planned `NO_DECISION` must identify the missing fact, scope, capability, or owning accuracy requirement | Adopted and generalized | F-03, F-05, explainability requirements |
| D-38 | Coverage must never count `NO_DECISION`, unknown, unavailable, stale, or presence-only as PASS | Adopted | F-09 and Key Results |
| D-39 | Report exact denominators and reconcile assessed plus explicitly unevaluated inventory | Adopted and strengthened | F-01A and F-09 |
| D-40 | Separate control presence from evidence that a control is behaviorally effective | Adopted | F-09 and product constraints |

### Graph, exposure, and general-security context

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-41 | Preserve and extend the existing typed relationship graph | Adopted | F-07 and component map |
| D-42 | Use PostgreSQL bounded graph traversal first; do not require a graph database | Added | Architecture section |
| D-43 | Correlate bounded AI-system subgraphs into explainable exposure paths | Adopted and expanded | F-07, Release 3 |
| D-44 | AI Grid consumes and attributes general CIEM, DSPM, ASM, asset, reachability, and ownership signals instead of rebuilding those platforms | Adopted | Strategic principle, F-06, Release 2 |
| D-45 | Build only the thinnest missing general-security computation needed for an AI use case | Adopted | F-06 and assumptions |
| D-46 | Effective-permission and trust analysis is the first high-value identity capability | Modified | Still prioritized in Release 2, but consume an existing host CIEM capability first and build CIEM-lite only if the host cannot supply the required contract |
| D-47 | Derived reachability must remain separate from configured public exposure | Adopted | F-06 |
| D-48 | A correlated exposure must show entry point, path, root cause, impact, confidence, blast radius, and remediation breakpoints | Added | F-07 and Release 3 |

### Findings and workflow

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-49 | AI findings belong in the host finding workflow to inherit ownership, SLA, suppression, exception, notification, ticket, and audit behavior | Adopted | F-08 |
| D-50 | Existing AI policy, policy-setting, evaluation, finding, and review data may be reset because it is demo data | New authoritative decision | Baseline, component map, reset sequence, Releases 0–1 |
| D-51 | Do not run a long-lived strangler or history migration for demo findings | Modified | New findings are created directly in the host workflow; standalone AI tables/services are retired after lifecycle and isolation tests |
| D-52 | Preserve finding behavior, not existing demo finding IDs or history | Modified | Open/update/suppress/close/reopen safety remains required; data backfill is not required |
| D-53 | Never close findings after partial, failed, unknown, stale, or error evidence | Adopted | F-08 |
| D-54 | Deduplicate shared-root-cause exposure and avoid one ticket per graph node | Adopted | F-07 and F-08 |

### Platform and API architecture

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-55 | Evolve the existing AI Security bounded context instead of rewriting secure collection and tenancy foundations | Modified | Code foundations are preserved, but demo policy/finding data and hardcoded policy components may be replaced directly |
| D-56 | Preserve forced RLS, entitlement gates, connector security, receipt idempotency, scope completeness, kill switches, tenant fairness, retries, and backpressure | Adopted | Baseline, F-02, F-12, non-functional requirements |
| D-57 | Keep REST; do not introduce GraphQL | Adopted | Proposed REST APIs; GraphQL intentionally excluded |
| D-58 | Keep existing `/api/ai-security/**` routes while shipped UI clients need them; add new APIs additively | Adopted | Architecture API section |
| D-59 | Add replayable pipeline stages and transactional outbox events without replacing the proven job worker first | Added | F-12 and component map |
| D-60 | Keep new tenant data under forced RLS and explicitly authorize restricted evidence | Adopted and expanded | F-03 and security requirements |

### Frameworks, scoring, and reporting

| ID | Decision | Status | PRD coverage / effect |
|---|---|---|---|
| D-61 | Use OWASP LLM Top 10 as the first reporting framework | Adopted | F-09 and Release 1 |
| D-62 | Add MITRE ATLAS and NIST AI RMF reporting later | Deferred | F-09 |
| D-63 | Avoid one opaque organization-wide risk score initially | Modified from the earlier weighted-score concept | F-10 keeps impact, exploitability, reachability, criticality, blast radius, confidence, and freshness separate |
| D-64 | Measure success through decision-complete coverage and exposure closure, not raw policy count | Added | Objectives and Key Results |
| D-65 | Preserve evidence and exception history for new production findings and exports | Adopted | F-03, F-08, F-09; this does not apply to reset demo data |
| D-66 | Encode materially different claims as different fact keys; keep state, provenance, evidence class, confidence, freshness, and derivation method as orthogonal metadata | Adopted | FR-04 |
| D-67 | Require exact fact keys and acceptable evidence constraints in every policy/correlation, with publication-time lint against fact semantics and workflow use | Adopted | FR-05 and FR-06 |
| D-68 | Keep catalog lifecycle, tenant selection, subject applicability, evidence readiness, and decision as separate state dimensions | Adopted | FR-05A |
| D-69 | Evaluate preview policies without owner-facing findings; recommend promotion on readiness but never silently change tenant selection | Adopted | FR-05A and FR-08 |
| D-70 | Use `POSTURE_FINDING`, `EXPOSURE_HYPOTHESIS`, and `VALIDATED_EXPOSURE` workflow classes with correlation-specific, bidirectional, freshness-gated graduation | Adopted | FR-08 |
| D-71 | Count all applicable published policies in transparent coverage, including preview and tenant-disabled categories; keep first-run utility separate | Adopted | FR-09 and FR-17 |
| D-72 | Use stable AI-system IDs with immutable revisions and lineage; retain underlying artifact/edge/path versions and do not auto-transfer findings across split/merge | Adopted | FR-01 |
| D-73 | Provide a Minimum Context Pack with distinct proxy fact keys, but never let a proxy substitute for a different verified claim | Adopted | FR-16 |
| D-74 | Make first-run utility and time to value explicit without shrinking the coverage denominator | Adopted | FR-17 and Releases 0–1 |
| D-75 | Operate provider answer-key environments as staffed, versioned, release-blocking product infrastructure | Adopted | FR-18 |
| D-76 | Govern precision claims through stratified samples, dual review, adjudication, versioned labels, and adequate sample disclosure | Adopted | FR-19 |
| D-77 | Use tenant-scoped content-addressed evidence, incremental discovery, retention classes, and per-tenant economics budgets and alerts | Adopted | FR-20 |
| D-78 | Permit confidence thresholds only for named, calibrated evidence classes or derivation methods; never treat equal scores from unrelated methods as comparable | Adopted | FR-21 |

## 4. Decisions changed from earlier plans

| Earlier decision | Current decision | Why it changed |
|---|---|---|
| Start with Bedrock only; Azure second | Bedrock and ARM-managed Azure are both in the first boundary | Azure discovery already exists and two providers validate the provider-neutral model |
| Migrate the 13 existing policies into catalog rows | Start with a fresh governed catalog; use old policies only as optional test fixtures | Existing policy content is demo data and does not need preservation |
| Use a strangler with finding-history migration and parity | Create new findings directly in the host workflow and reset demo AI findings/reviews | There is no production history to protect, so dual paths add cost and drift risk |
| Preserve policy distribution/settings data | Preserve the behavior, reset demo rows/settings | The controls matter; the demo configuration does not |
| Require old/new result parity for every existing policy | Require safety-semantic regression plus answer-key accuracy for every newly released policy | Old demo outcomes are not the product truth |
| Treat technology mainly as a tag used in applicability | Make technology a governed versioned registry with classification evidence and coverage reconciliation | Misclassification otherwise creates invisible false negatives |
| Maintain a policy catalog by enumeration | Generate or validate it from the bounded coverage matrix | A hand list missed implemented resource families |
| Aim toward a large Wiz-like rule catalog | Release a smaller set of accurate policies from the candidate matrix | Evidence quality and decision completeness are more defensible than catalog size |
| Add tags to both connectors | Preserve Azure tags and close AWS/family gaps | Source review found Azure tag ingestion already implemented |
| Build CIEM-lite first | Consume host CIEM first; build only a missing thin slice | Avoid rebuilding general CNAPP capabilities |
| Build a weighted posture/organization score early | Keep risk factors separate initially | An opaque score can hide uncertainty and weak evidence |
| Preserve existing APIs as permanent product shape | Keep them as compatibility routes while adding system/exposure APIs | The current routes serve the pilot UI but do not express the target system model |
| Model `CONFIGURED`, `DERIVED`, and `VERIFIED` as one ordered fact axis | Use distinct fact keys for distinct claims and orthogonal provenance/evidence/confidence/freshness metadata | The proposed axis mixed claim meaning, production method, and assurance and could rank evidence incorrectly |
| Auto-enable policies when tenant evidence becomes available | Keep tenant selection stable and audited; adapt evidence readiness, preview evaluation, recommendation, and governed promotion | Silent enablement makes governance nondeterministic and causes unexplained finding churn |
| Use one binary finding/exposure threshold | Use posture findings, exposure hypotheses, and validated exposures with per-definition graduation | Directly observed posture is actionable while proxy-based cross-domain paths require stronger evidence |

## 5. Intentionally ignored or rejected decisions

“Ignored” here means intentionally not carried into the current PRD, not accidentally overlooked.

| Item | Status | Reason |
|---|---|---|
| Clone Wiz’s exact 260-rule catalog | Excluded | The product is evidence- and attribution-led, not a catalog-count clone |
| Commit to shipping all 62 matrix candidates in Release 1 | Excluded | The matrix defines the bounded candidate surface; only validated policies ship |
| Generic CSPM findings unrelated to AI | Excluded | Violates the AI attribution boundary |
| Tenant-authored custom policies | Excluded initially | Raises authoring, validation, tenancy, and support risk before the built-in model is proven |
| Customer query-builder policy UI | Excluded initially | Not needed for a curated catalog |
| Customer-facing fact-schema registry | Excluded initially | Internal validation contract only |
| GraphQL transport | Excluded | Adds a second security and tenancy surface without a current product need |
| A graph database in the initial architecture | Excluded initially | Existing PostgreSQL graph storage is adequate until measurements show otherwise |
| Automatic cloud-resource mutation/remediation | Excluded initially | Requires separate permission, rollback, approval, and safety requirements |
| Claiming jailbreak resistance or control effectiveness from configuration presence | Excluded | Configuration can prove presence, not behavioral efficacy |
| Preserving demo policy rows, settings, evaluations, findings, review IDs, and review history | Excluded by latest decision | The data has no production value |
| A permanent separate AI finding workflow | Excluded | It blocks host ownership, SLA, exception, ticket, and notification integration |
| One opaque A–F or organization-wide risk score in the first releases | Excluded initially | Can conceal confidence, freshness, and unevaluated coverage |

## 6. Deferred decisions and capabilities

These are not ignored. They remain part of the long-term direction but are not Release 0–1 requirements.

| Item | Planned position |
|---|---|
| Source and CI discovery for SDKs, prompts, IaC, and `.mcp.json` | Release 4 candidate, first new discovery plane |
| MCP server and tool discovery | Release 4 candidate after source/CI |
| SaaS AI administration, including Copilot Studio | Release 4 candidate |
| Direct model-provider APIs | Release 4 candidate |
| Runtime telemetry and unknown runtime assets | Release 4 candidate |
| Self-hosted AI on compute and Kubernetes | Release 4 candidate |
| GCP managed AI | Release 4 candidate |
| SageMaker and broader AWS training surface | Deferred beyond the initial Bedrock boundary |
| Full DSPM and ASM mechanisms | Consume host capabilities or external sources; do not make AI Grid their owner |
| MITRE ATLAS and NIST AI RMF reporting | After OWASP reporting is stable |
| Approved automated remediation | After recommendation precision, permission, rollback, and customer-approval contracts exist |
| Event-driven continuous reassessment | Release 5 |

## 7. Open decisions not fully specified by the PRD

| ID | Open decision | Recommendation |
|---|---|---|
| O-01 | Exact technology taxonomy and initial seed list | Derive it from the bounded Bedrock/Azure families and the 62-policy matrix; assign stable IDs independent of display names |
| O-02 | Exact provider-neutral artifact taxonomy | Reconcile the earlier 17-type proposal with the 29 implemented resource families before schema freeze |
| O-03 | Policy predicate representation | Choose a small JSON predicate DSL with a fixed operator allowlist, typed fact references, bounded depth, and no executable code |
| O-04 | Which single policy is the Release 0 vertical slice | Use a Bedrock guardrail-strength policy because it exercises technology, facts, completeness, catalog, finding, and OWASP mapping with simple answer-key evidence |
| O-05 | Which policies from the 62-candidate matrix ship in Release 1 | Rank by customer impact, evidence availability, precision, and provider-family coverage after the vertical slice |
| O-06 | Whether to retain current artifact inventory during development reset | Prefer re-scan from connectors into immutable snapshots; do not reset connector credentials/configuration unless required |
| O-07 | Evidence retention periods and restricted-evidence sharing rules | Define with Security and Legal before external design-partner use |
| O-08 | Scale threshold for considering a graph database | Establish PostgreSQL traversal latency and affected-subgraph SLOs first |
| O-09 | CycloneDX ML-BOM export | Not covered by the current PRD; validate customer demand before adding to a release |
| O-10 | Platform advisory and multi-tenant platform-owner APIs | Not fully specified; define after the tenant workflow and policy governance model are proven |

## 8. Clean-start implementation consequence

The current implementation should be treated as reusable code and test evidence, not reusable demo assessment data.

Preserve:

- tenant isolation and forced RLS;
- entitlement and role gates;
- connector credentials, rotation, permission checks, and kill switches;
- observation idempotency and scope completeness;
- job fairness, retry, sanitization, and backpressure;
- useful discovery adapters and relationship collection;
- safe result-state and finding-lifecycle tests.

Reset or replace:

- hardcoded policy definitions;
- demo policy distribution and tenant settings;
- demo evaluation rows;
- demo AI findings and reviews;
- standalone AI finding workflow after host-workflow acceptance;
- mutable artifact JSON as the policy engine’s authoritative evidence source.

Build fresh:

- immutable snapshots and typed facts;
- technology registry and classification;
- policy applicability and governed catalog;
- inventory-to-assessment reconciliation;
- host AI findings;
- AI-system grouping and exposure correlation.
