# Product Requirements Document — AI Grid Final Scope

**Product:** AI Grid  
**Status:** Final scope baseline  
**Document owner:** Product  
**Last updated:** 2026-08-02  
**Initial production boundary:** AWS Bedrock and ARM-managed Azure AI  
**Supersedes:** `PRD-AI-Security-Exposure-Management.md` where scope or sequencing differs  
**Decision record:** `AI-GRID-DECISION-AUDIT.md`

---

## 1. Summary

AI Grid is an evidence-backed AI Security Exposure Management product for in-scope, discovered AI systems. It discovers managed AI resources, groups them into accountable systems, evaluates security controls from immutable evidence, correlates identity, data, network, model, agent, and tool conditions into explainable exposure paths, routes action through the host workflow, and verifies closure with fresh evidence.

The product will begin with AWS Bedrock and ARM-managed Azure AI. It will integrate with existing CIEM, DSPM, ASM, runtime protection, SIEM, MLOps, ITSM, and governance capabilities rather than rebuilding those products. It will compete on coverage integrity, explainability, exposure compression, and verified closure—not asset count, policy count, or unsupported claims of complete AI protection.

---

## 2. Contacts

| Name | Role | Responsibility |
|---|---|---|
| Karthik Gowri | Product owner | Scope, priority, claims, roadmap, and release acceptance |
| TBD | Engineering lead | Architecture, delivery, reliability, and operational readiness |
| TBD | Security architect | Threat model, tenant isolation, evidence security, and policy governance |
| TBD | Design lead | Inventory, coverage, exposure, and remediation experiences |
| TBD | Platform lead | Host findings, ownership, SLA, ServiceNow, CIEM, DSPM, ASM, and asset integrations |
| Design partners | Customer advisory group | Validate evidence quality, exposure precision, workflow value, and terminology |

### Decision authority

| Decision | Accountable roles |
|---|---|
| Product claims and release boundary | Product owner |
| Security and tenant-isolation acceptance | Security architect + Engineering lead |
| Policy publication and severity | Product owner + Security architect |
| Data contracts and migrations | Engineering lead |
| Production release | Product owner + Engineering lead + Security architect |

---

## 3. Background

### 3.1 Current implementation

The current AI Security module already provides valuable code foundations:

- AWS Bedrock and Azure AI/Foundry/ML/Search/Bot discovery;
- 29 catalogued resource families with regional and global completeness semantics;
- `ObservationEnvelopeV1`, chunking, receipt idempotency, and content-hash replay protection;
- forced tenant row-level security, entitlement gates, role checks, audit, and protected credentials;
- connector permission diagnostics, kill switches, retries, tenant fairness, concurrency limits, and backpressure;
- stable provider-resource artifact identity, typed relationships, graph APIs, and inventory UI;
- explicit `PASS`, `FAIL`, `NO_DECISION`, and `NOT_APPLICABLE` behavior;
- coverage gates and safe finding-lifecycle tests.

The current implementation is not yet AI Security Exposure Management because:

- evidence is primarily stored in mutable merged JSON;
- policies and applicability logic are hardcoded in Java;
- technology classification and inventory-to-policy reconciliation are implicit;
- AI-system membership and relationship confidence are not formally modeled;
- identity, sensitive-data, and verified-reachability context is incomplete;
- relationships are not correlated into validated exposure paths;
- AI findings use a separate workflow;
- runtime, behavioral, agent/MCP, source, and supply-chain evidence are future capabilities.

Existing AI policies, policy settings, evaluations, findings, and reviews are demo data. They may be reset. Existing code and tests remain reference material, but demo data and hardcoded policy behavior do not require migration or preservation.

### 3.2 Product problem

Security teams cannot reliably answer:

1. Which managed AI systems exist in the declared scope?
2. Which resources, identities, data stores, models, guardrails, tools, and networks form each system?
3. Who owns the system, and how confident is that ownership?
4. Which controls were evaluated, and what was unknown, stale, inaccessible, unsupported, or not covered?
5. Which combinations create meaningful paths to sensitive data or consequential actions?
6. Which high-leverage correction can break each path?
7. Was the exposure actually closed using fresh, complete evidence?

### 3.3 Strategic boundary

AI Grid owns:

- AI artifact and AI-system identity;
- AI-specific technology and capability classification;
- evidence integrity and coverage semantics;
- AI policy applicability and deterministic evaluation;
- AI attribution of identity, data, network, model, agent, and tool signals;
- AI-system exposure correlation;
- high-leverage remediation breakpoints;
- verified reassessment and closure.

AI Grid integrates with but does not initially replace:

- CSPM, CIEM, DSPM, ASM, vulnerability management, and asset management;
- runtime prompt and response protection;
- MLOps registries and model scanners;
- red-team and behavioral-evaluation platforms;
- SIEM, SOAR, ITSM, and GRC systems.

### 3.4 Product claims

Approved claim:

> AI Grid creates evidence-backed system views for in-scope AI, identifies explainable exposure paths, recommends high-leverage remediation breakpoints, and verifies closure with fresh evidence.

Prohibited initial claims:

- “complete AI security platform”;
- “discovers every AI system”;
- “stops prompt injection”;
- “AI firewall”;
- “hundreds of AI checks” as the primary value;
- “compliance out of the box”;
- “single AI risk score”;
- “optimal” or mathematically smallest remediation without validated optimization evidence.

---

## 4. Objective

### 4.1 Product objective

Enable cloud and exposure-management teams to reduce meaningful AI-system exposure using trustworthy inventory, explicit coverage, explainable paths, accountable workflow, and verified closure.

### 4.2 Customer outcomes

Customers can:

- understand managed AI systems across Bedrock and Azure within the declared boundary;
- see observed, derived, missing, stale, and restricted evidence separately;
- identify classified, unclassified, unsupported, and unassessed inventory;
- distinguish configuration presence from behavioral effectiveness;
- prioritize system exposure rather than isolated configuration issues;
- assign remediation to a confirmed or explicitly unresolved owner;
- replay decisions and prove why findings opened or closed;
- measure exposure reduction without treating unknown coverage as safe.

### 4.3 Key results

#### Foundation production release

1. Achieve at least **95% discovery recall per certified resource family** in seeded Bedrock and Azure answer-key environments.
2. Maintain a **zero silent-omission rate**: every active supported artifact is assessed or receives an explicit reconciliation state.
3. Produce an explicit result for **100% of applicable critical controls**; incomplete, unknown, stale, or inaccessible evidence never counts as PASS.
4. Achieve at least **95% reviewed precision** for every released high- or critical-priority policy family before broad publication.
5. Demonstrate **100% replay determinism** for identical artifact snapshot, fact, applicability, and policy versions.
6. Demonstrate zero unauthorized cross-tenant access through APIs, graph traversal, caches, jobs, outbox events, evidence references, and exports.
7. Ensure every new host finding retains tenant, subject, policy version, fact snapshot, evidence references, reason, and stable fingerprint.
8. Meet the calibrated first-run utility target without excluding preview, disabled, or missing-evidence policies from the disclosed security denominator.
9. Establish measured per-tenant provider-call, processing, unique-snapshot-storage, retention, and graph-recomputation baselines before production pricing or scale claims.
10. Publish precision only through the approved sampling, dual-review, and adjudication process.

#### Exposure-management release

1. Release three validated exposure templates covering:
   - external reachability, weak authentication, and sensitive-data access;
   - tool-enabled agent, excessive privilege, and secret or consequential-action access;
   - untrusted content, autonomous execution, and inadequate guardrail or approval.
2. Meet the approved human-reviewed precision threshold for each template before general release.
3. Explain every exposure using entry point, path, affected system, evidence, temporal validity, confidence, impact, root cause, and breakpoint.
4. Route at least **90% of accepted high-priority exposures** to a confirmed owner and SLA workflow.
5. Close exposures only after a complete reassessment confirms the relevant path is broken.

### 4.4 North Star Metric

**Percentage of in-scope production AI systems with a confirmed owner, fresh decision-complete coverage for applicable critical controls, and no unresolved or unaccepted critical exposure.**

### 4.5 Initial operating metric

**Decision-complete critical-control coverage for certified Bedrock and Azure families, with zero silent inventory omissions.**

---

## 5. Market Segments

### 5.1 Primary — Cloud security and exposure-management teams

**Job:** Identify which managed AI systems create meaningful exposure and route the right corrective action to the right owner.

**Why first:** These teams already operate asset, identity, finding, SLA, ticket, and exposure workflows that AI Grid can extend.

### 5.2 Secondary — AI platform and application owners

**Job:** Understand whether AI systems have safe identities, data access, network exposure, guardrails, tools, approvals, and logging before and after deployment.

### 5.3 Secondary — Governance and risk teams

**Job:** Demonstrate which AI security controls were evaluated, which evidence supports them, and which coverage gaps, exceptions, and limitations remain.

### 5.4 Later — SOC and incident-response teams

**Job:** Correlate runtime AI detections with systems, exposure paths, owners, evidence, containment actions, and verified remediation.

SOC becomes a primary workflow only after runtime-signal ingestion is delivered.

### 5.5 Initial ideal customer profile

An organization that:

- uses AWS Bedrock or Azure AI across multiple accounts or subscriptions;
- already operates cloud security or exposure-management workflows;
- has SIEM and ITSM processes;
- has some ownership, CMDB, CIEM, DSPM, or reachability data;
- values evidence and remediation closure more than a large rule count.

---

## 6. Value Propositions

### 6.1 Evidence honesty

Unknown, stale, inaccessible, unsupported, untested, and no-policy conditions remain visible. They never become passing results merely to improve a score.

### 6.2 AI-system context

AI Grid connects resources, identities, models, tools, data, networks, and guardrails into accountable system views instead of showing isolated cloud resources.

### 6.3 Exposure compression

Many low-level conditions are correlated into fewer actionable exposure paths with explicit root causes.

### 6.4 High-leverage remediation

AI Grid recommends a breakpoint that can remove one or more paths, explains why it was selected, and avoids claiming mathematical optimality until supported by evidence.

### 6.5 Verified closure

A finding or exposure closes only after fresh, complete reassessment proves that the required control passed or the relevant path was broken.

### 6.6 Open security-signal ecosystem

Existing cloud controls, runtime protection, CIEM, DSPM, ASM, MLOps, SIEM, and ITSM tools provide evidence. AI Grid supplies AI attribution, correlation, workflow, and closure.

---

## 7. Solution

### 7.1 Core user flows

#### Flow A — Connect and establish coverage

```text
Tenant admin enables AI Grid
→ configures a read-only Bedrock or Azure connector
→ validates permissions
→ runs discovery
→ reviews family completeness and connector health
→ sees every artifact reconciled to an assessment or explicit coverage gap
```

#### Flow B — Investigate an AI system

```text
Analyst opens AI Inventory
→ selects a system
→ reviews membership and confidence
→ sees technologies, capabilities, relationships, owner, and criticality
→ reviews observed, derived, missing, stale, and restricted facts
→ opens findings and exposure paths
```

#### Flow C — Remediate and verify

```text
Analyst opens an exposure
→ reviews entry point, impact, path, evidence, confidence, and root cause
→ accepts or changes the recommended breakpoint
→ assigns the host finding and ticket
→ owner remediates
→ complete reassessment runs
→ exposure closes only if the relevant path is broken
```

#### Flow D — Manage coverage

```text
Coverage owner opens Coverage Integrity
→ reviews UNKNOWN_TECHNOLOGY, NO_POLICY_COVERAGE, MISSING_FACTS,
  INCOMPLETE_SCOPE, STALE_EVIDENCE, UNSUPPORTED, and UNRESOLVED_OWNER
→ assigns a reason, owner, action, and SLA
→ tracks resolution without counting the gap as secure
```

### 7.2 Functional requirements

#### FR-01 — Canonical artifacts and AI systems — Must

- Retain stable tenant/provider/provider-resource artifact identity.
- Treat artifact identity, evidence-backed relationship edges, and host-asset links as authoritative records. Treat AI-system membership and exposure paths as derived or user-confirmed overlays.
- Support provider-neutral artifact types while preserving native identifiers and kinds.
- Group artifacts into AI systems using deterministic, heuristic, and user-confirmed membership.
- Store membership source, rationale, confidence, validity, and state.
- Support shared components, user rejection, split, merge, and membership history.
- Give each AI system a stable logical ID and immutable revisions of its membership and system state.
- Record `CREATED`, `SPLIT`, `MERGED`, and `RETIRED` lineage events with predecessor and successor references.
- Retain system ID, system revision, underlying artifact IDs, relationship IDs, and path version on system findings and exposures.
- Do not automatically transfer findings or exposures across a split or merge. Re-evaluate whether the affected subject and path still exist.
- Ensure artifact-level policy correctness never depends on uncertain AI-system grouping.
- Track first seen, last seen, deleted, stale, and rediscovered states.

Ownership states must remain separate:

```text
CONFIRMED | INFERRED | CANDIDATE | UNOWNED
```

Ownership coverage must report state and confidence rather than combining all non-empty values.

#### FR-02 — Technology and capability classification — Must

- Maintain a platform-owned, versioned technology registry with stable IDs, aliases, provider kinds, resource families, lifecycle, and replacement mappings.
- Assign artifacts zero or more technology classifications and capabilities with evidence and registry version.
- Designate one primary technology only when evidence is unambiguous.
- Make unknown, ambiguous, retired, and unmapped technology visible coverage conditions.
- Do not block a provider-neutral policy when artifact type, capabilities, relationships, facts, and scopes are sufficient.

#### FR-03 — Discovery and connector health — Must

- Preserve supported AWS Bedrock and ARM-managed Azure AI discovery adapters.
- Certify each resource family separately before production enablement.
- Record `COMPLETE`, `PARTIAL`, `FAILED`, `UNSUPPORTED`, and `NOT_CONFIGURED` scope states.
- Record missing permission, throttle, provider error, credential, and unsupported-region reasons.
- Preserve read-only access, protected credentials, rotation, diagnostics, kill switches, fairness, retries, and backpressure.
- Collect an approved and redacted primitive configuration set, not unrestricted provider payloads.

#### FR-04 — Immutable snapshots, facts, and evidence — Must

- Store immutable artifact snapshots for assessment and replay.
- Give each fact key one documented claim meaning. Encode materially different claims as different keys, such as `network.public_access_configured` and `network.internet_reachability_verified`.
- Store typed facts with value, state, provenance, evidence class, source, timestamps, expiry, confidence, schema version, derivation method/version, and input references.
- Maintain an internal fact registry that documents value type, claim semantics, allowed evidence classes, allowed workflow uses, freshness rules, derivation method, and replacement/deprecation history.
- Distinguish provenance values such as `PROVIDER_OBSERVED`, `DERIVED`, `IMPORTED`, `USER_ASSERTED`, and `RUNTIME_OBSERVED`.
- Distinguish evidence classes such as `CONFIGURATION`, `GRAPH_ANALYSIS`, `ACTIVE_TEST`, `RUNTIME_OBSERVATION`, and `MANUAL_ATTESTATION`.
- Use `KNOWN`, `UNKNOWN`, `ERROR`, and `STALE` fact states.
- Do not treat provenance or evidence class as one universal strength ranking. A derived fact may be strongly corroborated, and a configuration fact may be directly observed.
- Keep raw prompts, responses, tokens, secrets, retrieved documents, and tool parameters out of ordinary facts and logs.
- Store approved sensitive material only through encrypted, role-restricted evidence references with redaction and retention controls.
- Maintain current-state projections separately for fast UI access.

#### FR-05 — Governed policy catalog — Must

- Replace the hardcoded Java registry and policy switch with a declarative, bounded predicate model.
- Use a curated platform-owned catalog; tenants may enable or disable distributed built-ins.
- Support `DRAFT`, `VALIDATED`, `APPROVED`, `CANARY`, `PUBLISHED`, and `RETIRED` lifecycle states.
- Validate types, operators, fact references, applicability references, required scopes, execution limits, tests, mappings, remediation, and reason codes.
- Require each policy or correlation version to declare exact fact keys, acceptable evidence classes, maximum age, confidence requirements, corroboration requirements, and scope completeness.
- At publication, lint required facts against the fact registry and intended workflow tier. Reject substitution of a configuration proxy for a different verified claim.
- Permit a configuration-class fact in a validated exposure only when it proves the configuration claim that the template actually requires and the fact registry permits that workflow use.
- Require answer-key tests, impact preview, independent approval, immutable publication, rollback, and audit.
- Do not execute tenant-authored code.
- Do not provide tenant-authored policies or a customer query builder in the initial releases.

Applicability order:

```text
artifact type
→ capabilities
→ required relationships
→ required facts and scope completeness
→ optional technology constraint
→ evaluation
```

#### FR-05A — Policy selection, evidence readiness, and preview — Must

Keep these dimensions independent:

```text
Catalog state:      DRAFT | VALIDATED | APPROVED | CANARY | PUBLISHED | RETIRED
Tenant selection:   REQUIRED | ENABLED | PREVIEW | DISABLED
Applicability:      APPLICABLE | NOT_APPLICABLE
Evidence readiness: READY | MISSING_FACTS | INCOMPLETE_SCOPE | STALE | UNSUPPORTED
Decision:           PASS | FAIL | NO_DECISION | ERROR
```

- Never silently change tenant policy selection because evidence appears or disappears.
- Always evaluate `REQUIRED` and `ENABLED` policies when applicable.
- Evaluate `PREVIEW` policies for analysts and coverage, but do not create owner-facing SLA findings from them.
- Keep `DISABLED` applicable policies visible in coverage denominators.
- Recommend promotion when a preview policy becomes decision-ready, but require an audited tenant or platform governance action to promote it.
- Record every selection, recommendation, promotion, and demotion with actor, reason, and timestamp.

#### FR-06 — Deterministic assessment — Must

- Evaluate only stored, versioned facts; never call provider APIs during evaluation.
- Satisfy a fact requirement only when the exact fact key, acceptable evidence class, freshness, confidence, corroboration, and scope conditions declared by the policy are met.
- Retain policy version, snapshot, exact inputs, decision, missing evidence, and reason.
- Support deterministic replay.
- Preserve the following states:

```text
PASS | FAIL | NO_DECISION | NOT_APPLICABLE |
NO_RESOURCE | DISABLED | ERROR | STALE
```

- Never return PASS from incomplete, missing, inaccessible, error, or stale required evidence.
- Every `NO_DECISION` must name the missing fact, scope, capability, or owning accuracy requirement.

#### FR-07 — Inventory-to-assessment reconciliation — Must

After each complete run:

1. classify every active artifact;
2. resolve all applicable published policies, regardless of tenant selection;
3. create exactly one current decision or explicit non-evaluated reconciliation state per applicable policy and subject;
4. identify silent omissions and catalog drift;
5. reconcile expected and actual counts by technology, family, type, capability, and policy;
6. expose actionable coverage-gap objects.

Required reconciliation states:

```text
ASSESSED | NO_POLICY_COVERAGE | UNKNOWN_TECHNOLOGY |
AMBIGUOUS_TECHNOLOGY | MISSING_FACTS | INCOMPLETE_SCOPE |
STALE_EVIDENCE | UNSUPPORTED | UNRESOLVED_OWNER
```

Each gap must support reason, owner, age, action, and SLA.

#### FR-08 — Host finding workflow — Must

- Create new AI results directly in the canonical host finding workflow.
- Support artifact, AI system, relationship, and linked asset subjects.
- Use a stable tenant-bound fingerprint.
- Open on new FAIL only when policy selection and workflow-graduation rules permit it; update on repeated FAIL and reopen after recurrence.
- Close only after a complete later assessment confirms PASS or the affected subject is intentionally retired.
- Never close on `NO_DECISION`, `STALE`, `ERROR`, partial discovery, or connector failure.
- Reuse ownership, assignment, SLA, suppression, exception, notification, ticket, evidence, and audit services.
- Reset existing demo AI policy, evaluation, finding, and review data; no history migration is required.

Workflow classes:

```text
POSTURE_FINDING
Observed or otherwise policy-accepted configuration failure; may create an owner-facing host finding.

EXPOSURE_HYPOTHESIS
Potential cross-domain path that does not meet validated-exposure evidence requirements; analyst-visible, but no automatic owner SLA or ticket.

VALIDATED_EXPOSURE
Meets correlation-specific fact, evidence, confidence, freshness, temporal-validity, and scope requirements; may create an SLA-bound host finding and ticket.
```

- Define graduation rules per policy or correlation version, not through one global confidence threshold.
- Keep high-impact, low-confidence hypotheses visible in analyst triage.
- Recompute workflow class whenever required evidence, confidence, freshness, scope, or path validity changes.
- Demote a validated exposure when its validating evidence becomes stale or no longer qualifies. Staleness alone must never close the exposure or imply remediation.
- Resolve or close only when fresh evidence proves the condition no longer exists or the required path is broken.

#### FR-09 — Coverage and framework reporting — Must

- Display PASS and FAIL separately from every unevaluated state.
- Publish exact denominators.
- Report coverage by technology, provider, family, account, environment, owner, policy, and framework.
- Generate or validate the catalog from a bounded resource-family × control-dimension coverage matrix.
- Use OWASP LLM Top 10 as the first mapping.
- Clearly label framework mappings as evidence relationships, not certification or proof of regulatory conformity.
- Current tenant posture must use a composite coverage epoch formed from the latest successfully completed
  authoritative scope for every retained provider/account/region/family. It must not select one tenant-global
  latest provider run. Preserve the contributing source run and manifest on every materialized candidate so
  historical replay remains immutable and independently addressable.
- Materialize the current expected artifact × applicable published-policy candidate set once per coverage epoch;
  coverage, readiness, reconciliation, setup actions, and dimensional reads must consume that same denominator.

At minimum, publish these separate denominator fields:

```text
applicablePublished
publishedPolicies
policiesWithResources
noResourcePolicies
expectedAssessments
recordedAssessments
missingAssessments
required
tenantEnabled
tenantDisabled
preview
evidenceReady
evaluatedPass
evaluatedFail
noDecision
notApplicable
stale
unsupported
applicableNotEnabled
decisionReachabilityPercent
ownerFacingDecisionReachabilityPercent
```

- Calculate security coverage over all applicable published policies, including preview and tenant-disabled policies as disclosed categories.
- Derive `expectedAssessments` from the immutable run's artifact × applicable latest-published-policy candidate
  set. Never use emitted assessment rows as the denominator.
- Expose every candidate artifact/policy pair in a detail ledger. A missing row is an explicit
  `MISSING_ASSESSMENT` coverage gap, distinct from an artifact with `NO_POLICY_COVERAGE`.
- Report first-run utility separately from security coverage; policy selection must never be used to shrink the security denominator.

#### FR-10 — Identity, data, and reachability context — Must for exposure release

Consume or derive:

- human, workload, service, and delegated identities;
- assumed roles, effective privileges, trust, secret access, and consequential actions;
- configured public exposure and separately verified reachability;
- sensitive-data presence, permitted use, and effective access;
- authentication, approval, sandbox, and network boundaries;
- model, tool, retrieval, and data relationships.

AI Grid consumes host CIEM, DSPM, ASM, asset, and ownership facts first. It builds only the thinnest missing AI-attribution or computation layer.

#### FR-11 — Exposure correlation — Must for exposure release

- Build on the existing typed relationship store and PostgreSQL bounded traversal.
- Version and govern correlation definitions.
- Enforce allowed nodes and edges, maximum depth and fan-out, temporal validity, confidence aggregation, path deduplication, and negative examples.
- Show entry point, impact, path, evidence, confidence, temporal validity, root cause, and breakpoint.
- Recompute only affected bounded subgraphs.
- Avoid duplicate tickets when one root cause affects multiple systems or paths.

Initial exposure templates:

1. Externally reachable AI application + inadequate authentication + sensitive-data access.
2. Tool-enabled agent + excessive effective privilege + secret or consequential-action access.
3. Untrusted input or retrieval path + autonomous execution + inadequate guardrail, isolation, or approval.

#### FR-12 — Risk and prioritization — Should

- Keep impact, exploitability, reachability, criticality, blast radius, confidence, and freshness separate.
- Explain priority and breakpoint selection.
- Avoid a single opaque organization-wide score.
- Use “recommended high-leverage breakpoint,” not “optimal,” until optimization accuracy is validated.

#### FR-13 — Configuration and control effectiveness — Future assurance release

Store configuration separately from effectiveness evidence.

Configuration state:

```text
PRESENT | NOT_PRESENT | UNKNOWN | NOT_APPLICABLE
```

Effectiveness evidence:

```text
UNTESTED | TEST_PASSED | TEST_FAILED | OBSERVED_EFFECTIVE |
OBSERVED_BYPASS | STALE | NOT_OBSERVABLE
```

Define a vendor-neutral runtime control-decision contract before building native runtime enforcement. Raw prompt and response content must be excluded by default.

#### FR-14 — SOC event contract — Future assurance release

Export exposure and runtime-control changes with system, owner, path, policy/correlation/evidence versions, confidence, freshness, root cause, breakpoint, fingerprint, restricted-evidence link, and workflow state.

Initial SOC scope is an event contract and bidirectional status integration. A full AI incident object, forensic timeline, threat hunting, and response playbooks are later requirements.

#### FR-15 — Platform operations — Must

- Preserve current job fairness, provider isolation, retries, sanitization, concurrency controls, and backpressure.
- Use idempotent processing and transactional outbox events for new stages.
- Support replay without repeating provider calls.
- Provide stage metrics, dead-letter visibility, kill switches, audit, and drift detection.
- Keep every tenant table under forced RLS and every tenant operation under explicit tenant context.

#### FR-16 — Minimum Context Pack — Must for managed-AI foundation

Provide useful baseline context when host CIEM, DSPM, or ASM signals are unavailable, without claiming those full capabilities.

Baseline context may include:

- directly attached policies, wildcard actions, trust conditions, and obvious administrative privilege indicators;
- configured public access, authentication settings, network controls, and private endpoints;
- linked data sources, customer classification tags, encryption, and public-access configuration;
- ownership tags, account/subscription ownership, host-asset links, and service-catalog mappings.

Mandated distinctions include:

```text
network.public_access_configured       != network.internet_reachability_verified
identity.wildcard_permission_observed  != identity.effective_admin_access_derived
data.source_linked                     != data.sensitive_content_confirmed
owner.tag_candidate                    != owner.confirmed
```

- Use the baseline context for posture findings or exposure hypotheses only where the relevant policy permits it.
- Never allow a proxy fact to satisfy a requirement for a different verified fact key.
- Display proxy provenance, evidence class, confidence, freshness, and next step.
- A direct provider or graph relationship may produce `data.source_linked` with its derivation inputs, but must
  not produce `data.sensitive_content_confirmed` without an approved classification source.
- Persist policy evidence readiness separately from tenant selection using `READY`, `PARTIAL`, `BLOCKED`,
  `NOT_APPLICABLE`, and `NO_RESOURCES`. Readiness must not mutate REQUIRED/ENABLED/PREVIEW/DISABLED state.

#### FR-17 — First-run value and time to value — Must

On the first complete connector run:

- classify or explicitly reconcile every supported artifact;
- produce useful posture decisions from decision-ready controls;
- present prioritized setup actions for missing permissions and evidence;
- avoid overwhelming the user with an undifferentiated wall of `NO_DECISION` results;
- report time to first inventory, first decision, first owner-routed finding, and first exposure hypothesis.
- Project missing assessments, permissions, facts, freshness, unsupported evidence, confidence, classification,
  coverage, and ownership gaps into a structured setup-action queue ordered by operational priority.
- Bind baseline-run telemetry to the connector identifier retained with the immutable run.
- Persist expected/missing assessments, full decision reachability, REQUIRED/ENABLED decision reachability,
  target percentage, target result, and the first-event timestamps. Missing assessments remain in the relevant
  denominator; recorded `NOT_APPLICABLE` subjects do not.

Initial target:

> At least 80% of `REQUIRED` and `ENABLED` applicable policies reach PASS or FAIL in certified answer-key environments on the first complete run, while 100% of applicable published policies remain visible in the full coverage denominator.

The threshold must be recalibrated from answer-key and design-partner evidence before general availability. It may not be improved by disabling difficult policies or excluding missing-evidence states from the security denominator.

#### FR-18 — Answer-key environments — Must

Treat Bedrock and Azure answer-key environments as staffed product infrastructure, not disposable test fixtures.

Each certified resource family must maintain:

- secure and insecure resource variants;
- expected inventory, technologies, capabilities, facts, relationships, applicability, decisions, findings, gaps, and closure transitions;
- complete, partial, denied, throttled, stale, unsupported, deleted, renamed, split, merge, and rediscovered cases as relevant;
- explicit proxy-versus-verified fact cases;
- expected first-run, replay, storage, provider-call, and processing-cost measurements;
- versioned labels, provider API versions, test data, change history, and named owners.

Required operating model:

- named engineering owner and security reviewer;
- scheduled provider and schema drift review;
- response process for provider API or product changes;
- environment cost budget and cleanup controls;
- provenance-bind observed outputs to immutable platform execution artifacts (tenant/run/assessment identifiers
  and decision fingerprints) and validate that binding server-side; caller-supplied JSON alone is an external
  attestation, not proof that the pipeline produced the result;
- release blocking when the answer key is stale, incomplete, or cannot support the claimed metric.

#### FR-19 — Precision-review governance — Must

- Define the review population and use stratified samples by provider, family, policy/correlation, severity, and outcome.
- Record minimum sample size and confidence limits with every precision claim.
- Require two independent reviewers for high- and critical-severity policy or exposure releases.
- Adjudicate disagreements through a named security reviewer.
- Store versioned labels, rationale, evidence references, reviewer identities, and adjudication outcome.
- Gate a precision claim on the configured confidence-interval lower bound meeting the threshold, not merely
  on the point estimate.
- Do not publish a precision percentage when the sample is too small or biased to support it.
- Measure discovery recall separately from finding precision using certified answer-key inventory; negative
  precision labels do not by themselves constitute the discovery-recall gate.
- Re-run review after material changes to discovery, normalization, facts, applicability, policy logic, correlation, or evidence rendering.

#### FR-20 — Evidence and scan economics — Must

- Use tenant-scoped content-addressed snapshot bodies and immutable snapshot manifests so unchanged evidence is not stored repeatedly.
- Do not use cross-tenant content deduplication. Sensitive content identifiers must not reveal whether another tenant holds the same evidence.
- Support incremental discovery, no-change detection, and configurable scan cadence by provider family, environment, and criticality.
- Define hot, archive, restricted-evidence, deletion, legal-hold, and replay retention classes.
- Measure provider API calls, bytes collected, unique snapshot bytes, retained bytes, fact/evaluation volume, graph recomputation, and processing time per tenant and run.
- Provide per-tenant budgets, alerts, throttling, and administrative visibility.
- Keep retention and cost controls from deleting evidence still required by an active finding, exception, legal hold, or replay commitment.

#### FR-21 — Confidence calibration — Must wherever confidence is used

- Confidence is owned by a named derivation method and version, not entered as a free-floating score.
- Define what the score predicts, its valid population, features/inputs, calibration dataset, error behavior, and expiry.
- Calibrate and validate each method within its evidence class using answer-key or independently reviewed production evidence.
- Do not assume equal numeric confidence from different evidence classes or derivation methods is comparable.
- A policy may set a confidence threshold only for named evidence classes or derivation methods with approved calibration.
- Define explicit aggregation rules when several confidence-bearing facts contribute to an exposure.
- Show method, version, calibration status, confidence, and limitations to analysts.

### 7.3 Processing model

```text
Cloud collectors
→ ObservationEnvelopeV1
→ canonical artifact identity
→ immutable snapshot
→ technology and capability classification
→ observed facts
→ derived facts
→ capability-first policy applicability
→ deterministic assessment
→ inventory reconciliation
→ AI-system graph
→ exposure correlation
→ workflow graduation and demotion
→ host finding reconciliation
→ workflow and verified reassessment
```

Runtime, source, MLOps, SaaS, and behavioral events join through versioned contracts in later releases.

### 7.4 Architecture decisions

- Evolve the existing AI Security bounded context; preserve secure collection, tenant isolation, and job controls.
- Reset demo policy and finding data rather than building history migration.
- Use forward-only database migrations.
- Use PostgreSQL for the first bounded graph implementation.
- Keep REST; do not introduce GraphQL.
- Add new APIs additively and keep existing `/api/ai-security/**` routes only while shipped UI clients require them.
- Use a small typed JSON predicate format with an operator allowlist, bounded depth, and no executable policy code.
- Treat a graph database as a measured future decision, not a prerequisite.

### 7.5 Initial APIs

```text
GET /api/ai-systems
GET /api/ai-systems/{id}
GET /api/ai-systems/{id}/graph
GET /api/ai-systems/{id}/facts
GET /api/ai-systems/{id}/findings
GET /api/ai-technologies
GET /api/ai-coverage
GET /api/ai-coverage/technologies
GET /api/ai-assessment-runs
GET /api/ai-policies
GET /api/ai-policies/{id}/versions
GET /api/ai-exposures
GET /api/ai-exposures/{id}
```

### 7.6 Non-functional requirements

#### Security

- Forced RLS and tenant context for all tenant data and processing.
- No cross-tenant cache entries, graph traversal, outbox payloads, replay, exports, or evidence references.
- Read-only least-privileged connectors.
- Encryption and explicit authorization for restricted evidence.
- No credentials, tokens, raw prompts, or provider secrets in logs or ordinary facts.
- Independent policy publication approval and complete catalog audit.

#### Reliability

- At-least-once delivery with idempotent consumers.
- Deterministic replay.
- No closure after incomplete or failed discovery.
- Safe retries, dead-letter recovery, and provider/tenant/stage kill switches.

#### Performance

- Cursor-based APIs for large inventory and findings.
- Incremental discovery and affected-subgraph recomputation.
- Bounded policy and graph execution.
- Establish PostgreSQL graph SLOs before considering another database.

#### Explainability

- Every FAIL and exposure shows its facts, evidence, versions, reason, and remediation.
- Every unknown or non-evaluated state shows the missing input, owner, and next action.
- Every derived fact and heuristic system membership shows inputs, confidence, version, and expiry.

### 7.7 Out of scope for foundation and exposure releases

- Full inline prompt or response enforcement.
- A native AI firewall.
- Tenant-authored policies or policy query builder.
- Full CIEM, DSPM, ASM, CSPM, SIEM, SOAR, MLOps, or GRC replacement.
- Unrestricted autonomous red teaming.
- Automated cloud-resource mutation.
- Full model/package/source supply-chain scanning.
- Full model-risk and regulatory-case management.
- Behavioral-effectiveness claims from configuration alone.
- GraphQL or a dedicated graph database.
- Preservation of demo AI policy and finding data.
- A commitment to ship all 62 candidate policies.
- A single opaque AI risk or compliance score.

### 7.8 Assumptions to validate

1. Customers value accurate evidence and exposure context more than catalog size.
2. Host finding, ownership, SLA, ticket, asset, CIEM, DSPM, and reachability capabilities expose usable contracts.
3. Bedrock and Azure provide enough variety to prove provider-neutral artifact, fact, applicability, and graph contracts.
4. PostgreSQL supports initial bounded graph workloads at acceptable latency.
5. Design partners accept explicit unknown and untested states even when dashboards appear less green.
6. High-confidence AI-system membership can be produced using provider IDs, relationships, tags, ownership, and user confirmation.
7. Runtime providers can supply normalized control decisions without storing raw prompts by default.

---

## 8. Release

Releases are gated by evidence and acceptance criteria, not calendar dates.

### Release 0 — Foundation vertical slice

**Goal:** Prove the complete architecture using one narrow Bedrock scenario.

**Market position:** AI Grid Foundation preview—not yet a general posture or Exposure Management claim.

**Scenario:** A Bedrock agent system with guardrail evidence. The first policy evaluates guardrail strength against a minimum approved level and maps to the appropriate OWASP control category.

Includes:

- one connector path and complete scope;
- one canonical AI system containing at least the Bedrock agent and guardrail artifacts;
- one immutable snapshot;
- tenant-scoped content-addressed snapshot storage and a no-change replay case;
- a small typed fact set;
- distinct configured and verified fact keys with provenance and evidence-class enforcement;
- technology and capability classification;
- one governed published policy;
- capability-first applicability;
- one explicit unknown case;
- one host finding;
- one coverage-gap object;
- first-run time-to-value instrumentation;
- provider-call, processing, storage, retention, and replay-cost instrumentation;
- owned answer-key environment and initial precision-review procedure;
- replay and verified closure;
- RLS, evidence authorization, and lifecycle tests;
- reset of demo AI policies, settings, evaluations, findings, and reviews.

Exit criteria:

- identical inputs and versions produce identical decisions and fingerprints;
- incomplete scope and missing facts cannot PASS or close;
- cross-tenant negative tests pass;
- the finding opens, updates, assigns, suppresses, closes, recurs, and reopens correctly;
- the decision can be replayed without provider access;
- unchanged evidence reuses its tenant-scoped content body without losing immutable snapshot lineage;
- remediation closes the finding only after complete reassessment;
- first-run inventory, decision, gap, and finding timings are recorded;
- the answer key, reviewers, labels, precision result, and economics baseline are versioned and reproducible;
- the existing supported connector and inventory paths remain operational.

### Release 1 — Managed-AI foundation

**Goal:** Deliver trustworthy Bedrock and Azure posture, inventory, and coverage integrity.

**Market position:** AI Grid Foundation—managed-AI posture and coverage integrity.

Includes:

- certified Bedrock and ARM-managed Azure AI families;
- approved artifact and technology taxonomy;
- immutable snapshot and normalized-fact coverage;
- selected policies from the bounded coverage matrix;
- policy governance with required, enabled, preview, and disabled tenant selection separated from evidence readiness;
- Minimum Context Pack with mandatory proxy-versus-verified fact separation;
- inventory-to-assessment reconciliation;
- coverage-gap workflow;
- owner states and confidence;
- OWASP reporting;
- canonical host findings;
- connector and pipeline operations UI;
- staffed Bedrock and Azure answer-key environments;
- precision-review governance;
- retention classes, tenant budgets, economics alerts, and calibrated first-run reporting.

Exit criteria:

- discovery recall, policy precision, decision completeness, determinism, and isolation Key Results pass;
- every supported artifact is assessed or explicitly reconciled;
- no unavailable state appears as secure;
- preview and disabled applicable policies remain in the disclosed denominator;
- first-run utility meets the calibrated target without shrinking security coverage;
- no policy is released ahead of its facts without an owned `NO_DECISION` requirement;
- confidence thresholds are used only for approved, calibrated methods and evidence classes;
- per-family provider-call, processing, storage, retention, and graph-cost budgets and alerts are operating;
- high/critical policy precision passes the approved sample, dual-review, and adjudication process;
- design-partner soak passes for each enabled provider slice.
- the aggregate R1 readiness gate derives answer-key and per-policy governance from platform records, accepts
  only named expiring operational evidence for external gates, and records an immutable gate snapshot with the
  release decision; external attestations cannot override platform-derived gates.

At this stage, AI Grid is a production AI security posture and coverage-integrity product. It must not yet claim mature exposure management.

### Release 2 — AI Security Exposure Management

**Goal:** Earn the exposure-management claim.

**Market position:** AI Grid Exposure—validated paths, accountable remediation, and verified closure.

Includes:

- AI-system membership confidence and split/merge lifecycle;
- confirmed/inferred/candidate/unowned ownership;
- effective identity and delegated authority;
- sensitive-data attribution;
- configured and verified reachability;
- temporal relationship validity;
- three validated exposure templates;
- posture finding, exposure hypothesis, and validated exposure workflow classes with bidirectional freshness-gated graduation;
- root-cause and high-leverage breakpoint recommendations;
- exposure deduplication and compression;
- workflow, ticketing, reassessment, verified closure, reopen, and recurrence.

Exit criteria:

- all three templates meet their reviewed precision thresholds;
- analysts can trace every exposure from entry point to impact;
- fixing a breakpoint closes the path only after complete reassessment;
- stale qualifying evidence demotes validation without falsely closing the exposure;
- proxy-based hypotheses remain visible without automatically creating owner-facing SLA tickets;
- shared dependencies do not cause uncontrolled ticket duplication;
- high-priority exposure ownership and SLA targets pass.

### Release 3 — AI Assurance integration

**Goal:** Add runtime and behavioral evidence without becoming an inline firewall.

**Market position:** AI Grid Assurance—testing and production evidence about connected control effectiveness.

Includes:

- vendor-neutral runtime control-decision contract;
- guardrail, model-call, retrieval, and tool-action event ingestion;
- OpenTelemetry correlation where available;
- separate configuration and effectiveness evidence states;
- assurance expiry and drift;
- SIEM exposure-event contract and bidirectional status;
- imported approved behavioral-test evidence.

### Release 4 — Agent, MCP, source, and supply-chain expansion

Recommended order:

1. Source and CI discovery.
2. MCP servers and tools.
3. Agent identities, delegated authority, approvals, and action telemetry.
4. SaaS AI administration.
5. Model, package, prompt, container, dataset, and deployment lineage.
6. Direct model-provider integrations.
7. Self-hosted AI and Kubernetes.
8. GCP managed AI.

Each plane must adopt the same identity, snapshot, fact, evidence, applicability, coverage, graph, finding, and tenant-security contracts.

### Release 5 — Continuous assurance

Includes:

- event-driven incremental assessment;
- drift and recurrence analytics;
- exposure breakpoint leverage measurement;
- approved scoped adversarial-test orchestration;
- extended NIST AI RMF, MITRE ATLAS, ISO/IEC 42001, and regulatory evidence packages;
- carefully approved low-risk remediation workflows with permission, approval, rollback, and blast-radius controls.

### Rollout model

```text
answer-key fixtures
→ automated tests
→ internal tenant
→ provider-slice canary
→ design partner
→ limited availability
→ general availability
```

### Release blockers

Any release is blocked when:

- tenant isolation cannot be demonstrated;
- missing or incomplete evidence can produce PASS or closure;
- supported inventory can disappear without a reconciliation state;
- policy or correlation execution is unbounded;
- evidence authorization or redaction is incomplete;
- finding lifecycle or replay is nondeterministic;
- precision or discovery gates are not met;
- product claims exceed the evidence actually collected;
- a proxy fact can satisfy a requirement for a materially different verified claim;
- tenant policy selection can change silently because evidence readiness changes;
- preview or tenant-disabled applicable policies disappear from the disclosed denominator;
- an uncalibrated confidence value controls workflow graduation;
- a stale validated exposure remains represented as currently validated;
- first-run utility can be improved by hiding applicable controls;
- required answer-key, precision-review, or economics evidence is missing for the release.

---

## Appendix A — Final scope summary

| Horizon | Product capability | Included |
|---|---|---|
| Release 0 | One complete Bedrock evidence-to-closure slice | Yes |
| Release 1 | Bedrock + Azure posture and coverage integrity | Yes |
| Release 2 | Identity/data/reachability exposure correlation and verified closure | Yes |
| Release 3 | Runtime and behavioral evidence ingestion | Later |
| Release 4 | Agent/MCP/source/supply-chain and broader providers | Later |
| Release 5 | Continuous validation and carefully governed remediation | Later |

## Appendix B — Authoritative supporting documents

- `AI-GRID-DECISION-AUDIT.md`
- `CLAUDE.md`
- `known-limitations.md`
- `designs/2026-08-01-coverage-matrix.md`
- `designs/2026-08-01-bedrock-azure-policy-catalog.md`
- `designs/2026-08-01-discovery-prerequisite-epics.md`
- `designs/2026-07-31-phase2-computation-plan.md`
