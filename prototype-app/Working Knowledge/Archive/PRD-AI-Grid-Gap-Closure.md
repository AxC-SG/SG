# PRD: AI Grid gap closure for customer demos and first pilots

**Status:** Draft requirements for review · **Date:** 5 October 2026  
**Stage:** Customer demos; customer acceptance and production readiness are unverified.  
**Scope:** Product requirements, not authorization to collect customer data or activate paused policies.

## 1. Summary

Make AI Grid's existing inventory, posture, exposure and workflow capabilities deliver one complete customer outcome: discover an AI system, explain an evidenced risk, assign treatment and verify the fix. Then add approved-versus-observed comparison and reusable evidence packs. Broad Wiz feature parity is a later, demand-led expansion rather than the acceptance target for this release.

**Demo promise:** “Understand which AI systems are deployed, what they can reach, which risks need attention, who owns them and what evidence confirms resolution.”

**Next proposition, after implementation and qualification:** “Compare deployed AI with what your organisation approved and reopen review when it changes.”

## 2. Contacts and decision ownership

Names remain to be assigned; these are responsibilities, not assumed appointments.

| Role | Accountable decision or deliverable |
|---|---|
| Product owner | Target buyer/workflow, demo scope, control selection, acceptance and scope changes |
| Engineering lead | Implementation inventory, dependencies, estimates and delivery |
| Provider/platform owner | Permissions, reference estate, service availability and collector qualification |
| Security/evidence reviewer | Evidence contracts, control precision, privacy and claim review |
| Customer approval owner | Business purpose, permitted scope, approval and expiry authority |
| Demo/customer lead | Script, buyer feedback, pilot agreement and value measurement |
| Operations owner | Onboarding, isolation, deployment, support and production gates |

## 3. Background and current coverage

The supplied competitor image describes Wiz Code, Wiz Cloud, Wiz Defend and AI-SPM as one lifecycle, connecting discovery/scanning to a security graph, risk prioritisation and remediation. Provider logos in the image are integrations, not additional competitors. AI Grid overlaps with important parts of that story but does not have equivalent breadth or proven runtime protection.

Current baseline comes from repository documentation and source spot-checks. No deployed tenant or customer pilot was inspected. Existing user changes in the workspace are not assumed released.

| Area | Existing foundation | Remaining requirement |
|---|---|---|
| Discovery | AWS Bedrock/AgentCore/SageMaker, Azure AI/Foundry and Copilot Studio collectors | Independent completeness qualification, failure handling and actionable health |
| Inventory/context | Systems, versions, models, tools, prompts, identities, relationships and ownership | A coherent customer workflow and reliable served-version context |
| AI-BOM | Ingestion, declaration projection, reviewed deployment linking and software-vulnerability links | Product qualification, ambiguity handling and accurate declaration/observation labels |
| Static controls | Latest roadmap records 159 distinct policies: 76 GA, 83 paused | A customer-qualified 5–8-control pack; counts do not prove tenant coverage |
| Exposure | Bounded evidence-backed correlations and freshness handling | Clear explanation of evidence, uncertainty, impact and treatment |
| Workflow | Canonical findings, ownership, SLA/audit and ServiceNow integration | Demonstrated fix verification, recurrence handling and useful evidence packs |
| Approvals | Version manifests, allowlists and reviewed resource mappings | Complete customer purpose/scope/approver/expiry register and comparison |
| Runtime | Ingestion, timelines, deterministic evaluation and nine preview/paused packages | Authoritative source evidence, certification and live qualification before activation |

Macie/Purview inputs consume existing classification results; AI Grid does not perform native sensitive-data scanning. Static exposure does not prove execution or exploitation. The reviewed baseline does not establish native malicious-model scanning, full code/IaC/IDE scanning, universal provider discovery or inline agent prevention.

### Relationship to existing requirements

The [Discovery health PRD](../../Other%20Docs/Archive/Archived%20final%20plans/1.1_Req1_PRD_Discovery-health.md) remains the detailed specification for AWS, Azure and Copilot qualification. This umbrella PRD does not reduce its three-provider scope, change thresholds or declare completion. A first demo can use one explicitly named provider; a combined three-provider release still needs all contracted provider boundaries to pass. Do not duplicate its reference-comparison engine or gap queue.

The [prioritised roadmap](../../Other%20Docs/Archive/Archived%20final%20plans/1_ai-grid-prioritized-roadmap-2026-2029.md) supplies implementation and release boundaries. Recheck package/deployment state before committing a capability to a customer.

## 4. Objective and success measures

**Objective:** Convert an inventory/posture demo into a reviewer-accepted, repeatable AI risk decision and treatment workflow.

Proposed acceptance targets apply at their named milestone, rather than implying achieved results:

| Milestone | Required measurable result |
|---|---|
| Demo release | One approved script; three evidence-supported risk scenarios; one benign and one missing/stale-evidence case; one complete finding-to-verified-fix scenario |
| Repeatability | Complete the script twice on resettable test data, without direct database edits during the walkthrough; record build, scope, results and discrepancies |
| Discovery qualification | Meet the linked PRD's 100% stable-fixture and ≥95% independent-reference coverage requirements per provider/non-empty contracted slice and separate 14-day windows |
| Control qualification | Every selected control has positive, benign, missing, stale and permission-denied cases, source/evidence contracts and independent review; normal production precision gates apply |
| Approval comparison | Demonstrate matched, undeclared, unobserved and conflicting states, plus expired/revoked approval and ambiguous identity handling |
| Pilot acceptance | Customer reviewer accepts the scoped evidence pack, three agreed scenarios and one fresh verified fix; record acceptance explicitly |
| Value measurement | Record baseline and AI Grid preparation/investigation effort for two comparable reviews; report observed results before setting improvement claims |

Do not average failing slices into a passing total. Missing/stale evidence cannot become PASS. Pilot sign-off, paid conversion and measured savings are customer outcomes, not consequences of code completion.

## 5. Market segments and users

Initial segment: organisations adopting managed AI agents that need to answer “what is running, what can it reach, who approved it and who will address its risks?” Select a named design partner and workflow before broadening scope.

| User | Job to be completed |
|---|---|
| Security analyst | Understand an evidenced risk and choose a treatment |
| AI/application owner | Identify the affected deployed version and fix the configuration |
| Cloud/platform owner | Establish access, resource coverage and collection health |
| Approval/review owner | Compare approved purpose/scope with observed deployment and review changes |
| Security leader | Review unresolved risk, accountable treatment and evidence limitations |

Assume a small delivery team until staffing is confirmed. Existing catalogues and platform services must be reused. Choose provider order from customer demand, service availability and evidence feasibility.

## 6. Value proposition

Deliver an understandable chain from deployed agent to model/tool/identity/data, from that context to an evidenced risk, and from the risk to accountable treatment and verified resolution. Make observation gaps visible so reviewers can distinguish a supported conclusion from an unanswered question.

Wiz already markets inventory, AI-BOM, graphs and workflows; these alone are not unique claims. Approved-versus-observed comparison and reviewer-ready treatment evidence are differentiation hypotheses to validate with buyers. AI Grid should not imply Wiz lacks those capabilities without separate evidence.

## 7. Solution and detailed requirements

### 7.1 User journey

1. Open the scoped AI estate and see provider, source, freshness and coverage limitations.
2. Select an application/agent and its served version; inspect connected tools, identities and data.
3. Open a prioritised issue; understand evidence, impact, uncertainty and recommended treatment.
4. Assign an accountable owner, due date or expiring exception.
5. Reassess after a change; display fresh verification or keep the issue unresolved.
6. Export the review evidence. In the next increment, compare the estate with the customer approval register and review drift.

### 7.2 Prioritised functional requirements

**P0:** Required for a credible next-demo release. **P1:** Next increments for pilot value. **P2:** Conditional expansion; discovery work already contracted in the linked PRD retains that commitment.

#### DEM-01 — Repeatable demo experience · P0 · Productise existing capabilities

- Select one named provider/workflow and a compact estate with an agent, authoritative served-version context, model, tool, identity and linked data where supported.
- Provide three scenarios selected only after checking source facts and predicates: candidates include a guardrail baseline gap, consequential tool privilege and an MCP/sensitive-data exposure. Substitute unsupported candidates transparently.
- Show safe configuration and unavailable evidence alongside risk scenarios. Label source/state at record level: provider observation, customer declaration, seeded fixture or preview.
- Supply a reset procedure, script, expected results and limitations. Demo seeding must remain restricted to demo/test tenants.

**Acceptance:** Two recorded rehearsals pass the approved script. Each displayed finding resolves to its exact evidence/control version. Reset is tenant-scoped and cannot seed a customer production tenant. Seeded data cannot qualify customer controls or discovery.

#### DIS-01 — Dependable discovery and actionable health · P0 · Qualify and extend

- Implement and qualify the linked Discovery health PRD, including independent references, pagination, permission gaps, stale evidence, deletion semantics and the gap queue.
- Show discovery coverage separately from policy coverage. Without a qualified reference, show “coverage unverified”.
- Link unsupported/inaccessible/failed scopes to their affected conclusions and next actions; do not use absence as evidence of non-use.

**Acceptance:** The chosen demo boundary passes its approved test scenarios. Provider/customer qualification follows the linked PRD's complete gates; a demo pass cannot substitute for them.

#### CTL-01 — Small qualified control pack · P0 · Qualify existing policies

- Select 5–8 controls across the agreed workflow, not automatically per provider. Document policy/version, target types, relationships, facts, authority, permissions and freshness.
- Reuse governed evaluation/distribution. Add policies only for an agreed valuable gap with a supportable evidence contract.
- Keep disabled, preview, not applicable, unknown and failed results distinct. Include why a control could not run and how to obtain evidence.

**Acceptance:** Each selected control passes positive, benign, missing, stale and denied-evidence cases. Release evidence includes answer keys, independent review and the normal configured precision/distribution gates. Demo approval does not enable a customer control.

#### EXP-01 — Explainable risk and bounded exposure · P0 · Productise existing graph

- Show the affected deployed version, relationship path, finding/control, supporting source/time and evidence state.
- Distinguish configured, reachable, activity observed and validated exposure. Explain unverified steps and freshness-driven demotion.
- Show impact and the specific configuration/relationship to change. Do not claim full effective permissions from wildcard indicators or actual tool use from discovery.
- Explain priority using relevant factors and missing context; avoid a score that hides unknowns.

**Acceptance:** A reviewer traces three scenarios to supporting facts and the proposed treatment. Expiring a required fact removes validated status and changes the explanation. No synthetic relationship satisfies a validation contract.

#### FIX-01 — Accountable treatment and fresh verification · P0 · Qualify and extend workflow

- Reuse canonical findings, assignments, audit and SLA behaviour. Support owner, due date, treatment, reason and expiring risk acceptance/exception.
- Use one existing workflow destination when needed. External ticket state remains distinct from technical resolution.
- Reassess the relevant resource/control after treatment. Record verification time, scan, policy version and changed evidence; report blocked verification when collection fails.
- Reopen recurring failures and expired exceptions through governed lifecycle rules. Repeated sync/retries must not create duplicate findings or tickets.

**Acceptance:** Demonstrate issue → assignment → change → fresh reassessment → verified resolution. Ticket closure alone leaves verification pending; failed/stale reassessment cannot resolve the issue. Reintroducing the fault reopens or links a deduplicated recurrence with history.

#### APR-01 — Customer approval register and comparison · P1 · New capability

- Import a bounded CSV or narrow API with customer application ID, owner, purpose, environment, provider/region/data scope, approver, approval state, effective time and expiry. Define optional model/version/tool restrictions where comparable observations exist.
- Validate rows before commit and provide actionable errors. Version revisions, preserve provenance, and audit approval/revocation; only authorised approval owners can change approval state.
- Match immutable provider/resource identifiers within tenant and scope. Route name-only, ambiguous and conflicting matches for review; AI-BOM linking may assist but is not approval authority.
- Show four comparison states: matched, observed but undeclared, declared but unobserved and conflicting. Show expiry/revocation separately; incomplete discovery must qualify any “unobserved” conclusion.
- A matched identity does not by itself mean approved: approval must be active and observed comparable attributes must satisfy its permitted scope. Non-comparable fields remain unknown.

**Acceptance:** Fixtures demonstrate all four states, duplicate-name ambiguity, partial discovery, scope violation, expiry and revocation. Declaration cannot overwrite provider facts. Re-import updates the same scoped records without destroying approval history; approval writes and exports obey tenant/role controls.

#### EVD-01 — Reviewer-ready evidence pack · P1 · Extend existing export

- Reuse inventory CSV, snapshot, assessment and finding APIs. Add a human-readable pack and structured export with application/scope IDs, observations/source times, control versions/results, evidence references, owner, treatment, exceptions and verification.
- Include collection limitations, unknowns, comparison state where available and a stable pack ID/time. Historical packs remain reproducible or retain an immutable evidence manifest.
- Exclude prompts, responses, tool arguments, credentials and raw sensitive document content. Apply export authorisation and retention rules.

**Acceptance:** Reviewer reproduces selected conclusions from the pack; scoped totals reconcile with the UI. A later scan cannot silently rewrite a prior pack. Cross-tenant export tests fail safely and privacy fixtures remain excluded.

#### BOM-01 — AI-BOM qualification · P1 when needed by the pilot · Qualify existing integration

- Qualify replacement/source lifecycle, model/dataset/software typing, projection, reviewed links, ambiguous/unlinked setup actions and inherited vulnerability applicability.
- Preserve the difference between declaration, observed deployment and approval. Keep paused AI-BOM-dependent policies paused until separately qualified.

**Acceptance:** Updating a BOM revision retains history, refreshes current declarations and reconciles dependent links/results. An ambiguous deployment stays unresolved; software applicability uncertainty cannot become a confirmed affected model.

#### DRF-01 — Approval and definition drift · P1 after APR-01 · Extend foundations

- Reopen review on supported changes to served version, tool/identity/data scope, definition digest, owner or approval expiry/revocation.
- Store before/after evidence, change source/time, impact and reviewer disposition. Limit triggers to fields with qualified source authority.

**Acceptance:** A relevant change creates one deduplicated review with evidence; unchanged rescans do not create duplicates. Missing or stale observations indicate uncertainty rather than confirmed drift.

#### ONB-01 — Repeatable customer onboarding · Required before customer collection

- Qualify least-privilege access, identity/roles/revocation, tenant isolation, secrets/support access, privacy, region/retention choices and audit.
- Provide provider permission templates, setup diagnostics, supported-type matrix and customer boundary/acceptance checklist.
- Verify demo seeding/auto-publication and development approval bypasses cannot qualify customer production controls.

**Acceptance:** Record onboarding evidence before collecting customer data. A second installation of the supported workflow requires configuration rather than a customer-specific code fork. Production use additionally requires accepted restore, rollback, monitoring, incident response and support arrangements.

### 7.3 Conditional competitive gaps · P2

These are explicit gaps, not implied first-release commitments. Select one only when a named buyer demonstrates need, an authoritative evidence source exists and support capacity is funded.

| Gap | Smallest useful future requirement | Entry/acceptance boundary |
|---|---|---|
| Runtime detection (deferred; excluded from current release) | One qualified producer/source contract; correlate actor, agent/version, tool/action, decision, approval and outcome to investigation/findings | Validate authority, privacy, replay, duplicates and semantic correctness. Existing nine packages remain preview/paused until their gates pass. A custom adapter does not replace the current two-provider Program 2 gate; any separate adapter program needs explicit review. |
| Additional providers | Add one demonstrated blind spot, such as Vertex AI or direct OpenAI SaaS | Independent discovery reference and supported-type/permission matrix; do not claim universal coverage |
| Sensitive-data scanning | First import/consume one qualified classification source | Bind classification to data identity, source/time and expiry; native scanning is a separate decision |
| Malicious-model assessment | Import one specialist scanner result | Bind result to model digest, scanner/version, scope and expiry; inventory presence is not a safety verdict |
| Code/CI/release coverage | One repository or release evidence integration | Link component/release digest to deployment; avoid claiming full SAST/IaC/IDE coverage from SBOM ingestion |
| Bounded response | Integrate one existing identity/gateway/tool control with operator approval | Prove exact target, dry run, effect, idempotence, rollback and audit before claiming prevention |

General autonomous remediation, native gateways, broad behavioural/prompt-injection detection, universal replay and full IAM simulation are outside the initial release.

### 7.4 Shared quality requirements

- Every conclusion must carry tenant/scope, source/time, evidence state and control/version where applicable.
- Reuse metadata minimisation and evidence retention. Hash/digest references must not expose raw sensitive content.
- Preserve audit for approval, mapping, finding, exception and verification changes. Read and write roles must be explicit.
- Retries must be bounded and idempotent; partial scans cannot establish deletion or resolution.
- Demo, test, preview and customer-qualified states must be distinguishable in UI/export and must not silently promote one another.
- Before pilot scheduling, record supported estate size, API/processing budgets and measured interaction times. Performance targets require a scoped baseline; none is claimed here.

### 7.5 Assumptions and unresolved decisions

Confirm named buyer, first demo provider/control pack, test access, deployment preference, approval owner/source, first workflow destination, evidence-pack format, team capacity and time/cost budget. These decisions block dependent implementation or qualification, not preparation of internal fixtures and specifications.

Main risks: unsupported action/relationship evidence, shared blind spots in references, stale classifications, ambiguous approval identity, dependency on paused policies and customer-specific integration cost. Narrow the supported contract transparently when these cannot be resolved; retain failed results and prior scope versions.

## 8. Release plan, dependencies and completion

No calendar commitment is made. Estimate remaining implementation, qualification and operating work separately against the current source. Use one engineering stream by default for the assumed small team.

| Release | Scope | Exit gate |
|---|---|---|
| R0 — Next-demo readiness | DEM-01, demo-boundary DIS-01, CTL-01, EXP-01 and FIX-01 | Two rehearsals, three risks plus benign/unknown cases, one verified fix, explicit limitations; no customer-production claims |
| R1 — Bounded customer pilot | ONB-01 before collection; customer discovery/control qualification; APR-01 and EVD-01; BOM-01 if needed | Customer-approved boundary, discovery/control evidence, four comparison states, accepted pack and verified treatment |
| R2 — Repeatable value | DRF-01, second onboarding and comparable value reviews; production operations before production use | No code fork for supported repeat installation, change-review acceptance, observed effort measures and production gate evidence |
| R3 — Funded expansion | One selected P2 track | Track-specific evidence/operating qualification and revised scope; no automatic widening of prior claims |

Dependencies: dependable observation → qualified controls/exposure → treatment verification. Approval identity/evidence → comparison → drift. Secure onboarding → customer collection. Qualified runtime evidence → runtime activation. Production operations → production release.

**First development task:** Create a requirement-to-evidence ledger with ID, owner, existing API/UI/service, remaining work, source contract, acceptance scenario and release state. Reuse the Discovery health PRD's independent unchanged-collector baseline as its first discovery implementation task; do not start with a redesign or a new scanner.

**Release evidence:** Retain build/version, scope manifests, source/capability matrix, scenario results, independent reviewer decisions, unresolved limitations, demo script and customer acceptance separately. Mark requirements as Implemented, Test-qualified, Customer-qualified or Released with linked evidence; these states are not interchangeable.

Hold an affected claim/release if its source cannot support the conclusion, discovery is unqualified, privacy/isolation fails, normal policy gates fail or verification cannot distinguish a fix from missing evidence. Record remediate, rescope, defer or stop with owner and next review. Independent internal/test work can continue.

### References

- [AI Grid prioritised roadmap](../../Other%20Docs/Archive/Archived%20final%20plans/1_ai-grid-prioritized-roadmap-2026-2029.md): current retained baseline and qualification boundaries.
- [Discovery health PRD](../../Other%20Docs/Archive/Archived%20final%20plans/1.1_Req1_PRD_Discovery-health.md): detailed three-provider discovery requirements.
- [Business logic guide](business-logic-guide.md): AI-BOM, AI Grid, evidence, runtime and workflow foundations.
- [Exposure evaluator](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridExposureService.java): bounded correlations and evidence predicates.
- [Runtime readiness](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridRuntimeTelemetryReadinessService.java): existing provider readiness gate.
- [AI-BOM declared-resource API](../backend/src/main/java/com/prototype/vulnwatch/controller/AiBomDeclaredResourceController.java): existing read/setup/finding paths.
- [Wiz AI Security](https://www.wiz.io/solutions/ai-spm) and [Wiz agent-security overview](https://www.wiz.io/blog/wiz-ai-spm-secures-ai-agents): vendor capability claims reviewed in the preceding comparison; not an independent effectiveness assessment.
- User-supplied Wiz architecture image dated 3 October 2026: comparison input, not implementation instructions.
