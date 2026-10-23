# AI Grid — Working Context & Decision Memory

> **Purpose:** This is the living memory for the AI Grid (a.k.a. "AI Security" / "Scout AI Security") workstream
> as it moves **pilot → production**. It is updated every working session with new context, decisions, and
> important points. When working anywhere under `ai-grid/`, read this first.
>
> **Maintained by:** Claude, on instruction from @karthik.gowri (karthik.gowri@servicenow.com).
> **Started:** 2026-07-31. **Last updated:** 2026-08-03.

> **North star (end state in spirit):** the **Wiz AI Security** reverse-engineered PRD
> (`~/Downloads/WIZ-AI-Security-Reverse-Engineered-PRD (1).md`) — CNAPP-layered AI module, 260 AI-tagged rules,
> graph toxic-combination correlation, OWASP LLM Top 10 compliance. Adopted 2026-07-31 as the ambition target
> (supersedes the original scope PDF in scope, not in the security/tenancy requirements). "In spirit, not exact
> specs" — grow the architecture into that shape; don't chase 260 exact rules.
> **Near-term vision (user's own):** AWS + Azure agentless discovery → rich metadata for platform workflows
> (owner, relationships, criticality, hygiene recommendations) → **scalable policy engine + policy catalog** →
> violations captured as **AI Findings** graduated into the host workflow.

---

## 0. How to use this folder

```
ai-grid/
  CLAUDE.md                                    # THIS FILE — durable context + decision log (keep updated)
  AI-GRID-DISCUSSIONS.md                       # running, dated log of discussions & their outcomes
  known-limitations.md                         # LIVING — failure modes / boundaries; cite in coverage UI
  evaluations/
    2026-07-31-pilot-scope-conformance.md      # full write-up of the scope-vs-code evaluation
```

**Update discipline (do this every session):**
1. Append a dated entry to `AI-GRID-DISCUSSIONS.md` for what was discussed/decided.
2. Update **§4 Decision Log** and **§5 Current Status** below when a decision is made or state changes.
3. Bump the `Last updated` date at the top.
4. Longer analyses (evaluations, designs, spikes) get their own file under `evaluations/` or `designs/`, linked from the discussion log.

---

## 1. What AI Grid is

An AI-artifact **discovery + deterministic assessment** platform layered onto the existing VulnWatch/Scout
security-operations app. It continuously discovers AI-related artifacts across an org's estate, normalizes
them into one inventory, assesses each against a deterministic rule catalog mapped to recognized standards,
scores risk at artifact and org level, and routes findings into existing security workflows.

**It is read-only** — it never mutates the resources it scans. No inline enforcement, no automated
remediation, no red-team execution, no training-time governance (all explicitly out of scope for v1).

The **reconciled target spec** is the PDF: `AI-Security-Final-Scope (1).pdf`
(title: "Scout AI Security — AI-GRID Module", prepared 2026-07-26). Its 12 sections are the north star.
Key contents summarized in §3 below so we don't need the PDF open every time.

---

## 2. Where the code lives (current pilot)

**Backend** — isolated bounded context `com.prototype.vulnwatch.aisecurity`:
- `controller/` — `AiSecurityController` (`/api/ai-security/**`), `AiSecurityPlatformController`
  (`/api/platform/ai-security/policies`), `AiSecurityConnectorController` (`/api/connectors/ai-security/aws`),
  `AiSecurityAzureConnectorController` (`/api/connectors/ai-security/azure`),
  `AiSecurityAzureFoundryConfigController` (`/api/connectors/ai-security/azure-foundry`)
- `aws/` — `AwsBedrockDiscoveryService` (+ provider), `AiSecurityAwsAdmissionService`
- `azure/` — Azure AI/Foundry/ML/Search/Bot discovery, credential service, expiry, kill switches, metrics
- `service/` — `AiSecurityApiService` (read API assembly), `AiSecurityObservationService` (ingest),
  `AiSecurityPolicyEvaluationService` (rule engine), `AiSecurityJobWorkerService` (scheduled poller, 3s),
  `AiSecuritySyncRunFacade`, `AiSecurityAccessService` (entitlement gate)
- `policy/` — `AiSecurityPolicyRegistry` (14 hardcoded compatibility policies), `AiSecurityResourceFamilyCatalogue`
- `model/` — `AiSecurityContracts` (`ObservationEnvelopeV1`, enums)

**Frontend** — `frontend/src/`:
- Pages: `AiInventoryPage`, `AiFindingsPage`, `AiPoliciesPage`, `AiPolicyDetailPage`,
  `AiSecurityConnectorPage` (AWS), `AiSecurityAzureConnectorPage` (Azure) — all with `.test.tsx`
- `features/ai-security/` — `types.ts`, `AiInventoryOverviewStrip.tsx`
- Routes: `/inventory/ai`, `/findings/ai`, `/policies`, `/policies/:policyId` (gated by `AiSecurityRoute`)
- Styles: `styles/ai-security.css`; API methods in `api/client.ts`

**Migrations:**
- Platform (`db/migration/postgres_reset/`): `V47` entitlement compat, `V48` platform policy distribution
  + 5 AWS policies (tenant target → 45), `V49` + 8 Azure policies (tenant target → 46)
- Tenant (`db/migration/tenant/`): `V45` bounded-context (10 tables + forced RLS), `V46` Azure credentials,
  `V47` Foundry endpoint URL

**Docs (existing):** `docs/ai-security-pilot-readiness.md` (the pilot gate of record),
`docs/ai-security-azure-activation-runbook.md`, `docs/ai-security-azure-policy-permission-matrix.md`,
`docs/openllmetry-traceloop-ai-grid-analysis.md`.

**Entitlement:** `ai.security` — **ships DISABLED by default**, enabled per-tenant via override. Gated by
`AiSecurityAccessService.assertEntitled()` (backend) and `canUseEntitlement(actor, 'ai.security')` (frontend).

**Working branch (as of start):** `feat/ai-security-sync-run-history-metadata`.

---

## 3. The target scope in one screen (from the PDF)

- **§2 Taxonomy:** 17 canonical artifact types (AI_MODEL, FINE_TUNED_MODEL, EMBEDDING_MODEL, AI_AGENT,
  AI_APPLICATION, MCP_SERVER, AI_FUNCTION, AI_PIPELINE, AI_GATEWAY, AI_GUARDRAIL, KNOWLEDGE_BASE,
  VECTOR_STORE, PROMPT_ASSET, AI_IDENTITY, AI_DEPENDENCY, EVALUATION_RUN, ADVISORY).
- **§3 Discovery — 6 planes:** Cloud AI services (AWS/Azure/GCP), Direct model-provider APIs
  (OpenAI/Anthropic/HuggingFace), Source code/CI (AI SDK imports, IaC, `.mcp.json`, `copilot-instructions.md`),
  SaaS AI admin (Copilot/M365), Identity & access (IAM/Entra/Okta), Runtime telemetry (OTLP). GCP = v1 target.
  MCP discovery is cross-cutting, always modeled as its own `MCP_SERVER` artifact.
- **§4 Data model:** `ai_sources`, `ai_assets`, `ai_asset_snapshots` (redacted evidence + `prompt_hash`),
  `ai_asset_relations`, `ai_asset_tools`, `ai_assessment_runs`, `ai_asset_findings` (tenant-scoped) +
  `platform.ai_assessment_rules`, `platform.ai_tenant_risk_rollups`. **Hard rule: never leak raw prompts.**
- **§5 Assessment:**
  - **Capability normalization** — 12 boolean flags the rule engine reads INSTEAD of raw payloads:
    `inference, retrieval, tool_execution, code_execution, file_access, database_access, network_egress,
    memory_persistence, secrets_access, cross_tenant_access, policy_override, autonomous_action`.
  - **9 dimensions w/ multipliers:** TENANT_BOUNDARY (1.25), AGENCY (1.15), NETWORK (1.10),
    DATA_EXPOSURE (1.10), IDENTITY (1.05), GUARDRAILS (1.00), SUPPLY_CHAIN (1.00), DRIFT (0.90),
    OBSERVABILITY (0.80). Each rule declares artifact types, required capability flags, severity, OWASP mapping.
  - **Scoring (bottom-up, one formula, three levels):**
    - Finding = `severity_base (CRIT=10,HIGH=7,MED=4,LOW=2,INFO=0.5) × dimension_multiplier × confidence`
    - Asset = `max(finding) × 0.60 + avg(top-3) × 0.30 + drift_bonus × 0.10`, capped at 10
    - Tenant rollup = `max(asset) × 0.40 + avg(top-10) × 0.40 + avg(all) × 0.20`
  - **Two lenses over the same findings:** **Posture score** (how well configured, graded A–F) and
    **Blast radius** (how bad if compromised, drives remediation priority).
- **§6 Governance:** owner required (else it's a finding); OWASP LLM Top 10 (2025) per rule; MITRE ATLAS on
  supply-chain/runtime findings; NIST AI RMF function tags at rollup; EU AI Act + ISO 42001 as report layer;
  CycloneDX ML-BOM 1.5 export; **findings graduate into the HOST platform's findings workflow** (ownership,
  SLA, suppression, auto-close, ServiceNow) — "first-class citizens, not a bolted-on separate view."
- **§7 Runtime:** OTLP ingest, correlate trace→asset (assoc metadata → provider+model → tool name →
  `UNKNOWN_RUNTIME_AI_ASSET`). Content tracing off by default.
- **§8 Security:** schema isolation, credential *references* only, short-lived assumed creds, every run audited.
- **§9 API (target contract):** `/api/ai-sources`, `/api/ai-assets`, `/api/ai-assets/{id}/findings|relations`,
  `/api/ai-assessment-runs`, `/api/ai-risk-summary`, `/api/ai-rules`, `/api/ai-runtime/otlp`,
  `/api/platform/ai-grid/{tenants/summary,rules,advisories}`.
- **§11 Phases:** 1 Discovery core · 2 Deterministic assessment engine · 3 Identity & data depth
  · 4 Runtime fusion · 5 Enterprise workflow & compliance · 6 Surface expansion.
- **§12 DoD per phase:** connectors on schedule w/ health API; complete capability flags (no UNKNOWN);
  every applicable rule → correct severity/OWASP on a seeded answer-key env; **tenant rollup changes
  predictably when a seeded misconfig is fixed**.

---

## 4. Decision Log

> Append-only. Newest at top. Each entry: date · decision · rationale · owner.

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-08-03 (s9) | **R1 retires legacy finding-based policy assistance.** AI findings + reviews live exclusively in the host finding model; the legacy review-history *scope-suggestion* endpoint (`/api/ai-security/policies/{id}/assist/suggested-scope`) + its frontend card are removed. `review()`/`findingsById` stay on the host `findings` table (NOT pointed back to `ai_security_findings`). Adaptive AiGrid scope recommendations are **deferred** until integrated with the governed policy-applicability engine. | Post-merge with main's policy-assist, the suggestion path read the *disabled* legacy silo while review had moved to host findings — an internally inconsistent, UI-exposed defect. Option 3 (migrate only the suggestion query) rejected: a real migration must make suggested scopes actually govern AiGrid applicability/coverage, which today lives in the legacy evaluator. Confirmed product-integration defect, not a security vuln. |
| 2026-08-03 | **Current coverage is a materialized composite epoch, distinct from immutable provider runs.** Each epoch unions the latest `COMPLETE` head of every connector scope, selects the authoritative manifest per artifact, materializes the applicable published-policy candidate set once, and retains each candidate's source run for evidence/replay. Historical run metrics remain run-scoped. Current coverage/readiness/gaps use the epoch and report technology, provider, family, account, environment, owner, policy, and framework dimensions. | A tenant-global latest run silently alternated AWS and Azure posture. Scope heads preserve deletion semantics, while a separate current projection avoids weakening deterministic run replay and removes repeated artifact × policy recomputation from reads and pipeline stages. |
| 2026-08-03 | **R1 implementation completion and R1 deployment certification are separate states.** The aggregate R1 gate combines platform-derived AWS/Azure answer-key and per-policy release governance with six named, expiring operational evidence gates. External evidence cannot override platform-derived gates, and a release decision is recorded as BLOCKED unless every gate passes. | Makes “complete R1” executable without fabricating discovery recall, first-run utility, isolation, economics, or design-partner soak. Code can be complete while deployment remains correctly blocked pending real owned evidence. |
| 2026-08-02 | **Azure RAI policies are first-class `AI_GUARDRAIL` artifacts, but the first published control is limited to explicit disabled/non-blocking filter entries.** PASS requires a non-empty returned filter list with explicit `enabled=true` and `blocking=true` on every entry; incomplete shapes produce `NO_DECISION`. Deployment `raiPolicyName` is inventory/linkage evidence, not proof of filter completeness or efficacy. | Delivers an exact Azure LLM01/09 posture slice without claiming that policy presence, platform defaults, category coverage, thresholds, or behavioral efficacy are verified. |
| 2026-08-02 | **R1 policy readiness is computed per run and tenant but never changes policy selection or the security denominator.** Exact Minimum Context Pack facts preserve proxy/verified distinctions. Coverage gaps project into prioritized setup actions. Connector-scoped baseline telemetry reports full decision reachability separately from REQUIRED/ENABLED first-run utility and retains missing assessments conservatively. | Provides useful first-run guidance without adaptive-enablement gaming. A linked data source, wildcard permission, configured public access, or owner tag remains a limited claim and cannot become sensitive data, effective admin, verified reachability, or confirmed ownership by implication. |
| 2026-08-02 | **R1 coverage uses the immutable expected artifact × applicable published-policy candidate set, not emitted assessments as its denominator.** Missing rows are explicit `MISSING_ASSESSMENT` gaps and detail records. Answer-key release evidence must be `PLATFORM_RUN_BOUND`: tenant/run IDs are required, policy cases bind to source assessments, security outcomes are validated server-side, and the service persists its own decision fingerprint. Legacy external attestations cannot release a policy. | Enforces zero silent omission and prevents callers from manufacturing release evidence with self-consistent JSON. It also separates “no policy applies to this artifact” from “a policy should have assessed it but the pipeline omitted the row.” |
| 2026-08-02 | **Precision release governance gates on the Wilson confidence lower bound, not the point estimate.** A 100% result from an underpowered sample is recorded but fails a 95% release claim. Answer-key results are currently privileged external attestations; provenance binding to immutable tenant run/assessment artifacts is now an explicit FR-18 requirement and remains part of the real answer-key harness work. Discovery recall remains a separate answer-key inventory metric rather than being conflated with policy-finding precision labels. | Prevents statistically indefensible publication while avoiding a cosmetic “evidence reference” that would still be caller-controlled. The trusted harness integration must validate actual platform execution identifiers and decision fingerprints server-side. |
| 2026-08-02 | **R0 integrity hardening is part of the completed foundation.** Replay is evaluated only from immutable artifact, relationship, fact, policy-version, and stored `evaluation_as_of` evidence; policies enforce minimum confidence; assessment decision-content hashes are distinct from stable finding identity. `STANDARD_V1` performs recursive redaction. Complete-scope processing is explicitly transactional, policy downgrades auto-close existing owner-facing findings, and finding projections refresh once after commit. Legacy vulnerability findings retain their database subject invariant. | Converts the R0 reliability and determinism claims into enforced invariants with PostgreSQL regression proof. The transaction concern was partly overstated because ingestion already used a shared transaction manager, but the pipeline boundary and rollback behavior are now explicit and directly tested. |
| 2026-08-02 | **Release 0 implementation is complete on `codex/ai-grid-exposure-management`; release certification remains evidence-based.** The Bedrock guardrail slice now uses immutable content-addressed snapshots, governed facts and policies, canonical host findings with owner/SLA/suppression, verified reassessment closure, recurrence, and ServiceNow promotion. Evidence access is role-gated. Answer-key, precision, lifecycle, and latest-decision checks are exposed as executable release readiness. | Completes the R0 evidence-to-closure architecture without fabricating production evidence. A real owned answer-key run, precision sample, and release decision are operational inputs to certify deployment, not code-completeness claims. |
| 2026-08-02 | **The fact and workflow enforcement model is finalized.** Distinct claims use distinct fact keys; state/provenance/evidence class/confidence/freshness remain orthogonal. Policies declare exact keys and evidence constraints and are linted at publication. Tenant selection is separate from evidence readiness; preview is evaluated but not owner-facing. Workflow classes are posture finding, exposure hypothesis, and validated exposure with bidirectional freshness-gated graduation. All applicable published policies remain in coverage. | Prevents configuration proxies from satisfying verified claims, prevents silent adaptive enablement, protects the denominator, and makes exposure workflow promotion/demotion deterministic and auditable. Final PRD FR-01, FR-04–09. |
| 2026-08-02 | **Foundation scope now includes enforceable product-operating requirements:** Minimum Context Pack, first-run value without denominator shrinkage, staffed answer-key environments, governed precision review, tenant-scoped content-addressed evidence and scan economics, and method-specific confidence calibration. | These requirements address real-customer viability: usefulness without mature CIEM/DSPM/ASM, time to value, falsifiable accuracy, sustainable storage/provider cost, and non-theatrical confidence thresholds. Final PRD FR-16–21 and Release 0/1 gates. |
| 2026-08-02 | **`PRD-AI-Grid-Final-Scope.md` is the authoritative product scope.** Release 0 is one narrow Bedrock agent/guardrail evidence-to-closure slice; Release 1 is bounded Bedrock/Azure posture and coverage integrity; Release 2 earns the Exposure Management claim through system membership, identity, data, reachability, three validated paths, and verified closure. Runtime assurance, agent/MCP, supply chain, and continuous validation remain later modules. | Consolidates the implementation review, clean-start decision, technology/applicability correction, and external strategy critique into one executable scope. It prevents foundation work from silently absorbing the entire long-term platform. |
| 2026-08-02 | **Technology is a governed, versioned classification and coverage dimension, but not the universal policy-routing key.** Applicability resolves artifact type → capabilities → relationships → required facts/scopes → optional technology constraint. Unknown technology remains a visible gap but cannot block a provider-neutral policy when other evidence is sufficient. | Making every policy depend on technology would recreate silent false negatives from missing mappings, aliases, or vendor renames. Technology constraints are necessary for product-specific controls; capability/fact targeting is safer for portable controls. |
| 2026-08-02 | **Existing AI policy definitions/settings/evaluations and AI findings/reviews are demo data and may be reset. Preserve secure collection, tenancy, completeness, jobs, and safe decision semantics, but build the governed catalog and host finding path fresh.** A consolidated decision audit now classifies all prior choices as adopted, modified, added, deferred, superseded, excluded, or open. | There is no production policy/finding history to protect. Removing data migration and a long-lived strangler path reduces implementation cost and drift risk while retaining the parts of the pilot that have real engineering value. See [`AI-GRID-DECISION-AUDIT.md`](AI-GRID-DECISION-AUDIT.md) and the updated PRD. |
| 2026-08-01 (s8) | **Requirement registers consolidated by pipeline stage; prerequisite epics reorganized into TWO, by provider (P-AWS, P-AZ).** Collection (former AR-1..9) → the two prerequisite epics; computation (AR-10/11/12) → Phase-2 catalog (P2-1/2/3); accuracy register keeps only verdict-quality (AR-13..15) + structural (AR-16..18). One home per requirement; IDs retained as pointers. | Three overlapping registers (AR / P2 / P-A-B-C) described one collect→compute→evaluate pipeline — AR-7 was literally == P-A. Organizing by stage removes the duplication and gives Bedrock collection an owner (P-AWS) symmetric to Azure. See [`designs/2026-08-01-discovery-prerequisite-epics.md`](designs/2026-08-01-discovery-prerequisite-epics.md). |
| 2026-08-01 (s8) | **Catalog regenerated from the coverage matrix (41 → 62; BR-20..28, AZ-23..34 folded in). Azure gap policies recorded as prerequisite epics P-A/P-B/P-C** (content-filter/RAI collection == AR-7; AI-family config completion; Foundry Connections discovery). | Catalog must agree with the matrix, and every gap `NO_DECISION` needs an owning requirement (s7) — the prerequisite epics are those owners for Azure. Most Azure gaps are field-fetch on already-modelled families (cheap); P-C (Foundry Connections) is the one net-new family. Bedrock prerequisites (Customization Jobs, `PROMPT_ASSET`) noted for symmetry, not yet epic'd. See [`designs/2026-08-01-azure-discovery-prerequisites.md`](designs/2026-08-01-azure-discovery-prerequisites.md). |
| 2026-08-01 (s8) | **Release boundary fixed so "superset" is provable: AWS Bedrock (proper) + ARM-managed Azure AI (OpenAI/AI Services/Foundry/ML/Search/Bot/Content Safety), OWASP-mapped.** Content Safety promoted to first-class (Azure LLM01/09 backbone, not an edge). SageMaker + AWS-AI-adjacent and Copilot Studio + SaaS-admin plane → residual (phase-2 plan §8). Artifact-type axis kept provider-neutral so SageMaker slots in as content later. Completeness established via a **families × dimensions coverage matrix**, not a hand list — which revised the superset **41 → ~62**. | "Superset" only means something against a *bounded* scope; "all AI" is unprovable. SageMaker = framework #3 (biggest deferred value — training/LLM04 lives there, so Bedrock-only shows LLM04 thin *by design*); Copilot Studio = a different discovery *mechanism* (SaaS-admin plane), not a policy. Grid method surfaced real gaps: LLM04 + LLM07 homes, Foundry connections, ML training surface. See [`designs/2026-08-01-coverage-matrix.md`](designs/2026-08-01-coverage-matrix.md). |
| 2026-07-31 (s7) | **Two-phase model: Phase 1 = collection (facts from AWS/Azure), Phase 2 = computation (derive security signals from Phase 1 data + attribute to AI artifacts).** Phase 2 is open in mechanism (NOT limited to CIEM/ASM/DSPM — also trust-boundary, encryption, guardrail-coverage, secrets, lineage, drift, correlation, blast-radius) but bounded by attribution. Boundary is a data contract, not a release gate. | Clean separation: I/O-bound provider collection vs pure computation over normalized facts = the Wiz two-tier shape from first principles, and a pipeline view of the Epic 0 fact model. Four honest refinements baked in: P1 collects *primitives* not rule-fields + snapshot history; every P2 signal attributed to an AI artifact; derived≠observed (confidence/provenance); DSPM needs a new *collection source* (Macie/Purview), not a computation. Draft: [`designs/2026-07-31-phase2-computation-plan.md`](designs/2026-07-31-phase2-computation-plan.md). |
| 2026-07-31 (s7) | **AI Grid is a *consumer and attributor* of general-security signals (CIEM/DSPM/ASM), not the *owner* of those capabilities.** Extends the s5 Attribution Rule from policies to capabilities: the AI-ness is the attribution layer, not the engine. Build only the thin attribution layer + the thinnest capability slice not already available from the host platform; consume general-security facts where they exist. | CIEM/DSPM/ASM are general CNAPP mechanisms, not AI-specific — owning them fully = scope creep into CSPM (known-limitations #1). Same computation, different attribution = different product. Shrinks Group B (AR-10/11/12) from "build a capability" to "consume + attribute." |
| 2026-07-31 (s7) | **Initial scope = BOTH Bedrock and Azure** (supersedes s6 "Bedrock first, Azure #2"). Goal = *complete* coverage of every policy valid for AI artifacts in both, mapped to OWASP LLM Top 10, scoped by the Attribution Rule. Not a Wiz clone / not all 260 rules. | Azure discovery + 8 policies already ship — folding them in beats deprioritizing built work; two providers at once is the real multi-provider validation. Wiz is inspiration, not the target. |
| 2026-07-31 (s7) | **`NO_DECISION` is accepted and desirable — it is the accuracy-improvement backlog.** Every `NO_DECISION` must point to an owning accuracy requirement (`AR-##`); a policy may ship returning `NO_DECISION` only if that requirement is registered. Structural gaps documented as an accuracy-requirement register. | User wants `NO_DECISION` to *drive* going deep on specific controls to improve accuracy, not to be hidden. Turns the catalog's gaps into a tracked backlog instead of blank spots. See [`designs/2026-07-31-accuracy-improvement-requirements.md`](designs/2026-07-31-accuracy-improvement-requirements.md). |
| 2026-07-31 (s2) | **Adopt the Wiz PRD as the end-state-in-spirit north star.** | Far more mature/complete target than the original scope; gives a concrete 260-rule / graph-correlation / OWASP-compliance shape to grow into. |
| 2026-07-31 (s2) | **Make the policy engine data-driven (Epic 0) before adding coverage.** | Current engine is a hardcoded `switch` + `List` — one rule = Java in ~4 places; cannot load a large catalog. This is the #1 correction. |
| 2026-07-31 (s2) | **Graduate AI findings FULLY into the host `Finding` workflow, via a strangler pattern.** | Only way to inherit owner/SLA/ServiceNow/suppression/auto-close (the user's platform-workflow goal). Strangler = feature-flagged behind the disabled `ai.security` entitlement, artifact links to an `asset` where one exists else a light AI subject, evidence in a side table, old `ai_security_findings` retired after parity. Dual-write rejected (permanent drift); keep-separate rejected (goals unmet). |
| 2026-07-31 (s6) | **Initial scope = ONE framework: AWS Bedrock (agent-centric), reported against OWASP LLM Top 10 (2025) only.** | Single-framework-first = the vertical-slice principle applied to content; makes the ≥95% precision gate hand-validatable. Bedrock chosen because discovery is the most complete already AND the Bedrock Agent exercises the *entire* model in one ecosystem (multiple types, technology tag, capabilities, edges agent→guardrail/Lambda/KB/role, attribution rule, CIEM-lite on-ramp, OWASP LLM06/LLM02). Rich enough to stress the architecture, not a toy. Azure OpenAI = framework #2 (then mostly content, not architecture). Agent SDKs (LangChain/Claude) excluded — need source/host discovery we've deferred. |
| 2026-07-31 (s6) | **Coverage must NEVER present `NO_DECISION` as pass.** The UI/rollup must foreground the 5-way status (PASS/FAIL/NO_RESOURCES/DISABLED/NO_POLICY) + `NO_DECISION`. | Highest-attention failure mode (#9 in [`known-limitations.md`](known-limitations.md)): with so much `NO_DECISION`/`UNKNOWN`, a top-line "compliant %" can mean "not evaluated," giving false assurance — the worst failure for a security product. |
| 2026-07-31 (s5) | **Scope by AI-nexus + attribution, not by mechanism. The "AI Security Attribution Rule": every AI Grid finding is attributed to an AI artifact and justified by that artifact's own config OR a security-relevant relationship edge.** | "Cloud configuration out of scope" taken literally would gut the product — an AI artifact's security *is* derived from its own config + its dependencies' config (guardrail, execution role, action-group Lambda, backing bucket, network). IN: config/posture of the AI artifact (#2) + config of non-AI resources it depends on, viewed artifact-first (#3) + OWASP/NIST mapping of those. OUT: generic CSPM with no AI nexus (#1). Consume dependency config as **facts on the artifact / facts over graph edges**, never as standalone cloud-resource findings (e.g. ship "Knowledge base K exposes a public S3 source", not "Bucket X is public"). Dovetails with the Epic 0 fact model + Epic 5 graph. |
| 2026-07-31 (s4) | **Ship a curated, platform-owned built-in policy catalog; tenants only enable/disable. No tenant-authored custom policies, no query-builder authoring UI, no customer-facing fact-schema registry.** | Matches the model already in code (`ai_security_policy_distribution.available/default_enabled` + tenant `ai_security_policy_settings.enabled`). Simplifies scope — removes an authoring epic. Epic 0's declarative engine still stands, reframed as **internal authoring-at-scale + data-driven compliance/coverage**, NOT a customer feature ("curated-only" ≠ "keep the Java `switch`"). Fact dictionary downgraded to an internal seed/test validation helper. |
| 2026-07-31 (s4) | **Keep REST; do NOT adopt GraphQL as a transport.** | Curated catalog + enable/disable needs no flexible client query language; a GraphQL runtime would force re-plumbing auth + per-resolver tenant RLS + a second surface to test/secure against a REST-wired security spine. Borrow only the *ideas* (structured filter + cursor pagination + normalized per-type fact shape) on REST endpoints if/when the inventory table needs them. Revisit only if a customer-facing multi-resource inventory-exploration API becomes a product requirement. |
| 2026-07-31 (s3) | **Fact model (Epic 0) must be `UNKNOWN`-aware and provenance-tagged, and include the six Wiz graph-enrichment booleans** (`isAccessibleFromInternet`, `isOpenToAllInternet`, `hasAdminPrivileges`, `hasHighPrivileges`, `hasAccessToSensitiveData`, `hasSensitiveData`) as first-class facts. | Wiz's own `cloudResourcesV2` leaves these null at scan time and fills them via graph (CIEM/DSPM/ASM). Config policies ship now; correlation policies emit `NO_DECISION` until a capability populates the fact — no rewrite later. See [`evaluations/2026-07-31-connector-metadata-gap.md`](evaluations/2026-07-31-connector-metadata-gap.md). |
| 2026-07-31 (s3) | **Two near-term connector tasks added:** emit resource **tags** (both connectors — currently neither does; blocks Epic 1 ownership) + a **generic "fetch full resource config" step per family** (so Tier-1 field gaps close as data, not code). | Connectors originally fetched only the exact fields the compatibility policies read; ownership + breadth both need more. |
| 2026-07-31 (s3) | **CIEM-lite (effective-permission + trust-policy condition resolution) is the first Tier-3 capability epic.** | Unlocks the 4 AI-identity rules (admin/impersonation/secrets-KMS/confused-deputy); half-started on AWS (syntactic wildcard only). DSPM likely non-native (coarse proxy or defer); ASM validated-reachability deferred (config proxy meanwhile). |
| 2026-07-31 (s2) | **Build as ONE data-driven vertical slice (Epics 0→1→2→3, single rule), then breadth (Epic 4).** | Front-loads all architectural risk into the smallest unit; after the slice, Epic 4 is pure content. Piloted rule: Bedrock guardrail < MEDIUM → owner+criticality → host Finding w/ SLA/ServiceNow → OWASP LLM06 on a compliance view. User agreed 2026-07-31. |
| 2026-07-31 | **Set up this `ai-grid/` workspace** (CLAUDE.md + discussions log + evaluations) to carry the pilot→prod effort across many sessions. | Long multi-session workstream; need durable context & decision continuity. |
| 2026-07-31 | *(Proposed, not yet ratified)* Treat shipped AWS+Azure build as the **pilot v1**, keep shipping to design partners, **but insert the capability-flag layer and scoring model before the 3rd connector.** | Both are load-bearing for the scope thesis and get exponentially more expensive to retrofit after another provider lands. Awaiting user confirmation. |

---

## 5. Current Status (R0–R2 backend mechanisms implemented; certification and merge incomplete)

**Release position:** R0, the bounded R1 Managed-AI Foundation, and the R2 backend exposure mechanisms are
implemented on `codex/ai-grid-exposure-management` at `3e431fa`. R1 includes selected exact Bedrock/Azure controls
rather than a commitment to all 62 candidates. R2 adds system lifecycle, temporal host-context ports, three
bounded correlations, deterministic replay, exposure APIs, canonical finding graduation, and computed release
gates. This is **not** an R2 certification or production-release claim. As of 2026-08-03, GitHub PR #22 is still
open (not merged to `main`), `migration-boundaries` is red, strong host-context producers are not integrated,
and operational R1/R2 evidence has not passed the aggregate gates. Detailed review:
[`evaluations/2026-08-03-r2-implementation-review.md`](evaluations/2026-08-03-r2-implementation-review.md).

**R0 implemented:**
- ✅ Time-deterministic, provider-free replay from immutable artifact/edge/fact snapshots with a stored as-of
  timestamp and separate decision-content fingerprint
- ✅ Explicit per-complete-scope atomicity across evidence, assessment, canonical finding, receipt, and outbox,
  with forced-failure rollback and idempotent-retry proof
- ✅ Minimum-confidence gates, recursive `STANDARD_V1` redaction, governance-downgrade finding closure, and one
  after-commit projection refresh per assessment run
- ✅ Immutable, tenant-scoped, content-addressed evidence snapshots with redaction and retention controls
- ✅ Governed/versioned technology, fact, policy, predicate, applicability, and coverage model
- ✅ Exact fact-key and minimum evidence/verification enforcement with honest `NO_DECISION`
- ✅ Bedrock weak-guardrail evidence → assessment → canonical host finding vertical slice
- ✅ Host lifecycle parity: ownership, SLA due date, suppression preservation, verified reassessment closure,
  recurrence/reopen, audit events, and ServiceNow incident promotion
- ✅ Role-gated evidence access; tenant RLS and entitlement boundaries retained
- ✅ Answer-key, precision review, lifecycle, budget/economics, and release-readiness APIs and tests
- ✅ Expected-vs-recorded coverage denominator, explicit missing-assessment reconciliation, detail ledger, and
  tenant/run/assessment-bound answer-key release evidence
- ✅ Deletion-safe multi-provider current coverage epochs built from the latest complete connector-scope heads;
  AWS and Azure no longer replace each other when their independent runs finish
- ✅ Materialized current expected-candidate set and FR-09 breakdowns by technology, provider, family, account,
  environment, owner, policy, and framework; immutable per-run replay and metrics remain separate
- ✅ Exact Minimum Context Pack claim separation, relationship-derived linked-data proxy, per-run policy
  readiness, prioritized setup actions, and connector-scoped first-run utility telemetry
- ✅ Azure RAI policies as first-class guardrails with deployment linkage and an exact explicit
  disabled/non-blocking-filter policy; incomplete filter shapes remain `NO_DECISION`
- ✅ Aggregate R1 certification gate with immutable decisions, expiring operational evidence, provider answer-key
  requirements, and non-bypassable per-policy release governance
- ✅ Reset-line/default-template Finding compatibility and deterministic tenant-clone RLS parity, with production
  bootstrap structural-fingerprint regression proof
- ✅ Inventory/policy UI exposes governed technology, evidence readiness, applicability, and coverage state

**Operational gate before calling an environment R0-certified:**
- Run the seeded scenarios through the real owned Bedrock answer-key harness using the enforced tenant/run and
  assessment binding; retain the resulting server-derived decision fingerprints.
- Record the high/critical precision sample and resolve any failed threshold.
- Review the release-readiness result and record an explicit approved decision/canary outcome.

**Operational gate before calling an environment R1-certified:**
- Maintain fresh certified, platform-bound AWS and Azure answer-key runs covering each published policy version.
- Complete required high/critical dual-reviewed precision reviews against current policy digests.
- Record unexpired evidence for discovery recall, first-run utility, determinism/isolation, economics/budgets,
  and AWS/Azure design-partner soak.
- Evaluate `/api/platform/ai-grid/validation/releases/r1/readiness`; record an R1 decision only after it is ready.

**R2 backend mechanisms implemented:**
- ✅ Stable provider-rooted AI-system IDs, immutable membership revisions/overrides, and split/merge/successor/
  retirement lineage without automatic finding transfer
- ✅ Temporal relationship and host-context evidence plus separate configuration-proxy and verified fact keys
- ✅ Three versioned, bounded PostgreSQL correlation templates with hypothesis and validated-exposure states
- ✅ Current multi-provider coverage-epoch correlation and immutable replay execution manifests/material digests
- ✅ Canonical host-finding graduation only for validated exposure, shared-root ticket compression, reassessment
  closure, recurrence/reopen, dispositions, and exposure/system APIs
- ✅ Computed R2 gates for template precision, explainability, owner/SLA routing, stale evidence, and closure
- ✅ Focused PostgreSQL proof for all three templates, replay, stale demotion, complete closure, path compression,
  multi-provider epochs, membership lifecycle, and traversal bounds

**R2 release gaps:**
- ❌ Resolve platform/tenant migration ownership; do not permanently exempt the V59 tenant-DDL loop
- ❌ Connect trusted CIEM/DSPM/ASM/reachability producers for the seven strong facts used by validated templates
- ❌ Bind host facts to authorized/calibrated producer methods; reject null/low/unapproved confidence rather than
  treating missing confidence as `1.0`
- ❌ Replace R2 point-estimate/single-review precision with the R1 Wilson-bound, sample, dual-review,
  adjudication, and answer-key provenance contract
- ❌ Add the analyst exposure/path/evidence/root-cause/breakpoint/disposition frontend experience
- ❌ Implement affected-subgraph invalidation/recompute rather than full current-graph traversal on every change
- ❌ Define owner-facing finding/SLA behavior when a validated exposure demotes to a stale hypothesis
- ❌ Collect real R2 precision, explainability, owner/SLA, stale-demotion, verified-closure, and design-partner
  evidence and record an explicit R2 approval

**Next product work:** first close the migration boundary, host-evidence trust/confidence, and R2 precision-governance
gaps. Then connect real host evidence producers, add the analyst exposure UI and affected-subgraph economics, and
certify/canary R1 and R2 with real evidence. Runtime assurance, agent/MCP, supply chain, and continuous validation
stay later modules.

---

## 6. Roadmap to production — Epic structure (ratified 2026-07-31 s2)

Build order = one data-driven **vertical slice** through Epics 0→1→2→3 (single rule), then breadth (Epic 4+).
Full gap analysis + feature list: [`evaluations/2026-07-31-wiz-endstate-gap-and-feature-list.md`](evaluations/2026-07-31-wiz-endstate-gap-and-feature-list.md).
Detailed slice build plan (schemas/services/endpoints/migrations): [`designs/2026-07-31-vertical-slice-implementation-plan.md`](designs/2026-07-31-vertical-slice-implementation-plan.md).

- **Epic 0 — Data-driven policy engine + catalog** *(foundational)*: `platform.ai_policy_catalog` (declarative
  rules), normalized per-artifact fact model, generic predicate evaluator replacing the `switch`; keep
  `NO_DECISION` evidence gating. Incorporates the scope doc's capability-flag idea as the fact layer.
- **Epic 1 — Artifact metadata**: owner, criticality, tags, exposure/attack-surface; owner resolution (reuse
  `OwnershipRuleService`); unowned ⇒ finding; criticality from exposure + sensitivity + linked-asset criticality.
- **Epic 2 — Graduate AI Findings into host workflow** (strangler): host `Finding` w/ `AI_SECURITY` source +
  `ai_artifact_id`; reuse ownership/SLA/ServiceNow/suppression/auto-close.
- **Epic 3 — Framework mapping + compliance posture**: OWASP LLM01–09 + CWE tags; posture% + category rollup +
  5-way status; `GET /api/ai-security/compliance` + dashboard. (Makes the previously-unmeetable rollup DoD gate measurable.)
- **Epic 4 — Load Wiz AWS+Azure catalog (declarative)**: 24 AWS + 24 Azure cloud-misconfig + cloud-native
  Agent/Guardrail/Model config + 4 AI-identity rules as catalog rows; connector fact enrichment + CIEM-lite;
  expand taxonomy (`AI_GUARDRAIL`, `AI_GATEWAY`, `AI_DATASTORE`, `AI_IDENTITY`).
- **Epic 5 — Cross-resource correlation (toxic combinations)**: graph evaluator; reuse host CVE findings +
  asset sensitivity; `ai_security_correlated_issues`.
- **Discovery Prerequisite Epics — two, by provider (P-AWS, P-AZ)** *(Phase-1 collection that gates the gap
  policies; a refinement of Epic 4)*: **P-AWS** (Bedrock) — tags+full-config, guardrail content config, model
  CMK/LEGACY, KB data-source origin, Customization-Job + `PROMPT_ASSET` discovery (unblocks BR-8/9/10/20..28).
  **P-AZ** (Azure) — workstreams **P-A** content-filter/RAI (== AR-7, highest value), **P-B** AI-family config
  completion (+ tags/full-config), **P-C** Foundry Connections (unblocks AZ-11/12/23..34). Absorbs the former
  AR-1..9 collection requirements; the accuracy register now holds only verdict-quality (AR-13..15) + structural
  (AR-16..18); computation (AR-10/11/12) lives in the Phase-2 catalog (P2-1/2/3). See
  [`designs/2026-08-01-discovery-prerequisite-epics.md`](designs/2026-08-01-discovery-prerequisite-epics.md).
- **Deferred (new mechanisms):** model-artifact static scan, SAST AI code rules, attack-surface network probing,
  MCP risk, runtime/shadow-AI, GCP.

---

## 7. Open questions / decisions

**Resolved 2026-07-31 (s2):**
- [x] Pilot-vs-target stance → shipped build is the pilot; **grow it toward the Wiz end-state-in-spirit** (Decision Log).
- [x] AI findings graduate into the host workflow → **yes, fully, via strangler** (Decision Log).
- [x] Build sequencing → **one data-driven vertical slice first**, then breadth (Decision Log).
- [x] Rollup/compliance DoD gate → **build it** (Epic 3 makes it measurable).
- [x] Policy authoring model (s4) → **curated platform-owned catalog; tenants only enable/disable**. No custom authoring / query-builder UI / customer fact registry.
- [x] API transport (s4) → **stay REST; no GraphQL**. Borrow structured-filter/pagination ideas only if the inventory table needs them.

**Still open:**
- [ ] API naming: keep `/api/ai-security/*` or migrate toward `/api/ai-*` + `/api/ai-grid/*`? (integrator-facing; low urgency)
- [ ] GCP timing — deferred for now (near-term scope is AWS+Azure); revisit after Epic 4.
- [ ] Subject linkage detail (Epic 2): do AI artifacts register as first-class `assets`, or link opportunistically
  via nullable `ai_artifact_id` on `findings`? Plan currently assumes the latter — confirm during build.
- [ ] Migration lifecycle: remove the tenant `findings` compatibility loop from platform V59 by enforcing the
  existing production bootstrap before API startup and migrating `tenant_default` before JPA in PostgreSQL tests.
- [ ] Stale exposure workflow: decide whether an existing SLA-bound finding becomes `NEEDS_EVIDENCE`, pauses its
  SLA, or remains owner-actionable when validating evidence expires; expiry must not falsely resolve it.

---

## 8. Glossary / gotchas

- **AI Grid = AI Security = Scout AI Security** — same thing, different names across docs/code. Code namespace is `aisecurity`; product/spec name is "AI-GRID".
- **Two Flyway lines** — platform (`postgres_reset/`, startup) vs tenant (`tenant/`, applied by control plane). AI Grid tenant tables are in the tenant line; policy *distribution* is platform.
- **Tenant context before transaction** — background/scheduled AI Grid code must set tenant context before opening the tx (see root `backend/CLAUDE.md`); the job worker already does this via `TenantSchemaExecutionService.run(...)`.
- **Never edit applied migrations** — add new `V{next}` files in the correct line.
- **14 legacy/runtime registry policies today:** 5 AWS Bedrock + 9 Azure (registry `AiSecurityPolicyRegistry`);
  the governed platform catalog also includes newer R0/R1 policy versions outside that compatibility registry.
