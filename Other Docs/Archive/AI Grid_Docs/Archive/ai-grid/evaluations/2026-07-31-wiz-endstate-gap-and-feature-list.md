# AI Grid — Wiz End-State Gap Analysis & Feature List

**Date:** 2026-07-31 (session 2) · **Author:** Claude · **For:** @karthik.gowri
**Target evaluated against:** `WIZ-AI-Security-Reverse-Engineered-PRD (1).md` — adopted as **end state in spirit, not exact spec**.
**User's near-term vision:** AWS + Azure agentless discovery → rich metadata → platform-level workflows
(owner, relationships, criticality, hygiene recommendations) → **scalable policy engine + policy catalog**
assessed across the AI inventory → violations captured in **AI Findings**. Wants the Wiz policy catalog loaded.

---

## What Wiz is (target in spirit)

CNAPP-layered AI module: 7 validation mechanisms (agentless config scan, graph correlation, static
model-artifact scan, SAST, network probing, CIEM identity graph, runtime sensor); ~22 AI-aware resource
types; **260 AI-tagged rules** (25 Model, 37 Agent, 10 MCP, 16 Attack-Surface, 89 SAST, 79 Cloud-Misconfig,
4 AI-Identity); graph-based **toxic-combination** correlation; **OWASP LLM Top 10 (2025)** compliance
dashboard with a 3-way pass/fail/not-applicable status distinction.

## Conformance snapshot (AI Grid today vs Wiz spirit)

| Wiz domain / mechanism | AI Grid today | Gap |
|---|---|---|
| Agentless AWS+Azure config scan | ✅ Bedrock + Azure AI/Foundry/ML/Search/Bot | GCP absent (ok) |
| AI inventory / typed resources | 🟡 ~4 collapsed types + 21-edge relationship graph | Taxonomy too coarse for rule targeting |
| Scalable policy engine / catalog | 🔴 **hardcoded `switch` + hardcoded `List`** | Biggest blocker — cannot load a large catalog |
| Cloud-misconfig coverage (48 AWS+Azure) | 🔴 13 policies | Coverage + engine can't scale to load them |
| Owner per artifact | 🔴 none | Blocks "who owns it" |
| Criticality / blast radius | 🔴 none | Blocks prioritization |
| Relationships graph | 🟢 present, unused for correlation | Underexploited |
| Toxic-combination correlation | 🔴 none | Needs graph + sensitivity/vuln edges (host already has these) |
| OWASP LLM Top 10 compliance | 🔴 ad-hoc CIS/AZURE strings | No framework rollup / dashboard |
| AI Identity / CIEM | 🟡 one wildcard-role check | Needs effective-permission resolution |
| AI Findings → security workflow | 🔴 **separate silo `ai_security_findings`** | No owner/SLA/ServiceNow/suppression |
| Model scan / SAST / attack-surface / MCP / runtime | 🔴 none | New mechanisms — deferred |

## What went well

- Discovery + ingestion spine is Wiz-shaped: agentless read-only scan, `ObservationEnvelopeV1`
  (idempotency + chunking), per-scope completeness tracking, **21-type relationship graph** (the substrate
  Wiz correlation needs — nodes + edges already exist).
- Evidence-gated evaluation (`NO_DECISION`/`NOT_APPLICABLE`) maps directly to Wiz's 3-way status (§7).
- Multi-tenancy, forced RLS, credential ciphertext + rotation, per-run audit — production-grade, up front.

## What's not working

1. **Policy engine is not scalable** — `AiSecurityPolicyEvaluationService.evaluate()` is a `switch(policyId)`
   with a hardcoded Java branch per policy; `AiSecurityPolicyRegistry` is a hardcoded `List`. One rule =
   Java in ~4 places. Cannot load 48 (let alone 260) rules. **Fails the "scalable policy engine" requirement.**
2. **Artifacts carry no owner / criticality / attack-surface** → the platform workflows the user wants can't run.
3. **AI Findings are a silo** → no ownership assignment, SLA clocks, ServiceNow, suppression, auto-close.
4. **No framework mapping / compliance view** (OWASP LLM Top 10).
5. **Taxonomy too coarse** to target rules per resource type.

## Corrections (must-fix before scaling)

- Make the policy engine data-driven (Epic 0). Everything depends on it.
- Graduate AI findings into the host `Finding` workflow (Epic 2) — the unlock for owner/SLA/ServiceNow/criticality.
- Adopt OWASP LLM Top 10 + CWE as the mapping taxonomy (Epic 3), not CIS strings.

---

## Feature list (epics, dependency-ordered)

- **Epic 0 — Data-driven policy engine + catalog** *(foundational)*: `platform.ai_policy_catalog` (declarative
  rules), normalized per-artifact fact model, generic predicate evaluator replacing the `switch`; preserve
  `NO_DECISION` evidence gating. Migrate the 13 existing rules to rows.
- **Epic 1 — Artifact metadata**: owner, criticality, tags, exposure/attack-surface on `ai_security_artifacts`;
  owner-resolution via existing `OwnershipRuleService` pattern (tag → account alias → rules); unowned ⇒ finding;
  criticality derived from exposure + data sensitivity + linked-asset `business_criticality`.
- **Epic 2 — Graduate AI Findings into host workflow**: project violations into host `Finding`
  (`FindingCreationSource.AI_SECURITY` + `ai_artifact_id`), reusing `OwnershipRuleService`, `FindingSlaService`,
  `ServiceNowIncidentService`, delta queue, suppression, auto-close.
- **Epic 3 — Framework mapping + compliance posture**: OWASP LLM01–09 + CWE tags on catalog; posture % + category
  rollup + 5-way status (PASS/FAIL/NO_RESOURCES/DISABLED/NO_POLICY); `GET /api/ai-security/compliance` + dashboard.
- **Epic 4 — Load Wiz AWS+Azure catalog (declarative)**: 24 AWS + 24 Azure cloud-misconfig + cloud-native
  Agent/Guardrail/Model-config + 4 AI-identity rules as catalog rows. Real work = connector fact enrichment per
  resource family + CIEM-lite effective-permission resolution for identity rules; expand taxonomy
  (`AI_GUARDRAIL`, `AI_GATEWAY`, `AI_DATASTORE`, `AI_IDENTITY`).
- **Epic 5 — Cross-resource correlation (toxic combinations)**: graph evaluator promoting entry-point AND
  lateral-access AND value co-occurrence to Critical; reuse host CVE findings + asset sensitivity; new
  `ai_security_correlated_issues`.
- **Deferred (new mechanisms, later phases):** model-artifact static scan (A.1), SAST AI code rules (A.5),
  attack-surface network probing (A.4), MCP risk (A.3), runtime/shadow-AI (§8), GCP.

## Decisions taken this session

1. **Adopt the Wiz PRD as the end-state-in-spirit** north star (alongside, and superseding in ambition, the
   original scope PDF).
2. **Graduate AI findings fully** into the host workflow — via a **strangler pattern** (feature-flagged behind
   the disabled-by-default `ai.security` entitlement; AI artifact links to an `asset` where one exists, else a
   lightweight AI subject; AI-specific evidence in a side table; old `ai_security_findings` retired after parity).
3. **Sequence as one data-driven vertical slice** through Epics 0→1→2→3 (piloting a single rule —
   *Bedrock Guardrail below MEDIUM strength* → owner + criticality → host Finding w/ SLA/ServiceNow → OWASP
   LLM06 tag on a compliance view), **then breadth via Epic 4**. Front-loads architectural risk into the
   smallest unit; Epic 4 becomes pure content afterward.

Detailed build plan: [`../designs/2026-07-31-vertical-slice-implementation-plan.md`](../designs/2026-07-31-vertical-slice-implementation-plan.md).
