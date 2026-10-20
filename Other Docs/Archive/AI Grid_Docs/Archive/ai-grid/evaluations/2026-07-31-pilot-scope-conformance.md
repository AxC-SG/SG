# AI Grid — Pilot Scope-Conformance Evaluation

**Date:** 2026-07-31 · **Author:** Claude · **For:** @karthik.gowri
**Spec evaluated against:** `AI-Security-Final-Scope (1).pdf` — "Scout AI Security — AI-GRID Module" (prepared 2026-07-26)
**Code evaluated:** `com.prototype.vulnwatch.aisecurity` (backend), `frontend/src/features/ai-security` + AI pages,
migrations platform `V47–V49` / tenant `V45–V47`.

---

## What was actually built

A **deliberately narrowed, production-disciplined pilot**: read-only discovery + deterministic policy
assessment for **two cloud planes only — AWS Bedrock and Azure AI/Foundry/ML/Search/Bot**. It lives in an
isolated `aisecurity` bounded context, gated behind an `ai.security` entitlement that ships **disabled by
default**, with an explicit pilot-readiness gate doc, coverage/precision gates, and a soak procedure before
any tenant is turned on.

This is genuinely good engineering. It is also **materially different from the reconciled target
architecture** in the load-bearing parts. That gap is the core of this review.

---

## Conformance against the 12 scope sections

| # | Scope section | Status | Notes |
|---|---|---|---|
| 1 | Objective (read-only discovery + assessment, route into workflows) | 🟡 Partial | Read-only ✅. "Route into existing security workflows (ownership, SLA, ticketing)" ❌ — AI findings live in a **separate silo**, not the host findings workflow. |
| 2 | Canonical 17-type artifact taxonomy | 🔴 Diverged | Collapsed to ~4 types (`AI_AGENT`, `AI_MODEL`, `KNOWLEDGE_BASE`, `OTHER_AI_ARTIFACT`, `ACCOUNT_CONFIGURATION`). No `MCP_SERVER`, `AI_GATEWAY`, `VECTOR_STORE`, `PROMPT_ASSET`, `AI_DEPENDENCY`, `EVALUATION_RUN`, `ADVISORY`, etc. |
| 3 | Six discovery planes | 🔴 2 of 6 | Cloud (AWS+Azure) only. No GCP (scope: v1 target), direct-provider APIs (OpenAI/Anthropic/HF), source/CI scan, SaaS Copilot, standalone identity plane, or runtime. |
| 4 | Data model (`ai_sources`…`ai_asset_findings` + platform rule catalog/rollups) | 🟡 Conceptual match | `ai_security_*` tables map conceptually. Platform-owned `ai_security_policy_distribution` ✅. No `prompt_hash` snapshot model, no `platform.ai_tenant_risk_rollups`. |
| 5 | Capability normalization + 9-dim weighted catalog + 3-level scoring + posture/blast-radius | 🔴 **Not implemented** | **Biggest gap.** No capability flags; no dimensions/multipliers; no finding/asset/tenant scoring; no posture (A–F) or blast radius. Policies read raw provider attributes directly. |
| 6 | Governance (owner-required, OWASP/ATLAS/NIST/EU-AI-Act, AI-BOM, findings graduate into host workflow) | 🔴 Mostly missing | Ad-hoc `controlMappings` (CIS/AWS/AZURE + two NIST tags), **not** OWASP LLM Top 10 / MITRE ATLAS. No CycloneDX ML-BOM export. Findings not graduated. |
| 7 | Runtime telemetry (OTLP ingest, trace correlation, `UNKNOWN_RUNTIME_AI_ASSET`) | 🔴 Not implemented | No OTLP endpoint. |
| 8 | Multi-tenancy & security | 🟢 **Strong** | Schema isolation + forced RLS on every table ✅; credential *references*/ciphertext only ✅; assumed/short-lived creds + rotation ✅; every run audited ✅. |
| 9 | API surface | 🔴 Diverged | Ships `/api/ai-security/*`, `/api/connectors/ai-security/*`, `/api/platform/ai-security/*`. Scope specified `/api/ai-sources`, `/api/ai-assets`, `/api/ai-risk-summary`, `/api/ai-rules`, `/api/ai-runtime/otlp`, `/api/platform/ai-grid/*`. |
| 10 | Out-of-scope discipline (no enforcement/remediation/red-team/training-gov) | 🟢 Fully honored | All four deferrals respected. |
| 11 | Phased delivery | 🟡 ~Phase 1–2 partial | Discovery core (AWS+Azure subset) + a *simpler* assessment engine. Missing full catalog, scoring, runtime, compliance, surface expansion. |
| 12 | Definition of done | 🟡 Partly unmeetable | Connectors-on-schedule-with-health ✅; evidence-completeness gating ✅. But "correct OWASP mapping" and "**tenant risk rollup changes predictably**" **cannot be satisfied — there is no rollup score.** |

---

## What went well

- **Discovery pipeline architecture exceeds the scope's rigor.** The `ObservationEnvelopeV1` contract
  (idempotency key + content hash + chunk sequencing), per-scope `COMPLETE/PARTIAL/FAILED/UNSUPPORTED`
  tracking, and the connector→envelope→shared-ingestion handoff are exactly the "connectors only normalize
  and hand off" boundary the scope wanted.
- **Evidence-gated evaluation is a highlight.** `AiSecurityPolicyEvaluationService` refuses to decide
  (`NO_DECISION`) unless every required snapshot scope is `COMPLETE`. Directly serves the precision/coverage
  gate; more disciplined than most CSPM engines. **Preserve this through any refactor.**
- **Multi-tenancy and credential handling fully match §8** — forced RLS on 10+ tables, ciphertext-only
  secrets, rotation lifecycle, kill switches, per-run auditing. The hardest part to retrofit, done right up front.
- **Production discipline is exemplary** — disabled-by-default entitlement, shadow→enforce rollout, the
  `ai-security-pilot-readiness.md` gates (100% decision coverage for CRITICAL, 95% precision per family,
  7-day soak).
- **Clean UI slice with tests** — Inventory, Findings, Policies + detail, connector setup, overview strip.

## What is not going well

1. **The capability-flag normalization layer is absent — most consequential divergence.** Scope calls it
   *"the architectural boundary between discovery and assessment… the rule engine only ever reads flags,
   never raw payloads."* Today policies read provider-specific attributes (`s3Public`, `localAuthEnabled`,
   `codeInterpreterEnabled`). Every new provider needs its own provider-specific policies — the N×M
   explosion the flag abstraction exists to prevent. Fine at 2 providers / 13 policies; unmaintainable at 6 planes.
2. **No scoring model at all.** No finding/asset/tenant math, no posture grade, no blast radius. The product's
   stated objective is *"scores risk at the artifact and organization level"* — currently a flat findings list
   with static per-policy severities. One DoD criterion (rollup moves predictably) is literally unmeetable.
3. **Framework mapping isn't the promised one.** Buyers expect OWASP LLM Top 10 + MITRE ATLAS; code has
   ad-hoc CIS/cloud control strings.
4. **AI findings are a bolted-on separate view** — the one thing §6 explicitly said not to do. Own table,
   status enum, and review model rather than graduating into host ownership/SLA/ServiceNow.
5. **Scope-vs-code drift is undocumented.** Divergence on taxonomy, API contract, dimensions, and scoring,
   with nothing recording that the narrowing was intentional.

---

## Next items to focus on (recommended priority)

**Decide first:** Is the shipped AWS+Azure pilot the intended **v1 as-is**, or a **stepping stone** to the
reconciled scope? Recommendation: treat it as the pilot it is, keep shipping to design partners, **but insert
the capability-flag layer and scoring now** — both get exponentially more expensive after a third provider lands.

1. **Introduce capability normalization before the 3rd connector.** Map each provider's raw attributes into
   the fixed boolean flag set at ingestion; rewrite the 13 policies to read flags. Highest-leverage correction.
2. **Build the scoring layer** (finding → asset → tenant rollup + posture and blast-radius lenses over the
   same findings). Unblocks the core value prop *and* the DoD gate. Persist it.
3. **Reconcile framework mapping** to OWASP LLM Top 10 (2025) + MITRE ATLAS tactic tags + NIST AI RMF function
   tags. Mostly a data exercise on the existing policy registry.
4. **Graduate AI findings into the host findings workflow** (or consciously keep separate and amend the scope).
5. **Later phases, in scope order:** source-code/CI plane (`MCP_SERVER` discovery lives here) → runtime OTLP
   ingest + `UNKNOWN_RUNTIME_AI_ASSET` → CycloneDX ML-BOM export → GCP + direct-provider APIs.

## Should something be corrected

- **Reconcile spec and code deliberately.** Move code toward the scope on the four structural items
  (taxonomy, capability flags, scoring, API naming), or revise the scope doc to declare the pilot narrowing
  intentional. A reader currently can't tell "not built yet" from "decided against."
- **Fix the unmeetable DoD gate.** `ai-security-pilot-readiness.md` and §12 require the tenant rollup to move
  when a seeded misconfig is fixed. With no rollup, that gate can't be evaluated — build the rollup (preferred)
  or amend the gate before it blocks pilot sign-off on a technicality.
- **Rename/alias the API surface** toward the `ai-*` contract, or update the contract doc.

## Overall feedback

A **well-built, honestly-scoped pilot** with excellent discovery plumbing, exemplary multi-tenant/credential
security, and disciplined rollout gating — the parts hardest to get right and hardest to retrofit are done
well. Where it falls short is the **conceptual core of the reconciled scope**: the capability-flag boundary,
the 9-dimension weighted rule catalog, and the three-level scoring with posture/blast-radius lenses. Those
aren't polish — they're the thesis of "one inventory, one rule engine, two lenses," and their absence is why
the product is currently a per-provider AI CSPM rather than the estate-wide AI risk platform the scope
describes.

**Net:** keep shipping the pilot, but land the capability-flag layer and the scoring model before the third
connector, and make the scope-vs-implementation divergence an explicit, recorded decision rather than silent drift.
