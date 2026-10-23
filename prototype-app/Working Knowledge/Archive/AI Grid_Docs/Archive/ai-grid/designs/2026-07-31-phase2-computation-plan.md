# AI Security — Phase Model: Phase 1 Collection / Phase 2 Computation

**Date:** 2026-07-31 (session 7) · **Author:** Claude, on instruction from @karthik.gowri
**Status:** draft plan for discussion.
**Companions:** [`2026-07-31-accuracy-improvement-requirements.md`](2026-07-31-accuracy-improvement-requirements.md),
[`2026-07-31-vertical-slice-implementation-plan.md`](2026-07-31-vertical-slice-implementation-plan.md),
[`../known-limitations.md`](../known-limitations.md).

---

## 1. The two phases

- **Phase 1 — Collection.** Gather raw facts from provider sources (AWS, Azure, later others). I/O-bound,
  provider-specific, no interpretation. Populates the normalized fact model. *The connectors are already built;
  Phase 1's remaining work is to broaden from rule-specific fields to complete primitives + history (see §4).*
- **Phase 2 — Computation.** Derive security signals **from Phase 1 data**, and attribute each to an AI artifact.
  Pure functions over normalized facts — no new provider I/O (except where a signal requires a *new collection
  source*, which is Phase 1 work, not Phase 2). Scope is **open in mechanism** (not limited to CIEM/ASM/DSPM) but
  **bounded by attribution** (§3).

**The phase boundary is a data contract, not a release gate.** Phase 2 signals light up incrementally as Phase 1
collects the primitive each one needs:

```
Phase 1  collect  →  normalized facts        (provenance: OBSERVED, source, scope-complete?)
Phase 2  derive   →  derived facts / signals  (provenance: DERIVED, confidence, inputs[])
Engine   evaluate →  policy verdict           (reads OBSERVED + DERIVED facts uniformly)
```

This is the Epic 0 fact model split into producer (Phase 1) and consumer (Phase 2). Nothing here replaces Epic 0
— it *is* Epic 0, viewed as a pipeline.

---

## 2. Four principles (the refinements that keep it honest)

1. **Phase 1 collects primitives, not rule-specific fields.** Full IAM policy + trust-policy documents, complete
   network config, tags, and **point-in-time snapshots retained over time** — so Phase 2 can compute things no
   single rule asked for yet (incl. drift). (Generalizes AR-2 into a Phase-1 rule.)
2. **Every Phase 2 signal is attributed to an AI artifact.** Open mechanism, bounded scope: compute over the
   *AI attribution subgraph* (AI-artifact identities / AI-reachable data / AI endpoints + their dependency edges),
   never the whole estate. A signal that can't be attributed to an AI artifact is out of scope (that's CSPM).
   (s5 + s7.)
3. **Derived ≠ observed.** Every derived fact carries `confidence` + the `inputs[]` it was computed from. The
   coverage UI distinguishes an *observed* FAIL from a *derived* FAIL; low-confidence derivations degrade to
   `NO_DECISION` rather than assert. (Extends the `UNKNOWN`-aware model to computed facts.)
4. **Some signals need a new *collection source*, not a computation.** Data sensitivity (DSPM) is the archetype:
   it is not derivable from config we hold — it requires ingesting a classification service (Macie/Purview) as a
   **Phase 1 source**, or an explicit defer. Don't file these as Phase 2 computations.

---

## 3. Scope guardrail — "beyond CIEM/ASM/DSPM," still AI security

Phase 2 is deliberately **not** limited to the three named industry categories. The underlying primitive is
*"derive a security signal from collected facts and attribute it to an AI artifact."* Many general-security
concepts fit that primitive. What keeps them AI security is **principle 2 (attribution)**, not the mechanism.
AI Grid remains a **consumer and attributor** — it owns the attribution layer + the thin computation, and
consumes external capability outputs (Macie/Access Analyzer/Defender) where they exist.

---

## 4. Phase 1 — what collection must produce (drives collection backward from Phase 2)

| Primitive | Provider call(s) | Status today | Needed by (Phase 2) |
|---|---|---|---|
| Full IAM policy documents (attached + inline + boundary) | `Get/ListRolePolicy`, `GetPolicyVersion` | ✅ fetched (used syntactically) | Effective-permission, privilege, secrets-reach |
| IAM **trust policy** (assume-role conditions) | `GetRole` | ❌ | Confused-deputy, cross-account trust |
| Complete network config (SG/NSG, public IP, route, private endpoint) | EC2/Azure network describes | ⚠️ flags only | Reachability/exposure |
| Resource **tags** (all families) | per-resource | ❌ (AR-1) | Ownership attribution, environment |
| CMK / key config + key policy | KMS / Key Vault | ⚠️ partial | Encryption posture, key-access |
| **Point-in-time snapshots retained** (fact history) | (storage concern) | ❌ | Drift detection |
| Data-classification findings | **Macie / Purview** (new source) | ❌ | Data sensitivity (DSPM) — principle 4 |
| Relationship edges (already strong: 21 edges) | discovery | ✅ | Correlation / toxic combinations |

**Takeaway:** Phase 1 is *not done* — it must move from "fields the rules read" to "complete primitives + tags +
trust policies + snapshot history," and (if we pursue DSPM) add Macie/Purview as a collection source.

---

## 5. Phase 2 — computation catalog (open-ended, attribution-bounded)

Each computation: input facts (from Phase 1) → derivation → AI attribution → OWASP. First three are the former
"Group B"; the rest are the "beyond."

| # | Computation | Input facts (Phase 1) | Derives | AI attribution | OWASP |
|---|---|---|---|---|---|
| P2-1 | **Effective permissions** (CIEM-class) | full policy docs (+ boundary) | is the identity effectively admin / over-privileged (not syntactic) | agent execution role / managed identity | LLM06, LLM08 |
| P2-2 | **Reachability / exposure** (ASM-class) | network config; (later Defender EASM) | is the AI endpoint actually internet-reachable | AI endpoint / agent alias / gateway | LLM06, LLM02 |
| P2-3 | **Data sensitivity** (DSPM-class) | **Macie/Purview findings (P1 source)** | does the AI-reachable store hold sensitive data | KB / vector store / training bucket | LLM02, LLM08 |
| P2-4 | **Cross-resource correlation** (toxic combinations) | derived P2-1..3 + edges | reachable + over-privileged + sensitive-data chains | the AI system (multi-artifact) | LLM06, LLM02, LLM08 |
| P2-5 | **Trust-boundary analysis** | trust policies, account/tenant ids | cross-account/cross-tenant assume-role, confused deputy | agent identity + its trust edges | LLM06 |
| P2-6 | **Encryption & key posture** | CMK config + key policy | at-rest encryption + who can use the key | model / KB / store | LLM02, LLM03 |
| P2-7 | **Guardrail-coverage composition** | model-invocation paths + guardrail edges | does *every* path to a model enforce a guardrail (not just "one attached") | agent / application | LLM01, LLM05 (presence-only ceiling) |
| P2-8 | **Secrets exposure** | policy docs + secret refs + edges | can the agent read a secret that feeds it | agent identity | LLM06, LLM02 |
| P2-9 | **Supply-chain / model lineage** | model provenance, import jobs, CMK/LEGACY | untrusted/stale model origin | model artifact | LLM03, LLM04 (presence-only) |
| P2-10 | **Drift detection** | **snapshot history** | a control was disabled/loosened since last scan | any AI artifact | (cross-cutting) |
| P2-11 | **Blast-radius / criticality propagation** | host asset criticality + edges | how bad if this AI artifact is compromised | AI artifact + linked assets | (scoring input) |

The list is intentionally extensible — new computations are catalog additions, not architecture. Anything that
*(a)* computes over collected facts and *(b)* attributes to an AI artifact qualifies.

---

## 6. Sequencing within Phase 2

Ordered by *inputs-already-collected* and value:

1. **P2-1 Effective permissions** — inputs already fetched (policy docs); highest value; fixes the syntactic
   wildcard accuracy bug (AR-13). Self-contained. **First.**
2. **P2-5 Trust-boundary** + **P2-8 Secrets** — small extensions once trust policies are collected.
3. **P2-2 Reachability** — config-proxy now (inputs present), validated later via Defender EASM/Reachability Analyzer.
4. **P2-6 Encryption**, **P2-7 Guardrail-coverage**, **P2-9 Lineage** — modest computations on P1 config.
5. **P2-10 Drift** — unlocks once snapshot history exists.
6. **P2-3 Data sensitivity** — gated on the Macie/Purview collection source (principle 4); proxy-or-defer.
7. **P2-4 Correlation** — *last*; needs P2-1/2/3 populated or it's empty (limitation #3).

---

## 7. Architecture notes

- **A derivation service** reads normalized facts for a discovery run and writes derived facts (idempotent,
  re-runnable per snapshot). No provider I/O in Phase 2.
- **Fact provenance model:** `{value, provenance: OBSERVED|DERIVED, source, confidence, inputs[], observedAt}`.
  Policies read facts uniformly; the engine already returns `NO_DECISION` when a required fact is `UNKNOWN` /
  below a confidence floor.
- **Consumer/attributor stays intact:** where a provider service (Macie/Access Analyzer/Defender) supplies the
  derived signal, Phase 1 *collects its finding* and Phase 2 *attributes* it — AI Grid does not recompute it.
- **Tenant context before tx** for any batch derivation job (root `backend/CLAUDE.md` rule).

---

## 8. Residual / deferred scope (moved here s8)

Explicitly **out of this release's boundary** (Bedrock-proper + ARM-managed Azure AI), parked here with reasons
and priority so the completeness claim stays bounded and these aren't forgotten:

- **AWS AI beyond Bedrock** — SageMaker → Amazon Q / Kendra → Comprehend/others. **SageMaker first**: the
  training/fine-tuning and model-hosting surface (OWASP **LLM04** poisoning, LLM03) genuinely lives there, so a
  Bedrock-only release shows LLM04 as thin *by design* — accepted, shown honestly, closed later by SageMaker.
  This is framework **#3**.
- **Azure Copilot Studio + the SaaS-AI-admin discovery plane** (scope PDF plane 4) — a *different discovery
  mechanism* (Power Platform / Dataverse APIs, different auth + tenancy), not a policy. High value
  (citizen-developer / shadow-agent risk); the flagship for the SaaS-admin plane when we build it.
- **Other deferred discovery planes** (source/CI incl. MCP, runtime OTLP, GCP) — already tracked in
  `CLAUDE.md` §6 "Deferred."

**Architecture guardrail:** keep the artifact-type axis **provider-neutral** (`AI_MODEL`, `MODEL_ENDPOINT`,
`TRAINING_JOB`, `PROMPT_ASSET`, `AI_IDENTITY`) so SageMaker and others slot in as *content, not architecture*.

## 9. Open questions

- [ ] DSPM: commit to a Macie/Purview collection source (P1) now, or defer P2-3 and ship it as `NO_DECISION`?
- [ ] Snapshot history: how much retention for drift (P2-10) — every run, or daily deltas?
- [ ] Do P2 derived facts persist per-snapshot (auditable history) or only latest? (Leaning per-snapshot.)
- [ ] Is P2-11 blast-radius a Phase 2 fact or a scoring-layer concern (Epic 3)? (Likely scoring consumes it.)
- [ ] Release gate: ship a provider on Phase 1 + P2-1/2 (proxy), with P2-3/4 as `NO_DECISION`? (Leaning yes.)
