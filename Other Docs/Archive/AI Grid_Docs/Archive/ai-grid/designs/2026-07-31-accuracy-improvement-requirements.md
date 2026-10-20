# AI Grid — Accuracy-Improvement Requirements (Bedrock + Azure)

**Date:** 2026-07-31 (session 7) · **Author:** Claude, on instruction from @karthik.gowri
**Status:** ratified framing; requirement register is the working backlog (keep updating).
**Consolidated 2026-08-01 (s8):** requirements are now organized by pipeline stage, one home each — **collection**
(former AR-1..9) moved to the two [Discovery Prerequisite Epics](2026-08-01-discovery-prerequisite-epics.md);
**computation** (AR-10/11/12) moved to the [Phase-2 catalog](2026-07-31-phase2-computation-plan.md) as P2-1/2/3.
This register now holds only **verdict-quality (AR-13..15)** + **structural (AR-16..18)**. AR IDs are retained
below as pointers so cross-links survive.
**Companions:** [`../known-limitations.md`](../known-limitations.md),
[`../evaluations/2026-07-31-connector-metadata-gap.md`](../evaluations/2026-07-31-connector-metadata-gap.md),
[`../evaluations/2026-07-31-policy-superset-matrix.md`](../evaluations/2026-07-31-policy-superset-matrix.md).

---

## 1. Framing (ratified session 7)

- **Scope = AWS Bedrock *and* Azure AI** (both providers, this release). Supersedes s6's "Bedrock first,
  Azure #2." Azure discovery + 8 policies already ship — fold them in rather than deprioritize them.
- **Coverage goal = *complete* coverage of every policy genuinely valid for AI artifacts in Bedrock + Azure**,
  mapped to **OWASP LLM Top 10 (2025)**. Not a Wiz clone, not all 260 Wiz rules, not generic CSPM.
  Scope is set by the **AI Security Attribution Rule** (s5): a rule is in scope iff it is attributed to an AI
  artifact and justified by that artifact's own config *or* a security-relevant relationship edge.
- **Wiz is inspiration, not the target.** Take the two-tier metadata idea, the enrichment-signal idea, and the
  graph-correlation idea — build a *more honest* product on top of them.
- **`NO_DECISION` is accepted and desirable.** It is not a failure to hide; it is the signal that tells us
  *where to go deeper on a specific control to improve accuracy.* **Every `NO_DECISION` must point to an
  owning accuracy requirement in §4 below.** A policy is allowed to ship returning `NO_DECISION` only if the
  requirement that would let it verdict is registered here.
- **Non-negotiable guardrail (s6):** the coverage UI/rollup must **never** present `NO_DECISION` as PASS. See
  [AR-18](#ar-18).

---

## 2. Why results are ever less than a clean PASS/FAIL

Four distinct causes. The first three produce `NO_DECISION`; the fourth produces a *possibly-wrong verdict*.
Each cause is closed by a requirement class in §4.

| # | Cause | Outcome | Closed by |
|---|---|---|---|
| C1 | **Fact not fetched** — connector doesn't collect the field the rule reads | `NO_DECISION` | Prerequisite epics P-AWS/P-AZ (collection) |
| C2 | **Derived signal not computed** — needs CIEM/DSPM/ASM the platform hasn't built | `NO_DECISION` | Phase-2 catalog P2-1/2/3 (computation) |
| C3 | **Scan couldn't read the resource** — permission missing, throttled, mid-provision | `NO_DECISION` (evidence-gated) | operational; surfaced, not silenced |
| C4 | **Single-field read is shallow** — fact fetched but doesn't capture the true control state | *wrong* PASS/FAIL | §4 Group C (deepen the control) |

C1/C2 are **scoping choices** — they exist only because we ship a policy ahead of its fact/capability, which we
now do *deliberately* so the `NO_DECISION` row advertises the accuracy work. C3 is unavoidable but *actionable*
("grant these scopes / re-scan"). **C4 is the one the user most cares about**: "go deep in a specific control"
means converting a shallow, sometimes-wrong verdict into a defensible one.

---

## 3. What no requirement can fix (accuracy ceilings — do not write requirements against these)

These are **hard limits of agentless config** (`known-limitations.md` #1, #2, #6). Policies touching them can
report **control-presence only**, never **control-efficacy**, and must be labelled that way in the UI so
"guardrail attached = PASS" is never mistaken for "jailbreak blocked."

- **Efficacy of a control** (does the guardrail actually block a jailbreak?) — behavioral. Caps honest coverage
  of **LLM01 (prompt injection), LLM04 (poisoning), LLM05 (improper output), LLM09 (misinformation)** to
  presence-of-control. Efficacy needs runtime/red-team — a deferred mechanism, out of scope.
- **Undiscoverable artifacts** — shadow AI, self-hosted models, SaaS AI, AI-in-source-not-deployed. No artifact
  → no finding. Needs runtime/DNS, host, SaaS-admin, source discovery planes.
- **Between-scan drift** — point-in-time scan; a control disabled right after a scan reads healthy until the
  next cycle. Needs runtime detection.

**These become explicit coverage-UI disclosures, not requirements.** They are why some OWASP categories will
always show "presence-only" even at full accuracy.

---

## 4. Accuracy-Requirement Register

IDs are stable (`AR-##`). Each requirement: the gap it closes, the policies/OWASP categories it upgrades, the
state today, what to build, and the accuracy outcome. **Bucket** ties to the feasibility matrix
(B = fetch more, C = new capability, A✎ = deepen an existing shallow verdict).

### Group A — Collection requirements → **moved to the Discovery Prerequisite Epics**

These "capture more metadata" requirements are Phase-1 collection and now live in
[`2026-08-01-discovery-prerequisite-epics.md`](2026-08-01-discovery-prerequisite-epics.md). IDs retained as pointers.

| ID | Requirement | New home |
|----|-------------|----------|
| AR-1 | Resource tags (both providers) | P-AWS · A1 / P-AZ · P-B |
| AR-2 | Generic full-config fetch per family (both) | P-AWS · A1/A7 / P-AZ · P-B |
| AR-3 | Guardrail PII / grounding / denied-topics | P-AWS · A2 |
| AR-4 | Model CMK + foundation-model LEGACY | P-AWS · A3 |
| AR-5 | KB data-source origin | P-AWS · A4 |
| AR-6 | Customization/Import-Job discovery (SageMaker/Comprehend → residual) | P-AWS · A5 |
| <a id="ar-7"></a>AR-7 | Azure content-filter / RAI policy config | P-AZ · P-A *(highest value)* |
| AR-8 | Azure private-link SKU / DLP / storage / bot-network | P-AZ · P-B |
| AR-9 | Copilot Studio agents | residual (SaaS-admin plane, phase-2 §8) |

### Group B — Computation requirements → **moved to the Phase-2 catalog**

AR-10/11/12 are Phase-2 *computations*, not collection — they live as **P2-1/2/3** in
[`2026-07-31-phase2-computation-plan.md`](2026-07-31-phase2-computation-plan.md). The **consumer-and-attributor**
principle (AI Grid owns the attribution layer, not the CIEM/DSPM/ASM capability) is recorded there and in
`CLAUDE.md` §4. IDs retained as pointers.

| ID | Signal | New home |
|----|--------|----------|
| <a id="ar-10"></a>AR-10 | CIEM-lite (effective permissions + trust policy) | P2-1 *(also fixes AR-13)* |
| AR-11 | DSPM / data classification | P2-3 |
| AR-12 | ASM validated reachability | P2-2 *(also fixes AR-15)* |

> AR-11/AR-12 (P2-3/P2-2) also gate **toxic-combination correlation** (P2-4 / Epic 5) — empty until they land.

### Group C — Deepen a shallow verdict (C4 → *correct* verdict) · bucket A✎ — "go deep in a control"

These rules **already fire** but on a single shallow field, so they carry false-positive/negative risk. This is
the core of the user's "improve accuracy / go deep in a specific control" intent.

| ID | Control today | Why it's shallow | Deepen to | Accuracy outcome |
|----|---------------|------------------|-----------|------------------|
| <a id="ar-13"></a>AR-13 | Agent role wildcard = `iamWildcardActions` (syntactic `*`) | Ignores permission boundaries, SCPs, resource scoping — a scoped `*` reads as over-privileged | Effective-permission set (via AR-10) | Removes false positives on boundaried roles |
| <a id="ar-14"></a>AR-14 | KB public S3 = `s3Public` (bucket-policy status only) | Ignores object ACLs + account Block-Public-Access — both FP and FN | Add ACL + account BPA read | Correct public/private verdict |
| <a id="ar-15"></a>AR-15 | Azure `publicNetworkAccess` flag | Flag ≠ reachable (WAF / private DNS / peering / NSG) | Reachability (via AR-12) | "Exposed" means exposed |

### Group D — Structural / operational accuracy (correctness of the *result set*, not one rule)

| ID | Requirement | Risk if unmet | Accuracy outcome |
|----|-------------|---------------|------------------|
| <a id="ar-16"></a>AR-16 | **Attribution + dedup rules** for shared dependencies (one bad bucket → 5 KBs = 1 finding or 5? owning node? whose SLA/owner?) | Finding counts + rollup are wrong; duplicate noise | Rollup and finding counts are trustworthy |
| AR-17 | **Technology-registry maintenance** (our CPE analog) | Misclassify a technology / vendor rename → Tier-B rules **silently don't fire** (FN, no error) | Prevents invisible coverage loss |
| <a id="ar-18"></a>AR-18 | **Coverage UI foregrounds the 5-way status** (PASS/FAIL/NO_RESOURCES/DISABLED/NO_POLICY + `NO_DECISION`); each `NO_DECISION` links its owning AR here | `NO_DECISION` read as PASS → coverage-as-safety (limitation #9, highest attention) | "Green" only ever means "checked and secure" |

---

## 5. OWASP LLM Top 10 — honest coverage after these requirements land

Shows what each category *can* reach with agentless config, and the accuracy ceiling from §3.

| OWASP (2025) | Config-assessable? | Requirements that raise it | Ceiling |
|---|---|---|---|
| LLM01 Prompt Injection | Presence only | AR-3 (Bedrock guardrail), **AR-7 (Azure content-filter/RAI)** | Efficacy = behavioral (§3) |
| LLM02 Sensitive Info Disclosure | **Yes** | AR-5, AR-7, AR-8, AR-11, AR-14 | AR-11 for severity |
| LLM03 Supply Chain | Partial | AR-4, AR-6 | Model-artifact scan deferred |
| LLM04 Data/Model Poisoning | Presence only | AR-4 | Efficacy = behavioral (§3) |
| LLM05 Improper Output Handling | Presence only | AR-3 | Efficacy = behavioral (§3) |
| LLM06 Excessive Agency | **Yes (strongest)** | AR-10, AR-13, AR-9, AR-8 | AR-10 for accuracy |
| LLM07 System Prompt Leakage | Weak | (config rarely exposes this) | Mostly behavioral |
| LLM08 Vector/Embedding Weakness | **Yes** | AR-5, AR-10, AR-11 | AR-11 for severity |
| LLM09 Misinformation | Presence only | AR-7 (groundedness) | Efficacy = behavioral (§3) |
| LLM10 Unbounded Consumption | Partial | (quota/throttle config where fetched) | — |

**Takeaway:** LLM02, LLM06, LLM08 are where agentless config delivers *real FAIL verdicts*; LLM01/04/05/09 are
**presence-only by nature** and must be labelled so. The requirement work above is what moves the assessable
categories from `NO_DECISION` to accurate verdicts.

---

## 6. How this plugs into the epics (post-consolidation)

- **Collection (AR-1..9)** → the two **Discovery Prerequisite Epics** (P-AWS, P-AZ). A refinement of Epic 4.
- **Computation (AR-10/11/12)** → the **Phase-2 catalog** (P2-1/2/3); consumer-and-attributor principle applies.
- **Verdict-quality (AR-13/14/15)** stay here: AR-13 rides on P2-1 (effective perms), AR-15 on P2-2
  (reachability), AR-14 is standalone (S3 ACL + account Block-Public-Access read).
- **Structural (AR-16/17/18)**: AR-16 (attribution/dedup) → Epic 1; AR-18 (5-way coverage UI) → Epic 3;
  AR-17 (technology-registry) → cross-cutting.
- **Epic 0** enforces that every `NO_DECISION` carries an owning requirement (prereq epic / P2 / AR).
- **§3 ceilings** become coverage-UI disclosures, not backlog items.

---

## 7. Open decisions

- [ ] Per-provider release gate: do we ship a provider once its **Group A + Group C** are done (Group B rows
  live as `NO_DECISION`), or hold until AR-10 (CIEM) lands? (Leaning: ship on A+C; CIEM rows advertise as
  `NO_DECISION`.)
- [ ] AR-11 DSPM: coarse proxy now vs explicit defer.
- [ ] The concrete **per-policy catalog** (every Bedrock + Azure AI rule → OWASP → required facts → AR link) is
  the next artifact; this register defines the accuracy columns it will reference.
