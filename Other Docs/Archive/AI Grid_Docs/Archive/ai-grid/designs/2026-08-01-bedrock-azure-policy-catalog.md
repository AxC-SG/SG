# AI Security — Bedrock + Azure Policy Catalog (OWASP LLM Top 10)

**Date:** 2026-08-01 (session 8) · **Author:** Claude, on instruction from @karthik.gowri
**Status:** draft catalog — the per-policy artifact the accuracy register + phase plan were built to feed.
**Regenerated 2026-08-01 (s8):** folded in the 21 coverage-matrix gap candidates (BR-20..28, AZ-23..34) so the
catalog now agrees with [`2026-08-01-coverage-matrix.md`](2026-08-01-coverage-matrix.md); superset = **~62**.
Collection prerequisites are the two **Discovery Prerequisite Epics** — **P-AWS** (Bedrock gaps BR-20..28) and
**P-AZ** (Azure gaps AZ-11/12/23..34; workstreams P-A/P-B/P-C). See
[`2026-08-01-discovery-prerequisite-epics.md`](2026-08-01-discovery-prerequisite-epics.md).
**Companions:** [`2026-07-31-accuracy-improvement-requirements.md`](2026-07-31-accuracy-improvement-requirements.md)
(AR-##), [`2026-07-31-phase2-computation-plan.md`](2026-07-31-phase2-computation-plan.md) (P2-##),
[`../evaluations/2026-07-31-policy-superset-matrix.md`](../evaluations/2026-07-31-policy-superset-matrix.md).

---

## 1. Purpose & how to read

Complete coverage of every policy **valid for AI artifacts** in AWS Bedrock and Azure AI, mapped to **OWASP LLM
Top 10 (2025)**. Scope is set by the **Attribution Rule** (s5): each policy is attributed to an AI artifact and
justified by its own config or a relationship edge — no generic CSPM. Not a Wiz clone; not all 260 Wiz rules.

**Columns:** `ID` (stable BR-##/AZ-##) · `Policy` · `Sev` · `Artifact` · `OWASP` · `Required fact(s)` ·
`Eval today`.

**Eval-today legend:**
- 🟢 **VERDICT** — ships a real PASS/FAIL now (fact collected in Phase 1).
- 🔵 **VERDICT\*** — verdicts now but on a *shallow* field (accuracy tail → owning AR/P2 to deepen).
- 🟡 **NO_DECISION → B** — needs a Phase-1 **fetch** (collect more) before it verdicts.
- 🟠 **NO_DECISION → C** — needs a Phase-2 **computation** or a new collection source before it verdicts.
- ⚪ **NO_ARTIFACT** — resource type not discovered yet (needs new discovery scope).

Presence-only ceiling (§3 of accuracy doc): LLM01/04/05/09 policies assert *control presence*, never *efficacy*.
Labelled `(presence)`.

Every 🟡/🟠/⚪ row **must** carry an owning `AR-##`/`P2-##` (the s7 rule: no `NO_DECISION` without a requirement).

---

## 2. Coverage summary

| | Bedrock | Azure | Total |
|---|---|---|---|
| Shipped policies (in registry) | 5 | 8 | **13** |
| 🟢/🔵 Verdict now | 7 | 10 | **17** |
| 🟡 NO_DECISION → B (fetch / discovery) | 10 | 17 | **27** |
| 🟠 NO_DECISION → C (compute / consume) | 5 | 5 | **10** |
| ⚪ New artifact / scope | 6 | 2 | **8** |
| **Superset total** | **28** | **34** | **62** |

Bucket splits are approximate where a row needs *both* discovery and compute. **17 verdict now** (blocked only by
making the engine data-driven); the rest advertise their owning requirement (`AR-##` / `P2-##` / prerequisite
epic `P-A/B/C`) as `NO_DECISION` — the s7 rule holds for all 62 rows.

---

## 3. Bedrock catalog (BR-1 … BR-19)

| ID | Policy | Sev | Artifact | OWASP | Required fact(s) | Eval today |
|----|--------|-----|----------|-------|------------------|-----------|
| BR-1 | Public knowledge-base S3 source *(shipped: `AWS_BEDROCK_PUBLIC_KB_S3`)* | CRIT | KNOWLEDGE_BASE | LLM02, LLM08 | `s3Public` | 🔵 VERDICT\* → AR-14 (ACL+BPA) |
| BR-2 | Unauthenticated action-group Lambda URL *(shipped)* | CRIT | AI_AGENT | LLM06 | `lambdaUrlAuthType` | 🟢 VERDICT |
| BR-3 | Wildcard agent execution-role actions *(shipped)* | HIGH | AI_AGENT | LLM06, LLM08 | `iamWildcardActions` (syntactic) | 🔵 VERDICT\* → P2-1/AR-13 (effective) |
| BR-4 | Weak attached guardrail strength *(shipped)* | HIGH | AI_AGENT | LLM01 (presence), LLM05 | `guardrailAttached`, `guardrailMinimumStrength` | 🟢 VERDICT |
| BR-5 | Model invocation logging disabled *(shipped)* | MED | ACCOUNT_CONFIG | LLM (detection support) | `invocationLoggingEnabled` | 🟢 VERDICT |
| BR-6 | No guardrail attached to agent | HIGH | AI_AGENT | LLM01 (presence), LLM05 | `guardrailAttached=false` | 🟢 VERDICT |
| BR-7 | Agent inactive / missing service role | MED | AI_AGENT | LLM06 | agent `status`, `executionRoleArn` | 🟢 VERDICT |
| BR-8 | Guardrail PII / grounding / relevance not configured | HIGH | AI_AGENT | LLM02, LLM09 | guardrail PII list, grounding cfg | 🟡 → AR-3 |
| BR-9 | KB uses external / non-owned data source | HIGH | KNOWLEDGE_BASE | LLM02, LLM08 | data-source origin | 🟡 → AR-5 |
| BR-10 | Model not CMK-encrypted / foundation LEGACY | MED | AI_MODEL | LLM03, LLM04 (presence) | model CMK, lifecycle | 🟡 → AR-4 |
| BR-11 | Agent execution role has **effective admin** | CRIT | AI_AGENT / AI_IDENTITY | LLM06, LLM08 | effective permission set | 🟠 → P2-1/AR-10 |
| BR-12 | Agent role cross-account / **confused deputy** | HIGH | AI_AGENT / AI_IDENTITY | LLM06 | trust-policy conditions | 🟡→🟠 P2-5 (fetch trust doc → compute) |
| BR-13 | Agent role can read **secrets / KMS** | HIGH | AI_AGENT / AI_IDENTITY | LLM06, LLM02 | effective perms over Secrets/KMS | 🟠 → P2-8/AR-10 |
| BR-14 | AI endpoint **validated** internet-reachable | HIGH | AI_AGENT / endpoint | LLM06, LLM02 | reachability (path/EASM) | 🟠 → P2-2/AR-12 |
| BR-15 | KB backing store holds **sensitive data** | HIGH | KNOWLEDGE_BASE | LLM02, LLM08 | data classification | 🟠 → P2-3/AR-11 (Macie source) |
| BR-16 | Unowned AI artifact (no owner resolved) | MED | any | governance | resource `tags` | 🟡 → AR-1 |
| BR-17 | AgentCore / SageMaker / Comprehend / Import-Job artifacts | — | (various) | coverage breadth | new discovery scope | ⚪ → AR-6 |
| BR-18 | Guardrail-coverage: not every model path enforces a guardrail | HIGH | AI_AGENT / AI_APPLICATION | LLM01 (presence), LLM05 | model-path + guardrail edges | 🟠 → P2-7 |
| BR-19 | Drift: guardrail/logging disabled since last scan | HIGH | any | cross-cutting | snapshot history | 🟠 → P2-10 |
| BR-20 | Agent / KB not in a VPC / no network isolation | HIGH | AI_AGENT | LLM06, LLM02 | VPC / network cfg | 🟡 → B (AR-2) |
| BR-21 | Fine-tuning job uses untrusted / exposed training data | HIGH | TRAINING_JOB | **LLM04** | training data source | ⚪ → new scope (customization jobs) |
| BR-22 | Fine-tuned / output model not CMK-encrypted | MED | AI_MODEL | LLM03 | output model CMK | ⚪ → new scope |
| BR-23 | Imported model provenance unverified | MED | AI_MODEL | LLM03, LLM04 | model origin / signature | ⚪ → new scope + C |
| BR-24 | Uncontrolled foundation-model access enablement | LOW | ACCOUNT_CONFIG | governance | enabled-model list | 🟡 → B |
| BR-25 | Prompt / Flow leaks or exposes the system prompt | HIGH | PROMPT_ASSET | **LLM07** | prompt / flow cfg | ⚪ → new artifact (PROMPT_ASSET) |
| BR-26 | Prompt-asset access not restricted | MED | PROMPT_ASSET | LLM07, LLM02 | prompt resource perms | ⚪ → new artifact |
| BR-27 | Guardrail denied-topics / word-filter incomplete | MED | AI_GUARDRAIL | LLM01 (presence) | guardrail topic/word cfg | 🟡 → AR-3 |
| BR-28 | Invocation-log destination not encrypted | LOW | ACCOUNT_CONFIG | LLM02 | log destination CMK | 🟡 → B |

---

## 4. Azure catalog (AZ-1 … AZ-22)

| ID | Policy | Sev | Artifact | OWASP | Required fact(s) | Eval today |
|----|--------|-----|----------|-------|------------------|-----------|
| AZ-1 | Unrestricted public network access *(shipped: `AZURE_AI_UNRESTRICTED_PUBLIC_ACCESS`)* | CRIT | AI account | LLM02, LLM06 | `publicNetworkAccess`, `networkAcls` | 🔵 VERDICT\* → P2-2/AR-15 (validate) |
| AZ-2 | Local (key) authentication enabled *(shipped)* | HIGH | AI account | LLM06 | `disableLocalAuth` | 🟢 VERDICT |
| AZ-3 | Diagnostic logging disabled *(shipped)* | MED | AI account | LLM (detection) | `diagnosticLoggingEnabled` | 🟢 VERDICT |
| AZ-4 | Foundry agent Code Interpreter enabled *(shipped)* | HIGH | AI_AGENT | LLM06 | `codeInterpreterEnabled` | 🟢 VERDICT |
| AZ-5 | ML endpoint local auth enabled *(shipped)* | HIGH | ML endpoint | LLM06 | `mlLocalAuthEnabled` | 🟢 VERDICT |
| AZ-6 | Search local admin-key auth *(shipped)* | HIGH | Search svc | LLM06, LLM08 | `searchLocalAuthEnabled` | 🟢 VERDICT |
| AZ-7 | Search data-source non-identity auth *(shipped)* | HIGH | Search data src | LLM06, LLM08 | `authoritativeNonIdentityAuthentication` | 🟢 VERDICT |
| AZ-8 | Bot password auth without managed identity *(shipped)* | HIGH | AI_AGENT (bot) | LLM06 | `botPasswordAuthWithoutManagedIdentity` | 🟢 VERDICT |
| AZ-9 | No private endpoint / private link | MED | AI account | LLM02 | `privateEndpointCount` | 🟢 VERDICT |
| AZ-10 | No customer-managed-key encryption | MED | AI account | LLM02, LLM03 | `customerManagedKey` | 🟢 VERDICT |
| AZ-11 | **Content-filter / RAI not configured** (jailbreak, prompt-injection shield, harmful, protected-material) | CRIT | AI account / deployment | LLM01 (presence), LLM02 | content-filter / RAI cfg | 🟡 → AR-7 *(the Azure LLM01 story)* |
| AZ-12 | Groundedness detection disabled | MED | AI account / deployment | LLM09 (presence) | groundedness cfg | 🟡 → AR-7 |
| AZ-13 | Private-link SKU unsupported / DLP off / customer-owned storage | MED | AI account | LLM02 | SKU, DLP, storage | 🟡 → AR-8 |
| AZ-14 | Bot public network access | MED | AI_AGENT (bot) | LLM06 | bot `publicNetworkAccess` | 🟡 → AR-8 |
| AZ-15 | Copilot Studio agent auth / multi-tenant / maker creds | HIGH | AI_AGENT | LLM06 | Copilot Studio agents | ⚪ → AR-9 |
| AZ-16 | Managed identity has **effective admin** (RBAC) | CRIT | AI_IDENTITY | LLM06, LLM08 | effective role assignments | 🟠 → P2-1/AR-10 |
| AZ-17 | Identity can read **Key Vault / secrets** | HIGH | AI_IDENTITY | LLM06, LLM02 | effective perms over Key Vault | 🟠 → P2-8/AR-10 |
| AZ-18 | AI endpoint **validated** internet-reachable | HIGH | AI account / endpoint | LLM06, LLM02 | reachability (EASM) | 🟠 → P2-2/AR-12 |
| AZ-19 | Search index / store holds **sensitive data** | HIGH | Search / vector | LLM02, LLM08 | data classification | 🟠 → P2-3/AR-11 (Purview source) |
| AZ-20 | Unowned Azure AI artifact | MED | any | governance | resource `tags` | 🟡 → AR-1 |
| AZ-21 | Cross-tenant access on AI account | HIGH | AI account / identity | LLM06 | tenant ids + trust | 🟡→🟠 P2-5 |
| AZ-22 | Drift: control loosened since last scan | HIGH | any | cross-cutting | snapshot history | 🟠 → P2-10 |
| AZ-23 | Foundry connection stores a key instead of a managed identity | CRIT | AI_IDENTITY | LLM06 | connection auth mode | ⚪ → **P-C** (new family) |
| AZ-24 | ML workspace allows public network access | HIGH | ML workspace | LLM02 | workspace `publicNetworkAccess` | 🟡 → **P-B** |
| AZ-25 | ML compute has a public IP / no VNet | HIGH | ML compute | LLM06 | compute network cfg | 🟡 → **P-B** |
| AZ-26 | ML job / datastore: untrusted training data or exposed creds | HIGH | TRAINING_JOB | **LLM04** | datastore auth / source | 🟡 → **P-B** |
| AZ-27 | ML model-registry integrity / unsigned model | MED | AI_MODEL | LLM03 | model lineage / signing | 🟡 → **P-B** + C |
| AZ-28 | Search index not CMK-encrypted | MED | Search index | LLM02 | index `encryptionKey` | 🟡 → **P-B** |
| AZ-29 | Search skillset custom-skill egress (data exfil) | HIGH | Search skillset | LLM02 | skillset endpoint URIs | 🟡 → **P-B** |
| AZ-30 | OpenAI deployment content filter disabled (per-deployment) | HIGH | Model deployment | LLM01 (presence) | per-deployment filter | 🟡 → **P-A** (AR-7) |
| AZ-31 | Deployment uses deprecated / retiring model version | MED | Model deployment | LLM03 | model version / status | 🟡 → **P-B** |
| AZ-32 | Bot channel publicly exposed without secret | MED | Bot channel | LLM06 | channel cfg | 🟡 → **P-B** |
| AZ-33 | Foundry project network isolation disabled | MED | Foundry project | LLM02 | project managed network | 🟡 → **P-B** |
| AZ-34 | Content Safety blocklist / custom category not configured | MED | Content Safety | LLM01 (presence) | blocklist / category cfg | 🟡 → **P-A** (AR-7) |

---

## 5. OWASP LLM Top 10 — coverage rollup

| OWASP (2025) | Policies | Verdict-now anchor | Ceiling |
|---|---|---|---|
| LLM01 Prompt Injection | BR-4, BR-6, BR-18, AZ-11 | BR-4/BR-6 (guardrail presence) | **presence only** (efficacy behavioral) |
| LLM02 Sensitive Info Disclosure | BR-1, BR-8, BR-13, BR-15, AZ-1, AZ-9, AZ-11, AZ-13, AZ-17, AZ-19 | BR-1, AZ-1/9 | AR-11 for severity |
| LLM03 Supply Chain | BR-10, BR-22, BR-23, AZ-10, AZ-27, AZ-31 | AZ-10 (CMK) | model-scan deferred |
| LLM04 Data/Model Poisoning | BR-21, BR-23, AZ-26, AZ-27 | AZ-26 (training datastore) | training-data *source* assessable; content/efficacy behavioral |
| LLM05 Improper Output Handling | BR-4, BR-6, BR-18 | BR-4/BR-6 | **presence only** |
| LLM06 Excessive Agency | BR-2, BR-3, BR-7, BR-11, BR-12, BR-13, BR-14, AZ-2, AZ-4–8, AZ-14, AZ-16–18, AZ-21 | many (strongest category) | P2-1 for accuracy |
| LLM07 System Prompt Leakage | BR-25, BR-26 | — | config exposure assessable; runtime leakage behavioral |
| LLM08 Vector/Embedding Weakness | BR-1, BR-3, BR-9, BR-11, BR-15, AZ-6, AZ-7, AZ-16, AZ-19 | BR-1, AZ-6/7 | AR-11/P2-1 |
| LLM09 Misinformation | BR-8, AZ-12 | — | **presence only** (groundedness) |
| LLM10 Unbounded Consumption | *(quota/throttle where fetched)* | — | thin; revisit |

**Real FAIL verdicts concentrate in LLM02, LLM06, LLM08** — exactly where agentless config delivers. LLM01/04/05/09
are presence-only by nature; LLM07/LLM10 are thin. This is the honest OWASP story to show in the compliance UI.

---

## 6. Notes & concrete backend tasks this catalog implies

1. **Re-map shipped `controlMappings` to OWASP LLM Top 10.** The 13 registry policies currently carry ad-hoc
   `CIS`/`AWS`/`AZURE`/`NIST` strings — none are OWASP. Add the OWASP mapping (keep NIST as secondary). This is a
   catalog-row/data change once Epic 0 makes policies data-driven.
2. **17 verdict-now policies are the Epic 0 seed set** — the data-driven engine should reproduce BR-1..7 + AZ-1..10
   with a golden parity test against today's engine for the 13 shipped ones.
3. **Every 🟡/🟠/⚪ row is pre-linked to its owning AR/P2** — this catalog *is* the `NO_DECISION`→requirement index
   the s7 rule demands.
4. **`AZ-11` (content-filter/RAI) is the highest-value single unlock** — it is the entire Azure LLM01 story and is
   currently unfetched (AR-7).
5. Severities here are first-pass; final severity flows from the scoring model (Epic 3) once dimensions/multipliers
   exist. Treat the `Sev` column as provisional.

---

## 7. Open questions

- [ ] LLM10 (unbounded consumption): is there a Bedrock/Azure quota-or-throttle config we already collect that
  makes a real rule, or defer the category?
- [ ] BR-17 / AZ-15 new-scope discovery (AgentCore, Copilot Studio): in this release or the next?
- [ ] Do we express the shipped→OWASP re-mapping as the first Epic 0 catalog migration, bundled with seeding?
