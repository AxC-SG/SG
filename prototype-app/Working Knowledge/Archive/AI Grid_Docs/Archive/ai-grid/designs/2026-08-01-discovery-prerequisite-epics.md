# AI Security — Discovery Prerequisite Epics (P-AWS + P-AZ)

**Date:** 2026-08-01 (session 8) · **Author:** Claude, on instruction from @karthik.gowri
**Status:** draft — the **Phase-1 collection backlog**, organized as two provider epics.
**Supersedes:** `2026-08-01-azure-discovery-prerequisites.md` (Azure-only P-A/B/C — now a workstream of P-AZ).
**Companions:** [`2026-08-01-coverage-matrix.md`](2026-08-01-coverage-matrix.md),
[`2026-08-01-bedrock-azure-policy-catalog.md`](2026-08-01-bedrock-azure-policy-catalog.md),
[`2026-07-31-accuracy-improvement-requirements.md`](2026-07-31-accuracy-improvement-requirements.md).

---

## Why two epics, by provider

These are **Phase-1 collection prerequisites** — a gap policy cannot verdict until its family is discovered and
its facts fetched. Consolidated from what were three overlapping registers (the AR "fetch" group, the coverage-
matrix Azure gaps, and the P-A/B/C draft) into **one collection backlog, split by provider** because the work is
connector-specific. They are a refinement of **Epic 4**, called out because they *gate* the superset.

**Requirement homes now (one each):**
- **Collection (fetch metadata)** → *these two epics.* Absorbs former **AR-1..AR-9**.
- **Computation (derive signals)** → the Phase-2 catalog (**P2-1..11**). Former **AR-10/11/12** live there.
- **Verdict-quality + structural** → the accuracy register keeps **AR-13..18**.

Every gap `NO_DECISION` in the catalog points here (or to P2) — the s7 rule holds.

---

## Epic P-AWS — AWS Bedrock Discovery Collection

| WS | Workstream | Absorbs | Facts to collect | Unblocks |
|----|-----------|---------|------------------|----------|
| A1 | Tags + generic full-config fetch (AWS) | AR-1, AR-2 | resource tags; full per-family config (not just rule fields) | BR-16 (ownership) + future rules as data |
| A2 | Guardrail content config | AR-3 | PII / grounding / relevance config; denied-topics / word filters | BR-8, BR-27 |
| A3 | Model posture | AR-4 | model CMK; foundation-model LEGACY lifecycle | BR-10, BR-22 |
| A4 | KB data-source origin | AR-5 | external / non-owned data-source detail | BR-9 |
| A5 | Training / Customization Jobs discovery *(new family)* | AR-6 (jobs part) | training data source; output-model encryption; import provenance | BR-21, BR-22, BR-23 *(LLM04/03)* |
| A6 | PROMPT_ASSET discovery *(new artifact)* | — | Prompt Management / Flows config; prompt-resource perms | BR-25, BR-26 *(LLM07)* |
| A7 | Misc fetches | AR-2 | VPC/network cfg; enabled-model list; log-destination CMK | BR-20, BR-24, BR-28 |

*Out of P-AWS (residual, phase-2 plan §8): SageMaker / Comprehend (AR-6 remainder) — framework #3. AgentCore is
Bedrock-proper but emerging — fold into A5/A7 only if cheap, else defer.*

---

## Epic P-AZ — Azure AI Discovery Collection

| WS | Workstream | Absorbs | Facts to collect | Unblocks |
|----|-----------|---------|------------------|----------|
| **P-A** | Content-Filter / RAI collection *(highest value)* | AR-7 | jailbreak / prompt-injection shield, harmful-content categories+thresholds, protected-material, groundedness, custom blocklists — account **and** per-deployment | AZ-11, AZ-12, AZ-30, AZ-34 *(LLM01/09)* |
| **P-B** | AI-family config completion | AR-8 + AR-1/AR-2 (Azure) | tags + full-config; ML workspace `publicNetworkAccess`, ML compute public-IP/VNet, ML job datastore auth, Search index CMK, Search skillset egress URIs, deployment model-version, Bot channel cfg, Foundry project network isolation | AZ-20, AZ-24..29, AZ-31, AZ-32, AZ-33 |
| **P-C** | Foundry Connections discovery *(new family)* | — | connection target; **auth mode** (key vs managed identity vs Entra); is-shared/scope | AZ-23 *(biggest identity miss)* |

Note: the resource-family catalogue already **models** most P-B families (`AZURE_ML_*`, `AZURE_SEARCH_*`,
`AZURE_BOT_CHANNELS`, `AZURE_FOUNDRY_PROJECTS`) — discovery just doesn't fetch their config yet. So P-B is mostly
field-collection on known ARM resources; only P-C is a net-new family.

---

## Sequencing & DoD

1. **Foundational first (both epics):** A1 / P-B tags + generic full-config — unblocks ownership everywhere and
   makes later fetches data, not code.
2. **P-AZ · P-A next** — the Azure LLM01/09 marquee value (was AR-7).
3. **Family completion** — A2/A3/A4 (Bedrock), P-B (Azure).
4. **New families / artifacts last** — A5 Customization Jobs, A6 PROMPT_ASSET, P-C Foundry Connections.

**DoD (per policy):** it flips from ⚪/🟡 to a real PASS/FAIL verdict on a seeded answer-key environment, and its
`Eval today` in the catalog becomes 🟢/🔵.

## Open questions

- [ ] Release wave: foundational (A1/P-B tags) + P-A first, or all workstreams together per provider?
- [ ] P-C: are Foundry Connections read-only reachable with current Azure connector permissions, or add a role?
- [ ] P-B ML surface: fetch every run, or gate behind an "ML enabled" tenant flag to bound scan cost?
- [ ] A6 PROMPT_ASSET: is Bedrock Prompt/Flow discovery a cheap fetch or a new scope like Customization Jobs?
