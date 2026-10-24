# AI Security — Coverage Matrix (Bedrock + Azure) — the "how we know it's the superset" artifact

**Date:** 2026-08-01 (session 8) · **Author:** Claude, on instruction from @karthik.gowri
**Status:** draft — this matrix is the *completeness basis*. The policy catalog is regenerated from its cells.
**Companions:** [`2026-08-01-bedrock-azure-policy-catalog.md`](2026-08-01-bedrock-azure-policy-catalog.md)
(BR-##/AZ-##), [`2026-07-31-accuracy-improvement-requirements.md`](2026-07-31-accuracy-improvement-requirements.md)
(AR-##), [`2026-07-31-phase2-computation-plan.md`](2026-07-31-phase2-computation-plan.md) (P2-##).

---

## 1. Why this exists

The 41-policy catalog was an **enumeration**, not a derived superset — so it can't claim completeness (and it
under-covered: several code-modelled families had zero policies). This matrix fixes that:

> **Superset = { (AI resource family × control dimension) : a valid AI-attributed policy exists }.**

Enumerate the **full cross-product**, mark **every** cell, and the count of "real" cells *is* the superset — you
know it's complete because it was generated from the grid, not remembered. The catalog is then regenerated from
the real + gap cells. Two-sided validation of the family axis: the **provider service surface** (what exists) and
the **connector discovery output** (what we actually see); the delta is itself a coverage finding.

**Boundary (s8, ratified):** AWS **Bedrock (proper)** + **ARM-managed Azure AI** (OpenAI / AI Services /
Foundry / ML / Search / Bot / **Content Safety**). SageMaker + AWS-AI-adjacent and Copilot Studio + SaaS-admin
plane are residual (see phase-2 plan §8). Artifact-type axis is provider-neutral so those slot in later.

---

## 2. The two axes

**Control dimensions (columns):**

| Code | Dimension |
|---|---|
| D1 | Network exposure / reachability |
| D2 | Authentication mode (key/local vs managed identity/Entra) |
| D3 | Authorization / effective permissions (admin, secrets, cross-account/tenant, confused-deputy) |
| D4 | Data protection (encryption/CMK, data-source exposure, sensitive data) |
| D5 | Guardrails / content safety |
| D6 | Logging / observability |
| D7 | Agency / tool & code execution |
| D8 | Supply chain / model integrity (provenance, import, **training data**, lifecycle) |
| D9 | Governance / hygiene (owner, tags, drift) |
| D10 | Config-completeness / guardrail-coverage composition |

**Cell legend:** `BR-3`/`AZ-1` = existing catalog policy · **`+`** = **gap → new candidate policy** (enumerated in
§5) · `–` = N-A (dimension doesn't apply) · `✕` = out-of-scope (behavioral efficacy / generic CSPM) · blank = low-value/defer.

---

## 3. Bedrock grid (family × dimension)

| Family | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 |
|---|---|---|---|---|---|---|---|---|---|---|
| Bedrock Agent | BR-14 `+`BR-20 | – | BR-3 BR-11 | – | ✕ | – | BR-2 BR-7 | – | BR-16 | BR-18 |
| Action Group → Lambda | – | BR-2 | `+` | – | – | – | BR-2 | – | – | – |
| Knowledge Base | – | – | – | BR-1 BR-9 BR-15 | – | – | – | – | BR-16 | – |
| KB Data Source (S3) | – | – | – | BR-1 | – | – | – | – | – | – |
| Guardrail | – | – | – | – | BR-4 `+`BR-27 | – | – | – | – | BR-6 BR-18 |
| Foundation / Imported Model | – | – | – | BR-10 | – | – | – | BR-10 `+`BR-23 | `+`BR-24 | – |
| Fine-tuning / Customization Job | – | – | – | `+`BR-22 | – | – | – | `+`BR-21 | – | – |
| Prompt / Flow (PROMPT_ASSET) | – | – | `+`BR-26 | – | `+`BR-25 | – | `+`BR-25 | – | – | – |
| Invocation Logging (account) | – | – | – | `+`BR-28 | – | BR-5 | – | – | – | – |
| Execution Role (AI_IDENTITY) | – | – | BR-3 BR-11 BR-12 BR-13 | – | – | – | – | – | – | – |

Notes: D3 secrets/KMS + effective-admin (BR-11/BR-13) and confused-deputy (BR-12) are 🟠 compute (P2-1/P2-5).
D5 on the Agent is `✕` for *efficacy* (behavioral) but the guardrail's *presence/strength* is BR-4/BR-6.

---

## 4. Azure grid (family × dimension)

| Family | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 |
|---|---|---|---|---|---|---|---|---|---|---|
| OpenAI / AI Services Account | AZ-1 AZ-9 | AZ-2 | – | AZ-10 AZ-13 | AZ-11 AZ-12 | AZ-3 | – | – | AZ-20 | – |
| Model Deployment | – | – | – | – | `+`AZ-30 | – | – | `+`AZ-31 | – | – |
| Content Safety / RAI | – | – | – | – | AZ-11 AZ-12 `+`AZ-34 | – | – | – | – | – |
| Foundry Project (hub) | `+`AZ-33 | – | (RBAC) | – | – | – | – | – | AZ-20 | – |
| Foundry Connection | – | `+`AZ-23 | `+`AZ-23 | `+` | – | – | – | – | – | – |
| Foundry Agent | – | – | – | – | – | – | AZ-4 | – | – | – |
| Foundry Agent Tool | – | – | – | – | – | – | AZ-4 `+` | – | – | – |
| ML Workspace | `+`AZ-24 | – | – | `+` | – | `+` | – | – | AZ-20 | – |
| ML Compute | `+`AZ-25 | `+` | – | – | – | – | – | – | – | – |
| ML Online Endpoint | `+` | AZ-5 | – | – | – | – | – | – | – | – |
| ML Model / Deployment | – | – | – | – | – | – | – | `+`AZ-27 | – | – |
| ML Job / Pipeline | – | – | – | – | – | – | – | `+`AZ-26 | – | – |
| Search Service | `+` | AZ-6 | – | – | – | – | – | – | – | – |
| Search Index | – | – | – | AZ-19 `+`AZ-28 | – | – | – | – | – | – |
| Search Skillset | `+`AZ-29 | – | – | – | – | – | `+`AZ-29 | – | – | – |
| Search Indexer / Data Source | – | AZ-7 | – | – | – | – | – | – | – | – |
| Bot Service | AZ-14 | AZ-8 | – | – | – | – | – | – | – | – |
| Bot Channel | `+`AZ-32 | – | – | – | – | – | – | – | – | – |
| Managed Identity / RBAC | – | – | AZ-16 AZ-17 AZ-21 | – | – | – | – | – | – | – |

---

## 5. Gap register — candidate policies the grid surfaces (beyond the 41)

Each is a cell that *should* be real but isn't in the catalog yet. IDs continue the catalog numbering.

### Bedrock (BR-20 … BR-28)

| ID | Candidate policy | Family × Dim | OWASP | Bucket / owner |
|----|------------------|--------------|-------|----------------|
| BR-20 | Agent / KB not in a VPC / no network isolation | Agent × D1 | LLM06, LLM02 | B (fetch VPC cfg) |
| BR-21 | Fine-tuning job uses untrusted / exposed training data source | Customization Job × D8 | **LLM04** | B (new scope: customization jobs) |
| BR-22 | Fine-tuned / output model not CMK-encrypted | Customization Job × D4 | LLM03 | B |
| BR-23 | Imported model provenance unverified | Model × D8 | LLM03, LLM04 | B→C |
| BR-24 | Uncontrolled foundation-model access enablement | Model × D9 | governance | A/B |
| BR-25 | Prompt / Flow exposes or leaks the system prompt | Prompt × D5/D7 | **LLM07** | B (new artifact PROMPT_ASSET) |
| BR-26 | Prompt-asset access not restricted | Prompt × D3 | LLM07, LLM02 | B |
| BR-27 | Guardrail denied-topics / word-filter incomplete | Guardrail × D5 | LLM01 (presence) | B (AR-3) |
| BR-28 | Invocation-log destination not encrypted | Logging × D4 | LLM02 | A/B |

### Azure (AZ-23 … AZ-34)

| ID | Candidate policy | Family × Dim | OWASP | Bucket / owner |
|----|------------------|--------------|-------|----------------|
| AZ-23 | Foundry connection stores a key instead of using a managed identity | Connection × D2/D3 | LLM06 | B (new scope: connections) |
| AZ-24 | ML workspace allows public network access | ML Workspace × D1 | LLM02 | B |
| AZ-25 | ML compute has a public IP / no VNet | ML Compute × D1 | LLM06 | B |
| AZ-26 | ML job / datastore uses untrusted training data or exposed creds | ML Job × D8 | **LLM04** | B |
| AZ-27 | ML model-registry integrity / unsigned model | ML Model × D8 | LLM03 | B→C |
| AZ-28 | Search index not CMK-encrypted | Search Index × D4 | LLM02 | A/B |
| AZ-29 | Search skillset custom-skill egress (data exfil) | Search Skillset × D1/D7 | LLM02 | B |
| AZ-30 | OpenAI deployment content filter disabled (per-deployment) | Deployment × D5 | LLM01 (presence) | B (AR-7) |
| AZ-31 | Deployment uses deprecated / retiring model version | Deployment × D8 | LLM03 | B |
| AZ-32 | Bot channel (Direct Line / web chat) publicly exposed without secret | Bot Channel × D1 | LLM06 | B |
| AZ-33 | Foundry project network isolation disabled | Foundry Project × D1 | LLM02 | B |
| AZ-34 | Content Safety blocklist / custom category not configured | Content Safety × D5 | LLM01 (presence) | B |

---

## 6. Revised superset

| | Bedrock | Azure | Total |
|---|---|---|---|
| Catalog (enumerated) | 19 | 22 | 41 |
| **Gap candidates (grid-derived)** | 9 | 12 | 21 |
| **Superset** | **28** | **34** | **≈ 62** |

**The claim we can now defend:** every (family × dimension) cell in §3/§4 is accounted for — *real*, *gap*, *N-A*,
or *out-of-scope*. The superset is ~62, not 41, and the ~21 additions are **derived**, not remembered.

**What the grid fixed (the gaps it forced into the open):**
- **LLM04 (Data/Model Poisoning)** now has homes — BR-21/22, AZ-26/27 (training/fine-tuning). Previously near-empty.
- **LLM07 (System Prompt Leakage)** now has homes — BR-25/26 via a new **PROMPT_ASSET** artifact. Previously zero.
- **Foundry Connections** (AZ-23) — credential-storage, arguably the biggest single Azure miss.
- **Azure ML training surface** (AZ-24/25/26) — 6 code-modelled families that had zero policies.
- **Search skillset egress** (AZ-29) — data-exfil path that was invisible.

---

## 7. Next steps

1. **Regenerate the catalog** to fold in BR-20..28 + AZ-23..34 (with `Eval today` status + owning AR/P2), so the
   catalog and matrix agree.
2. Add **PROMPT_ASSET** to the taxonomy (BR-25/26) and confirm **Customization Job**, **Foundry Connection**,
   **ML Workspace/Compute/Job**, **Search Skillset**, **Bot Channel** as first-class discovered families.
3. The matrix is the **living completeness gate**: a new provider/resource type = new rows; a new attack class =
   a new dimension. Re-mark cells; never hand-append to the catalog again.

## 8. Open questions

- [ ] Are all ~21 gap candidates in *this* release, or a first wave (verdict-now + LLM04/LLM07 homes) then the rest?
- [ ] PROMPT_ASSET discovery for Bedrock Prompt Management/Flows — is the connector fetch cheap, or a new scope like AgentCore?
- [ ] D10 (config-completeness) is thinly populated — is guardrail-coverage (BR-18) the only real member, or are there Azure analogs?
