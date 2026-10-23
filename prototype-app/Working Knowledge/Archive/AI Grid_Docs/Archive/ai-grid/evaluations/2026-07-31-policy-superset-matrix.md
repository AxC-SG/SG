# AI Grid — Policy Superset & Validation-Feasibility Matrix

**Date:** 2026-07-31 (session 3) · **Author:** Claude
**Purpose:** Define the policy superset, categorize it, and bucket every category by whether validation is
possible **now (A)**, **with code changes to existing connectors/engine (B)**, or is a **real gap needing a
new capability (C)**. Companion to [`2026-07-31-connector-metadata-gap.md`](2026-07-31-connector-metadata-gap.md).

**Bucket key:**
- 🟢 **A — Validatable now**: fact already emitted; only the data-driven engine (Epic 0) is needed to declare the rule.
- 🟡 **B — Achievable via code changes**: same agentless mechanism — fetch more fields, discover a new resource
  type, or parse a document we already retrieve. No new capability.
- 🔴 **C — Real gap / new capability**: requires CIEM / DSPM / ASM / model-scan / SAST / runtime. Not a fetch problem.

## 1. Policy superset

Superset = 13 shipped ∪ Wiz catalog (260) ∪ governance/hygiene meta.

| Source domain | Count | Near-term (AWS+Azure agentless) |
|---|---|---|
| Shipped today | 13 | In |
| Wiz Cloud Misconfig — AWS+Azure native | 48 | **In — near-term core** |
| Wiz Cloud Misconfig — GCP + IaC | 31 | Out (GCP deferred; IaC = source plane) |
| Wiz Agent Risk | 37 | ~10 cloud-native config In; ~27 SDK/framework Out-near (source) |
| Wiz Identity (AI-specific) | 4 | In (needs CIEM) |
| Wiz Model Risk | 25 | Out-near (artifact scan) |
| Wiz MCP Risk | 10 | Out-near (source+network) |
| Wiz Attack Surface | 16 | Out-near (ASM) |
| Wiz SAST | 89 | Out-near (code) |
| Cross-resource correlation | graph | Engine In, gated on C-inputs |
| Governance/hygiene meta | ~6 | In |

**Near-term addressable ≈ 70** (48 config + ~10 cloud-native agent + 4 identity + ~6 governance + correlation).
Remaining ~190 belong to deferred mechanisms.

## 2. Categories
Cloud Config Posture · Guardrail & Content-Safety · Logging & Observability · Identity & Access (CIEM) ·
Attack Surface / Reachability · Model Artifact Integrity · Agent/Framework Config · MCP Server Risk ·
Data Exposure (DSPM) · Cross-Resource Correlation · Governance & Hygiene.

## 3. Master matrix

| Category | Mechanism | Metadata today | Bucket | Change / gap |
|---|---|---|---|---|
| Cloud Config Posture | config scan | mostly yes | 🟢A/🟡B | B: SKU, DLP, storage, description |
| Guardrail & Content-Safety | config scan | partial (Azure content-filter/RAI = none) | 🟡B | fetch guardrail PII/grounding + **Azure content-filter/RAI** |
| Logging & Observability | config scan | yes | 🟢A | — |
| Identity & Access (CIEM) | identity graph | syntactic wildcard only | 🟡B+🔴C | B: trust-policy (confused-deputy); **C: effective-perm resolution** |
| Attack Surface / Reachability | network probe | config proxy only | 🔴C | **ASM validated reachability** |
| Model Artifact Integrity | static artifact scan | no | 🔴C | pull + format parsers |
| Agent/Framework Config | SAST | no | 🔴C | repo AST scanning |
| MCP Server Risk | source scan + probe | no | 🔴C | MCP scan + probe |
| Data Exposure (DSPM) | classification | no | 🔴C | DSPM (proxy or defer) |
| Cross-Resource Correlation | graph traversal | edges yes; node booleans null | 🟡B engine / 🔴C inputs | engine buildable; needs CIEM/DSPM/ASM facts |
| Governance & Hygiene | metadata + config | **tags not emitted** | 🟡B | emit tags; drift/observability rules |

## 4. Near-term AWS/Azure config matrix (per fact)

| Cloud | Rule family | Required fact | Today | Bucket |
|---|---|---|---|---|
| AWS | Guardrail attached / weak strength | guardrailAttached, guardrailMinimumStrength | ✅ | 🟢A |
| AWS | Guardrail PII / grounding / relevance | PII list, grounding config | ❌ | 🟡B |
| AWS | Unauth Lambda URL | lambdaUrlAuthType | ✅ | 🟢A |
| AWS | KB public S3 | s3Public | ✅ (bucket-policy only) | 🟢A ⚠️ |
| AWS | KB external data sources | data-source origin | partial | 🟡B |
| AWS | Invocation logging disabled | invocationLoggingEnabled | ✅ | 🟢A |
| AWS | Agent active service role | agent status/role | ✅ | 🟢A |
| AWS | Agent role wildcard | iamWildcardActions | ✅ (syntactic) | 🟢A ⚠️ |
| AWS | Model CMK / foundation LEGACY | encryption/lifecycle | ❌ | 🟡B |
| AWS | AgentCore Runtime/Gateway/Policy/Memory | AgentCore resources | ❌ | 🟡B (new scope) |
| AWS | SageMaker / Comprehend / Import-Job | those types | ❌ | 🟡B (new scope) |
| AWS | Confused-deputy | trust-policy SourceArn/ExternalId | ❌ | 🟡B (extends CIEM-lite) |
| AWS | Agent admin / impersonation / secrets-KMS | effective permission set | ❌ | 🔴C (CIEM) |
| Azure | Public network disabled/restricted | publicNetworkAccess, networkAcls | ✅ | 🟢A |
| Azure | Private link present | privateEndpointCount | ✅ | 🟢A |
| Azure | Private-link SKU support | account sku | ❌ | 🟡B |
| Azure | Local auth disabled (OpenAI/AI/ML/Search) | disableLocalAuth, mlLocalAuthEnabled, searchLocalAuthEnabled | ✅ | 🟢A |
| Azure | CMK encryption | customerManagedKey | ✅ | 🟢A |
| Azure | Diagnostic logging | diagnosticLoggingEnabled | ✅ | 🟢A |
| Azure | Content-filter/RAI (jailbreak, harmful, protected-material, prompt-injection, groundedness) | content-filter/RAI config | ❌ **none** | 🟡B (biggest content-safety gap) |
| Azure | AI Service DLP / customer-owned storage | DLP + storage | ❌ | 🟡B |
| Azure | Foundry agent Code Interpreter | codeInterpreterEnabled | ✅ | 🟢A |
| Azure | Search data-source identity auth | authoritativeNonIdentityAuthentication | ✅ | 🟢A |
| Azure | Bot managed identity / password auth | botPasswordAuthWithoutManagedIdentity | ✅ | 🟢A |
| Azure | Bot public network access | bot publicNetworkAccess | ❌ | 🟡B |
| Azure | Copilot Studio auth / multi-tenant / maker creds | Copilot Studio agents | ❌ | 🟡B (new scope) |
| Azure | Agent admin / impersonation / secrets-KMS | effective permission set | ❌ | 🔴C (CIEM) |

## 5. The three buckets

- 🟢 **A — Now (~18–20):** the 13 + facts already emitted (missing-guardrail, active-service-role; Azure
  private-link-present, extra local-auth families). Blocked only by Epic 0.
- 🟡 **B — Code changes (~40+):** emit **tags** + generic full-config fetch; guardrail PII/grounding;
  **Azure content-filter/RAI**; model CMK/LEGACY; SKU/DLP/storage/bot-network; discover AgentCore/SageMaker/
  Comprehend/Import-Jobs/Copilot Studio; parse IAM trust policy (confused-deputy).
- 🔴 **C — Real gaps:** **CIEM** (effective-perm → identity rules; highest-value, half-started), **DSPM**
  (sensitive data; proxy-or-defer), **ASM** (validated reachability), model-artifact scan, SAST, MCP, runtime.
  Correlation engine is buildable but meaningful only once these populate node facts.

## Bottom line — needs specific attention
1. A/B are engine + enrichment problems, not metadata problems → Epic 0 + tags + generic config fetch unlocks ~60.
2. **Azure content-filter/RAI (B)** is the most important enrichment — no it, no OWASP-LLM01 story on Azure.
3. **CIEM (C)** is the one capability worth explicit near-term investment (identity rules; accuracy of admin/wildcard).
4. Name DSPM/ASM/model-scan/SAST/runtime as deferred **fact-feeding capabilities**, and keep the fact model
   `UNKNOWN`-aware so their policies exist as catalog rows returning `NO_DECISION` until the capability lands.
