# AI Grid — Connector Metadata Sufficiency vs. Wiz Policy Needs

**Date:** 2026-07-31 (session 3) · **Author:** Claude
**Question:** Do our AWS/Azure connectors fetch enough metadata to validate policies *accurately*?
**Inputs:** Wiz PRD policy catalog (A.6 etc.), the current discovery code, and Wiz's `cloudResourcesV2`
GraphQL sample (getCloudResource + AI_AGENT/MCP_SERVER filter results).

## Key insight from the Wiz `cloudResourcesV2` sample

Every node has **two metadata tiers**:
- **Inventory/config tier (populated):** `id, name, externalId, type, technology, cloudAccount, cloudPlatform,
  tags, projects, timestamps, nativeType, typeFields (type-specific config union), resourceGroup`.
- **Enrichment tier (NULL on freshly scanned resources):** `isOpenToAllInternet`, `isAccessibleFromInternet`,
  `hasAccessToSensitiveData`, `hasAdminPrivileges`, `hasHighPrivileges`, `hasSensitiveData`.

Those six nulls are the signals the highest-severity Wiz policies + all toxic-combination correlations depend
on — and **Wiz computes them asynchronously in its Security Graph (CIEM/DSPM/ASM), not from a describe call.**
This validates the Epic 0 normalized-fact model and proves a class of policies is gated on capabilities, not fields.

## What our connectors emit today (accurate to code)

- **AWS Bedrock** (`AwsBedrockDiscoveryService`): agent `status`, `executionRoleArn`, `guardrailAttached/Id`,
  `guardrailMinimumStrength`; `lambdaUrlAuthType`; KB→dataSource `s3Public`, `s3Buckets`; `iamWildcardActions`
  (+`iamEvidenceAvailable`); `invocationLoggingEnabled`; referenced `AI_MODEL` id. Calls: list/getAgent,
  listAgentActionGroups, getFunctionUrlConfig, listKnowledgeBases/listDataSources, getBucketPolicyStatus,
  listGuardrails/getGuardrail, list/getRolePolicy+getPolicyVersion, getModelInvocationLoggingConfiguration.
- **Azure AI** (`AzureAiDiscoveryService`/`AzureAiManagementClient`): `publicNetworkAccess`, `networkAcls`,
  `networkDefaultAction`, `privateEndpointCount`, `disableLocalAuth`, `customerManagedKey`, `identityType`,
  `managedIdentityAssigned`, `diagnosticLoggingEnabled`, `codeInterpreterEnabled`, `mlLocalAuthEnabled`,
  `searchLocalAuthEnabled`, `authoritativeNonIdentityAuthentication`, `botPasswordAuthWithoutManagedIdentity`.
  Reads Cognitive/OpenAI/ML/Search/Bot accounts, diagnosticSettings, roleAssignments, ManagedIdentity principals,
  Foundry projects/agents/tools.

**Two immediate findings:** (1) **neither connector emits resource `tags`** → Epic 1 owner-resolution has no
input today (must-fix). (2) We fetch *exactly* the fields the 13 policies read — no general "grab full config" —
so every new rule needs new fetch code (scalability problem on the discovery side too).

## Gap tiers

**Tier 1 — config fields not fetched yet (easy: more describe calls → more facts):** Bedrock guardrail PII /
grounding config; **Azure OpenAI content-filter / RAI policy config** (the entire OWASP LLM01 prompt-injection
story on Azure — none fetched); model CMK + LEGACY status; Azure private-link SKU, DLP, customer-owned storage;
resource `description`; agent VPC/network mode; **resource tags** (all families).

**Tier 2 — resource types not discovered at all (medium: new scopes):** Bedrock AgentCore
(Runtime/Gateway/Memory/Policy Engine), Bedrock Model Import Jobs, SageMaker endpoints, Comprehend, Azure OpenAI
content filters/RAI policies as first-class, Copilot Studio agents, Databricks serving endpoints.

**Tier 3 — derived signals no single API returns (hard: new capabilities):**
- `hasAdminPrivileges`/impersonation/secrets-KMS → CIEM effective-permission resolution. We have **CIEM-lite**
  only (AWS syntactic wildcard on role policies; no effective-perm; no Azure admin detection).
- Confused-deputy (`IAM-236`) → trust-policy condition analysis (`SourceArn`/`ExternalId`) — not done.
- `hasAccessToSensitiveData`/`hasSensitiveData` → DSPM/data classification — nothing.
- `isAccessibleFromInternet` (validated) → ASM probe — only a config proxy possible today.

## Recommendations (fold into the plan)

1. **Fact model (Epic 0) must model the six enrichment booleans as first-class facts with an explicit `UNKNOWN`
   state + provenance/confidence.** Config policies ship now; correlation policies emit `NO_DECISION` until
   CIEM/DSPM/ASM populate the fact. Avoids a later rewrite.
2. **Adopt Wiz's two-tier shape explicitly:** normalized envelope (owner/tags/account/exposure/timestamps) +
   per-type config bag (their `typeFields` union) = Epic 0 facts + Epic 1 metadata.
3. **Add resource-tag collection to both connectors now** — small, unblocks Epic 1 ownership.
4. **Add a generic "fetch full resource config" step per family** so Tier-1 gaps close as data, not code.
5. **Treat CIEM / DSPM / ASM as fact-feeding capability epics, not policy work.** CIEM-lite (effective-perm +
   trust-policy) is the highest-value next capability (unlocks the 4 identity rules, half-started). DSPM likely
   not native → coarse proxy or explicit defer. ASM validated-reachability deferred; ship config proxy meanwhile.
6. **Accuracy caveats in today's 13:** `iamWildcardActions` is syntactic (ignores permission boundaries/SCPs/
   resource scoping); `s3Public` uses bucket-policy status only (ignores ACLs + account Block Public Access).
   Acceptable for pilot; note them — single-field reads are exactly where identity/exposure accuracy breaks,
   which is why Wiz built a graph.

## Impact on decisions
- Adds a ratified design constraint to Epic 0: **`UNKNOWN`-aware, provenance-tagged fact model** including the
  six graph-enrichment booleans.
- Adds two near-term connector tasks: **emit resource tags** + **generic full-config fetch per family**.
- Elevates **CIEM-lite (effective-permission + trust-policy resolution)** to the first Tier-3 capability epic.
