# AWS Connector Maturity Implementation Plan

## Purpose

Mature Scout's AWS AI connector to provide the same customer security story as the Azure connector without copying the Service Graph Connector architecture and without making continuous runtime-log ingestion a prerequisite for first-customer adoption.

The first release must let a customer answer:

1. Which AWS agents exist and which versions are deployed?
2. Who can invoke each agent and which identity does it use?
3. Which models, prompts, tools, knowledge sources and guardrails belong to each deployed version?
4. Where does the agent run and which consequential execution surfaces can it reach?
5. Which configuration and exposure risks are supported by fresh, authoritative evidence?
6. Which important risks have targeted activity evidence?
7. Who owns remediation and how is resolution verified?

## Product position

The first-customer proposition is configuration posture plus evidence-backed exposure management:

> AI Grid maps deployed AWS agents, their identities, models, prompts, tools and sensitive-data paths; identifies the highest-impact control weaknesses; and uses targeted, expiring activity evidence to strengthen important findings without ingesting customer conversation logs.

The implementation must distinguish:

- **Configured:** attached to the agent definition.
- **Reachable:** an evidence-backed graph path shows that the agent can reach it.
- **Activity observed:** a governed external source reported relevant activity.
- **Confirmed:** validating evidence satisfies the exposure template's evidence contract.

Absence of activity evidence must never be presented as proof of non-use.

## Scope boundaries

### Included

- AWS rollout and connector-safety controls.
- Explicit connector capability observations.
- Bedrock agent versions and aliases.
- Version-specific model, prompt, tool, knowledge-base and guardrail mapping.
- First-class AWS prompts, tools, guardrails and execution identities.
- Improved IAM evidence and per-role failure isolation.
- AgentCore runtime, browser and code-interpreter inventory.
- An evidence spike to determine authoritative AgentCore relationships.
- Governed, metadata-only AWS activity facts through the trusted-evidence boundary.
- Existing policy replay, impact preview, certification, findings and workflow integration.

### Excluded from the first release

- Continuous CloudWatch log ingestion.
- A general-purpose log-normalization pipeline.
- External writes to `ai_agent_executions`.
- Per-run AWS execution timelines.
- Behavioral anomaly detection.
- Real-time blocking or autonomous response.
- Creation or deletion of IAM access keys.
- CloudFormation, CloudTrail, CloudWatch, S3 or X-Ray mutation by the discovery identity.
- ServiceNow staging or CMDB compatibility.
- Inferred agent-to-AgentCore relationships without authoritative evidence.

## Current-state constraints

- AWS agents are discovered as `AI_AGENT`, but agent versions and aliases are not first-class.
- Agent action groups and knowledge-base associations are queried against `DRAFT`.
- AWS prompts are generic artifacts without version-to-prompt relationships.
- Action groups are primarily reduced to `INVOKES_LAMBDA` relationships rather than `AI_TOOL` assets.
- Execution roles are summarized through agent attributes such as `iamWildcardActions` instead of identity nodes.
- AgentCore gateways, targets and MCP servers are discovered but are not authoritatively connected to an agent/runtime workload.
- Guardrails are emitted as `OTHER_AI_ARTIFACT` and read at `DRAFT`.
- AWS has no native runtime collector, while the shared execution store and UI already exist.
- The trusted evidence endpoint supports governed runtime-observation facts but not execution writes.
- Capability readiness is currently inferred by substring matching resource-family names.
- Artifact attributes are merged across scopes; stopped or renamed fields remain unless explicitly cleaned.
- Several resource families can be added to a collector without corresponding budget, permission, sanitizer or kill-switch registration.

## Canonical AWS graph

The target definition graph is:

```text
AI_AGENT
  ├── HAS_COMPONENT ──> AWS_BEDROCK_AGENT_ALIAS
  │                         └── SERVES_VERSION ──> AI_AGENT_VERSION
  └── owned by / exposed through provider metadata

AI_AGENT_VERSION
  ├── VERSION_OF ──> AI_AGENT
  ├── USES_MODEL ──> AI_MODEL
  ├── USES_PROMPT ──> AI_PROMPT
  ├── USES_TOOL ──> AI_TOOL
  ├── USES_KNOWLEDGE_BASE ──> KNOWLEDGE_BASE
  ├── USES_GUARDRAIL ──> AI_GUARDRAIL
  └── ASSUMES_ROLE ──> AWS identity artifact

AI_TOOL
  ├── IMPLEMENTED_BY ──> Lambda / AgentCore capability
  └── may route through MCP_GATEWAY → MCP_TARGET → MCP_SERVER
```

`DRAFT` remains a version, but it is not treated as served unless a provider routing object explicitly targets it.

## Workstream 0 — Safety and evidence contracts

### 0.1 AWS rollout controls

Add independently controlled AWS feature flags for:

- Agent versions and aliases.
- First-class prompt/tool/guardrail taxonomy.
- AWS identity graph.
- AgentCore execution-surface inventory.
- AWS curated activity evidence.

Add kill switches at tenant, connector, region and resource-family levels. A disabled family reports `DISABLED`; it must not masquerade as an empty complete scan.

New behavior remains disabled by default until replay and certification gates pass.

### 0.2 AWS permission preflight

Create an AWS permission matrix parallel to Azure's matrix. For every resource family declare:

- Required read actions.
- Optional enrichment actions.
- Prohibited mutation actions.
- Scope: global or regional.
- Connector test behavior.
- Customer remediation text.

Expose preflight results before a discovery run and materialize missing permissions as setup actions.

An access failure for one family or role produces `UNAUTHORIZED` or `PARTIAL`; it must not erase previously complete evidence from other families.

### 0.3 Explicit capability observations

Replace resource-family substring inference with an explicit contract:

```text
CapabilityObservation
- capabilityId
- status: COMPLETE | DISABLED | UNAUTHORIZED | UNSUPPORTED_API | PARTIAL | ERROR | STALE
- reasonCode
- evidenceScopes
- observedAt
- expiresAt
```

Add `reason_code` and `evidence_scopes_json` to tenant capability observations. Collector code declares capability observations explicitly; `AiGridCapabilityService` validates and persists them without deriving capabilities from naming conventions.

Composite capabilities are complete only when their evidence contract is satisfied. For example, `AWS_EFFECTIVE_ACCESS` requires the required role, trust, attached-policy, inline-policy and boundary evidence; successful role enumeration alone is insufficient.

Capability observations must reference active platform capability definitions. Unknown capability IDs are rejected.

### 0.4 Scope-owned attributes

Do not globally replace artifact attributes because multiple AWS scopes enrich the same agent. Add source ownership for attributes so a complete scope can remove its previously owned keys before applying new values.

Required behavior:

- Each attribute emitted by a scope is recorded as owned by that scope.
- A subsequent `COMPLETE` observation removes owned keys no longer emitted by that scope.
- `PARTIAL`, `ERROR`, `UNAUTHORIZED` and `DISABLED` scopes do not delete previous keys.
- Keys owned by other scopes remain intact.
- Any renamed field includes a targeted cleanup/backfill.

### 0.5 Registration integrity

Create a certification test comparing:

- Collector resource families.
- Permission-matrix entries.
- Budget/admission registration.
- Sanitizer native kinds.
- Feature flags and kill switches.
- Capability declarations.

Missing safety-critical permission or sanitizer registration fails tests/certification. Missing cadence/budget registration emits a startup warning and fails certification without taking down the service.

### 0.6 Replay baseline

Reuse and extend:

- Policy impact preview.
- R1/R2 certification.
- Reconciliation.
- AGCF answer-key corpus.

Capture the current AWS artifact, system, finding and exposure outputs before enabling new semantics. Every workstream must replay the same corpus and explain intended differences.

## Workstream 1 — Deployed agent correctness

### 1.1 Agent versions

Collect every Bedrock agent version using provider-stable identifiers and emit:

- Artifact type: `AI_AGENT_VERSION`.
- Native kind: `AWS_BEDROCK_AGENT_VERSION`.
- `VERSION_OF` relationship to the logical agent.
- Version number, status, created/updated time and privacy-safe definition digest.

Discover version-specific:

- Model.
- Action groups.
- Knowledge-base associations.
- Guardrail identifier and version.
- Prompt reference where exposed.

### 1.2 Aliases and routing

Represent each Bedrock alias as `AI_COMPONENT` with native kind `AWS_BEDROCK_AGENT_ALIAS`.

Emit:

- Agent → alias using `HAS_COMPONENT`.
- Alias → version using new `SERVES_VERSION`.

`SERVES_VERSION` must be added to the relationship allowlist and to non-membership relationships.

Support multiple aliases and multiple served versions. Do not assume one universal active version. Alias routing evidence includes source API, source field, observation time and routing metadata.

### 1.3 Correlation resolver

Update agent/version resolution to accept:

- Agent ID or ARN.
- Agent version.
- Alias ID or ARN.

Alias-based observations resolve through `SERVES_VERSION`. Multiple valid routing targets produce an explicit multi-target result rather than `AGENT_VERSION_REFERENCE_NOT_FOUND`.

Alias components must not automatically appear as execution participants. Exclude native kind `AWS_BEDROCK_AGENT_ALIAS` from `HAS_COMPONENT` participant projection.

### 1.4 Version-aware posture

Stop using DRAFT composition as the sole basis for deployed-agent posture:

- Retain DRAFT as a separate non-served version.
- Evaluate deployed-version policies against versions referenced by aliases.
- Fetch action groups and knowledge associations for the relevant version.
- Resolve the guardrail version attached to that deployed version.
- Label draft-only findings as pre-deployment posture.

## Workstream 2 — Definition graph parity

### 2.1 Prompts

Promote Bedrock prompts to `AI_PROMPT` while preserving provider resource IDs.

Persist only:

- Prompt ID and version.
- Name and lifecycle metadata.
- Tenant-keyed digest.
- Digest algorithm and key version.
- Owner/approval metadata where available.

Do not persist prompt bodies. Emit `USES_PROMPT` from the relevant agent version only when the provider supplies a reference or an approved registration supplies the relationship.

### 2.2 Tools

Represent Bedrock action groups as `AI_TOOL` with stable IDs.

Persist:

- Action-group ID, name, status and version.
- Executor type.
- Lambda ARN where applicable.
- Privacy-safe API definition/function-schema digest.
- Authentication/approval configuration where available.
- Tool consequence classification.

Emit:

- Agent version → tool using `USES_TOOL`.
- Tool → Lambda using `IMPLEMENTED_BY`.

Keep the existing agent/Lambda facts temporarily for backward-compatible policy replay; deprecate them only after equivalent results are certified.

### 2.3 Guardrails

Retype AWS guardrails to `AI_GUARDRAIL` in place. Preserve the ARN provider identity and historical snapshots.

Link the deployed agent version to the exact guardrail version. DRAFT guardrail posture is shown separately as pre-deployment evidence.

### 2.4 Policy scope

Do not bulk-add canonical artifact types to every AWS policy package. Existing provider-native-kind scoping remains authoritative.

Canonical types support:

- Cross-cloud UI grouping.
- Graph semantics.
- Definition-drift policies.
- Deliberately designed provider-neutral policies.

Any catalog applicability change must pass impact preview, answer-key replay and certification.

## Workstream 3 — Identity and AgentCore

### 3.1 AWS identities

Represent each agent execution role as a first-class supporting identity artifact and emit version → identity using `ASSUMES_ROLE`.

Collect and analyze:

- Trust policy.
- Attached managed policies.
- Inline policies.
- Actions and resources.
- `NotAction`/`NotResource` semantics.
- `iam:PassRole`.
- Permission boundaries.
- Cross-account principals and conditions.

Preserve existing agent-level wildcard facts during migration. New graph/exposure logic uses the identity artifact; old facts are retired only after replay proves equivalence.

Malformed policy documents degrade that role's evidence to `PARTIAL` with a diagnostic. They do not fail the entire `IAM_GLOBAL` scope.

### 3.2 AgentCore discovery

Add control-plane inventory for:

- Agent runtimes as `AI_COMPONENT`.
- Browsers as `AI_TOOL`.
- Code interpreters as `AI_TOOL`.

Preserve existing gateway, target and MCP server inventory.

### 3.3 AgentCore relationship spike

Before implementing agent/runtime/gateway edges, verify whether authoritative control-plane fields exist for:

- Runtime → workload identity.
- Runtime → gateway.
- Runtime → agent definition or deployment.
- Tool → gateway/target.
- Registration or tags that provide only candidate evidence.

The spike produces a mapping of supported direct, inferred and unavailable relationships with source API/field evidence.

If no authoritative classic-agent relationship exists, do not emit `CONNECTS_TO_MCP`. Keep the AgentCore graph runtime-rooted and create an unattached-resource coverage/ownership action.

## Workstream 4 — Lightweight activity evidence

### 4.1 Evidence model

Use governed host-context facts, not execution records, for the first release.

Add producer `SCOUT_AWS_ACTIVITY` with:

- Provenance: `OBSERVED`.
- Evidence class: `RUNTIME_OBSERVATION`.
- Source port: `ASSET`.
- Method/version: `SCOUT_AWS_ACTIVITY` / `1.0.0`.
- Mandatory confidence between 0 and 1.
- Mandatory `validUntil`, even though keys are non-validating.

Authorize these exact keys:

| Fact key | Type | Meaning |
|---|---|---|
| `activity.agent_invocation_observed` | BOOLEAN | A trusted source observed at least one invocation in the evidence window. |
| `activity.tool_use_observed` | BOOLEAN | A trusted source observed tool use associated with the agent/version. |
| `activity.identity_use_observed` | BOOLEAN | A trusted source observed the execution identity in use. |
| `activity.external_action_observed` | BOOLEAN | A trusted source observed an external-effect action. |
| `activity.sensitive_data_access_observed` | BOOLEAN | A trusted source observed access carrying an authoritative sensitive-data classification. |
| `activity.invocation_count_observed` | NUMBER | Bounded invocation count for the stated evidence window. |
| `activity.agent_last_observed_at` | STRING | ISO-8601 UTC time of the last observed activity. |

All keys end in `_observed`, so they are explicitly non-validating. They can drive the `activity observed` UI state and prioritization, but cannot promote an exposure to validated.

Each fact definition must declare:

- Active lifecycle.
- Matching value type.
- Allowed evidence class `RUNTIME_OBSERVATION`.
- Allowed workflow uses limited to activity context and exposure prioritization; do not authorize `VALIDATED_EXPOSURE` in this phase.
- Default maximum age consistent with its collection interval.

If the existing workflow-use vocabulary lacks activity/prioritization values, add the vocabulary and consumers deliberately rather than misusing `VALIDATED_EXPOSURE`.

### 4.2 Idempotency and freshness

- Producers always send `observedAt`.
- Periodic aggregates bucket `observedAt` to the collection window, such as UTC day.
- Re-pushing the same producer/artifact/fact/window updates rather than inserts.
- `evidenceReference` identifies the source query, alert or external record without embedding content.
- Expired evidence remains auditable but does not contribute to current activity state.

### 4.3 Evidence sources

Initial supported sources are:

- Customer SIEM or SOAR detections.
- CloudWatch alarms or customer-managed summaries.
- Agent gateway or runtime-control decisions.
- Bounded, explicitly initiated provider queries implemented later if demanded.

No raw prompts, responses, conversations, tool arguments, results, secrets or personal identifiers are accepted.

### 4.4 UI behavior

Add an Activity Evidence section to agent/version detail showing:

- Configured, reachable, activity-observed and confirmed states.
- Evidence source.
- Observation window.
- First/last observation.
- Count where available.
- Confidence and expiry.
- Explicit `No activity evidence available` wording rather than `Not used`.

Activity evidence influences prioritization only; it does not create a per-run execution timeline.

## Public contracts

### Artifact taxonomy

Reuse existing canonical types:

- `AI_AGENT_VERSION`
- `AI_PROMPT`
- `AI_TOOL`
- `AI_COMPONENT`
- `AI_GUARDRAIL`

Add AWS native kinds for agent versions, aliases, action groups, runtimes, browsers and code interpreters.

### Relationships

Add:

- `SERVES_VERSION`
- `IMPLEMENTED_BY`

Reuse:

- `VERSION_OF`
- `HAS_COMPONENT`
- `USES_MODEL`
- `USES_PROMPT`
- `USES_TOOL`
- `USES_KNOWLEDGE_BASE`
- `USES_GUARDRAIL`
- `ASSUMES_ROLE`

Every relationship includes confidence and evidence source API/field. Unknown relationship types remain rejected.

### Trusted evidence

Keep the existing trusted-evidence endpoint and item shape. Extend the governed producer/fact registry only. Do not add external execution writes.

### Capability contract

Extend the observation pipeline with explicit capability observations and retain backward-compatible empty declarations for collectors not yet migrated. Remove substring inference only after AWS and Azure collectors declare their capabilities explicitly.

## Verification plan

### Unit tests

- Agent version and alias pagination.
- Multi-alias and multi-target routing.
- DRAFT versus served versions.
- Version-specific action groups, knowledge and guardrails.
- Prompt/tool digest generation and content rejection.
- Relationship allowlist and non-membership behavior.
- Alias exclusion from execution participants.
- IAM `Action`, `NotAction`, `Resource`, `NotResource`, trust, boundary and `PassRole` evaluation.
- Per-role malformed-policy degradation.
- Scope-owned attribute removal and cross-scope preservation.
- Explicit capability status and completeness evaluation.
- Activity fact type, authorization, confidence, expiry and idempotency.

### Integration tests

- AWS fixture containing multiple versions and aliases.
- Alias routing changes between scans.
- Removed tool/prompt/guardrail attributes disappear after a complete scan.
- Partial scope does not delete previous authoritative attributes.
- Stable artifact IDs across taxonomy changes.
- Deployed version graph reaches model, prompt, tool, knowledge, guardrail and identity.
- AgentCore resources remain unattached without authoritative evidence.
- Trusted activity evidence changes prioritization but not validation state.
- Tenant isolation for artifacts, capabilities and activity evidence.

### Policy and release tests

- Before/after impact preview for every changed AWS policy.
- Existing answer-key corpus remains stable except documented intentional changes.
- Definition-drift policies begin evaluating AWS prompts/tools only after certification.
- Missing capabilities produce explicit readiness gaps.
- Feature disable/kill switch restores previous tenant behavior.
- No unsupported provider edge is classified `DIRECT`.

### Security and privacy tests

- Prompt and tool definition bodies never reach snapshots, logs or APIs.
- IAM documents are parsed transiently and are not exposed through inventory APIs.
- Evidence references cannot carry raw content or secrets.
- Producer identity is bound to the authenticated service account.
- Activity facts cannot be used for validated exposure in the first release.

## Acceptance criteria

- Every discovered Bedrock agent shows versions and alias routing.
- Every served version shows its model, prompt, tools, knowledge bases, guardrail and execution identity when provider evidence is available.
- Draft-only state is visibly separated from deployed state.
- AWS prompt, tool and guardrail assets appear in the same canonical UI groupings as Azure.
- Every graph edge exposes evidence source, confidence and observation time.
- No agent-to-AgentCore edge is emitted without authoritative evidence.
- IAM parse failure for one role does not fail global IAM evidence.
- Removed scope-owned attributes do not persist after a complete scan.
- Every new family is covered by certification checks for permissions, budgets, sanitizer and rollout controls.
- Capability gaps state the missing capability, reason and contributing scopes.
- Existing finding changes are explained by impact preview and approved answer-key deltas.
- Curated activity evidence is expiring, idempotent and visibly non-validating.
- AWS discovery remains useful when no activity evidence is supplied.
- Continuous log ingestion is not required for first-customer deployment.

## Delivery gates

1. **Foundation gate:** rollout controls, registration validation, capability contract and replay baseline pass.
2. **Definition gate:** deployed version/alias graph is complete and privacy-safe in fixtures.
3. **Exposure gate:** prompt/tool/identity relationships produce certified, explainable findings without regressions.
4. **AgentCore gate:** relationship spike resolves the supported graph; unsupported relationships remain coverage actions.
5. **Activity gate:** governed facts affect activity state and prioritization without validating exposures.
6. **Canary gate:** enable for selected tenants, monitor artifact churn, finding deltas, incomplete scopes, API calls and scan duration.
7. **GA gate:** precision, stability, privacy and rollback criteria are approved through existing certification governance.

## Implementation assumptions

- The existing canonical taxonomy and execution UI remain shared across providers.
- Provider resource IDs remain stable through retyping and version enrichment.
- Provider-native kinds continue to scope current AWS policy packages.
- Activity facts are advisory context, not proof of execution or attack.
- Alias routing is the authoritative indicator of a served Bedrock version.
- AgentCore relationships remain unknown unless provider or trusted evidence proves them.
- Current transactional storage remains appropriate because the first release does not ingest high-volume events.
