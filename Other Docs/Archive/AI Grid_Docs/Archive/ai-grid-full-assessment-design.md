# AI Grid - Full Assessment Design

> **Scope:** Enterprise architecture and implementation design for assessing AI artefacts in Scout.
> This includes agents, MCP servers, model deployments, fine-tuned models, embedding models, knowledge bases,
> vector stores, prompt assets, AI pipelines, AI gateways, AI functions, guardrails, identities, and evaluation runs.
>
> **Architectural position:** AI Grid extends Scout's existing tenant, findings, ownership, SLA, suppression,
> connector, and scoring capabilities. It must not become a parallel security platform.

---

## 1. Executive Assessment

The original Claude proposal was directionally correct: it chose a provider-neutral graph model, separate discovery
adapters, snapshot-based drift detection, and reuse of Scout findings. Those are the right foundations.

The proposal was not yet implementation-ready. The missing pieces were concrete normalization rules, schema DDL,
adapter contracts, rule IDs, scoring, APIs, Connect page integration, prompt data handling, data residency, and
cross-tenant analytics design.

This revision closes those gaps and turns the proposal into an implementable design.

---

## 2. Design Goals

AI Grid must:

1. Discover AI artefacts across cloud and self-hosted environments.
2. Normalize provider-specific resources into one tenant-scoped graph.
3. Evaluate deterministic posture rules over normalized capabilities.
4. Create standard Scout findings, not a separate AI-only findings workflow.
5. Support platform-owned rule catalogs and tenant-owned assessment data.
6. Scale to AWS, Azure, GCP, OpenAI, Hugging Face, self-hosted model servers, and MCP ecosystems.

---

## 3. AI Artefact Taxonomy

| Artefact type | Description | Examples |
|---|---|---|
| `AGENT` | Autonomous or semi-autonomous LLM actor | Bedrock Agent, Azure AI Agent, LangChain agent |
| `MCP_SERVER` | Model Context Protocol server exposing tools | Filesystem MCP, database MCP, GitHub MCP |
| `MODEL_DEPLOYMENT` | Hosted inference endpoint | Bedrock model endpoint, Azure OpenAI deployment, Vertex endpoint |
| `FINE_TUNED_MODEL` | Custom model trained from tenant data | Azure fine-tune, SageMaker fine-tune, OpenAI fine-tune |
| `EMBEDDING_MODEL` | Model producing embeddings | Titan Embed, text-embedding-3, Vertex textembedding |
| `KNOWLEDGE_BASE` | Retrieval corpus or search abstraction | Bedrock KB, Azure AI Search, Vertex Search |
| `VECTOR_STORE` | Embedding database | OpenSearch, Pinecone, pgvector, Weaviate |
| `PROMPT_ASSET` | System prompt, policy prompt, template, instruction pack | Bedrock instruction, prompt library template |
| `AI_PIPELINE` | Multi-step AI workflow | Prompt Flow, Vertex Pipeline, Bedrock Flow |
| `AI_GATEWAY` | Policy/routing layer for AI endpoints | APIM AI policies, internal model gateway |
| `AI_FUNCTION` | Callable tool, plugin, Lambda, function, action group | Lambda action group, Azure Function skill |
| `AI_GUARDRAIL` | Content/safety/policy control | Bedrock Guardrail, Azure Content Safety, Vertex safety settings |
| `IDENTITY` | Principal used by an AI artefact | IAM role, managed identity, service account |
| `EVALUATION_RUN` | Safety, red-team, or model quality evaluation result | Azure evaluation job, Scout red-team run |
| `ADVISORY` | External intelligence about models, frameworks, or AI services | vendor advisory, model deprecation, CVE-like notice |

---

## 4. Capability Normalization

### 4.1 Canonical Capability Flags

Assessment rules must reason over normalized capabilities, not raw provider fields. Every `ai_asset_snapshots` row
stores `capability_flags` as JSONB. The rule engine reads this object as the canonical source of what an artefact can do.

Canonical flags:

| Capability flag | Meaning |
|---|---|
| `inference` | Artefact can invoke or serve a model |
| `retrieval` | Artefact can query a knowledge base or vector store |
| `tool_execution` | Artefact can invoke tools, functions, plugins, or action groups |
| `code_execution` | Artefact can execute generated or user-provided code |
| `file_access` | Artefact can read or write file/object storage |
| `database_access` | Artefact can query or mutate a database |
| `network_egress` | Artefact can call external network destinations |
| `memory_persistence` | Artefact has persistent memory or conversation state |
| `secrets_access` | Artefact or linked runtime can access secrets |
| `cross_tenant_access` | Artefact can cross account, subscription, project, workspace, or tenant boundary |
| `policy_override` | Artefact can bypass or override policy/guardrail routing |
| `autonomous_action` | Artefact can act without human confirmation |

Example snapshot fragment:

```json
{
  "capability_flags": {
    "tool_execution": true,
    "code_execution": false,
    "file_access": true,
    "database_access": false,
    "network_egress": true,
    "memory_persistence": true,
    "secrets_access": false,
    "cross_tenant_access": false,
    "autonomous_action": true
  }
}
```

### 4.2 Provider Signal Mapping

The following table defines minimum mappings. Adapters can add stronger provider-specific evidence, but they must not
change the meaning of a canonical flag.

| Capability | AWS Bedrock / AWS signal | Azure signal | GCP signal | MCP / self-hosted signal |
|---|---|---|---|---|
| `tool_execution` | `ListAgentActionGroups` returns entries | `agent.tools` not empty | tool list not empty | `tools/list` returns entries |
| `code_execution` | action group invokes code interpreter, Lambda with code-exec tag | `code_interpreter` tool enabled | `code_exec` or notebook executor tool | tool type `SHELL`, `CODE`, `EXEC` |
| `file_access` | action group reaches S3/EFS or filesystem MCP | tool connects to Blob/File Share | Cloud Storage tool | tool type `FILESYSTEM` or object store connector |
| `database_access` | action group reaches DynamoDB/RDS/Redshift | Azure SQL/Cosmos DB connection | Spanner/BigQuery/Cloud SQL tool | tool type `DATABASE` |
| `network_egress` | Lambda/ECS action group or public endpoint exists | Function/Container App tool registered | Cloud Run/Function tool | outbound HTTP tool or open egress |
| `memory_persistence` | `memoryConfiguration` present | memory tool/resource enabled | memory store attached | persistent session/memory store configured |
| `secrets_access` | Lambda env/KMS/Secrets Manager access | Key Vault connection or secret ref | Secret Manager binding | env secret, mounted secret, vault connector |
| `cross_tenant_access` | execution role has cross-account trust | identity shared across subscriptions/tenants | service account shared across projects | shared API key or shared identity across tenants |
| `policy_override` | agent or gateway can bypass guardrail | APIM route without content filter | gateway route without safety config | policy bypass route or admin tool |
| `autonomous_action` | action group can mutate state without confirmation | workflow action has no approval step | pipeline/action has no approval gate | destructive tool exposed without approval |

### 4.3 Rule Preconditions

Each rule declares:

- applicable artefact types
- required capability flags
- optional provider evidence
- severity
- dimension

Example:

```json
{
  "checkId": "AGY-006",
  "appliesTo": ["MCP_SERVER"],
  "requiredCapabilities": ["tool_execution", "file_access"],
  "severity": "CRITICAL"
}
```

---

## 5. Tenant and Platform Model

### 5.1 Tenant-owned data

These records live in the tenant schema:

- `ai_sources`
- `ai_assets`
- `ai_asset_relations`
- `ai_asset_snapshots`
- `ai_asset_tools`
- `ai_asset_findings`
- `ai_assessment_runs`
- tenant-specific suppression and ownership records

### 5.2 Platform-owned data

These records live in the platform schema:

- `platform.ai_assessment_rules`
- `platform.ai_provider_capability_mappings`
- `platform.ai_advisories`
- `platform.ai_tenant_risk_rollups`
- feature entitlements

### 5.3 Tenant isolation requirement

All tenant data access follows Scout's existing tenant schema pattern. Background jobs must set `TenantContext` before
opening transactions and must use `TenantSchemaExecutionService` or the existing equivalent tenant execution wrapper.

### 5.4 Data residency

Cloud AI assets are regional. `ai_sources` and `ai_assets` must store provider region.

Data residency rule:

- snapshots and findings are stored in the tenant's configured Scout data region
- provider region is stored as metadata for compliance and filtering
- raw prompt content and raw provider payloads are not replicated into platform summary tables
- if Scout later supports region-local tenant schemas, AI Grid must write snapshots to the tenant's region-local schema

---

## 6. Core Schema DDL

The DDL below is the canonical starting point. Additional provider-specific fields must live in JSONB attributes, not
new provider-specific columns.

```sql
CREATE TABLE ai_sources (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider           VARCHAR(64) NOT NULL,
  display_name       VARCHAR(255) NOT NULL,
  account_ref        VARCHAR(255),
  region             VARCHAR(100),
  credential_ref     VARCHAR(255),
  enabled            BOOLEAN NOT NULL DEFAULT TRUE,
  sync_interval_hours INTEGER,
  last_synced_at     TIMESTAMPTZ,
  last_sync_status   VARCHAR(32),
  last_sync_message  TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_assets (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id           UUID NOT NULL REFERENCES ai_sources(id) ON DELETE CASCADE,
  asset_type          VARCHAR(64) NOT NULL,
  external_id         VARCHAR(700) NOT NULL,
  name                VARCHAR(500) NOT NULL,
  provider            VARCHAR(64) NOT NULL,
  account_ref         VARCHAR(255),
  region              VARCHAR(100),
  environment         VARCHAR(64),
  owner_ref           VARCHAR(255),
  model_family        VARCHAR(128),
  model_version       VARCHAR(128),
  runtime_framework   VARCHAR(128),
  identity_ref        VARCHAR(700),
  status              VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
  ai_risk_score       NUMERIC(4,2),
  first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at        TIMESTAMPTZ,
  last_assessed_at    TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source_id, external_id)
);

CREATE TABLE ai_asset_relations (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  from_asset_id       UUID NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
  to_asset_id         UUID NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
  relation_type       VARCHAR(80) NOT NULL,
  evidence            JSONB,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (from_asset_id, to_asset_id, relation_type)
);

CREATE TABLE ai_asset_snapshots (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id            UUID NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
  source_id           UUID NOT NULL REFERENCES ai_sources(id) ON DELETE CASCADE,
  snapshot_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  attributes          JSONB NOT NULL,
  capability_flags    JSONB NOT NULL DEFAULT '{}'::jsonb,
  sensitive_refs      JSONB NOT NULL DEFAULT '{}'::jsonb,
  prompt_hash         VARCHAR(128),
  raw_content_stored  BOOLEAN NOT NULL DEFAULT FALSE,
  change_detected     BOOLEAN NOT NULL DEFAULT FALSE,
  diff_summary        TEXT,
  UNIQUE (asset_id, snapshot_at)
);

CREATE TABLE ai_asset_tools (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id            UUID NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
  tool_name           VARCHAR(255) NOT NULL,
  tool_type           VARCHAR(64) NOT NULL,
  resource_ref        VARCHAR(700),
  has_write_access    BOOLEAN NOT NULL DEFAULT FALSE,
  requires_auth       BOOLEAN NOT NULL DEFAULT TRUE,
  approval_required   BOOLEAN NOT NULL DEFAULT FALSE,
  permissions         JSONB,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_assessment_runs (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id           UUID REFERENCES ai_sources(id) ON DELETE SET NULL,
  triggered_by        VARCHAR(64) NOT NULL,
  status              VARCHAR(32) NOT NULL,
  assets_discovered   INTEGER NOT NULL DEFAULT 0,
  assets_assessed     INTEGER NOT NULL DEFAULT 0,
  findings_created    INTEGER NOT NULL DEFAULT 0,
  findings_resolved   INTEGER NOT NULL DEFAULT 0,
  started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at        TIMESTAMPTZ,
  error_message       TEXT
);

CREATE TABLE ai_asset_findings (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id            UUID NOT NULL REFERENCES ai_assets(id) ON DELETE CASCADE,
  assessment_run_id   UUID REFERENCES ai_assessment_runs(id) ON DELETE SET NULL,
  check_id            VARCHAR(64) NOT NULL,
  dimension           VARCHAR(64) NOT NULL,
  severity            VARCHAR(32) NOT NULL,
  confidence          NUMERIC(4,2) NOT NULL DEFAULT 1.00,
  title               VARCHAR(500) NOT NULL,
  description         TEXT,
  evidence            JSONB,
  remediation         TEXT,
  owasp_llm_category  VARCHAR(16),
  status              VARCHAR(32) NOT NULL DEFAULT 'OPEN',
  finding_ref         UUID,
  first_detected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_confirmed_at   TIMESTAMPTZ,
  resolved_at         TIMESTAMPTZ,
  UNIQUE (asset_id, check_id, status)
);

CREATE TABLE platform.ai_assessment_rules (
  check_id              VARCHAR(64) PRIMARY KEY,
  dimension             VARCHAR(64) NOT NULL,
  title                 VARCHAR(500) NOT NULL,
  description           TEXT,
  severity              VARCHAR(32) NOT NULL,
  owasp_llm_category    VARCHAR(16),
  applies_to            TEXT[] NOT NULL,
  required_capabilities TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  remediation           TEXT,
  enabled               BOOLEAN NOT NULL DEFAULT TRUE,
  rule_version          INTEGER NOT NULL DEFAULT 1,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE platform.ai_tenant_risk_rollups (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             UUID NOT NULL,
  total_assets          INTEGER NOT NULL DEFAULT 0,
  critical_findings     INTEGER NOT NULL DEFAULT 0,
  high_findings         INTEGER NOT NULL DEFAULT 0,
  medium_findings       INTEGER NOT NULL DEFAULT 0,
  avg_ai_risk_score     NUMERIC(4,2),
  top_failing_checks    JSONB NOT NULL DEFAULT '[]'::jsonb,
  provider_breakdown    JSONB NOT NULL DEFAULT '{}'::jsonb,
  computed_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id)
);
```

Indexes:

```sql
CREATE INDEX idx_ai_assets_source_type ON ai_assets(source_id, asset_type);
CREATE INDEX idx_ai_assets_provider_region ON ai_assets(provider, region);
CREATE INDEX idx_ai_snapshots_asset_time ON ai_asset_snapshots(asset_id, snapshot_at DESC);
CREATE INDEX idx_ai_findings_asset_status ON ai_asset_findings(asset_id, status);
CREATE INDEX idx_ai_findings_check ON ai_asset_findings(check_id);
CREATE INDEX idx_ai_relations_from ON ai_asset_relations(from_asset_id);
CREATE INDEX idx_ai_relations_to ON ai_asset_relations(to_asset_id);
```

---

## 7. Adapter Contract

Every provider adapter implements the same contract.

```java
public interface AiSourceAdapter {
    String providerId();

    List<AiAssetSnapshotRecord> discover(AiSource source);

    AiAssetSnapshotRecord refresh(AiAsset asset, AiSource source);

    Set<CapabilityFlag> mapCapabilities(Map<String, Object> rawAttributes);
}
```

Normalized snapshot DTO:

```java
public record AiAssetSnapshotRecord(
    String externalId,
    AiAssetType assetType,
    String name,
    String provider,
    String accountRef,
    String region,
    String modelFamily,
    String modelVersion,
    String runtimeFramework,
    String identityRef,
    Map<String, Object> rawAttributes,
    Set<CapabilityFlag> capabilityFlags,
    List<AiAssetRelationRecord> relations,
    List<AiAssetToolRecord> tools,
    PromptHandlingResult promptHandling
) {}
```

Capability enum:

```java
public enum CapabilityFlag {
    INFERENCE,
    RETRIEVAL,
    TOOL_EXECUTION,
    CODE_EXECUTION,
    FILE_ACCESS,
    DATABASE_ACCESS,
    NETWORK_EGRESS,
    MEMORY_PERSISTENCE,
    SECRETS_ACCESS,
    CROSS_TENANT_ACCESS,
    POLICY_OVERRIDE,
    AUTONOMOUS_ACTION
}
```

The adapter is responsible for converting raw provider responses into normalized capability flags. The assessment
engine must not parse provider-specific API payloads directly.

---

## 8. Discovery Sources

### 8.1 AWS

Initial adapters:

- Bedrock Agents
- Bedrock Knowledge Bases
- Bedrock Guardrails
- Bedrock model and custom model inventory
- SageMaker endpoints and pipelines
- Lambda/ECS/EKS-hosted AI tools and MCP servers
- IAM role and policy analysis

### 8.2 Azure

Initial adapters:

- Azure AI Foundry projects and agents
- Azure OpenAI deployments
- Azure AI Search
- Azure ML endpoints and pipelines
- Azure Functions and Container Apps used as tools
- Managed identities, service principals, and role assignments

### 8.3 GCP

Initial adapters:

- Vertex AI endpoints and models
- Vertex AI Agent Builder / Reasoning Engine
- Vertex AI Pipelines
- Discovery Engine / Search data stores
- Cloud Run and Cloud Functions tools
- Service accounts and IAM policy

### 8.4 OpenAI, Hugging Face, self-hosted

Adapters should cover:

- OpenAI Assistants, vector stores, fine-tunes, tool definitions
- Hugging Face inference endpoints
- vLLM, Ollama, TGI, custom model gateways
- manually registered MCP servers

---

## 9. Prompt Asset Data Handling

Prompt content is sensitive. Scout may need to inspect prompts, but should not store raw prompt text by default.

Policy:

1. Fetch prompt text during discovery only inside the tenant assessment transaction.
2. Scan prompt text for secrets, unsafe instructions, and risky tool authorization.
3. Store `prompt_hash`, prompt length, provider reference, and redacted evidence.
4. Do not store raw prompt text in `attributes` unless a tenant explicitly enables "Store prompt evidence".
5. When raw prompt storage is enabled, encrypt it using the tenant secret/key management pattern and mark
   `raw_content_stored = true`.
6. Drift detection uses `prompt_hash`, not raw prompt text.

Example stored evidence:

```json
{
  "promptHash": "sha256:...",
  "secretDetected": true,
  "secretType": "api_key",
  "redactedSnippet": "Use API key sk-...redacted... for outbound calls"
}
```

---

## 10. Evaluation Runs

`EVALUATION_RUN` is valid but should be delivered later than core discovery.

Sources:

- provider-native evaluation jobs, such as Azure AI evaluation jobs
- tenant-uploaded red-team results
- Scout-initiated safety tests

Phase guidance:

- P1-P2: store provider evaluation references only as metadata on related assets
- P4: make `EVALUATION_RUN` a full asset type with relation `EVALUATED_BY`
- P5: add Scout-initiated evaluation runs

---

## 11. Assessment Rule Catalog

Stable check IDs are mandatory. They are used by findings, suppressions, analytics, documentation, and support.

### 11.1 Excessive Agency

| Check ID | Applies to | Severity | Required capability | Signal |
|---|---|---|---|---|
| `AGY-001` | `AGENT` | HIGH | `tool_execution` | Agent has write-capable tools |
| `AGY-002` | `AGENT` | HIGH | `network_egress` | Agent is internet-accessible without strong auth |
| `AGY-003` | `AGENT`, `AI_PIPELINE` | MEDIUM | `autonomous_action` | Destructive action has no approval gate |
| `AGY-004` | `AGENT` | HIGH | `tool_execution` | Agent callable by another agent without explicit trust |
| `AGY-005` | `PROMPT_ASSET`, `AGENT` | MEDIUM | `tool_execution` | Prompt grants unrestricted tool use |
| `AGY-006` | `MCP_SERVER` | CRITICAL | `file_access`, `tool_execution` | MCP exposes filesystem write/delete |
| `AGY-007` | `MCP_SERVER` | HIGH | `database_access` | MCP exposes database write without tenant or row scope |
| `AGY-008` | `MCP_SERVER` | HIGH | `tool_execution` | MCP tools callable without authentication |
| `AGY-009` | `AI_PIPELINE` | HIGH | `network_egress` | Pipeline calls external API outside allowlist |
| `AGY-010` | `AI_FUNCTION` | HIGH | `code_execution` | Callable function executes dynamic code |

### 11.2 Identity and Permissions

| Check ID | Applies to | Severity | Signal |
|---|---|---|---|
| `IAM-001` | `IDENTITY`, `AGENT`, `AI_FUNCTION` | HIGH | Wildcard action permission |
| `IAM-002` | `IDENTITY`, `AGENT`, `AI_FUNCTION` | HIGH | Wildcard resource permission |
| `IAM-003` | `IDENTITY` | MEDIUM | No permission boundary or equivalent control |
| `IAM-004` | `IDENTITY` | HIGH | Cross-account trust without strong condition |
| `IAM-005` | `IDENTITY` | MEDIUM | Identity shared across multiple production AI assets |
| `IAM-006` | `IDENTITY` | HIGH | Privilege escalation permission such as pass-role/policy attach |
| `IAM-007` | `IDENTITY` | CRITICAL | Identity can create or attach admin policy |

### 11.3 Guardrails and Safety

| Check ID | Applies to | Severity | Signal |
|---|---|---|---|
| `GRD-001` | `AGENT`, `MODEL_DEPLOYMENT` | HIGH | No guardrail/content filter attached |
| `GRD-002` | `AGENT`, `PROMPT_ASSET` | HIGH | No prompt injection/jailbreak control |
| `GRD-003` | `AGENT`, `MODEL_DEPLOYMENT` | MEDIUM | No sensitive data masking |
| `GRD-004` | `AGENT`, `KNOWLEDGE_BASE` | MEDIUM | No grounding or citation check |
| `GRD-005` | `AI_GATEWAY` | HIGH | Gateway routes to model without policy enforcement |
| `GRD-006` | `AI_GUARDRAIL` | MEDIUM | Guardrail is monitor-only where blocking is required |
| `GRD-007` | `MODEL_DEPLOYMENT` | MEDIUM | No quota or cost control |
| `GRD-008` | `FINE_TUNED_MODEL` | HIGH | No post fine-tune safety evaluation |

### 11.4 Data Exposure

| Check ID | Applies to | Severity | Signal |
|---|---|---|---|
| `DATA-001` | `KNOWLEDGE_BASE` | CRITICAL | Backing store is public |
| `DATA-002` | `VECTOR_STORE` | CRITICAL | Vector store API has no authentication |
| `DATA-003` | `VECTOR_STORE` | HIGH | Vector store is public or outside private network |
| `DATA-004` | `VECTOR_STORE` | HIGH | No tenant namespace isolation |
| `DATA-005` | `PROMPT_ASSET`, `AGENT` | CRITICAL | Secrets found in prompt/instructions |
| `DATA-006` | `AGENT` | HIGH | Memory store has no access control |
| `DATA-007` | `KNOWLEDGE_BASE` | HIGH | PII or regulated data without masking |
| `DATA-008` | `FINE_TUNED_MODEL` | HIGH | Unknown training data provenance |
| `DATA-009` | `MCP_SERVER` | HIGH | Tool returns raw rows without field filtering |
| `DATA-010` | `KNOWLEDGE_BASE` | MEDIUM | Missing metadata filters |

### 11.5 Network and Runtime

| Check ID | Applies to | Severity | Signal |
|---|---|---|---|
| `NET-001` | `MODEL_DEPLOYMENT` | HIGH | Public inference endpoint without private access path |
| `NET-002` | `MCP_SERVER` | CRITICAL | Public MCP endpoint without authentication |
| `NET-003` | `AGENT` | MEDIUM | Agent invocation not routed through private endpoint |
| `NET-004` | `VECTOR_STORE` | HIGH | Public vector store endpoint |
| `NET-005` | `AI_GATEWAY` | MEDIUM | No WAF/rate limiting in front of model endpoint |
| `NET-006` | `AI_PIPELINE` | MEDIUM | Egress not restricted to known destinations |

### 11.6 Supply Chain and Provenance

| Check ID | Applies to | Severity | Signal |
|---|---|---|---|
| `SC-001` | `MODEL_DEPLOYMENT` | MEDIUM | Model version not in approved catalog |
| `SC-002` | `FINE_TUNED_MODEL` | HIGH | Base model has advisory or is deprecated |
| `SC-003` | `AGENT` | HIGH | Agent framework has known CVE |
| `SC-004` | `AI_FUNCTION` | HIGH | Runtime image/layer has high CVE |
| `SC-005` | `MCP_SERVER` | HIGH | MCP runtime dependency has high CVE |
| `SC-006` | `MODEL_DEPLOYMENT` | MEDIUM | Model is end-of-life or provider-deprecated |
| `SC-007` | `FINE_TUNED_MODEL` | MEDIUM | Model drift from approved baseline |
| `SC-008` | `AI_PIPELINE` | MEDIUM | Pipeline uses unapproved dependency |

### 11.7 Drift, Tenant Boundary, Observability

| Check ID | Dimension | Applies to | Severity | Signal |
|---|---|---|---|---|
| `DRIFT-001` | Drift | All | MEDIUM | Tool surface changed since last approved snapshot |
| `DRIFT-002` | Drift | All | MEDIUM | Model version changed without reassessment |
| `DRIFT-003` | Drift | `PROMPT_ASSET` | MEDIUM | Prompt hash changed without approval |
| `TEN-001` | Tenant boundary | `VECTOR_STORE` | CRITICAL | Shared namespace across tenants |
| `TEN-002` | Tenant boundary | `IDENTITY` | HIGH | Shared runtime identity across tenants |
| `TEN-003` | Tenant boundary | `AI_GATEWAY` | HIGH | Global gateway policy overrides tenant policy |
| `OBS-001` | Observability | `AGENT`, `MCP_SERVER` | MEDIUM | Missing tool call audit log |
| `OBS-002` | Observability | `MODEL_DEPLOYMENT` | MEDIUM | Missing inference request metrics |
| `OBS-003` | Observability | `AI_PIPELINE` | MEDIUM | Missing step-level traceability |

---

## 12. Scoring Formula

Input: all open `ai_asset_findings` for one asset.

Severity base:

| Severity | Base score |
|---|---:|
| `CRITICAL` | 10 |
| `HIGH` | 7 |
| `MEDIUM` | 4 |
| `LOW` | 2 |
| `INFO` | 0.5 |

Dimension multipliers:

| Dimension | Multiplier |
|---|---:|
| `TENANT_BOUNDARY` | 1.25 |
| `AGENCY` | 1.15 |
| `NETWORK` | 1.10 |
| `DATA_EXPOSURE` | 1.10 |
| `IDENTITY` | 1.05 |
| `GUARDRAILS` | 1.00 |
| `SUPPLY_CHAIN` | 1.00 |
| `DRIFT` | 0.90 |
| `OBSERVABILITY` | 0.80 |

Finding contribution:

```text
finding_score = severity_base * dimension_multiplier * confidence
```

Asset score:

```text
asset_score =
  min(10,
    max(finding_score) * 0.60
    + average(top 3 finding_score values) * 0.30
    + drift_bonus * 0.10
  )
```

`drift_bonus = 10` when an asset has unapproved drift, otherwise `0`.

Tenant risk summary:

```text
tenant_ai_risk =
  max(asset_score) * 0.40
  + average(top 10 asset_score values) * 0.40
  + average(all asset_score values) * 0.20
```

This formula is intentionally simple for v1. It is deterministic, explainable, and supports trend analysis.

---

## 13. REST API Surface

Tenant APIs:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/ai-assets` | List AI assets with filters and pagination |
| `GET` | `/api/ai-assets/{id}` | Asset detail with latest snapshot and graph edges |
| `GET` | `/api/ai-assets/{id}/findings` | Findings for one AI asset |
| `GET` | `/api/ai-assets/{id}/relations` | Graph neighbors for one AI asset |
| `GET` | `/api/ai-sources` | List configured AI sources |
| `POST` | `/api/ai-sources` | Register an AI source |
| `PUT` | `/api/ai-sources/{id}` | Update source config |
| `DELETE` | `/api/ai-sources/{id}` | Disable/remove source |
| `POST` | `/api/ai-sources/{id}/sync` | Trigger manual discovery and assessment |
| `GET` | `/api/ai-assessment-runs` | Assessment run history |
| `GET` | `/api/ai-risk-summary` | Tenant-level AI risk aggregate |
| `GET` | `/api/ai-rules` | Effective enabled rule catalog for tenant |

Platform APIs:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/platform/ai-grid/tenants/summary` | Cross-tenant AI Grid summary |
| `GET` | `/api/platform/ai-grid/rules` | Platform rule catalog |
| `POST` | `/api/platform/ai-grid/rules` | Create/update platform rule |
| `GET` | `/api/platform/ai-grid/advisories` | Advisory feed status and records |

API rule: tenant endpoints must never read another tenant schema. Platform endpoints must read only platform summary
tables, not live tenant schemas.

---

## 14. Connect Page Integration

Add a new Connect category: `AI Discovery`.

Connector IDs:

| Connector ID | Display name | Source provider |
|---|---|---|
| `aws-bedrock-ai-grid` | AWS Bedrock AI Grid | AWS |
| `aws-sagemaker-ai-grid` | AWS SageMaker AI Grid | AWS |
| `azure-foundry-ai-grid` | Azure AI Foundry AI Grid | Azure |
| `azure-openai-ai-grid` | Azure OpenAI AI Grid | Azure |
| `gcp-vertex-ai-grid` | Google Vertex AI Grid | GCP |
| `openai-ai-grid` | OpenAI Assistants and Models | OpenAI |
| `huggingface-ai-grid` | Hugging Face AI Grid | Hugging Face |
| `mcp-server-ai-grid` | MCP Server | Self-hosted |
| `self-hosted-model-ai-grid` | Self-hosted Model Server | Self-hosted |

Connector form requirements:

- display name
- provider/account/subscription/project reference
- region selection
- credential reference
- sync interval
- test connection
- run discovery now
- last run status

Connect page should route AI source registrations into `ai_sources` and enqueue an AI Grid integration run.

---

## 15. Cross-Tenant Analytics

Platform dashboards must not query tenant schemas live. A scheduled job should:

1. Iterate tenants using the existing tenant execution pattern.
2. Compute tenant-local AI Grid summary.
3. Write only aggregate results into `platform.ai_tenant_risk_rollups`.
4. Exclude raw prompt text, raw provider payloads, and tenant-sensitive evidence.

Allowed platform summary fields:

- asset counts by provider and artefact type
- finding counts by severity and check ID
- score distribution
- connector health
- rule version coverage

Disallowed platform summary fields:

- prompt content
- raw tool arguments
- retrieved data snippets
- secrets
- tenant data source content

---

## 16. Findings Workflow Integration

AI Grid findings must graduate to standard Scout findings when policy says they are actionable.

Default policy:

- `CRITICAL` and `HIGH` create Scout findings
- `MEDIUM` stays as AI Grid posture finding unless tenant enables medium finding creation
- suppressed checks do not create Scout findings
- resolved AI Grid findings auto-close corresponding Scout findings

AI Grid findings participate in:

- ownership assignment
- SLA calculation
- ServiceNow incident creation
- suppression rules
- manual closure
- auto-close
- findings score configuration

---

## 17. Implementation Plan

### Phase 0 - Design hardening

- finalize taxonomy and capability flags
- implement schema migration
- seed `platform.ai_assessment_rules`
- add adapter interfaces and DTOs
- add Connect page category and connector IDs

### Phase 1 - Discovery and inventory

- implement AWS Bedrock adapter
- implement Azure AI Foundry adapter
- implement MCP server manual connector
- persist `ai_sources`, `ai_assets`, `ai_asset_relations`, and `ai_asset_snapshots`
- show AI inventory and graph edges in tenant UI

### Phase 2 - Deterministic assessment

- implement rule engine over capability flags
- create `ai_asset_findings`
- implement scoring formula
- add AI risk summary endpoint

### Phase 3 - Scout workflow integration

- create/reopen standard Scout findings for high and critical AI findings
- wire ownership, SLA, suppression, ServiceNow, and auto-close
- expose AI findings in existing Findings views

### Phase 4 - Provider expansion and advisories

- add GCP Vertex AI
- add OpenAI and Hugging Face
- add self-hosted model server adapter
- add model advisories and dependency CVE correlation for MCP/function runtimes

### Phase 5 - Evaluation runs

- make `EVALUATION_RUN` a full artefact type
- ingest provider-native evaluation jobs
- allow tenant-uploaded red-team results
- add Scout-initiated evaluation workflows

---

## 18. Design Rationale

The central decision is to make capability normalization the boundary between cloud discovery and assessment.
Adapters understand providers. Rules understand normalized capabilities. That keeps the rule catalog stable while cloud
providers change APIs and while Scout adds new integrations.

Tenant data remains in tenant schemas because AI artefacts can expose sensitive prompts, data sources, tools, and
identities. Platform data remains limited to rules, advisories, and aggregated summaries. This keeps the product
multi-tenant safe and makes platform analytics possible without live cross-schema reads.

The first shippable slice should be Bedrock, Azure AI Foundry, and MCP servers because those cover the highest-risk
agent, model, retrieval, identity, and tool-execution patterns. GCP, OpenAI, Hugging Face, and self-hosted runtimes
should follow through the same adapter contract.
