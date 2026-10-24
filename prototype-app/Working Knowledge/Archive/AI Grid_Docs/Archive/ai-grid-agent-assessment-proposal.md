# AI Grid — Agent Assessment Logic Proposal

> **Scope:** Assessment framework for AI agents, models, and artifacts ingested from AWS Bedrock and Azure AI Foundry into Scout's AI Grid security layer.

---

## Overview

AI agents are not just software — they are autonomous actors with tools, memory, and external reach. A CVE-only approach is insufficient. Assessment must cover four layers:

| Layer | Focus |
|---|---|
| 1. Discovery & AI-BOM | Inventory every AI asset across sources |
| 2. Vulnerability Assessment | CVEs in ML frameworks and base models |
| 3. Weakness Assessment | Misconfigurations mapped to OWASP LLM Top 10 |
| 4. Threat Scoring | Composite AI Risk Score per asset |

---

## Layer 1: Discovery & AI-BOM Ingestion

### AWS Bedrock — APIs to call

```
bedrock-agent:
  ListAgents              → agent ID, name, foundationModel, idleSessionTTL
  GetAgent                → executionRoleArn, instruction, promptOverrideConfig
  ListAgentActionGroups   → Lambda ARNs, API schemas, S3 actions
  ListAgentKnowledgeBases → KB ID, type (VECTOR), data source ARNs
  GetGuardrail            → contentFilters, sensitiveInfoPolicy, groundingConfig
  GetKnowledgeBase        → storageConfig (OpenSearch/Pinecone/Aurora), embeddingModel
```

### Azure AI Foundry — APIs to call

```
Azure AI Projects SDK:
  projects.list()       → project name, hub, region
  agents.list()         → agent ID, model, tools (code_interpreter, bing, function)
  deployments.list()    → model name, version, capacity
  connections.list()    → connected resources (storage, search, key vaults)
  evaluations.list()    → safety eval results

Azure OpenAI:
  deployments.list()    → model, version, content_filter_policy
```

### AI-BOM Record Structure

One record per discovered agent:

```json
{
  "agentId": "ABCDEF",
  "source": "aws-bedrock",
  "foundationModel": "anthropic.claude-3-5-sonnet-20241022-v2:0",
  "modelFamily": "claude",
  "modelVersion": "3.5-sonnet",
  "runtimeFramework": null,
  "tools": ["lambda:arn:aws:...", "s3:bucket/docs"],
  "knowledgeBases": ["KB-001"],
  "executionRoleArn": "arn:aws:iam::123456789:role/agent-role",
  "guardrailId": null,
  "internetAccess": false,
  "codeExecution": false,
  "memoryEnabled": true
}
```

---

## Layer 2: Vulnerability Assessment

### 2a. Framework & Dependency CVEs

Map the ML stack to the existing NVD/GHSA pipeline. Agents built on common frameworks have tracked CVEs:

| Package | Known CVEs | Risk Class |
|---|---|---|
| `langchain` / `langchain-community` | CVE-2024-5998, CVE-2023-46229 | RCE via tool injection |
| `llama-index` | CVE-2024-4181 | Arbitrary code execution |
| `autogen` | Active advisories | Prompt-to-code injection |
| `transformers` (HuggingFace) | CVE-2024-3568 | Pickle deserialization RCE |
| `torch` / `torchvision` | CVE-2022-45907 | Arbitrary code via model load |
| `ollama` | CVE-2024-37032 | Path traversal, RCE |

**Assessment logic:**

1. For each agent, extract `runtimeDependencies` from Lambda layer, container image, or deployment manifest
2. Normalize to CPE identifiers
3. Feed into existing CVE correlation pipeline (same as BOM Grid)
4. Create findings with `assetType = AI_AGENT`

### 2b. Base Model Advisories

A new advisory category. Maintain a dedicated `ai_model_advisories` table:

```sql
CREATE TABLE tenant_default.ai_model_advisories (
  id            UUID PRIMARY KEY,
  model_family  VARCHAR(100),   -- 'claude', 'llama', 'mistral', 'gpt'
  model_version VARCHAR(50),
  advisory_id   VARCHAR(100),   -- GHSA ID or custom
  severity      VARCHAR(20),
  description   TEXT,
  advisory_url  VARCHAR(500),
  published_at  TIMESTAMP
);
```

**Ingestion sources:**
- HuggingFace security advisories
- ML vendor security bulletins (Anthropic, OpenAI, Meta, Mistral)
- MITRE ATLAS entries
- NIST NVD model-related CVEs

---

## Layer 3: Weakness Assessment (Misconfiguration)

Mapped against **OWASP LLM Top 10** and cloud security benchmarks. Each dimension scores 0–10 and feeds into the composite AI Risk Score.

---

### A. Excessive Agency — LLM08 (Weight: 30%)

Agents that can take write actions or call unbounded external services represent the highest blast radius.

| Check | Severity |
|---|---|
| Agent has write-access tools (S3 put, DB write, Lambda invoke) | HIGH |
| Agent can call external APIs without an allowlist | HIGH |
| No human-in-loop required for destructive actions | MEDIUM |
| Tool permissions broader than agent's stated purpose | MEDIUM |
| Agent is callable by other agents without an auth boundary | HIGH |

```java
// Scoring pseudocode
int agencyScore = 0;
if (agent.hasWriteTools())               agencyScore += 30;
if (agent.hasUnboundedInternetAccess())  agencyScore += 25;
if (!agent.hasHumanApprovalForWrites())  agencyScore += 20;
if (agent.isCallableByOtherAgents())     agencyScore += 15;
// normalize to 0–10
```

---

### B. Missing Guardrails — LLM01 / LLM06 (Weight: 25%)

| Check | Bedrock Signal | Azure Signal |
|---|---|---|
| No content filter configured | `guardrailId == null` | `content_filter_policy == none` |
| No prompt injection protection | `topicPolicy == null` | `jailbreak_filter == off` |
| No sensitive data masking | `sensitiveInfoPolicy == null` | `pii_filter == off` |
| No grounding / hallucination check | `groundingPolicy == null` | no Azure groundedness eval |

---

### C. IAM / Identity Over-Privilege (Weight: 20%)

**AWS Bedrock — checks on `executionRoleArn`:**

```
Fetch IAM policy for executionRoleArn
  Flag: s3:* or dynamodb:* wildcard actions
  Flag: lambda:InvokeFunction on * (all functions)
  Flag: no resource-level constraint (arn:aws:s3:::* vs specific bucket)
  Flag: no permission boundary attached
  Flag: cross-account trust in assume-role policy without condition
```

**Azure AI Foundry — checks on managed identity:**

```
Fetch role assignments for managed identity
  Flag: Contributor or Owner scoped to subscription or resource group
  Flag: Storage Blob Data Contributor on * (all storage)
  Flag: no conditional access policy on identity
  Flag: identity shared across multiple agents
```

---

### D. Data Exposure — LLM06 (Weight: 15%)

| Check | Severity |
|---|---|
| Knowledge base backed by public S3 bucket | HIGH |
| OpenSearch/vector store domain not in VPC | HIGH |
| Vector store has no authentication | CRITICAL |
| Agent system instructions contain secrets or API keys | CRITICAL |
| No logging of agent invocations (CloudTrail / Azure Monitor) | MEDIUM |
| Knowledge base contains PII (detected via data classification) | HIGH |

---

### E. Network Exposure (Weight: 10%)

**AWS Bedrock:**
- Is the agent API endpoint routed via VPC endpoint or public internet?
- Are Lambda action group functions inside a VPC?
- Is CloudTrail logging enabled for `bedrock:InvokeAgent`?

**Azure:**
- Is a private endpoint configured on the AI hub?
- Are Azure Monitor diagnostic settings enabled?
- Is network isolation enforced on the AI project?

---

## Layer 4: AI Risk Score

Composite score (0–10) per AI asset, analogous to the existing S.AI Risk Score for CVEs:

```
AI Risk Score =
  0.30 × AgencyScore          (excessive permissions / tools)
+ 0.25 × GuardrailScore       (missing safety controls)
+ 0.20 × IAMScore             (identity over-privilege)
+ 0.15 × DataExposureScore    (knowledge base / vector store risk)
+ 0.10 × NetworkScore         (endpoint exposure, logging gaps)
```

### Risk Bands

| Score | Band | Example Profile |
|---|---|---|
| 8–10 | **Critical** | Write tools + no guardrails + wildcard IAM |
| 6–7 | **High** | Missing guardrails or over-privileged IAM role |
| 4–5 | **Medium** | Some controls present but notable gaps |
| 0–3 | **Low** | Least-privilege IAM, guardrails configured, VPC isolated |

---

## Domain Model

```sql
-- Core asset inventory
CREATE TABLE tenant_default.ai_assets (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            UUID NOT NULL,
  source               VARCHAR(50) NOT NULL,   -- 'aws-bedrock', 'azure-foundry'
  asset_type           VARCHAR(50) NOT NULL,   -- 'AGENT', 'MODEL', 'KNOWLEDGE_BASE', 'VECTOR_STORE'
  external_id          VARCHAR(255) NOT NULL,
  name                 VARCHAR(255),
  model_family         VARCHAR(100),
  model_version        VARCHAR(100),
  region               VARCHAR(100),
  account_id           VARCHAR(100),
  execution_role       VARCHAR(500),
  guardrail_configured BOOLEAN DEFAULT FALSE,
  internet_access      BOOLEAN DEFAULT FALSE,
  code_execution       BOOLEAN DEFAULT FALSE,
  memory_enabled       BOOLEAN DEFAULT FALSE,
  tool_count           INTEGER DEFAULT 0,
  write_tool_count     INTEGER DEFAULT 0,
  ai_risk_score        NUMERIC(4,2),
  last_discovered_at   TIMESTAMP,
  last_assessed_at     TIMESTAMP
);

-- Tools attached to each agent
CREATE TABLE tenant_default.ai_asset_tools (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id    UUID NOT NULL REFERENCES ai_assets(id),
  tool_type   VARCHAR(50),    -- 'LAMBDA', 'S3', 'API', 'CODE_INTERPRETER', 'SEARCH'
  resource_arn VARCHAR(500),
  permissions  TEXT            -- JSON array of permission strings
);

-- Weakness / misconfiguration findings
CREATE TABLE tenant_default.ai_asset_findings (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ai_asset_id       UUID NOT NULL REFERENCES ai_assets(id),
  check_id          VARCHAR(100) NOT NULL,
  severity          VARCHAR(20) NOT NULL,
  title             VARCHAR(500),
  description       TEXT,
  owasp_llm_category VARCHAR(20),   -- 'LLM01'..'LLM10'
  remediation       TEXT,
  status            VARCHAR(20) DEFAULT 'OPEN',
  detected_at       TIMESTAMP DEFAULT now(),
  resolved_at       TIMESTAMP
);

-- Base model advisories (equivalent of CVEs for AI models)
CREATE TABLE tenant_default.ai_model_advisories (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_family  VARCHAR(100),
  model_version VARCHAR(50),
  advisory_id   VARCHAR(100),
  severity      VARCHAR(20),
  description   TEXT,
  advisory_url  VARCHAR(500),
  published_at  TIMESTAMP
);
```

---

## Ingestion Client Architecture

```
AiGridDiscoveryService
  |
  |-- BedrockAgentDiscoveryClient          (AWS SDK: bedrock-agent)
  |     |-- listAndSyncAgents()
  |     |-- syncActionGroups()
  |     |-- syncKnowledgeBases()
  |     `-- syncGuardrails()
  |
  |-- AzureFoundryDiscoveryClient          (Azure AI Projects SDK)
  |     |-- listAndSyncAgents()
  |     |-- listAndSyncDeployments()
  |     `-- syncConnections()
  |
  `-- AiAssetAssessmentService
        |-- assessAgencyRisk()             (tool permissions analysis)
        |-- assessGuardrailGaps()          (content filter checks)
        |-- assessIamRisk()                (calls IAM / Azure RBAC APIs)
        |-- assessDataExposure()           (KB, vector store, logging)
        |-- assessNetworkExposure()        (VPC, private endpoints)
        `-- computeAiRiskScore()           (weighted composite)
```

### Auth Model

| Source | Auth Mechanism |
|---|---|
| AWS Bedrock | IAM Role ARN + External ID (cross-account assume-role, mirrors AWS Discovery connector) |
| Azure AI Foundry | Managed Identity Client ID + Tenant ID + Subscription ID |

---

## OWASP LLM Top 10 Coverage Map

| Category | Covered By |
|---|---|
| LLM01 Prompt Injection | Guardrail gap check, tool input validation |
| LLM02 Insecure Output Handling | Tool output review (future) |
| LLM03 Training Data Poisoning | Model advisory feed |
| LLM04 Model Denial of Service | Rate limit / throttle config check |
| LLM05 Supply Chain Vulnerabilities | Framework CVE correlation (BOM Grid pipeline) |
| LLM06 Sensitive Information Disclosure | Guardrail + data exposure checks |
| LLM07 Insecure Plugin Design | Action group tool permission analysis |
| LLM08 Excessive Agency | Agency risk scoring |
| LLM09 Overreliance | Grounding / hallucination guardrail check |
| LLM10 Model Theft | IAM / network exposure checks |

---

## Phased Delivery Plan

| Phase | Scope | Value Delivered |
|---|---|---|
| **P1** | Discovery + AI-BOM | Full inventory of agents, models, KBs across Bedrock and Azure Foundry |
| **P2** | Weakness assessment | Guardrail gap, IAM over-privilege, data exposure findings with OWASP mapping |
| **P3** | CVE correlation | ML framework dependency CVEs via existing BOM Grid pipeline |
| **P4** | AI Risk Score + findings workflow | Risk-ranked findings queue, SLA enforcement, ownership routing |
| **P5** | Base model advisory feed + prompt injection surface analysis | Model-level CVE equivalents, agentic attack surface mapping |

> P1 + P2 deliver the most visible value fastest. Customers will immediately see which agents are running without guardrails or with wildcard IAM, before any CVE work is needed.

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS](https://atlas.mitre.org/) — adversarial threat landscape for AI systems
- [AWS Bedrock Security Best Practices](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [Azure AI Foundry Security](https://learn.microsoft.com/en-us/azure/ai-studio/concepts/security-overview)
- [NIST AI RMF](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf)
