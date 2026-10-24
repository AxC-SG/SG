# PRD: AI Discovery Service

---

## 1. Summary

Organizations are deploying AI tools and models at a fast pace, but no one knows the full picture of what is actually in use. This project builds a standalone service that automatically finds and tracks every AI artifact across an organization — from AI libraries in code repositories to deployed cloud models to purchased AI software — and stores them in a clean, always-fresh inventory that any system can query.

---

## 2. Contacts

| Name | Role | Notes |
|---|---|---|
| Karthik Gowri | Product Owner | Defines requirements, reviews milestones, accepts deliverables |
| TBD | Intern Engineer | Sole builder of the service; owns architecture and implementation |
| TBD | Intern Mentor | Technical guidance; not a co-developer |

---

## 3. Background

### What is happening

Every company is now using AI. Some tools were bought by IT. Some were chosen by engineering teams. Some were added by individual employees. Most were never tracked. A developer adds the `openai` library to a project. A sales team signs up for an AI writing tool. An infrastructure engineer deploys a language model on a cloud server. None of these appear in any inventory.

This creates a real problem: security and governance teams cannot manage what they cannot see. Regulators, internal audit, and industry frameworks (NIST AI Risk Management Framework, OWASP LLM Top 10, MITRE ATLAS) all require organizations to know what AI systems they operate before they can apply any controls.

### Why now

Three things have changed in the last 12–18 months:

1. **AI adoption accelerated sharply.** The number of AI tools available to employees — both purchased and free — grew from dozens to hundreds. Organizations that had one or two AI systems now have dozens, often without realizing it.

2. **Cloud providers now have stable AI-specific APIs.** AWS Bedrock, Azure OpenAI, and Google Vertex AI all expose management APIs that let you enumerate deployed AI resources programmatically. This was not reliably available two years ago.

3. **AI is appearing in source code at scale.** Package managers now carry AI SDK libraries (`openai`, `anthropic`, `langchain`, `transformers`) as first-class dependencies. Scanning repos for AI usage has become both necessary and practical.

### Why this has not been solved

Existing security tools (vulnerability scanners, CMDB systems, cloud security posture tools) were built for traditional software. They find operating systems, CVEs, and network configurations — not AI model deployments, AI SDK usage, or purchased AI seat assignments. There is no off-the-shelf tool that provides a unified, cross-plane AI artifact inventory.

---

## 4. Objective

### Goal

Build a service that gives an organization a complete, accurate, and continuously refreshed inventory of every AI artifact in their environment — discovered automatically, without requiring employees to self-report.

### Why it matters

An organization cannot make decisions about AI risk, AI governance, or AI policy unless it first knows what AI it is running. This service is the foundation layer. It answers the question: *what AI exists here?* Other systems can then decide what to do about it.

### Key Results

| # | Result | Target | How Measured |
|---|---|---|---|
| KR1 | Artifact coverage across three discovery planes | ≥ 90% of AI artifacts in a target environment are discovered within 24 hours of deployment | Manual audit of 20 known artifacts against inventory |
| KR2 | Inventory freshness | No active artifact is more than 24 hours stale after its connector's last successful run | Staleness timestamps on artifact records |
| KR3 | Deduplication accuracy | The same real-world artifact found by multiple connectors produces exactly one inventory record | Automated test: seed same artifact in two sources, verify single record |
| KR4 | API availability | Service API responds to queries with < 500ms p99 latency under expected load | Load test at end of project |
| KR5 | Connector reliability | Each connector completes a scheduled run with < 2% error rate on artifact processing | Error rate tracked per connector run in run history table |

---

## 5. Market Segments

### Primary: Enterprise Security and Governance Teams

Security engineers, platform engineers, and CISOs at organizations with 500+ employees who are actively trying to understand and control their AI exposure. These teams know they have an AI governance gap but lack tooling to close it. They are comfortable with APIs and do not need a consumer-grade UI.

**Their job to be done:** *"Know everything AI-related running in our environment so we can decide what to allow, monitor, or shut down."*

**Constraints they operate under:**
- Cannot ask employees to self-report — reporting is incomplete and unreliable
- Cannot deploy agents on every endpoint — must use existing API surfaces (cloud APIs, source control APIs, SaaS admin APIs)
- Must handle multiple cloud accounts, multiple code repositories, multiple SaaS tools
- Data must be tenant-scoped — one organization's inventory must never be visible to another

### Secondary: AI Platform and MLOps Teams

Platform engineers responsible for AI infrastructure who want a single place to see what models are deployed, who owns them, and whether they are still active.

**Their job to be done:** *"Track what AI infrastructure we are running and who is responsible for it."*

---

## 6. Value Propositions

### Jobs being addressed

| Job | Current Pain | What This Service Provides |
|---|---|---|
| "Find every AI tool in use" | Manual spreadsheets, self-reporting, incomplete | Automated discovery across code, cloud, and SaaS in one inventory |
| "Know who owns each AI system" | No consistent attribution | Owner pulled from repo metadata, cloud account tags, and IdP group assignments |
| "Know if an AI system is still active" | No staleness tracking | Artifacts transition from ACTIVE → STALE → INACTIVE automatically based on re-confirmation cadence |
| "Avoid double-counting the same AI system found in two places" | Raw exports from multiple tools require manual deduplication | Canonical deduplication: one record per real artifact, multiple source attributions |
| "Get AI inventory data into our existing systems" | No standard API; manual exports | REST API with filtering, pagination, and incremental pull support |

### What users gain

- **Completeness.** A single inventory that spans code repositories, cloud accounts, and purchased SaaS — no plane is missed.
- **Accuracy.** Normalized, deduplicated records. Not raw dumps. Vendor names and model names follow a controlled vocabulary so queries are reliable.
- **Timeliness.** Connectors run on a schedule. The inventory reflects reality within hours, not months.
- **Traceability.** Every artifact record carries which connector found it and when. Nothing appears without an auditable source.

### Pains avoided

- No more asking teams to fill out AI inventory spreadsheets.
- No more discovering an unknown AI deployment only after a security incident.
- No more duplicate records because the same model shows up in three different exports.

---

## 7. Solution

### 7.1 User Experience

The primary interface is the **REST API**. There is no user-facing UI in this version. The intended user is an engineer or system querying the inventory programmatically.

**Connector status** is queryable via API so operators can see which connectors are healthy, when they last ran, and how many artifacts they found.

**Artifact lifecycle** is visible through the `status` field on every artifact: `ACTIVE` (confirmed recently), `STALE` (not re-confirmed within threshold), `INACTIVE` (not re-confirmed for extended period). No artifacts are hard-deleted; the history is preserved.

### 7.2 Key Features

#### Feature 1: Artifact Data Model

Every discovered AI artifact is stored in a canonical form with a shared envelope and a type-specific attribute bag.

**Artifact types:**

| Type | What It Represents |
|---|---|
| `AI_APPLICATION` | A purchased or licensed AI tool (e.g. GitHub Copilot, M365 Copilot, ChatGPT Enterprise) |
| `AI_MODEL` | A deployed AI model instance (e.g. GPT-4o on Azure OpenAI, Llama-3 on SageMaker) |
| `AI_AGENT` | An autonomous AI agent with tool-use capabilities (e.g. Bedrock Agent, Copilot Studio bot) |
| `AI_DEPENDENCY` | An AI library imported in source code (e.g. `openai`, `anthropic`, `langchain` found in a repository) |
| `AI_INFRASTRUCTURE` | AI compute or serving infrastructure (e.g. SageMaker endpoint, Bedrock provisioned throughput) |
| `AI_IDENTITY` | A non-human identity with access to AI systems (e.g. API key, service account with AI IAM roles) |

**Common envelope fields (all types):**

```
id                  Unique identifier
type                One of the six types above
name                Human-readable name
vendor              Normalized vendor name (e.g. "OpenAI", "Anthropic", "AWS")
tenant              Organization/tenant identifier
owner               Best-effort owner attribution (person, team, or system)
discovery_source[]  Which connectors found this artifact
first_seen          When the artifact was first discovered
last_seen           When it was last confirmed by a connector
confidence          HIGH / MEDIUM / LOW — how certain is the discovery
status              ACTIVE / STALE / INACTIVE
attributes          Type-specific key-value bag (e.g. model_id, parameter_count, license)
```

**Deduplication rule:** Two connector findings refer to the same real-world artifact if they share the same `type`, normalized `name`, and `vendor` within the same `tenant`. When matched, the record gets both sources in `discovery_source[]` rather than creating a duplicate.

**Staleness logic:**
- `ACTIVE` → `STALE`: artifact not re-confirmed within 3 consecutive connector run cycles
- `STALE` → `INACTIVE`: artifact not re-confirmed for 14 days
- `INACTIVE` → `ACTIVE`: artifact re-confirmed in a subsequent run

#### Feature 2: Connector Framework

A pluggable engine that all connectors share. Each connector is a self-contained module. The framework provides:

- **Scheduling:** Each connector runs on a configurable cron schedule
- **Run history:** Every run is recorded with start time, end time, status, artifact count, and error summary
- **Error isolation:** A failure in one connector does not affect others
- **Idempotency:** Re-running a connector produces the same inventory state; it does not create duplicates
- **Connector health API:** Exposes current status (HEALTHY / DEGRADED / FAILING) and last run metadata for each connector

Adding a new connector in the future requires implementing a single interface — no changes to the framework itself.

#### Feature 3: Source Code Scanner Connector

Scans all repositories in a GitHub or GitLab organization. Runs every 6 hours.

**What it detects:**

| Signal | Artifact Type Produced | Examples |
|---|---|---|
| AI library in package manifest | `AI_DEPENDENCY` | `openai`, `anthropic`, `langchain`, `transformers`, `torch`, `tensorflow`, `google-generativeai`, `cohere`, `mistralai`, `llama-index`, `semantic-kernel`, `crewai`, `autogen` across `package.json`, `requirements.txt`, `pom.xml`, `go.mod`, `Gemfile`, `Cargo.toml` |
| AI resource block in Infrastructure-as-Code | `AI_INFRASTRUCTURE` | `aws_bedrock_*`, `aws_sagemaker_*`, `azurerm_openai`, `azurerm_cognitive_account`, `google_vertex_ai_*` in Terraform, CloudFormation, Pulumi, Bicep |
| AI-specific configuration files | `AI_DEPENDENCY` | `.cursorrules`, `agent.yaml`, `.mcp.json`, `copilot-instructions.md`, `system_prompt.txt`, `.prompty` |
| AI provider API key naming patterns in non-secret files | `AI_IDENTITY` | Variable names matching `*OPENAI_API_KEY*`, `*ANTHROPIC_API_KEY*`, `*HUGGING_FACE_HUB_TOKEN*`, `*GEMINI_API_KEY*` |

**Ownership attribution:** The repo owner (from source control metadata) is used as the `owner` field on artifacts discovered in that repo.

**Out of scope for this connector:** File content reading beyond manifest files and IaC files. Source code logic analysis. Secret value extraction (key patterns detected by name only, never by value).

#### Feature 4: Cloud AI Services Connector

Enumerates AI resources in a cloud account via the cloud provider's control plane API. Runs every 4 hours. Targets one cloud provider (AWS or Azure — chosen based on the organization's primary cloud).

**AWS path — what it enumerates:**

| AWS Service | Resources Discovered | Artifact Type |
|---|---|---|
| Amazon Bedrock | Foundation model access grants, provisioned throughput units | `AI_MODEL`, `AI_INFRASTRUCTURE` |
| Amazon Bedrock Agents | Agent definitions, action group schemas, knowledge base connections | `AI_AGENT` |
| Amazon SageMaker | Deployed inference endpoints (real-time, serverless, async), model registry entries | `AI_MODEL`, `AI_INFRASTRUCTURE` |

**Azure path — what it enumerates:**

| Azure Service | Resources Discovered | Artifact Type |
|---|---|---|
| Azure OpenAI | Deployed model instances, fine-tuned models, Content Filter policies | `AI_MODEL` |
| Azure AI Foundry | Project definitions, connected resources, prompt flow deployments | `AI_INFRASTRUCTURE` |
| Azure ML Model Registry | Registered model versions, approval status, environment snapshots | `AI_MODEL` |

**Multi-account/subscription support:** The connector accepts a list of accounts (AWS) or subscriptions (Azure) and enumerates each in sequence.

**Ownership attribution:** Cloud resource tags (e.g. `Owner`, `Team`, `CostCenter`) are mapped to the `owner` field. If no tag exists, the account/subscription alias is used.

#### Feature 5: SaaS AI Admin Connector

Queries the admin APIs of the two most universally deployed enterprise AI tools. Runs every 12 hours.

**GitHub Copilot:**
- Seat assignments (which users are licensed)
- Active vs. inactive seats (GitHub tracks last-used date per seat)
- Business vs. Enterprise plan
- Policy settings (enabled/disabled features)
- Produces: `AI_APPLICATION` artifact per organization with `attributes` containing seat count, active user count, plan type

**Microsoft 365 Copilot:**
- Licensed user count and user list
- Enabled scenarios (Teams, Word, Excel, Outlook, Loop)
- Approved plugin/extension list
- Produces: `AI_APPLICATION` artifact per M365 tenant with `attributes` containing seat count, enabled scenarios, plugin list

**Ownership attribution:** M365 tenant admin and GitHub org admin are used as `owner` for these artifacts.

#### Feature 6: REST API

A clean, versioned API that exposes the inventory to downstream consumers.

**Endpoints:**

```
GET  /api/v1/artifacts
     Query parameters:
       type         Filter by artifact type (comma-separated)
       status       Filter by status; default: ACTIVE
       vendor       Filter by normalized vendor name
       since        ISO 8601 timestamp — return only artifacts updated after this time
       limit        Page size; default 100, max 500
       cursor       Pagination cursor from previous response

GET  /api/v1/artifacts/{id}
     Returns full artifact detail including all attributes and source history

GET  /api/v1/connectors
     Returns health status, last run time, artifact count, and error summary for each connector

GET  /api/v1/summary
     Returns artifact counts by type, by vendor, by status, and by connector source
     Includes overall inventory freshness metrics
```

**Authentication:** API key authentication on all endpoints. Keys are scoped to a tenant.

**Pagination:** Cursor-based. Every list response includes a `next_cursor` field when more results exist.

**Incremental pull:** The `since` parameter on `/artifacts` enables consumers to pull only what has changed since their last sync, making integration efficient.

### 7.3 Technology

The intern chooses the technology stack. The following constraints apply regardless of choice:

- The inventory must be stored in a persistent relational database
- The API must be HTTP/REST with JSON responses
- The connector framework must support scheduled execution without requiring external orchestration tools (no dependency on Airflow, Kubernetes CronJobs, or similar)
- The service must run locally in a single process for development purposes
- All external API calls must be tested with mock servers — no tests should hit live external APIs

Recommended but not required: a language and framework the intern already knows well, since time is short.

### 7.4 Assumptions

| # | Assumption | Risk if Wrong |
|---|---|---|
| A1 | The target organization uses GitHub or GitLab for source control (not Azure DevOps, Bitbucket, etc.) | Source Code connector covers fewer repos; must re-scope connector |
| A2 | The target organization uses AWS or Azure as their primary cloud (not GCP) | Cloud AI connector needs a different implementation path |
| A3 | GitHub Copilot and M365 Copilot are the primary procured SaaS AI tools | SaaS connector has lower value; may need to substitute a different SaaS target |
| A4 | Admin API credentials are available for all three connector targets | Any missing credentials reduce connector coverage |
| A5 | The same AI model name normalized the same way across cloud and source code will represent the same real-world model | Deduplication logic may produce false merges or missed merges; requires validation |
| A6 | 12 weeks is enough for one engineer to build the framework, three connectors, and the API to production quality | Scope must be cut if timeline pressure emerges — SaaS connector is the lowest priority |

---

## 8. Release

### Timeline

**12 weeks total.** No exact dates — relative to the intern's start date.

| Phase | Weeks | Deliverable |
|---|---|---|
| Design | 1–2 | Architecture document, artifact data model, API contract, connector framework skeleton |
| Source Code Connector | 3–6 | Working connector scanning a real GitHub org; artifacts appearing in inventory |
| Cloud AI Connector | 7–9 | Working connector enumerating AWS or Azure AI resources; deduplication against source code findings |
| SaaS AI Connector | 10–11 | Working connector pulling GitHub Copilot and M365 Copilot data |
| Polish | 12 | Staleness logic, enrichment from reference data, API completeness, error handling, documentation |

### Version 1 (this project)

- Connector framework
- Source Code Scanner (GitHub/GitLab)
- Cloud AI Services connector (one cloud provider)
- SaaS AI Admin connector (GitHub Copilot + M365 Copilot)
- Six artifact types with deduplication and staleness logic
- REST API with filtering, pagination, and incremental pull

### Future Versions (not in scope for this project)

- Additional connectors: identity/API key vaults, MLOps platforms, MCP infrastructure, agent platforms
- Second cloud provider support
- Additional SaaS AI tools (ChatGPT Enterprise, Salesforce Einstein, Atlassian Intelligence)
- Shadow AI detection via CASB or DNS log analysis
- Inventory UI / dashboard
- Webhook / push notifications on inventory changes
- AI Bill of Materials (AI BOM) export in standard formats

---

*Document version: 1.0 — May 2026*
