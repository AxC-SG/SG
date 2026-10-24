# ScoutGrid Associate Product Manager Training Plan

**Audience:** Newly hired Associate Product Manager  
**Duration:** 8 weeks of structured learning, followed by a 30-day applied ownership period  
**Expected commitment:** 8–10 hours per week of structured training, plus normal participation in product rituals  
**Primary outcome:** The APM can explain ScoutGrid to a customer, navigate its major workflows, reason about security exposure management, write evidence-based product requirements, and independently own a small product area.

## 1. Learning outcomes

By the end of the program, the APM should be able to:

1. Explain the customer problem ScoutGrid solves and distinguish inventory, vulnerability, posture, exposure, finding, and risk.
2. Describe ScoutGrid's end-to-end data flow from connectors and inventory through intelligence, correlation, prioritization, findings, remediation, and reporting.
3. Demonstrate the principal user journeys for a security analyst, cloud security lead, AI security lead, tenant administrator, and platform owner.
4. Explain the purpose and limitations of SBOM, CVE, CVSS, EPSS, CISA KEV, CPE, PURL, VEX, EOL, attack paths, and exposure evidence.
5. Explain ScoutGrid AI Grid's discovery, static posture, exposure correlation, policy governance, and runtime evidence capabilities without overstating what the product proves.
6. Convert customer problems into personas, jobs-to-be-done, requirements, acceptance criteria, success metrics, and a prioritized backlog.
7. Use product telemetry, customer evidence, and delivery constraints to make a defensible product recommendation.

## 2. Training principles

- Use a **learn → observe → do → teach-back** cycle every week.
- Spend approximately **40% on the domain, 40% on the product, and 20% on product-management practice**.
- Use one representative demo tenant throughout the program so that concepts connect across workflows.
- Treat repository documents and the running product as the source of truth. Clearly label roadmap items, previews, and known limitations.
- Never equate a detected configuration condition with a proven exploit. Always identify the evidence, its freshness, and its confidence.
- Keep a glossary, open-question log, and weekly learning journal.

## 3. Eight-week curriculum

### Week 1 — Customer, market, and product foundations

**Domain focus**

- Why attack surface and exposure management emerged: fragmented assets, noisy findings, weak ownership, and slow remediation.
- The difference between vulnerability management, cloud security posture management, application security, attack-surface management, and continuous threat exposure management.
- Primary stakeholders: CISO, cloud security, vulnerability management, AppSec, AI platform, GRC, infrastructure, and application owners.
- Core customer jobs: know what exists, know what is exposed, decide what matters, assign ownership, remediate, and prove progress.

**ScoutGrid focus**

- Product positioning and initial ideal customer profile.
- Major product areas: exposure dashboard, findings, fix intelligence, vulnerability repository, inventory, end-of-life, connectors, AI Grid, policies, operations, configuration, and administration.
- ScoutGrid's narrow entry promise: evidence-backed AI inventory and posture/exposure prioritization, with broader vulnerability operations as an expansion path.
- Current capability versus roadmap; understand that implementation, release readiness, and customer-validated value are different states.

**Activities**

- Attend a founder/product overview and one sales or discovery call.
- Complete a guided product tour using a demo tenant.
- Read `SCOUTGRID_GTM_30_60_90.md` and the core concept section of `prototype-app/docs/business-logic-guide.md`.
- Interview one sales/customer-facing stakeholder and one engineer.

**Deliverable and checkpoint**

- Produce a one-page product brief covering target customer, top three problems, value proposition, product pillars, and explicit non-claims.
- Give a five-minute teach-back: “What ScoutGrid does, for whom, and why now.”

### Week 2 — Security exposure management fundamentals

**Domain focus**

- Asset, software component, vulnerability, weakness, misconfiguration, threat, exploitability, exposure, control, and risk.
- CVE and CWE; CVSS severity versus likelihood; EPSS probability; CISA KEV evidence of known exploitation.
- Asset criticality, internet reachability, identity privilege, sensitive-data access, compensating controls, and business context.
- A practical prioritization model: severity + exploit likelihood + exposure path + business impact + evidence confidence + remediation cost.
- Exposure lifecycle: discover, normalize, correlate, validate, prioritize, assign, remediate, verify, and report.

**ScoutGrid focus**

- Vulnerability intelligence sources: NVD, GHSA, CISA KEV, EPSS, CSAF/VEX, EUVD, and JVN.
- Why ScoutGrid combines security intelligence with tenant inventory and organizational context.
- Finding lifecycle: open, acknowledged, in progress, resolved, suppressed, false positive, and risk accepted.
- Difference between an inventory observation, an applicability decision, an organizational CVE record, and an actionable finding.

**Activities**

- Trace one CVE from source intelligence to affected software, assets, organizational assessment, and finding.
- Compare three CVEs: high CVSS only, high EPSS, and KEV-listed. Explain why their priorities may differ.
- Review one suppression and one risk-acceptance scenario.

**Deliverable and checkpoint**

- Create a two-page domain glossary and a prioritization decision tree.
- Pass a scenario review in which the APM prioritizes five findings and explains the evidence and uncertainty behind each decision.

### Week 3 — Inventory, discovery, and software identity

**Domain focus**

- Why incomplete inventory undermines exposure management.
- SBOM concepts and formats: CycloneDX and SPDX.
- Software identity and matching: package URL (PURL), CPE, vendor/product/version normalization, and version ranges.
- CMDB and cloud discovery; coverage, freshness, source authority, duplicates, and reconciliation.
- End-of-life risk and why unsupported software is different from a known CVE.

**ScoutGrid focus**

- SBOM upload/fetch and GitHub/GHCR paths.
- ServiceNow, SCCM/MECM, AWS, and Azure discovery.
- Asset, software identity, inventory component, and source lineage.
- Deduplication, CPE resolution, inventory quality, sync runs, and connector health.
- EOL pipeline and lifecycle views.

**Activities**

- Ingest a sample CycloneDX or SPDX file and inspect the resulting components.
- Follow an asset from source connector through software identity and component records.
- Diagnose a deliberately ambiguous or incomplete identity match.
- Review freshness and failed-sync states.

**Deliverable and checkpoint**

- Draw the inventory data flow and document the top five ways inventory quality can fail.
- Write a short problem statement and acceptance criteria for one inventory-quality improvement.

### Week 4 — Correlation, findings, and remediation workflow

**Domain focus**

- Applicability versus presence: why a component name match is insufficient.
- CPE applicability and version-range evaluation.
- VEX states: affected, not affected, fixed, and under investigation.
- False positives, exceptions, suppressions, risk acceptance, SLAs, ownership, and auditability.
- Remediation choices: patch, upgrade, mitigate, isolate, remove, compensate, accept, or monitor.

**ScoutGrid focus**

- Correlation engine and component-vulnerability state.
- Organizational CVE aggregation and CVE Assessment Workbench.
- Finding creation modes, lifecycle, event history, ownership rules, and auto-close behavior.
- Fix intelligence, remediation campaigns, and ServiceNow incident integration.
- Audit trail and tenant-scoped workflows.

**Activities**

- Trace an applicable component from correlation through a finding and remediation decision.
- Run a mock triage session with security and application-owner roles.
- Review one VEX-driven applicability change and its downstream effect.
- Draft a small remediation campaign for a selected CVE.

**Deliverable and checkpoint**

- Produce a workflow map with actors, decisions, evidence, handoffs, and failure points.
- Facilitate a 30-minute mock triage and correctly distinguish product behavior from analyst judgment.

### Week 5 — AI security and AI Grid

**Domain focus**

- AI system inventory: models, agents, prompts, tools, identities, knowledge sources, endpoints, guardrails, and data paths.
- AI posture risks: weak guardrails, excessive privilege, public access, unsafe tool reach, untrusted MCP connections, sensitive retrieval, and unclear ownership.
- Static configuration evidence versus runtime evidence.
- Prompt injection, tool abuse, data leakage, insecure agency, and excessive autonomy at a product-manager level.
- Governance frameworks as organizing and reporting mechanisms, not proof of certification.

**ScoutGrid focus**

- AWS Bedrock/AgentCore/SageMaker, Azure AI/Foundry/ML, and Copilot Studio discovery.
- AI assets, relationships, agent systems, ownership, evidence snapshots, facts, and findings.
- AI policies, policy versions, tenant selections, exceptions, readiness, approvals, and framework mappings.
- Static posture findings, correlated AI exposures, and separate AI runtime findings.
- Evidence freshness, hypothesis versus validated exposure, and privacy-minimized metadata.
- Current boundary: runtime policies are implemented but preview/paused pending live evidence, certification, and rollout.

**Activities**

- Trace one AI agent across inventory, identity, tools, data sources, guardrails, policies, and findings.
- Compare a static posture issue, a correlated exposure path, and a runtime-policy finding.
- Review an AI policy's evidence requirements and explain what happens when evidence is missing or stale.
- Read `AI_GRID_IMPLEMENTED_CAPABILITIES.md`, especially current state, shared platform, Phase 1, Phase 2, and remaining work.

**Deliverable and checkpoint**

- Give a ten-minute AI Grid customer demonstration with accurate evidence language.
- Create a capability matrix with four labels: generally available/current, preview or paused, limited/conditional, and not implemented.

### Week 6 — Platform, trust, and enterprise readiness

**Domain focus**

- Multi-tenancy, tenant isolation, role-based access, least privilege, and audit logs.
- Enterprise connector trust: read-only access, credential models, permission preflight, rate limits, and failure handling.
- Data minimization, retention, legal hold, data residency questions, and customer security reviews.
- Operational requirements: reliability, freshness, scale, observability, supportability, and change control.

**ScoutGrid focus**

- Schema-per-tenant architecture and tenant context.
- Platform owner, tenant admin, analyst, and support-access boundaries.
- Connector budgets, capability manifests, scan cadence, evidence freshness, and readiness reporting.
- Policy release lifecycle, answer keys, precision review, canary rollout, and release manifests.
- Known limitations and the importance of not turning missing evidence into a pass.

**Activities**

- Review architecture and security-model sections of `prototype-app/docs/architecture.md`.
- Walk through connector setup and permission expectations.
- Participate in a mock enterprise security review.
- Analyze a stale-data incident and propose both customer-facing and operational responses.

**Deliverable and checkpoint**

- Produce an enterprise FAQ covering tenancy, access, collected data, evidence retention, connector permissions, freshness, and limitations.
- Pass a review with engineering/security in which answers are scored for accuracy and appropriate qualification.

### Week 7 — Product discovery, requirements, and metrics

**Product-management focus**

- Problem interviews, jobs-to-be-done, assumptions, and evidence quality.
- Problem statement, target user, current workaround, impact, desired outcome, and constraints.
- User stories, workflow requirements, non-functional requirements, acceptance criteria, and edge cases.
- Prioritization using reach, impact, confidence, effort, strategic fit, risk reduction, and learning value.
- Outcome metrics versus output metrics.

**ScoutGrid application**

- Suggested north-star direction: valuable exposures investigated and resolved with trustworthy evidence.
- Supporting metrics: inventory coverage/freshness, correlation confidence, actionable finding rate, time to triage, time to owner, time to remediate, reopen rate, suppression rate, connector success, and policy readiness.
- Guardrail metrics: false-positive rate, unknown/no-decision rate, stale evidence, tenant isolation defects, ingestion failures, and analyst effort.

**Activities**

- Observe or conduct two stakeholder/customer interviews.
- Analyze one funnel or workflow using available product data; if telemetry is absent, write the measurement specification.
- Turn one validated pain point into a discovery brief and testable hypothesis.
- Run a prioritization session with product, design, and engineering.

**Deliverable and checkpoint**

- Produce a concise product requirements document with problem evidence, scope, non-goals, workflow, acceptance criteria, dependencies, risks, rollout, and metrics.
- Defend the prioritization and identify what new evidence would change the decision.

### Week 8 — Capstone and ownership readiness

**Capstone assignment**

Choose one bounded ScoutGrid problem, such as inventory quality, evidence freshness, finding triage, remediation handoff, AI exposure explanation, connector onboarding, or policy readiness.

**Required work**

1. Interview at least three relevant stakeholders, including one customer-facing stakeholder and one engineer.
2. Demonstrate the current workflow and document evidence, pain points, and constraints.
3. Define the target user and measurable problem.
4. Compare at least two solution approaches and explicitly state non-goals.
5. Produce workflow, requirements, edge cases, acceptance criteria, telemetry, rollout, and risk plan.
6. Validate technical feasibility and security implications with engineering.
7. Present a recommendation and respond to challenge questions.

**Graduation standard**

- Product accuracy: explains current behavior and boundaries without material errors.
- Domain reasoning: connects security evidence to customer risk without relying only on severity.
- Customer clarity: anchors the proposal in a specific user and measurable problem.
- Execution quality: produces testable requirements, handles edge cases, and defines rollout and telemetry.
- Judgment: makes tradeoffs explicit and identifies uncertainty.

The APM graduates when the product manager and engineering lead agree that the person can independently own a low-to-medium-risk product increment.

## 4. Applied ownership period — Days 61–90

During the following 30 days, the APM should:

- Own one small discovery or delivery initiative from problem framing through review.
- Lead weekly backlog refinement for the selected product area.
- Join at least two customer calls and publish structured notes, insights, and follow-ups.
- Review product metrics weekly and investigate one meaningful anomaly or gap.
- Run one product demo for an internal or friendly-customer audience.
- Publish one product decision record with context, options, decision, evidence, risks, and revisit trigger.
- Propose the next-quarter learning agenda for the owned area.

## 5. Weekly operating cadence

| Activity | Cadence | Purpose |
|---|---:|---|
| Domain lesson or reading | 2 hours/week | Build security fundamentals |
| Guided product lab | 2 hours/week | Connect concepts to ScoutGrid behavior |
| SME shadowing | 1–2 hours/week | Learn customer, engineering, and operational context |
| Product-management exercise | 2 hours/week | Practice discovery, requirements, metrics, and prioritization |
| Teach-back and feedback | 45 minutes/week | Reveal gaps and correct terminology |
| Learning journal and glossary | 30 minutes/week | Preserve questions, insights, and decisions |

Recommended standing sessions:

- Monday: learning goals and domain lesson.
- Tuesday or Wednesday: product lab or customer-call shadowing.
- Thursday: artifact working session with the relevant SME.
- Friday: teach-back, artifact review, and next-week goals.

## 6. Mentors and responsibilities

| Role | Responsibility |
|---|---|
| Product manager/founder | Product narrative, customers, priorities, weekly coaching, and graduation decision |
| Security domain SME | Exposure-management concepts, triage scenarios, and accuracy review |
| Engineering lead | Architecture, data flow, feasibility, limitations, and requirement quality |
| Design or customer-success lead | User workflows, usability, onboarding, and customer evidence |
| APM | Own learning plan, maintain glossary/question log, complete artifacts, seek feedback, and demonstrate applied understanding |

## 7. Assessment scorecard

Score each dimension from 1 (needs close guidance) to 4 (independent). Graduation requires no score below 3.

| Dimension | Evidence |
|---|---|
| Customer and market understanding | Product brief, interview notes, persona/job articulation |
| Security domain fluency | Glossary, prioritization scenarios, correct use of evidence and uncertainty |
| ScoutGrid product fluency | Product demos, workflow traces, capability matrix |
| Product judgment | Prioritization rationale, tradeoffs, non-goals, decision record |
| Requirements quality | PRD, acceptance criteria, edge cases, dependencies, rollout plan |
| Data and outcomes | Metric tree, instrumentation specification, success/guardrail metrics |
| Communication | Teach-backs, written artifacts, stakeholder alignment |
| Ownership | Capstone execution and Days 61–90 initiative |

## 8. Required learning resources

### Internal ScoutGrid sources

1. `prototype-app/docs/business-logic-guide.md` — end-to-end product and domain behavior.
2. `prototype-app/docs/architecture.md` — system shape, data flow, and security model.
3. `prototype-app/docs/frontend.md` — routes, pages, components, and user-facing structure.
4. `AI_GRID_IMPLEMENTED_CAPABILITIES.md` — implemented AI Grid scope, evidence boundaries, and remaining work.
5. `SCOUTGRID_GTM_30_60_90.md` — positioning, target customers, buyers, and go-to-market assumptions.
6. The running demo tenant and representative source-to-finding workflows.

### External concepts to study

- NIST Cybersecurity Framework and NIST guidance on vulnerability and risk management.
- FIRST CVSS and EPSS documentation.
- CISA Known Exploited Vulnerabilities catalog.
- CycloneDX, SPDX, CPE, and VEX specifications at a product-manager level.
- OWASP guidance for LLM and agentic AI security.
- Continuous threat exposure management as a market category; compare definitions critically rather than treating any one vendor's framing as a standard.

## 9. Manager setup checklist

Before the APM starts, the manager should provide:

- Demo-tenant access with representative inventory, vulnerabilities, findings, AI assets, and policies.
- A named mentor and scheduled weekly review.
- Access to approved call recordings, win/loss notes, roadmap, product metrics, and current backlog.
- A list of current product claims, non-claims, previews, and known limitations.
- A capstone shortlist containing real but bounded product problems.
- Introductions to engineering, security, sales/customer success, and design stakeholders.

The manager should review the plan at the end of Weeks 2, 4, 6, and 8, adjusting depth based on demonstrated proficiency rather than merely recording course completion.
