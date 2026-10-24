# ScoutGrid Integration & Connector Roadmap Analysis

## Executive Summary

ScoutGrid currently has **18 connectors** across 4 core grids (SBOM/BOM, CMDB, Cloud Discovery, AI Security). This document provides:
1. **AI BOM Coverage Analysis** against top vendors
2. **Prioritized list of 40+ integration opportunities** across all grids
3. **Strategic recommendations** for Q4 2026 and beyond

---

## Part 1: AI BOM Coverage Analysis

### Current State vs. Competitors

**From competitive image provided:**

| Capability | Wiz | Prisma AIRS | SentinelOne | ScoutGrid |
|------------|-----|------------|------------|-----------|
| **AI BOM** | ● (Full) | ● (Full) | ● (Full) | ◐ (Partial) |
| **Scope** | Generic AI components | Generic AI components | Generic AI components | **Vulnerabilities for AI components** |

### Key Finding: AI BOM is NOT Unique to ScoutGrid

✗ **Problem:** Wiz, Prisma AIRS, and SentinelOne all offer AI BOM capabilities (documented/full)  
✓ **Opportunity:** ScoutGrid's AI Grid goes *beyond* BOM — it provides:
- Evidence-backed AI posture findings
- Cross-system AI exposure correlation (R2)
- Knowledge base and tool dependency mapping
- Read-only discovery model (no sensitive data required)
- Owner resolution for AI systems

### Recommendation

**Position AI BOM as a *component* of ScoutGrid's broader AI Grid**, not the differentiator:
- Competitors have AI BOM inventory; ScoutGrid has AI inventory + governance + risk correlation
- Emphasize: "We find AI systems AND the risks they pose — across AWS, Azure, and their tool dependencies"

---

## Part 2: Current ScoutGrid Connectors (18 Total)

### By Grid

**BOM Grid (4 connectors):**
1. SBOM Endpoint
2. GitHub SBOM / GHCR
3. BOM Management (SBOM/AI-BOM/CBOM)
4. ServiceNow CMDB

**Inventory Grid (2 connectors):**
5. SCCM/MECM CMDB
6. AWS Cloud Discovery
7. Azure Cloud Discovery

**AI Grid (2 connectors):**
8. AI Security — AWS Bedrock
9. AI Security — Azure

**Vulnerability Intelligence (8 connectors):**
10. NVD API
11. CISA KEV
12. GHSA Feed
13. Microsoft CSAF + VEX
14. Red Hat CSAF + VEX
15. Advisory Imports
16. endoflife.date EOL
17. ENISA EUVD
18. Japan VulnDB (JVN)

---

## Part 3: Priority Integration Roadmap

### Phase 1: Quick Wins (Months 1-2) — 8 Integrations

**Inventory Grid Expansion:**
1. **Google Cloud Discovery** — GCP Compute Engine, App Engine, ML resources
   - Priority: HIGH — GCP is #3 cloud, enterprise demand
   - Effort: MEDIUM (mirrors AWS/Azure)
   - ROI: High-value logos with multi-cloud strategy

2. **Kubernetes / Container Registries** — K8s cluster discovery, image scanning
   - Priority: HIGH — DevSecOps wedge, rapid adoption
   - Effort: HIGH (new paradigm)
   - ROI: Container-native companies, compliance (CIS)

3. **Jira / Linear** — Work item context enrichment
   - Priority: MEDIUM — Engineering workflow integration
   - Effort: LOW
   - ROI: Reduces context-switching in remediation

4. **OpsGenie / PagerDuty** — Incident creation + status sync
   - Priority: MEDIUM — On-call alerting
   - Effort: LOW
   - Rationale: Alert → Finding workflow

**Vulnerability Intelligence:**
5. **Apache NVD / NVD+ Commercial Feed** — Higher fidelity NVD data
   - Priority: MEDIUM
   - Effort: LOW
   - ROI: Enterprise compliance + SLA guarantees

6. **OSV (Open Source Vulnerability) Database** — Package-specific advisories
   - Priority: HIGH — JavaScript, Rust, Go ecosystems
   - Effort: LOW
   - ROI: Modern language support

7. **Dependabot Security Advisories** — GitHub-native dependency intelligence
   - Priority: MEDIUM
   - Effort: LOW
   - ROI: GitHub-native shops

**AI Grid:**
8. **Google Vertex AI** — Gemini models, AutoML workloads
   - Priority: HIGH — Google's AI platform
   - Effort: HIGH (new cloud provider)
   - ROI: GCP customers with AI workloads

---

### Phase 2: Core Platform (Months 2-3) — 12 Integrations

**Ticketing & Case Management:**
9. **Jira Service Management** — Incident/change ticket creation & sync
   - Priority: VERY HIGH
   - Effort: MEDIUM
   - ROI: CRITICAL — enterprise SecOps standard

10. **ServiceNow Incident Management** — Service-Now incident create/update
    - Priority: VERY HIGH (already have CMDB)
    - Effort: MEDIUM
    - Rationale: COMPLETE the ITSM integration

11. **Azure DevOps / Boards** — Work tracking for Microsoft-first shops
    - Priority: MEDIUM
    - Effort: MEDIUM

12. **GitHub Issues** — Built-in issue tracking for GitHub-native teams
    - Priority: MEDIUM
    - Effort: LOW

**Compliance & Governance:**
13. **Okta Directories** — User/group context for ownership assignments
    - Priority: HIGH
    - Effort: MEDIUM
    - ROI: Automatic entitlement + owner resolution

14. **Azure AD / Entra ID** — Azure identity + group membership
    - Priority: HIGH
    - Effort: MEDIUM
    - Rationale: Same as Okta for Azure shops

15. **Splunk Integration** — SIEM event forwarding
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Compliance + threat correlation

16. **Datadog Integration** — Metrics/logs forwarding
    - Priority: MEDIUM
    - Effort: LOW
    - ROI: Observability + security correlation

**Supply Chain & License:**
17. **SBOM.sh / CycloneDX Registry** — Public SBOM repository fetching
    - Priority: LOW
    - Effort: LOW
    - ROI: Niche but useful

18. **License Data Feeds** — FOSSA, Black Duck, WhiteSource integrations
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Compliance + risk scoring

19. **Software Heritage** — Dependency lineage, archival
    - Priority: LOW
    - Effort: HIGH
    - ROI: Research + forensics

20. **Artifactory / Nexus** — Private artifact repository scanning
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Internal supply chain visibility

---

### Phase 3: Advanced Capabilities (Months 3-4) — 12 Integrations

**AI & ML Monitoring:**
21. **Hugging Face Hub** — Model registry discovery & scanning
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: ML ops + supply chain (model vulnerabilities)

22. **MLflow Integration** — Model versioning/lineage
    - Priority: LOW
    - Effort: MEDIUM
    - ROI: ML experiment tracking

23. **LangChain / LlamaIndex Tools** — LLM app dependency scanning
    - Priority: HIGH
    - Effort: MEDIUM
    - ROI: LLM application risk (increasingly critical)

**Cloud Posture & Configuration:**
24. **CloudTrail / Activity Log** — Historical audit trail correlation
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Forensics + compliance

25. **AWS Config** — Configuration compliance snapshots
    - Priority: MEDIUM
    - Effort: LOW
    - ROI: Pre-existing compliance signals

26. **Azure Policy** — Policy compliance state
    - Priority: MEDIUM
    - Effort: LOW

27. **GCP Asset Inventory** — GCP resource history + policy state
    - Priority: MEDIUM
    - Effort: LOW

**Container & Runtime Security:**
28. **Falco Integration** — Runtime behavior monitoring
    - Priority: LOW
    - Effort: HIGH
    - ROI: Runtime AI/ML attack detection

29. **CrowdStrike / Falcon** — EDR telemetry correlation
    - Priority: HIGH (premium market)
    - Effort: HIGH
    - ROI: Breach risk correlation

30. **Wiz / Orca Integration** — Competitor APIs for data bridging
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Customer migration + evaluation

---

### Phase 4: Long-term Strategic (Q1+ 2027) — 8 Integrations

**Emerging Threat Intel:**
31. **MITRE ATT&CK** — Adversary tactics/techniques correlation
    - Priority: MEDIUM
    - Effort: LOW
    - ROI: Security research + maturity positioning

32. **Recorded Future / Censys** — Threat intelligence feeds
    - Priority: MEDIUM
    - Effort: MEDIUM
    - ROI: Proactive threat correlation

**Advanced Governance:**
33. **HashiCorp Vault** — Secret/credential drift detection
    - Priority: HIGH
    - Effort: HIGH
    - ROI: Credential security (AI Grid + Infra Grid)

34. **Snyk Integration** — Developer-native vulnerability source
    - Priority: HIGH
    - Effort: MEDIUM
    - ROI: SAST/DAST correlation

35. **Debricked / Whitesource SCA** — Advanced SCA feeds
    - Priority: MEDIUM
    - Effort: MEDIUM

**ML/AI Security:**
36. **Caldera / MITRE ATT&CK Simulator** — AI attack simulation
    - Priority: LOW
    - Effort: HIGH
    - ROI: Research + thought leadership

37. **Anthropic / OpenAI API** — LLM-powered investigation summaries (already exists, expand)
    - Priority: HIGH
    - Effort: MEDIUM
    - ROI: Differentiated workflow (AI grid investigation)

38. **SageMaker Pipelines** — ML pipeline lineage tracking
    - Priority: MEDIUM
    - Effort: HIGH
    - ROI: ML ops + supply chain

39. **Prompt Injection Detection Service** — LLM app security
    - Priority: HIGH
    - Effort: MEDIUM
    - ROI: AI Grid differentiation (LLM risk)

40. **ISO/IEC 42001 Compliance Framework** — AI governance mapping
    - Priority: MEDIUM
    - Effort: LOW (mapping only)
    - ROI: Compliance positioning

---

## Part 4: Priority Order by Strategic Value

### Tier 1: Must-Build (Next 8 Weeks)

1. **Jira Service Management** — #1 ITSM standard, non-negotiable
2. **ServiceNow Complete Integration** — Extend existing CMDB connector
3. **Google Cloud Discovery** — Multi-cloud requirement
4. **Okta / Entra ID** — Ownership resolution is core scoutgrid value
5. **Snyk API** — Largest developer SCA platform
6. **OSV Database** — Modern language vulnerability coverage
7. **Kubernetes Discovery** — Container-native enterprises demand this
8. **Jira / Linear** — Engineering workflow integration

### Tier 2: High-Value (Months 2-3)

9. **Vertex AI / Google ML** — GCP parity with AWS/Azure
10. **GitHub Issues** — GitHub-native workflow
11. **Datadog** — Observability platform standard
12. **AWS Config** — AWS config compliance signals
13. **Dependabot Advisories** — GitHub intelligence feed
14. **PagerDuty / OpsGenie** — On-call alerting integration
15. **Artifactory / Nexus** — Private artifact scanning
16. **LangChain / LlamaIndex** — LLM app security (AI Grid strategic)

### Tier 3: Differentiation (Months 3-4)

17. **HashiCorp Vault Integration** — Secret drift detection
18. **CrowdStrike / Falcon** — EDR telemetry (advanced)
19. **Anthropic / OpenAI Expansion** — AI-assisted investigation
20. **MITRE ATT&CK Correlation** — Threat actor tactics

### Tier 4: Long-term / Lower Priority

21-40: See Phase 4 above + others

---

## Part 5: Recommended 90-Day Build Plan

### Weeks 1-3: Foundation (Jira + Google Cloud)
- **Jira Service Management API** — ticket creation, status sync, custom fields
- **Google Cloud Discovery** — VM, App Engine, AI services
- **Okta / Entra ID** — User/group SCIM endpoints

### Weeks 4-6: Coverage (Snyk + OSV + Kubernetes)
- **Snyk API** — Vulnerable dependency intelligence
- **OSV Database** — Package vulnerability feed
- **Kubernetes / Helm** — K8s discovery connector

### Weeks 7-9: Polish (Workflows + LLM Security)
- **ServiceNow Complete** — wrap up CMDB gaps
- **LangChain / LlamaIndex** — LLM app inventory
- **GitHub Issues** — issue workflow

---

## Part 6: Estimated Impact by Grid

### BOM Grid
- **Current:** 4 connectors (SBOM, GitHub, BOM Mgmt, ServiceNow)
- **Recommended adds:** Snyk (SCA), OSV (OSS), Artifactory (private), License feeds
- **Impact:** 3-5 new integrations, +50% coverage

### Infra Grid
- **Current:** 3 connectors (AWS, Azure discovery, SCCM)
- **Recommended adds:** Google Cloud, Kubernetes, CrowdStrike EDR
- **Impact:** 3 new integrations, +60% coverage

### Cloud Grid
- **Current:** 2 connectors (AWS, Azure discovery)
- **Recommended adds:** AWS Config, Azure Policy, GCP Asset, Vault
- **Impact:** 4 new integrations, +100% coverage enhancement

### AI Grid
- **Current:** 2 connectors (AWS Bedrock, Azure AI)
- **Recommended adds:** Google Vertex AI, LangChain/LlamaIndex, Hugging Face, Prompt injection scanning
- **Impact:** 4 new integrations, complete AI platform coverage

### Ticketing / Governance
- **Current:** 0 connectors (ServiceNow CMDB only, no incident management)
- **Recommended adds:** Jira Service Mgmt, GitHub Issues, PagerDuty, Datadog, Splunk
- **Impact:** 5 new integrations, complete SecOps workflow

---

## Part 7: Success Metrics

**For each connector, measure:**
- **Adoption rate:** % of customers using within 60 days
- **Workflow savings:** Time from finding to ticket creation
- **Retention impact:** NRR lift for customers using 2+ connectors
- **Competitive win rate:** Percentage of deal evaluations where this connector was a deciding factor

**Target metrics by end of Phase 1:**
- 8 Tier-1 connectors launched
- 40%+ of new customer pilots using ≥2 connectors
- 3-5 case studies showing workflow time savings
- Competitive differentiation established vs. Wiz/Orca in "ITSM + Ticketing" positioning

---

## Appendix: Vendor-Specific Recommendations

### For AWS-First Customers
1. AWS Config + EventBridge
2. CloudTrail correlation
3. GuardDuty findings
4. Service Catalog tracking

### For Azure-First Customers
1. Entra ID / Azure AD
2. Azure Policy / Blueprints
3. Azure Defender findings
4. DevOps Boards integration

### For GCP Customers
1. Google Cloud Discovery
2. Vertex AI
3. GCP Config
4. Cloud Logging

### For Multi-Cloud (AWS + Azure + GCP)
1. All discovery connectors
2. Kubernetes (unified across clouds)
3. Vault (unified secret management)
4. LLM app scanning (Vertex + Bedrock + Azure OpenAI)

---

## Appendix: Technical Implementation Notes

### Quick-Win Implementations (Low Effort)
- **Jira Issues**: REST API, ~200 lines backend
- **GitHub Issues**: GraphQL API, ~200 lines backend
- **OSV DB**: Query-only, ~150 lines
- **AWS Config**: Already have SDK, ~100 lines
- **Datadog**: HTTP forwarder, ~80 lines

### Medium-Effort Implementations (MEDIUM)
- **Jira Service Mgmt**: Custom field mapping, ~400 lines
- **Snyk**: API + parsing, ~350 lines
- **Google Cloud Discovery**: Mirrors AWS, ~500 lines
- **Okta SCIM**: User provisioning, ~400 lines
- **Kubernetes**: Helm chart + K8s API, ~600 lines

### High-Effort Implementations (HIGH)
- **CrowdStrike EDR**: Real-time telemetry streaming, ~1500 lines
- **LangChain/LlamaIndex**: Custom dependency parsing, ~1200 lines
- **HashiCorp Vault**: Secret drift detection, ~1000 lines
- **Vertex AI**: New cloud provider + ML models, ~800 lines

