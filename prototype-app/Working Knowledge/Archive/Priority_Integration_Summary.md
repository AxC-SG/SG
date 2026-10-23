# ScoutGrid Integration Priority Matrix

## Quick Summary: 40 Recommended Integrations (Priority Order)

### 🔴 TIER 1: MUST-BUILD (Next 8 Weeks) - 8 Integrations

| Priority | Vendor/System | Category | Effort | ROI | Target Customers | Strategic Fit |
|----------|--------------|----------|--------|-----|-----------------|---------------|
| 1 | **Jira Service Management** | Ticketing | MEDIUM | VERY HIGH | Enterprise IT/Ops | Core ITSM workflow - non-negotiable |
| 2 | **ServiceNow Incident Mgmt** | Ticketing | MEDIUM | VERY HIGH | Enterprise (complete ITSM) | Extend existing CMDB connector |
| 3 | **Google Cloud Discovery** | Cloud Inventory | MEDIUM | VERY HIGH | Multi-cloud enterprises | #3 cloud platform, parity with AWS/Azure |
| 4 | **Okta Directory** | Identity/Ownership | MEDIUM | VERY HIGH | Enterprise SSO users | Enable automatic owner resolution |
| 5 | **Snyk API** | Vulnerability Intel | MEDIUM | HIGH | Modern dev orgs | #1 developer SCA platform |
| 6 | **OSV Database** | Vulnerability Intel | LOW | HIGH | JavaScript/Rust/Go shops | Modern language vulnerability coverage |
| 7 | **Kubernetes Discovery** | Container Inventory | HIGH | VERY HIGH | DevOps/Cloud-native | Container security trend, high demand |
| 8 | **GitHub Issues** | Ticketing | LOW | MEDIUM | GitHub-native teams | Engineering workflow integration |

---

### 🟠 TIER 2: HIGH-VALUE (Months 2-3) - 12 Integrations

| Priority | Vendor/System | Category | Effort | ROI | Target Customers | Strategic Fit |
|----------|--------------|----------|--------|-----|-----------------|---------------|
| 9 | **Google Vertex AI** | AI Inventory | HIGH | HIGH | Google AI customers | Complete AI platform parity |
| 10 | **Azure Entra ID** | Identity | MEDIUM | VERY HIGH | Azure-first enterprises | Azure identity + owner resolution |
| 11 | **AWS Config** | Cloud Config | LOW | MEDIUM | AWS customers | Config compliance signals |
| 12 | **PagerDuty / OpsGenie** | Incident Mgmt | LOW | MEDIUM | On-call teams | Alert → Ticket workflow |
| 13 | **Datadog** | Observability | LOW | MEDIUM | Datadog users | Metrics/logs correlation |
| 14 | **GitHub Dependabot Advisories** | Vulnerability Intel | LOW | MEDIUM | GitHub-native orgs | GitHub intelligence feed |
| 15 | **Artifactory / Nexus** | Artifact Registry | MEDIUM | MEDIUM | Enterprise DevOps | Private supply chain visibility |
| 16 | **LangChain / LlamaIndex** | LLM App Inventory | MEDIUM | HIGH | LLM app builders | AI Grid differentiator (LLM security) |
| 17 | **Azure Policy** | Cloud Config | LOW | MEDIUM | Azure customers | Policy compliance state |
| 18 | **Jira / Linear** | Work Tracking | LOW | MEDIUM | Engineering teams | Reduce context-switching |
| 19 | **GCP Asset Inventory** | Cloud Config | LOW | MEDIUM | GCP customers | Historical resource tracking |
| 20 | **Splunk** | SIEM | MEDIUM | MEDIUM | Enterprise security | Compliance + threat correlation |

---

### 🟡 TIER 3: DIFFERENTIATORS (Months 3-4) - 10 Integrations

| Priority | Vendor/System | Category | Effort | ROI | Target Customers | Strategic Fit |
|----------|--------------|----------|--------|-----|-----------------|---------------|
| 21 | **HashiCorp Vault** | Secret Management | HIGH | HIGH | Enterprise Infrastructure | Secret drift detection (Infra + AI Grid) |
| 22 | **CrowdStrike Falcon** | EDR | HIGH | VERY HIGH | Security-first enterprises | Breach risk correlation |
| 23 | **Prompt Injection Detection** | LLM Security | MEDIUM | HIGH | LLM-first companies | AI Grid differentiator |
| 24 | **Anthropic / OpenAI Expansion** | AI-Assisted Analysis | MEDIUM | HIGH | All segments | Investigation summaries, compliance analysis |
| 25 | **MITRE ATT&CK Mapping** | Threat Intelligence | LOW | MEDIUM | Security teams | Threat actor tactics correlation |
| 26 | **Hugging Face Hub** | Model Registry | MEDIUM | MEDIUM | ML Ops teams | ML model vulnerability scanning |
| 27 | **Software Heritage** | Dependency Lineage | HIGH | LOW | Research/Forensics | Archival + lineage tracking |
| 28 | **Recorded Future** | Threat Intel Feed | MEDIUM | MEDIUM | Threat-focused orgs | Proactive threat correlation |
| 29 | **Falco Integration** | Runtime Security | HIGH | MEDIUM | K8s environments | Container runtime monitoring |
| 30 | **Wiz / Orca / Lacework API** | Competitor Bridge | MEDIUM | MEDIUM | Migration scenarios | Evaluation/migration data |

---

### 🟢 TIER 4: EMERGING / STRATEGIC (Q1 2027+) - 10 Integrations

| Priority | Vendor/System | Category | Effort | ROI | Target Customers | Strategic Fit |
|----------|--------------|----------|--------|-----|-----------------|---------------|
| 31 | **ISO/IEC 42001 Framework** | AI Governance | LOW | MEDIUM | Regulated enterprises | AI compliance positioning |
| 32 | **SageMaker Pipelines** | ML Ops | HIGH | MEDIUM | AWS ML teams | ML pipeline lineage |
| 33 | **MLflow Integration** | ML Versioning | MEDIUM | LOW | ML Ops / Data teams | Model experiment tracking |
| 34 | **Debricked SCA** | Vulnerability Intel | MEDIUM | MEDIUM | Enterprise Dev | Advanced SCA intelligence |
| 35 | **Apache NVD+ Feed** | Vulnerability Intel | LOW | MEDIUM | Enterprise | Higher-fidelity NVD data |
| 36 | **SBOM.sh Registry** | BOM Repository | LOW | LOW | Public SBOM ecosystem | Registry consumption |
| 37 | **License Scanning (FOSSA/WhiteSource)** | License Mgmt | MEDIUM | MEDIUM | Compliance-driven | License risk scoring |
| 38 | **Caldera / MITRE Simulator** | Attack Simulation | HIGH | LOW | Research/PoC | AI attack simulation |
| 39 | **CloudTrail / Activity Logs** | Audit Trail | MEDIUM | MEDIUM | Compliance/Forensics | Historical correlation |
| 40 | **Censys / Shodan** | External Asset Mgmt | MEDIUM | LOW | Threat/Brand teams | External exposure visibility |

---

## Key Findings: AI BOM Analysis

### Current Competitive Position

**From the image provided:**

| Capability | Wiz | Prisma AIRS | SentinelOne | **ScoutGrid** |
|------------|-----|-----------|-----------|------------|
| Policy governance | ● | ● | ● | ◐ |
| AI-powered assessment | ● | ◐ | ● | ◐ |
| **AI BOM** | **●** | **●** | **●** | **◐** |

### Critical Insight: AI BOM is NOT a Differentiator
- **❌ Problem:** Wiz, Prisma, and SentinelOne all have documented/full AI BOM coverage
- **✓ Solution:** ScoutGrid's AI Grid differentiator is:
  - ✓ Cross-system AI exposure correlation (R2 with evidence trails)
  - ✓ Evidence-backed risk scoring (not just inventory)
  - ✓ Read-only discovery (no prompt/data ingestion)
  - ✓ Owner resolution + accountability
  - ✓ Policy-based governance + platform control

### Recommendation
**Position AI BOM as "inventory component" of broader AI Grid, not primary messaging:**
- Competitors find AI systems; ScoutGrid finds AI systems AND the risks they pose
- Emphasize: "End-to-end AI posture + exposure governance across AWS, Azure, and LLM app dependencies"
- Add LangChain/LlamaIndex support to differentiate on LLM app risk (emerging, under-served market)

---

## By-Grid Coverage Analysis

### BOM Grid (Software Bill of Materials)
**Current:** 4 connectors  
**Gaps:** SCA platforms, OSS databases, artifact registries  
**Recommendation:** Add Snyk, OSV, Artifactory (↑3-4 connectors, +75% coverage)

### Infra Grid (Infrastructure Discovery)  
**Current:** 3 connectors  
**Gaps:** GCP, Kubernetes, runtime monitoring  
**Recommendation:** Add Google Cloud, K8s, CrowdStrike, Falco (↑4 connectors, +80% coverage)

### Cloud Grid (Cloud Bill of Materials + Posture)  
**Current:** 2 connectors  
**Gaps:** Config states, secrets management, asset history  
**Recommendation:** Add AWS Config, Azure Policy, GCP Asset, Vault (↑4 connectors, +100% enhancement)

### AI Grid (AI/ML Resource Governance)  
**Current:** 2 connectors  
**Gaps:** Google Vertex, LLM app scanning, Hugging Face, model registries  
**Recommendation:** Add Vertex AI, LangChain/LlamaIndex, Hugging Face, Prompt scanning (↑4 connectors, complete platform parity)

### Ticketing & Governance (NEW)  
**Current:** 0 connectors (ServiceNow CMDB only)  
**Gaps:** ITSM, issue tracking, identity, observability  
**Recommendation:** Add Jira, ServiceNow, GitHub Issues, Okta, Datadog, PagerDuty, Splunk (↑7 connectors, new grid)

---

## Recommended 90-Day Build Plan

### Weeks 1-3: Foundation Layer
```
Jira Service Management (350 lines) — CRITICAL
Google Cloud Discovery (500 lines)  — CRITICAL
Okta / Entra ID (400 lines)          — CRITICAL
```
**Expected outcome:** Multi-cloud + ITSM workflow foundation

### Weeks 4-6: Coverage Expansion
```
Snyk API (350 lines)                 — HIGH
OSV Database (150 lines)             — HIGH
Kubernetes Discovery (600 lines)     — HIGH
```
**Expected outcome:** Developer + container security coverage

### Weeks 7-9: Workflow Integration
```
GitHub Issues (200 lines)            — MEDIUM
ServiceNow Complete (300 lines)      — HIGH
LangChain/LlamaIndex (400 lines)     — HIGH
```
**Expected outcome:** Engineering + AI Grid workflow completion

---

## Success Metrics

**By end of 90 days, measure:**
- ✓ 8 new connectors launched + documented
- ✓ 40%+ of pilot customers using ≥2 new connectors
- ✓ 2-3 case studies showing time savings (finding → ticket → owner)
- ✓ NRR lift from customers using 2+ connectors
- ✓ Competitive win rate vs. Wiz/Orca (connector breadth as factor)
- ✓ Adoption rate: 60%+ of customers enabling Jira + Google Cloud within 60 days

---

## Implementation Effort Summary

### Quick Wins (≤5 hours each, ≤200 lines)
- OSV Database
- GitHub Issues
- AWS Config / Azure Policy
- PagerDuty / OpsGenie
- Datadog forwarder
- Apache NVD+ Feed

### Medium Complexity (5-15 hours each, 200-600 lines)
- Jira Service Management
- Google Cloud Discovery
- Snyk API
- Okta / Entra ID
- LangChain/LlamaIndex
- Artifactory / Nexus
- Datadog integration

### High Complexity (15-40 hours each, 600-1500 lines)
- Kubernetes Discovery
- Google Vertex AI
- HashiCorp Vault
- CrowdStrike Falcon EDR
- Falco Integration
- SageMaker Pipelines

