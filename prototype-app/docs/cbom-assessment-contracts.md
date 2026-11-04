# ScoutGrid CBOM Assessment Contracts

Status: Accepted for the V12–V14 CBOM workflow  
Owner: CBOM Product and Canonical Findings

## Vocabulary

- **Evidence presence** states whether a CBOM currently supports a claim: `SUPPORTED`, `CONFLICTING`, `WITHDRAWN`, or `LEGACY_UNKNOWN`.
- **Assurance** states how strongly a claim is established: `UNKNOWN`, `DECLARED`, `CORROBORATED`, `VERIFIED`, or `CONFLICTING`.
- **Completeness** is the fraction of important claims present in the artifact. Missing optional evidence lowers completeness; it is not a failed security control.
- **Confidence** is the fraction of assessed important claims that are non-conflicting and supported at `DECLARED` or better.
- **Validation** decides whether an artifact can be assessed and records field-level diagnostics. Validation is not a risk decision.
- **Assessment** evaluates one immutable artifact checksum with one effective rule-package digest and evaluator version.
- **Withdrawal** means source evidence disappeared or was superseded. It never asserts remediation.
- **Remediation** is a canonical Findings workflow decision backed by accepted verification evidence when the applicable rule requires it.

## Lifecycle contracts

Validation outcomes are `VALID`, `VALID_WITH_WARNINGS`, and `INVALID`. Assessment lifecycle is independently `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, or `CANCELLED`. A successful assessment can contain warnings and unknown assurance.

`bom_ingestion_records.source_id` is the logical source identity. A source has one current version; `previous_bom_id` and `superseded_by` form its version chain. Components match across versions by `bom-ref` first and the normalized component fingerprint second. Collisions are surfaced as ambiguous rather than selected silently.

Canonical `findings` exclusively own workflow state, assignment, SLA, tickets, campaigns, suppression, verification, and resolution. CBOM observations own rule evidence, presence, and source history.

## Authorization

- `TENANT_ADMIN`: tenant rule configuration, suppression policy, direct noncritical suppression, request decisions, reassessment, and reports.
- `SECURITY_ANALYST`: assessment, suppression requests, remediation workflow, tickets, and reports.
- `INVENTORY_ADMIN`, `CREATOR`, `OPERATOR`: CBOM inventory and assessment visibility.
- `READ_ONLY_AUDITOR`: immutable assessment reports and audit visibility.
- Support-session actors cannot suppress or decide suppression requests. Slice 1 has no evidence-unredaction endpoint.

## Retention and purge/export inventory

| Object | Retention | Tenant purge | Tenant export |
|---|---:|---|---|
| `cbom_assessment_runs` | 400 days after artifact supersession | Cascade with tenant schema/artifact | JSON report and assessment API |
| `cbom_validation_issues` | Parent assessment lifetime | Cascade with assessment | Included in assessment report |
| `cbom_claim_assurances` | Parent assessment lifetime | Cascade with assessment | Included in assessment report |
| `cbom_rule_configurations` | Tenant lifetime plus audit history | Tenant schema drop | Configuration API and audit export |
| `finding_suppression_requests` | 400 days after terminal decision | Cascade with finding/tenant | Audit export |
| Generic finding verification fields | Canonical finding lifetime | Cascade with finding/tenant | Finding and audit export |
| `cbom_relationships` | 400 days after evidence expiry | Tenant schema drop | Bounded graph API |

The external full-tenant export program remains a platform dependency. These objects are registered here so its inventory is explicit.

## Performance and safety budgets

- Accept and queue ingestion within p95 2 seconds, excluding transfer time.
- Assess 10,000 cryptographic assets within p95 120 seconds on `cbomAssessmentExecutor`.
- Limit assessment claims to one running job per tenant and two worker threads per node.
- Paginated inventory and finding queries target p95 750 ms at one million components.
- Semantic diff targets p95 30 seconds for 10,000 assets.
- Assessment reports target p95 60 seconds and never fetch external resources.
- Relationship traversal is capped at depth 3 and 500 nodes and targets p95 2 seconds.
- JSON/HTML reports are `UNSIGNED`; their SHA-256 checksum detects content changes but does not authenticate the publisher.

## Navigation decision

The first release remains in BOM Inventory and canonical Findings. A top-level `/crypto/*` workspace is deferred until the navigation review in Milestone 2; this does not block assessment functionality.
