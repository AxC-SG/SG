# Step 3 — Metadata-Only AI Relationship Graph

## Summary

Over 3–4 weeks, deepen Scout’s existing artifact graph so it shows evidence-backed paths across model → deployment → agent → tool → identity → data source, without collecting raw prompts, documents, model weights, API keys, connection strings, or Azure Search documents.

AWS is the enabled pilot in `us-east-1`. Azure adapters ship feature-gated and remain disabled until its existing-resource, read-only validation passes in `eastus2`.

## Key changes

- Extend the existing relationship contract and storage with:
  - direct versus inferred confidence;
  - source API and field-path evidence;
  - scope/run timestamps and safe relationship attributes only.
  - Keep the current idempotent edge identity: tenant + source + target + relationship type.

- Add an allowlist-based metadata extraction layer. Collect only relationship-bearing identifiers and configuration references; strip or reject prohibited fields before persistence, logs, API responses, and UI rendering.

- Expand AWS direct relationships:
  - Bedrock model ↔ provisioned model/inference profile/customization job;
  - Bedrock prompt/flow/alias ↔ referenced model, agent, tool, knowledge base, or Lambda reference where the API exposes metadata;
  - SageMaker endpoint ↔ endpoint configuration ↔ model package/model;
  - SageMaker domain/space/job/pipeline/endpoint ↔ execution role, VPC, subnet, and security group;
  - Bedrock/SageMaker identity and data-reference edges without reading IAM policies, S3 objects, or model content.

- Add inferred-reference handling:
  - If a resource contains an approved reference that cannot be resolved to a discovered artifact, persist it as an explicitly `INFERRED` edge to a synthetic reference node or show it as an unresolved reference diagnostic.
  - Never present inferred links as direct evidence.

- Expand Azure adapters behind existing flags:
  - Foundry agent/tool ↔ project, deployment/model, managed identity, and declared tool/data references behind `APP_AI_SECURITY_AZURE_FOUNDRY_AGENTS_ENABLED`.
  - AI Search indexer ↔ data source, skillset, and index; Foundry tool/agent ↔ Search target where metadata references permit it, behind `APP_AI_SECURITY_AZURE_SEARCH_DATA_PLANE_ENABLED`.
  - Permit only definition endpoints; forbid Search queries, documents, keys, connection strings, and secrets.
  - Keep Azure flags off until credential, permission, and evidence review succeeds using existing resources only.

- Enhance the existing graph and relationship APIs/UI:
  - Return confidence and evidence metadata with graph edges.
  - Add filters for relationship type, provider, direct/inferred confidence, and active scope status.
  - Show an artifact’s observed relationship path and evidence source while redacting raw configuration.

- Extend run evidence with relationship counts by family, direct/inferred totals, API-budget totals, and exact partial/denied/unsupported diagnostics. Do not add posture findings in this phase.

## Delivery sequence

1. **Week 1:** relationship contract/evidence model, extraction allowlist, storage migration if required, AWS Bedrock/SageMaker direct edge collection.
2. **Week 2:** AWS identity/network/data-reference resolution; Azure Foundry and AI Search feature-gated adapters with contract fixtures.
3. **Week 3:** graph API/UI evidence enhancements, scope/budget reporting, two-scan AWS pilot validation, and console reconciliation.
4. **Week 4 buffer:** Azure preview compatibility fixes, unresolved-reference improvements, and performance/API-budget tuning only if pilot evidence requires it.

## Test and validation

- Unit tests for stable edge keys, idempotent upserts, pagination, inactive-edge reconciliation, tenant isolation, and direct/inferred labeling.
- Negative contract tests prove collectors never call model invocation, job execution, prompt-content, document, Search-query, key, secret, or connection-string APIs.
- Tests for access denied, throttling, unsupported API versions, absent resource families, partial scopes, and unresolved references.
- Two AWS scans against existing `us-east-1` resources must produce stable artifact and edge identities with no duplicates.
- Reconcile representative AWS console resources to Scout paths: model/deployment, agent/tool, role, and data/network reference.
- Validate Azure only after read-only credentials and permissions pass; absent Azure resources remain `COMPLETE` with zero artifacts—no test resources may be created without explicit approval.

## Assumptions

- Relationship confidence uses the selected **Direct + inferred** model: source-field-backed links are shown but clearly distinguished from directly observed API relationships.
- Existing graph storage and UI are extended rather than replaced.
- Cloud permissions remain least-privilege and read-only; account owners apply any generated IAM/RBAC policy updates.
- Azure is implemented this phase but enabled only after its real-account read-only validation; Scout will not create, deploy, start, invoke, or modify Azure resources.
