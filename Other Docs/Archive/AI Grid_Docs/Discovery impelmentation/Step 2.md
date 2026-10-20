# Next Phase — Managed AI Inventory Expansion

## Summary

Deliver feature-gated, inventory-only discovery for AWS SageMaker and remaining deployable Amazon Bedrock resources; certify Azure AI Search definition-only reads and enable Azure Foundry-agent discovery. Pilot only in the current AWS `us-east-1` account and Azure `eastus2` subscription. Ship versioned least-privilege permission artifacts for an account owner to apply.

## Implementation changes

- Extend AWS discovery for SageMaker domains/spaces, registry groups/packages, endpoints/configurations, jobs/pipelines, compute, execution roles, and linked network/data references.
- Extend Bedrock discovery for deployable/custom/provisioned/imported models, inference profiles, customization jobs, prompts, flows/aliases, and runtime configuration.
- Add stable artifact identities, relationships, scope status, budget accounting, read-only permission matrices, and explicit incomplete-scope diagnostics for every new family.
- Repair AWS scope-detail/error reporting so failed scopes identify their exact API or permission cause and permit an idempotency validation scan.
- Add versioned least-privilege AWS IAM policy JSON and Azure custom-role definitions. These exclude invocation, execution, object-content reads, key retrieval, and secret access.
- Implement Azure AI Search index, skillset, indexer, and data-source definition discovery only. Never fetch documents, search results, keys, connection strings, or secret values.
- Implement Foundry-agent and tool discovery through a version-isolated preview adapter. Gate it with `APP_AI_SECURITY_AZURE_FOUNDRY_AGENTS_ENABLED`; gate Search definitions with `APP_AI_SECURITY_AZURE_SEARCH_DATA_PLANE_ENABLED`.
- Keep all new families disabled by default and enable them only for the current pilot after permission and evidence checks pass.
- Do not add new posture findings this phase; focus on reliable inventory and relationship evidence.

## Azure safety constraint

- Do not create, deploy, modify, start, or otherwise spin up any Azure resource without the user’s explicit approval.
- Azure work is restricted to read-only credential validation, discovery, permission assessment, and console/API reconciliation.
- If validation requires representative resources that are absent, stop and request approval rather than provisioning them.

## Validation

- Unit-test pagination, normalization, relationships, feature gates, access denied, unsupported APIs, throttling, and partial scope outcomes.
- Contract-test that Azure Search makes definition-only calls and never accesses documents, queries, keys, or secrets.
- Run two scans in the pilot account/subscription; require stable identities and no duplicate artifacts.
- Reconcile a representative sample in AWS/Azure consoles and produce an evidence pack with policy artifacts, scope status, artifact counts, API-budget totals, and idempotency results.

## Assumptions

- Pilot scope remains AWS account `919221584905` in `us-east-1` and Azure subscription `85de82e7-db21-4879-ace4-e5e4093ac0f0` in `eastus2`.
- An authorized cloud account owner applies generated IAM/RBAC artifacts; Scout does not mutate cloud permissions.
- Foundry preview discovery stays pilot-only until its evidence review passes.
