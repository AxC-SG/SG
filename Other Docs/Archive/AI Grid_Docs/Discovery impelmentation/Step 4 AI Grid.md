# Step 4: Code, Workload, and Identity AI Inventory

## Summary

Extend AI Inventory Preview with three metadata-only discovery planes: GitHub source analysis, EKS/AKS/ECS workload inventory, and a separate Entra ID/AWS IAM identity connector. Reuse the existing AI artifact, relationship, scope-receipt, tenant-isolation, job, and coverage infrastructure; do not collect source content, notebook cells, prompts, secrets, or workload environment values.

## Key Changes

- Add a `GITHUB_CODE` AI discovery connector, separate from GitHub SBOM sources but reusing the existing GitHub token, allowlist, repository enumeration, tree traversal, file retrieval, retry, and queued-run infrastructure.
  - Scan only a versioned, allowlisted catalog of repository paths and dependency manifests. Detect AI SDK declarations/import references; MCP configurations; `.ipynb` notebook metadata and dependency references; Terraform, CloudFormation, Bicep/ARM, CDK, Helm, and Kubernetes IaC declarations; and GitHub Actions AI-related CI declarations.
  - Persist a synthetic repository artifact plus metadata-only artifacts for detected declarations, with repository URL, default branch, file path, blob SHA, classifier/rule version, and matched package/resource identifiers. Store no file body, notebook cell output, token, secret, prompt, or environment value.
  - Emit relationships from repository/declaration artifacts to referenced cloud resource IDs where resolvable, and otherwise retain the normalized reference as evidence for later correlation.
  - Add resource families `GITHUB_AI_SDKS`, `GITHUB_MCP_MANIFESTS`, `GITHUB_NOTEBOOKS`, `GITHUB_IAC`, and `GITHUB_CI_DECLARATIONS`, each with COMPLETE/PARTIAL/FAILED/UNSUPPORTED scope receipts.

- Add AWS and Azure workload families: `AWS_ECS_WORKLOADS`, `AWS_EKS_CLUSTERS`, `KUBERNETES_WORKLOADS`, and `AZURE_AKS_CLUSTERS`.
  - AWS discovery inventories ECS clusters, services, task definitions, task roles/execution roles, container image references, launch types, and network configuration; it inventories EKS cluster metadata and identity-provider configuration.
  - Azure discovery inventories AKS cluster metadata, node resource group, network profile, Microsoft Entra integration, and workload-identity configuration.
  - Deliver a minimal, read-only in-cluster agent for EKS and AKS. It authenticates with a dedicated service account and reports namespace, Deployment/StatefulSet/DaemonSet/Job/CronJob, Pod template, ServiceAccount, image digest/tag, declared service/ingress references, and workload-identity annotations. It redacts all Secret data and environment-variable values.
  - Correlate workloads to AI code declarations, images, cloud AI resources, Kubernetes service accounts, ECS task roles, and managed identities through stable resource IDs and explicit relationship types. Private or unreachable clusters report an explicit incomplete scope rather than an empty inventory.

- Add a separate `IDENTITY` connector with Entra ID and AWS IAM providers, its own configuration, permissions validation, schedule, sync-run type, coverage families, and connector UI.
  - Entra discovery uses Microsoft Graph plus Azure Resource Manager to inventory applications/OAuth clients, service principals, managed identities, federated identity credentials, direct app-role assignments, OAuth2 permission grants, and Azure role assignments. Compute effective grants for each non-human principal from direct assignments and transitive group membership.
  - AWS IAM discovery inventories roles, trust policies, attached and inline policies, permission boundaries, instance profiles, and role links from ECS/EKS/Bedrock/SageMaker. Compute an explainable effective-permission summary from allow/deny statements and boundaries; retain policy metadata and normalized actions/resources, never credentials or policy secrets.
  - Define declared-effective-grant limits clearly: no PIM activation, Conditional Access evaluation, resource-policy simulation, dynamic-group expansion, or runtime credential use. Mark these as unsupported evidence in family receipts.
  - Add relationships from identities to workload bindings, OAuth clients, federated credentials, cloud AI artifacts, and direct/effective grants.

- Extend the AI resource-family catalogue, connector admission checks, permission matrices, job registry/history, and coverage API to recognize all new families and providers. Add a tenant feature flag for each plane: GitHub code, workloads, Kubernetes agent ingestion, Entra identity, and AWS IAM identity.
- Expose connector setup/run status and family-level coverage in the existing Connect and AI Inventory experiences. Add provider/source filters and relationship details for repositories, workloads, and identities. This milestone is inventory-only; it adds no new posture findings or runtime telemetry policies.

## Public Interfaces and Data

- Add connector CRUD/test/run APIs for GitHub code, workload targets/agent registration, and identity providers; each returns configuration state, configured families, permission readiness, and safe diagnostics.
- Add a metadata-only Kubernetes agent ingestion endpoint authenticated by a tenant-scoped registration credential and cluster identity; require idempotency keys, payload limits, schema versioning, and scope receipts.
- Add a tenant migration for connector configuration extensions and workload/identity provenance needed by the existing `ai_security_artifacts`, `ai_security_relationships`, and `ai_security_snapshot_scopes` model. Use new native kinds rather than a parallel graph schema.

## Test Plan

- Unit-test the GitHub classifier catalog with representative manifests/configurations, false-positive cases, SHA-based idempotency, rule-version evidence, and redaction guarantees.
- Contract-test GitHub, AWS, Azure, Microsoft Graph, and Kubernetes clients for pagination, rate limiting, revoked credentials, missing permissions, malformed metadata, and partial discovery.
- Test relationship correlation across repository → workload → identity → AI resource paths, including unresolved references without fabricated links.
- Test Kubernetes agent authentication, tenant/cluster isolation, replay protection, payload-size limits, private-cluster failure receipts, and zero secret/environment-value persistence.
- Add integration tests for tenant RLS, deactivation on authoritative COMPLETE scopes only, coverage counts, feature-flag gating, connector run history, and UI states for complete, permission-denied, unsupported, and partial families.

## Assumptions

- First release covers Microsoft Entra ID and AWS IAM; Okta, Auth0, browser/CASB discovery, prompt telemetry, and repository-content retention are out of scope.
- Kubernetes workload discovery uses the read-only in-cluster agent; ECS remains direct AWS API discovery.
- GitHub access requires metadata/content read access for allowlisted repositories; identity access is read-only Graph/ARM/IAM access with least-privilege permission manifests published alongside the connectors.
