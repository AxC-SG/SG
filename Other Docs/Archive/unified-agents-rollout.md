# Unified Agents rollout

The current roster uses provider identity and successful identity enumeration. Deployment status is computed from immutable routing observations at request time. It does not enter policy evaluation, finding gates, or system grouping.

## Review boundaries

1. Roster foundation: `AiAgentInventoryClassification`, API roster/count predicates, paginated roster queries, and `/inventory/ai/agents`.
2. Evidence collection: independent Bedrock routing enumeration, AgentCore endpoint evidence, Foundry endpoint selectors and legacy application/deployment reads, permission matrices, platform V8 and tenant V14 migrations.
3. Deployment metadata: `AiAgentDeploymentService`, nullable summary/detail fields, tenant freshness configuration, connector/family setup actions, and deployment presentation.
4. Version consolidation: paginated versions within agent details, independent definition/serving labels, shared version classification, and history-replacing legacy redirects.

These boundaries are file groups for review; the changes are in the working tree alongside existing connector work. No commits or deployments have been made.

## Compatibility and rollout

Apply the additive platform V8 and tenant V14 migrations before starting the updated backend. The existing summary endpoint remains available without `inventoryView`; deployment fields are nullable. The roster uses `inventoryView=AGENTS`, and the Other view uses `inventoryView=OTHERS`. Direct artifact/version details and security relationships remain available.

Freshness defaults to 24 hours. Tenant administrators and platform owners can update it through `PUT /api/ai-security/agent-deployment/settings` with `{"freshnessHours":24}`; values from 1 to 8760 are accepted. The corresponding GET returns current configuration. Discovery intervals longer than freshness generate a setup action rather than extending evidence lifetime.

The latest finalized routing attempt controls current metadata. Earlier complete observations remain available for last verified history even when newer evidence is ambiguous. Freshness uses the provider observation timestamp, and expires at the exact boundary. Complete empty routing enumeration supersedes older routes. Complete identity enumeration may deactivate missing roster members while retaining their stored records and history.

Rollback the application without removing the additive migrations. Rolling back collectors can leave deployment unverified; it does not remove logical agents or retained versions. Older version-category URLs redirect to the roster while retaining provider/subscription filters.

## Supported evidence and explicit gaps

Bedrock requires an accepting production alias with a resolved non-DRAFT version. AgentCore requires READY endpoints with resolved version lineage. Foundry supports explicit endpoint/version selectors and project-scoped legacy application/deployment relationships with complete traffic and readiness evidence.

Copilot publication currently lacks an enabled-channel evidence adapter, so it remains `UNSUPPORTED_CHANNEL_EVIDENCE`. Classic Foundry assistants and unsupported hosted configurations remain visible with unverified metadata. Azure ML resources without an explicit provider relationship cannot establish agent serving. No adapter invokes or publishes an agent.

## Verification

Frontend: 639 tests across 69 files pass, including status presentation, search/provider pagination, redirects, direct version links, and combined definition/served labels. Type checking and production bundle verification pass. Coverage thresholds are unchanged; final line coverage is 42.14%, compared with 42.08% at the preceding full run.

Backend tests cover closed status/reason contracts, freshness boundaries, historical proof, constant batched lookup counts, provider pagination, permission isolation, and deterministic call-budget exhaustion. All 14 PostgreSQL observation tests and eight R2 exposure tests pass. PostgreSQL observation tests cover identity deduplication, retained versions, complete-empty enumeration, count consistency, policy assessment, and system grouping. A 1,000-agent fixture runs EXPLAIN ANALYZE with buffers for the paged scope query; its initial measured execution time was 0.472 ms. This local measurement is not a production latency guarantee.
