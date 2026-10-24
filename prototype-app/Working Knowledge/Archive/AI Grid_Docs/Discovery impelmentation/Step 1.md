# Week-one AI Inventory Pilot

## Summary

Run a read-only, stealth-mode validation of the existing AWS Bedrock and Azure AI connectors against one non-production AWS account and one non-production Azure subscription. The release goal is trustworthy coverage evidence—not new provider breadth.

## Implementation and pilot work

- Configure the existing connectors with workload identity only:
  - AWS cross-account read-only role, limited to approved Bedrock regions.
  - Azure managed identity or app registration, limited to the selected subscription and approved AI regions.
  - Keep all credentials outside source control and do not grant key-reading, document-reading, write, or execution permissions.

- Validate every currently supported connector family live and record, per provider/family/region:
  - artifact count, relationship count, last successful run, completion state, and missing permissions;
  - explicit `UNSUPPORTED` receipts for Azure AI Search data-plane families and Foundry-agent preview discovery;
  - no silent “zero assets means no AI” interpretation.

- Generalize the AI inventory overview from its current Bedrock-only wording to provider-neutral “AI inventory coverage,” using the existing AI coverage APIs and surfacing incomplete/unsupported scope states prominently.

- Fix only defects discovered during the live pilot: incorrect resource mapping, pagination/region handling, relationship resolution, permission diagnostics, or UI coverage presentation. Do not add SageMaker, MCP, SaaS/browser, or runtime telemetry this week.

- Produce a private pilot evidence pack: configured scope, least-privilege permissions used, discovered artifact/relationship totals, unsupported families, missing permissions, defects fixed, and the prioritized next connector slice. Keep it internal/design-partner only.

## Schedule

- **Day 1:** Provision access; select one non-production account/subscription and their AI regions; establish expected artifact inventory with cloud owners.
- **Day 2:** Run AWS Bedrock and Azure discovery; capture scope receipts and permission failures.
- **Day 3:** Reconcile results with cloud-console inventory; fix confirmed connector or coverage-display defects.
- **Day 4:** Repeat both scans; verify idempotency, relationship counts, and no write-side cloud actions.
- **Day 5:** Review evidence pack and lock the next milestone: AWS SageMaker inventory first, followed by Azure AI Search definition-only discovery.

## Test and acceptance criteria

- Automated regression coverage verifies complete, partial, failed, and unsupported scopes remain visible in current coverage.
- A repeated scan creates no duplicate artifacts or relationships and preserves the latest successful scope head.
- The pilot completes with read-only identities; no cloud resource, key, prompt, document, or model-weight content is retrieved.
- Every configured AWS/Azure family has a visible status and explanation.
- Cloud owners can reconcile sampled discovered resources with their respective consoles.
- The evidence pack identifies the top three inventory gaps and includes the approved next-slice backlog.

## Assumptions

- The pilot uses one non-production AWS account and one non-production Azure subscription.
- Approved target regions and workload identities are supplied before Day 1; no secrets are shared in chat.
- Azure Foundry-agent preview and Azure AI Search data-plane discovery remain disabled this week until separately certified.
