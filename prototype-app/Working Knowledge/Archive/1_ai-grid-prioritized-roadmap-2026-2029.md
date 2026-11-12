# AI Grid: recommended feature priorities

Reviewed 4 October 2026; revised 5 October 2026 following implementation feedback. Planning recommendation, not an implementation or deployment instruction.

## Objective and assumptions

Deliver reviewer-accepted evidence for a supported AI estate: what is deployed, what was approved, who owns each gap, and whether a fix was verified. Assume the strategy's 2–4-person team and first-customer stage until confirmed otherwise. Choose one provider and customer workflow before committing engineering scope.

Inputs: the 26-page ASTRA AI Grid Final Strategy dated 28 September 2026, the consolidated implementation record dated 26 September, and the current NoScan repository. Repository inspection establishes implementation evidence; it does not establish customer acceptance, deployment, precision or operating reliability. Effort ranges below are the strategy's preliminary incremental engineer-week estimates, not fresh estimates or elapsed delivery dates. Re-estimate against current code before scheduling.

Priorities use customer value, evidence feasibility, dependencies and support burden. Effort ranges are reference information only and do not determine the ranking. Before scheduling, estimate each item's remaining implementation, qualification and operating work against the current code. There is insufficient customer reach, revenue or satisfaction data for a defensible numeric RICE score.

## Retained implementation baseline and gaps

This roadmap is self-contained for planning: the external PDFs and removed implementation record are historical inputs, not required checkout dependencies. The retained conclusions are:

- The latest versions of **159 distinct static policies** comprise **76 GENERAL_AVAILABILITY and 83 PAUSED** entries; defaults are 32 REQUIRED, 24 ENABLED and 103 DISABLED. Across all 175 static version files, 99 are PAUSED and 119 DISABLED. Historical version totals must not be reported as distinct-policy counts. Package GA status does not establish tenant enablement, evaluable evidence or customer qualification.
- Nine runtime packages remain PREVIEW/PAUSED. RT-010–014 are pending-evidence declarations, not executable packages. Existing runtime ingestion, evaluation, timelines and governance need authoritative telemetry and operational qualification; they do not establish inline prevention.
- The runtime Program 2 gate requires at least two qualifying PROVIDER_CONNECTOR sources. A custom adapter does not replace that requirement. Its rolling window is 14 days; source defaults include 100 executions, 95% consequential-event decision-field fill, 90% agent correlation and 80% version correlation over at least 50 version-applicable executions. Field population alone does not establish authority or semantic correctness.
- AI-BOM lifecycle, declared resources, durable projection, deployment linking, reviewed mappings, inherited software-vulnerability links and UI exist. Complete customer acceptance remains unverified. AWS-058/AZR-060 remain PAUSED/DISABLED and require separate evidence-contract qualification. BOM declarations do not constitute an approval registry or verified deployment evidence.
- A complete customer-owned purpose/permitted-scope/approval-expiry registry and its comparison with observed assets are not established by the reviewed paths. Existing scan/coverage/finding reconciliation is a different capability.
- Broad delegation/JIT credentials, general agent enforcement, advanced behavioral analytics and universal replay remain outside the implemented baseline. Static Agentic mapping expansion, complete IAM authorization semantics and dedicated approval/drift controls remain partial or unestablished.
- Checked-in migration heads at this review are platform V7 / tenant V13. Repository counts and migrations do not prove live deployment. No production tenant or customer pilot was inspected.

These conclusions replace the external implementation record's §6/§7 dependency for this roadmap. Recheck them before a release or scope commitment.

## Five features to prioritize first

| Rank | Feature and deliverable | Existing foundation / remaining work | Why this order | Strategy ID / historical sizing only |
|---|---|---|---|---|
| 1 | Dependable discovery and coverage health for one provider | AWS/Azure/Copilot collectors exist. Qualify exact resource types, permission gaps, pagination, throttling, stale evidence and deletion behavior. Show unsupported and inaccessible scopes separately. | Every downstream conclusion depends on reliable observation; reused implementation limits incremental scope. | Y1-03; 3–5 weeks |
| 2 | Customer approval registry and approved-scope comparison | Add one CSV/narrow API import for customer IDs, owner, purpose, environment, permitted provider/region/data scope, approver and expiry. Preserve field authority and timestamps; expose matched, undeclared, unobserved and conflicting states. AI-BOM declarations and reviewed mappings provide reusable foundations, but do not replace the approval registry. Existing scan/coverage/finding reconciliation does not implement this customer approval model. | This creates the decision context that a raw inventory cannot provide. Matching ambiguity and conflicting authorities are the main risks. | Y1-04; 2–3 weeks |
| 3 | A customer-qualified pack of 5–8 controls | Select from the existing static catalog, including 76 GA policies, and reuse governance. Qualify every selected control against the customer source; GA is not a qualification shortcut. Add declaration-dependent checks only where evidence supports them. Include positive, benign, missing, stale and permission-denied cases. | A small defensible pack is more valuable initially than adding more paused catalog entries. Independent review and representative labels constrain release. | Y1-05; 2–4 weeks |
| 4 | Accountable remediation with fresh fix verification | Reuse canonical findings and one workflow destination, including existing ServiceNow integration where suitable. Qualify ownership, due dates, expiring exceptions, retries, reopening and post-fix reassessment. | Turns evidence into treatment and prevents ticket closure from masquerading as remediation. Main risk is incorrect lifecycle reconciliation. | Y1-06; 2–3 weeks |
| 5 | Reusable application/control evidence packs | Reuse the existing tenant-scoped `GET /api/ai-security/artifacts-export` CSV and snapshot/assessment/finding APIs. Add reviewer-facing and machine-readable packs carrying customer IDs, scope, source/time, control version, result, exception and disposition. Reconcile totals with the UI and disclose unknowns. Inventory export alone is not a complete control evidence pack. | Makes the workflow useful in repeated approval/audit reviews and allows effort savings to be measured. Customer acceptance is essential. | Y1-07; 2–3 weeks; re-estimate the reused export path |

Proposed acceptance: use the reference-population protocol below; target ≥95% discovery and a 14-day dependable collection window. This discovery window is a strategy acceptance proposal, distinct from the runtime gate's implemented 14-day window. Test all four approved-scope comparison states. Demonstrate three agreed control scenarios and one fresh verified fix. Production policy release retains the configured 95% Wilson lower-bound precision requirement at 95% confidence and required independent reviewers; the strategy's 90% pilot operating metric is a different measure. Have reviewers accept two comparable evidence reviews and measure preparation effort against a recorded baseline.

## Discovery denominator and qualification protocol

Before customer qualification, the engineering lead and customer access/platform owner approve a versioned reference-population manifest. Record provider, accounts/subscriptions/workspaces, regions, resource types, stable-ID rules, enumeration principal/permissions, API versions, collection times, pagination completion and exclusions.

| Provider | Proposed reference instrument to qualify | Required limitation check |
|---|---|---|
| AWS | Separately executed, paginated AWS CLI/SDK service List/Get exports for each contracted Bedrock/AgentCore/SageMaker resource type and account/region. Archive commands/request parameters and raw reference IDs. | Config or Resource Explorer may corroborate only types they actually support; absence there cannot establish absence for all AI resources. |
| Azure | Azure Resource Graph export for supported ARM resources, plus separately executed management/data-plane List/Get exports for Foundry agents/versions and other child resources not represented in Resource Graph. | Document reference principal permissions, query completeness and unsupported child types. |
| Copilot | Customer-admin export or qualified administrative API enumeration for the contracted environments, bots and versions. | Establish that the export/API actually enumerates each contracted type; a user-visible bot list alone may be incomplete. |

Implement only the chosen provider's reference instrument first. These are proposed instruments, not claims that every API or export covers every type. Qualification must demonstrate their completeness for the contracted scope. Do not use the AI Grid collector's own output as its reference population.

Discovery coverage = uniquely matched observed resources / independently enumerated supported in-scope resources. Use immutable IDs within the declared account/region/type boundary, not display names. Preserve unmatched reference and observed records and explain time-window churn. Permission failures and incomplete reference pagination make the comparison unqualified; they do not justify a smaller denominator. Show unsupported types and inaccessible scopes separately, and report whether the reference principal has any blind spots shared with the collector. No independently defensible reference means no 95% coverage claim.

Scope reductions require customer approval, a new manifest/version and a fresh measurement. Preserve the previous result and exclusions; do not retrospectively edit the denominator to achieve the target.

## Stop and rescope criteria for the first five features

At each pilot review, record continue, remediate, rescope, defer or stop, with a decision owner and next review date. Agree the time/cost limit before starting; none is assumed here.

| Rank | Evidence that stops or changes the work | Decision |
|---|---|---|
| 1 | No defensible reference population, unresolved collection blind spots, or coverage below the agreed threshold after the agreed remediation budget. | Hold dependent customer qualification. Narrow scope transparently, choose another provider/source, or stop that pilot. Do not qualify ranks 2–5 against failed evidence. |
| 2 | No authoritative declaration owner, no stable matching contract, or discrepancies do not improve the customer's actual review decision. | Pause approved-scope claims; reduce to useful inventory context, revise the workflow or defer the registry. |
| 3 | Source evidence cannot support a control, unknowns become false passes, or required precision/independent review fails. | Remove/defer the control and hold its release. Rescope the pack with customer acceptance; stop the offer if no valuable defensible pack remains. |
| 4 | Target/owner cannot be established, retries duplicate work, or fresh evidence cannot distinguish remediation from ticket closure. | Hold verified-resolution claims; retain unresolved/accepted-risk state and correct the lifecycle before further rollout. |
| 5 | Reviewers reject completeness/traceability or comparable reviews show no useful benefit against the agreed baseline. | Revise the pack/workflow; stop expansion if the same outcome is already obtained with comparable effort by existing tools. |

Internal fixtures and explicitly separate test-account work may continue while a customer gate is blocked. A smaller supported scope may justify continuing ranks 2–5 only after the customer accepts the revised boundary and rank 1 qualifies that boundary.

## Mandatory predecessors and release gates

These are engineering prerequisites, not optional expansion features.

- **Secure customer onboarding (Y1-02, 4–6 weeks):** customer IdP/roles and revocation, tenant-isolation negative tests, least-privilege collection, secrets/support access, metadata minimization, region/retention agreement and audit. This is a predecessor to customer data collection and customer-tenant qualification of ranks 1–3, not a parallel engineering allocation.
- **Production operations (Y1-08, 3–5 weeks):** tested tenant-aware restore, upgrade/rollback, service/queue monitoring, incident response, independent security assessment and accepted support scope. The PDF's availability/recovery targets are proposals to negotiate and demonstrate.
- **Deployment branch (Y1-15, 4–8+ weeks):** decide early whether private collection is a purchase prerequisite. Fund it and displace other scope if necessary. A private collector, private control plane and air gap require separate qualification.

The PDF estimates the Year-1 core at 22–39 incremental engineer-weeks, excluding sales, access waiting and independent review. At two people, plan one engineering stream: deployment decision → secure onboarding → customer discovery qualification → approved-scope comparison/control qualification → remediation/evidence acceptance → production operating gate. Internal fixtures, sample imports and separate test accounts may be used before onboarding, but cannot substitute for customer acceptance. Account for onboarding and operations in the same capacity budget, with an operations reserve; do not overlap their estimates to imply extra capacity.

### Concrete production checks

Record the production configuration, test and result for each named path. These are qualification tasks, not a conclusion that the deployed product is exploitable.

- `AiGridDemoPolicyAutoPublishService`: verify `app.ai-security.grid.demo-auto-publish-bundled-policies=false` in the deployed environment; prove synthetic/demo approvals cannot qualify the customer control pack.
- `DemoDatasetController` and demo provisioning/startup paths: prevent demo seeding in customer qualification/production tenants. The controller is PLATFORM_OWNER-restricted; test the production restriction and absence of seeded data rather than describing it as a public endpoint.
- `AiGridValidationGovernanceService.approvePolicy`: the `devTestApproval` branch uses a tenant test note plus dev/test deployment evidence to bypass answer-key/precision prerequisites. Prove that approval/distribution to the customer production scope cannot rely on that bypass, and that normal production gates still apply.
- `SecurityConfig` and `FixIntelligenceController`: review the explicit `/api/fix-intelligence/**` `permitAll()` rule. Qualify intended authentication/authorization and tenant behavior using anonymous and cross-tenant negative tests. The public matcher is confirmed source evidence; actual exposure and isolation require checking the complete request/service/data path.
- Verify seeded sensitive prompts, responses, credentials and tool arguments cannot enter the initial metadata collection boundary; retain the privacy test evidence.

## Next: deepen and repeat the accepted workflow

| Order | Feature | Scope and dependency | Source |
|---|---|---|---|
| 6 | Approval and definition drift | Reopen review after relevant owner, provider/region, tool permission, model/component version, digest, approval-expiry or revocation changes. Start with supported change evidence and approved-scope reconciliation. | Y1-10 |
| 7 | Repeatable onboarding package | Permission templates, source capability matrix, setup diagnostics, import profiles and evidence templates. Qualify a second installation/customer without a code fork. | Y1-11 |
| 8 | Customer coverage/value scorecard | Coverage denominator, freshness, unknowns, reviewed precision, verified treatment, reviewer effort, service health and per-customer operating cost. Avoid a composite score that hides evidence gaps. | Y1-12; Y2-07; Y3-07 |
| 9 | Productize current AI-BOM integration | Acceptance-test lifecycle/replacement/backfill, model/dataset/software typing, bounded projection, reviewed deployment links, ambiguity/setup queues and inherited software vulnerabilities. Keep document declarations separate from observed deployments. Qualify AWS-058/AZR-060 separately before activation. | Retained baseline above; Y1-10; Y3-02 |
| 10 | Minimal continuous assurance | Automate freshness expiry, affected-control reassessment, review reopening and recurring evidence packs for the contracted scope. Deliver this incrementally after ranks 4–6; retain the strategy's longer 90-day qualification as a later gate. | Y3-03, deliberately split into early increments |

AI-BOM implementation is ahead of the September 26 attachment: common lifecycle, declared resources, durable projection, reviewed mapping, dependent vulnerability links and UI now exist. It should be scheduled as qualification/productization rather than rebuilding a missing bridge. Portable export and specialist evaluation are separate additions.

## Conditional expansion, in dependency order

| Order | Feature | Entry condition / boundary | Source |
|---|---|---|---|
| 11 | Trusted runtime action evidence | A buyer funds one producer contract covering actor, agent/version, action/tool, decision, approval reference, outcome and provenance. Qualify source authority, privacy, replay/duplicates and correlation before activation. | Y1-14 / Y2-01 |
| 12 | Runtime controls and scoped autonomy review | Qualify applicable RT-001–009 and introduce customer-owned autonomy profiles with allowed tools/data, approvals, escalation and evidenced stop mechanisms. Missing telemetry prevents unconditional readiness. | Y2-02; existing runtime catalog |
| 13 | Portable provenance and specialist model-result import | Export supported model/component manifests or import one scanner/evaluation result bound to a digest, tool version, scope and expiry. AI-BOM composition claims do not prove behavioral safety. | Y1-13; Y3-02 |
| 14 | Release evidence integration | Bind evidence manifests to application/component version or digest. Start with export; qualify one CI/release consumer if paid demand requires it. | Y2-04 |
| 15 | One downstream policy-engine feed | Authenticated, expiring attributes with explicit audience, stale/missing fallback, revocation and shadow-mode validation. This is a new decision-influence obligation. | Y2-03 |
| 16 | One complementary discovery source | Pick the demonstrated blind spot: second cloud, repository, SaaS or existing usage feed. Require repeated demand, a reference population/evidence contract and support capacity. | Y2-06 |
| 17 | Operator-approved bounded response | Integrate one existing gateway/identity/tool-control system; qualify target identity, dry run, approval, effect, idempotence and rollback. | Y2-05 |
| 18 | Selected cross-agent relationships and RAG/memory evaluation | Qualify a specific workflow and authoritative relationship/action evidence. Seed tests for a precise retrieval/memory failure; use specialist results where appropriate. RT-010–014 remain pending evidence. | Y3-01; Y3-04 |
| 19 | Customer-controlled control plane or reversible automation | Separate funded initiatives with lifecycle support, restore/upgrade or response safety/rollback evidence. Neither follows automatically from a private collector or advisory finding. | Y3-05; Y3-06 |

Current runtime packages remain nine PREVIEW/PAUSED entries. A single custom producer experiment cannot satisfy the existing two-provider Program 2 readiness gate. Activation must follow that unchanged program or an explicitly reviewed separate adapter qualification program. Do not infer runtime readiness from the presence of the ingestion API.

## Work to defer or keep customer-driven

- Broad new policy-count targets, full framework mapping backfills and a distinct ARISE control pack: prioritize mappings and controls needed for the contracted decisions, then expand with reviewed evidence.
- Universal discovery across clouds/SaaS/repos/endpoints; an endpoint/browser fleet; native gateway and policy-engine development.
- Full IAM authorization simulation unless a contracted control needs it; tighten evidence-completeness claims meanwhile.
- General autonomous remediation, learned intent drift, poisoning detection/rollback, full red-team platform and universal historical replay.
- Full model-risk governance, model hosting/training, full private hosting and air gap without separately funded demand.

## Commercial gates tracked separately from features

Y1-01 selects the funded problem and fixes pilot acceptance. Y1-09 records an actual paid-production decision. Y1-11 records independent repeat sale separately from onboarding capability. Y1-12/Y2-07/Y3-07 track support economics, retention and investment decisions. None is achieved by shipping code.

## Suggested delivery horizons

**Now, in sequence:** choose provider/buyer/problem and deployment boundary; prepare internal fixtures and the reference instrument; complete secure onboarding before customer collection; qualify customer discovery; then deliver the minimal approval registry/comparison and initial controls. At two people, these share one engineering stream.

**Next:** complete finding-to-fix workflow and accepted evidence packs; qualify production operations; then deliver drift, repeated onboarding and the value scorecard. Complete AI-BOM acceptance where it serves that same customer outcome.

**Later:** start one funded runtime or model-result track, then selectively add release/policy integrations and one complementary source or response integration. Advance continuous assurance through qualified increments. Treat the PDF's 2026–2029 dates as capacity-dependent planning windows, not delivery commitments.

For each item, track implementation, product qualification and customer acceptance separately, with evidence and an owner. This prevents implemented foundations from being repeatedly scheduled as new features while live qualification remains invisible.

## References

- Historical strategy input: ASTRA_AI-Grid-Final-Strategy-2026-2029.pdf, **28 September 2026 edition, 26 pages**. IDs and page references are version-specific: feature/DoD pages 7–21, release gates p. 22, measurements p. 23, next-90-days decisions p. 24. This external source is not a required repository dependency; relied-on scope, gates and assumptions are retained above.
- Historical implementation input: AI_GRID_IMPLEMENTED_CAPABILITIES.md, **26 September 2026 edition**. The relevant §6 gaps and §7 release boundaries are summarized and updated in the retained baseline above; the removed file is not a required repository dependency.
- Repository evidence: [AI-BOM business logic](business-logic-guide.md#ai-bom--ai-grid-integration), [runtime wave contract](../policy-packages/agcf/runtime-wave-contract.json), and [static policy packages](../policy-packages/agcf/).
- Repository gate logic: [runtime readiness](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridRuntimeTelemetryReadinessService.java) and [validation governance](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridValidationGovernanceService.java).
- Repository production paths: [demo auto-publisher](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridDemoPolicyAutoPublishService.java), [demo dataset controller](../backend/src/main/java/com/prototype/vulnwatch/controller/DemoDatasetController.java), [security configuration](../backend/src/main/java/com/prototype/vulnwatch/config/SecurityConfig.java), and [inventory CSV export](../backend/src/main/java/com/prototype/vulnwatch/aisecurity/controller/AiSecurityController.java).
- Repository migration authority: [migration catalog tests](../backend/src/test/java/com/prototype/vulnwatch/migration/MigrationCatalogTest.java). Packaged heads are V7/V13 at review; stale V5/V11 prose elsewhere is not authoritative. No full test-suite run or live-tenant inspection was performed for this document revision.
- [NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook): voluntary suggested actions across Govern, Map, Measure and Manage; useful reference for governance/evidence design, not certification or a mandate for this feature order.
