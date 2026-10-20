# AI-BOM correlation repair plan and Definition of Done

## Goal

Repair the correctness of AI-BOM-to-finding associations while preserving the shared software vulnerability pipeline. AI-BOM software inventory already queues normal correlation, which creates canonical VULNERABILITY findings asynchronously. AI-BOM reconciliation attaches affected-resource context; it must not create duplicate AI_SECURITY CVE findings or change canonical finding workflow state.

Deliver this work in three reviewable PRs: storage and matching, reconciliation and readers, then classification coverage and uncertainty display. Backend retirement must not be enabled until active-link readers ship with it.

## Scope decisions

Included: bounded multi-hop paths; strict package/version matching; explicit correlation gaps; atomic link/subject repair; authoritative retirement; tenant/resource failure isolation; classification regression tests; path/gap display; accurate upload wording.

Deferred: exact per-upload completion receipts, shared delta-queue schema changes, full stage-status UI, automatic classification-conflict detection, direct model/dataset advisory ingestion, and deployment-based priority changes.

Separate workstream: closing AI Grid posture findings for deleted artifacts.

The seven original items are covered at correctness level. Item 7 means accurate asynchronous wording, not an exact assessment-completion guarantee. Classification tests document current behavior; they do not automatically reclassify mis-typed components.

## Required correctness contract

1. **Source authority:** Each declared resource remains source-scoped. Reconciliation uses that source's current BOM and its dependency edges, never the resource's stale stored component ID without validating its BOM membership. Replacing a source replaces its document-level dependency assertions. A removed path or omitted declaration withdraws that source's support even if the replacement is PARTIAL. PARTIAL controls asset-wide software retirement, not whether superseded dependency assertions remain current.
2. **Inventory authority:** Partial-document omission does not prove an installed component disappeared. Reuse the software inventory pipeline's component lifecycle and provenance decisions; do not invent inventory retirement in AI-BOM code. A supported active component's closed finding remains eligible for historical association.
3. **Uncertainty:** Failed reads, ambiguous/missing identity, missing versions, and traversal truncation do not establish absence. Preserve previously supported associations where the uncertainty prevents a conclusion, record a gap, and qualify them in current context. Definitely removed edges can retire their paths even when an unrelated branch has a gap.
4. **Association lifecycle:** ACTIVE means dependency support remains recorded; it does not imply an OPEN finding, proven deployment, or proven exploitability. An association retires only when its last supporting path is authoritatively withdrawn. Retirement never resolves or otherwise mutates the canonical finding.
5. **Concurrency:** Resource locks serialize reconcilers; source locking also coordinates with uploads. Computing from current evidence is insufficient if an upload can commit between reads and writes. Check captured source revision under a source lock before applying mutations; hold that lock until commit. The ingestion writer must acquire the same source lock before advancing the current BOM/revision. A mismatch aborts that unit without retirement and leaves retry to the next sweep. No new SUPERSEDED status model is required.
6. **Completion:** Upload SUCCESS means ingestion succeeded. Queue PENDING/PROCESSING can indicate outstanding work; absence of those rows cannot prove successful assessment. Failed rows and unmatchable components prevent a clean completion inference. This work does not claim exact per-upload completion.

## PR 1 — Storage, traversal, and matching

### Implementation

- Add a forward tenant migration (V2 if still the next version); preserve V1 and update migration catalog/target tests, including MigrationCatalogTest.
- Extend ai_bom_resource_vulnerability_links with ACTIVE/RETIRED, confirmation and retirement timestamps/reason. Preserve the existing tenant/resource/finding unique constraint.
- Add a path table recording source/BOM revision, ordered component and relationship IDs, terminal inventory component, match method, deterministic fingerprint, and path lifecycle. Multiple alternate paths support one link. Do not introduce cross-source resource merging.
- Add a small gaps table keyed by source-scoped resource, relevant component when known, and reason. Support resource-level gaps where no terminal component exists. Define resolution of old gaps after successful recomputation.
- Build a pure correlation resolver that returns supported paths, matches, gaps, and completeness before making changes. Batch-load current-document nodes and edges.
- Traverse only dependency relationships allowed by the existing schema. Use path-local cycle guards and configurable depth/node/edge/path limits. A cycle is not itself missing coverage; a limit preventing exploration is.
- Prefer canonical purl plus a trustworthy version. Fall back to ecosystem-aware name plus compatible normalized version when purl is absent. Reject collisions, ambiguous matches, conflicting standalone/purl versions, and versionless identities. Use existing ecosystem version utilities rather than generic string equality/case folding.

### Definition of Done

- [ ] New tenant provisioning and V1-to-new-version upgrade both pass PostgreSQL migration tests; V1 is unchanged.
- [ ] Direct and at least three-hop dependency fixtures resolve to the correct terminal finding candidates.
- [ ] A diamond graph preserves both paths; removing either path from resolver input leaves the other support intact.
- [ ] Cycles terminate; non-dependency edges and cross-document nodes produce no false support.
- [ ] Each configured traversal limit has a test yielding TRAVERSAL_LIMIT_REACHED; no limit is silently treated as complete.
- [ ] Exact versioned purl and valid fallback identity match; wrong ecosystem/namespace/version and ambiguous duplicates do not.
- [ ] Version in purl works when the standalone version is absent; a versionless purl yields VERSION_MISSING; conflicting versions yield a gap.
- [ ] Gaps are persistable without a finding/link row and resolve when evidence becomes sufficient.
- [ ] Existing link uniqueness survives migration; path uniqueness prevents duplicate support on repeated delivery.

## PR 2 — Atomic reconciliation, retirement, worker isolation, and readers

### Implementation

- Establish tenant context before transactions. Add a transaction-owning reconciliation boundary through a Spring proxy or TransactionTemplate, scoped per resource. Process source membership/omitted declarations explicitly so old declarations cannot keep superseded links active forever.
- Acquire consistent tenant/source/resource locks in documented order. Coordinate the source lock with ingestion, capture revision for computed evidence, and discard computations that no longer match current source state.
- Atomically upsert/reactivate links and path support, ensure the finding_subjects row exists regardless of prior link existence, retire authoritatively unsupported paths/links, and persist/resolve gaps.
- Delete only the active AFFECTED_AI_RESOURCE subject owned by the retired association when no support remains. Preserve history in link/path rows. Remove the current existence-check early return.
- Update all link and subject consumers: resource detail, affected-resource summaries, finding filters/counts, and any relevant projections. Current context uses active associations; history uses explicit retired associations. Finding-status filters remain independent.
- Use the existing FindingProjectionRefreshService after commit where affected readers require it; batch refresh per tenant sweep where practical. Verify whether a projection actually stores changed subject data before adding refresh work. Refresh failure must not roll back committed links and must remain recoverable.
- Catch failures per tenant around scheduling plus correlation, and per resource around transactional reconciliation. Restore context, roll back failed units, log sanitized tenant/source/resource identifiers, and permit retry on later sweeps. No new general retry platform.

### Definition of Done

- [ ] Failure injected between link and subject writes leaves neither partial write committed.
- [ ] A pre-existing link missing its subject is repaired on the next pass; repeated passes create no duplicates.
- [ ] Concurrent reconcilers produce one consistent link/path set with tenant isolation.
- [ ] A concurrent replacement test pauses computation, commits a newer BOM, resumes reconciliation, and proves older support cannot retire or overwrite newer results.
- [ ] Removing one of two paths retains the link; removing the last authoritative path retires it and its active subject association.
- [ ] Removing a resource from a replacement BOM, changing a dependency version, disabling/deleting a source through supported lifecycle operations, and restoring support each have transition tests.
- [ ] Partial source replacement withdraws its removed dependency path without retiring shared software inventory; partial asset inventory omission alone does not withdraw deployment-independent support.
- [ ] Missing/ambiguous versions, failed reads, and bounded traversal preserve affected prior support with a visible gap; definite removals still retire independently.
- [ ] Reactivation reuses the canonical association identity and restores its subject; history remains inspectable.
- [ ] Reconciliation does not change finding status, suppression, due date, owner, or canonical finding count.
- [ ] Closed findings retain valid associations; current-risk requests respect existing status filters rather than reporting every historical finding as open risk.
- [ ] Retired subjects/links disappear from current summaries and filters without duplicate finding rows or inflated pagination counts.
- [ ] Tenant A failure does not prevent tenant B, and resource A failure does not prevent resource B; retry repairs the failed unit.
- [ ] Any required projection updates happen after commit, and readers see the committed associations.

## PR 3 — Classification coverage, path/gap display, and upload wording

### Implementation

- Add fixtures for vLLM/Triton typed library/application, serving software mis-typed machine-learning-model, model weights, and datasets. Assert both ingestion inventory and declared-resource categorization.
- Preserve declared-type behavior for this round. A mis-typed serving component may remain excluded; document the consequence rather than claiming the test fixes it. Do not infer software from a name allowlist or from purl presence alone.
- Correct comments asserting models can never have CVEs; describe the current software inventory boundary without making a universal security claim.
- Extend resource detail responses and UI with active supporting paths, gap reasons/remediation, and historical retired associations. Keep queries paginated/batched.
- Retain the existing asynchronous upload explanation, explicitly distinguishing ingestion from assessment and later AI-resource linking. Do not display zero findings as a clean assessment result or add a queue-derived COMPLETE claim.

### Definition of Done

- [ ] Properly typed serving software enters shared software correlation; model weights/datasets stay in declared inventory.
- [ ] Mis-typed serving fixtures explicitly demonstrate current exclusion and record automatic reclassification as deferred.
- [ ] Resource detail shows ordered dependency evidence and a useful explanation for VERSION_MISSING, IDENTITY_AMBIGUOUS, and TRAVERSAL_LIMIT_REACHED.
- [ ] Retained but uncertain support is visibly qualified; retired associations appear only in history, not current affected-resource counts.
- [ ] Upload success copy says ingestion completed and assessment/linking run asynchronously; no pending state is rendered as zero confirmed risk.
- [ ] API additions are backward compatible; frontend loading, empty, gap, error, and history states have tests.
- [ ] Frontend lint, typecheck, build, and relevant tests pass.

## Release Definition of Done

- [ ] All three PR checklists are satisfied or exceptions are explicitly documented with owner, reason, and follow-up; deferred work is not claimed complete.
- [ ] Focused unit/PostgreSQL suites pass, followed by required backend verification, migration guards, and frontend CI checks. Tests assert outcomes and rollback/lifecycle transitions, not only mocked method calls.
- [ ] End-to-end fixture: upload model → framework → vulnerable library; shared correlation creates exactly one canonical finding; AI reconciliation adds the full path; replacement removes support and retires the AI association without altering the software finding; restoring support reactivates it.
- [ ] An observation-only pass compares desired versus existing associations for representative tenants before retirement is enabled. Existing links stay ACTIVE during this phase; legacy missing-path records are not retired merely because path backfill has not run.
- [ ] Read/filter changes and retirement writes ship together. Observation mode validates matches and repairs missing subjects before enabling retirement; incomplete units retain prior support and report gaps.
- [ ] Backfill uses the production reconciler, is repeatable, and does not duplicate findings/links/paths. An unchanged second pass makes no semantic changes.
- [ ] Release evidence records test results and observed association changes; logs identify failures, repairs, retirement/reactivation, gap reasons, and traversal limits without sensitive BOM payloads.
- [ ] A rollback disables retirement/reconciliation writes while leaving forward migrations intact; readers can still distinguish history, and canonical software correlation continues normally.

## Delivery dependencies and completion accounting

PR 1 supplies storage and pure resolution. PR 2 consumes it and delivers backend correctness with current readers. PR 3 completes classification/documentation and user-visible explanations. PR 2 alone does not close the entire agreed list.

No exact upload completion receipts or full stage UI are required for this release. If requested later, design them as a separate shared-pipeline change rather than deriving successful completion from an empty queue.
