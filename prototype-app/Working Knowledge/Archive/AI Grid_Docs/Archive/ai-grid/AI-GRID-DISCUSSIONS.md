# AI Grid — Discussions Log

> Running, dated log of AI Grid discussions and their outcomes as we move **pilot → production**.
> Newest entry at the top. Durable context and ratified decisions live in [`CLAUDE.md`](CLAUDE.md);
> this file is the narrative of *how we got there*.

---

## 2026-08-03 (session 10) — R2 implementation review: mechanism-complete, not release-complete

**Request.** Review Claude's R2 completion at `3e431fa`, preserve durable context, and identify missing or
incorrect implementation.

**Verified state.** R2's backend foundation is substantial: stable system identity/revisions/lineage, temporal
host-context facts, three versioned bounded correlations, hypothesis/validated separation, immutable replay
manifests, canonical finding graduation and compression, complete-reassessment closure, exposure APIs, and
computed R2 release gates are implemented. Focused PostgreSQL suites pass (7 exposure tests and 1 certification
test). The certification test intentionally remains blocked without operational evidence.

**Corrections to status.** PR #22 is still **open**, with `mergedAt = null`; `3e431fa` is not on `main` as of this
review. The platform migration V59 tenant-`findings` loop was restored after session 9 and the local/GitHub
`migration-boundaries` guard correctly fails. Production bootstrap already migrates `tenant_default` through the
tenant Flyway line before runtime verification, so the recommended durable fix is to enforce that bootstrap and
make PostgreSQL tests migrate the default tenant before JPA initialization, then remove the V59 loop. A narrow
guard exemption is acceptable only as explicit, time-boxed release debt—not the architecture.

**Material R2 gaps.** The strong facts required for validated exposures have no real CIEM/DSPM/ASM/reachability
producer in application code; they are test-seeded or accepted through a generic analyst-writable endpoint.
Producer identity/method trust is not server-bound, null confidence becomes `1.0`, and correlations do not enforce
calibrated minimum-confidence/corroboration/scope rules. R2 precision governance uses a raw point estimate with no
minimum sample, Wilson lower bound, dual review, or adjudication, regressing from R1/FR-19. The frontend has no AI
exposure path experience, and correlation recomputes the entire current graph rather than affected subgraphs.
Stale demotion correctly avoids false closure but leaves the existing finding marked `VALIDATED_EXPOSURE` with an
active SLA; the owner-facing needs-evidence behavior remains a product decision.

**Conclusion.** Record R2 as **backend mechanisms implemented and integration-tested**, not R2-certified or
release-complete. Full evidence and recommended closure order are in
[`evaluations/2026-08-03-r2-implementation-review.md`](evaluations/2026-08-03-r2-implementation-review.md).

## 2026-08-03 (session 9) — Merge `main` into the R0–R2 branch, CI work, retire legacy policy-assist suggestion

**Context.** Opened PR #22 (R0–R2), merged `main` into the feature branch, resolved conflicts, and worked through CI.
This did not merge PR #22 into `main`.

**Merge/CI resolutions.** Reconciled main's "AI-backed policy assist": kept main's scope/exception/parameter
evaluator but preserved the `legacyFindingsEnabled` gate; caught a hidden **tenant V48 collision** (renamed
main's policy-scope migration to tenant V58, bumped the tenant schema target 57→58 across CLI/status/ITs);
bumped platform schema-version ITs 60→64; temporarily removed the tenant-`findings` DDL loop from platform V59.
Commit `3e431fa` later restored that loop to keep JPA-backed PostgreSQL tests compatible before the application-ready
tenant migrator runs, reopening the migration-boundary failure. Session 10 records the required resolution.

**Retire legacy policy-assist suggestion (user decision, option 1 + correction).** The post-merge state was
inconsistent: `review()`/`findingsById` moved to the host `findings` table, but the review-history
scope-**suggestion** still read the *disabled* legacy `ai_security_findings`/`ai_security_finding_reviews`,
and the frontend still advertised the card. Rather than only delete the failing test, we **retired the whole
surface**: removed `suggestScopeFromReviewHistory` + its endpoint/DTO, the frontend "Suggest scope from review
history" card + client method + type, and the obsolete test. Kept AI findings/reviews exclusively in the host
model (did **not** repoint `review()` to the legacy silo). Added regression coverage (legacy silo stays empty by
default; host finding review records a disposition) and documented scope suggestions as **deferred** until
integrated with the governed policy-applicability engine. Rejected option 3 for R1 (a real migration must make
suggested scopes govern AiGrid applicability/coverage, which lives in the legacy evaluator). See decision log.

---

## 2026-08-03 — R1 multi-provider coverage integrity closure

**Finding.** Current coverage and readiness selected one tenant-global latest `run_id`. Because AWS and Azure
connectors create independent runs, the most recently completed provider displaced the other provider from the
current denominator. The expected candidate CTE was also recomputed across reconciliation, readiness, metrics,
and every coverage read, while FR-09 dimensional reporting was incomplete.

**Decision and implementation.** Immutable provider runs remain the unit of replay and historical economics.
Current posture is now a separate, transactionally materialized coverage epoch. It unions the latest `COMPLETE`
head for every connector scope, so an empty newer complete scope removes artifacts authoritatively without
resurrecting old manifests. The epoch records each artifact's source run and materializes the applicable
published-policy candidates once. A tenant-scoped advisory transaction lock serializes concurrent AWS/Azure
refreshes. Policy selection changes, owner confirmation, replay, and complete-scope processing refresh the
projection and current readiness/gaps.

**Reporting.** `/api/ai-coverage/dimensions` reports exact expected, recorded, missing, PASS, FAIL, and
`NO_DECISION` counts by technology, provider, resource family, account, environment, owner, policy, and
framework. Framework mappings remain evidence relationships, not certification claims.

**Proof.** PostgreSQL regression coverage starts with independent AWS and Azure scope runs, proves both remain
in current coverage/readiness after Azure completes, then publishes an empty newer Azure scope and proves only
Azure is removed while AWS remains. The regression also verifies every FR-09 dimension is present.

## 2026-08-03 — R1 implementation completion and evidence-backed certification boundary

**Context.** “Complete R1” includes both buildable product mechanisms and operational release evidence. The PRD
requires real provider answer keys, precision review, discovery recall, first-run utility, isolation, economics,
and design-partner soak. Treating test fixtures or caller-authored JSON as that evidence would overstate readiness.

**What changed.** Added an aggregate R1 certification service and platform-owner API. It computes AWS and Azure
answer-key gates from fresh certified `PLATFORM_RUN_BOUND` executions, computes policy governance from every
published policy's current digest and precision requirements, and accepts only six named external evidence types:
discovery recall, first-run utility, determinism/isolation, economics/budgets, and AWS/Azure design-partner soak.
Evidence is immutable, expiring, and cannot impersonate an automatic gate. R1 decisions persist the complete gate
snapshot and remain `BLOCKED` until every gate passes.

**Schema and verification closure.** The generalized host `Finding` columns are now applied to the reset-line
`tenant_default` template as well as migrated customer schemas. A production-bootstrap mismatch then exposed that
two V52 RLS policies retained clone-time tenant-specific predicates. V52 now drops and recreates those policies
deterministically, restoring structural checksum parity between the migrated template and newly provisioned
customer schemas. The production bootstrap, certification test, legacy finding correlations, and tenant clone
regressions pass independently.

**Decision.** The bounded R1 implementation is code-complete with selected exact Bedrock/Azure controls; the
product is not called R1-certified until the aggregate gate passes with real evidence. The 62-policy matrix remains
a roadmap/completeness basis, not an R1 shipment commitment.

## 2026-08-02 — R1 chunk 3: Azure RAI policy collection and exact filter control

**Context.** The bounded catalog identified Azure content-filter/RAI configuration as the highest-value
uncollected Azure LLM01/09 surface. The implementation needed a real verdict without treating default-policy
behavior, omitted fields, or filter presence as proof of complete protection.

**What changed.** Added `AZURE_RAI_POLICIES` as a regional, least-privilege ARM discovery family using
`Microsoft.CognitiveServices/accounts/raiPolicies/read` at the pinned `2024-10-01` API. RAI policies are
first-class `AI_GUARDRAIL` artifacts; named deployment references are collected and matched into
`USES_GUARDRAIL` relationships. The evidence body retains mode, base policy, filter counts, custom-blocklist
count, and the deployment's `raiPolicyName` without collecting prompts or completions.

Published `AZURE_RAI_POLICY_NON_BLOCKING_FILTER` is intentionally narrow. It fails only when a returned filter
explicitly has `enabled=false` or `blocking=false`, and passes only when every returned filter has explicit
boolean values and all are enabled+blocking. Empty or structurally incomplete lists omit the decision fact and
produce `NO_DECISION`; category coverage, thresholds, and filter efficacy are not claimed by this control.

**Integrity fixes found by the new answer key.** Fresh tenant provisioning exposed V52 clone/replay
non-idempotence, so the readiness migration is now safe when template tables/columns/indexes already exist.
The R1 coverage CTE also used PostgreSQL's `?` JSONB operator with named JDBC parameters; it now uses
`jsonb_exists`, eliminating placeholder ambiguity.

**Verification.** Unit tests prove conservative safe/unsafe/incomplete RAI interpretation, family and
permission-matrix alignment, and ARM type classification. PostgreSQL answer-key coverage proves FAIL opens an
owner-facing finding, PASS closes it, and incomplete evidence remains `NO_DECISION`/`MISSING_FACTS`.

**Next.** Complete category/threshold semantics only after a separately curated answer key defines mandatory
filter names and acceptable thresholds; continue P-AZ/P-B collection or the next high-value Bedrock prerequisite.

## 2026-08-02 — R1 chunk 2: Minimum Context Pack and first-run utility

**Context.** After coverage integrity, R1 needed useful baseline context and tenant-specific readiness without
turning evidence availability into hidden policy enablement or shrinking the security denominator.

**What changed.** Added the four exact proxy-versus-stronger claim pairs to the governed fact dictionary.
Direct provider relationships can now derive `data.source_linked` with `RELATIONSHIP_GRAPH` provenance,
method/version, confidence, and derivation input IDs. It never produces `data.sensitive_content_confirmed`;
effective-admin, sensitive-content, verified-reachability, and confirmed-owner claims still require their own
approved evidence sources.

Each run now persists policy readiness separately from tenant selection. Readiness reports candidate,
applicable, decision-required, decision-ready, no-decision, error, and missing-assessment counts plus required,
available, and missing evidence. States are `READY`, `PARTIAL`, `BLOCKED`, `NOT_APPLICABLE`, and
`NO_RESOURCES`; none changes REQUIRED/ENABLED/PREVIEW/DISABLED or removes a policy from coverage.

Open coverage gaps are projected into a prioritized setup-action queue. Pipeline omissions and collection
errors rank ahead of missing permissions, missing/unsupported/stale/low-confidence evidence, classification,
coverage, and ownership actions. This replaces an undifferentiated wall of `NO_DECISION` without hiding it.

First-run telemetry is bound to the connector ID retained on immutable manifests. It records expected and
missing assessments, full and owner-facing decision reachability, the 80% provisional target/result, and time
anchors for inventory, decision, finding, owner-routed finding, gap, and future exposure hypothesis. The
owner-facing utility numerator/denominator is separate from full security coverage and conservatively retains
missing assessments.

**Verification.** PostgreSQL proves exact proxy separation, relationship-derived linked-data context, absent
sensitive-content promotion, blocked policy readiness with missing IAM scope, prioritized setup actions,
connector-scoped baseline telemetry, and agreement between metrics and the full coverage denominator. Schema
bootstrap/reconciliation and the full backend suite pass.

**Next.** Expand certified Bedrock and Azure policy/fact breadth against the bounded coverage matrix, beginning
with connector prerequisites that turn the highest-value setup actions into reliable decisions.

## 2026-08-02 — R1 chunk 1: coverage integrity and provenance-bound validation

**Context.** The first major R1 chunk needed to make the “zero silent omission” and answer-key provenance
requirements executable rather than documentation-only.

**What changed.** Coverage is now computed from the immutable run's expected artifact × latest-published-policy
candidate set, using artifact type and native kind applicability, instead of counting only assessment rows that
happened to be emitted. The API reports expected, recorded, and missing assessments; policy/resource coverage;
owner-facing and full decision reachability; and an artifact/policy detail ledger. Reconciliation distinguishes
an artifact with no candidate policy (`NO_POLICY_COVERAGE`) from a missing assessment for a candidate policy
(`MISSING_ASSESSMENT`). Replay re-runs reconciliation and resolves repaired omissions.

Answer-key runs now require source tenant and immutable AI Grid run identifiers. Every policy-scoped case must
reference a source assessment from that run. The server validates policy/version, applicability, decision, and
finding presence against tenant-scoped platform state, derives the decision fingerprint itself, and persists the
binding. Only `PLATFORM_RUN_BOUND` answer-key runs can satisfy policy release readiness; pre-existing external
attestations remain visible but cannot approve a release.

**Verification.** PostgreSQL tests create and repair a deliberate candidate-policy assessment omission, reject a
forged assessment reference, prove the server-bound result persists tenant/run/assessment provenance, and retain
the existing Wilson precision/release flow. Focused suites, the full backend suite, and `-Ppostgres-it verify`
pass.

**Next.** Continue R1 with the Minimum Context Pack and adaptive evidence readiness/first-run utility telemetry,
then expand bounded Bedrock/Azure catalog breadth without weakening the denominator.

## 2026-08-02 — Governance precision review

**Context.** A follow-up review validated the answer-key and precision governance architecture and identified
that precision publication used the point estimate, answer-key output was caller-attested rather than bound to
pipeline execution, and recall labels were collected without a precision-review recall gate.

**Decision and implementation.** The statistical finding was valid and fixed immediately: finalization now
passes only when the Wilson confidence lower bound meets the configured precision threshold. PostgreSQL tests
prove 2/2 true positives fail a 95% claim while a dual-reviewed 100/100 sample passes and releases normally.

The provenance observation is valid, but adding another caller-supplied evidence string would not close it.
FR-18 therefore requires the real answer-key harness to bind results to immutable tenant run IDs, assessment IDs,
and server-derived decision fingerprints. That binding was implemented in the following R1 chunk; older external
attestations cannot satisfy release readiness. The recall note does not change the precision gate:
discovery recall is a separate answer-key inventory metric under the PRD and must not be inferred from policy
finding labels.

## 2026-08-02 — R0 integrity review and hardening

**Context.** A principal review identified replay determinism, atomicity, confidence, fingerprinting,
redaction, finding-governance lifecycle, projection cost, and core-finding schema risks.

**Adjudication.** The replay, confidence, fingerprint, redaction, downgrade, and projection findings were
valid. Replay had a deeper mutable-state dependency: it read current artifacts and relationships in addition
to wall-clock time. The transaction finding was partially accurate: ingestion already used a shared Spring
transaction through `TransactionTemplate`, so JDBC/JPA/outbox writes were normally atomic, but the AI Grid
pipeline did not declare that invariant and had no forced-failure proof. The V48 concern was valid in spirit,
but the existing legacy invariant is vulnerability ID plus an asset-or-component subject; asset ID alone has
not been universally required since V44.

**What changed.** Replay now reads immutable snapshot bodies and run-scoped relationship snapshots and uses
the stored snapshot as-of time for freshness. Policies enforce `minConfidence`; assessments retain stable
finding identity and add a separate decision-content hash. `STANDARD_V1` now recursively removes sensitive
keys before both snapshot and fact persistence. Complete-scope processing is explicitly transactional.
Policies leaving `REQUIRED`/`ENABLED` auto-close existing owner-facing findings, while projection rebuilds are
batched once after commit. V51 restores the legacy vulnerability-subject database constraint and advances the
tenant target; the redundant missing-scope branch was removed.

**Verification.** Focused unit tests, the complete AI Security PostgreSQL integration suite, validation
governance, production bootstrap, tenant reconciliation, and the full backend suite pass. Forced failure
proves no partial snapshot/assessment/finding/receipt/outbox state survives, and retry succeeds. Replay remains
stable after wall-clock aging and current-inventory mutation; low-confidence evidence becomes
`NO_DECISION/LOW_CONFIDENCE`; governance downgrade closes the canonical finding; invalid legacy vulnerability
subjects are rejected by PostgreSQL.

## 2026-08-02 — R0 implementation completion

**Context.** The user asked to complete Release 0 after the core catalog, snapshot, fact, assessment,
reconciliation, economics, and initial UI foundation had landed.

**What changed.** Completed the canonical finding workflow for the Bedrock guardrail slice: new FAILs create
host findings with owner and SLA; active suppressions survive reassessment; only a complete, verified PASS can
resolve a finding; incomplete evidence remains `NO_DECISION`; and later recurrence reopens the same finding
with an audit trail. Added generic ServiceNow promotion for canonical AI findings and role-gated fact/evidence
access. Made answer-key freshness, precision thresholds, lifecycle state, and recorded release decisions
queryable as one release-readiness result.

**Verification.** Added PostgreSQL integration coverage for FAIL → suppression → repeated FAIL → verified
PASS closure → incomplete-evidence non-closure → recurrence, plus governance readiness, evidence RBAC, and
ServiceNow linking tests. Full backend/frontend regression results are recorded in the implementation handoff.

**Boundary.** R0 is implementation-complete; no production approval is fabricated. An environment becomes
R0-certified only after its real answer-key run, precision review, and explicit release decision pass.

**Next.** Begin R1 breadth and coverage integrity; do not start R2 exposure claims until R1 exit gates pass.

## 2026-08-01 (session 8) — Per-policy catalog (Bedrock + Azure, OWASP-mapped)

**Participants:** @karthik.gowri, Claude.

**Context.** "Open the next" — build the concrete per-policy catalog the accuracy register + phase plan were
built to feed.

**What we did.** Read the shipped registry to ground truth (5 Bedrock + 8 Azure = the 13; confirmed their
`controlMappings` are ad-hoc `CIS`/`AWS`/`AZURE`/`NIST` strings, **none OWASP**). Authored the catalog: 41
policies (19 Bedrock BR-##, 22 Azure AZ-##), each with severity, artifact type, **OWASP LLM Top 10 mapping**,
required facts, and an `Eval today` status (🟢 verdict / 🔵 verdict-shallow / 🟡 NO_DECISION→B fetch / 🟠
NO_DECISION→C compute / ⚪ no-artifact). Every non-green row is pre-linked to its owning `AR-##`/`P2-##` — so the
catalog *is* the `NO_DECISION`→requirement index the s7 rule demands. Added an OWASP coverage rollup.

**Headlines.** 17 verdict-now policies (Epic 0 seed set; golden-parity the 13 shipped). Real FAIL verdicts
concentrate in **LLM02 / LLM06 / LLM08**; LLM01/04/05/09 are presence-only by nature; LLM07/LLM10 thin.
`AZ-11` (Azure content-filter/RAI) is the single highest-value unlock — the whole Azure LLM01 story, unfetched
(AR-7). Concrete backend task surfaced: re-map the 13 shipped policies' `controlMappings` to OWASP.

**Deliverable.** [`designs/2026-08-01-bedrock-azure-policy-catalog.md`](designs/2026-08-01-bedrock-azure-policy-catalog.md).

**Update (same session) — "how do we know 41 is the superset?"** It isn't: the catalog was an *enumeration*, and
reading the code proved it (several modelled families — ML workspace/compute/jobs, Foundry projects/connections,
Search skillsets, Bot channels, RBAC — had **zero** policies). Agreed the rigorous test is a **coverage matrix**:
superset = { AI resource family × control dimension : a valid AI-attributed policy exists }; enumerate the full
cross-product, mark every cell. Settled two scope calls (my recommendation, user agreed): **(1)** strictly
**Bedrock** this release — SageMaker/AWS-AI-adjacent deferred (framework #3; LLM04/training lives there, so
Bedrock-only shows LLM04 thin by design); **(2)** **Content Safety IN** (it's the Azure LLM01/09 backbone, not an
edge), **Copilot Studio DEFER** (different discovery mechanism = SaaS-admin plane). Residual scope moved to the
phase-2 plan §8; boundary keeps the artifact-type axis provider-neutral.

**Deliverable.** [`designs/2026-08-01-coverage-matrix.md`](designs/2026-08-01-coverage-matrix.md) — family×dimension
grids for Bedrock + Azure with every cell marked, a gap register of **21 grid-derived candidate policies**
(BR-20..28, AZ-23..34), revising the superset **41 → ~62**. Grid forced open the real gaps: **LLM04** homes
(training/fine-tuning), **LLM07** homes (new PROMPT_ASSET), **Foundry connections** (biggest Azure miss), Azure
ML training surface, Search skillset egress.

**Update — catalog regenerated (s8).** Folded the 21 gap candidates into the catalog (superset **62**; OWASP
rollup now populates LLM04 + LLM07). Introduced Azure **prerequisite epics** as the owning requirements for the
Azure gap policies: **P-A** content-filter/RAI collection (== AR-7, highest value; unblocks AZ-11/12/30/34),
**P-B** AI-family config completion (field-fetch on already-modelled ML/Search/Bot/Foundry families; unblocks
AZ-24..29/31/32/33), **P-C** Foundry Connections discovery (new family; unblocks AZ-23). Doc:
[`designs/2026-08-01-azure-discovery-prerequisites.md`](designs/2026-08-01-azure-discovery-prerequisites.md).
Bedrock has symmetric prerequisites (Customization Jobs, PROMPT_ASSET) — noted, not yet epic'd.

**Update — requirement registers consolidated (s8).** Noticed the metadata-collection requirements were
duplicated across three registers (AR "fetch" group / coverage-matrix Azure gaps / P-A-B-C) — AR-7 was literally
== P-A. Consolidated **by pipeline stage, one home each**: **collection** (former AR-1..9) → **two prerequisite
epics organized by provider, P-AWS + P-AZ** (user's call); **computation** (AR-10/11/12) → Phase-2 catalog
(P2-1/2/3); the accuracy register keeps only verdict-quality (AR-13..15) + structural (AR-16..18). P-AWS closes
the Bedrock-symmetry gap; P-AZ absorbs the old P-A/B/C as workstreams. AR IDs retained as pointers; old
Azure-only prereq doc redirected. Doc: [`designs/2026-08-01-discovery-prerequisite-epics.md`](designs/2026-08-01-discovery-prerequisite-epics.md).

**Next session likely starts with:** Epic 0 build — `platform.ai_policy_catalog` migration seeding the 17
verdict-now rows (OWASP-mapped) + generic predicate evaluator with a golden parity test against the current
engine for the 13 shipped policies; **P-AZ · P-A** (content-filter/RAI) + the foundational tags/full-config
workstreams are the highest-value prerequisites to schedule alongside.

---

## 2026-07-31 (session 7) — Scope to both providers; `NO_DECISION` as the accuracy backlog

**Participants:** @karthik.gowri, Claude.

**Context.** Revisited s6. Two moves: (1) **change scope from "Bedrock first" to both Bedrock and Azure**;
(2) drill into "why is there `NO_DECISION` at all," then decide what to do about it.

**Discussion — why `NO_DECISION` exists.** Enumerated four causes: C1 fact not fetched (bucket B), C2 derived
signal not computed / no CIEM-DSPM-ASM capability (bucket C), C3 scan couldn't read the resource
(permission/throttle — evidence-gated, operational), C4 single-field read is shallow so the verdict may be
*wrong* (bucket A✎). Key point: `NO_DECISION` volume is mostly a **scoping choice** — it only appears when a
policy ships ahead of its fact/capability. A well-scoped A-bucket config rule verdicts every time.

**Decisions made (user).**
1. **Scope = both Bedrock and Azure**, complete coverage of every policy valid for *AI artifacts* (Attribution
   Rule), OWASP LLM Top 10 in scope. Explicitly **not** a Wiz clone and **not** the full 260 rules — "Wiz is
   inspiration; take the idea and build a better, more honest solution."
2. **Keep `NO_DECISION` — it is desirable.** It marks where to go deep on a control to improve accuracy. Every
   `NO_DECISION` must carry an owning accuracy requirement; policies may ship `NO_DECISION` only if the
   requirement is registered. The C4 "shallow verdict" class ("go deep in a specific control") is first-class.
3. **AI Grid is a *consumer and attributor* of general-security capabilities (CIEM/DSPM/ASM), not their owner.**
   Followed a "do these fall under AI security or general security?" discussion: the *mechanisms* are general
   CNAPP; only the **attribution** to an AI artifact makes a finding AI security. So AI Grid builds the
   attribution layer + the thinnest slice not already available from the host, and consumes general-security
   facts where they exist — it does not rebuild CIEM/DSPM/ASM. Extends the s5 Attribution Rule from *policies*
   to *capabilities*; shrinks Group B (AR-10/11/12) accordingly.

**Deliverable produced.** [`designs/2026-07-31-accuracy-improvement-requirements.md`](designs/2026-07-31-accuracy-improvement-requirements.md)
— the structural gaps written up as an accuracy-requirement register (AR-1..AR-18), grouped into fetch-more (B),
build-capability (C), deepen-shallow-verdict (A✎), and structural/operational (attribution, registry, coverage
UI). Includes the §3 hard-limit ceilings (efficacy/undiscoverable/drift — *not* requirements) and a §5 honest
OWASP LLM Top 10 coverage map (LLM02/06/08 deliver real FAIL; LLM01/04/05/09 are presence-only by nature).

4. **Two-phase model.** User proposed **Phase 1 = collection** (facts from AWS/Azure — connectors already built)
   and **Phase 2 = computation** over that data, and said Phase 2 must go **beyond CIEM/ASM/DSPM** to any general
   security concept. Endorsed with four refinements: (i) Phase 1 must collect *primitives* + snapshot history,
   not rule-specific fields; (ii) every Phase 2 signal attributed to an AI artifact (open mechanism, bounded
   scope — else it's CSPM); (iii) derived ≠ observed → confidence/provenance, coverage UI distinguishes them;
   (iv) DSPM is not a computation — it needs a new *collection source* (Macie/Purview) or a defer. Verified
   against code first: the Bedrock connector fetches only primitives (IAM policy docs, bucket-policy-status,
   network flags) and calls **no** provider security service (Macie/Access Analyzer/Simulator/Reachability/
   Purview/Defender) — confirming CIEM/ASM/DSPM are derived/consumed, never fetched attributes.

**Deliverable produced.** [`designs/2026-07-31-phase2-computation-plan.md`](designs/2026-07-31-phase2-computation-plan.md)
— phase model, four principles, Phase 1 primitive-collection table, an 11-item Phase 2 computation catalog
(P2-1..11, extensible), sequencing (effective-perms first, correlation last), and architecture (derivation
service + fact provenance model).

**Next session likely starts with:** the concrete **per-policy catalog** (every Bedrock + Azure AI rule → OWASP
→ required facts → `AR-##`/`P2-##` link) — the artifact the register + phase plan were built to feed — then
Phase-1 primitive-collection hardening and the P2-1 effective-permission computation.

---

## 2026-07-31 (session 6) — Failure modes; scope to a single initial framework

**Participants:** @karthik.gowri, Claude.

**Context.** User asked "when will this model NOT work," then proposed scoping the initial solution to a single
framework and asked which is the best initial target.

**Failure-mode analysis.** Enumerated 10 failure classes, split into hard limits of agentless-config (can't see
undiscoverable artifacts; can't prove controls *work*; point-in-time drift; single-field inaccuracy) vs.
deferred-capability gaps (marquee risks → `NO_DECISION` until CIEM/DSPM/ASM; toxic combinations empty early) vs.
design/operational risks (attribution/dedup of shared dependencies; ownership/technology-registry silent
failures; **coverage-as-safety**; scale/delta discovery). Captured as a **living** doc:
[`known-limitations.md`](known-limitations.md).

**Decisions made.**
1. **Coverage must never present `NO_DECISION` as pass** — foreground the 5-way status (highest-attention risk).
2. **Single-framework-first is the right approach**, provided the framework is rich enough to exercise the whole
   architecture (types + technology + capabilities + edges + attribution + CIEM on-ramp + OWASP mapping).
3. **Initial target = AWS Bedrock (agent-centric), reported against OWASP LLM Top 10 (2025).** Most complete
   discovery already; the Bedrock Agent stress-tests the full model in one ecosystem. Azure OpenAI = framework #2.
   Agent SDKs excluded (need deferred source/host discovery). `known-limitations.md` is a living doc to keep updating.

**Next session likely starts with:** Epic 0 build scoped to Bedrock — the agent "hero" chain (agent + guardrail +
action-group Lambda + KB→S3 + execution role), a handful of A/B policies + one C stub (`NO_DECISION`), all
attributed to the agent and OWASP-tagged, coverage-honest.

---

## 2026-07-31 (session 5) — Scope boundary: is cloud config in scope for AI security?

**Participants:** @karthik.gowri, Claude.

**Context.** User proposed cloud-configuration policies are out of scope — focus only on AI security / compliance
of AI artifacts — and asked whether cloud resource config is actually needed to derive AI-artifact security.

**Discussion.** "Cloud config" is three things: (1) generic CSPM with no AI nexus, (2) config of the AI artifact
itself, (3) config of non-AI resources the artifact depends on. Excluding #1 is correct (don't be a CSPM), but
#2/#3 *are* AI security — an agent's risk is its guardrail + execution-role perms + action-group Lambda auth +
backing-bucket exposure, all config. Excluding cloud config literally would gut the product (our 13 policies and
the piloted slice rule are all config), and OWASP-LLM compliance itself requires config (LLM06 = perms + tools).

**Decision made (user agreed).** Scope by **AI-nexus + attribution, not by mechanism** — the **AI Security
Attribution Rule**: every finding is attributed to an AI artifact and justified by that artifact's own config OR
a security-relevant relationship edge. IN: #2 + #3 (dependency config consumed artifact-first as facts/edges) +
OWASP/NIST mapping. OUT: #1 generic CSPM. Ship "Knowledge base exposes a public S3 source", not "Bucket X is
public". Cloud-config *reads* in scope; standalone cloud-resource *findings* out. Recorded in decision log + plan
guardrails; dovetails with Epic 0 fact model + Epic 5 graph.

**Next session likely starts with:** Epic 0 build (unchanged), authoring all catalog rules artifact-first.

---

## 2026-07-31 (session 4) — API style (GraphQL?) & policy authoring model

**Participants:** @karthik.gowri, Claude.

**Context.** Two architecture questions: (1) should the API shift to GraphQL (à la Wiz `cloudResourcesV2`)?
(2) is the backend policy engine scalable, and should we move to a query-builder model for policy creation?

**Discussion.** Both reduce to one primitive — a structured predicate over a normalized fact vocabulary
(`fact + op + value`, AND/OR). GraphQL's `filterBy`, a policy `predicate_json`, and a query-builder UI are three
consumers of it. GraphQL as a *transport* would force re-plumbing auth + per-resolver tenant RLS + a second
surface to secure/test against a REST-wired spine, for ~80% overlap with what a REST structured-filter endpoint
gives. Current engine is a hardcoded `switch` + `List` — not scalable; Epic 0 already fixes the evaluation model.

**Decisions made (user).**
1. **Ship a curated, platform-owned built-in catalog; tenants only enable/disable.** No tenant-authored custom
   policies, no query-builder authoring UI, no customer-facing fact-schema registry. (Matches existing
   distribution + settings tables.) → Simplifies scope; removes an authoring epic.
2. **Stay REST; no GraphQL.** Borrow structured-filter/cursor/projection ideas on REST only if the inventory
   table needs them.

**Consequences.** Epic 0's declarative engine still stands but is reframed as *internal* authoring-at-scale +
data-driven compliance/coverage (curated-only ≠ keep the `switch`). The fact dictionary is downgraded to an
internal seed/test validation helper. Authoring the 48 Wiz AWS/Azure rules (Epic 4) is an internal content task
(catalog rows). Plan + decision log updated.

**Next session likely starts with:** Epic 0 build (unchanged), now with these scope guardrails documented.

---

## 2026-07-31 (session 3) — Connector metadata sufficiency vs. Wiz policy needs

**Participants:** @karthik.gowri, Claude.

**Context.** User asked whether the AWS/Azure connectors fetch enough metadata to validate policies *accurately*,
to review the Wiz policy catalog for gaps, and shared Wiz's `cloudResourcesV2` GraphQL query + sample responses
(IAM role, AI_AGENT, MCP_SERVER).

**What we did.** Traced the exact facts each discovery service emits and their backing API calls; cross-read
against the Wiz A.6 catalog and the `cloudResourcesV2` shape.

**Findings (headline).** Wiz's API has two metadata tiers: a populated inventory/config tier and an **enrichment
tier that is null at scan time** (`isAccessibleFromInternet`, `hasAdminPrivileges`, `hasSensitiveData`, …) —
computed asynchronously via CIEM/DSPM/ASM. Our connectors fetch *exactly* the fields the 13 policies read and
**no resource tags** (blocks ownership). Gaps fall into three tiers: (1) config fields not fetched yet — easy;
(2) resource types not discovered (AgentCore, SageMaker, Copilot Studio, Azure content-filter/RAI policies) —
medium; (3) derived signals no single API returns (admin/sensitive-data/validated-reachability/confused-deputy)
— hard, requiring CIEM/DSPM/ASM capabilities. Full analysis:
[`evaluations/2026-07-31-connector-metadata-gap.md`](evaluations/2026-07-31-connector-metadata-gap.md).

**Decisions made.**
1. Epic 0 fact model must be **`UNKNOWN`-aware + provenance-tagged** and include the six Wiz enrichment booleans.
2. Add two near-term connector tasks: **emit resource tags** + **generic full-config fetch per family**.
3. **CIEM-lite** (effective-permission + trust-policy resolution) is the first Tier-3 capability epic.

Follow-up in the same session: produced the **policy superset & validation-feasibility matrix** (categorizes
the ~70 near-term addressable policies into A = validatable now / B = achievable via code changes / C = real
capability gap): [`evaluations/2026-07-31-policy-superset-matrix.md`](evaluations/2026-07-31-policy-superset-matrix.md).
Headlines: ~18–20 policies validatable now (blocked only by Epic 0); ~40+ via connector enrichment (tags +
full-config fetch + Azure content-filter/RAI + new resource types); real gaps = CIEM / DSPM / ASM / model-scan /
SAST / runtime. Azure content-filter/RAI is the most important B enrichment; CIEM the most important C to invest in now.

**Next session likely starts with:** Epic 0 build (as before), now with the `UNKNOWN`-aware fact model and tag
collection folded into the vertical slice.

---

## 2026-07-31 (session 2) — Wiz end-state, feature list, and build sequencing

**Participants:** @karthik.gowri, Claude.

**Context.** User articulated their AI Grid vision: AWS + Azure agentless discovery → rich metadata for
platform workflows (attack surface, owner per artifact, relationships, criticality, hygiene recommendations)
→ a **scalable policy engine + policy catalog** assessed across the AI inventory → violations as **AI Findings**.
Introduced the **Wiz AI Security reverse-engineered PRD** (`~/Downloads/WIZ-AI-Security-Reverse-Engineered-PRD (1).md`)
as the **end state in spirit, not exact specs**, and asked for a gap evaluation and a feature list with backend changes.

**What we did.** Read the full Wiz PRD (7 validation mechanisms, ~22 resource types, 260 AI-tagged rules,
graph toxic-combination correlation, OWASP LLM Top 10 compliance dashboard). Grounded the host-app workflow
anchors (`Finding`, `FindingSlaService`, `OwnershipRule`/`OwnershipRuleService`, `ServiceNowIncidentService`,
`BusinessCriticality`, `assets.business_criticality`). Produced a conformance snapshot + feature list.

**Findings (headline).** The pilot built the right **spine** (agentless discovery, 21-edge relationship graph,
evidence-gated evaluation, strong tenancy) but the **policy layer is code, not data** (`switch(policyId)` +
hardcoded `List`) — which fails the "scalable policy engine" requirement — and **findings/artifacts are
isolated from the platform's own workflows** (no owner/criticality; separate `ai_security_findings` silo).
Fix those two + artifact metadata and the rest becomes content, not architecture.

Full gap analysis + feature list: [`evaluations/2026-07-31-wiz-endstate-gap-and-feature-list.md`](evaluations/2026-07-31-wiz-endstate-gap-and-feature-list.md).

**Decisions made (all ratified by the user).**
1. Adopt the Wiz PRD as the end-state-in-spirit north star.
2. Make the policy engine data-driven (Epic 0) before adding coverage.
3. Graduate AI findings **fully** into the host `Finding` workflow, via a **strangler** pattern (feature-flagged
   behind the disabled `ai.security` entitlement; artifact links to an `asset` where one exists, else a light AI
   subject; evidence in a side table; retire `ai_security_findings` after parity).
4. Build as **one data-driven vertical slice** (Epics 0→1→2→3, single rule = Bedrock guardrail < MEDIUM), then
   breadth via Epic 4. Recommendation given and user agreed.

**Deliverable produced.** Detailed vertical-slice implementation plan with schemas, migrations (platform V50,
tenant V48), services, and endpoints: [`designs/2026-07-31-vertical-slice-implementation-plan.md`](designs/2026-07-31-vertical-slice-implementation-plan.md).

**Next session likely starts with:** kicking off the Epic 0 build — `platform.ai_policy_catalog` migration +
seeding the 13 existing rules as rows + the generic predicate evaluator with a golden parity test against the
current engine.

---

## 2026-07-31 — Kickoff: pilot scope-conformance evaluation

**Participants:** @karthik.gowri, Claude.

**Context.** Expanding the app into the AI Security space. First task was to evaluate the AI Grid
capabilities currently in the codebase against the reconciled spec `AI-Security-Final-Scope (1).pdf`
("Scout AI Security — AI-GRID Module", prepared 2026-07-26).

**What we did.** Read the full 12-section PDF, then mapped the actual implementation end-to-end:
migrations (platform `V47–V49`, tenant `V45–V47`), the `com.prototype.vulnwatch.aisecurity` backend
package (discovery, observation ingest, policy engine, job worker), and the `features/ai-security`
frontend slice.

**Findings (headline).** The shipped code is a **well-built, honestly-scoped pilot**: read-only discovery +
deterministic policy assessment for **AWS Bedrock + Azure AI/Foundry/ML/Search/Bot only**, entitlement
`ai.security` **disabled by default**, with strong multi-tenant/RLS/credential handling and exemplary
production-readiness gating. It diverges from the reconciled scope in the **load-bearing** parts:
no capability-flag normalization, no scoring (finding/asset/tenant rollup, posture, blast radius), a flat
13-policy engine instead of the 9-dimension weighted catalog, ad-hoc control mappings instead of OWASP LLM
Top 10 / MITRE ATLAS, and AI findings living in a separate silo rather than graduating into the host
findings workflow. Discovery covers 2 of 6 planes; no runtime OTLP; no ML-BOM export; API naming differs.

Full write-up: [`evaluations/2026-07-31-pilot-scope-conformance.md`](evaluations/2026-07-31-pilot-scope-conformance.md).

**Recommendation put to the user (awaiting ratification).** Treat the shipped build as the **pilot v1**,
keep shipping to design partners, **but land the capability-flag layer and the scoring model before the
third connector** — both are the scope's thesis and get exponentially more expensive to retrofit later.
Also flagged: the DoD gate "tenant rollup changes predictably when a seeded misconfig is fixed" is currently
**unmeetable** (no rollup exists) and must be built or amended before pilot sign-off.

**Decisions made.**
- Stood up this `ai-grid/` workspace (CLAUDE.md context memory + this discussions log + evaluations folder)
  to carry the multi-session pilot→prod effort.

**Open items carried forward.** See [`CLAUDE.md` §7](CLAUDE.md) — pilot-vs-target stance, findings
graduation, API naming, rollup DoD gate, GCP timing.

**Next session likely starts with:** ratifying the pilot-vs-target stance, then designing the capability-flag
normalization layer against the current `attributes_json`.
