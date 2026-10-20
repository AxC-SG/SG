# AI findings creation workflow review

Reviewed October 12, 2026. Five defects were identified; six targeted PostgreSQL regression assertions reproduced them. Existing focused tests pass. Production code was not changed.

## Scope and flow

Traced connector observation ingestion → chunk/scope completion → immutable snapshots and produced facts → policy distribution/selection/scope/capability/evidence gates → assessment persistence → canonical finding upsert and subject links → finding API → AI findings list/detail UI. Also traced current-coverage exposure correlation, validation, deduplication, suppression, evidence expiry, verified closure and recurrence, and policy configuration replay/Execute now.

Posture findings require ENABLED/REQUIRED selection and a deterministic FAIL. Incomplete scopes, missing/stale/unsupported facts and unavailable capabilities intentionally produce coverage gaps rather than new findings. Exposure hypotheses intentionally do not graduate until validating evidence is present. Runtime assessment is explicitly outside the current release in AiGridPipelineService; its lack of findings is not counted as a regression.

## Findings

### 1. P1 — Policy selection changes leave findings out of sync

Location: `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridApiService.java:400` (updateSelection); current projection helper at line 662.

The selection endpoint writes the selection/history and refreshes coverage/readiness, but neither evaluates stored evidence nor reconciles findings. Reproductions:

- A PREVIEW policy has a persisted FAIL and no finding. Change to ENABLED: the API succeeds, but open finding count remains **0**, expected **1**.
- An enabled policy has an OPEN finding. Change to DISABLED: finding remains **OPEN**, expected **AUTO_CLOSED** with a governance reason.

This persists until a subsequent assessment reaches the affected artifact. Recommended fix: reconcile selection transitions against current authoritative artifact evidence; withdraw owner-facing findings immediately on downgrade, and evaluate current evidence on enable. Invalidate affected findings queries in the UI after reconciliation.

### 2. P1 — Reassessment only visits the newest run, skipping other current scopes

Location: `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridReevaluationService.java:25`; related Execute now path in `AiGridApiService.java:235`.

Policy configuration edits choose exactly one latest snapshot run, disregarding the policy/artifact being edited. The assessment loop loads only that run's manifests and facts. Current coverage can contain authoritative artifacts from several independent scope heads.

Reproduction: run A discovers a failing agent; exclude the agent and confirm its finding becomes AUTO_CLOSED. Run B discovers an unrelated guardrail in another region. Remove the agent exception: the API succeeds, but its still-failing finding remains **AUTO_CLOSED**, expected **OPEN**.

The same run selection exists in Execute now. It reports the number of selected loaded policies even when the newest run contains no matching artifact, so successful execution can miss findings for older current scopes. This Execute now consequence was traced statically; the policy-exception path was reproduced with PostgreSQL.

Recommended fix: assess the union of authoritative scope heads relevant to the selected policy, using each artifact's bound snapshot/facts and required evidence scopes. Report actual assessed subjects separately from loaded policy count.

### 3. P2 — Restored exposure evidence never resumes the paused SLA

Location: `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridExposureFindingService.java:71`; demotion at line 96.

Evidence expiry leaves the finding OPEN with workflow class NEEDS_EVIDENCE and clears due_at. Revalidation changes the class to VALIDATED_EXPOSURE, but due_at is assigned only for new findings or a status transition from a non-OPEN state.

Reproduction: validated exposure → expired evidence/hypothesis → fresh validating evidence, without an intervening closure. The finding returns to VALIDATED_EXPOSURE but **due_at remains NULL**. Expected a resumed SLA deadline. Existing lifecycle coverage goes through closure before recurrence, which masks this path.

Recommended fix: explicitly handle NEEDS_EVIDENCE → VALIDATED_EXPOSURE and restore the deadline according to the SLA pause/resume policy.

### 4. P2 — Exposure reassessment overrides active suppression

Location: `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridExposureFindingService.java:71`.

Any existing status other than OPEN triggers reopenByObservation, including SUPPRESSED with a future suppressed_until. The posture finding service already guards active suppression; the exposure service does not.

Reproduction: create a validated exposure, suppress its finding for one day, then observe the same validated exposure again. Status becomes **OPEN**, expected **SUPPRESSED**. Routine reassessment defeats the user's workflow decision.

Recommended fix: preserve active timed/indefinite suppression while refreshing observation and evidence; reopen only after expiry or an applicable explicit transition.

### 5. P2 — Merged exposure findings return duplicate list rows and incorrect context

Locations: `prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/service/AiGridExposureFindingService.java:89` and `AiSecurityApiService.java:892`.

Exposure upsert merges paths sharing correlation/root cause into one finding, but adds a PRIMARY EXPOSURE_PATH subject for each path. The list and total-count queries join every PRIMARY subject, producing one row per path instead of one row per finding.

Reproduction: reconcile two exposure inputs sharing correlation and root cause. Database contains **1 AI_EXPOSURE finding**; the findings API returns **2 rows** for that finding. This also distorts pagination/counts and supplies duplicate React keys.

Additionally, those PRIMARY subjects are EXPOSURE_PATH rather than ARTIFACT/EXECUTION. The current list mapper cannot derive artifact_id/provider/subscription from them and uses the 'Runtime execution …' fallback for exposure paths. Consequently provider/subscription/native-kind filters can exclude valid exposure findings. This context/filter consequence was traced statically.

Recommended fix: paginate/count distinct finding identities and resolve exposure context through explicit exposure/entry-point/root-cause associations; return exposure-aware subject labels and routes.

## Validation and evidence

Existing tests passed:

- Backend unit tests: 22 assertions/tests across finding, assessment, snapshot, fact production, graph evidence and policy default services.
- PostgreSQL integration tests: 11 tests across policy configuration and R2 exposure lifecycle, using an isolated temporary PostgreSQL 16 database.
- Frontend tests: 21 tests across AI findings, finding detail and policy pages.

Six added regression tests failed with assertion mismatches (zero execution errors), confirming the five defects above. Temporary regression modifications were removed from the source test files. The adjacent `AI_FINDINGS_REGRESSION_REPRODUCTIONS.patch` preserves the test additions for inspection/application. It contains no production changes.

Reproduction test names:

- reviewEnablingPolicyWithStoredFailureShouldCreateFinding
- reviewDisablingPolicyShouldWithdrawExistingFinding
- reviewReincludeOlderScopeAfterUnrelatedRunShouldReopenFinding
- reviewRevalidationWithoutClosureShouldResumeSla
- reviewActiveExposureSuppressionShouldSurviveReassessment
- reviewMergedExposureShouldAppearOnceWithArtifactContext

To run after applying the patch against a dedicated local test database:

```sh
mvn -o -Ppostgres-it -Djacoco.skip=true \
  -Dpostgres.test.admin-url=jdbc:postgresql://127.0.0.1:PORT/postgres \
  '-Dit.test=AiSecurityPolicyConfigurationPostgresIntegrationTest#review*,AiGridR2ExposurePostgresIntegrationTest#review*' \
  test-compile failsafe:integration-test failsafe:verify
```

The integration harness creates/replaces its dedicated `vulnwatch_it_*` databases. Review used an isolated temporary cluster rather than application data. No live AWS/Azure/Copilot accounts were exercised, and frontend verification used component tests rather than a live browser session. Passing baseline tests do not establish that these edge cases work.
