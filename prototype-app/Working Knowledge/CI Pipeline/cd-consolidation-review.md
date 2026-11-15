# Review and proposed CI/CD approach

Reviewed 15 November 2026 against local commit `c013bd795f599a02a5d0c81e8028186233f4bd82`, the uncommitted consolidation plan, the supplied discussion, current release tooling, and official GitHub/Vercel documentation. GitHub repository metadata was read to confirm visibility. No AWS deployment, configuration change, or production release was performed; live AWS alarms, running images, and browser results were not independently inspected.

**Recommendation: adopt one visible GitHub Actions release path, with corrections before unattended deployment.** Keep ECS, ECR, Vercel, Terraform, and `release.py`. Use reusable jobs/workflows behind one orchestrator rather than requiring every operation in one YAML file. Keep CI qualification, live deployment, and human acceptance as distinct recorded results.

The repository is currently public. Earlier advice based on a private-repository assumption does not apply to this repository's reviewer availability. Required environment reviewers are available for public repositories on GitHub Free. Standard hosted runner minutes are free for public repositories; larger runners, storage, concurrency, AWS infrastructure, and Vercel remain separate considerations. Visibility is an owner/business decision, not a CI cost optimization. Account IDs and ARNs are generally identifiers, but their presence does not establish that every published lab record or artifact is safe to disclose. Sources: [repository](https://github.com/AxC-SG/SG), [GitHub environment controls](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

## Changes needed before automatic releases

### 1. Preserve every release gate inside the orchestrator

The plan keeps Performance Governance separate, then replaces four-workflow qualification with `publish needs: required`. That dependency cannot wait for another workflow. The current aggregate gate also does not include security/image/performance jobs because those currently run elsewhere.

Call the main performance check as a reusable job/workflow inside the main dependency graph, and include image/security/performance results in the aggregate gate. Keep the nightly schedule as a separate trigger using the same implementation. If Semgrep is retired, make that a separate explicit coverage decision rather than a consequence of consolidation. The gate must fail for a missing, canceled, failed, or unexpectedly skipped required job.

Evidence: [plan performance scope](<cd-consolidation-plan.md>), [publication dependency](<cd-consolidation-plan.md>), [current gate](<../../../.github/workflows/quality.yml#L321>), [gate checker](<../../../.github/scripts/check-quality-gate.py#L8>).

### 2. Make automatic schema-neutral releases runtime-only

The current deploy path compares candidate migration heads to cached release inputs, then runs the migrator even for neutral releases. This conflicts with the plan's statement that automatic rollback never follows migration execution.

For automation, establish an unchanged schema contract against the deployed release and verified database state: migration catalog/fingerprint, compatible binary and effective configuration ranges, and applicable platform/tenant state. Comparing only maximum version numbers or the latest PR's diff is insufficient, especially after skipped commits. Unknown or changed contracts take the manual path.

A proven neutral release should retain the existing migrator and call the runtime-only path. Do not launch the owner-credential task. Give GitHub a narrower runtime-release role, not a copy of the full manual role: no migrator registration, migrator PassRole, migrator RunTask, or schema snapshot/recovery authority.

The proposed full role can register a new migrator, pass its execution role, and run code receiving database-owner credentials. Denying AWS database-deletion APIs does not prevent SQL changes or deletion of application data. Even the restricted runtime role retains the application's data permissions; amend the plan's claim about a compromised main being unable to affect data/identity.

Evidence: [cached comparison](<../../infrastructure/lab/scripts/release.py#L295>), [unconditional migrator argument](<../../infrastructure/lab/scripts/release.py#L311>), [migration execution](<../../infrastructure/lab/scripts/release.py#L366>), [proposed privileges](<cd-consolidation-plan.md>), [owner-secret injection](<../../infrastructure/terraform/standard/runtime-iam.tf#L43>).

### 3. Verify worker correctness and authenticated behavior

Existing worker alarms cover running task count and CPU. They would not reliably detect a process that stays running while tenant jobs fail. The current verifier also marks startup ERROR counts as passing information; its API probes check public CSRF and the expected unauthenticated 401, not signed-in application behavior.

Add a targeted critical worker/schema-error signal and at least one bounded successful worker operation or meaningful progress check. Use a bake window that covers the relevant scheduling cadence. Retain infrastructure alarms, but do not describe them as worker correctness checks. Verify alarm delivery and how failure enters the release recovery path; an SNS email alone does not trigger rollback.

Add a small authenticated smoke suite for the role-sensitive routes and tenant findings implicated in the incident. Authorization-code authentication does not inherently prevent browser automation. Prefer exercising the existing login flow with dedicated, bounded lab identities over adding a password-grant client solely for testing. Qualify actual MFA/session constraints. Authentication state, cookies and sensitive traces must not become public artifacts. If no suitable authenticated test is approved, keep lab deployment manually triggered until the owner accepts the documented detection gap.

Evidence: [worker alarms](<../../infrastructure/terraform/standard/operations.tf#L324>), [current verification](<../../infrastructure/lab/scripts/release.py#L458>), [incident](<../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md>), [Playwright authentication](https://playwright.dev/docs/auth).

Enabling `operations` also creates an audit KMS key, S3 archive and multi-region CloudTrail trail. It is not just enabling alarms. Introduce independently enabled lab release alarms/SNS, or review and budget the entire existing operations stack and its parked-lab behavior. [Operations configuration](<../../infrastructure/terraform/standard/operations.tf#L1>), [CloudTrail](<../../infrastructure/terraform/standard/operations.tf#L241>).

### 4. Return explicit outcomes and provide a catch-up action

Exit-zero skips conflate parked, awaiting acceptance, interrupted release, superseded candidate and unchanged backend. Only `backend_verified` or a specifically proven `already_live_compatible` result may authorize frontend promotion. Emit these as structured outputs, alongside `parked`, `awaiting_acceptance`, `schema_blocked`, `superseded`, and `needs_operator`.

Acceptance, lab startup, and a manual schema release do not themselves produce a new main-push event. Add one dispatch/reconcile action, invoked after these events, which selects the newest eligible qualified candidate. Coalesce blocked candidates instead of replaying every obsolete merge. An interrupted release must reconcile/resume its recorded operation before a newer candidate can replace it.

There is only one live release awaiting acceptance, so "batch acceptance" cannot mean accepting several independently deployed candidates. The owner accepts the current release pair; the reconciler then considers the newest eligible candidate. A passing CI run or a successful skip must not be presented as an accepted deployment.

Evidence: [ambiguous promotion condition](<cd-consolidation-plan.md>), [acceptance block](<../../infrastructure/lab/scripts/release.py#L281>), [acceptance handling](<../../infrastructure/lab/scripts/release.py#L421>).

### 5. Build, stage and promote one identifiable frontend artifact

The diagram promises promotion of an existing deployment, but the implementation rebuilds after backend rollout. `npm run build` produces Vite's `dist`; Vercel's `--prebuilt` expects `.vercel/output` generated by its build process. Also, `vercel deploy --prebuilt --prod` assigns production domains immediately unless staging is explicitly requested.

Build for the intended lab production configuration before changing the backend. Use a qualified Vercel build/prebuilt process, stage the production deployment with `--skip-domain`, and record its deployment ID, source SHA, configuration and artifact identity. After backend checks pass, promote that exact staged production deployment and run paired smoke checks. Do not promote an arbitrary latest deployment or a preview expecting unchanged bytes: preview promotion can rebuild with production settings.

The staged URL's inability to complete lab sign-in is a known origin restriction; it can still receive static checks, while signed-in paired checks run on the authorized canonical origin after promotion. Keep the old frontend available for recovery and record a failed frontend promotion separately so retry does not redeploy the backend or rerun migration.

Compatibility is bidirectional: backend N must support frontend N-1 for open tabs; frontend N must support the qualified rollback backend where rollback is intended. The plan's current open-tabs explanation tests the other direction.

Evidence: [proposed build/deploy](<cd-consolidation-plan.md>), [frontend build script](<../../frontend/package.json#L8>), [Vercel deploy semantics](https://vercel.com/docs/cli/deploy), [preview promotion behavior](https://vercel.com/docs/deployments/promote-preview-to-production).

### 6. Cover the complete release transaction and interruption recovery

The existing S3 lock ends when backend `deploy` returns. A separate frontend job would run outside that lock, allowing lab shutdown or operator acceptance between backend verification and frontend promotion. Coordinate the backend/frontend transaction and release-record completion with the same environment lock; browser acceptance applies to the completed pair. Do not hold an allocated runner while waiting hours for browser results.

Persist intent before mutations and the task ARN immediately after launching a task. On resume, inspect actual Terraform/ECS/task state rather than assuming an operation never ran. `cancel-in-progress: false` does not prevent manual cancellation, runner loss or timeout. Frontend failures, failed state writes, partial applies and stale-lock recovery need explicit outcomes. A failed restoration becomes `needs_operator`; decide whether a verified restoration of the exact accepted pair can automatically return to accepted or intentionally requires recovery approval.

Evidence: [lock lifetime](<../../infrastructure/lab/scripts/release.py#L189>), [effects recorded after execution](<../../infrastructure/lab/scripts/release.py#L366>), [GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).

The planned rollback target `abd8c038…` has the documented worker/schema configuration defect. A mechanical rollback exercise to it is not proof of recovery to healthy service. Qualify healthy compatible baseline and candidate releases, then force a failure and prove recovery of both API and worker. [Recorded defect and proposed drill](<../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md>).

## Proposed streamlined flow

```text
PR: selected checks in parallel → stable required Quality gate

main: independent source checks and release builds in parallel
      image branch: exact-image checks → performance as soon as ready
      all required branches → complete Quality gate
      → publish immutable backend / stage configured frontend
      → reconcile candidate eligibility under the environment lock
           parked / awaiting acceptance / changed schema → record deferred reason
           proven neutral → runtime-only API + worker rollout
      → authenticated API + worker checks and bounded bake
      → promote exact staged frontend → paired smoke checks
      → persist deployed pair / awaiting browser acceptance
      → accept or recover → reconcile newest eligible deferred candidate
```

Use one orchestrator with reusable CI, publication and release jobs. Keep privileged reusable workflow identities narrow; requalify actual OIDC claims and denied branch/workflow cases when moving jobs. The existing publication record documents a real custom-subject probe and successful publication, so a claim-name assumption should not override that observed evidence. Public PR checks remain read-only and secret-free; only reviewed main release jobs receive cloud credentials or the Vercel token. [Existing OIDC evidence](<../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md>).

## Efficiency changes worth making

- Parallelize independent static, frontend, backend/Postgres and security work. Optimize measured critical-path time, not just YAML count or summed job-minutes.
- Cancel superseded PR validation. Keep deployment transactions non-canceling and select the latest eligible candidate after acquiring the lock.
- Reuse the qualified backend image and configured frontend output in downstream jobs. Do not rebuild on deployment; add actual startup/runtime checks of the image that will run.
- Cache Maven, npm and BuildKit dependencies with lockfile/toolchain-aware keys. Avoid large intermediate archives unless measured reuse saves more than upload/download overhead.
- Separate test selection from deployment relevance. Documentation-only changes can validate without rolling ECS; a true frontend-only release can retain the compatible accepted backend. Never report a new backend artifact as tested when reusing a previous one.
- Retain one stable branch-protection gate and one release summary linking immutable S3 evidence, backend/frontend identities, failure/recovery outcomes, and timings. Keep signed-in data and secret-bearing logs out of public artifacts.
- Keep nightly performance/visual sweeps and native scanning schedules where useful, sharing implementations. They need not be competing deployment paths.

## Revised delivery sequence

| Step | Scope | Exit criterion |
|---|---|---|
| 0 | Qualify a healthy fixed baseline and recovery target | Authenticated API and worker checks pass; recovery drill restores healthy behavior |
| 1 | Consolidate CI, publication and release artifacts without enabling auto-deploy | Same-SHA image/security/performance checks gate publication; required check migration is verified |
| 2 | Add targeted lab alarms, worker semantics, authenticated smoke, and runtime-only release path/role | Injected worker/API failure is detected; neutral mode cannot run the migrator; cost/scope reviewed |
| 3 | Run coordinated backend/frontend deployment manually through Actions | Exact staged frontend and backend pair verified; blocked, interrupted and frontend-only retries recover correctly |
| 4 | Enable automatic neutral lab releases | Forced failure recovers a qualified pair; acceptance/startup reconciliation catches up; pending states are honest |
| 5 | Separate production delivery plan | Accepted backend digest promoted unchanged; production-configured frontend qualified separately when baked origins differ; reviewers and recovery approved |

This puts frontend coordination and meaningful smoke checks before unattended rollout, rather than temporarily automating the existing skew.

## Recommended owner decisions

| Decision | Recommendation |
|---|---|
| D1: visibility | Confirm deliberately; do not change it as part of CI consolidation. Review public release evidence and artifact content separately. |
| D2: automatic neutral release | Conditional yes, after steps 0–3 and failure/recovery evidence. Until then, use the same workflow with a manual release trigger. |
| D3: signed-in testing | Approve a design for tests through the existing browser flow; do not default to enabling a new password-grant client. Keep remaining human acceptance explicit. |
| D4: frontend promotion | Yes; stage the production-configured artifact and promote its exact ID only after backend verification. |

Before enabling production reviewers, identify the reviewer and self-review policy; feature availability alone does not establish independent approval. Do not infer production authorization from a manual dispatch button.

Minimum meaningful failure tests before auto-deploy: missing security/performance result; schema mismatch; failed authenticated API check; running-but-failing worker; parked lab; acceptance outstanding then cleared; superseded candidate; frontend failure/retry; partial Terraform apply or runner cancellation; successful and failed restoration of the accepted pair. These test the release contract rather than merely mirroring happy-path job ordering.
