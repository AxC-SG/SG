# Single-pipeline CD plan: lab first

**Status:** revised 2026-11-15 to incorporate the [review](cd-consolidation-review.md) and agreed follow-up. Revised again the same day after the `c013bd7` browser checks, with priorities re-ordered for one owner and a lab:
1. fix the observed failures;
2. improve detection;
3. automate only when release frequency justifies it.

Implementation and live enablement remain future work; updating this plan does not enable deployments or grant AWS access.
**Scope:** the Sydney lab (account `736486260824`). Production gets a separate continuous-delivery plan with an approval gate.
**Builds on:** [CI simplification plan](ci-simplification-plan.md) (PR D), [lab release tooling](../../infrastructure/lab/README.md#releases), and [the first-release record](../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md).

## 1. Goal

Use **one visible GitHub Actions pipeline** to qualify release artifacts, publish the backend, coordinate backend/frontend rollout, and report the result. Keep ECS, ECR, Vercel, Terraform and `release.py`; reusable workflows behind the orchestrator are encouraged.

Keep three results distinct: **CI qualified**, **deployed and verified**, and **accepted**. The stable PR `Quality gate` is a merge check, not proof that a release is live or accepted. One summary links the authoritative release record and any deferred or recovery action.

**Non-goals:**

- Moving hosting, adding AWS CodePipeline/CodeDeploy, or replacing `release.py`.
- Automatic schema-changing releases or production deployment.
- A release scheduler, multiple SSM pointers, or a new release database. Extend the existing S3 inputs, history and shared lock.
- Changing repository visibility or weakening authentication as part of CI consolidation.

## 2. Baseline and corrections

The baseline below describes the repository and release record reviewed on 2026-11-15; it is not a fresh certification of running AWS/Vercel resources.

| Piece | Baseline |
|---|---|
| CI | Quality, Semgrep, Trivy and Performance Governance run as separate workflows. |
| Frontend | Vercel publishes `main` independently; branch previews cannot complete lab sign-in under the current origin policy. |
| Backend publication | The publisher waits for all four successful checks on the same main SHA, then uploads the retained image to immutable lab ECR. |
| Deployment | An operator runs `release.py`; Terraform owns task definitions and ECS service revisions. |
| Release history | The recorded first release upgraded V15/V20 to V16/V23 and exposed tooling/permission gaps and the worker schema-configuration defect (rejected, superseded). The second, `20261115t063842z-c013bd7`, fixed the worker defect but **failed its browser checks** (next row). It remains unaccepted, so no healthy accepted release exists yet. |
| Browser checks, `c013bd7` | Every platform-scope **write** (demo-request delete, approval and others) returns `[INTERNAL_ERROR]`. The API logs `new row violates row-level security policy for table "audit_events"` for a managed-session platform owner with no workspace (requestIds `5d0576cf-…`, `24fbc171-…`, `348e207a-…`, `396a669a-…`). No invitation or approval emails arrived. That may be a consequence of the failed writes, or a separate problem; not yet traced. Page loads did not show the failure. |
| Readiness | `TenantSchemaReadinessHealthIndicator` returns UP even when `unreadyTenantCount` is non-zero, by design. A tenant's migration state controls only that tenant's eligibility. So a healthy target does not prove every tenant schema is ready. |
| Restricted-role tests | `RestrictedRuntimeJourneysPostgresIntegrationTest` runs as the non-bypass runtime role and already deletes a platform demo request, but with a locally issued token. The failing lab path is a managed (Cognito) session with no workspace, under the `prod` profile settings. |
| Dependabot | Maven and Terraform updates are grouped; npm, Docker and Actions are not. Dependabot is about a third of PR updates. |
| Health coverage | Local `operations` is unset. Existing defined worker alarms cover task count/CPU, not successful job execution. Current startup ERROR counts are informational. |
| Authentication | Signed-in acceptance is manual. Authorization-code login is compatible with browser automation; a password-grant client is not required merely to test it. |

**Visibility correction:** GitHub reports this repository as public. Required environment reviewers are available on GitHub Free for public repositories. Standard hosted runner minutes are free there; larger runners, storage, concurrency and hosting have separate limits/costs. Earlier private-repository assumptions do not apply. D1 remains an explicit business decision, with visibility unchanged by this plan. IDs/ARNs are generally identifiers, but do not establish that every public record/artifact is safe to disclose. [Environment controls](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

The earlier estimate of roughly 43 job-minutes per main push is a measurement baseline to recheck, not a latency target. Measure elapsed critical-path time separately.

## 3. Target pipeline

```text
PR → changes → selected independent checks in parallel → required Quality gate
     Vercel preview builds remain separate and unprivileged

main → independent source checks and release builds in parallel
       image branch: exact-image checks → main performance as soon as ready
       all expected results → complete Quality gate
         → publish immutable backend + stage configured frontend
         → reconcile eligibility under the shared environment lock
              parked / acceptance outstanding / schema changed or unverified / migrator drift → blocked(reason)
              proven neutral → runtime-only API + worker rollout
         → authenticated API + worker verification and bounded bake
         → promote exact staged frontend → paired smoke checks
         → persist verified pair / awaiting browser acceptance → release lock

owner → accept the current pair, or recover/fix it
      → manual dispatch: reconcile / release newest eligible
```

A failed runtime, worker or paired check enters the qualified recovery path. A publication/staging failure before live changes simply fails qualification; it is not an application rollback.

## 4. Design

### 4.1 One orchestrator and a complete gate

PR D makes `quality.yml` the visible PR/main orchestrator, with reusable CI/publish/release workflows where useful. Update the CI simplification implementation to include:

- Independent static, secret, frontend, backend/Postgres and image/security jobs in parallel.
- Main Performance Governance inside the same dependency graph, invoked through a reusable implementation. Run it as soon as its candidate/environment prerequisites are ready. The nightly schedule may reuse that implementation.
- A `Quality gate` covering every expected result, including security/image and main performance. Missing, failed, canceled or unexpectedly skipped results fail it; PR-only and selection-based skips must be explicit and tested.
- Separate selection of checks and deployment relevance. Documentation-only changes do not roll ECS. Frontend-only changes can retain a specifically qualified compatible backend.

Remove the redundant main `workflow_run` publication chain only after this graph preserves its same-SHA guarantees. Retain Semgrep unless a separate, explicit CI coverage decision retires it. Migrate branch-protection check names in two verified steps; do not introduce a window with no enforced gate. Nightly visual/performance and native scanner schedules need not become competing deployment paths.

### 4.2 Release artifacts and publication

Build and inspect the backend candidate, scan it, and exercise startup/runtime compatibility of that exact image. Performance should consume that candidate where feasible rather than independently rebuilding the application. Source tests remain useful but are not proof that the ECS image boots.

Publish only qualified main artifacts. Preserve archive checksum, loaded image/configuration identity, source SHA, candidate run, platform, RDS CA and migration-catalog evidence. Record the ECR digest and deploy the same artifact without rebuilding. Publication may continue while the lab is parked or awaiting acceptance; it never implies deployment.

Build the frontend once for the intended lab configuration before live backend changes. Reuse its qualified release output downstream. A reused unchanged artifact retains its original identity; do not imply a new backend image was built/tested for a documentation-only or frontend-only commit.

Keep publication and runtime release identities separate. Prefer narrow reusable privileged workflows rather than trusting every job in a broad CI file. Verify actual OIDC subject/audience, repository identity, environment and workflow/ref through a limited claim probe and denied-case tests before changing trust. The recorded custom-subject probe and successful publication remain the starting evidence; do not derive a new trusted subject by file-name substitution alone.

### 4.3 Proven neutral releases and a restricted automatic role

Automatic eligibility is checked against the actual deployed/accepted release and verified database state, across all skipped commits. Require:

- **The same migration-catalog fingerprint.**
  - The build adds a SHA-256 over the packaged platform and tenant migration files (names and bytes) to the publication manifest, next to `migration_heads`.
  - The release inputs store the deployed release's fingerprint.
  - Equal heads with a different fingerprint is not neutral.
- **Verified live schema state** from a bounded, read-only control-plane check. The fingerprint describes packaged files, not the database, so it cannot replace this check. Readiness is not enough, because it stays UP while `unreadyTenantCount` > 0.
  - Before rollout, and on the candidate after it, require zero unready tenants and a supported tenant range containing the database head.
  - Read this through the application, for example the platform-owner `GET /api/platform/tenant-schema-status` with the signed-in smoke identity (§4.6), or the readiness details from inside the VPC.
  - Never use direct database or owner credentials.
- **The same effective configuration ranges.** The schema bounds the candidate will run with must equal the binary's own. That is the 2026-11-15 V23..V20 failure.
- **No migrator configuration drift.** The runtime-targeted plan does not cover the migrator. Run a second, read-only plan that renders the migrator with its **retained** digest, the one in the release inputs. Any migrator task-definition change then means its configuration changed, not merely that a new runtime image exists. That returns `blocked` for manual review: drift is not necessarily a schema change, but a lab cycle would refuse it.
- **No other infrastructure changes.** The runtime plan's allowlist already refuses anything outside the api/worker task definitions and services. Rely on it; no separate review step.
- **A qualified previous accepted recovery pair** (§4.7), and compatible queued-work behavior.

Unknown, divergent or changed evidence returns `blocked` (reason `schema_changed`, `schema_unverified`, `migrator_drift`) or `needs_operator`, and leaves live services unchanged.

The automatic path **never replaces or runs the migrator**. Retain its current digest and use the runtime-only path. Owner-run schema changes keep the existing stop/snapshot/migrate/runtime procedure and explicit recovery planning.

The proposed `scoutgrid-lab-github-release` role is narrower than `ScoutGridSydneyLabRelease`: register the API/worker definitions, pass only their approved execution/application roles, update those two services, and use the necessary scoped state/release/lock paths and metadata reads. Exclude migrator registration/retirement, migrator PassRole/RunTask, DB-owner secret access, snapshots/restores and unrelated foundation/IAM changes. Preserve Terraform ownership and plan allowlists.

Runner support must use short-lived OIDC credentials, the existing account/region guards and checksum-verified Terraform 1.13.5 with `-lockfile=readonly`. Local operator profiles remain the fallback. Proposed non-interactive mode removes the prompt only after all eligibility checks; it does not bypass them, initialize state, unlock stale operations or authorize schema changes.

### 4.4 Explicit outcomes and one manual reconcile action

Return a machine-readable result, and never treat exit zero alone as authority to promote. Version 1 has **four top-level outcomes**. Every result also records its **phase**, **reason**, candidate and release ID, the **actual** live backend and frontend identities, and the acceptance state. Nothing needed for recovery is lost by keeping the outcome list short.

| Outcome | Meaning | Reasons / next action |
|---|---|---|
| `verified` | This transaction verified the backend, or proved the live backend compatible for a frontend-only change. The recorded staged frontend may be promoted | Next: paired checks, then browser acceptance |
| `blocked` | Nothing live changed | `parked`, `awaiting_acceptance`, `superseded`, `schema_changed`, `schema_unverified`, `migrator_drift`. Next: start the lab, accept, run a manual schema release or review, then reconcile |
| `failed` | A live step or check failed | Phase plus `recovered` (the exact accepted pair was restored and verified; the attempt stays failed in history) or `frontend_pending` (backend fine, frontend step to retry without redeploying the backend) |
| `needs_operator` | State, compatibility or recovery is uncertain | The recorded action required; never auto-resolved |

Start with **one `workflow_dispatch` action: reconcile / release newest eligible**. No scheduler is required. The operator invokes it after lab startup, acceptance, manual schema deployment or interruption. Optional automatic dispatch hooks are later convenience work, not a prerequisite.

An interrupted operation is reconciled/resumed at its recorded SHA before selecting a replacement. Otherwise select the current main head only when its exact artifacts and checks qualify; if its checks are incomplete, wait. Coalesce deferred candidates instead of replaying every obsolete merge. Recheck eligibility after acquiring the lock and before the first mutation. Once a transaction starts, pin that pair through completion/recovery; newer merges do not cancel it.

### 4.5 One transaction, durable intent and staged frontend

**Initially local.** Until release frequency justifies Actions-run releases (phase 4), a paired release may be `release.py` locally plus a staged Vercel promotion. Two conditions: the promotion runs under the same shared lock, and both halves are written to the same paired release record. A `release.py` step that stages and promotes the recorded Vercel deployment keeps this a single transaction. The rules below apply to either runner.

Build/publish/stage outside the live release lock. Then hold the shared S3 environment lock across eligibility recheck, backend rollout, verification/bake, frontend promotion, paired checks and release-record finalization. GitHub release concurrency uses `cancel-in-progress: false`; local cycle/release commands must honor the same lock. Do not hold a runner or the lock while waiting hours for manual browser acceptance.

Persist intent before each mutation and task/deployment identifiers immediately after launch, before waiting. On retry inspect actual Terraform, ECS, task and Vercel state. Cancellation, timeout or runner loss does not prove a child operation stopped. Never blindly launch another migrator or clear a stale lock; those recovery actions remain owner-run. Allowlisted plans and protected Terraform state remain required.

The frontend sequence is:

1. Pull approved project/production configuration, run a pinned `vercel build --prod` process, including the existing bundle verification, and retain the valid `.vercel/output` identity. `npm run build` alone produces Vite `dist`, not the Vercel prebuilt contract.
2. Stage with `vercel deploy --prebuilt --prod --skip-domain`; record deployment ID, SHA, API origin/configuration and artifact identity. Await READY and perform applicable static checks.
3. After a `verified` outcome (backend verified, or live backend proven compatible for a frontend-only change), promote that exact staged production deployment ID. Never promote an arbitrary latest deployment or infer permission from a successful skip.
4. Run paired checks on the canonical lab origin, then record the completed pair for browser acceptance. Staged URLs do not acquire broader sign-in/CORS authority just for testing.

Disable Vercel's independent main-to-live path only when the replacement manual pipeline is verified. Keep unprivileged PR previews. Configure the chosen Git deployment/domain-assignment setting deliberately and verify it with a harmless main change; the required behavior is no independent main promotion, not a particular untested JSON setting.

Backend N must support frontend N-1 for open tabs. Frontend N must also support the qualified rollback backend where recovery requires it. Verify these directions on representative contracts rather than relying solely on review.

If frontend promotion has not happened and the old frontend still serves compatibly, record `failed` with reason `frontend_pending` and retry that step without rerunning backend/migration. If promotion outcome is uncertain, inspect the actual deployment/domain first. A failed paired check after promotion enters recovery. [Vercel deploy semantics](https://vercel.com/docs/cli/deploy).

### 4.6 Health checks, signed-in smoke and isolated release alarms

Retain ECS circuit breaker/rollback, existing 100/200 rolling settings and 300-second grace.

**Pre-merge first: restricted-role tests that reproduce the real failure.** Both 2026-11-15 defects (V23..V20, `audit_events` RLS) appear only under the restricted runtime role and deployed configuration. CI is the cheapest place to stop them.

Extend `RestrictedRuntimeJourneysPostgresIntegrationTest` rather than relying on its name. Its existing demo-delete journey uses a locally issued token. The new cases must match the failing actor context: a managed (Cognito) platform-owner session with no workspace, under the `prod` profile's tenancy settings (`enforce-schema-version: true`, configured bounds). For each platform-scope write, assert:
- the mutation itself;
- the committed `audit_events` row;
- the email delivery intent or outbox row;

not just HTTP success. Start with demo-request delete and approval.

**Post-deploy, application-level qualification:**

- **Signed-in writes, not just page loads.** The `c013bd7` pages loaded while every write failed. Cover, at minimum:
  - one platform-scope write (demo-request delete or approval);
  - one tenant write;
  - one email-producing action, traced to provider acceptance.

  These need **seeded, disposable fixtures** created through the platform API or a fixture script. The public demo-request form is behind Turnstile, so tests cannot create their own data through it. Fixtures are removed or recycled after each run.
- **Signed-in reads** of the routes #101 fixed, and Findings in a workspace.
- **Worker correctness** needs new application work: the worker emits no progress signal today. Add one, for example one structured success line per scheduled job, turned into a CloudWatch metric by a log metric filter, or a custom metric. Pair it with targeted fatal-error detection: the `TenantWorkRunner` failure and the "outside this release's supported range" message.
- **A bounded bake window** of at least one full five-minute scheduler cycle plus jitter. Missing or stale required evidence cannot count as passing.

Gate on defined failures and failed progress, not every generic `ERROR` line. Record expected/benign errors explicitly. Public CSRF/401 probes, running task counts and CPU remain useful infrastructure checks but cannot certify signed-in or worker correctness.

**Email delivery is traced stage by stage before it is called a configuration bug:**
1. the action commits its delivery intent (it may not, if the RLS failure rolls the transaction back);
2. the intent is queued;
3. the worker processes it;
4. Resend accepts it (the provider response, and Resend's log);
5. the email is received.

A smoke check asserts the earliest stage it can observe without reading a mailbox.

Use Playwright through the existing Cognito authorization-code browser flow. Qualify the actual lab MFA/session behavior; do not add a password-grant client or change production MFA for this purpose. Keep test passwords in the designated environment secret and expose them only to trusted release jobs. Cookies, authentication state, tokens and sensitive traces must not enter public artifacts. The repository is public, so a CI contract test asserts that no release job uploads Playwright traces, screenshots, videos or storage state. If a suitable signed-in test cannot be approved, keep deployment manual and record the detection gap. [Playwright authentication](https://playwright.dev/docs/auth).

Enable **lab release alarms independently** of `operations`: API unavailable/5xx, critical worker/schema failures and absent/stale worker progress, with a scoped SNS destination. Choose thresholds/evaluation periods from measured behavior; validate the five-minute incident cadence and parked/maintenance behavior. Test signal generation, delivery and its consumption by the release verifier/recovery path. An email alarm alone does not trigger rollback.

Do not enable the entire existing `operations` object just to obtain alarms: it also creates audit KMS/S3/CloudTrail resources. That audit stack has a separate scope/cost decision.

### 4.7 Qualified recovery and a healthy baseline

Automatic recovery is allowed only for a proven neutral transaction with an unchanged compatible schema/data contract and a previously accepted healthy backend/frontend pair. Record the backend digest/task/configuration identity and frontend deployment ID needed to restore that pair. ECS rollback does not restore database data or undo application side effects.

On runtime, worker or paired-check failure, restore the accepted pair and rerun the required API/worker/paired checks. A verified restoration can reuse the prior acceptance and is recorded as `failed` with reason `recovered`; keep the attempted release failed and notify the owner. If restoration fails, side effects invalidate qualification, or compatibility/state is uncertain, use `needs_operator`. No automatic database restore, cross-schema rollback, stale-lock unlock or improvised downgrade is allowed.

**`c013bd7` is not a healthy baseline.** It fixed the worker defect, but failed its browser checks: every platform-scope write fails on `audit_events` RLS, and no emails arrive. It stays unaccepted, and it cannot be a recovery target. The first healthy baseline is the release that fixes those failures and then passes signed-in checks, worker progress and the observation window. A subsequent compatible, healthy release provides the second drill participant; a merge alone is not proof. Do not use `abd8c038…`, with its documented worker defect, as last-known-good recovery evidence. A mechanical switch to a defective image is a different test.

First prove both releases healthy, force a meaningful failed check, restore the accepted pair, verify API and worker recovery, and move forward again. Phase 0 may use supervised browser/worker evidence while automated checks are being built. No artificial commit is required solely to obtain a second version.

### 4.8 Acceptance and visibility

One completed live backend/frontend pair may await browser acceptance. `release.py accept` records the answers for that exact pair under the shared lock. It cannot accept an incomplete frontend stage or several hypothetical releases in a batch. Rejection records the failed behavior and uses the qualified recovery/fix-forward path; manual schema releases may require operator recovery.

After acceptance/startup/manual schema work, use the same manual reconcile dispatch to catch up. Newer builds/publications can continue while rollout is blocked. Never label a blocked or awaiting-acceptance release accepted because the Actions run is green.

Extend the existing S3 release record with source/artifact identities, migration fingerprint/compatibility evidence, intended and observed phases, frontend deployment/configuration, checks/bake results, browser answers, previous accepted pair, and recovery outcome. Keep immutable history with the existing controlled current inputs; no four-parameter SSM model is required.

The Actions summary links that record and shows actual outcome/reason, from/to identities, timings, failures and the next manual action. `release.py status` reports live/accepted/pending separately. Use workflow failure notifications plus tested alarm delivery; do not assume default email reaches the owner without qualification.

### 4.9 Measure efficiency before optimizing

Measure critical-path duration, per-job and queue times, job-minutes, retry/failure rate and release/recovery duration over a representative sample. Then prioritize:

- Parallel independent checks; start performance once its own prerequisites are ready.
- Reuse qualified image/frontend artifacts downstream instead of rebuilding on release.
- Maven/npm/BuildKit dependency caches keyed by relevant lockfiles/toolchains; compare artifact-transfer overhead with any saved compilation time.
- Cancel superseded PR validation, while keeping started release transactions non-canceling.
- Dependabot is about a third of PR updates, and only Maven and Terraform are grouped today. Evaluate grouping for npm and GitHub Actions (and Docker if useful), then measure its effect on PR runs against caching. Don't assume either wins.
- Skip live deployment for non-runtime changes, retaining complete qualification evidence and honest artifact identities.

File count is not a performance metric. Keep nightly sweeps where useful and share their implementations.

### 4.10 Production is a separate plan

Production remains disabled for the GitHub publisher/release roles until its own reviewed enablement. Promote the accepted backend artifact unchanged and verify its destination registry identity. Qualify a production-configured frontend separately when the baked API origin differs from lab; do not serve lab-targeting frontend bytes to production.

Configure and test production required reviewers, branch restrictions, reviewer identity and self-review policy before enabling its roles. Feature availability is not independent approval by itself, and a dispatch button is not an approval gate. Production authentication, alarms, recovery, severity/exception policy and data handling belong to that separate plan. Do not assume a generic paid GitHub tier restores private-repository reviewer features; verify the selected plan if D1 changes visibility.

## 5. Security model

| Identity | Scope |
|---|---|
| Lab ECR publisher | Qualified artifact upload to immutable lab ECR; no ECS deployment. Preserve narrow workflow/repository/ref/audience trust. |
| Automatic lab runtime releaser (new) | API/worker rollout and required scoped state/record/lock access only; no privileged migrator or schema-recovery authority. |
| Owner's existing release identity | Explicit manual schema-changing and recovery procedures, with reviewed plans and recorded evidence. |
| Lab Vercel token | Approved project/environment deployment and promotion; configured directly in the protected secret store and scoped to authenticating steps. Verify available token scope rather than assuming project-only permissions. |

PR jobs stay read-only and secret-free. Cloud credentials and Vercel secrets are limited to qualified main/manual-main release jobs; never execute fork/PR artifacts with those permissions. Verify main ruleset enforcement and OIDC denied cases before enablement.

A compromised trusted main/runtime releaser can affect application data through deployed code. Restricting AWS resource deletion does not establish application-data safety. Preserve role separation, limited secrets and independent production authority rather than claiming otherwise.

## 6. Phases and exit criteria

Ordered by value for one owner and a lab:
1. fix what failed;
2. catch it before you do;
3. consolidate CI;
4. prove recovery;
5. automate only when release frequency justifies it.

Detection (phase 1) pays off even if releases stay manual. Every 2026-11-15 defect was found by a person.

| # | Scope | Done when (measurable) |
|---|---|---|
| 0 | **Not pursued (owner, 2026-11-16; see the phase 0 decision below).** **Fix the observed failures; first healthy baseline.** `audit_events` RLS on platform-scope writes, then email delivery (traced, §4.6), each with restricted-role regression tests. Release the fix; record `c013bd7` as rejected | The new restricted-role tests fail before the fix and pass after. Released to the lab: all nine browser checks pass and are recorded with `release.py accept`. Zero `row-level security` and zero "outside this release" lines across two scheduler cycles. An invitation reaches a test inbox |
| 1 | **Detection.** Restricted-role tests for each platform-scope write (§4.6); worker progress signal (application change); lab release alarms independent of `operations`; signed-in Playwright smoke with seeded fixtures; startup ERROR gating on defined failures; live schema-state check (§4.3) | A deliberately broken platform write fails CI. A forced worker schema failure raises an alarm to the owner within 10 minutes. The smoke suite fails on a forced 500 from one write route, and passes on the healthy release. No traces or auth state in public artifacts (contract test) |
| 2 | **PR D:** consolidate CI, artifacts and publication; no automatic rollout. Measure critical path before and after; evaluate npm/Actions Dependabot grouping | One `Quality gate` covers image, security and main performance for the same SHA. A missing or failed required result blocks a test PR. Publication comes from the consolidated run. Critical-path time recorded before and after |
| 3 | **Recovery drill** between two healthy compatible releases (the phase 0 baseline and the next healthy release) | Force a failed check, restore the accepted pair, and pass API and worker checks within 15 minutes. Move forward again. Both recorded |
| 4 | **Coordinated paired releases**, still owner-run: `release.py` plus staged Vercel promotion under one lock and record; manual reconcile action; the runtime-only path and role; independent Vercel `main` promotion disabled once the replacement is proven | A backend and frontend pair ships as one recorded transaction. Parked, acceptance-outstanding and frontend-only retries behave as §7. Neutral mode cannot launch the migrator (simulated and tested) |
| 5 | **Automatic schema-neutral lab rollout**, only when release frequency justifies it and the owner enables it | Phases 0–4 are complete. A forced failure recovers the healthy pair automatically. Schema-changing, unverified or migrator-drift candidates stay `blocked` |
| 6 | Production delivery | Separate plan |

Phases 1 and 2 can be prepared in parallel once phase 0 is under way. Do not claim phase 0 complete before the browser checks pass and are recorded. Owner-run paired releases (phase 4) come before automatic rollout, so automation never preserves the frontend/backend drift.

### 6.1 Next pull requests

| PR | Contents | Size | Status (2026-11-16) |
|---|---|---|---|
| R1 | Fix `audit_events` RLS for platform-scope writes. Extend `RestrictedRuntimeJourneysPostgresIntegrationTest` with a managed-session, no-workspace platform owner under the `prod` tenancy settings, asserting each write's mutation, audit row and delivery intent. Tenancy and security config are on the never-touch list: the owner approves the change first | Small–medium | #111, merged. Fails before and passes after the fix under the exact lab actor. Released in `2c382df`; demo-request delete passes in the lab |
| R2 | Email delivery: trace the stages (§4.6) after R1. Fix only a separate defect if one remains, with a test | Small, possibly none | Traced in the [lab record](../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md): no separate defect, so no PR. An invitation reaching an inbox stays a phase 0 exit check |
| R3 | Detection, part 1: worker success-line metric filter and fatal-error metric; lab release alarms (SNS email) outside `operations`; `release.py` verify fails on the defined fatal patterns and waits one scheduler cycle | Medium | Merged via #115 (combining #112–#114) and released in `2c382df`: the release's bake saw six healthy progress lines. Alarms are opt-in; their read grant must be attached before they are enabled |
| R4 | Detection, part 2: a Playwright signed-in smoke suite with seeded fixtures, run by `release.py` after rollout; the contract test against public traces | Medium | Merged via #115 and released in `2c382df`, but not yet configured for the lab (`LAB_SMOKE_CONFIG` unset), so it has run only against a local stub. A second managed platform owner has no operator binding path yet |
| R5 | Migration-catalog fingerprint in the publication manifest and release inputs; the live schema-state check; the migrator-drift plan (§4.3) | Small–medium | Merged via #115 and released in `2c382df`: the schema-state check reported V23..V23 ready. Adds read-only `release.py check` |

PR D of the CI plan follows these.

**Phase 0 status (2026-11-16):** release `20261115t171747z-2c382df` is live and passed every automated check. Since the rollout the logs show no ERROR lines and no `row-level security` lines, and the worker reports `tenant_work_progress outcome=healthy` and `tenant_schema_state unready_tenants=0` at V23. `c013bd7` is recorded as rejected. Browser acceptance is **not recorded**: check 6 passed, and the owner deferred the other checks, including the invitation (check 7), to a separate full-app test plan after the CI work. Phase 0 is therefore not closed. `release.py deploy` refuses while a release awaits acceptance, so 2c382df needs its nine answers before PR D's release, and it becomes the healthy baseline for phase 3 only if all of them pass.

**Phase 2 status (2026-11-16):** PR D merged as #117 and its exit criteria are met; see the [PR D record](ci-simplification-plan.md#pr-d-record).
- One `Quality gate` covers image, security and `main` performance for the same SHA.
- A failed security result blocked test PR #118.
- The lab publication came from the consolidated run `43755583811`.
- Critical path: 14m48s–21m42s before and 21m11s after, set by `backend-postgres` both times.

PR D changed only CI files and docs, so the image published for `90cb7e2` is byte-identical to the one 2c382df runs (`sha256:fc1b533f…`). Releasing it would change nothing that runs, so it cannot serve as the second healthy release for the phase 3 drill. That needs the next merge that changes the backend image.

**Phase 3 status (2026-11-16): done.** The [drill record](../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md#phase-3-recovery-drill-2026-11-16) has the full evidence.
- **Participants:** 2c382df (`fc1b533f…`) and 52163ec (#124, `9d83db25…`, the AWS SDK BOM bump). Both are V16 / V23 with the same catalog, and both are accepted with browser checks *waived*, not passed. "Healthy" here therefore means every automated check and the bake passed.
- **Failure and recovery:** a 52163ec deploy was forced to fail its signed-in smoke check with a deliberately empty `LAB_SMOKE_CONFIG`. `release.py rollback` then restored the accepted 2c382df through the Release role and passed the API and worker checks and the bake 12m26s after the failed check.
- **Forward again:** the lab moved back to 52163ec (`20261116t055459z-52163ec`, accepted with a waiver). Previous accepted is 2c382df.
- **Gaps for phases 4–5:** the failed release and its recovery aren't linked (§4.7's `failed`/`recovered`). `rollback` takes no reason. `previous_accepted` empties after a rollback is accepted. And a rollback has only about 2.5 minutes of margin inside the 15-minute limit.

**Phase 4 status (2026-11-16, later): done, except the frontend half of reconcile, which waits for the environment's `VERCEL_TOKEN`.**
- **First live paired release:** `20261116t082637z-cbb265b` shipped backend and frontend as one recorded transaction ([lab record](../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md#first-live-paired-release-2026-11-16)). The backend image was unchanged (`9d83db25…`). Frontend `dpl_G3By6vq5QDcH2dwSQoXpyQcfLEST` was staged from `cbb265b` and promoted only after the backend verified. The signed-in smoke passed before and after promotion.
- **Vercel's independent promotion is off** (`autoAssignCustomDomains = false`), verified by the following `main` merge.
- **Still to prove:** a pair whose backend image changes.
- **Slice 2** (runtime-only role, reconcile dispatch): live. [Design](phase4-slice2-design.md) and code in #130/#131, a download fix in #132. Rollout done: part2 v3, environment `aws-standard-lab-release`, role `scoutgrid-lab-github-release`, simulation 31/31, the GitHub denials, and the first reconcile `20261116t160758z-e7f871c` verified backend-only ([lab record](../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md#reconcile-rollout-phase-4-slice-2-2026-11-16)).

**Phase 4, slice 1 (code):** It adds `release.py deploy --frontend`: a pinned Vercel stage outside the lock, then promotion of that exact deployment after the backend verifies, then paired checks, with one record and the pair in the accepted entry.
- **Frontend retries:** `frontend_pending` retries repeat no backend step.
- **Pair recovery:** the frontend is restored first. Restoring the exact accepted pair reuses its acceptance (§4.7).
- **Outcomes:** §4.4 results.
- **Drill gaps closed:** the failed and recovered records are linked, `rollback --note` records why, and a resumed deploy no longer reruns a migrator that exited 0.
- **Kept on purpose:** `previous_accepted` stays null after an accepted rollback to it. Refilling it with the release just left would make the next rollback return to a release the operator fled.
- **Tests:** offline only, against a fake Vercel. The Vercel API calls (`/v13/deployments`, `/v4/aliases`, `/v10/projects/…/promote`) and the CLI flow are unqualified until slice 3, the first live paired release. Slice 3 then disables Vercel's independent `main` promotion.
- **Slice 2:** the runtime-only role and the manual reconcile dispatch.

**Phase 0 correction (2026-11-16):** 2c382df was later accepted with `release.py accept --waive` (#123), so it could serve as the recovery target. The waiver doesn't close phase 0: the nine browser checks still have to pass and be recorded.

**Phase 0 decision (2026-11-16, owner): not proceeding.** Phase 0 stays closed as *not pursued*, not as *passed*. Its fixes (R1 and the R2 trace) are released and the automated checks pass, but the nine browser checks and the invitation-to-inbox check will not be run under this plan. What that means:
- Releases keep being accepted with `release.py accept --waive`, which records every check as waived (`passed: null`), never as passed. Acceptance still gates the next deploy as before.
- "Healthy" in phases 3–5 means every automated check, the bake and the signed-in smoke passed. It never means browser-verified.
- Phase 5's entry condition "phases 0–4 are complete" reads as "phases 1–4 are complete" for the lab.
- Full-app browser testing, if it is done later, belongs to a separate test plan, not this one.

## 7. Required failure and resume tests

Offline tests cover missing/security/performance results, allowed skips, schema fingerprints across skipped commits, outcomes, lock conflicts, partial Terraform effects, failed state writes, interrupted waits, frontend failure/retry and deferred catch-up. Add live supervised evidence for authenticated/worker failures, alarm delivery, exact frontend promotion and healthy recovery.

Acceptance cases include:

- Parked lab publishes artifacts but changes no live release; startup plus reconcile catches up without another merge.
- Acceptance outstanding blocks rollout; accepting the current pair plus reconcile selects the newest qualified head.
- A schema-changing or uncertain candidate never invokes the automatic migrator path.
- Equal migration heads with a different catalog fingerprint, or an unready tenant reported by the control plane, return `blocked`.
- A merge that changes only the migrator's configuration returns `blocked` (`migrator_drift`), not a runtime release, and a new runtime image alone is not reported as drift.
- A managed-session platform owner with no workspace can complete each platform-scope write under the restricted role: the mutation, the audit row and the delivery intent all commit (the 2026-11-15 `audit_events` failure).
- An effective schema range that excludes the database head (the 2026-11-15 V23..V20 failure) fails before rollout.
- A running-but-failing worker fails qualification; generic expected log errors do not create an indiscriminate rollback rule.
- A failed frontend step retries the recorded deployment without repeating backend/migration effects.
- Cancellation/timeout inspects recorded intent and actual child operation before resume or owner unlock.
- Recovery restores the exact accepted pair; failed/uncertain recovery becomes `needs_operator`.

## 8. Owner decisions and activation

| Decision | Recorded direction and boundary |
|---|---|
| D1: visibility | Explicit owner/business decision; unchanged by this work. Review public evidence/artifact content separately. |
| D2: automatic neutral releases | Conditional yes to the design; enable only at phase 4 after exit evidence and owner decision. Until then use manual delivery. |
| D3: signed-in testing | Existing browser flow with dedicated bounded lab accounts and protected secrets; no new password-grant client by default. Remaining browser acceptance stays explicit. |
| D4: frontend control | Stage then promote the identified configured deployment after backend verification; qualify the replacement manual path before disabling the old one. |

These are planning directions, not evidence that roles, tests, reviewers or automation have been configured. Each implementation PR records its exact changes, validation and enable/undo steps; live AWS/GitHub/Vercel actions remain separately scoped.

## 9. Out of scope

- Hosting migration, a new scheduler/orchestrator, automatic production or schema-changing deployment.
- Blue/green migration; retain the existing rolling strategy while qualifying its recovery limits.
- Unrelated Jackson/PR F work, blanket scanner retirement, visibility changes or unreviewed audit-stack enablement.
