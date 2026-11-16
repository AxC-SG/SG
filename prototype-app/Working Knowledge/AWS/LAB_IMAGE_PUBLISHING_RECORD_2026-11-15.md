# Lab image publishing: record, November 14–15, 2026

What was decided and done to let GitHub publish qualified backend images to the lab ECR. This is a record only. The decision itself is in [A03 of STANDARD_IMPLEMENTATION_READINESS.md](STANDARD_IMPLEMENTATION_READINESS.md), and the change is [PR #107](https://github.com/AxC-SG/SG/pull/107).

## Starting point

- PRs #100 (TypeScript 6, Spring Boot 4.1.2) and #101 (managed-session 403 fix, demo-request delete) merged to `main` on November 14.
- **Frontend:** Vercel auto-deploys `main`. Production at scoutgrid.io was serving `3de7401` (#100's merge, which includes #101).
- **Backend:** nothing auto-deploys. A read-only check on November 15 found `api` (`scoutgrid-lab-api:3`) and `worker` (`scoutgrid-lab-worker:2`) both running `scoutgrid-lab-backend@sha256:e0477a842367866505e469c7dc97aef77759fce5febf3a59d10d49acbe3a3ad5`, built from November 12 code. #100 and #101 are therefore not running in the lab.
- How a backend image reaches the lab:
  - **Build:** each `main` push builds and scans the image in `trivy.yml` and keeps it as the artifact `aws-backend-candidate-<run>` for 14 days. The #100/#101 candidate is Trivy run `43624919114` and expires around November 28.
  - **Publish:** `aws-publish-candidate.yml` (manual dispatch) pushes a candidate to ECR. It had never run. The November 12 image was pushed by an operator.
  - **Deploy:** ECS runs the digest pinned in `runtime-*.tfvars`. `lab.sh` only creates or deletes runtime resources and refuses task-definition changes, so it cannot roll out a new image. A release needs its own path (next PR).

## Design discussion (summary)

- **ECR, then ECS.** ECS always pulls from a registry, so there is no "direct to ECS" option.
- An external review corrected the first proposal:
  - `lab.sh up` cannot deploy a new image.
  - Terraform must stay the only writer to ECS.
  - Schema compatibility gates rollback: the binary accepts tenant V23 only.
  - The circuit breaker, rollback and 300 s grace period already exist.
  - Lab "down" removes the services; it does not just scale them to zero.
  - The migrator request is pinned to revision `:1`.
  - Trivy blocks CRITICAL findings only.
- **Agreed order:**
  1. Automatic **publication** to the lab ECR (this record).
  2. A release PR: a local `release.sh` first; Terraform as the single writer; separate migrator and runtime digests; two applies with the candidate migrator in between; an environment lock that `lab.sh` honours; durable release inputs and a release record in the state bucket; authenticated smoke tests; a rollback exercised on the first release; frontend promotion coordinated with the backend.
  3. Automatic deployment only after one release and one rollback are proven.

## Security decision

A03 had kept `github_publisher = null`, because GitHub Free cannot require reviewers or restrict branches on private-repository environments.

**Owner decision, November 15:** enable it for the lab, with the restriction carried by the OIDC subject instead.

- **Trust:** the role trusts only the publisher workflow as merged to `main`. Its subject includes `job_workflow_ref`, and `main` changes only through reviewed PRs.
- **Permissions:** the role can only push to the immutable `scoutgrid-lab-backend` repository. ECS runs only digests selected through Terraform, so a publication never changes what runs.
- **Production:** stays `null` and operator-published.

## PR #107: `chore/auto-publish-lab-candidate`

Commits: `bf4a20d2`, `80ac65fe`, `79361e11`.

| File | Change |
|---|---|
| `.github/scripts/select-aws-candidate.py` | Candidate selection. Manual runs keep the exact-commit qualification. Automatic runs (lab only) publish once Quality, Semgrep, Trivy and Performance Governance all passed for the commit, it is still `main`'s head, and it has not been published. |
| `.github/scripts/test-select-aws-candidate.py` | 14 tests |
| `.github/workflows/aws-publish-candidate.yml` | `workflow_run` trigger for the four checks; one publication per target at a time; publish job skipped when the selector declines; artifact `aws-publication-<target>-<sha>` (90 days) |
| `.github/workflows/quality.yml` | Runs the new tests |
| `.github/scripts/test-ci-contracts.py` | The trigger's workflow names must match the checks the selector uses (guards PR D renames) |
| `infrastructure/terraform/standard/release-iam.tf` | The subject must pin `job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main` |
| `tests/runtime.tftest.hcl`, `tests/integrated-lab.tftest.hcl` | Reject a bare environment subject, branch workflows and other workflows; the lab creates exactly the publisher role |
| `infrastructure/lab/config/sydney-lab.foundation.tfvars` | `github_publisher` set for the lab |
| `infrastructure/lab/grants/bootstrap-github-publisher-role.json`, `LAB_CYCLE_MATRIX.md` | The Bootstrap grant |
| `Working Knowledge/AWS/STANDARD_IMPLEMENTATION_READINESS.md` (A03), `Working Knowledge/CI Pipeline/ci-simplification-plan.md` (4.2) | Decision and PR D note |

Local verification:
- Terraform 1.13.5 `validate`, plus `test` (28 passed)
- `lab.test.sh`
- actionlint
- all CI script tests

## Changes made outside the repository

Each step was approved by the owner before it ran.

| # | When (UTC) | Change | Verification | Undo |
|---|---|---|---|---|
| 1 | 2026-11-14 19:15 | Created IAM OIDC provider `arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com`, audience `sts.amazonaws.com`, tags `Environment=lab`, `Purpose=github-ecr-publish` (sign-in profile `scoutgrid-lab`) | Read back URL and client list | `aws iam delete-open-id-connect-provider` |
| 2 | 2026-11-14 19:16 | GitHub repository OIDC subject template: `use_default=false`, `include_claim_keys=[repo, context, job_workflow_ref]` (immutable subjects stay on) | Read back via the API | Same API with `use_default=true` |
| 2a | 2026-11-14 19:16 | Throwaway probe: branch `chore/oidc-subject-probe`, run `43631212372`, deployment `7792549423` on `aws-standard-lab`. It printed only the decoded `sub` claim. | `sub=repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/oidc-subject-probe.yml@refs/heads/chore/oidc-subject-probe`, so the workflow-file part uses names | Branch, run and deployment deleted and verified gone |
| 3a | 2026-11-14 | Inline policy `GithubPublisherRole` on `ScoutGridSydneyLabBootstrap` (`grants/bootstrap-github-publisher-role.json`): create, read, tag and delete on `scoutgrid-lab-github-ecr-publish` only | Access Analyzer: no findings. Inline total 2,636 of 10,240 bytes. Simulator: allowed on this role, `implicitDeny` on others | `aws iam delete-role-policy --role-name ScoutGridSydneyLabBootstrap --policy-name GithubPublisherRole` |
| 3b | 2026-11-14 | Targeted Terraform apply as Bootstrap of `aws_iam_role.github_publisher` and `aws_iam_role_policy.github_publisher` only, from the PR branch: 2 added, 0 changed, 0 destroyed | Role in state and AWS; trust is `aud=sts.amazonaws.com` and `sub=repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab:job_workflow_ref:AxC-SG/SG/.github/workflows/aws-publish-candidate.yml@refs/heads/main`; policy `publish-backend-image`; ARN matches GitHub's `AWS_ECR_PUBLISH_ROLE_ARN` | Revert #107 and destroy the two resources through Bootstrap, or set `github_publisher = null` and apply |

The `-target` was needed because the full lab plan also shows a change that was already pending and is unrelated: new `api`/`worker` task-definition revisions adding `RESEND_FROM_EMAIL` / `RESEND_API_KEY` from PR #81, which would roll both services. It stays unapplied.

## Findings along the way

- **The repository uses immutable OIDC subjects** (`repo:AxC-SG@351325919/SG@1427276590`). The first name-based subject would never have matched; commit `80ac65fe` corrected it.
- **No scoped lab role could create the publisher role.** Bootstrap was limited to the five runtime roles, hence grant 3a.
- **The plan role lacks `budgets:ViewBudget`,** so a full plan as `ScoutGridSydneyLabPlan` stops at the budget. This gap existed before and is not fixed here.
- **`aws-standard-production` has no protection rules.** That is acceptable only while production keeps `github_publisher = null`.

## First automatic publication (verified)

- **Merge:** #107 merged at 2026-11-14 19:42 UTC as `e268395b7f925e7b296d18e5925c4e6545dee12a`. This commit contains #100 and #101, so the manual publication of `3de7401` was no longer needed.
- **Checks:** Quality, Semgrep SAST, Trivy Security Scan and Performance Governance all passed on `e268395`.
- **Publisher runs:**
  - Runs `43633578447`, `43633684607` and `43633747759` (triggered by the earlier check completions) qualified the candidate and skipped publishing.
  - Run `43634738494` (the last completion) published the image from Trivy run `43633506061`.
- **ECR image:** `736486260824.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend@sha256:abd8c038a4a8608cc2377f3392f6072f5f8d3d64784d5738ac00af92efed5a3e`, tag `e268395b7f925e7b296d18e5925c4e6545dee12a-43634738494-1`, pushed 2026-11-14 19:56 UTC, 333 MB. The lab repository now holds this image and the November 12 image.
- **Record:** artifact `aws-publication-lab-e268395b7f925e7b296d18e5925c4e6545dee12a`, which expires 2027-02-12.
- **ECS:** unchanged. The services still run `sha256:e0477a84…`.

## Release flow and first lab release (PR #108)

**PR #108** (merged as `9827b131`) added:
- `infrastructure/lab/scripts/release.py`;
- the `backend_images` variable (separate runtime and migrator digests), read from `s3://…tfstate…/standard/lab/release/inputs.json`;
- a lock shared with `lab.sh` (`release/lock.json`);
- per-release records in `release/records/`.

**Before the first release**, each step with owner approval:
- Created role `ScoutGridSydneyLabRelease`: inline `LabRelease`, plus `common-read-state-part1/2`, `waf-association-read` and `cycle-watch`.
- Attached managed `ScoutGridSydneyLab-release-inputs` to the cycle role.
- Added profile `sglab-release`.
- Ran `release.py init 0ae3de9… 15 20`: baseline-20261114, `e0477a84…`.

**Release `20261115t045506z-e268395`** moved the lab from `e0477a84…` (0ae3de9, platform V15 / tenant V20) to `abd8c038…` (e268395, platform V16 / tenant V23). It was schema-changing, so the maintenance path ran.

| UTC (2026-11-15) | Step |
|---|---|
| 04:55 | api and worker stopped (sign-in offline) |
| 05:00 | snapshot `scoutgrid-lab-release-20261115t045506z-e268395` available |
| 05:00–05:07 | three stops, each before its step, fixed and resumed (below) |
| 05:04 | migrator `scoutgrid-lab-migrator:3` registered |
| 05:09 | migrator task `7b114b045b3a41f59695e1d1ae7f1c35` exited 0: V16 / V23 |
| 05:14 | api `scoutgrid-lab-api:4` and worker `scoutgrid-lab-worker:3` settled on `abd8c038…` (sign-in back, about 19 minutes offline) |
| 05:15 | automated checks passed: both services 1/1, target healthy, `/api/auth/csrf` 200, `/api/me` 401; release waiting for browser checks |

**Stops and gaps found by the first run** (PR #110 unless noted):
- **Release role permission:** it lacked `s3:GetBucketWebsite` on the imports/exports buckets. Added to `LabRelease`.
- **Wrong CLI flag:** `run-task` takes `--disable-execute-command`.
- **Stale ARNs:** a targeted apply doesn't recompute root outputs, so task-definition ARNs are now read from state.
- **`lab.sh` plans broken since #107:** they couldn't read the publisher role. `common-read-state-part2` v2 adds it (v1 kept). After that, `lab.sh plan-up` reports no changes.
- **Application bug (PR #109):** `application.yml` capped the tenant schema at V20, so after the migration the supported range was empty ("V23..V20"). Tenant-scoped scheduled jobs in the worker fail every five minutes until a release of the fix.

## Second release and its browser checks

**Release `20261115t063842z-c013bd7`** (06:47 UTC) rolled the merged #109/#110 commit to the lab: image `eae5dafa…`, api `scoutgrid-lab-api:5`, worker `scoutgrid-lab-worker:4`. It was schema-neutral (V16 / V23), so no outage. The #109 fix is confirmed: no "outside this release's supported range" errors after the rollout.

**Browser checks failed.** Every platform-scope write (demo-request approve, reject, delete) returned `[INTERNAL_ERROR]`. The API logged `new row violates row-level security policy for table "audit_events"` for a managed-session platform owner with no workspace (requestIds `5d0576cf…`, `24fbc171…`, `348e207a…`, `396a669a…`; also `a9bc9976…` on the previous release, so the bug predates `c013bd7`). Page loads did not show the failure. The release stays unaccepted and is not a recovery target.

**Cause (fixed in PR #111, R1 of the [CD plan](../CI%20Pipeline/cd-consolidation-plan.md)):** with `require-tenant-context=true`, a connection with no tenant or platform context binds the no-tenant sentinel, and the `audit_events` policies reject a tenant-less row under that sentinel. Superuser ITs and `require-tenant-context=false` ITs could not see it. `RestrictedManagedPlatformWritesPostgresIntegrationTest` reproduces the lab actor (managed session, no workspace, non-bypass runtime role, prod tenancy settings): all three writes fail with the lab error before the fix and pass after.

**Email trace (R2), stage by stage:**
1. *Delivery intent:* under managed auth, approval sends nothing. It queues Standard onboarding (`QUEUED` / `STANDARD_APPROVED`), and the setup email comes from Cognito in the operator's enrollment steps. Before #111 the request rolled back, so no intent committed.
2. *Configuration:* the Resend settings are present in api `:5` and worker `:4`.
3. *Provider:* Resend logs show no request from the app since 1 November, consistent with no action reaching a send.

No separate email defect was found, so R2 needs no code change. The phase 0 exit check still requires an invitation to reach a test inbox after the #111 release.

## Third release and phase 0 status

**Release `20261115t171747z-2c382df`** (17:31 UTC) rolled out #115, which contains the #111 RLS fix and the R3–R5 detection signals. Image `fc1b533f…` (publisher run 43739404235), api `scoutgrid-lab-api:6`, worker `scoutgrid-lab-worker:5`. It was schema-neutral (V16 / V23). Before the deploy, `c013bd7` was recorded as rejected (`yyyyynnyy`, relayed).

**Automated checks passed.** Six healthy `tenant_work_progress` lines, schema state ready at V23..V23, no defined failure patterns. The signed-in smoke was not configured (`LAB_SMOKE_CONFIG` unset), and the catalog fingerprint was not verified.

**After the deploy (to 18:55 UTC):** the worker log shows no ERROR lines, no `row-level security` lines and no Resend warnings. The worker reports `outcome=healthy` (e.g. 416 succeeded, 0 failed in one cycle) and `tenant_schema_state unready_tenants=0`.

**Browser checks:**
- Check 6, demo-request delete, passes. The `audit_events` failure is fixed in the lab.
- Approving a demo request stays `QUEUED` / "Approved. Awaiting workspace setup." This is correct: managed approval sends no email. So check 7 was reworded to the workspace invite (User Management > Invite user, reaching `SENT` through Resend). A successful send logs nothing; only a rejected or unknown Resend outcome logs a warning.
- The owner deferred the remaining checks, including the invitation, to a separate full-app test plan after the CI work.

**Phase 0 is not closed.** Acceptance has not been recorded, so 2c382df is not yet the accepted baseline. `release.py deploy` refuses while it awaits acceptance, so the next release (PR D) first needs its nine answers.

**2026-11-16 update:** the owner waived the browser checks. PR #123 (merged in #124) added `release.py accept --waive --note`, which records every check as waived (`passed: null`), never as passed. 2c382df was accepted that way, which made it the recovery target. Phase 0 stays open until the checks actually pass.

## Fourth release (52163ec) and the stale-lock incident

**Release `20261115t214430z-52163ec`** rolled out #124, the combined PR. It includes the AWS SDK BOM 2.58.0 bump, which changes the backend image. Image `9d83db25…`, api `scoutgrid-lab-api:7`, worker `scoutgrid-lab-worker:6`. It was schema-neutral (V16 / V23, catalog `839784f6…` same), and `release.py check 52163ec` reported `eligible` first.

**Incident: a laptop sleep left a stale Terraform lock.**
- 21:45:03Z: the migrator step applied. The migrator task ran and exited 0, but it was only recorded at 22:10:11Z. Long gaps like this suggest the laptop slept.
- 22:25:38Z: the runtime plan left a stale S3 Terraform plan lock (`standard/lab/terraform.tfstate.tflock`, ID `12117951-9cd6-3eeb-1066-6ed3ca21889d`). The deploy failed at `runtime`.
- Nothing ran on the new image: the state was untouched since the 21:45 migrator apply, and ECS stayed on api `:6` / worker `:5` (`fc1b533f…`). There was no outage.
- Before unlocking, the operator proved four things: it was a plan lock, no terraform or release.py process was running, the state hadn't changed since the last recorded step, and the release lock was free. Auto mode refused Claude's `force-unlock`, so the owner ran it.
- Terraform cannot read the `aws login` source profile, so the unlock needs `eval "$(aws configure export-credentials --profile sglab-release --format env)"` first. The procedure is now in the [lab README](../../infrastructure/lab/README.md#long-releases-and-stale-locks).

**Resume (2026-11-16, under `caffeinate -i`).** Rerunning `deploy 52163ec` resumed the same record:
- migrator step at 04:36:58Z (no changes); the migrator task ran again (exit 0, 04:38:17Z);
- runtime at 04:43:53Z;
- bake 04:44:22–04:50:22Z;
- verified at 04:50:30Z.

All automated checks passed: six healthy progress lines, schema state V23..V23, no defined failures, smoke not configured. The owner accepted it with a waiver at 04:54:13Z. The record keeps the first attempt's `failed_at: runtime` and the lock error alongside `status: accepted`, so the history of the resume stays visible.

## Phase 3 recovery drill (2026-11-16)

**Participants.** Accepted `20261115t214430z-52163ec` (`9d83db25…`) and previous accepted `20261115t171747z-2c382df` (`fc1b533f…`). Both were accepted with browser checks waived, not passed. Both are V16 / V23 with the same catalog, so recovery is runtime-only.

**Forcing the failure.** The owner chose a real failed automated check over an operator-only rollback, and over injecting fake application log lines. The forced-failure deploy ran with `LAB_SMOKE_CONFIG` set to an empty `{}` config. The signed-in smoke check therefore failed (`smoke run: JSONDecodeError`) without signing in or touching the app. The image itself was healthy, and every other check passed. No browser answers were recorded: each acceptance is a waiver whose note names the drill step.

**Why four operations.** A rollback after a failed release returns to the *accepted* release. With 52163ec accepted, a failed 52163ec deploy would roll back to 52163ec itself. So the drill first made 2c382df the accepted release.

| # | Release | Kind, outcome | api / worker | Start → end (UTC) | Duration |
|---|---|---|---|---|---|
| – | `20261116t051149z-2c382df` | rollback, **failed** at the runtime plan: DNS lookup of the ECS endpoint failed (`no such host`). No steps, nothing changed. A read-only `release.py check 52163ec` then passed, so it was transient | `:7` / `:6` | 05:11:49 → 05:12:11 | 31 s |
| 1 | `20261116t051350z-2c382df` | operator rollback 52163ec → 2c382df, verified, accepted (waived) | `:8` / `:7` | 05:13:50 → verified 05:26:43 | 12m59s |
| 2 | `20261116t052737z-52163ec` | deploy with the forced failure, **failed at verify** (`signed-in smoke`); the migrator ran again (no-op, exit 0) | `:9` / `:8` | 05:27:37 → failed 05:41:39 | 14m14s |
| 3 | `20261116t054145z-2c382df` | recovery rollback to the accepted 2c382df, verified, accepted (waived) | `:10` / `:9` | 05:41:45 → verified 05:54:05 | **12m26s** |
| 4 | `20261116t055459z-52163ec` | forward again, clean deploy, verified, accepted (waived) | `:11` / `:10` | 05:54:59 → verified 06:09:20 | 14m33s |

**Exit criterion met.** The failed check was at 05:41:39Z (record ended 05:41:42Z). The restored 2c382df passed API and worker checks at 05:54:02Z and was verified at 05:54:05Z: 12m26s, within 15 minutes.
- Rollback runtime apply and ECS rollout: 05:42:10 → 05:47:28.
- Bake: 05:47:55 → 05:53:55.
- API: both services settled, targets healthy, `GET /api/auth/csrf` 200, `GET /api/me` 401.
- Worker: six healthy progress lines; schema state `unready_tenants=0 supported=V23..V23`; no defined failures in either log; 0 startup ERROR lines.

The previous image restarted on today's schema and configuration through the Release role. Moving forward again ended in the same state as before the drill: accepted 52163ec (now `20261116t055459z-52163ec`), previous accepted 2c382df, lock free, nothing pending.

**Records** (`s3://scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/release/records/`): `20261116t051149z-2c382df.json`, `20261116t051350z-2c382df.json`, `20261116t052737z-52163ec.json`, `20261116t054145z-2c382df.json`, `20261116t055459z-52163ec.json`. The bucket is versioned, so every state of each record is kept. The Release role cannot list versions (`s3:ListBucketVersions`).

**What the drill showed about the tooling** (inputs for phases 4–5, not fixed here):
1. **Little margin.** Each rollback took 12–13 minutes, so it stays inside 15 minutes only if it starts within about 2.5 minutes of the failure. Automatic recovery (phase 5) must start at once, not wait for an operator.
2. **No link between the failure and its recovery.** §4.7 asks for the attempted release to be recorded as `failed` with reason `recovered`. Today the failed deploy record says `failed`, and the rollback record names only `rolls_back_to`. Neither names the other.
3. **No reason on a rollback.** `rollback` takes no reason or note, so the drill context lives only in the acceptance notes.
4. **The left release's record isn't updated.** An operator rollback away from an accepted release leaves that release's record at `accepted`.
5. **No second rollback target.** Accepting a rollback to the previous accepted release sets `previous_accepted` to null until a new release is accepted.
6. **A resumed or neutral deploy always reruns the migrator task.** It is harmless on an unchanged schema, but adds about 1.5 minutes.

## Signed-in smoke setup (2026-11-16)

**Smoke workspace.** Demo request `e8d1afb0-e27d-453c-bcc6-7cbb47423591` for `delivered+smoke-admin@resend.dev`, submitted through `/demo/request` and approved by the owner. The request ID is the workspace UUID.

| Step | Identity | Evidence |
|---|---|---|
| Re-pin the migration operator | owner, `put-role-policy` | `ScoutGridSydneyLabMigration` / `MigrationOperator`: `RunOnlyReviewedMigratorRevision` changed from `migrator:1` to `migrator:6` (the repo's `grants/migration-operator.json` matched the live policy apart from this line) |
| Provision | `sglab-migration`, release lock held | task `b7dccecea48d4dce809ddac63aff1ee5` on `migrator:6`, 07:40:42Z, exit 0: `database_preflight`, `standard_tenant_reserved`, `standard_tenant_activated`, `runtime_verification` |
| Cognito user | `sglab-identity` | `AdminCreateUser` with `SUPPRESS`, `email_verified=true`; sub `99dee4c8-d011-7069-cbe4-5bd52378cdc9`; temporary password written only to the config file |
| Link the admin | `sglab-migration`, release lock held | task `decd7aa806044f0499796a57a15ec067`, 07:44:19Z, exit 0: `standard_admin_link_verified` |
| First sign-in | owner, by hand | temporary password replaced |

**Platform owner.** The config uses the owner's own platform-owner account. There is still no operator path for a second one.

**Config.** `~/.config/scoutgrid/lab-smoke.json`, mode 0600, outside the repository. Lab MFA is off, so it is a credential.

**What the first runs found.** The smoke had only been tested against a stub, and three of its failures were the smoke's own:
- **CSRF token reuse.** The smoke reused one CSRF token for several writes, so the second write (cancelling the invite) got 403. The app fetches a fresh token per write, and the smoke now does too.
- **Asynchronous invite.** The smoke expected the invite to be `SENT` immediately. The API returns `QUEUED`, and the worker's outbox submits it every five seconds, so the smoke now waits up to 90 seconds.
- **Bad config value.** The platform `email` was not an address, so Cognito showed "Invalid email address."

One invite from the first run stays open, `SENT` to `delivered+smoke@resend.dev`, until it expires.

**First full run passed** all 14 checks. Platform side: sign-in without a workspace, four pages, a fixture created, then rejected and deleted, sign-out. Tenant side: workspace entry, Findings, an invite reaching `SENT` and cancelled, sign-out. Set `LAB_SMOKE_CONFIG=~/.config/scoutgrid/lab-smoke.json` for every release from now on.

## First live paired release (2026-11-16)

**Release `20261116t082637z-cbb265b`** (`release.py deploy cbb265b --frontend`, with `VERCEL_TOKEN` and `LAB_SMOKE_CONFIG` set): outcome `verified`, phase `paired`, 10m30s.

| UTC | Step |
|---|---|
| 08:26:10–08:26:29 | Staged frontend `dpl_G3By6vq5QDcH2dwSQoXpyQcfLEST` from `cbb265b` (`vercel@65.9.0`), not promoted |
| 08:27:03–08:28:24 | Migrator plan: no changes; the migrator task ran as a no-op, exit 0 |
| 08:28:43 | Runtime plan: no changes. The image `9d83db25…` was unchanged, so api `:11` and worker `:10` kept running |
| 08:29:03–08:34:56 | Bake |
| 08:35:40 | All backend checks passed (six healthy progress lines, schema V23..V23, no defined failures, 0 startup ERROR lines). The signed-in smoke passed 14/14 against the old frontend and the new backend |
| 08:35:46–08:35:55 | Promotion: the first live `POST /v10/projects/…/promote`, which worked |
| 08:36:32 | Paired checks: scoutgrid.io serves `dpl_G3By…`, `GET /` 200, and the signed-in smoke passed 14/14 on the pair |

**Accepted** at 08:59:51Z with the browser checks waived. The accepted pair is now `9d83db25…` with `dpl_G3By…`. The previous accepted pair is 52163ec with the adopted `dpl_4cm35SwLZ48ddWwsDek6sex1zrYt`.

**Before the release,** Vercel's own `main` promotion had moved scoutgrid.io to `dpl_GrRcgUafDEbzM66yC1ofZPKhZjTh` (the #128 merge), outside the record, and `status` showed `DIFFERS FROM INPUTS`. At 09:03:26Z, with the owner's approval, `autoAssignCustomDomains` was set to `false` (`PATCH /v9/projects/{id}` returned 200; a read-back showed `false`). Verification: the merge of this record must build a production deployment and leave scoutgrid.io on `dpl_G3By…`.

**What is proven live now:** staging, promotion, the paired checks, and the signed-in smoke inside a release.

**Still to prove:** a pair whose backend image changes, and a paired recovery (frontend-first rollback).

**Dry-run leftovers:** deployments `dpl_AcWAF5…` and `dpl_AJQJfSt…` were never assigned a domain.

## Reconcile rollout (phase 4 slice 2, 2026-11-16)

PRs #130 (design) and #131 (code) merged as `86074ff9`. The owner asked for the rollout to be completed ("proceed to complete slice2"). The steps follow the lab README "Reconcile" section.

| UTC | Step | Result | Undo |
|---|---|---|---|
| 14:59:15 | 1. `ScoutGridSydneyLab-common-read-state-part2` v3 published as default (`grants/common-read-state-part2.json`). The only difference from v2 is the new role's ARN in `ReadExactRuntimeRoleMetadata` | v1, v2 kept (3 of 5 versions) | `aws iam set-default-policy-version --version-id v2` |
| 14:59:32 | 2. GitHub environment `aws-standard-lab-release`: custom deployment branch policy `main` only, no required reviewer (S3). Variable `AWS_LAB_RELEASE_ROLE_ARN`. Secret `LAB_SMOKE_TENANT_CONFIG` from the local smoke config with `platform` removed by `jq del(.platform)`, piped straight into `gh secret set`, never printed (S1) | `VERCEL_TOKEN` not set: the separate team-scoped token (S2) has to be created by the owner in the Vercel dashboard | Delete the environment |
| ~15:01 | 3a. Inline `GithubReleaseRole` (`grants/bootstrap-github-release-role.json`) on `ScoutGridSydneyLabBootstrap`. Access Analyzer: no findings. Inline total 3,612 bytes | Detached again at ~15:06 | `delete-role-policy` |
| ~15:02–15:04 | 3b. `github_releaser` set in `sydney-lab.foundation.tfvars`. Targeted plan as Bootstrap (foundation + `runtime-running` + released images, the three `github_releaser` targets), under the shared release lock: **6 to add, 0 to change, 0 to destroy**, all IAM. Applied: 6 added | Role trust is exactly `aud=sts.amazonaws.com` and `sub=…:environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/main`; max session 3600; inline `runtime-only-release`; the four read policies attached | `github_releaser = null`, same targets |
| 15:05:53 | 3c. `lab.sh plan-up` (cycle role) | **no changes** (part2 v3 lets the cycle role read the new role) | - |
| ~15:07 | 4. `aws iam simulate-principal-policy` on the role, 31 cases | **31/31 as expected** (below) | - |
| ~15:10–15:14 | 5. GitHub denials | All three refused (below) | Probe branch deleted |

**Simulation (step 4).** Allowed: api and worker `RegisterTaskDefinition` with the required tags, Fargate and the reviewed CPU/memory; `UpdateService` on api and worker to api/worker revisions; `PassRole` on the api task role to ECS tasks; `PutObject` on release inputs and records; `DeleteObject` on the release lock and the Terraform state lock; state `GetObject`/`PutObject`; the state key through S3 only; `DescribeServices`; api logs. Implicitly denied: untagged or resized registrations, pointing a service at the migrator family, direct (non-S3) use of the state key, `rds:StopDBInstance`. Explicitly denied: migrator `RegisterTaskDefinition`, `RunTask`, `StopTask`, `CreateDBSnapshot`, `GetSecretValue`, `PassRole` on the migrator execution role, IAM writes, `DeleteObject` on the inputs or the state, `DeleteObjectVersion`.

**GitHub denials (step 5).**
- `lab-reconcile.yml` dispatched from `chore/lab-reconcile-rollout` with `confirm=reconcile`: the job was **skipped** by its `main`-only guard (run 43893260929).
- A temporary probe workflow on branch `probe/releaser-trust` (run 43893344721, branch deleted afterwards, never merged) tried `AssumeRoleWithWebIdentity` with its own OIDC token. With no environment (`sub=…:ref:refs/heads/probe/releaser-trust:job_workflow_ref:…probe-releaser-trust.yml@…`) and in the publisher's environment `aws-standard-lab`: **AccessDenied** both times. In `aws-standard-lab-release`: GitHub **rejected the job** ("Branch "probe/releaser-trust" is not allowed to deploy to aws-standard-lab-release due to environment protection rules").

## Open

1. **Full-app browser checks** for the accepted release. Until all nine pass and are recorded, phase 0 stays open; waivers do not count.
2. **Signed-in smoke:** configured and passing (see above). Remaining gaps: no operator path for a second managed platform owner, and the migration operator grant must be re-pinned after each new migrator revision.
3. **Recovery record gaps** from the drill: items 2–4 and 6 are addressed by phase 4 slice 1 (`release.py deploy --frontend`, linked recovery records, `rollback --note`). Item 5 is kept on purpose; the CD plan's phase 4 status explains why. Item 1 waits for automatic recovery (phase 5).
4. **Later:** keep or delete the pre-migration snapshot. Delete the stale `aws-cleanup` follow-up about deploying #81 (done by the first release).
5. **Later:** write a production severity and exceptions policy for Trivy.
