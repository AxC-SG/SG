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

## Open

1. **Accept or reject 2c382df** with `release.py accept --answers <9 letters> --note …` after the owner's full-app checks. Every check must pass for it to become the healthy baseline.
2. **Configure the signed-in smoke** (`LAB_SMOKE_CONFIG`, the account steps from R4) so later releases check platform writes and the invitation themselves.
3. **Rollback exercise** between the accepted 2c382df and the next healthy release (CD plan phase 3). `abd8c038…` and `eae5dafa…` are not healthy recovery targets.
4. **Later:** keep or delete the pre-migration snapshot. Delete the stale `aws-cleanup` follow-up about deploying #81 (done by the first release).
5. **Later:** PR D must update the publisher trigger and selector if it renames workflows. Write a production severity and exceptions policy for Trivy.
