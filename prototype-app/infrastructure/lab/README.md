# Sydney lab operations

Runnable tooling for the Sydney AWS lab, ScoutGrid's only environment (account `736486260824`, `ap-southeast-2`). It drives the Terraform in [`../terraform/standard`](../terraform/standard).

| Path | Contents |
|---|---|
| `scripts/lab.sh` | Lab up, down, status, plan-only and IAM simulation |
| `scripts/release.py` | Lab releases: move the lab to a published `main` commit (backend, or backend and frontend as a pair), roll back, show release status, and the runtime-only `reconcile` that the manual Actions workflow runs |
| `scripts/release_lib/` | Pure release checks, settings, GitHub publication lookup, Vercel adapter, and runtime configuration renderer |
| `scripts/tests/support.py` | Shared offline lab fixtures; test suites do not import each other |
| `scripts/tests/lab.test.sh` | Offline tests for `lab.sh` failure handling; AWS, Terraform and Cloudflare are stubbed. CI runs it. |
| `scripts/tests/test_release.py` | Offline tests for `release.py` against a fake lab. CI runs it. |
| `scripts/bootstrap-sydney-state.sh` | Creates or verifies the encrypted Terraform state bucket |
| `scripts/sydney-plan-role-*.json` | Trust and permission policy for the read-only plan role |
| `config/` | Common runtime JSON and per-mode overrides, foundation tfvars, the S3 backend config, the post-release browser checks, and captured service and task-definition requests |
| `grants/` | Every IAM grant used or corrected in the lab, with the [cycle matrix](grants/LAB_CYCLE_MATRIX.md) |

How to run the cycle, the budget rule and the lab's history are in the [lab record](<../../Working Knowledge/AWS/aws-lab/README.md>) and [findings](<../../Working Knowledge/AWS/aws-lab/FINDINGS.md>). Evidence from the lab runs stays there too.

## Runtime configuration and tooling

`config/runtime-common.json` owns shared certificate, secret and KMS references and feature flags. Each `runtime-{running,down,noenroll,stopped}.json` supplies only its lifecycle settings; only `stopped` adds the pinned enrollment reference. These are renderer inputs, not standalone Terraform var files. `lab.sh` and `release.py` render the same configuration into a private temporary `*.tfvars.json` file. The renderer explicitly merges `backend_candidate`, because Terraform replaces whole object values across var files.

For a manual Bootstrap plan, render the selected mode first (from the repository root), then pass the result after the foundation var file, together with the released `backend_images`:

```sh
umask 077
python3 -I prototype-app/infrastructure/lab/scripts/release_lib/runtime_config.py stopped > /tmp/scoutgrid-runtime.tfvars.json
# terraform plan ... -var-file=<foundation> -var-file=/tmp/scoutgrid-runtime.tfvars.json -var-file=<released-images>
# Remove the rendered file after reviewing/applying the plan.
```

Historical evidence names `runtime-*.tfvars`; use the renderer above for current operations. Existing state addresses, image inputs, release records, locks and CLI commands are unchanged. `release.py` removes its temporary plans and downloaded objects on normal success, exceptions and interruption; durable recovery data remains in S3.

The Terraform version and Linux archive checksum are pinned in [`.github/tool-versions.json`](../../../.github/tool-versions.json). Both workflows use the local setup action, and both operator scripts read the required version from that manifest. The installer checks the archive before extracting it.

Runtime task definitions now add Cognito hosts through `HTTP_OUTBOUND_ADDITIONAL_ALLOWED_HOSTS`; the backend owns its default provider catalogue. This setting is supported by source since `bf179fa4`. Apply this task configuration only with an image containing that support, including when choosing rollback images. `lab.sh` continues to refuse task-definition changes; the first rollout of the environment change goes through the reviewed release path.

CI contract tests parse YAML with the pinned dependency in `.github/scripts/requirements-ci.txt`. Install it into a virtual environment before running `.github/scripts/test-ci-contracts.py`. `.github/scripts/test-cleanup-tooling.py` exercises runtime rendering, installer checksum rejection, CLI workspace cleanup and the reconcile shell's tenant-only smoke configuration with offline stubs.

## Releases

Every `main` commit that passes its checks is published to the lab ECR automatically. Nothing then changes what ECS runs until a release moves it.

**Released images.** The images ECS runs are not in the tfvars. They live in the release inputs object, `s3://scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/release/inputs.json`, next to the state:

- `release.py` writes it after each successful Terraform step.
- `lab.sh` passes it to Terraform as `backend_images`.
- A cycle therefore always plans the task definitions the last release registered.

**One operation at a time.** `lab.sh up`/`down` and `release.py` share one lock, `release/lock.json`, created with a conditional write.

**What a release does.** `release.py deploy <commit>` (profile `sglab-release`, role `ScoutGridSydneyLabRelease`):

1. **Qualify.** Checks the commit's lab publication record, its ECR image, and its schema heads against the database. Equal heads with a different migration-catalog fingerprint (`migration_catalog_sha256`, a SHA-256 over every packaged migration's name and bytes) means an applied migration changed: the release is refused before anything changes. A fingerprint missing on either side (inputs or publications from before R5) is recorded as `unverified`. The worker's latest `tenant_schema_state` line must show no unready tenant and a supported range holding the database's tenant head; for a schema-neutral release, a failing line refuses the release.
2. **Stop and snapshot (schema-changing releases only).** Stops `api` and `worker`, then snapshots RDS as `scoutgrid-lab-release-<id>`.
3. **Migrator.** Terraform registers the candidate migrator task definition and nothing else.
4. **Migrate.** Runs the candidate migrator once; it must exit 0.
5. **Runtime.** Terraform moves `api` and `worker` to the candidate and nothing else. ECS's circuit breaker rolls back a rollout that never becomes healthy.
6. **Verify.** Checks that services settled, targets are healthy, `GET /api/auth/csrf` returns 200 and `GET /api/me` returns 401, and counts startup `ERROR` lines (informational). It then bakes for one scheduler cycle (six minutes from settling) and fails on:
   - any defined failure in the api or worker log: `outside this release's supported range`, `violates row-level security policy`, `Tenant-scoped background work failed`, or `Unhandled API error` (every HTTP 500);
   - worker progress: no `tenant_work_progress` line, or a minute where tenant work ran and none of it succeeded (`outcome=failing`);
   - worker schema state: no `tenant_schema_state` line, an unready tenant, or a supported range that excludes the database's tenant head (the 2026-11-15 `V23..V20` failure).

   An image built before these lines existed (before PRs R3 and R5) never logs them. For a deploy or rollback to such an image, pass `--no-progress-signal`; the record notes that the check was waived.
7. **Accept.** The release stays live and waits for `release.py accept`, which asks the browser checks in `config/release-browser-checks.json`. Use `--answers yyn… [--note TEXT]` to record answers the operator relayed; the record marks them as relayed. All passing makes the release the accepted one; any failure rejects it. A new deploy waits until the live release is accepted or rolled back. When the owner decides to skip the checks, `release.py accept --waive --note TEXT` accepts the release and records every check as waived, never as passed, with the note; `status` shows the accepted release as waived.

Each step is recorded in `release/records/<id>.json`. The bucket is versioned, so every state of a record is kept.

**When a step fails.** The inputs keep `pending`, so `lab.sh` refuses to run. Rerunning `deploy` for the same commit resumes it, because every step is idempotent. `release.py rollback` recovers.

**Rollback.** It moves `api` and `worker`, and the frontend when a release moved it, to the accepted release (after a failed or rejected one) or to the accepted release before it. It runs only when that image supports the current schema. The binary accepts exactly one tenant schema version. After a schema-changing release, recovery is fixing forward or restoring the pre-migration snapshot, never an older image.

`--note TEXT` records why. When the rollback verifies, it and the release it replaced each name the other: the replaced record gets `rolled_back`, with reason `recovered` for a failed or rejected release.
- **Restoring the exact accepted release** reuses that release's acceptance (CD plan §4.7), so nothing waits for `accept`.
- **Returning to the accepted release before it** is a change of accepted release, so it waits for `release.py accept`.

The phase 3 drill (CD plan) measured 12–13 minutes per rollback: about 5–6 minutes of Terraform apply and ECS rollout, then the six-minute bake.

**Result.** `deploy` and `rollback` print a JSON result (CD plan §4.4):

| Outcome | Meaning |
|---|---|
| `verified` | The release is live and passed its checks |
| `blocked` | Nothing live changed. Reason: `parked`, `awaiting_acceptance`, `schema_changed`, `schema_unverified`, `not_confirmed` or `refused`; `reconcile` adds `superseded` and `migrator_drift` |
| `failed` | A live step or check failed. Reason: `check_failed`, `step_failed`, `frontend_pending`, or later `recovered` |
| `needs_operator` | Reason: `unfinished`, `recovery_failed`, `frontend_unrecorded`, `schema_changed` or `no_target` |

`reconcile` also returns `verified` / `no_change` when the lab already runs the pair. The exit status is 0 only for `verified`; `reconcile` also exits 0 for `blocked` with one of its planned reasons (`parked`, `awaiting_acceptance`, `superseded`, `schema_changed`, `schema_unverified`, `migrator_drift`), because nothing changed by design.

### Paired releases (backend and frontend)

`release.py deploy <commit> --frontend` ships the backend and the scoutgrid.io frontend as one recorded transaction (CD plan §4.5). Run it from a clean checkout of that commit, with `VERCEL_TOKEN` set to a token for the `scout-frontend` project.

1. **Stage, before the lock.** The pinned Vercel CLI (`vercel@65.9.0`, through `npx`) pulls the production settings, runs `vercel build --prod` (including the bundle verification), and uploads with `vercel deploy --prebuilt --prod --skip-domain`. The deployment ID goes into the record. A staging failure changes nothing live. The staged URL sits behind Vercel authentication, so nothing is checked on it beyond its READY state.
2. **Backend.** Steps 1–6 above run unchanged, with the old frontend serving.
3. **Promote, under the lock.** Only after the backend verifies, scoutgrid.io is pointed at that exact deployment. The intent is saved before the call, because a failed call does not prove the domain didn't move. A retry or rollback reads the domain first.
4. **Paired checks.** scoutgrid.io serves the recorded deployment and answers 200, then the signed-in smoke runs again (when configured).
5. **Accept.** It records the pair. The accepted entry and the inputs carry `frontend.deployment_id`.

If promotion fails, the result is `failed` / `frontend_pending`. Rerun the same `deploy … --frontend`: it promotes the recorded deployment without repeating the migrator, the runtime rollout or the bake. A failed paired check enters recovery: `rollback` restores the accepted frontend first (backend N serves frontend N-1), then the backend, then reruns the paired checks.

**Start tracking the frontend once.** Before the first paired release, run `release.py adopt-frontend`. It records the deployment scoutgrid.io serves now as the accepted release's frontend, marked `adopted`. A rollback to a release with no recorded frontend leaves the frontend alone, unless a release moved it; then it stops with `frontend_unrecorded`.

**Vercel no longer promotes `main` by itself.** Since 2026-11-16, `scout-frontend` has `autoAssignCustomDomains = false`. A `main` merge still builds a production deployment, and PR previews are unchanged. But scoutgrid.io moves only when `release.py deploy … --frontend` (or `rollback`) promotes, so every frontend change ships as a paired release. `release.py status` shows `DIFFERS FROM INPUTS` if anyone promotes outside it. To undo, set the project's `autoAssignCustomDomains` back to `true` (Vercel API `PATCH /v9/projects/{id}`).

### Long releases and stale locks

**Run every release command under `caffeinate -i`.** A release takes 15–30 minutes. If the laptop sleeps mid-step, Terraform cannot release its state lock and the release stops:

```sh
echo yes | caffeinate -i env TERRAFORM=<terraform 1.13.5> python3 release.py deploy <commit>
```

On 2026-11-16 the laptop slept during a deploy, after its migrator step and during the runtime plan. That left a stale Terraform plan lock.

**Two locks.**
- `release/lock.json` is the release lock, shared with `lab.sh`. `release.py status` shows it and `release.py unlock` clears it.
- `standard/lab/terraform.tfstate.tflock` is Terraform's S3 state lock. `release.py` cannot clear it.

**Clearing a stale Terraform lock.** Unlock only after proving all four of these:
1. **It is a plan lock.** `aws s3 cp s3://scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/terraform.tfstate.tflock -` shows `"Operation": "OperationTypePlan"`. Note its `ID` and `Created`.
2. **Nothing is running.** `pgrep -fl 'terraform|release.py'` prints nothing.
3. **The state hasn't changed since the last recorded step.** The `LastModified` of `standard/lab/terraform.tfstate` is not later than the last step in the release record. The live task definitions (`aws ecs describe-services --cluster scoutgrid-lab --services api worker`) match that step.
4. **The release lock is free**, or is held only by the stopped release. `release.py status` shows it.

Terraform cannot read the `aws login` source profile, so export the release role's credentials first:

```sh
cd prototype-app/infrastructure/terraform/standard
eval "$(aws configure export-credentials --profile sglab-release --format env)"
AWS_REGION=ap-southeast-2 <terraform 1.13.5> force-unlock -force <ID>
```

Then rerun the same `release.py deploy <commit>` (or `rollback`). It resumes from the record and skips a migrator that already exited 0. A step that fails before Terraform applies anything, such as a DNS failure while refreshing, is recorded as `failed` with no steps and changes nothing. Check `release.py status`, then rerun.

### Signed-in smoke

`frontend/e2e/lab-smoke.mjs` signs in through the real Cognito managed login (lab MFA is off) and checks **writes**, not just page loads. The `c013bd7` pages loaded while every platform-scope write failed. `release.py verify` runs it after the bake when `LAB_SMOKE_CONFIG` names its config file. Without that variable, the release records the smoke as not configured, a detection gap, and does not block.

What it checks:
- **Platform owner, no workspace:** sign-in; Platform Audit, End-of-Life, the Vulnerability Repository dashboard and the feeds pages load with no API 5xx or managed-session 403; reject one and delete one disposable demo request (the 2026-11-15 `audit_events` failure); sign-out.
- **Tenant admin:** enters the workspace; Findings loads; an invite to `delivered+smoke@resend.dev` reaches `SENT` (Resend accepted it), then is cancelled; sign-out.

The demo requests come from `POST /api/platform/demo-requests/smoke-fixtures`: platform-owner only, at most five pending, `.invalid` addresses, audited. The route answers 404 unless `enable_smoke_fixtures` is set, and Terraform refuses that flag in production. The common runtime configuration sets it for the lab api; the next `release.py deploy` registers it. Until then `lab.sh` plans show the api and worker task-definition change and refuse, as for any env change.

Privacy (public repository): it records no trace, screenshot, video, HAR or storage state, prints only check names and statuses, and runs without AWS credentials. No workflow runs it directly. The one workflow that may give release.py a config is the manual lab reconcile (below): tenant part only (owner decision S1), written to a private temporary file that is removed afterwards, never printed or uploaded. `.github/scripts/test-ci-contracts.py` enforces all of this.

Setup, once. This is how the lab's smoke workspace was set up on 2026-11-16 (see the lab record for its identifiers):
1. **Tenant admin: a dedicated Standard workspace** (`Working Knowledge/AWS/STANDARD_IMPLEMENTATION_READINESS.md`, A10/P10).
   1. Submit a demo request at `https://scoutgrid.io/demo/request` for the admin's address, then approve it in **Platform → Demo Requests**. It stays `QUEUED`, which is expected. The lab uses `delivered+smoke-admin@resend.dev`, Resend's test address: app email to it is accepted and discarded.
   2. As the **migration operator** (`sglab-migration`), under the release lock, run the migrator with `--provision-standard-request <request-id>` and confirm `standard_tenant_activated`. The request ID is the workspace UUID. That role's `RunOnlyReviewedMigratorRevision` grant names one migrator revision (`grants/migration-operator.json`), so re-pin it after a release registers a new one. The task must carry the tag `ReleasePurpose=Migration`.
   3. As the **identity operator** (`sglab-identity`), create the Cognito user with `AdminCreateUser`, `MessageAction=SUPPRESS`, `email_verified=true` and a generated temporary password. Write the password straight into the config file, never to output. The identity role cannot set a permanent password.
   4. Run the migrator with `--link-standard-admin <request-id> <cognito-sub>` and confirm `standard_admin_link_verified`.
   5. Sign in once by hand at `https://scoutgrid.io` with the temporary password. Choose the permanent one and put it in the config.
2. **Platform owner.** Today there is no operator path to bind a *second* managed platform owner: managed operator enrollment only runs on a fresh installation. Until one exists, either use your own platform-owner account in the local config, or leave `platform` out and accept the gap for platform writes (the restricted-role ITs still cover them before merge). `email` is the address you sign in with, not a username. Adding a binding command is a separate, reviewed migrator change.
3. Keep the config **outside the repository** (the lab uses `~/.config/scoutgrid/lab-smoke.json`, mode 0600, from `config/lab-smoke.example.json`). Lab MFA is off, so treat the file as a credential.
4. In `prototype-app/frontend`, run `npm ci` and `npx playwright install chromium`.
5. Run it once without a release: `node prototype-app/frontend/e2e/lab-smoke.mjs --config <file>`. Then export `LAB_SMOKE_CONFIG=<file>` before `release.py deploy`.

The smoke fetches a fresh CSRF token for every write, as the app does; a reused token is rejected after the first write. It waits up to 90 seconds for the invite to reach `SENT`, because the worker's outbox submits it every five seconds.

**Release alarms (off until enabled).** `release_alarms_enabled` in Terraform adds, independently of `operations` and its audit stack: SNS topic `scoutgrid-lab-release`, log metric filters for worker progress and the defined failures above, and five alarms: API or worker defined failures, tenant work failing for ten minutes, API without a running task for three minutes, and a running worker without succeeding tenant work for fifteen minutes. They read fixed names only, so `lab.sh` cycles plan no change to them, and they stay OK while the lab is parked. To enable, in order:

1. Attach managed `ScoutGridSydneyLab-release-alarms-read` (`grants/release-alarms-read.json`) to the Cycle, Release and Apply roles. Without it, every `lab.sh` plan fails once the alarms exist.
2. Set `release_alarms_enabled = true` in `config/sydney-lab.foundation.tfvars`, and run one targeted Bootstrap apply (with `grants/bootstrap-release-alarms.json` attached) of `aws_sns_topic.release_alarms`, `aws_sns_topic_policy.release_alarms`, `aws_cloudwatch_log_metric_filter.release`, `aws_cloudwatch_metric_alarm.release`, `aws_cloudwatch_metric_alarm.release_api_unavailable` and `aws_cloudwatch_metric_alarm.release_worker_progress_stale`. Then `lab.sh plan-up` must report no changes.
3. Subscribe the owner's address out of band, so it is not in this public repository: `aws sns subscribe --topic-arn <output release_alarms.topic_arn> --protocol email --notification-endpoint <address>`, then confirm the email.
4. Prove delivery: `aws cloudwatch set-alarm-state --alarm-name scoutgrid-lab-release-worker-fatal-errors --state-value ALARM --state-reason "delivery test"` must reach the inbox. Record the time.

Undo: set it back to `false` and apply the same targets (the topic, filters and alarms are deleted; no data depends on them).

**Runtime-only eligibility (read-only).** `release.py check <commit>` reports whether the commit would be a proven schema-neutral, runtime-only release (CD plan §4.3), as `eligible`, `blocked` or `needs_operator` with reasons: `parked`, `awaiting_acceptance`, `schema_changed` (heads), `schema_unverified` or `schema_changed` (catalog fingerprint), `schema_unverified` (no or failing live schema state), `migrator_drift`. For drift, it plans the migrator task definition with the **retained** migrator digest from the inputs, so run it from a checkout of the candidate commit. Any change means the migrator's configuration moved, not merely that a new image exists. It takes no lock and changes nothing; `deploy` stays the only way to release.

Seed the inputs once from what the lab runs: `release.py init <full commit> <platform head> <tenant head>`.

### Reconcile: the runtime-only path (manual)

`release.py reconcile [--frontend] [--yes]` is the manual reconcile action (CD plan §4.4, phase 4 slice 2). It changes the lab only through the **runtime-only path**: it never plans, registers or runs the migrator, stops the services or takes a snapshot. Schema-changing releases, `rollback`, `accept` and `unlock` stay owner-run with the Release role.

Under the shared lock, in this order:
1. **Resume first.** A pending `reconcile` release is resumed at its recorded commit. Any other unfinished release (a `deploy` that ran its migrator, a `rollback`) returns `needs_operator` / `unfinished`; resume it locally with the command that started it. Nothing new is chosen while anything is unfinished.
2. **Choose `main`'s head**, once it has a lab publication. Not yet published (checks running or failed), or this checkout is not that commit: `blocked` / `superseded`, nothing changed.
3. **Recheck eligibility** exactly as `check` does: `parked`, `awaiting_acceptance`, `schema_changed`, `schema_unverified`, `migrator_drift`, each `blocked` with nothing changed.
4. **Already live:** when the runtime was released from this commit with this image (and, with `--frontend`, the tracked frontend comes from it too): `verified` / `no_change`.
5. **Runtime-only rollout:** the runtime plan (api/worker task definitions and services only), verify, bake and signed-in smoke. With `--frontend`, the frontend is staged before the lock and promoted after the backend verifies, then the paired checks, as for `deploy --frontend`. A failed promotion is `failed` / `frontend_pending`; reconcile again to promote it.
6. **Stop at `verified`**, waiting for `release.py accept` locally. Rollback recovers a failed reconcile as it does a deploy.

`deploy` refuses to resume a pending `reconcile`, so the full path's migrator can never run on a runtime-only release. Run `reconcile` from a clean checkout of the commit it releases. `--yes` skips only the prompt, after every check. With `LAB_RELEASE_PROFILE` set empty, release.py uses the ambient credentials (a runner's OIDC session); the account, region and Terraform-version guards are unchanged.

The result names the outcome, reason and phase, the candidate and release, the live backend and frontend, the acceptance state, the record and the next manual action.

**In GitHub Actions:** `.github/workflows/lab-reconcile.yml`, `workflow_dispatch` only (inputs `frontend`, default true, and `confirm`, which must be `reconcile`), on `main` only, in environment `aws-standard-lab-release`, one run at a time (`lab-release`, never cancelled). It assumes `scoutgrid-lab-github-release` (`terraform/standard/release-iam.tf`) and runs `release.py reconcile --yes [--frontend]`. The job summary shows the result. A green run is never acceptance.

The role is a strict subset of the Release role: register, tag and retire api/worker task definitions, pass the api/worker roles, update the two services, read target health and api/worker logs, and keep the release inputs, records and lock, plus the four read policies Terraform's plan needs. It explicitly denies RunTask/StopTask, the migrator family and role, RDS snapshots and changes, secret values, IAM writes, and deleting anything but the release lock and Terraform's state lock. `ecs:DeregisterTaskDefinition` cannot be scoped, so the role could retire a migrator revision; that is an accepted gap. See the [design](<../../Working Knowledge/CI Pipeline/phase4-slice2-design.md>) for the accepted risk.

**Enabling it (done 2026-11-16 except the `VERCEL_TOKEN` secret; see the lab record "Reconcile rollout"):**
1. **Grants first.** Publish `ScoutGridSydneyLab-common-read-state-part2` v3 (`grants/common-read-state-part2.json` adds the new role), keeping v2 for rollback. Without it, every `lab.sh plan-up` fails once the role exists.
2. **Environment.** Create `aws-standard-lab-release` with deployment branches `main` only and no required reviewer (owner decision S3). Add the secrets `VERCEL_TOKEN` (a separate team-scoped token, S2) and, optionally, `LAB_SMOKE_TENANT_CONFIG` (the smoke config **without** `platform`, S1; the workflow refuses one with it), and the variable `AWS_LAB_RELEASE_ROLE_ARN` = `arn:aws:iam::736486260824:role/scoutgrid-lab-github-release`.
3. **Role.** Attach `grants/bootstrap-github-release-role.json` inline to Bootstrap. Set in `config/sydney-lab.foundation.tfvars`:
   ```hcl
   github_releaser = {
     provider_arn = "arn:aws:iam::736486260824:oidc-provider/token.actions.githubusercontent.com"
     subject      = "repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/main"
   }
   ```
   Run one targeted Bootstrap apply of `aws_iam_role.github_releaser`, `aws_iam_role_policy.github_releaser` and `aws_iam_role_policy_attachment.github_releaser`. Then `lab.sh plan-up` must report no changes. Detach the Bootstrap grant.
4. **Simulate** with `aws iam simulate-principal-policy` on the new role. Allowed: api/worker `RegisterTaskDefinition` (with the required tags) and `UpdateService`. Denied: migrator `RegisterTaskDefinition`, `RunTask`, `CreateDBSnapshot`, `GetSecretValue`, `PassRole` on the migrator execution role, `DeleteObject` on the inputs. Record the results in the lab record.
5. **Prove the denials in GitHub:** a dispatch from another branch is refused, and a run outside the environment cannot assume the role.
6. **First reconcile:** dispatch on `main`. Expect `verified` / `no_change` when `main` is the accepted pair, otherwise a runtime-only paired release. Record it, then `release.py accept` locally.

Undo: set `github_releaser = null` and apply the same targets (the role and its policies are deleted; nothing depends on them), or simply delete the environment so the workflow cannot assume it.

Run the tests locally with:

```
bash prototype-app/infrastructure/lab/scripts/tests/lab.test.sh
python3 -I prototype-app/infrastructure/lab/scripts/tests/test_release.py
shellcheck prototype-app/infrastructure/lab/scripts/*.sh prototype-app/infrastructure/lab/scripts/tests/*.sh
```
