# Phase 4, slice 2: runtime-only release role and manual reconcile (design for approval)

Status: **approved and live 2026-11-16.** Code in #131 (with the #132 download fix). Rollout steps 1–6 done; the first reconcile, `20261116t160758z-e7f871c`, verified backend-only. Open: the environment's `VERCEL_TOKEN` (S2), so reconcile can release the frontend.

This slice touches the never-touch list: IAM (a new role) and `.github/workflows/` (a new workflow). It needs the owner's approval of this design and of the decisions in §6 before any code.

It implements CD plan [§4.3](cd-consolidation-plan.md#43-proven-neutral-releases-and-a-restricted-automatic-role) (a restricted automatic role), [§4.4](cd-consolidation-plan.md#44-explicit-outcomes-and-one-manual-reconcile-action) (one manual reconcile action) and [§5](cd-consolidation-plan.md#5-security-model) (security model).

**Phase 4 exit criteria this slice closes:**
- **Neutral mode cannot launch the migrator,** simulated and tested.
- **Parked, acceptance-outstanding and frontend-only retries** behave as §7 says.
- **A manual reconcile action exists.**

It does not enable automatic rollout. Phase 5 does that, only after the owner decides.

## 1. What changes

| Piece | Where | What |
|---|---|---|
| `release.py reconcile` | `infrastructure/lab/scripts/release.py` | Releases the newest eligible `main` commit through the **runtime-only path**, or resumes the interrupted release first. Prints the §4.4 result |
| Runtime-only path | same | Never plans, registers or runs the migrator; keeps the retained migrator digest. Used by `reconcile`; `deploy` keeps today's full path |
| Credentials without a profile | same | `LAB_RELEASE_PROFILE=` (empty) uses the ambient credentials, as on a runner. Account, region and Terraform-version guards are unchanged |
| Role `scoutgrid-lab-github-release` | `infrastructure/terraform/standard/release-iam.tf` | OIDC role for the workflow only. A strict subset of `ScoutGridSydneyLabRelease`, with explicit denies (§3) |
| Workflow `lab-reconcile.yml` | `.github/workflows/` | `workflow_dispatch` only, `main` only, a protected environment, one concurrency group. Runs `release.py reconcile --yes` |
| Tests | `scripts/tests/test_release.py`, `.github/scripts/test-ci-contracts.py` | Offline reconcile tests; workflow contract tests; IAM simulation evidence in the lab record |

## 2. `reconcile`: selection and runtime-only path

Under the shared lock, in this order:
1. **Resume first.** If `pending` names a release, resume it at its recorded commit, through the runtime-only path, and only if the record is neutral. A forward (schema-changing) or migrator-phase pending returns `needs_operator`. No new candidate is chosen while anything is unfinished (§4.4).
2. **Pick the candidate:** the current `main` head that has a lab publication record. If the head's checks are still running, return `blocked` / `superseded` and change nothing.
3. **Recheck eligibility after taking the lock:** the same rules as today's read-only `check`.
   - parked lab → `blocked` / `parked`;
   - a release awaiting acceptance → `blocked` / `awaiting_acceptance`;
   - different heads or catalog → `blocked` / `schema_changed`;
   - a catalog that can't be compared, or no ready live schema state → `blocked` / `schema_unverified`;
   - a migrator task-definition change in the drift plan → `blocked` / `migrator_drift`.

   Any of these changes nothing.
4. **Same pair already live:** if the candidate's backend image *and* frontend are already what runs, return `verified` / `no_change` without a rollout.
5. **Runtime-only rollout:** no migrator plan, registration or task.
   - Terraform targets only the api/worker task definitions and services; the existing allowlist refuses anything else.
   - Then the full verify, bake and signed-in smoke.
   - With `--frontend`, the paired steps follow (stage → promote → paired checks), exactly as `deploy --frontend` does them.
6. **Finish** at `verified`, awaiting acceptance. Acceptance stays local (`release.py accept`), and the lock is never held while waiting.

**The guarantee, tested:** a test fake records every call and asserts that `reconcile` never calls `plan("migrator", …)`, `apply` on a migrator plan, or `run_migrator`, for every path: fresh, resume, blocked and failed. The IAM role then denies the same actions anyway (§3), so the code guarantee and the permission agree.

**Exit status:** 0 for `verified` and `blocked` (nothing changed, as designed). 1 for `failed` and `needs_operator`. The workflow summary always shows the outcome and reason, so a green run is never read as "accepted" (§4.8).

## 3. Role `scoutgrid-lab-github-release`

**Trust:** the account's GitHub OIDC provider, audience `sts.amazonaws.com`, and exactly this subject:

```
repo:AxC-SG@351325919/SG@1427276590:environment:aws-standard-lab-release:job_workflow_ref:AxC-SG/SG/.github/workflows/lab-reconcile.yml@refs/heads/main
```

The publisher keeps its own environment and subject, so neither role can be assumed by the other's workflow. `max_session_duration` is 3600; a paired release takes about 11–15 minutes.

**Allowed:** the subset of `LabRelease` that a runtime-only release needs.
- Register and tag task definitions in the **api and worker families only**.
- Deregister replaced api/worker revisions.
- `UpdateService` on the api and worker services.
- `PassRole` for the api/worker execution and application roles only. **Not** the migrator execution role.
- S3 read/write of the release inputs, records and lock.
- Log and target-health reads.
- The four shared read policies Terraform's plan needs: `common-read-state-part1`/`part2`, `waf-association-read`, `cycle-watch`. Before attaching them, re-read them to confirm none grants secret values or write access.

**Explicitly denied:** belt and braces, even though nothing allows them.
- `ecs:RunTask` and `ecs:StopTask`;
- `ecs:RegisterTaskDefinition` on the migrator family;
- `iam:PassRole` on the migrator execution role;
- `rds:CreateDBSnapshot`, `rds:RestoreDBInstance*`, `rds:Modify*`, `rds:Delete*`;
- `secretsmanager:GetSecretValue` on every secret;
- `iam:*` writes;
- `s3:DeleteObject` outside `release/lock.json`.

**Accepted risk** (§5, unchanged): ECS cannot constrain the content of a registered task definition. A malicious change merged to `main` could register an api task that runs a different lab ECR image. The mitigations:
- only `main` (reviewed PRs) runs the workflow;
- release.py's plan allowlist;
- images come only from the lab ECR;
- no secret values or migrator authority.

**Creation:** Terraform (`var.github_releaser`, `count` 0 until set), applied by one targeted Bootstrap apply with a new grant file `grants/bootstrap-github-release-role.json`, in the same pattern as the publisher.

## 4. Workflow `lab-reconcile.yml`

- **Trigger:** `workflow_dispatch` only, with inputs `frontend` (boolean, default true) and `confirm` (must equal `reconcile`). There are no push, PR or schedule triggers; automatic dispatch hooks are phase 5.
- **Job guard:** `if: github.ref == 'refs/heads/main'`; environment `aws-standard-lab-release`, whose deployment branch policy is `main` only.
- **Concurrency:** `concurrency: { group: lab-release, cancel-in-progress: false }`.
- **Permissions:** `id-token: write`, `contents: read`, `actions: read` (to read publication records), nothing else. `permissions: {}` at the top.
- **Steps:**
  1. `actions/checkout` at the dispatched `main` SHA.
  2. Terraform 1.13.5 from releases.hashicorp.com, SHA-256 verified against a pinned checksum, with `-lockfile=readonly` as today.
  3. Node, then `npm ci` and Playwright Chromium in `prototype-app/frontend`, only when the smoke secret is present.
  4. `aws-actions/configure-aws-credentials`, pinned by commit SHA, with the role ARN from an environment variable.
  5. `release.py reconcile --yes [--frontend]`, with `LAB_RELEASE_PROFILE=` and `VERCEL_TOKEN` from an environment secret. If the smoke config secret exists, it is written to a 0600 file under `$RUNNER_TEMP` and deleted at the end.
  6. A job summary with the outcome JSON, the record key, and the next manual action.
- **Contract tests** (`test-ci-contracts.py`):
  - no trigger other than `workflow_dispatch`;
  - the job is guarded to `main`;
  - the environment name matches the IAM subject;
  - `cancel-in-progress: false`;
  - permissions as listed;
  - actions pinned by SHA;
  - the smoke config is never echoed or uploaded as an artifact.

## 5. Rollout (owner-run, after merge)

1. **Merge.** The role stays `count = 0`, and the workflow fails closed without its environment.
2. **Create the environment:** `aws-standard-lab-release`, deployment branches `main` only. Add the environment secrets agreed in §6 and the variable `AWS_LAB_RELEASE_ROLE_ARN`.
3. **Create the role:** attach `grants/bootstrap-github-release-role.json` to Bootstrap, set `github_releaser` in `sydney-lab.foundation.tfvars`, and run one targeted apply of the role and its policy. `lab.sh plan-up` must then report no changes.
4. **Simulate:**
   - allowed: api/worker register and update;
   - denied: migrator register, RunTask, snapshot, GetSecretValue, PassRole on the migrator role.

   Record the results.
5. **Prove the denials in GitHub:** a dispatch from a non-main branch is refused, and a run without the environment cannot assume the role.
6. **First reconcile:** dispatch on `main`. The expected result is `verified` / `no_change` if `main` equals the accepted pair, or a full runtime-only paired release. Record it, then accept locally.

## 6. Decisions for the owner

| # | Question | Recommendation |
|---|---|---|
| S1 | **Signed-in smoke in Actions.** The local config holds the owner's own platform-owner password, and lab MFA is off | Store **only the tenant part** (the dedicated smoke admin) as an environment secret. Platform-write checks stay in local releases until a second platform owner can be bound (a separate migrator change). Never put the owner's own password in GitHub |
| S2 | **Vercel token in Actions** | A **separate** team-scoped token as an environment secret, so it can be revoked independently of the operator's local token |
| S3 | **Environment protection** | Branch policy `main` only. No required reviewer: the owner is the only dispatcher, and self-review prevention would block them |
| S4 | **Exit status for `blocked`** | 0 (nothing changed; the summary shows the reason), as in §2 |
| S5 | **Order** | Build the code and tests first (one PR: release.py, Terraform at count 0, the workflow, tests). The rollout in §5 follows separately, each live step approved |

## 7. As built (2026-11-16)

The PR follows §1–§6 with these refinements, each found while building:

- **Terraform's own lock.** The lab backend uses S3 native locking (`use_lockfile`), which releases its lock by deleting `standard/lab/terraform.tfstate.tflock`. The deny on `s3:DeleteObject` therefore excepts that object as well as `release/lock.json`. Without it, every plan would leave a stale lock. It also denies `s3:DeleteObjectVersion`, bucket deletion, and bucket policy, versioning and lifecycle changes.
- **Deregistration cannot be scoped.** `ecs:DeregisterTaskDefinition` takes no resource-level permission (`grants/bootstrap-deregister-migrator.INEFFECTIVE-scoped-arn.json`), so the role keeps `Resource: "*"` as the Release role does. It could retire a migrator revision, but never register, pass or run one. Accepted, and recorded in the cycle matrix.
- **Re-reading the shared read policies** (§3). `common-read-state-part1/part2`, `waf-association-read` and `cycle-watch` grant no secret value; part2 denies `GetSecretValue`. Their only writes are the Terraform state object and its lock, which any apply needs.
- **Full lab plans must read the new role.** As after #107, `lab.sh plan-up` refreshes every role in state. `common-read-state-part2` v3 adds `scoutgrid-lab-github-release` to `ReadExactRuntimeRoleMetadata`. It must be published before the role is created (README rollout step 1).
- **"Already live" means the same commit, not only the same image.** `no_change` needs the runtime to have been released from the candidate commit with its image, so a merge that changes only task-definition configuration is still released. With `--frontend`, the tracked frontend must come from that commit too.
- **Which checkout.** Terraform renders from the checkout, so reconcile runs only from a clean checkout of the commit it releases. A new candidate in another checkout is `blocked` / `superseded`; a resume from another checkout is `needs_operator` / `unfinished`, because Actions can only run at `main`'s head. Resume such a release locally from its commit.
- **Which pending releases reconcile resumes.** Only its own: kind `reconcile`, mode neutral, no migrator steps. `deploy` refuses to resume a pending `reconcile`, so the full path can never run the migrator on a runtime-only release.
- **Exit status.** 0 for `verified` and for `blocked` with a planned reason (`parked`, `awaiting_acceptance`, `superseded`, `schema_changed`, `schema_unverified`, `migrator_drift`). A held lock, a refused publication or a missing confirmation stays 1.
- **The smoke contract.** `.github/scripts/test-ci-contracts.py` used to forbid `LAB_SMOKE_CONFIG` in every workflow. It now allows it only in `lab-reconcile.yml`, and only as a tenant-only config written to a private temporary file that is removed and never printed or uploaded. The workflow refuses a config with a `platform` part (S1).
- **Ambient credentials** keep the account guard. `LAB_RELEASE_PROFILE=` uses the runner's session. Terraform's environment never receives `VERCEL_TOKEN`.

**Tests:**
- `test_release.py`: 22 new tests. Every reconcile path (fresh, paired, resumed, each blocked reason, failed check, frontend retry, no change, foreign pending deploy, a held lock) is checked against a fake that records every call. None plans or applies the migrator, runs it, stops the services or snapshots.
- `integrated-lab.tftest.hcl` and `runtime.tftest.hcl`: the role's exact allowed actions, no allowed resource naming the migrator, the deny set, the four attachments, and rejected subjects (publisher workflow or environment, a branch, production).
- `test-ci-contracts.py`: the workflow contract in §4.
