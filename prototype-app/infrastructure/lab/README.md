# Sydney lab operations

Runnable tooling for the Sydney AWS lab, ScoutGrid's only environment (account `736486260824`, `ap-southeast-2`). It drives the Terraform in [`../terraform/standard`](../terraform/standard).

| Path | Contents |
|---|---|
| `scripts/lab.sh` | Lab up, down, status, plan-only and IAM simulation |
| `scripts/release.py` | Backend releases: move the lab to a published `main` commit, roll back, show release status |
| `scripts/tests/lab.test.sh` | Offline tests for `lab.sh` failure handling; AWS, Terraform and Cloudflare are stubbed. CI runs it. |
| `scripts/tests/test_release.py` | Offline tests for `release.py` against a fake lab. CI runs it. |
| `scripts/bootstrap-sydney-state.sh` | Creates or verifies the encrypted Terraform state bucket |
| `scripts/sydney-plan-role-*.json` | Trust and permission policy for the read-only plan role |
| `config/` | Lab tfvars per stage, the S3 backend config, the post-release browser checks, and captured service and task-definition requests |
| `grants/` | Every IAM grant used or corrected in the lab, with the [cycle matrix](grants/LAB_CYCLE_MATRIX.md) |

How to run the cycle, the budget rule and the lab's history are in the [lab record](<../../Working Knowledge/AWS/aws-lab/README.md>) and [findings](<../../Working Knowledge/AWS/aws-lab/FINDINGS.md>). Evidence from the lab runs stays there too.

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
7. **Accept.** The release stays live and waits for `release.py accept`, which asks the browser checks in `config/release-browser-checks.json`. Use `--answers yyn… [--note TEXT]` to record answers the operator relayed; the record marks them as relayed. All passing makes the release the accepted one; any failure rejects it. A new deploy waits until the live release is accepted or rolled back.

Each step is recorded in `release/records/<id>.json`. The bucket is versioned, so every state of a record is kept.

**When a step fails.** The inputs keep `pending`, so `lab.sh` refuses to run. Rerunning `deploy` for the same commit resumes it, because every step is idempotent. `release.py rollback` recovers.

**Rollback.** It moves only `api` and `worker`, to the accepted release (after a failed or rejected one) or to the accepted release before it, and only when that image supports the current schema. The binary accepts exactly one tenant schema version. After a schema-changing release, recovery is fixing forward or restoring the pre-migration snapshot, never an older image.

**Release alarms (off until enabled).** `release_alarms_enabled` in Terraform adds, independently of `operations` and its audit stack: SNS topic `scoutgrid-lab-release`, log metric filters for worker progress and the defined failures above, and five alarms: API or worker defined failures, tenant work failing for ten minutes, API without a running task for three minutes, and a running worker without succeeding tenant work for fifteen minutes. They read fixed names only, so `lab.sh` cycles plan no change to them, and they stay OK while the lab is parked. To enable, in order:

1. Attach managed `ScoutGridSydneyLab-release-alarms-read` (`grants/release-alarms-read.json`) to the Cycle, Release and Apply roles. Without it, every `lab.sh` plan fails once the alarms exist.
2. Set `release_alarms_enabled = true` in `config/sydney-lab.foundation.tfvars`, and run one targeted Bootstrap apply (with `grants/bootstrap-release-alarms.json` attached) of `aws_sns_topic.release_alarms`, `aws_sns_topic_policy.release_alarms`, `aws_cloudwatch_log_metric_filter.release`, `aws_cloudwatch_metric_alarm.release`, `aws_cloudwatch_metric_alarm.release_api_unavailable` and `aws_cloudwatch_metric_alarm.release_worker_progress_stale`. Then `lab.sh plan-up` must report no changes.
3. Subscribe the owner's address out of band, so it is not in this public repository: `aws sns subscribe --topic-arn <output release_alarms.topic_arn> --protocol email --notification-endpoint <address>`, then confirm the email.
4. Prove delivery: `aws cloudwatch set-alarm-state --alarm-name scoutgrid-lab-release-worker-fatal-errors --state-value ALARM --state-reason "delivery test"` must reach the inbox. Record the time.

Undo: set it back to `false` and apply the same targets (the topic, filters and alarms are deleted; no data depends on them).

**Runtime-only eligibility (read-only).** `release.py check <commit>` reports whether the commit would be a proven schema-neutral, runtime-only release (CD plan §4.3), as `eligible`, `blocked` or `needs_operator` with reasons: `parked`, `awaiting_acceptance`, `schema_changed` (heads), `schema_unverified` or `schema_changed` (catalog fingerprint), `schema_unverified` (no or failing live schema state), `migrator_drift`. For drift, it plans the migrator task definition with the **retained** migrator digest from the inputs, so run it from a checkout of the candidate commit. Any change means the migrator's configuration moved, not merely that a new image exists. It takes no lock and changes nothing; `deploy` stays the only way to release.

Seed the inputs once from what the lab runs: `release.py init <full commit> <platform head> <tenant head>`.

Run the tests locally with:

```
bash prototype-app/infrastructure/lab/scripts/tests/lab.test.sh
python3 -I prototype-app/infrastructure/lab/scripts/tests/test_release.py
shellcheck prototype-app/infrastructure/lab/scripts/*.sh prototype-app/infrastructure/lab/scripts/tests/*.sh
```
