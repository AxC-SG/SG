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

1. **Qualify.** Checks the commit's lab publication record, its ECR image, and its schema heads against the database.
2. **Stop and snapshot (schema-changing releases only).** Stops `api` and `worker`, then snapshots RDS as `scoutgrid-lab-release-<id>`.
3. **Migrator.** Terraform registers the candidate migrator task definition and nothing else.
4. **Migrate.** Runs the candidate migrator once; it must exit 0.
5. **Runtime.** Terraform moves `api` and `worker` to the candidate and nothing else. ECS's circuit breaker rolls back a rollout that never becomes healthy.
6. **Verify.** Checks that services settled, targets are healthy, `GET /api/auth/csrf` returns 200 and `GET /api/me` returns 401, and counts startup `ERROR` lines.
7. **Accept.** Asks the browser checks in `config/release-browser-checks.json`. All passing makes the release the accepted one; any failure rejects it.

Each step is recorded in `release/records/<id>.json`. The bucket is versioned, so every state of a record is kept.

**When a step fails.** The inputs keep `pending`, so `lab.sh` refuses to run. Rerunning `deploy` for the same commit resumes it, because every step is idempotent. `release.py rollback` recovers.

**Rollback.** It moves only `api` and `worker`, to the accepted release (after a failed or rejected one) or to the accepted release before it, and only when that image supports the current schema. The binary accepts exactly one tenant schema version. After a schema-changing release, recovery is fixing forward or restoring the pre-migration snapshot, never an older image.

Seed the inputs once from what the lab runs: `release.py init <full commit> <platform head> <tenant head>`.

Run the tests locally with:

```
bash prototype-app/infrastructure/lab/scripts/tests/lab.test.sh
python3 -I prototype-app/infrastructure/lab/scripts/tests/test_release.py
shellcheck prototype-app/infrastructure/lab/scripts/*.sh prototype-app/infrastructure/lab/scripts/tests/*.sh
```
