# Sydney lab operations

Runnable tooling for the Sydney AWS lab, ScoutGrid's only environment (account `736486260824`, `ap-southeast-2`). It drives the Terraform in [`../terraform/standard`](../terraform/standard).

| Path | Contents |
|---|---|
| `scripts/lab.sh` | Lab up, down, status, plan-only and IAM simulation |
| `scripts/tests/lab.test.sh` | Offline tests for `lab.sh` failure handling; AWS, Terraform and Cloudflare are stubbed. CI runs it. |
| `scripts/bootstrap-sydney-state.sh` | Creates or verifies the encrypted Terraform state bucket |
| `scripts/sydney-plan-role-*.json` | Trust and permission policy for the read-only plan role |
| `config/` | Lab tfvars per stage, the S3 backend config, and captured service and task-definition requests |
| `grants/` | Every IAM grant used or corrected in the lab, with the [cycle matrix](grants/LAB_CYCLE_MATRIX.md) |

How to run the cycle, the budget rule and the lab's history are in the [lab record](<../../Working Knowledge/AWS/aws-lab/README.md>) and [findings](<../../Working Knowledge/AWS/aws-lab/FINDINGS.md>). Evidence from the lab runs stays there too.

Run the tests locally with:

```
bash prototype-app/infrastructure/lab/scripts/tests/lab.test.sh
shellcheck prototype-app/infrastructure/lab/scripts/*.sh prototype-app/infrastructure/lab/scripts/tests/*.sh
```
