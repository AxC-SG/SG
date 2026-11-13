# ScoutGrid AWS lab (Sydney)

One folder for everything about the Sydney application lab: how to run it, the corrected IAM grants, the exact lab configuration, and the evidence from the November 12, 2026 run. Production fixes are listed in [FINDINGS.md](FINDINGS.md).

**Status at 16:30 UTC, November 12, 2026:** the lab is **running**. The owner signed in as platform owner and as the SG Internal administrator. There is no cleanup deadline. Billable runtime costs about USD 0.30 per hour until lab-down.

**November 13, 2026 — the lab is the only ScoutGrid environment** ([plan](../LAB_SOLE_ENVIRONMENT_PLAN.md)). Render is being retired. The public Vercel site `https://scoutgrid.io` becomes the lab's single frontend origin, calling `https://api-lab.scoutgrid.io/api`. The cutover was applied on November 13 and the Amplify frontend at `lab.scoutgrid.io` was removed the same day (record: `evidence/2026-11-13/cutover-rollback.json`). The lab stays up for the week of November 13; `scripts/lab.sh` brings it up or parks it. While the lab is down, sign-in and the demo form on `scoutgrid.io` are offline. Do not onboard real customers onto the lab.

## Environment

| Item | Value |
|---|---|
| Account / region | `736486260824` / `ap-southeast-2` (Sydney) |
| Source candidate | `0ae3de9f4e4f7b1f784622d31656f30a89499043` (main after PR #70) |
| Backend image | `736486260824.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend@sha256:e0477a842367866505e469c7dc97aef77759fce5febf3a59d10d49acbe3a3ad5` |
| Frontend | Vercel project `scout-frontend`, https://scoutgrid.io (`www` redirects to the apex with a 308). The Amplify app `d20ebk72hfk5ft` and `lab.scoutgrid.io` were retired on November 13, 2026. |
| API | https://api-lab.scoutgrid.io/api (ALB `scoutgrid-lab-api`, WAF with 2 AWS managed rule sets) |
| Cognito | pool `ap-southeast-2_fPdRmnVqM` (Essentials tier), browser client `7egknl0kls1dkrkk3fmvcioev1`. **MFA OFF** for platform and tenant sign-in since 16:37:39 UTC, November 12, by owner decision. Set by `cognito_mfa_configuration = "OFF"` in `config/sydney-lab.foundation.tfvars`. The Terraform default is also `OFF`, so production gets MFA off too (owner decision). |
| Database | RDS `scoutgrid-lab`, PostgreSQL 16.15, db.t4g.medium, 100 GB gp3, private, deletion protection on |
| Terraform state | `s3://scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/terraform.tfstate` |
| Operators | Platform owner `scoutgrid.io@gmail.com`; SG Internal admin `scoutgridtenant@gmail.com` |

## What stays between runs and what goes

The owner chose to keep the low-cost layer between runs. Expect roughly USD 20 per month while the lab is down, mostly stopped-database storage (100 GB). Lab-down is `config/runtime-down.tfvars` (`start_services = false`, `runtime_ingress_enabled = false`, `nat_gateway_mode = "none"`).

| Kept | Removed at lab-down, recreated at lab-up |
|---|---|
| VPC, subnets, security groups and rules (including the ALB security group) | ECS services `api` and `worker` |
| Cognito pool and both operator accounts | ALB, listener, rule, target group |
| Secrets (`scoutgrid-lab/runtime-db`, `application-settings`, `managed-installation`) | WAF web ACL and association |
| KMS keys, S3 buckets, ECR image, Terraform state | NAT gateway, Elastic IP, task egress routes |
| API ACM certificate and its validation CNAME | RDS is **stopped**, not deleted |
| Task definitions, runtime roles, log groups, ECS cluster, the $100 budget alert | `api-lab` CNAME (removed at down, recreated at up) |

> **RDS restarts by itself 7 days after it is stopped.** Stop it again or delete it if the next run is more than 7 days away. `lab.sh down` prints the restart date.

## Budget operating rule (owner decision, November 13, 2026)

The lab ceiling is **USD 100 per month, inclusive**, measured as **gross usage before credits** (the budget alert and `lab.sh status` both exclude credits and refunds, so credits cannot mask consumption). `monthly_budget` in `config/sydney-lab.foundation.tfvars` creates an AWS Budgets alert at that amount (80% actual and 100% forecast, emailed to the owner). It is an alert, not a cap, and Cost Explorer data lags usage by hours.

- **Before a week-long run:** month-to-date actual + days up × about USD 7 + remaining days down × about USD 0.70 + 20% contingency must be ≤ USD 100. Otherwise plan a shorter run.
- **Responder:** the owner. Claude runs `lab.sh status` at the start of every working session on the lab.
- **Shutdown trigger:** month-to-date ≥ USD 80, or projected month-end > USD 100. Run `lab.sh down` the same day. `lab.sh status` prints a warning when either is true.

## Lab up and lab down (`scripts/lab.sh`)

1. Sign in for the AWS CLI: `aws login --profile scoutgrid-lab --region ap-southeast-2`. Choose account `736486260824`, never production.
2. Run `scripts/lab.sh status` to see RDS, services, ALB, NAT, DNS and cost against the budget rule.
3. **Up** (about 20–30 minutes): `scripts/lab.sh up`. It starts RDS, plans `sydney-lab.foundation.tfvars` + `runtime-running.tfvars`, refuses anything outside the up allowlist, asks you to type `yes`, applies, waits for a healthy API target, points `api-lab` at the new ALB and smoke-tests `/api/auth/csrf`.
4. **Down** (about 10–15 minutes): `scripts/lab.sh down`. It first simulates every lab-up permission (so the lab is never parked by a role that cannot bring it back), plans `runtime-down.tfvars`, asks for `yes`, applies, removes the `api-lab` CNAME and stops RDS.
5. `scripts/lab.sh plan-up` and `plan-down` produce and check the plan without applying. `scripts/lab.sh simulate [up|down]` runs only the IAM simulation.

Requirements: Terraform 1.13.5; profile `sglab-cycle` for role `ScoutGridSydneyLabCycle` ([matrix](grants/LAB_CYCLE_MATRIX.md), attached November 13); a Cloudflare token limited to DNS Edit on `scoutgrid.io` saved with `security add-generic-password -s scoutgrid-cloudflare-dns -a scoutgrid -w`. Without the token the script prints the DNS record to set by hand.

The script never changes task definitions, data, identity or foundation resources. A plan that wants any of those stops with REFUSED and goes through the reviewed Bootstrap or Apply path instead.

## First build order (proven November 12, historical)

1. Foundation: network, keys, RDS, Cognito, Amplify, ECR, S3. This exists and is kept.
2. Secrets under scoped custody. These exist and are kept.
3. Publish the exact backend image to ECR (digest above).
4. Runtime security-group rules, ECS cluster and log groups: **Apply** role.
5. Runtime roles and task definitions: **Bootstrap** role.
6. ALB, HTTPS listener (TLS 1.3), `/api/*` host rule, target group, WAF: **Apply** role.
7. One-time database setup with the migrator task: **Migration** role. Platform V15, tenant V20, exactly one SG Internal tenant. A rerun is a no-op.
8. Remove the migrator's enrollment-secret access: **Bootstrap** role.
9. Start `api` and `worker`: **Service** role.
10. Frontend: build with the settings below, then deploy with `CreateDeployment`/`StartDeployment` (**Frontend** role) and connect the domain.
11. DNS: `api-lab` → ALB, `lab` → Amplify CloudFront, plus the ACM validation CNAMEs. All DNS only.
12. Sign in as platform owner, then as SG Internal.

Steps 4–9 used `config/runtime-stopped.tfvars` (services stopped, enrollment pinned), then `runtime-noenroll.tfvars`, then `runtime-running.tfvars`. These were `*.auto.tfvars` until November 13; they are now passed only with explicit `-var-file`.

### Frontend build settings (Vercel production after the cutover; Amplify lab before it)

```
VITE_API_BASE=https://api-lab.scoutgrid.io/api
VITE_MANAGED_BROWSER_AUTH_ENABLED=true
VITE_DURABLE_BOM_UPLOADS_ENABLED=true
VITE_TURNSTILE_SITE_KEY=0x4AAAAAAF9qZ1T6AfbbM6kS   # public site key
```

In Vercel these are Production environment variables of `scout-frontend`. Preview deployments (`*.vercel.app`) cannot sign in: the API accepts exactly one browser origin. Build with Node 24 (`engines.node = 24.x`): `tsc -b --force && vite build && node scripts/verify-production-bundle.mjs`. The November 12 bundle is `evidence/2026-11-12/claude-takeover/frontend-lab-0ae3de9.zip` (SHA-256 `c1ae294a47ac0ca2d2a3bad872e8d460e6420708ad52731b2f1a8bc64059050d`).

## Lab deviations from the reviewed candidate (still live)

- API runs `scoutgrid-lab-api:2`: revision 1 plus `HTTP_OUTBOUND_ALLOWED_HOSTS` with the Cognito login domain and `cognito-idp.ap-southeast-2.amazonaws.com`. See `config/api-td2-request.json`. Terraform now sets the same list (PR #73); the cutover apply reconciles it.
- API service health-check grace is 300 s. Terraform now also sets 300 s (PR #73).
- `api` and `worker` were created by CLI from Terraform-planned parameters (`config/create-service-*.json`) and then imported into state.
- `scoutgrid-lab-migrator:1` is still registered, but its execution role can no longer read the enrollment secret.

## Folder map

| Path | Contents |
|---|---|
| `FINDINGS.md` | Defects and gaps found by the lab, with the production fix for each |
| `grants/` | Every IAM grant used or corrected in the run. `LAB_CYCLE_MATRIX.md`, `lab-cycle.json` and `lab-cutover-once.json` were attached on November 13 with owner approval; they supersede `teardown-lab-down.PROPOSED-NOT-ATTACHED.json`. |
| `config/` | Lab tfvars per stage (`runtime-running`, `runtime-down`, `runtime-noenroll`, `runtime-stopped`), service create requests, task-definition change, migrator request, saved MFA config |
| `scripts/lab.sh` | Lab up, down, status, plan-only and IAM simulation |
| `evidence/2026-11-12/recovery-status/` | Run log (`STATUS.md`, `OWNER_DECISION_20261112_1310Z.md`), cleanup sequence, access reviews |
| `evidence/2026-11-12/codex-run/` | Codex's run artifacts: preflight tools, readbacks, policy templates, recovered commands |
| `evidence/2026-11-12/claude-takeover/` | Frontend bundle, migrator run record |
| `evidence/2026-11-11-prep/` | November 11 preparation evidence (`integrated-lab-20261111`, `frontend-qualification-20261111`, `cd741250faf4`), moved here from `release-evidence/` |

## Running lab Terraform from this repo

Run all lab Terraform from `prototype-app/infrastructure/terraform/standard` in this repo, with Terraform **1.13.5** (the version that wrote the state). `.terraform/` is gitignored.

```
cd prototype-app/infrastructure/terraform/standard
CFG="../../../Working Knowledge/AWS/aws-lab/config"
eval "$(aws configure export-credentials --profile sglab-plan --format env)"   # or sglab-apply / sglab-bootstrap / sglab-service / sglab-teardown
terraform init -backend-config="$CFG/sydney-lab.s3.tfbackend" -lockfile=readonly
terraform plan -var-file="$CFG/sydney-lab.foundation.tfvars" -var-file="$CFG/runtime-running.tfvars"
```

Expected first plan after November 13 (the cutover): S3 imports CORS, the Cognito logout URL and invite link, new `api` and `worker` task-definition revisions (frontend origin, outbound hosts), the services rolling to them, the migrator revision, and the new budget. Anything else is unexpected and must be investigated before applying. Routine cycles use `scripts/lab.sh`. The `sglab-*` profiles in `~/.aws/config` assume the scoped `ScoutGridSydneyLab*` roles from the `scoutgrid-lab` sign-in profile.

No Terraform state, plan files, credentials or secret values are stored here. Gitleaks 8.30.1 found only false positives: KMS `CurrentKeyMaterialId` values and a file SHA-256.
