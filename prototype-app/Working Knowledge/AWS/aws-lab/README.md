# ScoutGrid AWS lab (Sydney)

One folder for everything about the Sydney application lab: how to run it, the corrected IAM grants, the exact lab configuration, and the evidence from the November 12, 2026 run. Production fixes are listed in [FINDINGS.md](FINDINGS.md).

**Status at 16:30 UTC, November 12, 2026:** the lab is **running**. The owner signed in as platform owner and as the SG Internal administrator. There is no cleanup deadline. Billable runtime costs about USD 0.30 per hour until lab-down.

## Environment

| Item | Value |
|---|---|
| Account / region | `736486260824` / `ap-southeast-2` (Sydney) |
| Source candidate | `0ae3de9f4e4f7b1f784622d31656f30a89499043` (main after PR #70) |
| Backend image | `736486260824.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend@sha256:e0477a842367866505e469c7dc97aef77759fce5febf3a59d10d49acbe3a3ad5` |
| Frontend | Amplify app `d20ebk72hfk5ft`, branch `lab`, https://lab.scoutgrid.io |
| API | https://api-lab.scoutgrid.io/api (ALB `scoutgrid-lab-api`, WAF with 2 AWS managed rule sets) |
| Cognito | pool `ap-southeast-2_fPdRmnVqM` (Essentials tier), browser client `7egknl0kls1dkrkk3fmvcioev1`. **MFA OFF** for platform and tenant sign-in since 16:37:39 UTC, November 12, by owner decision. Set by `cognito_mfa_configuration = "OFF"` in `config/sydney-lab.foundation.tfvars`. The Terraform default is also `OFF`, so production gets MFA off too (owner decision). |
| Database | RDS `scoutgrid-lab`, PostgreSQL 16.15, db.t4g.medium, 100 GB gp3, private, deletion protection on |
| Terraform state | `s3://scoutgrid-lab-tfstate-736486260824-ap-southeast-2/standard/lab/terraform.tfstate` |
| Operators | Platform owner `scoutgrid.io@gmail.com`; SG Internal admin `scoutgridtenant@gmail.com` |

## What stays between runs and what goes

The owner chose to keep the low-cost layer between runs. Expect roughly USD 20 per month while the lab is down, mostly stopped-database storage (100 GB).

| Kept | Removed at lab-down, recreated at lab-up |
|---|---|
| VPC, subnets, security groups and rules | ECS services `api` and `worker` |
| Cognito pool and both operator accounts | ALB, listener, rule, target group |
| Secrets (`scoutgrid-lab/runtime-db`, `application-settings`, `managed-installation`) | WAF web ACL and association |
| KMS keys, S3 buckets, ECR image, Terraform state | NAT gateway, Elastic IP, task egress routes |
| Amplify app, `lab.scoutgrid.io` domain, both ACM certificates | RDS is **stopped**, not deleted |
| Task definitions, runtime roles, log groups, ECS cluster | |

> **RDS restarts by itself 7 days after it is stopped.** Stop it again or delete it if the next run is more than 7 days away.

## What the owner does for each run

1. Sign in for the AWS CLI: `aws login --profile scoutgrid-lab --region ap-southeast-2`. Choose account `736486260824`, never production.
2. Ask for **lab up**: start RDS, apply NAT, ALB, WAF and services, then wait for health checks. This takes about 20–30 minutes.
3. **DNS:** the new ALB gets a new hostname, so the `api-lab` CNAME needs updating. That is automatic if the Cloudflare connection has *Zone Read* and *DNS Edit*. Otherwise update it in Cloudflare, set to **DNS only**.
4. Sign in with your existing passwords and authenticator. No new invitations are needed.
5. Ask for **lab down** when finished.

One-time, before the next run:
- Merge the fix PR described in [FINDINGS.md](FINDINGS.md).
- Re-authorize the run's spend window.
- Optionally give the Cloudflare MCP connection DNS Edit permission.

## Lab-up order (proven November 12)

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

Steps 4–9 use `config/runtime-stopped.auto.tfvars` (services stopped, enrollment pinned), then `runtime-noenroll.auto.tfvars`, then `runtime-running.auto.tfvars`.

### Frontend build settings (lab)

```
VITE_API_BASE=https://api-lab.scoutgrid.io/api
VITE_MANAGED_BROWSER_AUTH_ENABLED=true
VITE_DURABLE_BOM_UPLOADS_ENABLED=true
VITE_TURNSTILE_SITE_KEY=0x4AAAAAAF9qZ1T6AfbbM6kS   # public site key
```

Build with Node 24 (`engines.node = 24.x`): `tsc -b --force && vite build && node scripts/verify-production-bundle.mjs`. The November 12 bundle is `evidence/2026-11-12/claude-takeover/frontend-lab-0ae3de9.zip` (SHA-256 `c1ae294a47ac0ca2d2a3bad872e8d460e6420708ad52731b2f1a8bc64059050d`).

## Lab deviations from the reviewed candidate (still live)

- API runs `scoutgrid-lab-api:2`: revision 1 plus `HTTP_OUTBOUND_ALLOWED_HOSTS` with the Cognito login domain and `cognito-idp.ap-southeast-2.amazonaws.com`. See `config/api-td2-request.json`.
- API service health-check grace is 300 s. Terraform sets 120 s.
- `api` and `worker` were created by CLI from Terraform-planned parameters (`config/create-service-*.json`) and then imported into state.
- `scoutgrid-lab-migrator:1` is still registered, but its execution role can no longer read the enrollment secret.

## Folder map

| Path | Contents |
|---|---|
| `FINDINGS.md` | Defects and gaps found by the lab, with the production fix for each |
| `grants/` | Every IAM grant used or corrected in the run. `teardown-lab-down.PROPOSED-NOT-ATTACHED.json` is pending owner approval. |
| `config/` | Lab tfvars per stage, service create requests, task-definition change, migrator request, saved MFA config |
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
terraform plan -var-file="$CFG/sydney-lab.foundation.tfvars" -var-file="$CFG/runtime-running.auto.tfvars"
```

Expected plan while the lab deviations above are live: `api` and `worker` services update (revision and grace differences), the migrator task definition is replaced, and Amplify headers update (finding 5). Anything else is unexpected and must be investigated before applying. The `sglab-*` profiles in `~/.aws/config` assume the scoped `ScoutGridSydneyLab*` roles from the `scoutgrid-lab` sign-in profile.

No Terraform state, plan files, credentials or secret values are stored here. Gitleaks 8.30.1 found only false positives: KMS `CurrentKeyMaterialId` values and a file SHA-256.
