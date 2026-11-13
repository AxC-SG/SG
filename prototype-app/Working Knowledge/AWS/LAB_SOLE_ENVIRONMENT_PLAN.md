# Plan: retire Render, make the Sydney lab the only backend, Vercel as the only frontend

## Context
Render (`scout-backend`, free plan, Oregon) is the old pre-production backend. It has been in `update_failed` since Nov 8, so `api.scoutgrid.io` is already broken. The Sydney AWS lab is up and qualified for sign-in. The owner wants:
- Render removed completely.
- The public Vercel site (`scoutgrid.io`) pointed at the lab API.
- The lab's Amplify frontend (`lab.scoutgrid.io`) torn down.
- Cloudflare DNS reconciled.
- The lab as the only environment until production is planned after this week's testing.

The lab stays **up all week**. Lab-up and lab-down scripts must exist so it can be brought down at any time. Remind the owner on **2026-11-20** to decide next steps.

**Owner decisions (2026-11-13):**
- Frontend origin is `https://scoutgrid.io`.
- Lab spend ceiling rises to **$100/month**.
- Render database: take a final encrypted dump, then delete.
- **Vercel is the production frontend too**, so Amplify is deleted from Terraform.
- DNS is changed through a **scoped Cloudflare API token** stored in the macOS Keychain.

## Feedback on the approach (summary for the owner)
- **Sound overall.** Render adds nothing (its deploy is failing), and one environment cuts operational overhead. Keeping Vercel removes the Amplify work in A08 and the IAM friction behind lab finding 5 and the frontend grants.
- **The lab now carries the public site.** Whenever the lab is down, sign-in and the demo form on `scoutgrid.io` are offline. Marketing pages still load because they're static.
- **Don't onboard real customers onto the lab.** It has MFA off, single-AZ RDS, Sydney data location, a disposable posture and down cycles. Demo requests that arrive this week should be treated as test data or re-entered in production.
- **There can be only one origin.** While managed sign-in is on, the backend accepts exactly one frontend origin (`ManagedBrowserAuthController.java:38-46`). Vercel previews (`*.vercel.app`) can't sign in, and `www` must redirect to the apex.
- **Production will reclaim `scoutgrid.io`.** The lab will then need its own Vercel domain, such as `lab.scoutgrid.io` on a branch with lab build settings. That gets planned with production.
- **Lab-down can't be done with Terraform alone today.** NAT has no "none" mode, and the teardown grant is pinned to today's ALB and NAT IDs, which change at every lab-up. Both are fixed below.
- **The per-step IAM roles make scripting brittle** (FINDINGS: one deploy role per environment). The scripts use one reviewed lab cycle role, and the owner approves it before it's attached.
- **Timing:** lab-up takes about 20–30 minutes (RDS start 5–10, ALB 3–5, API cold start about 155 s). Lab-down takes about 10–15 minutes. RDS restarts by itself after 7 days stopped.

## Part A — repository changes (one PR, owner merges)

### A1. Terraform lab-down modes (`prototype-app/infrastructure/terraform/standard`)
- `main.tf` `nat_gateway_mode`: add `"none"`, rejected when `environment == "production"`. In `modules/standard-network`, `nat_zones`, the EIPs and the `task_egress` routes become empty for `none`.
- New variable `runtime_ingress_enabled` (default true; false rejected in production). It gates the ALB, listener, rule, target group, WAF and association in `ingress.tf` (`for_each = local.backend` becomes a filtered local). A validation requires `start_services = false` when ingress is off, because the API service references the target group.
- Task definitions, runtime roles, log groups, the ECS cluster, RDS, Cognito, S3, KMS, secrets and ECR stay put. This matches the README's "kept" list.
- `hosting.tf`: delete `aws_amplify_app.frontend`, `aws_amplify_branch.frontend` and `local.frontend_security_headers`. Keep the ECR repository. Drop `frontend_app_id` and `frontend_branch` from `output.release_targets`; the test at `tests/runtime.tftest.hcl:583-584` only checks region and registry.
- `budget.tf`: raise the lab cap validation from 50 to 100.
- Tests: new `tests/lab-cycle.tftest.hcl` (mocked):
  - The down configuration plans zero NAT, EIP, ALB, WAF and service resources while keeping task definitions and the cluster.
  - Production rejects `nat none` and ingress off.
  - The budget accepts 100 and rejects 101.
  - Update `integrated-lab.tftest.hcl:67` to `frontend_origin = https://scoutgrid.io`.

### A2. Lab configuration (`Working Knowledge/AWS/aws-lab/config/`)
- `sydney-lab.foundation.tfvars`: set `frontend_origin = "https://scoutgrid.io"` and `monthly_budget` to 100. The second is applied only if the budget is enabled in the lab.
- New `runtime-down.auto.tfvars`: the running settings with `start_services = false`, `runtime_ingress_enabled = false` and `nat_gateway_mode = "none"`.

### A3. Lab cycle role (proposed, not attached)
- `grants/lab-cycle.PROPOSED.json` generalizes the policies proven on Nov 12 from exact IDs to name and tag scopes:
  - `apply-runtime-ingress.json`, `service-operator-v2.json` and `teardown-lab-down.PROPOSED-NOT-ATTACHED.json`
  - the security-group-rule, ELB, WAF and `GetWebACLForResource` corrections listed in FINDINGS
- Scopes: `loadbalancer/app/scoutgrid-lab-api/*`, NAT and EIP by `Name=scoutgrid-lab-*` tag, RDS `db:scoutgrid-lab` start and stop, ECS `service/scoutgrid-lab/*`, the Terraform state bucket and lock, and Sydney only.
- Also includes one-time `amplify:DeleteApp`, `amplify:DeleteBranch` and `amplify:DeleteDomainAssociation` on app `d20ebk72hfk5ft`.
- New `sglab-cycle` profile in `~/.aws/config`.
- Validate with IAM Access Analyzer and simulate before attaching.

### A4. Scripts (`Working Knowledge/AWS/aws-lab/scripts/lab.sh`)
- **Subcommands:** `status | plan-up | up | plan-down | down`.
- **Guards:**
  - STS account must be `736486260824` and the region `ap-southeast-2`; refuse otherwise.
  - Terraform must be 1.13.5. Init with `sydney-lab.s3.tfbackend` and `-lockfile=readonly`.
  - Every apply uses a saved plan. An allowlist check fails if the plan touches anything outside the expected addresses for the mode, which blocks deletes of RDS, Cognito, S3, KMS or ECR. The owner types `yes` before each apply.
- **`up`:**
  1. Start RDS and wait for `available`.
  2. Apply with `runtime-running` (NAT, ingress, services).
  3. Wait for healthy targets with `aws elbv2 describe-target-health`.
  4. Upsert the `api-lab` CNAME to the new ALB hostname through the Cloudflare API. The token comes from `security find-generic-password -s scoutgrid-cloudflare-dns -w` and is never echoed.
  5. Smoke test `https://api-lab.scoutgrid.io/api/auth/csrf`.
- **`down`:**
  1. Apply `runtime-down`: services first, then ingress and NAT.
  2. Point the `api-lab` CNAME away from the deleted ALB (delete the record).
  3. `rds stop-db-instance`.
  4. Print the date of the 7-day auto-restart.
- **`status`:** RDS state, services and desired counts, ALB, NAT, the DNS target and month-to-date cost from Cost Explorer.
- Pass `shellcheck`. No secrets in output.

### A5. Frontend (`prototype-app/frontend/vercel.json`)
- Set CSP `connect-src 'self' https://api-lab.scoutgrid.io https://<imports-bucket>.s3.ap-southeast-2.amazonaws.com https://challenges.cloudflare.com https://*.ingest.sentry.io`. Read the bucket host from `terraform output` and remove `api.scoutgrid.io`.
- Leave the `src/api/base.ts` fallback alone; Vercel env vars override it.

### A6. Remove Render from the repo
- Delete `render.yaml` (it also contains a personal email address at line 85).
- Delete `backend/scripts/run-render-migration.sh` and `test-run-render-migration-env.sh`.
- `backend/Dockerfile`: drop the `default-runtime` stage so `aws-runtime` is the final default target. Before removing anything, search the workflows and scripts for builds that rely on the default target. The Dockerfile is deploy infrastructure, so the PR description calls this out.
- Remove the `render` entries from `.mcp.json` and `.claude/settings.local.json`.
- Docs:
  - `docs/architecture.md:14,299-300`
  - `Working Knowledge/AWS/AWS_MASTER_MIGRATION_PLAN.md`: line 48 (Vercel replaces Amplify), A08, R04 (Render retired early, with the date), and lab-as-sole-environment
  - `STANDARD_IMPLEMENTATION_READINESS.md`, a new dated entry
  - `aws-lab/README.md`: origins, scripts, Amplify removed, cost table
  - `aws-lab/FINDINGS.md` process items

## Part B — live changes, in order (after the PR merges; I confirm each outward step)
1. **IAM:** the owner approves `lab-cycle.PROPOSED.json`. Create and attach the `ScoutGridSydneyLabCycle` role, then simulate and read it back.
2. **Cloudflare token:** the owner creates a token limited to Zone DNS Edit on `scoutgrid.io` and adds it to the Keychain.
3. **Turnstile:** add `scoutgrid.io` to the lab widget's hostnames, through the dashboard or a token with Turnstile scope. Keep the lab site key and secret pair.
4. **Vercel** (dashboard, or the Vercel MCP after auth): set Production env vars:
   - `VITE_API_BASE=https://api-lab.scoutgrid.io/api`
   - `VITE_MANAGED_BROWSER_AUTH_ENABLED=true`
   - `VITE_DURABLE_BOM_UPLOADS_ENABLED=true`
   - `VITE_TURNSTILE_SITE_KEY=<lab site key>`

   Then redirect `www` to the apex with a 308, and redeploy `main`.
5. **Lab Terraform:** run `lab.sh plan-up` with the new origin. Expected changes:
   - S3 CORS, the Cognito logout URL and invite link
   - the API and worker env (`APP_CORS_ALLOWED_ORIGINS`, `APP_DEMO_APP_BASE_URL`, `APP_TURNSTILE_EXPECTED_HOSTNAME`) as new task definition revisions
   - reconciling the Nov 12 CLI deviations, already in code since #73
   - removal of the Amplify app and branch

   First delete the hand-made Amplify domain association for `lab.scoutgrid.io`. Then apply.

   Optional: if PR #74 is merged, publish its exact image first. Use the CI candidate artifact pushed with `crane`, since local Docker doesn't work.
6. **Cloudflare DNS:** delete `api.scoutgrid.io` (pointing to onrender), `lab.scoutgrid.io` (pointing to CloudFront) and `_7198af0c…lab.scoutgrid.io` (the ACM validation record for the Amplify certificate). Keep `api-lab` and its `_62ca8e28…` ACM validation record (needed for renewal), the Vercel apex and `www`, the Zoho MX and verify records, and the Resend `send.` MX, SPF, DKIM and DMARC records.
7. **Render** (dashboard, or the Render MCP after auth):
   1. Take an encrypted `pg_dump` of `scoutdb-preprod-v1`, stored outside the repo with its SHA-256 recorded.
   2. Remove the `api.scoutgrid.io` custom domain.
   3. Delete the `scout-backend` web service and the database.
   4. Revoke any Render-only credentials, such as a Resend API key used only there.
   5. Confirm the Render billing shows nothing remaining.
8. **IAM cleanup:** detach `frontend-deploy-and-domain.json` and retire the `sglab-frontend` profile.
9. **Reminder:** use the `schedule` skill to create a one-time routine for 2026-11-20 at 10:00 IST: "Lab week done — decide lab-down vs keep, kick off production planning (us-east-1, 560246495987, prod frontend origin, lab moves to its own Vercel domain)". Also save a project memory with the same date.

## Verification
- **Local:**
  - `terraform fmt -check -recursive`, `terraform init -backend=false`, `terraform validate` and `terraform test` (the new lab-cycle tests plus the existing ones)
  - frontend `npm run build` and `node scripts/verify-production-bundle.mjs`
  - `shellcheck lab.sh`
  - the CI contract scripts
- **Before any live apply:** `lab.sh status`, `lab.sh plan-up` (only the expected origin and Amplify changes) and `lab.sh plan-down`, as a plan only that shows removal of just the services, ALB tree, WAF, NAT, EIP and routes. Lab-down itself isn't run this week.
- **After cutover:**
  - At `https://scoutgrid.io`, sign in as the platform owner and as the SG Internal admin (managed Cognito, `__Host-sg-session` cookie set).
  - The demo request form passes Turnstile.
  - A BOM upload through BOM Management → Ingest Now shows up in Run History, which checks S3 CORS and the CSP.
  - `www` redirects.
  - `api.scoutgrid.io` and `lab.scoutgrid.io` no longer resolve.
  - Render shows no services.
  - `lab.sh status` and Cost Explorer stay within $100 for the month.
