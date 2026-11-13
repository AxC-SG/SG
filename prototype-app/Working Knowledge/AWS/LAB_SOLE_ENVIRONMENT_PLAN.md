# Plan: retire Render, make the Sydney lab the only backend, Vercel as the only frontend (rev 2)

## Context
Render (`scout-backend`, free plan, Oregon) has been in `update_failed` since Nov 8, so `api.scoutgrid.io` is already broken. The Sydney AWS lab is up and qualified for sign-in.

The owner wants:
- Render removed completely.
- The public Vercel site (`scoutgrid.io`) pointed at the lab API.
- The lab Amplify frontend (`lab.scoutgrid.io`) torn down.
- Cloudflare DNS reconciled.
- The lab as the only environment until production is planned after this week's testing.

The lab stays **up all week**. Lab-up and lab-down scripts must exist so it can come down at any time. Remind the owner on **2026-11-20**.

**Owner decisions (2026-11-13):**
- Frontend origin is `https://scoutgrid.io`.
- Lab ceiling is **$100/month**.
- Render database: take a final encrypted dump, then delete.
- **Vercel is the production frontend too**, so Amplify is deleted from Terraform.
- DNS is changed through a **scoped Cloudflare token** stored in the macOS Keychain.

**Rev 2** takes in the external review of rev 1. Already done on `main`:
- PR #75 removed `render.yaml`, both Render migration scripts and the Render `CMD` and `chmod` in the Dockerfile (`92c84b1e`).
- PR #74 (finding 3) is merged.

Work continues on branch `feat/lab-sole-environment`.

## Feedback on the approach (summary for the owner)
- **Sound overall.** Render adds nothing, and one environment cuts overhead. Keeping Vercel removes the Amplify A08 work and its IAM friction.
- **The lab now carries the public site.** When it's down, sign-in and the demo form on `scoutgrid.io` are offline. Static marketing pages still load.
- **Don't onboard real customers onto the lab.** It has MFA off, single-AZ RDS, Sydney data location and a disposable posture.
- **There can be only one origin.** With managed sign-in on, the backend accepts exactly one frontend origin (`ManagedBrowserAuthController.java:38-46`). Vercel previews can't sign in, and `www` must redirect to the apex.
- **Production will reclaim `scoutgrid.io`.** The lab then moves to its own Vercel domain, planned together with production.
- **Timing:** lab-up takes about 20–30 minutes and lab-down about 10–15 minutes. RDS restarts by itself after 7 days stopped.

## Part A — repository changes (PR 1, owner merges)

### A1. Terraform lab-down modes (`prototype-app/infrastructure/terraform/standard`)
- **NAT:** `main.tf` `nat_gateway_mode` gains `"none"`, rejected in production. In `modules/standard-network`, `nat_zones`, the EIPs and the `task_egress` routes are empty for `none`.
- **Ingress switch:** new variable `runtime_ingress_enabled` (default true; false rejected in production).
  - A filtered local gates every resource in `ingress.tf`: ALB, listener, rule, target group, WAF, association and the ALB security-group rules.
  - Validation: ingress off requires `start_services = false`, because `runtime.tf:286` references the target group.
- **Outputs and other references must be safe when ingress is off:**
  - `runtime.tf:315-316`: `api_load_balancer_dns_name` and `api_load_balancer_zone_id` become `null` when ingress is off.
  - `operations.tf:293-318`: the ALB and target-group alarms are gated on ingress as well as `operations`.
- **Kept in every mode:** task definitions, runtime roles, log groups, the ECS cluster, RDS, Cognito, S3, KMS, secrets and ECR.
- **Budget:** in `budget.tf`, the lab cap goes from 50 to 100.
- **Tests:**
  - Update the existing budget tests in `tests/runtime.tftest.hcl` (around lines 505-530). They accept 100 and reject **100.01**, replacing the current $50 and $50.01 cases.
  - New `tests/lab-cycle.tftest.hcl` (mocked) plans **the whole root module** in down mode with services, ingress and NAT `none`, operations enabled, and every output evaluated. It asserts:
    - zero NAT, EIP, egress-route, ALB, WAF and service resources
    - task definitions and the cluster are kept
    - `backend_runtime.api_load_balancer_dns_name == null`
  - A matching up-mode test asserts all of those resources return.
  - Production rejects `none` and ingress off.
  - Update `integrated-lab.tftest.hcl:67` to `https://scoutgrid.io`.
- **Amplify:** `hosting.tf` Amplify removal is **not** in PR 1. It's PR 2, after the verification gate (B6), so `lab.scoutgrid.io` stays available for rollback.

### A2. Lab configuration and budget operating rule (`aws-lab/config/`)
- **Foundation tfvars:**
  - Set `frontend_origin = "https://scoutgrid.io"`.
  - **Remove** `nat_gateway_mode` (line 6), so mode lives only in the runtime files.
  - **Explicitly enable** `monthly_budget = { amount_usd = 100, operator_email = <owner billing email> }`. There's no budget in the lab today.
- **Runtime files.** Each sets all three switches explicitly:

  | File | `start_services` | `runtime_ingress_enabled` | `nat_gateway_mode` |
  |---|---|---|---|
  | `runtime-running.tfvars` | true | true | `"single"` |
  | `runtime-down.tfvars` | false | false | `"none"` |
  | `runtime-noenroll.tfvars` and `runtime-stopped.tfvars` | (as now) | true | `"single"` |

  The `.auto` suffix is dropped. Files are passed only with explicit `-var-file`.
- **Budget operating rule** (written into `aws-lab/README.md`):
  - **Before the week starts:** month-to-date actual (Cost Explorer) + 7 days up (about $50) + the rest of the month down (about $0.70/day) + retained storage + 20% contingency must be ≤ $100. Otherwise the lab doesn't stay up all week.
  - **Alerts:** at 80% of actual and 100% of forecast, by email to the owner.
  - **Responder:** the owner. Claude also runs `lab.sh status` at the start of every session.
  - **Shutdown trigger:** month-to-date ≥ $80, or projected month-end > $100. Run `lab.sh down` the same day.
  - **Caveat:** AWS Budgets is an alert, not a cap, and its data can lag usage by hours.

### A3. IAM: action/resource matrix and two grants (proposed, not attached)
New `grants/LAB_CYCLE_MATRIX.md` lists every API action per Terraform resource type, for both the **initial transition** and **repeat cycles**. It's built from the planned resource diffs and checked against the Nov 12 grants:
- `apply-runtime-ingress`
- `service-operator-v2`
- `bootstrap-trusted-runtime.live`
- the teardown proposal
- the foundation and common read-state grants

**`grants/lab-cycle.json`** is for repeat cycles, as role `ScoutGridSydneyLabCycle` with profile `sglab-cycle`. It's scoped by name or tag (IDs change every cycle) and to Sydney only:

| Phase | Actions |
|---|---|
| **Up** | `ec2:AllocateAddress`, `CreateNatGateway`, `CreateRoute`, `CreateTags`. The ELB create set and WAF create/associate/tag from `apply-runtime-ingress`, plus the security-group-rule tag fix. `ecs:CreateService`, `UpdateService`, `DescribeServices`, `TagResource`, and `iam:PassRole` limited to the two runtime task roles. `rds:StartDBInstance`. |
| **Down** | The teardown set (ECS, ELB, WAF, NAT, EIP and route deletes) and `rds:StopDBInstance`. |
| **Always** | Terraform state bucket and lock. The common read-state actions Terraform needs to refresh every resource in state, including `wafv2:GetWebACLForResource` and `s3:GetBucketWebsite`. |

Explicitly excluded:
- `ecs:RegisterTaskDefinition`. If a cycle plan wants a task-definition change, the script stops and sends it to the Bootstrap path.
- Any delete or modify on RDS (other than start/stop), Cognito, S3, KMS, ECR or IAM.

**`grants/lab-cutover-once.json`** is for the one-time origin change and Amplify retirement. It's attached to the existing Apply and Bootstrap roles and detached afterwards:
- `s3:PutBucketCORS` on the imports bucket
- `cognito-idp:UpdateUserPool` and `UpdateUserPoolClient` on the lab pool
- `ecs:RegisterTaskDefinition` and `DeregisterTaskDefinition`, with `iam:PassRole` for the runtime roles (Bootstrap)
- `ecs:UpdateService` (Service)
- `budgets:CreateBudget`, `ModifyBudget` and `TagResource` for the lab budget
- later, for PR 2: `amplify:DeleteDomainAssociation`, `DeleteBranch` and `DeleteApp` on app `d20ebk72hfk5ft`

**Proof before relying on down:**
1. Access Analyzer validation.
2. `iam simulate-principal-policy` for **every** action and resource pattern in the matrix, both up and down.
3. `lab.sh down` refuses to run unless the up-set simulation passes in the same session. This keeps the lab from being taken down when it can't come back up.

### A4. Scripts (`aws-lab/scripts/lab.sh`)
- **Subcommands:** `status | plan-up | up | plan-down | down | simulate`.
- **Guards:**
  - STS account must be `736486260824` and the region `ap-southeast-2`.
  - Terraform must be 1.13.5. Init with `-backend-config=$CFG/sydney-lab.s3.tfbackend -lockfile=readonly`.
  - Saved plans only.
  - An address allowlist per mode refuses anything else, including any delete of RDS, Cognito, S3, KMS or ECR, and any task-definition change.
  - The owner types `yes` before each apply.
- **Exact arguments:**
  - **up:**
    ```
    terraform plan -out=up.tfplan \
      -var-file=$CFG/sydney-lab.foundation.tfvars \
      -var-file=$CFG/runtime-running.tfvars
    ```
    `runtime-running.tfvars` explicitly restores `runtime_ingress_enabled = true` and `nat_gateway_mode = "single"`.
  - **down:**
    ```
    terraform plan -out=down.tfplan \
      -var-file=$CFG/sydney-lab.foundation.tfvars \
      -var-file=$CFG/runtime-down.tfvars
    ```
- **`up`:**
  1. `rds start-db-instance` and wait for `available`.
  2. Plan and apply up.
  3. Wait for healthy targets with `elbv2 describe-target-health`.
  4. Upsert the `api-lab` CNAME through the Cloudflare API. The token comes from `security find-generic-password -s scoutgrid-cloudflare-dns -w` and is never echoed.
  5. Smoke test `GET https://api-lab.scoutgrid.io/api/auth/csrf`.
- **`down`:**
  1. Run the simulate gate.
  2. Plan and apply down.
  3. Delete the `api-lab` CNAME.
  4. `rds stop-db-instance`.
  5. Print the date of the 7-day auto-restart.
- **`status`:** RDS state, services, ALB, NAT, the DNS target, and month-to-date plus projected cost against the rule in A2.
- Pass `shellcheck`. No secrets in output.

### A5. Frontend (`prototype-app/frontend/vercel.json`)
- Set CSP `connect-src 'self' https://api-lab.scoutgrid.io https://<imports-bucket>.s3.ap-southeast-2.amazonaws.com https://challenges.cloudflare.com https://*.ingest.sentry.io`. Read the bucket host from Terraform state.

### A6. Remaining Render references (most were removed by PR #75)
- Remove the `render` entries in `.mcp.json:17-19` and `.claude/settings.local.json:4`.
- Dockerfile: check that `aws-runtime` builds and that the leftover empty `default-runtime` stage (`backend/Dockerfile:31`, no Render references) is either unused or kept as the default. Require the CI `Trivy images gate` (`trivy.yml:169-171`), which builds `--target aws-runtime`, to pass.
- Docs:
  - `docs/architecture.md:14,299-300`
  - Master plan: line 48 (Vercel), A08, R04 (Render retired early), and the lab as the sole environment
  - `STANDARD_IMPLEMENTATION_READINESS.md`, a dated entry
  - `aws-lab/README.md`
  - `aws-lab/FINDINGS.md`
  - `LAB_SOLE_ENVIRONMENT_PLAN.md`, replaced with rev 2

## Part B — live changes, gated (I confirm each outward step)
1. **Record rollback state:**
   - Vercel's current production deployment ID
   - the lab Terraform state version
   - the current task-definition revisions and their CORS, base-URL and Turnstile values
   - the S3 CORS
   - the Cognito logout URL and invite template

   Save these to `aws-lab/evidence/<date>/cutover-rollback.json`.
2. **IAM:** after owner approval, attach `lab-cutover-once`, then create and attach `ScoutGridSydneyLabCycle`. Run `lab.sh simulate`.
3. **Additive prerequisites:**
   - The owner creates the Cloudflare DNS token and adds it to the Keychain.
   - Add `scoutgrid.io` to the lab Turnstile widget's hostnames.
   - Run the budget calculation from A2; stop if it's over.
4. **Backend first:** `lab.sh plan-up`. Expected changes are S3 CORS, the Cognito logout URL and invite link, new API and worker task-definition revisions with the new origin variables, the Nov 12 deviations reconciled (already in code), and the budget. Review it, then apply. From here `lab.scoutgrid.io` stops signing in. This is expected, and rollback is B1 plus reverting the origin. Keep the current image; the main image with #74 and the ownership-MVP migrations is a separate, later upgrade.
5. **Vercel:** set Production env vars:
   - `VITE_API_BASE=https://api-lab.scoutgrid.io/api`
   - `VITE_MANAGED_BROWSER_AUTH_ENABLED=true`
   - `VITE_DURABLE_BOM_UPLOADS_ENABLED=true`
   - `VITE_TURNSTILE_SITE_KEY=<lab key>`

   Redirect `www` to the apex with a 308. Deploy `main` once PR 1 merges, which brings in the CSP change.
6. **Verification gate — must pass before anything is retired:**
   - Managed sign-in at `https://scoutgrid.io` as the platform owner and as the SG Internal admin.
   - A demo request submitted through Turnstile is **persisted** and visible in **Platform → Demo Requests**.
   - A BOM upload through BOM Management → Ingest Now **completes processing** in Run History and appears in BOM Inventory.
   - `www` redirects to the apex.

   **On failure:** roll back with Vercel Instant Rollback to the recorded deployment, revert `frontend_origin` to `https://lab.scoutgrid.io`, and apply.
7. **Retire, only after B6 passes:**
   1. Delete the Cloudflare `api.scoutgrid.io` CNAME (pointing to Render).
   2. Render: take an encrypted `pg_dump` of `scoutdb-preprod-v1`, stored outside the repo with its SHA-256 recorded. Then remove the custom domain, delete the service and the database, revoke Render-only credentials and confirm billing is clear.
   3. Amplify: delete the domain association, merge **PR 2** (removes the Amplify resources from `hosting.tf`), then apply.
   4. Delete the Cloudflare `lab.scoutgrid.io` and `_7198af0c…lab` ACM validation records.
   5. Detach `frontend-deploy-and-domain.json` and `lab-cutover-once`.
   6. Keep `api-lab`, its `_62ca8e28…` validation record, the Vercel apex and `www`, the Zoho records, and the Resend, DKIM and DMARC records.
8. **Reminder for 2026-11-20 at 10:00 IST:** "Lab week done — decide lab-down vs keep, start production planning (us-east-1, 560246495987, prod origin, lab moves to its own Vercel domain), upgrade the lab image to current main." Create it with the scheduler of whichever agent runs this: in Claude Code, the `schedule` skill (available in this session); in Codex, its automation action. Also save a project memory.

## Verification
- **Local:**
  - `terraform fmt -check -recursive`, `init -backend=false`, `validate` and `terraform test` (all, including the updated budget tests and the down-mode whole-root test)
  - frontend `npm run build` and `node scripts/verify-production-bundle.mjs`
  - `shellcheck lab.sh`
  - CI contract scripts
  - CI must be green, including the AWS image build
- **Live, before any apply:** `lab.sh status` and `lab.sh simulate` (up and down sets), plus `lab.sh plan-up` and `lab.sh plan-down` in plan-only mode. Each must show only allowlisted addresses. Lab-down isn't executed this week unless the A2 rule triggers.
- **After cutover:** the B6 gate, then after B7: `api.scoutgrid.io` and `lab.scoutgrid.io` no longer resolve, Render shows no services, and `lab.sh status` is within the A2 rule.

## Implementation notes (PR 1, November 13, 2026)

Approved rev 2 with these deliberate adjustments, found while implementing:

1. **Foundation keeps `nat_gateway_mode = "single"`** instead of dropping it. Without it, a foundation-only plan would default to `zonal` and create a second NAT. Every runtime file still sets the mode explicitly, and as the later `-var-file` it wins: `runtime-running` sets `single`, `runtime-down` sets `none`.
2. **The ALB security group and its two rules stay in both modes.** They're free, and keeping them means the cycle role needs no security-group-rule permissions, which were the hardest grants on November 12.
3. **Removing the Render MCP entries (`.mcp.json`, `.claude/settings.local.json`) moves to PR 2.** The Render MCP is one way to run step B7.
4. **The cycle role also gets** `iam:SimulatePrincipalPolicy` on itself (for the `lab.sh down` gate) and Cost Explorer read (for `lab.sh status`).
5. **Budget alerts** go to `scoutgrid.io@gmail.com`, the platform owner's address.

**Verified locally:**
- Terraform 1.13.5 `fmt -check -recursive` and `validate` pass.
- `terraform test` passes for the root module (25/25, including whole-root lab-up and lab-down plans with operations enabled and the $100/$100.01 budget cases) and the network module (3/3, including `none`).
- `shellcheck` is clean on `lab.sh`.
- The plan allowlist rejects task-definition changes, replacements, RDS deletes and wrong-direction actions.

## Execution status (November 13, 2026)

- **Part A:** merged as PR #77 (`718a7c24`).
- **B1 (rollback state):** recorded in `aws-lab/evidence/2026-11-13/cutover-rollback.json`.
- **B2 (IAM):** the owner approved both grants. Applying the cutover exposed missing cycle-role reads; these were added (see the matrix).
- **B3 (Turnstile):** the widget allows `scoutgrid.io`.
- **B4 (backend):** applied. CORS, email links and Turnstile now use `https://scoutgrid.io`, with services on `api:3` and `worker:2`. `lab.sh plan-up` reports no changes.
- **B5 (Vercel):** production variables set, `#77` deployed, and `www` redirects to the apex with a 308.
- **B6 (verification):** all infrastructure checks passed. The owner **waived** the browser checks (sign-ins, demo request, BOM processing).
- **B7 (retirement):** `api.scoutgrid.io`, `lab.scoutgrid.io` and its validation record were deleted. Amplify was destroyed (this PR removes it from Terraform). Turnstile lists only `scoutgrid.io`. The cutover and Amplify grants were removed. **Render is still pending:** a final dump, then deletion.
