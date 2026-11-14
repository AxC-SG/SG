# Lab findings — November 12, 2026

Found while deploying candidate `0ae3de9` to the Sydney lab. Fix these in one PR on main before the next lab run and before production. Severity reflects impact on a production launch.

## Status in branch `codex/aws-lab-and-workspace-sync`

| # | Status | Change |
|---|---|---|
| 1 | **Fixed** | `runtime.tf` sets `HTTP_OUTBOUND_ALLOWED_HOSTS` on api and worker: the backend default plus `cognito=<login domain>,cognito-idp.<region>.amazonaws.com`. A new `runtime.tftest.hcl` assertion compares the list with `application.yml` and requires the Cognito entry; the test fails when the entry is removed. |
| 2 | **Fixed** | ECS service `health_check_grace_period_seconds` 120 → 300, with a test assertion that fails at 120. Startup time itself is not yet investigated. |
| 3 | **Root cause found; fix awaits owner approval** | `TenantService.listActiveTenants()` reads the platform tenant registry without declaring platform scope. Pollers that call it outside `TenantContext.runAsPlatform` (for example `AiGridAssessmentWorker.recover`, `AiBomProjectionWorker`, every 5 s) check out an unscoped connection. Production marks it with the no-tenant sentinel, so RLS stays closed and no data leaks. Proposed fix: wrap the read in `TenantContext.runAsPlatform` inside `listActiveTenants()`, with a unit test. `TenantService` is on the never-touch list. |
| 4 | **Fixed in the grant and run order** | `infrastructure/lab/grants/bootstrap-retire-migrator-revision.json` allows `ecs:DeregisterTaskDefinition` on `*` (AWS accepts no narrower resource), limited to Sydney. Retire the enrollment migrator (step 8) before planning services (step 9), so no pending migrator replacement is pulled into the service plan. The ARN-scoped grant attached on November 12 was ineffective and is kept as `bootstrap-deregister-migrator.INEFFECTIVE-scoped-arn.json`. |
| 5 | **Fixed** | `hosting.tf` sends `custom_headers` as the compact JSON array Amplify stores. Plan against the lab shows no Amplify change. |
| 6 / 6a | **Superseded by decision; risk recorded** | MFA is off everywhere (`identity.tf`). Risk acceptance recorded as AR-01 in the [G08 decision record](../release-evidence/standard-g08/G08_RELEASE_DECISION.md). |
| 7 | **Open (production decision)** | Needs a sender domain and SES identity before production onboarding. |
| 8 | **Open (configuration)** | Needs the Resend, OpenAI and Sentry values decided and added to `application-settings`. |
| Dependabot #94 | **Fixed** | `minimatch` (dev-only, via ESLint) forced to `^11.0.1` with an npm override; lock resolves 11.0.8. Lint, typecheck, build and unit tests pass. |

## Application and Terraform

| # | Finding | Evidence | Fix | Severity |
|---|---|---|---|---|
| 1 | Managed sign-in fails: the backend outbound allowlist omits Cognito. The OAuth callback returns `Outbound hostname is not allowlisted`. | API log 15:09:40 UTC, request `35bcfc3f…`. `OutboundHostPolicy` default list has no Cognito hosts, and Terraform never sets `HTTP_OUTBOUND_ALLOWED_HOSTS`. | In `runtime.tf`, set `HTTP_OUTBOUND_ALLOWED_HOSTS` for api (and worker if needed) to the default list plus `cognito=<pool domain>.auth.<region>.amazoncognito.com,cognito-idp.<region>.amazonaws.com`. Add a contract test that managed auth implies the Cognito entry. | Blocker |
| 2 | API cold start is about 152–160 s on 0.5 vCPU / 2 GB, longer than the 120 s health-check grace. Tasks are killed just before readiness. | Revision-2 tasks replaced twice. The first deployment also replaced once. | Raise `health_check_grace_period_seconds` (300 s works) and/or increase API CPU. Investigate startup time (about 110 s between Hibernate init and the dashboard cache). | High |
| 3 | `Tenant-aware connection acquired without tenant or platform context` logged about 28 times per minute by the worker, and on owner and SG Internal requests. | 3,356 WARNs over 2 h on the worker; 8 on API requests. No errors. | Trace the call sites. Bind platform/tenant context before connection acquisition, or make the path fail closed per the P09 routing contract. | High |
| 4 | Terraform targets cannot separate the services from the migrator task definition. Any service plan replaces `migrator`. ECS `DeregisterTaskDefinition` only accepts `Resource: "*"`. | Guard refused the plan at 13:50 UTC. Bootstrap denied on `*`. | Split task definitions into separate resources, or set `skip_destroy = true` on task definitions. Give the deregistration step a reviewed `*` statement or retire revisions at cleanup. | Medium |
| 5 | Amplify `custom_headers` shows a permanent in-place update. Terraform sends YAML; Amplify stores JSON with identical content. | Every plan shows `~ aws_amplify_app.frontend`. | Use `jsonencode` matching Amplify's stored form, or `ignore_changes` with a header verification test. | Low |
| 6 | Operator MFA recovery is undefined. A saved TOTP device cannot be cleared by `AdminSetUserMFAPreference` while pool MFA is `ON`, and `AdminGetUser` showed no MFA list. | Owner locked out 15:30–15:43 UTC. Recovered by setting pool MFA `OPTIONAL` for about 70 s. | Write an operator runbook for lost authenticators. Consider a second platform operator, and test recovery in the lab. | High (production) |
| 6a | **Owner decision, November 12:** MFA is OFF for platform and tenant sign-in in **every environment**. `identity.tf` takes `cognito_mfa_configuration` with default `OFF`; the lab tfvars also set `OFF`. Risk accepted by the owner: the platform owner can reach every tenant with a password alone. | Lab pool `MfaConfiguration=OFF`; Terraform plan shows no changes. | Record the risk acceptance in the G08 release decision. Strong unique operator passwords and Cognito email-based account recovery remain the controls. Finding 6 no longer applies while MFA is off. | Decision (risk accepted) |
| 7 | Cognito uses `COGNITO_DEFAULT` email, which has a low daily send limit. | Pool email configuration. | Use Amazon SES for the production pool before onboarding customers. | Medium (production) |
| 8 | App email and AI integrations are not configured in the lab: no Resend key, OpenAI key or Sentry DSN. | Task definition environment and secrets. | Decide the production values. Add them to `application-settings` and test demo-request notices and member invites in the lab. | Medium |

## IAM grants (corrected copies in [`infrastructure/lab/grants/`](../../../infrastructure/lab/grants/))

Each of these failed on first use and was fixed during the run:

- **Security-group rules:** tagged `AuthorizeSecurityGroupIngress/Egress` also needs `security-group-rule/*` with the four request tags.
- **ALB create:** `elasticloadbalancing:Scheme` is absent when Terraform omits `scheme` (internet-facing is the default), so use `StringEqualsIfExists`. ELB also calls `ec2:DescribeAccountAttributes`. `AWSServiceRoleForElasticLoadBalancing` did not exist and needs `iam:CreateServiceLinkedRole` once.
- **WAF:** `wafv2:GetWebACLForResource` is evaluated against `regional/webacl/*/*` and is needed by every role that plans or applies anything depending on the association: Plan, Apply, Bootstrap, Service and Teardown.
- **Service role:** needs the existing read-only `s3:GetBucketWebsite` correction and the shared state grant to run Terraform. `UpdateService` requires the request to repeat the network configuration (`Null: ecs:subnet = false`).
- **Amplify deploy:** `CreateDeployment` and `StartDeployment` are evaluated on `branches/<branch>/deployments/*`, not the branch. Domain association needs `route53:ListHostedZones` even with external DNS. Recreating a failed association needs `DeleteDomainAssociation`.
- **Teardown:** needs a lab-down grant for runtime resources. See `teardown-lab-down.PROPOSED-NOT-ATTACHED.json`.

**Recommendation:** replace per-step hand-bound grants with one reviewed deploy role per environment, ideally assumed from CI with OIDC. Keep these documents as its least-privilege baseline and prove that role once before production.

## Process

- Run the lab from a local terminal or CI rather than browser CloudShell. CloudShell restarted mid-run and lost its temporary files.
- Automate Cloudflare DNS (`api-lab`, `lab`, ACM validation CNAMEs). Use the Terraform Cloudflare provider or an API token scoped to DNS Edit for `scoutgrid.io`. **November 13:** `infrastructure/lab/scripts/lab.sh` updates `api-lab` with a Keychain token scoped to DNS Edit; `lab` and its validation record are deleted with Amplify.
- Script lab-up and lab-down from the sequence in [README.md](README.md) so each run is one command. **November 13:** done in `infrastructure/lab/scripts/lab.sh` with Terraform modes (`nat_gateway_mode = "none"`, `runtime_ingress_enabled = false`) and one proposed cycle role ([matrix](../../../infrastructure/lab/grants/LAB_CYCLE_MATRIX.md)).
- Not yet qualified: BOM upload, demo-request onboarding, tenant isolation tests, scheduling under worker replacement, MFA end to end, the ten-customer 24-hour capacity run, recovery, and security operations (CloudTrail/GuardDuty/Config).
