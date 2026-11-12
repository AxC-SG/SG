# Owner decision — November 12, 2026, ~13:10 UTC (18:40 IST)

Recorded by Claude Code at the owner's direction. No AWS action was taken by Claude Code when this was written.

- The owner directed Claude Code to take over the Sydney application lab run from the Codex session and continue deploying the remaining resources.
- The owner set aside the 4-hour cleanup-start rule (originally 14:07:33 UTC). The build may continue to about 16:00 UTC (21:30 IST).
- The hard deadline is unchanged: cleanup must be complete by 18:07:33 UTC (23:37:33 IST). The clock start (10:07:33.532342 UTC), the $25 inclusive run allocation and the $50 monthly ceiling are also unchanged.
- **Inform the owner before bringing anything down.** Do not start teardown without first notifying the owner, except where needed to meet the 18:07:33 UTC hard deadline or on unexpected spend or loss of cleanup capability.
- All other run rules in `CLEANUP_EXECUTION_SEQUENCE.md` and the execution authorization still apply.

## Claude Code takeover progress — 14:05 UTC

Ran from the owner's local terminal with `aws login` (AccountFullAccessRole) assuming the scoped lab roles; Terraform 1.13.5 checksum-verified; plan source matched source-manifest.json (16 files).

- Apply: ECS cluster, 3 log groups, 12 SG rules; ALB, HTTPS listener (TLS13), host+/api/* rule, target group, WAF (2 AWS managed rule sets) and association.
- Bootstrap: 5 runtime roles + policies, task definitions api:1 worker:1 migrator:1.
- Migration: exit-once bootstrap task 798c86cb… success (platform V15, tenant_default V20, scout_runtime, owner verified, managed operator links committed). Rerun 5b32b43d… no-op (links verified, no migrations).
- Enrollment access removed from migrator execution policy. migrator:1 still registered (DeregisterTaskDefinition requires Resource "*"; left for cleanup).
- Service: api and worker created by CLI from Terraform-planned parameters (targeted Terraform pulled the migrator replacement), then imported. Both steady; API target healthy behind ALB. Public routing exposes only /api/* (actuator 404 by design); unauthenticated API returns 401.
- Owner-approved grant changes: CapturedRuntimeRules + TaggedRulesOnCapturedGroupsOnly; Apply CapturedRuntimeIngress (incl. scheme IfExists, DescribeAccountAttributes, GetWebACLForResource); Migration MigrationOperator; Service ServiceOperator + common-read-state + ProviderBucketMetadataCorrection; managed ScoutGridSydneyLab-waf-association-read on Plan/Bootstrap/Service/Teardown; Bootstrap RetireEnrollmentMigratorRevision (ineffective; scoped ARN unsupported).
- Observation: first API task failed ALB health checks during startup and was replaced once; tune grace period/health thresholds for 0.5 vCPU API.
- Note: the WAF association was replaced once after a tainted read (guard failure, fixed).

## Findings and lab deviations — 15:30 UTC

- FINDING (blocker for managed sign-in): candidate 0ae3de9 does not add the Cognito login domain or cognito-idp.ap-southeast-2.amazonaws.com to HTTP_OUTBOUND_ALLOWED_HOSTS; the OAuth callback fails with "Outbound hostname is not allowlisted". Lab deviation (owner approved): scoutgrid-lab-api:2 = api:1 + HTTP_OUTBOUND_ALLOWED_HOSTS (code default + cognito entry), same image digest. Fix in runtime.tf via PR.
- FINDING: API cold start ~152–160 s on 0.5 vCPU exceeds the 120 s health-check grace; revision-2 tasks were killed twice before readiness. Lab deviation: api service grace set to 300 s by update-service. Fix grace and/or task size in runtime.tf.
- Service grant ServiceOperator now allows UpdateService for api:1 or api:2 (owner approved).
- Frontend: exact 0ae3de9 frontend built with Node 24 (VITE_API_BASE=https://api-lab.scoutgrid.io/api, managed auth, durable uploads, Turnstile site key) and deployed as Amplify job 1; lab.scoutgrid.io domain association AVAILABLE. Owner added api-lab, lab and ACM validation CNAMEs (DNS only) in Cloudflare.
- Owner Cognito invitation resent via the Identity role (MessageAction RESEND); SG Internal admin not yet invited.

## Managed sign-in result — 15:45 UTC

- Owner reported successful sign-in to https://lab.scoutgrid.io as platform owner (Platform console visible) at ~15:44 UTC on api:2.
- MFA recovery gap: the owner's first TOTP enrollment (~15:07–15:09 UTC) was saved by Cognito but not shown in AdminGetUser (UserMFASettingList null); the owner deleted that authenticator entry on Claude's incorrect advice. AdminSetUserMFAPreference(Enabled=false) did not clear the saved token while pool MFA was ON. With owner approval, pool MFA was set OPTIONAL at 15:43:51 UTC and restored to ON (identical to the saved configuration) at 15:45:01 UTC (~70 s). Sign-in in that window was password-only, so this run does NOT qualify the MFA step end to end. Define an operator MFA-recovery procedure before production.
- FINDING to investigate: six WARN "Tenant-aware connection acquired without tenant or platform context" on authenticated owner requests 15:44–15:45 UTC (no errors). Check against the P09 fail-closed routing contract.
- No ERROR/Exception lines in the API log over the sign-in window.

## SG Internal and teardown scope — 16:10 UTC

- SG Internal administrator (scoutgridtenant@gmail.com, f9ee14b8…) invitation resent 15:51 UTC; password set 15:52 UTC (CONFIRMED); owner reports successful sign-in to the SG Internal workspace. The same tenant-context WARN appeared on two requests at 15:52–15:53 UTC.
- OWNER DECISION: keep the low-cost layer between runs (Cognito pool and users, secrets, KMS keys, ECR, S3, Amplify app and domain, certificates, VPC/subnets/security groups, task definitions, runtime roles, log groups, cluster). Remove only billable runtime: ECS services, ALB/listener/rule/target group, WAF, NAT gateway and EIP; stop RDS. This supersedes the full-cleanup disposition in CLEANUP_EXECUTION_SEQUENCE.md for this run.

## Owner decision — 16:20 UTC

- OWNER DECISION: the 18:07:33 UTC cleanup deadline is removed ("there is no deadline"). The lab may keep running; billable runtime continues (~USD 0.30/hour) within the USD 50 monthly ceiling until the owner chooses lab-down.
- Worker observation: 3,356 "Tenant-aware connection acquired without tenant or platform context" WARNs in 2 hours on the worker (≈28/min), alongside scheduled maintenance (finding projections, entitlement shadow sweep: 1 active tenant, 0 mismatches). Elevates the tenant-context finding.
- Not configured in this lab: Resend email, OpenAI, Sentry, GitHub token (no such env/secrets in task definitions).

## Owner decision — 16:37 UTC: MFA disabled

- OWNER DECISION: "permanently disable MFA for both platform and tenant flows."
- Lab pool ap-southeast-2_fPdRmnVqM set to MfaConfiguration=OFF at 16:37:39 UTC (owner identity). The backend does not enforce MFA claims, so sign-in is password-only for both operators.
- Terraform (worktree branch codex/aws-lab-consolidation-20261112, uncommitted): identity.tf adds variable cognito_mfa_configuration (default "ON"); lab tfvars set "OFF". Targeted plan against live state: no changes. Production default unchanged pending owner decision.
- 16:45 UTC OWNER DECISION: "turn MFA OFF everywhere." Terraform default for cognito_mfa_configuration changed to "OFF", so production also deploys with MFA off. Risk (password-only platform owner with access to every tenant) accepted by the owner; record in the G08 decision.

## Workspace consolidation — 17:10 UTC (owner approved "go")

- SG workspace (codex/aws-part-1-implementation @ f9426447, 217 changes) backed up as local commit 710dc5a0 on backup/sg-workspace-20261112 (not pushed).
- SG now on codex/aws-lab-and-workspace-sync from origin/main 0ae3de9 with the backup replayed (uncommitted). 19 conflicts resolved to main: 16 were exact earlier versions in main's history; 3 planning docs were superseded November 11 snapshots. Render deletions (render.yaml, run-render-migration scripts) were kept out because main's Dockerfile still references them; they remain on the backup branch for the Render retirement work.
- aws-lab moved into SG; duplicate November 11 prep evidence removed (originals moved into aws-lab/evidence/2026-11-11-prep). Temporary worktree SG-aws-lab and branch codex/aws-lab-consolidation-20261112 removed.
- Lab Terraform now runs from SG; Plan-role plan shows only the known lab deviations.
