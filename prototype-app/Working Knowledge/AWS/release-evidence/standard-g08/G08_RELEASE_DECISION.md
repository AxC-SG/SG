# G08 — Standard production go/no-go

**Status: OPEN / NOT EVALUATED.** No go/no-go has been taken. G00–G05, the selected capacity gate (G07b by default) and R01 have no recorded passes yet. See the [master plan](../../AWS_MASTER_MIGRATION_PLAN.md) G08 row for the pass conditions.

This record collects decisions that the G08 approver must see before signing. Accepted risks stay listed here until the owner reverses them or G08 closes.

| Field | Value |
|---|---|
| Release candidate | Not selected |
| Selected capacity gate | Not selected (G07b by default) |
| Accountable release owner | Not named |
| Decision | Pending |

## Accepted risks

### AR-01 — No MFA for any sign-in, including the platform owner

| Field | Value |
|---|---|
| Decided | November 12, 2026, 16:45 UTC, by the owner ("turn MFA OFF everywhere") |
| Applies to | Platform and tenant sign-in in every environment, production included |
| Configuration | `prototype-app/infrastructure/terraform/standard/identity.tf`: `cognito_mfa_configuration` defaults to `OFF` (commit `dc93651a`, merged in PR #73). The lab tfvars also set `OFF`. With `OFF`, no software-token MFA is configured on the pool. |
| Lab state | Pool `ap-southeast-2_fPdRmnVqM` set to `MfaConfiguration=OFF` at 16:37:39 UTC. Terraform plan against the lab shows no changes. |
| Evidence | [Owner decision log](../../aws-lab/evidence/2026-11-12/recovery-status/OWNER_DECISION_20261112_1310Z.md), [lab findings 6 and 6a](../../aws-lab/FINDINGS.md) |

**Risk.** The platform owner can reach every tenant's data. That account is protected by a password alone. A phished, reused or guessed password, or a compromised mailbox used for Cognito email recovery, gives full cross-tenant access. Tenant administrators and members are also password-only.

**Why it was accepted.** On November 12 the owner was locked out of the lab for 13 minutes (15:30–15:43 UTC). A saved TOTP device could not be cleared while pool MFA was `ON`, and there was no tested recovery procedure (finding 6). The owner chose to turn MFA off rather than run production with an untested authenticator-recovery path.

**Controls that remain.**

- Admin-created accounts only (`allow_admin_create_user_only`); no self sign-up.
- Cognito default password policy; the Terraform sets no stronger policy.
- Account recovery through verified email only.
- Strong, unique operator passwords. This is an operating practice; nothing enforces it.

**Effects on other plan items.** These items assumed MFA. While AR-01 stands, they do not require it:

- Master plan, *Identity, sessions and tenant authority*: "MFA for privileged staff".
- Readiness, owner bootstrap step 5: "complete required MFA".
- Lab finding 6, the lost-authenticator runbook.

MFA for human access to the AWS accounts (A01, Identity Center and root) is a separate control and is **not** covered by AR-01.

**Revisit when** any of these happens: a customer contract or security questionnaire requires MFA, a second platform operator is added, a suspected credential compromise occurs, or SOC 2 scoping begins. To turn MFA back on, set `cognito_mfa_configuration` to `ON` or `OPTIONAL`, then write and test the lost-authenticator recovery runbook (finding 6) in the lab before production.

**G08 approver acknowledgement:** Pending.

## Deferred items the approver should know about

### Render files removed from the repository

The November 12 workspace consolidation deferred deleting `render.yaml`, `scripts/run-render-migration.sh` and `scripts/test-run-render-migration-env.sh`. They are removed in the same change as this record.

The AWS migrator never used these files: `runtime.tf` overrides the task command with `/app/scripts/run-schema-migration.sh --run-once`, and CI tests only that script. The `Dockerfile` `default-runtime` stage overrode `CMD` to call `run-render-migration.sh`. Only a Render migrator service used that path, and that service had already been deleted. With the override gone, `default-runtime` inherits the `runtime` stage's command. Removing the script changes the backend image, so re-check any image already checked against an earlier `main`.

Retiring the live Render resources (`scout-backend` and `scoutdb-preprod-v1`) is a separate step under R04, after cutover, stabilization and the retention review.
