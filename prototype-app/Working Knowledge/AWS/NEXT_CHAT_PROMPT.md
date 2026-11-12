Continue ScoutGrid Part 1 in the isolated checkout
`/private/tmp/scoutgrid-part1-postmerge-20261111`, now on
`codex/aws-part1-budget-50`. Preserve `/Users/karthik/Desktop/SG`: it has 217
pre-existing changed entries. Do not reset, stash, clean or commit it wholesale.

Read `AWS_MASTER_MIGRATION_PLAN.md`, `STANDARD_IMPLEMENTATION_READINESS.md`,
`release-evidence/postmerge-20261111/README.md`, and the current
`EXECUTION_AUTHORIZATION_20261111.md` and `authorized-budget-20261111.json` there.
The primary workspace's integrated-lab evidence is historical preparation.

PR #69 was manually merged by AxC-SG on November 11 at 17:19:53 UTC as
`4678580ab0a84c6cd2dfd96a02cfedc168e0a9cf`. Its tree exactly matches PR head
`5dfb9ed3a05a9d703826bee3ea67ae41af2ef9a6`. All four required main-push workflows
passed: Quality 43067107769, Trivy 43067107850, Semgrep 43067107669 and Performance
43067107897. Full browser sweep 43061543315 passed on that PR head.

The owner explicitly authorized one replacement PR for the subsequent budget
records and Terraform budget guard: PR #70. Its first Trivy run 43131822238 failed
because the two exact-PURL Spring advisory exceptions expired at 00:00 UTC on
November 12. Fresh vendor/source review confirms no XSLT views or SSE fragments.
The repair renews only those exceptions until 00:00 UTC November 19 and adds the
applicability guard to the AWS candidate job. See
`prototype-app/docs/security-scan-exceptions.md`. Eight CI contracts and the two
applicability controls pass locally. Verify the repaired head's remote checks;
never reuse the first failed run or earlier successful source as its evidence. Use the budget branch above; do not reopen
#69 or create concurrent change PRs. The owner merges manually. Never merge or
enable auto-merge. Verify the replacement PR's current state before acting.
Current qualification is retained in
`/private/tmp/scoutgrid-postmerge-artifacts/budget-pr-final-qualification.json`.

Retain the exact `4678580` backend/frontend build artifacts in
`/private/tmp/scoutgrid-postmerge-artifacts/main-4678580/` and verify manifest,
archive, layer/config identity, platform V15/tenant V20 and all SQL/source bytes.
The frontend archive is CI-default configuration, not a configured lab build.
If the replacement PR changes main, qualify the new exact main SHA and retain
its new backend/frontend pair. Earlier artifacts do not qualify changed source.
No ECR publication digest or independent publication approval exists yet.

The owner authorized **$50 USD total monthly Sydney lab spend**, including prior
charges, unposted usage, tax and contingency. This supersedes older $20 and
unapproved-budget statements. Do not request the increase again. Allocate **$25
inclusive** to the application run. November 12 Cost Explorer estimates
$0.2371053074; the conservative prior-run allowance plus posted costs, tax and
variance is about $4.59, leaving $20.41 unallocated after the run reserve. This
intentionally double-counts any overlap rather than understating costs. The
application model is $14.58 at four hours or $16.69 at eight inclusive. These are
planning allowances, not a final bill. Recalculate with refreshed costs before
billable creation. Target four hours from the first billable dependency; start
cleanup at hour four if incomplete, sooner on failure or usage overrun; complete
cleanup by eight. Codex executes/verifies cleanup in the active chat; owner is
fallback. The application clock has not started.

Lab: account `736486260824`, `ap-southeast-2`, `lab.scoutgrid.io` /
`api-lab.scoutgrid.io`, one NAT, `github_publisher=null`. Production account
`560246495987`, `us-east-1`, has no change authorization. Stage B ten-customer /
24-hour capacity, recovery, security/observability, cutover and stabilization remain
separate open gates. This bounded lab does not complete Part 1.

The free non-exportable API ACM certificate is ISSUED:
`arn:aws:acm:ap-southeast-2:736486260824:certificate/2fdafd2b-1c89-47d0-80ba-d27158736e40`.
Its exact DNS-only validation CNAME was separately approved and saved in
Cloudflare; no application-routing record exists. The existing Sydney CloudShell
session was previously verified for CLI and identity only; reverify it before use.
No billable application stack was created.

Only the limited ScoutGridSydneyLabPlan role exists among ScoutGrid roles.
The three emitted release policies are unattached; synthetic validation is not
effective-role evidence. Complete concrete infrastructure/cleanup permissions,
trusted bootstrap review of the five runtime roles/task definitions, final-ARN
positive/negative and assumed-role checks, protected state/lock checks, secret
custody/disposition, exact release approval independent of the publisher, ECR
publication/digest, exit-once bootstrap (one SG Internal), then live managed login,
onboarding/email, durable upload/findings, isolation and scheduling/replacement.
Initial owner: scoutgrid.io@gmail.com; SG Internal admin: scoutgridtenant@gmail.com.
Customer fixture alias and live Turnstile pair remain to be frozen. Remove pinned
enrollment-secret access before starting services. Never expose values or
credentials. Preserve retired keys' December 11 deletion schedules; never revive
them. Freeze a normal saved cleanup plan retaining ECR/state history, with no
blanket destroy, force-delete or state removal. Agree new key/secret/log/backup and
certificate/DNS disposition before creating dependents.
