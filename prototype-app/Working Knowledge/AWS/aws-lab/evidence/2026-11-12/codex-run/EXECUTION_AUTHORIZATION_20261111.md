# Current Sydney application lab decisions

This record supplements the frozen PR #69 source evidence at
5dfb9ed3a05a9d703826bee3ea67ae41af2ef9a6. It does not modify the dirty primary
workspace or approve a production deployment.

The owner's latest continuation prompt authorizes **$50 USD total for the month**
in account 736486260824, ap-southeast-2, including prior charges, unposted usage,
tax and contingency. It explicitly supersedes every older $20 ceiling and pending
budget statement. Do not ask the owner to approve this increase again.

Allocate **$25 inclusive** to the bounded integrated application run. The November 12
Cost Explorer refresh estimates $0.2371053074 excluding credits/refunds; some
November 11 foundation usage has posted. Final usage and tax are not reconciled. The conservative prior-run bound remains
$4.5932471614 including assumed 18% tax and variance; it is not a final bill.
The historical application model is $14.5817572712 at four hours and
$16.6926033425 at eight, including 18% tax and $0.50 variance. After the prior-run
bound and $25 reserve, $20.4126629707 is unallocated monthly contingency. The
calculator and retained prior bound reproduce these figures without claiming a
fresh price quote or reconciled invoice. Do not spend the unallocated balance on
additional scope automatically.

Target four hours from the first billable application dependency creation; start
cleanup at hour four if tests are incomplete, earlier on failures, unexpected
usage or loss of cleanup capability. **Complete cleanup by eight hours** and stop
sooner if necessary to preserve the $25 run reserve and $50 inclusive monthly
ceiling. Codex executes and verifies cleanup in this active chat, with the owner
as fallback. This authorization persists. Production, the separate 24-hour
capacity soak, new security-control retention programmes and unbounded jobs are
excluded. Other release/access/secret prerequisites are not waived.

A non-exportable Amazon-issued RSA-2048 public ACM certificate was requested for
api-lab.scoutgrid.io only:
arn:aws:acm:ap-southeast-2:736486260824:certificate/2fdafd2b-1c89-47d0-80ba-d27158736e40
Created at 2026-11-11T16:56:56.155Z. Export is DISABLED. No private key was
retrieved; no billable application stack was created.

The owner separately approved the exact DNS-only certificate validation record
at the Cloudflare Save action. The UI then displayed the saved record:

    _62ca8e284273e6c9feb063274b88f0c6.api-lab.scoutgrid.io CNAME
    _7969bc1f72c5e93b4980475661a1c07f.wzccmgtwzk.acm-validations.aws

TTL Auto; proxy off. Production api, apex and www records were unchanged.
A fresh ACM DescribeCertificate read confirms ISSUED, issued at
2026-11-11T17:07:27.059Z, Export DISABLED, InUseBy empty. No application routing record
has been created. Retention/removal of this certificate and validation record
must be included in the final cleanup disposition.

An existing CloudShell session was verified in the lab account, Sydney, with
AWS CLI 2.39.6. Only CLI version and STS caller identity were executed there.
No deployment, role attachment, secret-value retrieval or credential export was
performed. The existing limited ScoutGridSydneyLabPlan role remains available;
the three generated release operator policies are unattached and synthetic
simulation success is not effective live-role authorization.

PR #69 was manually merged as `4678580ab0a84c6cd2dfd96a02cfedc168e0a9cf`.
The owner authorized one replacement budget PR on `codex/aws-part1-budget-50`.
Exact merged main workflows and retained backend/frontend artifacts are required;
neither its base-main archive nor PR checks replace that qualification. Full
infrastructure/cleanup scopes, final-ARN negative checks, secret custody,
independent candidate approval, identities and live application tests remain
required. Part 1 is still open.

## Current preparation and remaining boundary

The refreshed read-only inventory at 17:20 UTC confirms no ECS clusters, RDS
instances, ECR repositories or secrets, including pending-deletion secrets.
The two retired KMS keys remain PendingDeletion on December 11 at their original
times. Neither schedule was changed. The application clock has not started.

Only `ScoutGridSydneyLabPlan` exists among the ScoutGrid roles. Its existing
inline policy permits limited foundation reads and exact protected state/lock
access; it cannot perform the integrated apply/cleanup or inspect the runtime.
The connected metadata reader uses AccountFullAccessRole. That broad reader is
not evidence of an effective scoped deployment role. AWSServiceRoleForECS is
absent. No policy or trust relationship was changed.

All four required main workflows passed on `4678580a`; full browser sweep
43061543315 passed on PR #69 head `5dfb9ed3`, whose source tree is identical.
The replacement budget PR requires fresh checks. Its final results are retained
in `/private/tmp/scoutgrid-postmerge-artifacts/budget-pr-final-qualification.json`.
Offline Terraform validation and all 19 Standard mock plans pass, including
acceptance of $50 and rejection of $50.01. No live provider or deployment ran.

The replacement budget PR is the only authorized active change PR. The owner
merges manually; no auto-merge. After its merge, qualify the exact new main SHA,
retain its backend archive and frontend bundle, verify archive/config/layers,
packaged platform V15/tenant V20 and SQL bytes, and prepare independent candidate
approval naming the SHA, Trivy run, archive hash, frontend configuration/hash,
account/region/repository and publisher identity. A manual PR merge by itself
does not establish this publication decision.

Complete concrete infrastructure apply/cleanup policies and trusted bootstrap
review for five runtime roles/inline policies and exact task definitions. Rebind
all dependency ARNs, verify effective assumed-role positive/negative checks,
freeze the normal ECR-retaining cleanup plan and verify state/lock recovery before
billable creation. The synthetic three-profile policy evidence remains useful
but does not establish effective live permissions. Do not attach retired
foundation policies or revive the retired keys.

Secret custody remains metadata-only until the release is frozen: create fresh
application key material inside the authorized runtime, store restricted DB and
application JSON separately, pin the enrollment version, and let ECS inject
values. Never print values or put them in Terraform, CLI arguments, chat, source
or evidence. Verify the selected owner/internal-admin Cognito mappings and remove
enrollment access before services start. A live Turnstile pair for
lab.scoutgrid.io and the customer fixture alias are still required. Agree new
certificate/DNS/secret/key/log/backup disposition before creation; preserve
retained ECR and protected state history. No application-routing DNS change has
been made.

Part 1 remains OPEN. Live managed sign-in, onboarding/email receipt, durable
upload/findings, tenant/object isolation and scheduling/replacement are not yet
qualified. Security/observability, Stage B capacity and 24-hour soak, timed
recovery, production cutover and stabilization remain separate open gates.
