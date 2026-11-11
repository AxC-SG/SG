# Proposed bounded Sydney application run

**Not approved; do not execute from this document alone.** This is the next
application milestone, not Part 1 production approval or another standalone
foundation exercise.

| Item | Proposed boundary |
| --- | --- |
| Account and region | `736486260824`, `ap-southeast-2` only |
| Release | Final manually merged PR #69 SHA; four successful same-SHA main checks, retained scanned archive, paired frontend build/config and independent exact-candidate approval |
| Hosts | `lab.scoutgrid.io`, `api-lab.scoutgrid.io`, and their exact ACM/Amplify validation records; production records unchanged |
| Capacity | One NAT/EIP, two-AZ private task/DB subnet boundaries, private Single-AZ PostgreSQL 16.15 `db.t4g.medium`/100 GiB, one 0.5 vCPU/2 GiB API and one 1 vCPU/4 GiB worker |
| Execution | Bootstrap with services stopped; exactly one SG Internal; remove enrollment access before starting API/worker; ten-customer policy retained |
| Spend | Up to $15 reserved for this run, subject to all posted/known unposted charges and tax/variance fitting within the existing $20 monthly ceiling |
| Clock | Target four hours from first billable create; start cleanup at hour four if tests are incomplete; finish cleanup by hour eight |
| Operator | Codex in this active chat executes and verifies cleanup; owner must be available as fallback and for credential setup/browser sign-in |
| Publication | Scoped operator publishes the exact scanned image; record ECR registry digest; `github_publisher = null` |
| Tests | Managed sign-in/role separation, one approved customer onboarding flow, durable BOM upload through findings, tenant/object denial checks, and bounded scheduling/replacement tests |

The previously prepared model reserves approximately $11.93 before tax for four
hours and $13.72 before tax for eight, including conservative usage/retention
allowances. These are planning allowances, not a guaranteed bill. The latest
billing read is estimated and does not yet reconcile the completed foundation
run. Do not start if a conservative reconciliation, tax and variance cannot fit
the monthly ceiling. No 24-hour capacity soak or new security-control retention
programme is included in this reserve.

Before billable creation, complete the reviewed infrastructure/cleanup access
scope, a fresh scoped execution path, protected state/backend verification,
candidate decision, DNS plan, secret custody and cleanup inventory. The three
unattached policy profiles in this PR cover publication, migrations and API/worker
service operation; they are not a complete infrastructure apply role. Revalidate
generated ARNs and effective assumed permissions after provisioning dependencies.
Do not attach old foundation policies with retired resource IDs or revive old
keys scheduled for December 11 deletion.

Separate trusted bootstrap review is required for the five ECS roles and their
inline policies and the task definitions. Do not give the ordinary service
operator permission to edit IAM policies or register arbitrary task definitions.
The service operator cannot select the privileged migrator; the migration
operator remains privileged because ECS IAM cannot constrain command/environment
overrides or RunTask networking. Service desired counts are not an IAM-enforced
budget cap. Review exact plans and requests, and stop on unexpected changes.

At completion/deadline, stop admissions and services, wait for tasks to stop,
inventory disposable identities/data, and review deletion-protection transitions.
Delete only captured lab objects/versions/multipart uploads and disposable runtime
resources. Use a reviewed normal saved plan that retains the exact immutable ECR
repository/image and protected state history; never force-delete ECR, remove it
from state, or use a blanket destroy. Fresh plans must reject unexpected creates,
ECR replacement/deletion, state-bucket changes and any production resource.

Agree the disposition of newly created ACM validation records/certificate,
runtime/enrollment secrets, recovery keys, logs and any backups before execution.
Keep keys until every dependent object and backup is disposed of or deliberately
retained. Secret/key deletion schedules are separate explicit cleanup decisions;
no existing key deletion schedule may be cancelled for reuse.

The customer fixture alias, identity setup/email delivery, actual DNS targets,
secret version references and final resource inventory still need to be frozen
before their respective actions. This budget decision alone does not approve
unreviewed identities, secret mappings, IAM expansion or DNS targets.

Stage B ten-customer/24-hour capacity, full security/observability and recovery,
production rollout and stabilization require their own approved scope, budgets
and evidence. This application run does not close those Part 1 gates.
