# Remaining Sydney lab access and cleanup review

This is a concrete additional access grant review, not another budget or backend
publication decision. Account 736486260824, ap-southeast-2 only. The existing owner
operator is the only trusted principal. All operator sessions are limited to one
hour. No production account, GitHub OIDC publisher or permanent access key is used.

The publisher role is already explicitly approved and created. This review does
not request its approval again. No other role below has been created or expanded.

## Roles and attachments

Create these eight temporary operator roles. Create/attach only the reviewed
managed-policy shards identified in role-grant-manifest.json. All shards are
below the IAM managed-policy size limit; no administrator policy is attached.
Trust only arn:aws:iam::736486260824:role/managed/AccountFullAccessRole.

| Role | Granted responsibility and limits |
|---|---|
| ScoutGridSydneyLabBootstrap | Tagged fresh symmetric lab KMS keys, the two exact private lab artifact buckets, one planned lab Cognito pool/Amplify app, and the ECS service-linked role constrained to ecs.amazonaws.com. Trusted runtime bootstrap is limited to the five exact scoutgrid-lab API/worker/migrator execution/task roles, their reviewed inline policies/trust and the three exact task families. API CPU/memory is 512/2048; worker and migrator 1024/4096; Fargate only; privileged containers denied. PassRole only these five roles to ecs-tasks.amazonaws.com. No operator self-policy editing, arbitrary managed-policy attachment, RunTask or service deployment. |
| ScoutGridSydneyLabApply | Exact encrypted state/lock writes and Sydney metadata; tagged lab network creation, private managed-password RDS named scoutgrid-lab, the new pool/app components, immutable scoutgrid-lab-backend repository, captured runtime networking, log groups, ALB/HTTPS listener/target group and regional WAF. No IAM writes, task registration, secret-value reads or ECR deletion. Service creation/updates use only the separate reviewed API/worker policy bound to final task revisions and private subnets. |
| ScoutGridSydneyLabTeardown | Normal saved-plan cleanup of captured lab services/tasks, roles, logs, ALB/WAF, database/groups, disposable backups, network and approved object versions/buckets. Final resource IDs must be captured and checked. ECR/state history deletion is explicitly denied. Newly captured secrets use seven-day recovery without force deletion; database/object keys may be scheduled for 30-day deletion only after all consumers are gone. The application-secret key remains usable for secret recovery. |
| ScoutGridSydneyLabMigration | The qualified main Terraform migration-operator output only: exact final migrator revision/cluster, migration launch tags, one migrator execution role, tagged migration task inspect/stop, and its log group. No task registration, IAM writes or direct secret reads. ECS IAM cannot constrain command/env or all network overrides, so review the exact private, count-one exit-once request under this trusted session. |
| ScoutGridSydneyLabService | Qualified main Terraform service-operator output only: exact API/worker revisions, private task subnets, no public IP/exec/EBS enablement and only their corresponding roles. Cannot select/pass the migrator, register definitions or edit IAM. IAM does not cap desired counts; reviewed plans and the timed run enforce one API/one worker. |
| ScoutGridSydneyLabSecretCustody | Create/write/tag/inspect metadata for only scoutgrid-lab/runtime-db, application-settings and managed-installation under the fresh application KMS key. KMS GenerateDataKey/Decrypt only through Sydney Secrets Manager for those secret ARNs. GetSecretValue/BatchGetSecretValue explicitly denied. Values are generated/entered inside the authorized runtime and never printed, passed as CLI arguments, put in source/Terraform, or returned to chat. |
| ScoutGridSydneyLabIdentity | AdminCreateUser/AdminGetUser/DescribeUserPool only in the final new lab pool. Only the three approved aliases may be enrolled or sent setup emails: scoutgrid.io@gmail.com, scoutgridtenant@gmail.com and karthikjd9@gmail.com. IAM cannot enforce email alias values; the trusted exact request must. No password-setting/reset, IAM, secret or other-pool access is granted. Human password/MFA entry stays with the owner. |
| ScoutGridSydneyLabFrontend | Manual deployment/job inspection only on the new Amplify app's lab branch; association only for the child domain lab.scoutgrid.io. No production/apex domain association, DNS administration, IAM or secrets. Exact live frontend configuration/hash still requires its own review. |

Expand the existing ScoutGridSydneyLabPlan inline policy only to the reviewed
Sydney runtime metadata reads, the same exact encrypted state read and single
lock path. No secret values or application mutation permissions are added. Retain
its existing owner-only trust and one-hour limit. Restore its original narrower
inline policy after lab cleanup.

The trusted bootstrap permission to write the five runtime role policies is
security-sensitive: IAM cannot enforce the JSON policy contents. Only the exact
qualified main task policies and final secret/image/cluster references may be
used, after reviewing the saved plan and task definitions. It is not ordinary
operator permission to add arbitrary privileges.

## Final binding and execution gates

The template files are not attachable final policies. Replace RENDER_ tokens only
with captured new lab IDs from the reviewed plan/readback. Never attach synthetic
fixtures. Preserve account/region, names, tags, action lists and fixed trust;
reject production references, old keys, unrelated VPCs and unexpected creates.
Validate and simulate the final ARN documents, verify actual assumed callers and
harmless allowed/denied metadata requests, and review saved plans before use.
There is no delegation to widen a policy beyond this review. If an unsupported
permission is discovered, stop and review the precise correction.

The migration/service documents must be generated from the qualified main root's
lab_operator_policy_documents output and re-bound after every revision, including
removal of enrollment access before service startup. No IAM bypass substitutes
for those checks. Publisher approval is for the retained exact archive already
recorded, not a local rebuild.

Access Analyzer found no issues in the reviewed policy shards after correcting
condition types and using distinct synthetic resource IDs. The synthetic suite
passed tagged/missing-tag, wrong region/key/role, Fargate/privileged/CPU and secret
custody negatives. The final retirement suite additionally denies application-key
retirement while recovery secrets exist, old-key schedule changes and forced
secret deletion. These checks do not prove final live access or API dependency
coverage. Exact final-ARN and actual-role checks remain mandatory.

## Cleanup disposition requested with this grant

The run remains bounded by the standing $50 inclusive monthly ceiling and $25
application allocation, target four hours, cleanup completed by eight. Freeze the
first billable-create timestamp and all resource IDs before proceeding. This is
an integrated application test, not a repeated standalone foundation exercise.

At completion/failure/deadline, stop admissions/services/tasks, remove only the
new lab routing DNS/Amplify association if created, and delete the captured
disposable lab database, test identities/data, backups and object versions after
protection transitions are reviewed. Do not delete unrelated or held material.
Use a NORMAL reviewed cleanup plan against the same protected state, with the
exact ECR repository/image retained and no unexpected creates/replacements. No
blanket destroy, ECR force-delete or removing retained resources from state.

Retain the immutable image/repository and protected state history. Retain the
existing free non-exportable API certificate and its already-approved DNS-only
validation record; no production DNS is changed. Remove temporary operator roles
and policy objects, including the publisher, and restore the original plan policy.
Retain the ECS AWS-managed service-linked role if created.

New runtime/application/enrollment secrets get seven-day recoverable deletion,
never forced deletion. Keep their application KMS key enabled until recovery
secrets are physically gone; record it as intentionally retained, with its cost
included in the full-month reserve and a later owner-reviewed retirement action.
Database/object keys can be scheduled for deletion after 30 days only after every
dependent object, secret and backup is gone. If a managed dependent still needs a
key, retain the usable key/state record and report it explicitly rather than
claiming zero retained resources. The full-month KMS/secret allowances already
cover this conservative retention inside the $25/$50 allocation. No follow-up
scheduler or new retention programme is created by this approval.

Never cancel, enable or change the two previous keys' December 11 schedules.
Production, the separate 24-hour soak, security-control retention programmes,
unbounded provider/feed jobs, and unsupported IAM expansion remain excluded.

## Current facts

Exact main 0ae3de9f4e4f7b1f784622d31656f30a89499043 has all four required workflows
passing and independently approved backend publication. Fresh limited-role plan:
54 creates, zero changes/deletes, one NAT/EIP, private encrypted db.t4g.medium;
plan SHA-256 328d9e9724b336722b367654e27c5af310c6d1f0878b83c92ec046b700ba6369.
No billable application creation or image publication has occurred. Live Turnstile,
secret custody, final permissions and browser credentials remain preconditions.
