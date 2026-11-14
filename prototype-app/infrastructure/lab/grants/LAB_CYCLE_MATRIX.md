# Lab cycle and cutover IAM matrix (attached November 13, 2026)

**Update, November 13, 2026 (after Amplify retirement):** `ScoutGridSydneyLab-cutover-once` was detached from `ScoutGridSydneyLabApply` and deleted, and the Amplify-only inline policies `CapturedLabExecution` and `LabDeployAndDomain` were removed from `ScoutGridSydneyLabFrontend`, which now has no permissions. The cycle role remains.

**Attached 2026-11-13 with owner approval.** `lab-cycle.json` is the inline policy `LabCycle` on role `ScoutGridSydneyLabCycle` (trust: the `AccountFullAccessRole` sign-in, as for the other lab roles; max session 2 hours), alongside the existing managed `ScoutGridSydneyLab-common-read-state-part1/part2` and `ScoutGridSydneyLab-waf-association-read`, and the managed `ScoutGridSydneyLab-cycle-watch` (`lab-cycle-watch.json`: ECS service-deployment reads Terraform needs while waiting for a rollout; split out because the inline policy is at IAM's 10,240-byte limit). `s3:GetBucketWebsite` and the deployment reads were added during the November 13 cutover, when Terraform needed them. `lab-cutover-once.json` is the managed policy `ScoutGridSydneyLab-cutover-once` attached to `ScoutGridSydneyLabApply` (the role's inline policies were already at the 10,240-byte limit). Access Analyzer reported no findings for either, and `lab.sh simulate` passed 37/37. Both are generalized from grants proven on November 12. Exact IDs that change every cycle (ALB, target group, WAF, NAT, EIP) become name or tag scopes. IDs that persist (route tables, services, cluster, database, pool, buckets) stay exact.

| Document | Principal | Lifetime |
|---|---|---|
| `lab-cycle.json` + existing `common-read-state` | new role `ScoutGridSydneyLabCycle`, profile `sglab-cycle` | Permanent while the lab is the only environment |
| `lab-cutover-once.json` | managed policy on the existing Apply role, detached afterwards | The one-time origin change, budget creation and Amplify retirement |

Task definitions are registered only by the existing Bootstrap role (`bootstrap-trusted-runtime.live.json`). The cycle role cannot register task definitions, so `lab.sh` stops any cycle plan that wants a new revision and sends it to the Bootstrap path.

## Repeat cycles (`lab.sh up` / `lab.sh down`)

| Terraform resource | Up actions | Down actions | Scope | Source |
|---|---|---|---|---|
| `module.network.aws_eip.egress` | `ec2:AllocateAddress`, `ec2:CreateTags` (on create) | `ec2:DisassociateAddress`, `ec2:ReleaseAddress` | `elastic-ip/*` with lab request/resource tags | New (create); teardown proposal (delete) |
| `module.network.aws_nat_gateway.zonal` | `ec2:CreateNatGateway`, `ec2:CreateTags` (on create) | `ec2:DeleteNatGateway` | `natgateway/*` with lab tags; subnet and EIP must carry lab tags | New (create); teardown proposal (delete) |
| `module.network.aws_route.task_egress` | `ec2:CreateRoute` | `ec2:DeleteRoute` | the two task route tables (exact) | New (create); teardown proposal (delete) |
| `aws_lb.api` | `CreateLoadBalancer`, `ModifyLoadBalancerAttributes`, `AddTags`, `SetWebAcl`, `ec2:DescribeAccountAttributes`, ELB service-linked role once | `DeleteLoadBalancer` | `loadbalancer/app/scoutgrid-lab-api/*` | `apply-runtime-ingress.json`, teardown proposal |
| `aws_lb_target_group.api` | `CreateTargetGroup`, `ModifyTargetGroupAttributes`, `AddTags` | `DeleteTargetGroup`, `DeregisterTargets` | `targetgroup/scoutgrid-lab-api/*` | same |
| `aws_lb_listener.https` | `CreateListener` (HTTPS, TLS 1.3 policy only), `ModifyListener` | `DeleteListener` | `listener/app/scoutgrid-lab-api/*` | same |
| `aws_lb_listener_rule.api` | `CreateRule`, `ModifyRule` | `DeleteRule` | `listener-rule/app/scoutgrid-lab-api/*` | same |
| `aws_wafv2_web_acl.api` | `wafv2:CreateWebACL`, `wafv2:TagResource`, managed rule groups | `wafv2:DeleteWebACL` | `regional/webacl/scoutgrid-lab-api/*` | same |
| `aws_wafv2_web_acl_association.api` | `wafv2:AssociateWebACL` | `wafv2:DisassociateWebACL` | the lab WAF and ALB | same |
| `aws_ecs_service.backend` | `ecs:CreateService`, `ecs:TagResource` (on create), `iam:PassRole` (api/worker roles only) | `ecs:UpdateService` (desired 0), `ecs:DeleteService`, `ecs:DescribeServices` | `service/scoutgrid-lab/{api,worker}`, any revision of the `scoutgrid-lab-api` / `scoutgrid-lab-worker` families | `service-operator-v2.json` (revision pin widened) |
| RDS `scoutgrid-lab` (outside Terraform) | `rds:StartDBInstance` | `rds:StopDBInstance` | `db:scoutgrid-lab` | teardown proposal |
| Refresh of every resource in state | `common-read-state` (S3 state, lock, KMS, EC2, RDS, Cognito, Amplify, ECR, ECS, IAM, ELB, WAF, logs, secret metadata), `s3:GetBucketWebsite` on the two lab buckets, and `budgets:ViewBudget` | same | as reviewed | `common-read-state.json`, `provider-bucket-metadata.json`, new budget read |
| `lab.sh status` / `lab.sh simulate` | `ce:GetCostAndUsage`, `ce:GetCostForecast`; `iam:SimulatePrincipalPolicy` on the cycle role itself | — | account / own role | New |

The ALB security group and its two rules, task definitions, roles, log groups, the ECS cluster, RDS, Cognito, S3, KMS, secrets and ECR are kept in both modes. The cycle role has no permission to change or delete them.

## One-time transition (`lab-cutover-once`)

| Change | Actions | Principal |
|---|---|---|
| `frontend_origin` → `https://scoutgrid.io`: imports bucket CORS | `s3:PutBucketCORS` | Apply + cutover grant |
| Cognito invite link and logout URL | `cognito-idp:UpdateUserPool`, `cognito-idp:UpdateUserPoolClient` | Apply + cutover grant |
| New api/worker task-definition revisions (CORS, base URL, Turnstile host) | `ecs:RegisterTaskDefinition`, `iam:PassRole` | Bootstrap (existing `bootstrap-trusted-runtime.live.json`) |
| Retire replaced revisions | `ecs:DeregisterTaskDefinition` | Bootstrap (existing `bootstrap-retire-migrator-revision.json`) |
| Roll services to the new revisions | `ecs:UpdateService` on any revision of the two families | Apply + cutover grant (later the cycle role) |
| Lab budget at $100 | `budgets:ModifyBudget` (also authorizes creation), `TagResource`, reads | Apply + cutover grant |
| GitHub ECR publisher role (PR #107; targeted apply of `aws_iam_role.github_publisher` and its policy only) | `iam:CreateRole`, `PutRolePolicy`, reads, tags and delete, on `scoutgrid-lab-github-ecr-publish` only | Bootstrap + inline `GithubPublisherRole` (`bootstrap-github-publisher-role.json`, proposed 2026-11-15; Access Analyzer: no findings) |
| PR 2: retire Amplify | `amplify:DeleteDomainAssociation`, `DeleteBranch`, `DeleteApp` on app `d20ebk72hfk5ft` | Apply + cutover grant |

Detach `lab-cutover-once` and `frontend-deploy-and-domain.json` once Amplify is gone.

## Proof before relying on lab-down

1. IAM Access Analyzer `validate-policy` on both documents: no errors or security warnings.
2. `lab.sh simulate` runs `iam simulate-principal-policy` against the attached cycle role for every row above, in both the up and down columns, using representative ARNs. Any denial fails the command. `elasticloadbalancing:SetWebAcl` is granted but excluded: the simulator does not recognize it and denies it even for the Apply role that used the same grant live on November 12.
3. `lab.sh down` runs the up-set simulation first and refuses to continue if it fails. The lab is never parked by a role that cannot bring it back.
