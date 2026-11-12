# Standard Part 1 Sydney lab preflight

Recorded November 9, 2026 by Codex. Scope covers Q01 candidate checks, offline A02/A03 foundation validation, and read-only inventory of Sunlit Servers (`736486260824`) in Sydney (`ap-southeast-2`). The planned ECR repository is `736486260824.dkr.ecr.ap-southeast-2.amazonaws.com/scoutgrid-lab-backend`.

## Q01 candidate evidence

| Field | Recorded value |
| --- | --- |
| Source | `cd741250faf4a098d1519f073f7e38a0f503016e` on `main` |
| GitHub Actions | [Quality](https://github.com/AxC-SG/SG/actions/runs/42509402543), [Trivy](https://github.com/AxC-SG/SG/actions/runs/42509402323), [Semgrep](https://github.com/AxC-SG/SG/actions/runs/42509402389) and [Performance Governance](https://github.com/AxC-SG/SG/actions/runs/42509402788) all succeeded on this SHA |
| Retained artifact | [aws-backend-candidate-42509402323](https://github.com/AxC-SG/SG/actions/runs/42509402323/artifacts/13628534378) |
| Image archive SHA-256 | `5fa3237a27ee8539f908bf8619d0d93a4b8ff953867cb40d552a9aac59bd5bf2` |
| Image config ID | `sha256:1e48f3a8ace25d3a402eba21aeb9fffcb22bc7dfb8ba7662ce1ca5291cb03176` |
| Sydney RDS bundle SHA-256 | `d73890748b5a95551800df8a6f07c9c800e32ed34da7e6c9505918bf8ac2398b` |
| Migration heads | Platform V15 and tenant V20 |
| Reviewer, publication and ECR digest | Pending |

Downloaded the retained artifact and exact source into a temporary directory. The image archive and config hashes matched the manifest. Static image inspection confirmed Linux/amd64, the configured non-root user, both Dockerfile-pinned RDS CA bundles, and byte-for-byte matches for the migration wrapper and versioned SQL. The image was inspected offline without starting a container.

Local migration validation, tenant DDL ownership checks, schema migration environment tests and all five CI contract tests passed. Live PostgreSQL bootstrap and service qualification remain open.

## A02/A03 foundation validation

Terraform 1.13.5 with locked AWS provider 6.64.0 passed formatting, validation and all 13 repository mocks on the exact source. A separate temporary Sydney foundation mock passed with 56 planned creates, zero changes and zero destroys. It used `backend_candidate = null` and `github_publisher = null`, the documented Sydney AZ pair and PostgreSQL 16.15, and fixture CIDR and HTTPS origins. The mock showed private, deletion-protected RDS and an immutable ECR repository. It omitted the publisher role, ECS task definitions, ECS services and ALB. The backend was disabled and the provider was mocked.

## Live Sydney inventory

After reconnecting, AWS Core returned `Unknown tool` before dispatch. The signed-in AWS Console and STS from AWS CloudShell verified account `736486260824` in Sydney. The CloudShell session used `AccountFullAccessRole` for inventory.

| Check | Live result |
| --- | --- |
| Availability Zones | The planned `apse2-az1` and `apse2-az3` are available as `ap-southeast-2a` and `ap-southeast-2b`. `apse2-az2` is also available. |
| VPCs | One default VPC with CIDR `172.31.0.0/16`. The mock CIDR `10.21.0.0/16` does not overlap this VPC. Confirm any connected networks and address allocations before assigning it. |
| RDS | PostgreSQL `16.15` is available. Sydney returned zero DB instances. |
| ECR | Sydney returned zero repositories. The planned lab repository needs to be created by the foundation. |
| State and operator | A full IAM role listing showed three AWS-managed account roles and nine AWS service-linked roles. It showed no scoped ScoutGrid deployment role. There were no S3 buckets or IAM OIDC providers in Sunlit Servers. A state backend in another account remains possible, with no reference found here. |
| DNS and TLS | The account returned zero Route 53 hosted zones. Sydney returned zero ACM certificates and Amplify apps. The lab frontend and API hostnames and their DNS owner remain unverified. |
| Other deployment records | Sydney returned no active CloudFormation stacks in the checked completion states and no Parameter Store names matching the project, state, or lab hostname terms. The application tag lookup returned only the Cognito pool identifier from the earlier disposable smoke test. |

CloudShell created `scoutgrid-lab-tfstate-736486260824-ap-southeast-2` in Sunlit Servers and read back its Sydney region, bucket-owner-enforced ownership, all four public access blocks, enabled versioning and default SSE-KMS encryption with S3 Bucket Keys. The enabled AWS-managed `aws/s3` KMS key is `arn:aws:kms:ap-southeast-2:736486260824:key/2731031f-d79e-4db9-afe6-94fb01cba15a`. The [backend configuration](../../../../infrastructure/terraform/standard/sydney-lab.s3.tfbackend) binds Terraform to this account and key and enables S3 locking on `standard/lab/terraform.tfstate.tflock`. Terraform 1.13.5 initialized the live backend and completed a plan containing only the backend configuration under the scoped role. S3 version history showed an acquired lock version and a current delete marker, confirming release. [Bootstrap script](../../../../infrastructure/terraform/standard/scripts/bootstrap-sydney-state.sh) · [Terraform S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3)

Public DNS returned NXDOMAIN for proposed names `lab.scoutgrid.io` and `api-lab.scoutgrid.io`. The parent domain delegates to Cloudflare. The [foundation inputs](../../../../infrastructure/terraform/standard/sydney-lab.foundation.tfvars) include those proposed origins and the mock CIDR `10.21.0.0/16`. Confirm the names with the DNS owner and the CIDR against connected networks before applying.

After explicit approval, AWS CloudShell created `arn:aws:iam::736486260824:role/ScoutGridSydneyLabPlan` and attached its inline policy `SydneyLabPlan`. The role trusts only the existing Sunlit Servers `AccountFullAccessRole`. It can read the lab Terraform state, manage the single lock object, use the Sydney S3 KMS key through that bucket, and read Sydney AZ, VPC and PostgreSQL engine metadata. IAM Access Analyzer returned zero findings for both policies before creation. AWS policy readback matched the local approved policy digests, and STS verified assumption by the Sunlit Servers operator. [Trust policy](../../../../infrastructure/terraform/standard/scripts/sydney-plan-role-trust.json) · [Permissions policy](../../../../infrastructure/terraform/standard/scripts/sydney-plan-role-permissions.json)

## Live foundation plan

Terraform 1.13.5 validated and planned the foundation against the live Sydney S3 backend while assumed as `ScoutGridSydneyLabPlan`. The uploaded configuration archive SHA-256 matched the approved `3a601fd9fb107d69804d117c1ab6adcc56f552719375b55526c5118ea14ceee8`. The temporary CloudShell copy needed the Linux package checksum for signed AWS provider 6.64.0. Terraform added one `h1:` entry and retained every original lockfile line. The provider version and foundation configuration stayed fixed.

The plan reported **56 to add, 0 to change, 0 to destroy**. It includes two NAT gateways and public IPv4 addresses, private Single-AZ PostgreSQL 16.15 on `db.t4g.medium` with 100 GiB gp3 storage, encrypted S3 buckets, Cognito, Amplify and immutable ECR. ECS services, the ALB and the publisher role are outside this foundation plan. The plan was saved in private CloudShell temporary storage as `/tmp/scoutgrid-sydney-live-plan.5tHZ3Y/sydney-foundation.tfplan` with SHA-256 `472dc8c87e534c99bf961580876db4f1c432584be163b91434d5c5ae4b6a06c8`.

## Live execution handoff

- **G00 / A01.** Role assumption and state locking passed. The November 10 Sydney inventory confirmed the proposed CIDR against the account's VPCs and connectivity. Confirm the run window and owner. Confirm the proposed HTTPS names with the DNS owner before publishing records or testing browser sign-in.
- **A02 / A03.** Review the completed foundation plan with the candidate and GitHub publisher unset. The [cost and teardown review](sydney-cost-and-teardown.md) proposes an eight-hour lab window and a $12 reserve. The Terraform dependency graph passed a mocked create and teardown. Finish and verify the scoped execution policy before provisioning.
- **Candidate publication.** This pass omitted publication. The release procedure requires a reviewer independent of the scoped publisher. Record the approval against this SHA, Trivy run and repository in the protected evidence location before the operator publishes and records the ECR digest.
- **A07 / A10 / Q02.** Use the recorded ECR digest with service startup disabled. Run the exit-once migrator through the approved operator, verify the schema heads and exactly one SG Internal workspace, and repeat bootstrap to check idempotency before starting services. Continue integrated workflow, capacity and recovery qualification from the plan.

The state bucket and scoped plan role are provisioned. G00 and live G03 qualification remain open. [Master migration plan](../../AWS_MASTER_MIGRATION_PLAN.md) · [Standard readiness and operator publication procedure](../../STANDARD_IMPLEMENTATION_READINESS.md)

## November 10 execution checks

AWS Core authenticated to Sunlit Servers and confirmed that Sydney has only the default VPC, `172.31.0.0/16`. The account reported no Sydney VPC peering connections, transit gateway VPC attachments, VPN connections or gateways, Client VPN endpoints, or VPC endpoints. The proposed `10.21.0.0/16` CIDR has no overlap in that inventory. The check covers this account and region. Check any allocations managed outside AWS before connecting the lab to another network.

RDS confirmed PostgreSQL 16.15 with encrypted gp3 on `db.t4g.medium` in all three Sydney AZs. Cognito returned no domain registration for `scoutgrid-lab-736486260824`. Both proposed public hostnames, `lab.scoutgrid.io` and `api-lab.scoutgrid.io`, returned authoritative Cloudflare `NXDOMAIN`. The foundation uses them as configuration values. DNS publication and certificate setup are separate from the foundation smoke test.

Cost Explorer reported estimated unblended spend of `$0.0002102821` for November 1–9, excluding credits and refunds. The $12 reservation still fits the $20 ceiling at this reading. Refresh spend immediately before the test. [Cost and teardown review](sydney-cost-and-teardown.md)

### Scoped execution role review

Keep the existing planning role for previews. The proposed execution role would trust the same operator principal, `arn:aws:iam::736486260824:role/managed/AccountFullAccessRole`, and use short sessions in Sunlit Servers. The review compared the foundation resource types with the pinned AWS provider's API calls and the AWS service authorization catalog. This table is the scope for the execution policy and still needs action-level validation before attachment. [AWS service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html) · [AWS provider source at v6.64.0](https://github.com/hashicorp/terraform-provider-aws/tree/v6.64.0/internal/service)

| Area | Proposed boundary |
| --- | --- |
| State and locking | State read and write on `standard/lab/terraform.tfstate` only. Read, create and remove the exact `.tflock` object. Scope S3 listing and the managed KMS key to the Sydney state bucket. |
| VPC and egress | Create the VPC, subnets, routes, NAT gateways, EIPs, S3 endpoint and database security group in Sydney. Require ScoutGrid lab tags for supported creates and check those tags on existing resources where AWS supports it. Check referenced VPC, subnet, route-table and EIP permissions separately from newly tagged resources on multi-resource EC2 calls. |
| RDS and managed secret | Scope to `scoutgrid-lab` DB and subnet group and `scoutgrid-lab-postgres16` parameter group. Bound the RDS-managed secret and KMS integration to the lab. The AWS-managed RDS service-linked role was created separately, so the execution role can omit `iam:CreateServiceLinkedRole`. [RDS service-linked role](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAM.ServiceLinkedRoles.html) · [RDS-managed secret permissions](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html#rds-secrets-manager-permissions) |
| S3, KMS and ECR | Scope bucket configuration to the named lab imports and exports buckets, repository administration to `scoutgrid-lab-backend`, and customer-managed KMS operations to the two tagged lab keys and integrated services. The foundation uses the default KMS key policy and does not supply a custom policy. [Default KMS key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html) |
| Cognito and Amplify | Bootstrap the pool and app, then scope subsequent writes to the verified pool, app and `lab` branch ARNs. No user enrollment, token traffic or frontend deployment belongs to this run. |
| Teardown | Use separately authorized deletion and protection changes against the IDs captured by the apply. Keep data purge, key retirement and handling of any retained backups within the approved teardown procedure. |

The execution scope does not include IAM administration, arbitrary role passing, DNS writes, ECR image publication, or production access. Some AWS catalog entries list dependencies for optional API parameters. Resolve those against the planned resource arguments before granting them.

### RDS service-linked role bootstrap

On November 10 at 19:35 IST, AWS Core verified the STS account was `736486260824`, then created `arn:aws:iam::736486260824:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS`. Separate IAM reads confirmed that the trust principal is `rds.amazonaws.com` and the attached policy is the AWS-managed `AmazonRDSServiceRolePolicy`. The role is account-wide and is outside the Terraform lab state and teardown. [RDS service-linked role](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAM.ServiceLinkedRoles.html)

The local foundation archive still matches SHA-256 `3a601fd9fb107d69804d117c1ab6adcc56f552719375b55526c5118ea14ceee8`. A fresh Cost Explorer read returned the same estimated `$0.0002102821` through November 9, excluding credits and refunds. The $12 reserve still fits the $20 limit at this reading.

### Execution policy validation and proposed bootstrap

IAM Access Analyzer returned zero findings for the proposed operator trust policy and a test statement allowing `amplify:CreateBranch` and `amplify:TagResource` on one fixture branch ARN. IAM simulation with the four Terraform request tags showed that `apps/*/branches/lab` allows both actions under either of two fixture apps. Replacing the wildcard with the lab app ID allowed both actions for the lab branch and denied both for the other app. A separate simulation showed that `kms:TagResource` on `key/*` with the same request tags could tag a fixture key outside the lab. KMS requires tagging permission when creating tagged keys, so request tags alone cannot enforce the intended boundary. These checks cover the submitted statements and fixture context. The complete execution policy and live service authorization still need validation. [Amplify service authorization](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsamplify.html) · [KMS tagging on create](https://docs.aws.amazon.com/kms/latest/developerguide/add-tags.html) · [IAM policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)

Use a separately reviewed bootstrap plan under the existing Sunlit Servers operator to obtain the generated ARNs. A backend-disabled Terraform 1.13.5 mock using AWS provider 6.64.0 and the reviewed Sydney inputs passed with **17 to add, 0 to change, 0 to destroy** for the targets below. The plan includes the Amplify app, Cognito pool, both KMS keys, and both artifact buckets with their security configuration. It preserves the Cognito, KMS and bucket destroy guards. The remaining foundation includes the Amplify branch, RDS and both NAT gateways. [Terraform resource targeting](https://developer.hashicorp.com/terraform/cli/commands/plan#resource-targeting)

1. Confirm the eight-hour lab window, operator and cleanup deadline, including authorization to delete the disposable lab data and backups. Refresh the cost check before the first billable create.
2. Use the reviewed source and default workspace of the existing lab backend. Save a plan with the targets below. Verify that it contains only the 17 expected creates before applying it. Capture the actual Amplify app, Cognito pool and KMS key ARNs and check their tags against state. Confirm the buckets are empty and their public access blocks and encryption settings are active.
3. Use those ARNs in the proposed execution policy. Limit branch creation to the new app's `lab` branch ARN and KMS operations to the specific keys. Complete Access Analyzer and action-level simulation checks, including denial outside the lab, before attachment. Generate a fresh untargeted foundation plan against the updated state and review its changes before applying it. Prepare teardown permissions against the exact created IDs and follow the protected-resource teardown procedure.

```sh
umask 077
bootstrap_dir=$(mktemp -d)
terraform plan -var-file=sydney-lab.foundation.tfvars -lock-timeout=30s \
  -target=aws_amplify_app.frontend \
  -target=aws_cognito_user_pool.humans \
  -target=aws_kms_key.database \
  -target=aws_kms_key.objects \
  -target=aws_s3_bucket_policy.artifacts \
  -target=aws_s3_bucket_ownership_controls.artifacts \
  -target=aws_s3_bucket_versioning.artifacts \
  -target=aws_s3_bucket_server_side_encryption_configuration.artifacts \
  -target=aws_s3_bucket_cors_configuration.imports \
  -out="$bootstrap_dir/sydney-bootstrap.tfplan"
```

### Apply and teardown policy drafts

The [apply policy](sydney-apply-policy.template.json) scopes the lab state and lock, requires ScoutGrid lab tags on EC2 creates, and checks resource tags independently on the referenced VPC, subnets, route tables and EIPs. It uses exact bootstrap ARNs for Amplify, Cognito and KMS and exact names for RDS and ECR. The RDS secret permission is limited to the Sydney `rds!db-*` namespace and requires a forwarded RDS call. The draft includes no secret-value retrieval. It still needs confirmation that the live RDS request supplies the expected `aws:CalledVia` context. [RDS Secrets Manager integration](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html#rds-secrets-manager-permissions) · [AWS IAM condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-calledvia)

The [teardown policy](sydney-teardown-policy.template.json) uses exact created EC2 IDs and exact application ARNs. It allows inspection and removal of empty buckets and the empty ECR repository. If approved disposable data is present, handle its removal separately under the teardown procedure. Use the operator to verify RDS snapshots and retained backups, which have their own generated identifiers.

Render `BOOTSTRAP_*` placeholders from the verified bootstrap state and `CREATED_*` placeholders from the full apply state and AWS metadata. Use only IDs reconciled to the lab, and omit missing resources after a partial apply. The templates are assembled for review. After rendering, split each by the following zero-based statement slices into customer-managed policies. Check each compact JSON document against the 6,144-character quota, and run Access Analyzer and the relevant allow and deny simulations again before attachment. [IAM policy quotas](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)

| Policy | Shared state and reads | Network | Services |
| --- | --- | --- | --- |
| Apply | `0:17` | `17:29` | `29:41` |
| Teardown | `0:17` | `17:25` | `25:36` |

Access Analyzer returned zero findings across the five distinct policy documents rendered with synthetic IDs. IAM simulation found an initial EC2 scope error where a shared create statement also authorized subnet creation against an unrelated VPC. Separating newly created VPCs from the existing VPCs referenced by child resources fixed the error. The revised policy matched the expected decisions in all 16 fixture scenarios. The checks covered network creation and tagging, unrelated VPC and NAT inputs, exact Amplify branch scope, Terraform state and lock writes, private RDS creation, forwarded secret creation, direct secret access denial, exact teardown IDs, and denial of IAM administration and artifact data deletion. The fixtures did not execute service APIs. [IAM policy simulation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)

The November 10 follow-up inventory showed no custom Sydney execution role, current lab state object, Amplify app, RDS instance or NAT gateway in Sydney. The bootstrap and foundation remain unapplied. Live deletion and final billing are still unverified.

## November 11 approved lab run

The user approved starting the 17-resource bootstrap and teardown of the disposable lab data and backups. The operating target is four hours from the first billable create, with eight hours reserved for contingency. The exact start time and cleanup deadlines will be recorded at apply.

The refreshed AWS Core STS check identified Sunlit Servers (`736486260824`). Cost Explorer returned estimated unblended spend of `$0.0002157821` for November 1–10, excluding credits and refunds. Sydney returned zero RDS instances, active NAT gateways, Amplify apps and Cognito pools. The proposed Cognito domain was available. The account contained only the Terraform state bucket, with all four bucket public access blocks enabled. State version inventory contained historical lock versions and current lock delete markers, with no current foundation state object.

### Bootstrap applied

CloudShell reverified the source archive SHA-256 and Terraform 1.13.5 Linux binary checksum. The signed AWS provider 6.64.0 exceeded CloudShell's home-directory capacity during installation. Moving the Terraform provider data into temporary storage resolved the failure. The source, plans and logs remain in the private home-directory run folder `/home/cloudshell-user/scoutgrid-sydney-run-20261111.xuQccRq1`.

Terraform validation passed in the default workspace against the existing Sydney backend. The live bootstrap plan contained exactly the expected 17 creates, with zero changes or destroys, and the lab variables and protections matched review. The saved plan SHA-256 was `a4669a2e05de564a7106ffb70ffd47da849954e463068e35cd3c27bdb7a26692`.

Apply began November 11 at **09:19:02 IST** (`03:49:02 UTC`) and completed with 17 added, zero changed and zero destroyed. The four-hour target is **13:19:02 IST**, with the eight-hour contingency deadline at **17:19:02 IST**. Cleanup will start as soon as the checks finish.

| Bootstrap resource | Recorded identity |
| --- | --- |
| Amplify app | `d1r4wn9kt8tehk` |
| Cognito pool | `ap-southeast-2_XEOIpLHx6` |
| Database KMS key | `22cf6682-3133-47bd-af3e-200a1464b054` |
| Object KMS key | `ddb15ff2-ac4a-4eaa-92d4-7b697706ea11` |
| Imports bucket | `scoutgrid-lab-736486260824-imports` |
| Exports bucket | `scoutgrid-lab-736486260824-exports` |

AWS readback matched the Terraform identities. Cognito has active deletion protection and MFA enabled. Amplify auto-build and automatic branch creation are disabled. Both artifact buckets have all four public access blocks, KMS encryption with the object key and S3 Bucket Keys enabled. Both buckets contain zero object versions, delete markers and incomplete multipart uploads. Policies rendered with these IDs returned zero Access Analyzer findings before attachment.

### Full foundation review after bootstrap

The untargeted live plan under the existing operator contains **39 creates, one Amplify update and zero destroys**. Terraform console confirmed that decoding the API's JSON header array and the configured YAML `customHeaders` produces equal values. The update is caused by serialization format. The apply policy now includes `amplify:UpdateApp` on this specific lab app ARN. Access Analyzer returned zero findings and IAM simulation allowed the lab app while denying an unrelated app. The reviewed source configuration is unchanged.

The RDS settings in the plan remain private, encrypted, deletion-protected Single-AZ PostgreSQL 16.15 on `db.t4g.medium`, with 100 GiB gp3, a 200 GiB autoscaling maximum and RDS-managed master credentials. The saved review plan SHA-256 is `3ead7e37d2893fec9367dc8590afd1ee6ed59522f8aa5ea4e744c3f3b6229f69`. A fresh plan under the scoped role is required before apply.

Automatic approval review rejected creation and attachment of the proposed `ScoutGridSydneyLabApply` and `ScoutGridSydneyLabTeardown` roles because the run approval did not specifically name these IAM roles and their scope. A separate approval request identifies the roles, operator-only trust, one-hour sessions, lab permissions and cleanup of the roles and policies after the run. The IAM operation returned before API dispatch.

The user subsequently approved both scoped roles. AWS created them with the reviewed operator-only trust and 3,600-second maximum session duration. Policy readback matched the rendered documents. The apply role completed a live plan whose resource changes matched the operator's review exactly. Its saved plan SHA-256 was `0100f08f1fb3a606fb5984a5fe65cfaea90aa1efbb08bbb367747889b05e7cae`.

### Partial apply and recovery

The first foundation apply began at **09:31:34 IST** (`04:01:34 UTC`) and stopped after allocating both EIPs because the policy omitted `ec2:DescribeAddressesAttribute`. Access Analyzer accepted the added Sydney-only read permission, and the common policy's default version was updated to `v2` and verified by readback. AWS confirmed that both EIPs existed, were unassociated, had VPC domain and the expected lab tags. The failed reads had marked them tainted in state. They were untainted after reconciliation so the retry could reuse the existing allocations.

The recovery plan also exposed a default apply-method mismatch for `rds.force_ssl`. AWS reports value `1`, source `system`, apply type `dynamic` and apply method `pending-reboot`. The configuration now explicitly sets `apply_method = "pending-reboot"` for that parameter, matching the readback. This is the single foundation source change from the reviewed archive. The workspace and CloudShell copies contain the same change. Formatting passed, and the new live plan removed the parameter-group update.

The reviewed recovery plan contains seven creates and the same Amplify header-format update, with no replacement or deletion. Its SHA-256 is `a4305715745db9c352a7fdd139beb60fc4af206a039644776ce9c30e9ba891a3`.

### Foundation readback

Both NAT gateways became available after creation at `04:08:33 UTC`. RDS instance `scoutgrid-lab` (`db-DIS4TJ4VYNKQNJROIYVVKOGCAY`) reached `available`, with PostgreSQL 16.15, `db.t4g.medium`, 100 GiB gp3, encrypted storage, Single-AZ, private access, deletion protection and seven-day backup retention. Its parameter group is in sync and `rds.force_ssl` is `1`. The database security group has zero ingress and zero egress rules. Both customer-managed keys have annual rotation enabled.

The RDS-managed secret is active and uses the database key. Its ARN is `arn:aws:secretsmanager:ap-southeast-2:736486260824:secret:rds!db-3cb0d539-554a-42d8-a7a3-53e7c69843c7-ebPIby`. Metadata was inspected without retrieving the credential value. This validates the forwarded RDS secret setup in the apply policy. The Amplify `lab` branch has automatic builds disabled, the Cognito managed-login domain is active with version 2, and ECR is empty with immutable tags and scan-on-push enabled.

The provider's final RDS refresh failed because it queries by the generated resource ID and AWS evaluates `rds:DescribeDBInstances` against `db:*`. The original policy allowed the named instance only. Access Analyzer accepted the proposed Sydney-wide metadata-read scope, but automatic approval review rejected attachment because it exceeded the explicit lab-only IAM approval. A separate request asks the user to approve this read scope. Database writes and deletion remain scoped to `scoutgrid-lab`.

The exact network IDs have been incorporated into `SydneyLabTeardownNetwork`. The role's attached policies passed live IAM principal simulations for the recorded VPC, NAT gateways, EIPs, database, Cognito pool, KMS keys and artifact buckets. Tests denied unrelated resources and the Terraform state bucket. The isolated teardown copy is prepared. It has not changed the live deletion-protection settings yet.

The scoped role successfully read the database by its named identifier. Terraform state contained all 56 planned managed resources. The RDS instance was marked tainted by the failed filtered read and was untainted after the available instance and its settings were reconciled.

A narrower metadata policy requiring both `Application=ScoutGrid` and `Environment=lab` resource tags passed Access Analyzer and simulation, including denial for absent or production tags. Its live `dbi-resource-id` query still returned `AccessDenied` against `db:*`. The common policy was restored to `v2` and the experimental version was removed. The approval request for the broader Sydney metadata read remains pending.

Read-only review under the existing operator produced a protection-transition plan containing only the approved RDS and Cognito updates. Its SHA-256 is `b4ac4b912c7a500a6f1b02d25612227101899abdf333a1841ba2fa288c496025`. The transition targets these two resources to avoid the unrelated Amplify serialization diff. A destroy review then matched **all 56 deletion addresses and identities**, including the Cognito branding composite identity, against captured state. It contains no create, update, replacement or state-bucket resource. Its SHA-256 is `5d55ebd16f11df9c5a508eb93dd7ed23630eceffb3902ec6d193c62abc4a2ea9`. These are review plans. Fresh scoped plans are required for execution after the metadata-read approval.

### Scoped teardown execution

The user approved Sydney-wide `rds:DescribeDBInstances` metadata reads for both temporary lab roles. The common policy was updated to default version `v4`, with zero Access Analyzer findings and matching readback. A generated-resource-ID query under the apply role then succeeded. All RDS write and deletion permissions remain bound to the named lab instance.

The teardown role regenerated the protection-transition plan. It contains only the RDS and Cognito updates and verifies `skip_final_snapshot = true`, `delete_automated_backups = true` and removal of the final snapshot identifier. Its SHA-256 is `c3e9e0e760f2a95a732cdc0a250d0c49947ada70ca2acff5d90536cb82340cc6`. Teardown began at **10:11:09 IST** (`04:41:09 UTC`) with this protection update.

### Live teardown result — November 11, 2026

The protection transition completed with two updates. AWS readback confirmed RDS deletion protection was disabled and Cognito protection was `INACTIVE`. A fresh scoped destroy plan matched all 56 recorded resource identities and contained only deletions. Its SHA-256 was `32d4cb5b0fa16ccf78978fca295e9ed80d0a2f792dfe9013d19088ea3aa5455e`.

The first destroy removed 54 resources and stopped on the two EIPs. The saved plan retained association IDs that the NAT deletion had already removed; the provider attempted an ungranted `ec2:DisassociateAddress`. AWS readback confirmed both addresses were detached. A fresh destroy plan contained only those two recorded EIPs, with no association fields, and succeeded without expanding permissions. Its SHA-256 was `27101c3496f307ef94b937643d0ab6e3fd013cc18c918ec6484654569d3a2721`.

The final remote state was written at **10:19:27 IST** (`04:49:27 UTC`), **1 hour and 25 seconds** after the bootstrap create request. A subsequent read of that retained state asserted `FINAL_MANAGED_RESOURCE_COUNT=0`; the state lock's latest version is a delete marker. CloudShell's later session reset removed the temporary provider/module cache, so the final assertion read the S3 state directly rather than reinitializing Terraform.

AWS verification at approximately `09:03 UTC` found no lab VPC, allocated EIPs, active/deleting NAT gateways, RDS instance, manual/final snapshots, retained automated backups, RDS-managed secret, Cognito pool, Amplify app, ECR repository or artifact buckets. The only S3 bucket retained is the existing Terraform state bucket. Both customer-managed KMS keys are disabled and `PendingDeletion`: object key deletion is scheduled for `2026-12-11T04:45:33.250000Z`, and database key deletion for `2026-12-11T04:47:23.527000Z`. Physical key deletion remains a future check; AWS does not charge for keys scheduled for deletion. [KMS pricing](https://aws.amazon.com/kms/pricing/)

Both temporary roles and all five `SydneyLab*` managed policies were removed after verification. A subsequent IAM inventory at `09:04:31 UTC` confirmed they are absent. `ScoutGridSydneyLabPlan`, `AWSServiceRoleForRDS`, the remote state bucket and its history are retained. Final billing reconciliation awaits Cost Explorer's refreshed usage; resource removal is verified, but a final dollar total is not yet established. Small state-storage/request charges remain possible.
