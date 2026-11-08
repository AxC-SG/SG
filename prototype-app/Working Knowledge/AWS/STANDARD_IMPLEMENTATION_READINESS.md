# Standard implementation readiness

Use this record for G00 and P14. Candidate evidence belongs in `release-evidence/<release-id>/` or the protected release artifact store.

## G00 — Open

| Entry | Recorded decision or evidence still needed |
|---|---|
| Release | Fresh production database, G07b with ten Standard customer tenants plus SG Internal. Start enrollment with one to three customers after G08. |
| Workflows | Managed sign-in, onboarding, manual BOM import, findings, AWS asset discovery, GitHub repository and package BOM collection, shared intelligence, and the entitlement-gated AWS static AI path. |
| Recovery | Same account and region. RPO at most 15 minutes and RTO at most four hours. Starting PITR retention is seven days for the lab and 14 days for production. |
| Workload | Freeze one, three and ten customer fixtures with up to 1,000 assets and 100,000 associations per customer, shared corpus and active SG Internal. Capture isolated provider fixture baselines and 2 sustained/10 burst API RPS. |
| AWS account and DNS inventory | The disposable lab remains in account `736486260824`, Sydney (`ap-southeast-2`). The owner selected TeamSG Management (`560246495987`) for production. Use Northern Virginia (`us-east-1`) as the lower-cost production region. Confirm scoped deployment roles, AZ IDs, CIDRs, data location requirements, DNS and named owners. |
| Team and spend | The owner authorized a disposable lab under $20 per month, with teardown after each test. Stage B sizing and ongoing infrastructure require separate budget review. Name the product, platform, backend, quality, release and on-call owners. Record approved external data flows. |
| Legacy and reset targets | Confirm current hosting, database and schema identifiers, writers, backups, holds and test-only data. Record each verified target and its reuse or retirement disposition before any reset. |
| Migration baseline | Retain the existing append-only histories. The connector scheduling candidate advances the platform head to V15. The tenant head remains V20. Verify both heads against the packaged candidate. Fresh production bootstrap creates only SG Internal. |

The Terraform Standard root defines the VPC, subnet tiers, zonal NAT/EIPs, task-subnet S3 gateway endpoint, private RDS, encrypted object buckets, Cognito managed login, ECR and an Amplify manual deployment target. Its RDS security group starts without ingress. Use a separate encrypted, versioned state bucket and lock per environment. Supply the verified bucket, region, key and KMS key through backend configuration at init. Keep state, plans and secrets out of the repository. Run `terraform fmt -check -recursive`, `terraform init -backend=false` and `terraform validate` for local review. Applying these resources incurs spend and follows G00.

### Production region comparison — November 8, 2026

AWS STS confirmed TeamSG Management account `560246495987`. The AWS Price List comparison uses the same production footprint in each region for 730 hours: one PostgreSQL `db.m7g.large` Multi-AZ instance, two Fargate API tasks and one worker totaling 2 vCPU and 8 GiB, two NAT gateways, and one Application Load Balancer. The figures exclude storage, traffic, request charges and the remaining stack services. [AWS Price List API](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html)

| Region | RDS per hour | Fargate vCPU per hour | Fargate GiB per hour | NAT per hour | ALB per hour | Core subtotal per month |
|---|---:|---:|---:|---:|---:|---:|
| Northern Virginia (`us-east-1`) | $0.337 | $0.04048 | $0.004445 | $0.045 | $0.0225 | $413.19 |
| Ohio (`us-east-2`) | $0.337 | $0.04048 | $0.004445 | $0.045 | $0.0225 | $413.19 |
| Mumbai (`ap-south-1`) | $0.479 | $0.04256 | $0.004655 | $0.056 | $0.0239 | $538.20 |
| Sydney (`ap-southeast-2`) | $0.468 | $0.04856 | $0.005320 | $0.059 | $0.0252 | $548.14 |

Northern Virginia ties Ohio on the compared rates and is already supported by the candidate's regional configuration. AWS recommends keeping workloads in a member account because Organizations SCPs do not restrict the management account. Record the owner's placement decision as a production exception. Qualify the scoped deployment, publisher and runtime roles in the selected account before applying production infrastructure. [AWS management account guidance](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html)

## P14 — Owner approved November 8, 2026

The owner reviewed the first [Standard workflow mock](standard-ui-review.html) on November 8 and requested one more level of detail. The follow-up review asked how tenant administrators configure connectors and why the migration requires UI changes. The revised mock shows the existing AWS Discovery and GitHub paths from setup through the first run, alongside manual BOM import.

The mock reviews changes within existing workflows. Reuse the **Request a demo** form (`/demo/contact`), **Platform → Demo Requests** (`/platform/demo-requests`), and the password setup and login entry points (`/setup` and `/login`). Use the existing request status and the operator runbook for provisioning and recovery. Adapt the current BOM upload flow for asynchronous acceptance and results. Reuse current connector and findings screens and qualify the offered provider paths. The GitHub form now describes tenant tokens and supported anonymous access.

The owner clarified the first tenant administrator's onboarding sequence. The customer submits the existing **Request a demo** form (`/demo/contact`). The platform owner approves the request in the existing console. After the Standard workspace is provisioned and active, ScoutGrid emails the approved administrator a secure **Set your password** link. The administrator completes setup and signs in with tenant administrator access. The platform owner's approval is the access decision. The administrator's only onboarding action is account setup.

The owner approved the revised workflow review and authorized proceeding with Part 1 implementation. The existing approval action queues managed Standard onboarding. The reviewed operator task provisions the workspace and links the first administrator. Cognito handles password setup and sign-in. The managed member invitation flow remains separate.

The owner confirmed that both inventory setup and manual BOM import use the existing **Connectors → Sources** left-nav path (`/connect/sources`). Use the **Inventory** cards and their detail pages for AWS and GitHub. Use **BOM Management → Ingest Now** and the existing result area for manual import. P14 reviews the S3 upload and job status changes in the existing form and **Connectors → Run History**, with results verified in the existing Inventory and Findings views.

The owner confirmed reuse of **Settings → Authorized Workspaces** (`/authorized-workspaces`) for platform owners and the existing active workspace label. A tenant administrator with one workspace enters it directly after managed sign-in. The managed frontend selects the workspace per tab and sends the selected UUID on API requests. Qualify SG Internal visibility through explicit internal membership, tab isolation in a live browser, and denial after support access expires or is revoked.

## Disposable AWS lab — November 7, 2026

AWS Core verified caller identity through STS in the connected account ending in `0824`. In `us-east-1`, AWS Organizations policy `p-ptfrpjmr` explicitly denied both `s3:CreateBucket` and `cognito-idp:CreateUserPool`. The proposed run used a single temporary bucket and one zero-user pool with synthetic inputs. Both create calls were rejected. S3 listing confirmed the bucket was absent, and the same policy denied Cognito listing. Resume when the designated account permits scoped lab creation, verification and deletion.

The owner subsequently designated account `736486260824` for the disposable lab and authorized creating the needed Cognito identities through AWS MCP. The follow-up STS check confirmed the account. The same service control policy explicitly denied `cognito-idp:ListUserPools` and a fresh `cognito-idp:CreateUserPool` attempt in `us-east-1`. The connected role also lacked access to describe the policy. The creation attempt stopped before any user enrollment or invitation delivery.

### November 8 recheck

AWS Core STS again identified the designated account in `us-east-1`. Organizations policy `p-ptfrpjmr` explicitly denied `cognito-idp:ListUserPools`, `config:DescribeConfigurationRecorders`, and `config:DescribeDeliveryChannels`. Policy `p-82obf95m` explicitly denied `guardduty:ListDetectors`. The organization administrator must provide a lab account or a scoped policy path for the required create, read, test and teardown operations. Confirm the lab estimate against the owner's below-$20 authorization before creating resources. The full Standard stack requires its own budget.

Vercel resolved `scoutgrid.io` to the READY production deployment `dpl_9QvQ8GErSssZmv2tvdjULp28RTdf` in project `scout-frontend` (`prj_BTTCC6KBOQSkBaihL6MZd07ezJn2`), built from `AxC-SG/SG` main at `98155ae6d11e909fe87402a809c0f0804c5c8cd6`.

The owner confirmed the Scout Render workspace (`tea-d9adqh3eo5us739qcfag`). Read-only Render metadata identified the following resources in environment `evm-d9avk0uq1p3s73dthf0g`, Oregon.

| Resource | November 8 observation |
|---|---|
| Backend `scout-backend` (`srv-d9b802laeets73ahf5dg`) | Suspended. Configured source `AxC-SG/SG` main. Latest deployment `dep-dblv93g8v5cc73d2ail0` is `update_failed` at `98155ae6`. Prior deployment `dep-dbjdierbc2fs73ch0m6g` still carries Render's `live` label at `ac15bb1c`. |
| Legacy migrator `scout-tenant-migrator-demotest1` (`srv-dafbtvdg1s2s73dthf0g`) | Unsuspended web service. Configured source `ggkarthik/Scout` main. Deployment `dep-dbgkkm08v5cc73fv9g5g` is marked `live` at `ac15bb1c`. |
| PostgreSQL `scoutdb-preprod-v1` (`dpg-dadh04vqj5pc739239cg-a`) | Available PostgreSQL 18 primary, logical database `scoutdb_preprod_v1`, `basic_256mb`, HA disabled, no read replicas listed. |

Hosted Render MCP could not run the read-only schema and session query because the database's external IP allowlist is empty. Use an already authorized private access path to verify schema names, writer connections and service bindings. Verify backup and hold status and record the reset or retirement disposition before P16. No services, data or networking settings were changed.

The existing local backend JAR contains platform V15 and tenant V20. All 35 packaged migration files match the workspace SQL byte for byte. Migration validation, history integrity, tenant DDL boundary checks and the migration wrapper tests passed. Q01 still requires a candidate built from an exact reviewed commit and its published artifact evidence.

### November 8 cutover inventory

Render still lists the `scout-backend` web service and the `scoutdb-preprod-v1` database in the Scout workspace. The temporary tenant migrator was deleted. The backend is unsuspended, and its November 8 deploy exited during startup because `platform.invitation_email_outbox` was absent on the connected database. The Standard launch uses a fresh RDS database.

AWS Core confirmed the connected lab account `736486260824`. Organizations policy `p-ptfrpjmr` denied the ECS, RDS, Amplify, ECR, load balancer and Cognito inventory in `us-east-1`. Confirm the production account and deployment role with the organization administrator before applying the Standard stack. Verify the paired AWS API and frontend before moving DNS and retiring the Render backend and database under R04.

### November 8 organization features recheck

AWS Core still uses `AccountFullAccessRole` in member account `736486260824`. Organizations reports feature set `ALL` and SCPs enabled. S3 bucket inventory and AWS Config recorder and delivery-channel inventory succeeded. These were read-only calls. The current SCP `p-vw5q9u3o` explicitly denied the tested Cognito, GuardDuty, VPC, ECS, RDS, Amplify, ECR and load balancer inventory calls in `us-east-1`. The role also could not describe the current policy, the lab account's parent, or the organization's policy delegation.

Use TeamSG Management (`560246495987`) or an explicitly delegated Organizations policy administrator to inspect `p-vw5q9u3o` and its attachments. Identify which denies affect the lab account and scope any approved adjustment to the lab's deployment and teardown path. Recheck effective permissions with the lab role before provisioning. No AWS resources or policies were changed in this recheck. [AWS Organizations policy updates](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_policies_update.html)

The management-account inspection identified `p-vw5q9u3o` as `AdvancedModeRegionRestrictionSecurityControlPolicy`, attached to the organization root. Its regional deny rules do not apply in Sydney (`ap-southeast-2`). A read-only follow-up using the Sunlit Servers role in Sydney succeeded for availability zones, VPC, Cognito, ECS, RDS, Amplify, ECR, load balancer, GuardDuty and AWS Config inventory. The account reported three available AZs and one existing VPC. Review CIDR overlap and verify create and teardown permissions before provisioning.

The owner selected Sydney for the disposable lab. A new OU would still inherit this root SCP. [AWS SCP evaluation](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html)

### Sydney disposable smoke and regional candidate

AWS Core confirmed account `736486260824` and created a private S3 bucket and an empty Cognito Essentials user pool in `ap-southeast-2`. S3 reported the expected region and all four public access block settings enabled. Cognito listed zero users. AWS accepted both deletions and subsequent reads returned not found. Evidence identifiers are bucket `scoutgrid-sydney-smoke-736486260824-754a4191e619` and pool `ap-southeast-2_H1rEHpjLY`. The smoke test used a handful of S3 API requests, zero stored objects, zero active users, and no email or SMS. Its expected cost was within the below-$20 allowance. [S3 pricing](https://aws.amazon.com/s3/pricing/) · [Cognito pricing](https://aws.amazon.com/cognito/pricing/)

For the integrated lab set `environment = "lab"`, `account_id = "736486260824"`, and `aws_region = "ap-southeast-2"`. Supply the reviewed AZ IDs, non-overlapping CIDR, HTTPS origins and PostgreSQL minor. Use a distinct protected state key for the Sydney environment. Set the protected GitHub lab environment's `AWS_REGION` to `ap-southeast-2` and compare it with Terraform's `release_targets.aws_region` before publishing. The infrastructure uses regional AWS endpoints and ARNs, and the ECS task uses the Sydney RDS bundle with JDBC hostname verification. The existing `us-east-1` default and its image bundle remain available for separately approved environments.

Sydney inventory returned one default VPC with CIDR `172.31.0.0/16` and AZ IDs `apse2-az1`, `apse2-az2`, and `apse2-az3`. The mocked Sydney plan uses `apse2-az1` and `apse2-az3`. RDS reports PostgreSQL `16.15` available with all three G1 CA choices. Pin the minor after candidate database qualification.

Terraform validation and all 13 mocked plans passed, including the Sydney runtime and cross-region credential rejection. The Linux/amd64 candidate was built locally and its image inspection verified both pinned CA bundles and packaged platform V15/tenant V20. The release workflow YAML, inline Bash and regional manifest gate were checked locally. The integrated infrastructure still requires a reviewed duration and cost estimate, the approved role and state setup, and a reviewed artifact published from CI. Before an integrated apply, review its teardown procedure for RDS deletion protection and the protected KMS keys and versioned S3 buckets. The smoke test verified teardown only for its two disposable resources.

## P04 — Durable upload backend

The new browser API starts disabled. In a qualified environment set `APP_BOM_UPLOADS_ENABLED=true` on the API and configure `APP_BOM_UPLOADS_BUCKET` and `APP_BOM_UPLOADS_REGION` on the API and workers. A configured worker drains accepted jobs independently of the API enablement flag. The global import lock holds one connection from the worker pool while an import runs.

The candidate requires tenant schema V20. Its upload-intent policy uses the canonical `tenant_isolation` name checked by the one-shot bootstrap. A V19-only binary loses tenant eligibility on a V20 schema, so qualify the migration and roll-forward before using this candidate on an existing environment.

1. Create an intent with `POST /api/bom/uploads`, a UUID `Idempotency-Key` header, and JSON fields `bomType`, `assetType`, `assetName`, `assetIdentifier`, `filename`, `size` and base64 `sha256`. Optional fields are `supplier`, `sourceId` and `completeness`. The response includes upload status, the signed URL and required browser headers. Use the file itself as the PUT body so the browser supplies its length.
2. Complete with `POST /api/bom/uploads/{id}/complete`. The API verifies the encrypted immutable object and returns a single job ID. A repeat returns the same job. Read intent and job status with `GET /api/bom/uploads/{id}` and the existing ingestion-job API.
3. The worker takes the shared import slot before claiming a job. It downloads and parses outside the write transaction. It rechecks tenant and actor authority, persists the BOM under the asset lock, and commits the job result in the same fenced transaction.

The existing BOM Management form and result area support the upload API when the frontend is built with `VITE_DURABLE_BOM_UPLOADS_ENABLED=true`. Keep it paired with the enabled backend and the exact API and bucket origins. The form retains the idempotency key in the tab until acceptance so a retry with the same file and metadata can resume. Run History displays accepted manual jobs and their outcome. Before customer enablement, qualify the browser signature against live S3, the scoped S3/KMS permissions below, and hold-aware object retention. The current API restricts uploads to direct tenant members with the permitted roles and one pending intent per tenant. The multipart browser flow and separate machine ingest remain available.

Local verification passed Maven `verify`, the migration guards, and ten focused PostgreSQL 16 integration tests covering fresh bootstrap, worker overlap, concurrent finalization, tenant isolation, membership revocation and the shared import slot. S3 behavior was exercised through offline presigning and mocked object responses.

The frontend tests cover the existing form, successful job results, Run History, reuse of an upload intent after an interrupted transfer, and recovery of an already accepted job. The production build with durable uploads and managed auth enabled passed locally. Live S3 and browser qualification remain open.

## A02/A04/A05/A07 — Standard backend candidate

The [Standard runtime](../../infrastructure/terraform/standard/runtime.tf) adds private Fargate tasks for the API, worker, and exit-once migrator. The [HTTPS ingress](../../infrastructure/terraform/standard/ingress.tf) forwards only the configured API hostname and `/api/*` to the API. The ALB checks readiness directly against the private targets. The worker binds its health endpoint to loopback. The regional WAF uses the AWS IP reputation and known bad input rule groups, with request sampling disabled.

### Candidate preparation and launch order

1. In the designated account after G00, establish the foundation with `backend_candidate = null`. Obtain an issued ACM certificate for `api_origin` and arrange the DNS alias to the ALB. Keep the frontend and API origins distinct. Record the expected hostname, both egress IPs, and the WAF rule groups in the release evidence.
2. Publish the reviewed backend candidate through the A03 workflow below. The AWS build target pins the official Sydney and us-east-1 RDS CA bundles by SHA-256. The publication record contains the region, both bundle checksums, and the ECR image digest. Every task uses PostgreSQL hostname verification with the selected region's bundle. [AWS RDS certificate bundles](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
3. Prepare two Secrets Manager secrets in the same account and region, encrypted under the candidate KMS key. The restricted DB login secret has JSON fields `username` and `password`. The application secret has `credential_encryption_key`, `ai_identity_hmac_key`, and `turnstile_secret_key`. Configure a Turnstile site/secret pair for the intended frontend hostname. Supply full secret and KMS ARNs only. ECS injects current secret fields at task launch. After rotation, coordinate database password and credential-key changes with a new task rollout. [ECS secret injection](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html)
4. Supply the digest, certificate ARN, secret ARNs, and KMS ARN in `backend_candidate`. Keep `start_services` false until bootstrap passes. Use the `backend_runtime` output to run the exact migrator task definition once in the private task subnets, with its migration security group and `assignPublicIp=DISABLED`. Check exit code 0 and the bootstrap result for the expected database and schema heads and exactly one SG Internal tenant. The task uses the RDS owner secret and provisions the restricted login used by the API and worker. Run it through the approved migration operator identity. For a fresh AWS installation, supply the reviewed managed operator enrollment inputs below. This mode creates no local password setup link.
5. After bootstrap evidence is recorded, set `start_services = true` in the reviewed environment configuration. Record API target health, worker logs, the effective task definitions, negative database role and network checks, proxy-header handling, and replacement behavior. Terraform reports the ALB hostname and zone for the DNS change. The app is configured for EXTERNAL JWT validation. Managed browser sign-in, provider-specific access, and customer enrollment still need their own qualification.

For a local build and smoke check, run these commands from the repository root.

```sh
docker buildx build --platform linux/amd64 --target aws-runtime --tag scoutgrid-aws-backend:local --load prototype-app/backend
python3 .github/scripts/inspect-aws-backend-image.py scoutgrid-aws-backend:local
```

The [task IAM policies](../../infrastructure/terraform/standard/runtime-iam.tf) separate startup access from application credentials. API and worker startup roles can pull the candidate repository and read the restricted runtime secrets. The API task role can sign writes and verify current import objects. The worker task role can read specific versions. Their KMS permissions are constrained to S3 and the import bucket. The migrator alone gets startup access to the RDS owner secret. The release operator's ECS launch and PassRole permissions must be qualified separately.

The initial ceiling is two API tasks and one worker in production, and one of each in the lab. The production task pools allow 20 connections steady and up to 40 during full rolling overlap. The Standard runtime login limit includes one additional verification connection. Owner and administrative connections are budgeted separately. Both services use the ECS rollback circuit breaker. Retain a schema-compatible image digest for rollback and verify forced replacement and connection headroom in the selected AWS environment.

`enable_bom_uploads` defaults to false. Keep it disabled until the browser workflow, S3 presigning and hold-aware retention pass. The API has no bucket listing permission. An early completion call for a missing object can return S3 403 and surface as an upstream error, so qualify that recovery path before customer enablement.

Use Terraform 1.11 or later. Run `terraform test` from the initialized Standard root for the mocked runtime checks. This validates Terraform configuration and policy separation without creating AWS resources. The Stage B candidate includes billable ALB, WAF, NAT, RDS and Fargate resources. It requires its own approved environment and budget.

## A03 — Backend candidate build and ECR publication

The Trivy workflow builds the Linux/amd64 ECS target, checks the pinned RDS bundle and migration catalog inside the non-root image, and scans the image. Successful main pushes retain the scanned archive and a manifest containing the source commit, workflow run ID, archive checksum, image ID, RDS bundle checksum, and packaged migration heads for 14 days.

Use the **Publish AWS backend candidate** workflow on `main` with the reviewed Trivy run ID and the target environment. The workflow checks the successful main-push runs for Trivy, Quality, Semgrep, and Performance Governance on the candidate commit. It verifies the archived bytes and loaded image ID, publishes the retained image to the target account's immutable ECR repository, and records the registry digest. Use the same candidate run for lab and production. The 90-day publication artifact contains `image_digest` for `backend_candidate`. Copy it to the protected release evidence store with the approval and lab results. ECS updates remain a separate Terraform operation.

Before enabling publishing, configure the following in each designated account and the GitHub repository.

1. Pre-create `aws-standard-lab` and `aws-standard-production` with required reviewers, self-review prevention, and deployment restricted to the protected `main` branch. Keep OIDC publishing disabled if the repository cannot enforce those protections. [GitHub deployment environment controls](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
2. Use the account's existing GitHub OIDC provider with audience `sts.amazonaws.com`. Set `github_publisher.provider_arn` and `github_publisher.subject` to the exact verified environment subject for AxC-SG/SG, including repository and owner IDs if the repository uses immutable subjects. Terraform creates only the ECR publisher role. [GitHub OIDC for AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
3. Set the GitHub environment variables `AWS_ACCOUNT_ID`, `AWS_REGION`, and `AWS_ECR_PUBLISH_ROLE_ARN` from the environment inventory and Terraform output. Qualify a denied branch and mismatched environment, a rejected unreviewed run, and an approved lab push before recording G03 evidence.

The November 8 AWS preflight found no GitHub OIDC provider or regional ECR repository in either account. The repository owner added `aws-standard-lab` and `aws-standard-production`. A read-only check confirmed all six expected variables and found no protection rules on either environment. The owner reported GitHub Free, which does not support required reviewers for this private repository. Keep `github_publisher = null` in both AWS configurations. [GitHub environment availability and administration](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)

### Operator publication on GitHub Free

Use the existing CI build and scan to produce the candidate archive. Keep the publication step with a scoped AWS release operator and record the approval separately from the publishing action.

1. Verify successful Trivy, Quality, Semgrep and Performance Governance runs on the same exact `main` commit. Identify the retained Trivy archive by run ID and check its manifest, archive SHA-256, loaded image ID and target-region RDS CA bundle. Prepare the lab release record with those identifiers and the exact AWS account, region and ECR repository.
2. Have a reviewer independent of the publisher approve that release record. Store the approval in the protected evidence location with the candidate SHA, Trivy run ID and target. A change to those inputs requires fresh review.
3. Use a short-lived AWS operator session scoped to the designated ECR repository. Verify caller account and region, confirm the repository uses immutable tags, and push the exact scanned image. Record the ECR digest, approval reference and publisher identity. ECS deployment follows its own gate and uses the recorded digest. [ECR push permissions](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push-iam.html)

Qualify this operator path in Sydney before production use. The state backend, scoped roles, ECR foundation and a reviewed CI artifact are still required before the integrated lab run.

## P03 — Managed browser sign-in backend

The API can sign in an explicitly linked Cognito user and create a PostgreSQL-backed browser session. The managed sign-in and invitation paths require platform V12 or later and stay disabled by default. The Standard Terraform runtime supplies the pool issuer, public app client, managed-login domain, exact frontend origin and API callback. Use distinct HTTPS frontend and API origins on the same browser site so credentialed requests can carry the host-only API cookies. Enable `backend_candidate.enable_managed_auth` on a qualified API after migration and identity linking.

1. Start at `GET /api/auth/managed/login`. The API sets a five-minute, secure, HttpOnly browser-binding cookie and redirects to Cognito with an S256 PKCE challenge, state and nonce. The callback atomically consumes the matching attempt before exchanging the code. It validates the signed ID token against the exact Cognito issuer and browser client, then checks the nonce and token type. Cognito tokens stay on the server side of the exchange. [Cognito authorization endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html)
2. Link a verified Cognito `(issuer, sub)` to the approved existing `platform.app_users.id` using the controlled database operator path. The application resolves this link exactly and uses the user's current ScoutGrid authority. Email coincidence grants no access. Delete the link to revoke its sessions before assigning a replacement. Protect the binding record and include the operator and reviewer in the release evidence.

   ```sql
   INSERT INTO platform.managed_identities (issuer, subject, user_id)
   VALUES (:'issuer', :'cognito_sub', :'approved_app_user_id'::uuid);
   ```

3. The callback sends the frontend a redirect and sets the opaque `__Host-sg-session` cookie. The database stores only a hash of that token. A session lasts up to 30 minutes and ends sooner if the ID token expires. Use credentialed requests to `GET /api/auth/context` or `/api/auth/authorized-workspaces`. Each tab sends its selected tenant UUID in `X-Scout-Workspace` on tenant requests. The API resolves current roles, tenant eligibility, memberships and support grants for that request.
4. For unsafe browser requests, fetch `GET /api/auth/csrf` with credentials and send the returned header and token. `POST /api/auth/managed/logout` revokes the server-side session and clears the cookie. A fresh sign-in asks Cognito to reauthenticate. Managed mode uses the existing machine authentication contract for bearer credentials. LOCAL password and setup-token issuance are disabled in EXTERNAL mode.

Build the lab frontend with `VITE_MANAGED_BROWSER_AUTH_ENABLED=true` and `VITE_API_BASE` set to the exact API origin plus `/api`. The existing login and member-invitation routes hand off to Cognito, and Authorized Workspaces uses tab-local selection and server revalidation. Keep managed auth disabled for customer use until live operator enrollment, Cognito callback and cookie qualification, and the approval-to-first-admin password setup handoff pass.

The managed frontend tests cover a single-workspace administrator entering directly, workspace and CSRF headers on writes, expired support scope recovery, and managed logout. Seven focused PostgreSQL 16 integration tests passed, including the platform-owner access required by the existing tenant and support lists and denial of unscoped access to those endpoints for a tenant member.

Local verification passed Maven `verify`, 11 focused PostgreSQL 16 integration tests, the migration guards, and five mocked Terraform tests. The PostgreSQL cases covered browser binding, concurrent callback consumption, per-request workspace selection, grant revocation, CSRF-protected logout, and fresh bootstrap. The rebuilt Linux/amd64 image packages platform V11 and tenant V20.

## P03 — Managed tenant member invitation linking

An invited user must have a Cognito account in the configured pool. The pool remains admin-enrolled. The managed handoff requires a signed ID token with a verified email matching the active tenant invitation. The account's durable identity is the issuer and subject. Existing ScoutGrid users with credentials or authority require an operator-reviewed link before accepting a managed invitation.

1. Read the invitation token from the existing frontend link fragment. Fetch `GET /api/auth/csrf` with credentials and POST `{"token":"…"}` to `/api/auth/managed/invitation` with that CSRF header and credentials. The API returns `authorizationUrl` and a browser-binding cookie. Navigate the browser to that URL. The raw invite token stays out of the redirect and the login attempt stores its SHA-256 digest.
2. The callback consumes the browser-bound attempt and verifies the Cognito token. It locks and revalidates the invite and invited account, then commits the issuer-and-subject link, membership, acceptance audit, and browser session in one database transaction. A rotated, cancelled, expired, or mismatched invitation grants no access.
3. A failed acceptance can start a new sign-in attempt while the invite is still valid. If acceptance committed and the redirect was lost, use ordinary managed sign-in. It resolves the committed identity without replaying the invitation.

The existing LOCAL invite flow continues to issue password-setup credentials in LOCAL mode. Managed acceptance follows the existing tenant eligibility and membership rules and issues a session without generating a local password or setup token.

Local verification passed Maven `verify`, 15 focused PostgreSQL 16 integration tests, and both migration guards. The invitation tests covered concurrent acceptance, digest rotation, verified-email mismatch, conflicting identity links, and transaction rollback when session issuance fails. The rebuilt Linux/amd64 image packages platform V12 and tenant V20.

## P03/A04 — Initial managed operator enrollment

The exit-once production bootstrap can initialize the first platform owner and SG Internal administrator from two approved Cognito accounts in the configured pool. The first enrollment requires a fresh database with exactly one active SG Internal tenant and no ScoutGrid users. The owner receives platform authority. The administrator receives one SG Internal `TENANT_ADMIN` membership.

1. In the designated AWS account, the approved Cognito operator enrolls the two distinct accounts and verifies each account's email and `sub` against the exact pool. Record the approved mapping and reviewer in the protected release evidence. [Cognito administrator enrollment](https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-create-user-accounts.html)
2. Store the reviewed inputs in a separate Secrets Manager JSON version with `owner_email`, `owner_subject`, `internal_admin_email`, and `internal_admin_subject`. Encrypt it under the candidate secrets KMS key. Supply `backend_candidate.managed_installation.secret_arn` and `version_id` in the environment configuration, with `start_services = false`. Terraform supplies the issuer from the environment's Cognito pool. ECS injects the pinned version's fields only into the migrator. [ECS secret version references](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html)
3. Run the reviewed migrator task definition once. Verify exit code zero, the candidate’s recorded migration heads, and the `managed operator links committed` installation result. An exact retry reports `recorded managed operator links verified`. The same transaction commits both accounts, their separate roles, both identity links, and the enrollment audit. The report omits account emails and Cognito subjects.
4. Remove `managed_installation` before starting the API and worker. The Terraform update removes access to the enrollment secret and replaces the enrollment task revision. Routine migration runs omit enrollment inputs. A retry with the original inputs fails if a binding or role has been changed or revoked, preserving the current authority. Handle later account changes through the approved identity administration process.

The enrollment record is protected from the runtime database role. LOCAL setup remains available to legacy installations and is rejected after managed operator enrollment. Live qualification still needs scoped Cognito access in the designated lab account, the two approved operator aliases, and proof that each operator can use managed sign-in with the expected scope.

Local verification passed Maven `verify`, 10 focused PostgreSQL 16 cases, seven mocked Terraform plans, and the migration and wrapper checks. The Linux/amd64 image packages platform V13 and tenant V20. The packaged exit-once command and its retry ran on an isolated Docker network and left two identity bindings, one enrollment record, and zero local setup deliveries.


## A10/P10 — Standard customer provisioning

The Standard task definition supplies `backend_candidate.customer_limit`, which defaults to ten. Set it to three only for the owner-approved G07a profile. Initial bootstrap records the selected limit in platform V14 while the customer registry is empty. Later bootstraps and targeted tasks must match the recorded limit. Changing a Terraform variable alone cannot expand an enrolled environment. Expansion requires the G07b evidence and a separately reviewed database policy change.

1. Bootstrap SG Internal using the exact reviewed migrator task revision and record its successful exit. Remove the initial managed installation inputs before launching customer tasks. In the existing **Platform → Demo Requests** console, approve the request from platform scope and copy its request ID. Approval keeps the reviewed company and administrator email together in the SG Internal request queue.
2. Run the reviewed migrator revision without installation inputs and use the command override below with the approved request ID. Use the private task subnets and migration security group with public IP assignment disabled. Record the task ARN and request ID together. [ECS RunTask overrides](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html)

   ```json
   {
     "containerOverrides": [{
       "name": "migrator",
       "command": ["/app/scripts/run-schema-migration.sh", "--run-once", "--provision-standard-request",
                   "00000000-0000-4000-8000-000000000123"]
     }]
   }
   ```

3. Confirm exit code zero and `standard_tenant_activated` or `standard_tenant_already_active`. The request ID is also the tenant UUID. The task reserves and migrates its schema, checks it against SG Internal and probes runtime grants and RLS. The CURRENT projection and ACTIVE status commit together. After an interruption, retry the same request ID. Failed and suspended workspaces retain a slot until reviewed retirement. SG Internal is excluded from the count.
4. In the configured Cognito pool, the scoped identity operator uses `AdminCreateUser` with `SUPPRESS` for the approved administrator email. Verify the pool, email, `sub` and `FORCE_CHANGE_PASSWORD` state with `AdminGetUser`. Stop if an unrelated or confirmed user already exists. Keep temporary credentials out of task arguments and release evidence. Run the reviewed migrator with `--run-once --link-standard-admin <request-id> <cognito-sub>`. The task checks the active workspace and current schema, then commits the identity and its sole tenant administrator role. An exact retry verifies the binding. [Cognito user enrollment](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html)
5. After verifying the link, the identity operator submits Cognito `AdminCreateUser` with `RESEND` and delivery medium `EMAIL` for that same pending user. The email links to ScoutGrid sign-in and includes the temporary password. Cognito prompts the recipient to choose a password and complete required MFA. After provider success, run `--run-once --record-standard-setup-email <request-id> <cognito-sub> <provider-request-id>`. The console reports submission to Cognito. For a definitive provider failure, record `--run-once --record-standard-setup-failure <request-id> <cognito-sub>`. Reconcile unknown outcomes using the provider record before retrying, since a resend rotates the temporary password. Verify receipt and first sign-in in Q02. [Cognito email configuration](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html)

The bootstrap lock serializes reservations, activation and schema maintenance. Runtime database roles can suspend or resume an active Standard workspace and edit ordinary settings. The database reserves customer creation, first activation and routing identity changes for the privileged task. The earlier synchronous and demo provisioning paths remain available on installations that have no Standard enrollment policy.

Local PostgreSQL tests cover approval, replay, rejection after approval, and a complete synthetic request through provisioning, exact Cognito subject binding, and recorded setup submission. They also cover interrupted activation, orphan schema refusal, runtime bypass attempts, and concurrent requests at the three-customer cap. The platform and tenant migration heads remain V15 and V20. Live ECS, RDS, Cognito enrollment and email receipt remain open.


## P17 — Durable AWS and GitHub schedule admission

Each AWS Discovery configuration and saved GitHub source records its latest accepted five-minute UTC polling window per tenant. The scheduler captures the window at the start of the sweep. The cursor, connector run and executable ingestion job commit in the existing admission transaction. Quota rejection rolls back the cursor and leaves the source eligible. The configured interval, in-flight checks and manual trigger behavior still govern admission. A later sweep considers due work once after an outage without replaying every missed polling window.

An unavailable tenant schema defers that tenant's AWS schedule while eligible peers continue. Apply platform V15 before starting the new worker candidate. Existing connector data needs no cursor backfill. The previous worker still uses its original interval and in-flight checks during rollout, so exercise mixed-version overlap and forced ECS replacement in the Standard lab.

Maven verification passed, including 42 focused PostgreSQL 16 cases covering two overlapping callbacks per provider, terminal and stale-window replay, the next eligible window, atomic quota rollback, independent tenant progress, and expired attempt recovery. Migration integrity and boundary checks passed. The rebuilt Linux/amd64 candidate packages platform V15 and tenant V20. Live worker replacement and provider-path qualification remain open.

## P05 — Worker fairness and bounded finding sweeps

Ingestion claims and expired-attempt recovery now try the tenant's PostgreSQL admission lock. If an API or scheduler transaction owns it, the worker defers that tenant without changing its queued job or attempt count. Producer admission still takes the blocking lock so quota decisions and queue writes stay atomic. The zero-backlog executor still admits work before a worker takes a lease.

Finding deltas visit each eligible workspace once per round before revisiting a backlogged tenant. The sweep stops starting new batches after `APP_CORRELATION_DELTA_QUEUE_SWEEP_BUDGET_MS` (default 2,000 ms) and resumes at the next workspace. Each finding claim, batch write, retry write and stale recovery transaction uses `APP_CORRELATION_DELTA_QUEUE_TRANSACTION_TIMEOUT_SECONDS` (default 15 seconds). An in-flight batch may extend the sweep beyond its admission budget. A failed batch rolls back domain writes before the fenced retry transaction records the outcome.

Maven verification passed, including 29 focused PostgreSQL 16 cases. One case held a tenant admission lock while a peer claimed work and checked that the skipped job kept its attempt count. Another cancelled an intentionally slow finding query, checked rollback and durable retry, and confirmed the next sweep resumed at the unvisited workspace. Existing saturation, stale ownership, and recovery checks passed. Migration checks passed, and the rebuilt Linux/amd64 candidate still packages platform V15 and tenant V20. The timeout defaults and fairness bounds still need measurement under the Stage B workload.


## P06 — Fleet database budget and queue telemetry

| Environment | API pool per task | Worker pool per task | Steady runtime pools | Full rollout overlap | Runtime login limit |
|---|---:|---:|---:|---:|---:|
| Lab | 6 | 6 | 12 | 24 | 25 |
| Production | 6 | 8 | 20 | 40 | 41 |

Terraform derives the limits from the same task pool sizes, desired counts and ECS rollout percentage used in the deployment. The final slot is for one runtime verification connection under the migrator lock. Read the reviewed values from `backend_runtime.runtime_db_connection_budget`. The exit-once bootstrap sets the restricted PostgreSQL role limit. Report-only and targeted provisioning verify the configured limit against the database. Budget the migration owner, operator and RDS reserves separately. PostgreSQL can reject simultaneous new logins competing for the last available slot. [PostgreSQL role connection limits](https://www.postgresql.org/docs/16/sql-createrole.html)

The worker freshness snapshot now supplies the existing endpoint and GitHub queue depth and active gauges, plus `scoutgrid.ingestion.queue.oldest_visible_age_seconds` across ingestion job types. Scrapes read memory and the API has no refresh ownership. The ingestion gauges report unknown before a complete observation, after a failed or partial refresh, and after the snapshot ages out. Both workers can observe the same queues during a rollout, so treat their values as repeated observations of the same fleet backlog. Live metrics collection, per-tenant and provider telemetry, fleet provider allowances, and Stage B sizing measurements remain open.

Maven verification passed, including 11 focused PostgreSQL 16 cases. The restricted-login fixture held two connections and rejected a third. The telemetry fixture measured eligible queue age across two tenant schemas, preserved the existing job-type counts, and published changed values only after a refresh. Terraform validation and all seven mocked plans passed. The rebuilt Linux/amd64 image packages platform V15 and tenant V20.

## A09 — CloudTrail archive and baseline alarms

The [Standard operations configuration](../../infrastructure/terraform/standard/operations.tf) is opt-in through the `operations` input. Supply a reviewed account-local `audit_recovery_role_arn` and an existing standard `alert_topic_arn` in the same account and selected region. Check existing account and organization trails and approve the archive's ownership, retention, and cost before applying. The new trail records read and write management events across Regions and includes global service events. It delivers validated log files and digests to a private, versioned S3 archive with a dedicated KMS key. [CloudTrail S3 policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html) · [CloudTrail KMS policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)

CloudTrail delivery is scoped to the exact trail and the account's log prefix. The bucket denies object writes from ordinary principals. Deleting logs or changing retention requires the reviewed recovery role and its separate IAM permissions. Terraform protects the archive bucket and key from destruction. Confirm the operator read role can retrieve a version and decrypt it, confirm runtime identities cannot write or delete logs, and validate the delivered digest chain. Preserve the archive and key through any lab teardown unless their retirement is separately approved.

RDS CPU and free-storage alarms can run with foundation-only infrastructure. Once ECS services start, CloudWatch adds alarms for API target health, target-generated and ALB-generated 5xx responses, and worker CPU. The starting thresholds use two breaching one-minute periods out of three. Missing API health samples count as breaching, while missing 5xx counts count as healthy. Record the candidate threshold and observed baseline with the alert test. [ALB metrics](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html) · [RDS metrics](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-metrics.html)

Before enabling operations, authorize the CloudWatch service principal to publish to the existing SNS topic. Use the account and the alarm ARN pattern returned by `terraform output -json operations` in the topic policy. If the topic uses a customer-managed key, qualify CloudWatch's key access separately. Verify delivery and recovery notifications with the named lab operator and record the alarm history and receipt. [CloudWatch SNS actions and policies](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Notify_Users_Alarm_Changes.html)

### Configuration, security findings and spend

The [security operations configuration](../../infrastructure/terraform/standard/security-operations.tf) records S3 buckets and RDS instances continuously through AWS Config in the selected account and region. It checks RDS public access and storage encryption, and S3 public reads and writes. AWS Config history uses a separate prefix in the protected audit archive and the audit KMS key. Inventory any existing customer-managed recorder, delivery channel and organization rules before adoption. When the account has no conflicting recorder/channel, supply the account's verified `AWSServiceRoleForConfig` ARN as `operations.config_recorder_role_arn`. If the account already has organization-managed coverage, record the control owner, the equivalent rule results and the approved delivery path before enabling additional controls. [AWS Config service-linked role](https://docs.aws.amazon.com/config/latest/developerguide/using-service-linked-roles-config.html) · [S3 delivery policy](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html) · [KMS delivery policy](https://docs.aws.amazon.com/config/latest/developerguide/s3-kms-key-policy.html)

The account security owner enables or verifies GuardDuty foundational detection in the designated region and records enabled protection plans and the usage estimate. For a new standalone detector, explicitly disable unapproved optional features during creation. AWS can enable omitted features by default. Supply the verified detector ID as `operations.guardduty_detector_id`. EventBridge selects that detector's findings at severity 4 or greater and noncompliance changes for the configured AWS Config rules. Both routes use a dedicated, account-local `operations.security_topic_arn` with a confirmed operator subscription. The EventBridge execution role can publish only to that topic. Verify topic encryption and key permissions before use. Alerts carry the finding ID or rule name, account, region and EventBridge event ID. [GuardDuty detector defaults](https://docs.aws.amazon.com/cli/latest/reference/guardduty/create-detector.html) · [EventBridge target permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-events-iam-roles.html)

Set `monthly_budget` independently using the approved monthly USD amount and billing operator email. The [budget configuration](../../infrastructure/terraform/standard/budget.tf) tracks the entire account, with actual alerts above 80% and forecast alerts above 100%. It accepts a lab amount below $20. Budget alerts can lag usage, so enforce the lab limit through a reviewed resource estimate, run duration and teardown. Use the dedicated account scope to include untagged shared charges. [AWS Budgets update cadence](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html)

The worker availability alarm uses the existing ECS Container Insights service task count. It alarms when running count is below the configured desired count or when samples disappear. For lab evidence, generate a GuardDuty sample finding, demonstrate a Config rule evaluation and encrypted history delivery, and capture SNS receipt. Verify worker alarm and recovery under controlled replacement, then record the budget subscriber and actual or forecast notification evidence. [ECS Container Insights metrics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Container-Insights-metrics-ECS.html)

Terraform formatting and validation passed, along with 11 mocked plans. The plans cover opt-in behavior, archive grants, scoped event routing, worker alarm settings, and rejection of a lab budget at or above $20.

Live CloudTrail delivery and digest verification, detector enablement, Config evaluations, SNS and budget receipt, application telemetry alerts and restore access remain open.
