# ScoutGrid architecture review — November 5, 2026

**Planning status.** This source review informs the master. Part 1 retains Standard schemas behind a common resolver, and Part 2 selects and qualifies the Dedicated topology after Standard stabilizes. [AWS master migration plan](AWS_MASTER_MIGRATION_PLAN.md)

Reviewed source: `f9426447e18c6f3c4c836e3f1c14e0943fb93a22`, including the existing workspace configuration changes. This is a static code/configuration review, informed by AWS Core documentation searches. No AWS account resources, production data, cloud configuration, or application source were changed. Existing edits to `render.yaml`, deployment-source documentation and email documentation were left intact.

## Architectural decision

Retain the Java/Spring Boot modular monolith and React static frontend. Deploy the same immutable backend image in distinct API, worker and privileged migration/provisioning roles. Use Amplify Hosting for the frontend, ECS Fargate for backend roles, private RDS PostgreSQL for transactional state, private S3 for uploaded artifacts, and managed identity after an end-to-end integration spike. This agrees with the current November AWS plan; the October plan is historical.

The database split is an architectural workstream with its own acceptance criteria. For an initial bounded pilot, retain schema-per-tenant unless a customer requirement makes separate databases mandatory. Build tenant placement and shared-data interfaces first. Tenant databases on shared clusters, with optional dedicated enterprise clusters, remain a reasonable longer-term isolation model. Database-per-tenant does not remove schema duplication or independently scale tenants sharing the same server.

This sharpens the earlier tenancy recommendation: isolation and portability justify separate databases; the immediate AWS migration does not inherently require them. The repository plan models an initial 1–3-tenant pilot and describes no active customers, but those statements are dated planning assumptions, not a live customer inventory.

## Existing foundations worth retaining

- Durable connector admission: AWS discovery stores executable work through `jobs.withAdmission` and `enqueueConnectorJob` before returning queued status. [Source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java:103).
- Leased attempts, heartbeats, transaction fencing and expired-job recovery exist. These substantially improve rolling-deploy safety over the October review. [Attempt ownership](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionAttemptService.java:53), [recovery](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java:465).
- Runtime roles reject missing/unknown values, and background admission stops during shutdown. [Source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/BackgroundTaskExecutionPolicy.java:69).
- Tenant-context connections, reset/discard handling, RLS, restricted-role checks, schema migrations and tenant eligibility checks are useful defense and lifecycle mechanisms. Their existence is not proof that every path is isolated.
- Tenant migration failures no longer directly set whole-service readiness DOWN; inability to query the control plane still does. [Source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/TenantSchemaReadinessHealthIndicator.java:25).
- Customer AWS credential resolution validates account/role/external-ID binding and uses the default credential chain where explicit base credentials are absent. Retain ECS task-role integration. [Source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/client/AwsCredentialProvider.java:31).
- Credential encryption supports named active and previous keys. Preserve those keys during backup/restore and rotation. [Source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/CredentialEncryptionService.java:35).
- Local vulnerability archive operations are explicitly contained; do not repeat the older claim that the current implementation actively writes persistent archive files to container-local storage.
- CI includes PostgreSQL integration tests and architectural dependency rules. Passing results for today's candidate were not established in this review.

## Prioritized findings

### A01 — Move upload processing out of the API request path

**Priority:** Before opening the large-file/import capability to customers.

The multipart BOM endpoint calls `file.getBytes()` and invokes ingestion synchronously. The orchestrator takes an asset lock and processes bytes before returning. Remote BOM fetch already follows a durable-job pattern, so behavior differs by entry point. Large or concurrent uploads can consume API heap, threads and database capacity, with a result potentially obscured by an HTTP timeout.

**Change:** Issue a tenant-authorized, short-lived upload authorization for a unique S3 key. Validate the uploaded object's ownership, size, checksum and allowed format before admission. Bind the job to immutable object content, such as a version ID or verified immutable key, because a presigned URL can be reused until expiry. Persist the object reference and job intent, return 202 plus job ID, and process in workers. Include cleanup for abandoned uploads and explicit artifact retention. S3 and PostgreSQL are not one transaction: use a finalization state and reconciliation for partial completion.

**Acceptance:** A large import does not occupy API ingestion threads; replacing an API or worker task preserves accepted work; duplicate finalization is idempotent; a tenant cannot submit another tenant's object.

[Controller](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/controller/BomController.java:99), [orchestrator](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/BomIngestionOrchestrator.java:183), [AWS presigned upload semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html).

### A02 — Complete the Cognito identity contract rather than changing issuer settings alone

**Priority:** Before a managed-identity cutover.

LOCAL and EXTERNAL validation are now explicitly separated, and issuer/audience/token-purpose checks exist. However, the decoder requires an `aud` match for every access token. Cognito access tokens normally identify their app client with `client_id`; an API `aud` is present when resource binding was requested. Standard tokens without that binding would fail this validator. The browser still calls local login and token-returning tenant-context endpoints, while local token issuance explicitly rejects EXTERNAL mode.

**Change:** Implement the planned authorization-code/PKCE login and session contract. Define issuer, client ID, scopes, token purpose and resource audience explicitly. Validate actual Cognito access tokens, including resource-bound and unbound cases according to the chosen contract. Keep tenant membership/support authorization in the application. Decide how workspace switching works without minting LOCAL tokens in EXTERNAL mode. Follow the existing plan's Secure/HttpOnly backend-session design if selected, with CSRF, revocation and expiry.

**Acceptance:** Login, invitation, setup, tenant switching, support access, logout/revocation and service identities work end to end. Wrong issuer/client/resource, ID tokens and removed memberships are rejected.

[Decoder](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/JwtDecoderConfig.java:60), [local issuance guard](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AuthTokenService.java:99), [browser auth calls](/Users/karthik/Desktop/SG/prototype-app/frontend/src/api/client.ts:2291), [Cognito claims](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html).

### A03 — Treat database-per-tenant as a data-boundary refactor

**Priority:** Before enabling separate tenant databases.

The V1 tenant baseline contains 145 CREATE TABLE statements and 157 references to `platform.*` in foreign-key definitions. These are baseline counts, not live catalog measurements. Shared intelligence/tenant queries also rely on both schemas being in the same database. Routing currently changes session context on one underlying Hikari pool; it does not select a separate database.

**Change:** Introduce a tenant placement registry mapping tenant UUID to cluster/database, secret reference, lifecycle state and migration version. Resolve placement before transaction creation. Separate platform-management repositories from tenant repositories. Keep global intelligence authoritative centrally, with service queries or versioned local projections where needed for performance. Decide explicitly how global identities and references remain consistent after cross-database foreign keys are removed. Avoid synchronous distributed transactions as the default integration mechanism.

**Acceptance:** Two tenants on separate databases pass browser/API/worker flows; shared intelligence remains correct; tenant relocation and recovery are rehearsed; unknown placement fails closed; pool totals remain bounded. Keep one schema definition/release track across tenants rather than customer-specific code forks.

[Single pool](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/TenantIsolationConfig.java:40), [cross-schema query](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/repo/VulnerabilityIntelSummaryRepository.java:43), [tenant baseline](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/resources/db/migration/tenant/V1__tenant_schema.sql:9505).

### A04 — Budget connections across the fleet and qualify proxy behavior

**Priority:** Before increasing API/worker replicas; also before a tenant-database fleet.

Production defaults allow 30 Hikari connections and five idle connections per JVM. API, worker, migration, heartbeat and administrative activity compete for database capacity. Four ordinary JVMs permit up to 120 pooled connections before other consumers. Separate per-tenant pools would introduce another multiplier.

The datasource uses session-level tenant settings and `search_path`. Custom session state can reduce RDS Proxy multiplexing efficiency. The exact behavior of this code and driver must be measured; simply adding a proxy does not establish scalability or isolation.

**Change:** Set an explicit fleet budget: sum of maximum pool sizes across maximum replicas, deployment surge, maintenance and emergency reserve must fit the tested database budget. Use role-specific pool sizes; for tenant databases, lazy pool creation, total caps and idle eviction. Benchmark direct Hikari versus an appropriate pool/proxy configuration. Preserve tenant context and reset guarantees throughout.

**Acceptance:** At maximum autoscaling plus deployment surge, API requests and worker heartbeats retain capacity; alternating-tenant and failed-transaction isolation checks pass through the selected connection path.

[Production pool](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/resources/application-prod.yml:2), [session context](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/TenantAwareDataSource.java:91), [AWS proxy workload guidance](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/rds-proxy-best-practices.workload-considerations.html).

### A05 — Reserve execution capacity before leasing more jobs

**Priority:** Before increasing ingestion concurrency or tenant load.

Job claims set RUNNING, increment attempt count and start the lease before dispatch to the executor. The executor has two core threads, four maximum threads and a queue of 50; attempt heartbeats begin when execution opens the attempt. A queued task can wait longer than its lease, causing recovery/retries without useful execution. This is a control-flow risk, not an observed production incident. Fencing helps prevent stale database commits but does not eliminate wasted attempts or external-effect ambiguity.

**Change:** Reserve a worker slot before claiming, limit claims to available capacity and use a very small local queue, or explicitly renew ownership while awaiting execution. Separate slow connector scans from CPU-heavy parsing where measurements justify it. Do not rely on a large executor queue as durable storage.

**Acceptance:** With long jobs and several tenants, waiting jobs do not consume attempts due solely to executor delay; replacement workers make progress; expired owners cannot publish late results.

[Claim](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java:216), [dispatch](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobWorkerService.java:116), [executor](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/HttpClientConfig.java:93), [heartbeat start](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionAttemptService.java:95).

### A06 — Distinguish per-process limits from fleet guarantees

**Priority:** Before multiple replicas are relied on for strict aggregate quotas.

Public endpoint rate limits are explicitly process-local. AWS AI discovery admission uses local semaphores. Increasing replicas increases these local ceilings. Database-backed tenant job admission and some budgets already exist, so this is not a claim that all limits are local.

**Change:** Retain local overload protection. Add WAF ingress controls and shared, atomic application budgets for guarantees such as account/provider concurrency and tenant spend. WAF request limits are not a strict business quota. Existing PostgreSQL coordination may be sufficient initially; introduce Redis only when required by throughput/latency.

**Acceptance:** A multi-replica test cannot exceed the intended aggregate allowance, and one tenant does not consume all worker capacity.

[Public limits](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/security/PublicEndpointRateLimiter.java:21), [AWS admission](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/aisecurity/aws/AiSecurityAwsAdmissionService.java:12).

### A07 — Reduce tenant-wide polling as the tenant fleet grows

**Priority:** Measure in the pilot; redesign before large tenant expansion.

The ingestion poller iterates all active tenants every cycle and performs multiple claim passes by type. Recovery and connector scheduling also iterate tenants. More replicas multiply empty polling, and separate databases would add connection churn.

**Change:** Measure query rate and cycle duration first. Add a platform-level ready-work index or durable dispatch outbox so workers find tenants with pending work. Keep periodic sweeps as reconciliation. Assign tenants/cells or use coordinated claims to bound duplicate scanning. If SQS becomes useful, publish through a transactional outbox; moving to SQS does not remove idempotency, leases or reconciliation requirements.

**Acceptance:** Empty-tenant count has limited impact on dispatch latency and database load; a busy tenant cannot starve another.

[Poller](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobWorkerService.java:98), [scheduler](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java:131).

### A08 — Produce a deployable and recoverable AWS release

**Priority:** Before production cutover.

The reviewed infrastructure directory contains an AWS discovery fixture, not the application hosting stack. The tracked workflows inspected perform quality/security checks; they do not establish an AWS artifact-promotion pipeline. The current November plan correctly treats ECS/RDS/S3/Amplify infrastructure and qualification as future deliverables.

**Change:** Author reviewed IaC for networking, load balancing, task/execution roles, API/worker services, private database, buckets, secrets, alarms and deployment permissions. Promote immutable image digests with separate migration tasks and rollback compatibility checks. Coordinate ALB draining, application shutdown and ECS stop timeout. Port frontend security headers, routing and cache behavior from Vercel to Amplify; a provider switch does not copy those settings. Rehearse database/object/key recovery.

Native RDS recovery of an instance does not automatically give independent point-in-time recovery for one tenant schema/database. Define tenant-level restoration and external-effect reconciliation before promising an RPO/RTO. Preserve application encryption key versions as well as database snapshots.

[Fixture scope](/Users/karthik/Desktop/SG/prototype-app/infrastructure/cloudformation/README.md:1), [quality workflow](/Users/karthik/Desktop/SG/.github/workflows/quality.yml:204), [current migration plan](</Users/karthik/Desktop/SG/prototype-app/Working Knowledge/AWS/AWS_FINAL_MIGRATION_PLAN.md:1>), [ECS shutdown guidance](https://repost.aws/knowledge-center/ecs-graceful-shutdown-connection-draining-deployments).

### A09 — Strengthen module boundaries and operational telemetry

**Priority:** Incremental, alongside product delivery.

The backend contains 1,252 Java source files. Existing ArchUnit rules mainly enforce layering and specific AI-domain boundaries. That is a useful foundation; file count alone does not establish a performance problem. Some orchestration remains large, for example the 1,454-line BOM orchestrator. Selected operational metrics are stored in process-local sample collections, so they should not be mistaken for durable fleet-wide SLO history.

**Change:** Define explicit internal modules for tenancy/identity, intelligence, inventory/ingestion, correlation/findings, connectors, governance and workflow. Enforce allowed dependencies; move database coordination and provider adapters behind interfaces. Retain a monolith until measured deployment/scaling ownership justifies service extraction. Export request latency, oldest-job age, attempts/reclaims, feed freshness, pool waits and provider throttling to persistent monitoring. Use tenant/tier attribution with a deliberate cardinality policy rather than adding every record ID as a metric dimension.

**Acceptance:** Cross-module dependencies are checked in CI; dashboards can distinguish a tenant incident, provider outage, stalled queue and general API issue across task replacements.

[Architecture rules](/Users/karthik/Desktop/SG/prototype-app/backend/src/test/java/com/prototype/vulnwatch/ArchitectureRulesTest.java:22), [local samples](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/OperationalMetricsService.java:61), [AWS tenant insights](https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-insights.html).

### A10 — Remove schema-version metadata drift

**Priority:** Small operational correctness improvement before release.

Readiness reports supported versions as the literal `5..5`, while the current compatibility constants and application configuration require V19. Some injection fallback values also still say 14, though the normal application configuration overrides them. The hardcoded health detail is misleading; it does not itself change eligibility.

**Change:** Derive reported ranges and configuration defaults from one compatibility source. Rehearse expand/contract migrations and the overlap supported by old/new binaries before rolling deployments. Do not assume the previous image is safe after schema changes.

[Health detail](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/TenantSchemaReadinessHealthIndicator.java:32), [compatibility constants](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/TenantSchemaCompatibility.java:3).

## Suggested delivery sequence

1. Agree the offered pilot capability set and record tenant/workload/recovery assumptions. Preserve explicit exclusions.
2. Complete identity and asynchronous-upload changes; test worker preclaim behavior and bounded fleet capacity.
3. Create AWS IaC and a repeatable validation environment. Qualify API/worker separation, draining and provider connectivity.
4. Run alternating-tenant, two-worker, killed-owner, maximum-load, restore and rollback journeys. Retain candidate-specific evidence.
5. Open a small tenant cohort; observe queue latency, resource use and actual per-tenant consumption.
6. Implement separate tenant databases when required, using the placement/data boundaries above. Add cells or dedicated clusters based on measured limits and customer requirements.

If separate databases are an immediate non-negotiable requirement, move step 6 before customer cutover and include all of A03 and A04 in the launch gates. Do not simultaneously introduce Kubernetes, a microservice rewrite, multi-region active-active, Kafka, Redis and Aurora without an independently justified need.

## Verification and limits

Reviewed manifests, frontend hosting configuration, backend runtime profiles, datasource/tenancy and schema compatibility, representative auth paths, upload ingestion, durable connector admission, attempt/recovery/dispatch logic, executor configuration, credential handling, rate limits, migration orchestration, operational metrics, CI/architecture tests and current migration documents. This was a focused cross-cutting architecture review, not an exhaustive inspection of all 1,252 Java files or a formal vulnerability scan.

Attempted targeted tests: `ArchitectureRulesTest`, `JwtModeContractTest`, `PublicEndpointRateLimiterIsolationTest`, `IngestionAttemptStartupTest`. They did not run because `mvn` is not installed/on PATH and no repository Maven wrapper was found. No passing test claim is made. Runtime failure/load scenarios above are acceptance criteria, not executed results. No live AWS inventory, production load test, failover, restore or customer-data audit was performed. Source presence and historical documents do not certify deployed behavior or capacity.
