# Assessment of Claude's configurable tenant isolation review

**Planning status.** The replication assessment below informs the Part 2 topology decision. Standard launches in Part 1 using the existing shared-schema model. Part 2 compares a tenant-only database with shared application capacity against a dedicated deployment cell. [AWS master migration plan](AWS_MASTER_MIGRATION_PLAN.md)

Prepared November 6, 2026. Source baseline: `f9426447e18c6f3c4c836e3f1c14e0943fb93a22`, including existing workspace changes. This is a design assessment, not implementation approval or capacity certification. It considers the complete review supplied by the user, including native logical replication, two service tiers and deferred provisioning orchestration.

## Decision

Adopt the simpler Standard/Dedicated product structure and a repeatable provisioning job/runbook for initial customers. Treat allowlisted reference-table logical replication as a promising compatibility implementation that needs a focused proof of concept. Do not accept its lower total engineering cost, six-week delivery date, or complete isolation guarantees without that evidence.

Native replication can reduce read-query rewrites by retaining local table names and joins. It is a concrete implementation of local reference projections, with less custom copying code. It does not eliminate the boundaries between authoritative control-plane writes, tenant transactions and asynchronously replicated reads.

## Assessment by recommendation

| Recommendation | Assessment |
|---|---|
| Standard = shared schemas; Dedicated = tenant-only RDS | Good initial commercial simplification. Keep internal placement explicit so additional profiles do not require a redesign. |
| Drop logical-database-on-shared-instance tier | Reasonable prioritization, not a universal architectural rule. It has credential/namespace/export benefits but does not provide separate resource/recovery boundaries. |
| Replicate local reference tables to preserve SQL | Worth prototyping with an explicit table/column allowlist and freshness contract. Do not replicate the whole platform schema. |
| Refactor platform writes only | Understates shared transactions, ORM associations, immediate reference reads and central authorization. Inventory these before estimating. |
| Tenant-only search_path gives complete inventory in a day | Useful experiment, incomplete dependency discovery. |
| Defer Step Functions | Agree. A durable, idempotent job and IaC/runbook can satisfy initial provisioning without that service. |
| One pool per instance | Appropriate only where database and credential identity are also the same. Pool keys must include those identities. |
| Skip RDS Proxy initially | Reasonable for bounded containers/Hikari; retain measured connection budgets and validate session behavior. |
| Every release supports N/N-1 | Use explicit expand/contract compatibility, not a blanket promise. Current code supports exactly V19. |
| Add orchestration at five onboardings/quarter; revisit replication at twenty subscribers | Planning heuristics, not capacity or reliability boundaries. Use actual toil, lag, source load and recovery requirements. |

## Why the two-tier offer is sensible

Standard can retain current tenant schemas and RLS. Dedicated can provision a tenant-only RDS instance, a restricted runtime secret, an approved availability/backup policy, and a tenant-specific RDS storage encryption key where included in the contract. Both use the same application image and schema release track.

Do not use one tier to imply guarantees at unrelated layers. Shared API/worker capacity, identity, global intelligence and platform administration remain shared unless separately isolated. A dedicated database is not a fully independent deployment or an end-to-end availability boundary.

The assertion that customers usually mean four particular things by a separate database needs customer discovery. Logical isolation is different from a physical non-co-mingling requirement. Clean tenant export/deletion is possible with shared schemas too, subject to backup retention. A native per-tenant RDS storage key requires an appropriate separate resource; application-level per-tenant encryption is a different design and promise.

## Replication: real benefits and necessary corrections

### 1. Classify platform tables before selecting publication contents

The current platform schema includes global authority and sensitive identity fields, not just public intelligence. `AppUser` maps to `platform.app_users` and includes password/setup hash fields. Other platform entities include tenants, memberships and shared run history. This demonstrates why a broad platform publication is inappropriate; it is not a claim about populated production values.

Use an allowlist of explicitly classified reference/intelligence data. Exclude credentials, global users, unrelated tenant metadata, invitations, support grants and other customers' data. Keep authorization/revocation authoritative centrally. Local display/reference projections, if needed, should contain only the allowed data for that tenant. Make runtime DML on replicated reference tables unavailable; logical subscribers are not inherently read-only.

[AppUser source](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/domain/AppUser.java:13), [PostgreSQL logical replication security](https://www.postgresql.org/docs/16/logical-replication-security.html).

### 2. Platform-write routing changes current atomic transactions

There is a concrete example in the code. `AwsDiscoverySyncService.trigger()` uses `jobs.withAdmission` to create a `platform.sync_runs` record and enqueue a tenant ingestion job. `withAdmission` wraps this in one tenant-context transaction. Routing only the run insert centrally makes the two writes span independent databases.

Decide how executable intent and run history are recovered if only one write succeeds. An outbox/durable command and reconciliation approach can solve it; substituting a datasource cannot preserve the original atomicity by itself. This is a necessary design change in either a custom-projection or native-replication implementation.

[Trigger](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java:103), [run persistence](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java:217), [transaction wrapper](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java:523).

### 3. Some reference-like records are created during tenant processing

`SoftwareIdentityService.resolveHostSoftwareIdentity()` can create/update a platform software identity, identifiers and correlation links during ingestion. An immediate tenant write/read may need that new identity before asynchronous replication delivers it. This can lead to missing local joins or a tenant insert failing against an enforced local reference FK.

Choose which operations remain central, which references must be synchronized before work proceeds, and which joins can tolerate lag. Dropping FKs does not supply read-your-write behavior. Not all audit data belongs centrally either: the tenant audit table and platform audit/feed responsibilities need separate classification.

[Identity processing](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/SoftwareIdentityService.java:56), [platform mapping](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/domain/SoftwareIdentity.java:14).

### 4. The replicated DELETE/FK explanation is incorrect for default apply

PostgreSQL logical apply uses `session_replication_role=replica`. Default FK triggers do not run during ordinary replication apply. A replicated reference DELETE can therefore leave dangling tenant references rather than stop replication as the review suggests. Explicit replica/always trigger configuration can change the outcome; TRUNCATE has separate FK restrictions.

Define reference retirement, tombstones or retention and reconciliation deliberately. Removing constraints without those rules hides a consistency problem. Retain normal tenant-local constraints.

[Apply behavior](https://www.postgresql.org/docs/16/logical-replication-architecture.html), [TRUNCATE and other restrictions](https://www.postgresql.org/docs/16/logical-replication-restrictions.html).

### 5. DDL and subscriber recovery are additional lifecycle work

Logical replication does not copy schema migrations, sequence state or views/functions. Subscriber tables must exist with compatible names and structures. Deploy reference schema changes in a compatible order and version them alongside tenant schemas. Account for initial synchronization, permissions and any required subscriber-side computed/read-model objects.

Slots can retain publisher WAL when subscribers lag. A finite `max_slot_wal_keep_size` limits retained WAL at checkpoints but can remove data required for a subscriber to resume. A cap therefore needs alerting and a tested rebuild/resynchronization procedure. Qualify publisher failover and subscriber restoration against the exact RDS topology/version. A healthy database restore does not prove the subscription is usable.

Subscriber count alone is a poor scale threshold: source change volume, replicated corpus size, lag, worker limits, bandwidth and rebuild time matter. Each subscriber also duplicates reference storage and indexing.

[Schema restrictions](https://www.postgresql.org/docs/16/logical-replication-restrictions.html), [slot retention behavior](https://www.postgresql.org/docs/16/runtime-config-replication.html), [AWS source overhead and slot monitoring](https://aws.amazon.com/blogs/database/migrating-amazon-rds-for-postgresql-to-amazon-aurora-using-seeded-logical-replication/).

## Dependency discovery and rollout

Use the tenant-only search-path experiment, but override the application wrapper as well: it resets the path on connection acquisition. Explicit `platform.*` SQL and entities annotated with `schema="platform"` bypass that probe, and unexecuted paths remain untested. Combine static entity/query classification, captured SQL and transaction boundaries, permission-denial tests and representative integration journeys.

The backend's 1,252 source files do not establish that all require edits. Equally, enumerating platform writes does not establish that they are independent of tenant commits. Scope and estimate the dependency graph rather than using either file count as a project estimate.

The current compatibility class requires exactly V19. Support a tested version overlap during fleet rollout using expand/contract migrations; do not simply loosen validation to accept a schema missing required columns. Per-placement status and eligibility must accompany the release mechanism. Delay incompatible tenant capability activation until migration is ready.

[Datasource path](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/config/TenantAwareDataSource.java:91), [current compatibility](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/TenantSchemaCompatibility.java:3).

Placement caching also needs a bounded staleness/lease policy and migration invalidation. A cached generation cannot independently prove it is current during a registry outage. Multi-AZ improves infrastructure availability but does not eliminate logical database failures or control-plane dependencies.

## Offboarding and crypto-erasure

A separate key can support cryptographic erasure for ciphertext covered by that key. Do not promise immediate deletion of all tenant data. Standard AWS KMS key deletion has a 7–30-day waiting period. Exports, object storage, logs, central records, cross-region copies and backups encrypted under other keys require their own handling. Decide retention/holds and document the exact erasure scope.

A provider-managed customer-managed KMS key is not automatically a key controlled by the customer's own AWS account. State who controls policy and deletion.

[AWS KMS deletion behavior](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html).

## Cost and schedule assessment

AWS Core successfully queried the public Pricing API on November 6, 2026. For RDS PostgreSQL `db.t4g.medium` in `us-east-1`, On-Demand running-instance compute is:

| Deployment | Hourly USD | Compute at 730 hours |
|---|---:|---:|
| Single-AZ | 0.065 | 47.45 |
| Multi-AZ | 0.129 | 94.17 |

Monthly values were calculated by the tool using decimal arithmetic. A separate unused-capacity-reservation product returned by the API was excluded. Evidence is retained in [pricing-evidence/dedicated-rds-compute-check-2026-11-06.json](pricing-evidence/dedicated-rds-compute-check-2026-11-06.json).

The proposed $120–150/month dedicated figure is plausible as a small-resource infrastructure allowance, not a validated all-in cost or evidence of sufficient capacity. Include the duplicated intelligence corpus/indexes, storage growth, backup retention, source logical-decoding load, replication traffic, monitoring, key/secret usage, CPU credit charges where applicable and support/tax treatment. T4g is burstable; the existing plan already treats it as conditional for sustained correlation workloads. No tenant workload benchmark was performed. [AWS instance behavior](https://aws.amazon.com/rds/instance-types/).

The existing $753.05 pilot figure is AWS with contingency, not the full operating budget or an allowance for a growing dedicated fleet. Source refactoring by itself does not necessarily add an always-on service, but enabling replication can change compute, storage and network demand. Do not promise zero incremental cloud cost without measuring it.

Treat 1–2 weeks of groundwork and 4–6 weeks for Dedicated as hypotheses. Validate a vertical slice before making a delivery commitment. In particular, caller/worker transaction changes and recovery may dominate the read-query savings.

## Recommended next step

Proceed with a two-tier design and a time-boxed engineering spike rather than a full rewrite. The spike should produce evidence, not an artificial calendar guarantee:

1. Classify platform tables: central authority, public/reference intelligence and customer-derived data. Inventory platform/tenant transaction spans.
2. Build one disposable dedicated placement with a small allowlisted reference publication and restricted runtime role. This document does not authorize or perform billable provisioning.
3. Prove a complete connector admission → new identity → ingestion → findings journey under forced replication lag.
4. Exercise central membership revocation, reference deletion, reference DDL changes, worker replacement and failed provisioning.
5. Exercise a stalled subscriber, WAL-cap exhaustion, publisher failover and subscriber restore/resynchronization. Measure source overhead, subscriber storage and catch-up time.
6. Use the evidence to choose native replication or a narrower service/projection design and re-estimate the remaining work.

Keep the existing shared tier working during this effort. Deliver the dedicated profile only after the advertised provisioning, upgrade, isolation and recovery guarantees pass. Retain one product/release track and defer a self-service provisioning interface until its operational value is demonstrated. The user's requirement for a platform-managed separate database remains intact.

## Scope

This assessment used independent source/replication reviews, current primary PostgreSQL/AWS documentation and one public Pricing API query. No cloud resources or application code were changed, and no integration/load/restore tests ran. This does not establish the current customer count, staffing or live AWS cutover state. Research artifacts only were added under Working Knowledge/AWS.
