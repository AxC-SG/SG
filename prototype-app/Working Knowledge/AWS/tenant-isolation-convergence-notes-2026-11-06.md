# Tenant isolation: assessment of the revised Claude response

Prepared November 6, 2026. Read-only source review against the existing workspace, plus PostgreSQL 16 and 18 primary documentation. This note follows the supplied response that accepts the earlier corrections and proposes ownership classification, moving tenant-owned platform rows, and synchronous local insertion into replicated tables.

**Planning status.** The ownership inventory, run-state split, and replication experiment below inform Part 2. The architecture decision determines which implementation tasks are needed. Part 1 qualifies Standard with the existing shared-schema model, and Part 2 qualifies new Dedicated tenants alongside regression tests for Standard. [AWS master migration plan](AWS_MASTER_MIGRATION_PLAN.md)

## Recommendation

Adopt the ownership-first approach and the Standard/Dedicated product direction. Before implementing native reference replication, reject the assumption that an application upsert into a subscription target makes the later native insert a no-op. That behavior is not supplied by default PostgreSQL logical replication.

The next useful deliverables are a data-ownership and transaction matrix, then a bounded prototype with explicit acceptance conditions. This note does not change application code, create cloud resources or certify the design.

## Ownership classification is the strongest addition

Classifying data before selecting replication is the right order:

| Data responsibility | Proposed placement |
|---|---|
| Identity, tenant membership, support authority and commercial/platform configuration | Central authoritative control plane |
| Approved public/global reference intelligence | Central authoritative corpus; allowlisted, versioned local replication or projections where useful |
| Customer-owned ingestion, discovery and operational state | Tenant-local transactional storage wherever ownership and required consistency allow |

Use the 27 explicitly platform-mapped classes as a starting list, not the full inventory. Also cover native SQL/JDBC, views/functions/triggers, relationships, constraints, job claims and tables referenced without JPA entities. Classify rows/columns where a table mixes ownership. Record which process writes each dataset and which multi-table transactions currently depend on it.

Customer-derived software identities and correlation links are not automatically public just because they are stored in a shared catalog. Decide the permitted replication scope explicitly.

## Moving tenant state can avoid unnecessary distributed writes

The principle is sound: tenant run history and executable tenant work should be colocated if they need one transaction. This can eliminate an outbox that would otherwise be needed solely because of an accidental storage boundary. An outbox is a remedy for a justified cross-resource boundary, not a default requirement for every operation.

However, `platform.sync_runs` is currently mixed:

- `SyncRun` explicitly maps to `platform.sync_runs`.
- Global vulnerability feeds create `PLATFORM_VULNERABILITY` runs with no tenant.
- AWS discovery creates `TENANT_INVENTORY` runs.
- AI discovery uses tenant AI-security scopes.
- Intelligence staging/publication data also references the central run table.

Split platform feed runs from tenant run records, rather than moving the entire table. Move the tenant side's admission, claim, lease, status and recovery logic together. Update ORM mappings, query consumers and reporting. Global visibility can use a platform summary/read model with a defined freshness contract instead of reintroducing synchronous dual writes for every status update.

After that split, confirm the complete connector admission transaction is tenant-local before declaring its atomicity issue resolved. Central identity/reference creation and other remaining cross-resource operations still require independent treatment.

Evidence: [mapping](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/domain/SyncRun.java:16), [global run creation](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/vulningestion/VulnerabilitySyncRunService.java:371), [AWS tenant run](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/AwsDiscoverySyncService.java:217), [admission transaction](/Users/karthik/Desktop/SG/prototype-app/backend/src/main/java/com/prototype/vulnwatch/service/IngestionJobService.java:523).

## Do not make application writes to native replication targets the default consistency mechanism

The suggested sequence is:

1. Commit a new identity centrally.
2. Upsert it into the subscriber reference table from application code.
3. Let native replication later deliver the central insert.

Step 3 is not automatically idempotent. The replicated INSERT can violate the subscriber's primary/unique key and stop apply. The application's `ON CONFLICT` behavior does not configure native apply behavior. PostgreSQL 18 also documents `insert_exists` conflicts requiring resolution; upgrading alone does not establish a generic conflict-is-no-op policy.

The response acknowledges that a conflict policy is needed, but that policy is unresolved engineering, not a minor configuration detail. It would need to handle races with replication, concurrent creation, retries, canonical-ID selection, updates arriving in different orders, tombstones and rebuilds. Skipping a conflicting replication transaction can discard unrelated changes in that transaction and is not a safe routine deduplication strategy.

For the initial native-replication prototype, keep the subscribed reference tables application-read-only. Choose an explicit behavior for a newly created central reference:

- Gate/retry dependent work until that row and required revision are visible locally, with a timeout and observable job state; or
- Use a central reference interface for the operation that requires immediate authoritative visibility; or
- Maintain a separate pending-reference overlay, accessed through an application interface and retired after replication catches up. This needs additional code and reconciliation but avoids dual ownership of the subscription target.

Select by the operation's latency and integrity requirements. Do not change replication to synchronous fan-out across every dedicated tenant simply to hide this boundary; that can couple global write availability to tenant subscribers.

[PostgreSQL 16 conflicts](https://www.postgresql.org/docs/16/logical-replication-conflicts.html), [PostgreSQL 18 conflicts](https://www.postgresql.org/docs/18/logical-replication-conflicts.html).

## Two further qualifications

**Live central authority is necessary for prompt revocation, but does not by itself guarantee instantaneous revocation.** Verify actual request authorization, cached permissions, session/token behavior, background execution and in-flight operations. Define what happens when the authority is unavailable. Do not use stale replicated authorization as a fallback.

**Keep shared and Dedicated business behavior behind common contracts.** A replication failure should not lead to a permanent duplicate set of business rules for Dedicated. A common reference-data interface can retain the existing local implementation for shared tenants and use a replica/service adapter for Dedicated. This can be introduced incrementally; it does not require rewriting every shared query before experimenting. Replica and service implementations need the same freshness, missing-reference and retirement contract.

## Prototype charter

Treat two weeks as a timebox for learning and a go/no-go decision, not a delivery promise. Complete the ownership/transaction classification sufficiently to select one representative vertical slice. Record an incomplete or inconclusive result honestly; failure of a native replication experiment does not prove another design will fit the same schedule.

Acceptance evidence should include:

1. One shared tenant and one dedicated placement using the same application release and correct API/worker routing.
2. Tenant connector admission with no platform/tenant partial-write gap after the proposed run-state split.
3. A newly created central software identity under deliberate replication delay, with no application DML on the subscription target and no silent missing joins.
4. Prompt membership/support revocation and documented behavior when the control plane is unavailable.
5. Reference updates/retirement, duplicates/retries, compatible reference DDL rollout and tenant schema compatibility.
6. Subscriber outage and resynchronization, WAL-cap exhaustion handling, publisher failover and recovery from a subscriber backup.
7. Measured source overhead, reference storage, catch-up time and operational steps sufficient to estimate the complete Dedicated offer.

Decision outputs: accepted mechanism and consistency contract; unresolved dependencies; revised cost/effort assumptions; and the smallest qualified release scope. Defer additional broad architecture documents once these evidence-producing tasks are defined.

## Scope

Read the user's attached response in full; inspected mixed run ownership and existing transaction/identity paths; consulted PostgreSQL conflict documentation; used an independent read-only source review. No integration, replication, failover or restore test ran. Prior public-price observations remain supporting context, not newly benchmarked capacity. Research changes are confined to the AWS knowledge folder.
