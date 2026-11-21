# First customer local qualification

21 November 2026 · `codex/first-customer-readiness` · Base candidate `cdce657d` on GitHub main `27b3442a`

Both full-volume functional tests passed. Publication lock and restart approval and customer-environment performance qualification remain open.

The qualification uses a disposable PostgreSQL 16.16 instance on loopback, Java 17, fixed synthetic provider data, and blank demo-seed configuration. The local host has 10 CPU cores and 24 GiB of RAM. The catalog and inventory jobs overlapped for part of the run. Platform V31 and tenant V79 are the packaged heads. The independent catalog and inventory databases exercise the same working-tree candidate. UI traffic in the volume fixture uses the authenticated Spring MVC routes that back the UI. The existing Standard governance script also exercises live HTTP routes.

## Catalog, feed recovery and publication

| Stage | CVEs | Staged records | Elapsed | Sampled JVM heap peak | Database growth | Client connections |
|---|---:|---:|---:|---:|---:|---:|
| Continuous staging, first checkpoint | 10,000 | 82,500 | 82.5 s | 1.31 GiB | 82.6 MiB | 3 |
| Continuous staging, second checkpoint | 100,000 | 825,000 | 9 min 57 s | 1.37 GiB | 618.7 MiB | 4 |
| Staging completed after process replacement | 400,000 | 3,300,000 | 24 min 27 s from replacement | 1.40 GiB | 1.11 GiB from replacement | 3 |

The NVD fixture emits 1,000 records per page, 20,000 repeating product coordinates, two targets per CVE, and configuration expressions for one in four CVEs. The synthetic description, references, scores, and raw JSON follow the provider record shape. The volume run resumed an injected interruption at 100,000 CVEs. A second recovery terminated the disposable JVM. Its replacement resumed the same run after 192,000 committed CVEs and 1,584,000 staged records. The replacement completed a routine KEV run in 109 ms while the NVD attempt was active. Staging finished with 400,000 distinct CVE IDs and a matching checkpoint manifest. At completion the catalog database occupied 2.24 GiB. Statements from the replacement staging phase generated 1.96 GiB of database-attributed WAL. The full-volume recovery test paused live application and verified that the prior approved generation remained visible.

The original BUILD query took 17.7 seconds at 16,500 staged records, with 17.6 seconds inside candidate insertion. PostgreSQL repeatedly searched the staged run for invalid observations. BUILD now reads a deduplicated set of invalid run and canonical ID pairs before joining it to staged rows. The regression verifies that the quarantine stays within each run, preserves existing validation errors, and produces one candidate row per staged row. Publication applies a prepared metadata row in a single SQL update, reducing per-field round trips and intermediate journal rows.

At full volume, BUILD completed in 80.5 seconds. It inserted 3.3 million immutable candidate records. PostgreSQL attributed 51.9 seconds and approximately 5.7 GiB of temporary writes to candidate insertion. BUILD grew the database by 2.41 GiB and its statements generated 5.16 GiB of WAL. Owner approval followed 81.2 seconds after feed completion and includes automated BUILD time.

The operator observed publication progress with generation 1 still visible. The pause discarded its first 100 reported records, rolled back within 917 ms of the request, and released the observed lock after approximately 23.8 seconds. On restart, some early 100-row keyset pages took about six seconds before autovacuum analyzed the new candidate. The same prepared keyset query then used an ordered index scan and returned 100 rows in 0.04 ms in a direct probe. The first restart included that initial stale-statistics delay. The workstation suspended during the first long attempt, so the sample log contains gaps.

The long attempt exposed a separate, growing SQL cost. VEX cleanup executed 63,258 target subqueries and deleted zero assertion rows. PostgreSQL attributed 4,424 seconds and 1.34 billion shared-buffer hits to those calls. The attempt was stopped after 173,700 reported candidate records. Generation 1 and the original approval remained intact. Publication now looks up targets through the vulnerability index, removes dependent VEX assertions by target ID first, and deletes the selected targets in batches of 250. A replacement JVM reused the same reviewed candidate and digest. At 781,000 processed records, the new lookup averaged 0.039 ms across 94,671 calls.

The final retry rebuilt the live catalog from the start of the attempt and committed generation 2 in **23 minutes 7 seconds**. The observed release-lock hold was **at least 23 minutes 6.5 seconds** at approximately 200 ms sampling resolution. Generation 2 contained 400,000 synthetic CVEs plus the prior baseline CVE, 800,000 targets, 100,000 configuration expressions, and 3,700,006 total journal rows. Candidate review recorded zero exclusions. The final catalog database occupied 12.86 GiB, including 2.11 GiB of staging, 2.41 GiB of candidate rows, and 4.69 GiB of release history with their indexes. The retry recorded 1.30 GiB peak JVM heap and three sampled database clients. It generated 8.42 GiB of database-attributed statement WAL. The cluster recorded 19.95 GiB of WAL during the measurement window, which partly overlapped with the inventory run.

During staging at 59,000 CVEs, the existing EPSS candidate query took 181 ms to return one eligible CVE. The plan read approximately 487,000 staging tuples, including 427,752 rows filtered out by kind. The sort spilled about 2.4 MiB. This provides a baseline for the `canonical_id` lookup. The release has no agreed EPSS lookup budget.

## Inventory and live publication

The primary fixture stages SCCM rows through the connector’s PostgreSQL capture and consumes one host per merge transaction. It uses 1,000 assets with 500 observations per asset, a second tenant with its own evidence, and known CPE mappings for the findings probes. All 500,000 observations normalized in **5 minutes 55 seconds**, including collection and staging. The first full pass took 7 minutes 35 seconds. On the final pass, the per-host merge p95 was 461 ms and the p95 host completed 322 seconds after the first host started merging. This phase recorded 1.31 GiB peak JVM heap, 1.22 GiB database growth, 4.33 GiB of database-attributed statement WAL, and three sampled database clients. The 25-host unchanged rediscovery replay processed 12,500 observations in 12.7 seconds. It created zero new correlation jobs, changed no findings, and retained the tenant evaluation revision. It refreshed 501 coalesced software summary keys because summaries retain last-observed timestamps.

In a two-host sample, PgJDBC rewriting reduced the SCCM staging insert count from 1,000 single-row statements to 12 batched statements for the same 1,000 rows. Both modes executed 1,000 inventory-component and 1,000 software-instance inserts. Initial ingest wall time varied between runs at this size. With default driver settings at full volume, PostgreSQL counted 500,000 insert executions on each of the SCCM staging, software-instance, and inventory-component paths. Server execution time for those statements was 8.4, 10.0, and 124.7 seconds respectively. The rewrite setting remains a measured option for staging. A tenant-scoped read of 500 rows used both columns of `idx_inventory_tenant_asset`. That observed warm lookup took 85 µs, versus 2.66 ms for the local migration-owner sample.

The initial drain settled in **14 minutes 57 seconds**. All 500,000 software deltas completed on their first attempt. Queue-to-completion p95 was **845.7 seconds**, measured with the initial capture and drain run in sequence. The sampled maximum correlation transaction age was 263 ms. The highest transaction age captured by this sampler is a lower bound.

| Concurrent live update | Time through settlement | UI API samples | Observed UI API p95 |
|---|---:|---:|---:|
| EPSS ranking | 1.92 s | 4 | 280 ms |
| Applicability range | 2.58 s | 4 | 215 ms |
| VEX | 2.70 s | 4 | 211 ms |
| Target removal | 2.75 s | 4 | 238 ms |

Both tenants completed targeted delivery with no terminal delta failures. The test verifies source overlap, an independent change burst during publication, risk score and tenant rollup changes, and restoration after withdrawals. A digest target outside the routable key set scheduled explicit reevaluation and advanced its first page. The small UI samples confirm the routes respond under overlap. They establish no production traffic percentile.

The real EPSS normalization smoke test identified a route classification gap. Score updates generate observation and provenance rows, which previously triggered fallback reevaluation. Reviewed EPSS-only candidates now classify their ranking and provenance changes together when the canonical evidence is already active. A separate journal fix prevents a skipped canonical insert from appearing in withdrawal history. The volume run reproduced the expected EPSS score and rollup changes while leaving the applicability evaluation timestamp unchanged.

## Standard governance and regression results

Fresh production bootstrap reached the packaged migration heads. Standard baseline, correlation certification, and final scorecard passed with demo seeding disabled. The run sampled 20 UI API routes three times using a tenant JWT. No route, freshness, or resource checks failed, and the final queues were empty. The disposable instance allowed local default-tenant fallback for the existing API-key correlation probes. The Standard AWS association fixture remains an independent gate.

Maven verification passed 1,816 backend unit tests and 60 focused PostgreSQL tests, plus JaCoCo and SpotBugs. The focused cases covered malformed or incomplete feed data, checkpoint recovery, scheduled publication boundaries, scoped target and VEX replacement, inventory delta atomicity, partial and stale SSM snapshots, interrupted SCCM capture, and release recovery. Both full-volume Failsafe tests passed separately. Seven publication recovery, SSM and SCCM cases passed again on the separate disposable PostgreSQL instance used for the migration rehearsal. The migration checks against `27b3442a`, tenant-DDL check and 11 guard self-tests passed.

## Deployment baseline and local rehearsal

The November 16 Sydney lab record lists release `20261116t082637z-cbb265b` as the accepted pair, with API task revision `:11`, worker `:10`, backend digest prefix `9d83db25` built from `52163ec`, and frontend deployment `dpl_G3By6vq5QDcH2dwSQoXpyQcfLEST` built from `cbb265b`. The later verified backend-only reconcile `20261116t160758z-e7f871c` kept those task definitions and reported tenant V23–V23. It awaited acceptance in the local record. The November 15 migrator recorded platform V16 and tenant V23. Render's older pre-reset history belongs to the retired hosting path. [Sydney lab release record](<../AWS/LAB_IMAGE_PUBLISHING_RECORD_2026-11-15.md>) · [Hosting cutover](<../AWS/aws-lab/evidence/2026-11-13/cutover-rollback.json>)

The existing read-only Sydney profile reported an expired AWS session. The Vercel connection returned 404 for the recorded team-scoped project and production alias, so the active frontend deployment remains unconfirmed. Current release and recovery artifacts, effective API and worker role, flag and version settings, applied platform and per-tenant Flyway rows with script names and checksums, and a representative database backup approved for local restore are still required. The recorded November 15 RDS snapshot predates the V15/V20 → V16/V23 migration. A source migration head and a historical snapshot are insufficient to establish the current database contents or campaign recipient-data disposition.

For the local rehearsal, the platform V1–V16 and tenant V1–V23 migration files at `52163ec` matched the packaged candidate byte for byte. A synthetic database with two active tenants and one pre-existing host per tenant was dumped and restored into a new PostgreSQL 16 database. The candidate's production bootstrap migrated the restore to platform V31 and tenant V79 for both tenants, including platform V22 in nontransactional mode and pending tenant repairs. All 62 prior version, script and checksum rows survived. Both tenant schemas reported `CURRENT` with matching structural fingerprints. A second bootstrap validated the migrated histories without applying additional migrations and provisioned the second restricted runtime login.

The separate `worker` and `api` processes used the candidate backend with Flyway disabled and required tenant context. A Hikari pool with one connection verified that the worker reused the physical connection across canary, peer and canary again. The two tenants could each read their own rows. Queries that explicitly named the peer schema returned zero rows under forced RLS. The worker pool was then raised to five for publication, which opens independent progress transactions. The frontend was built from the candidate checkout and served on loopback. Both tenant sign-ins and authenticated inventory lists passed through the API's one-connection pool. Each list included its migrated host and excluded the other tenant's host. A host captured by the local SCCM fixture also rendered on its detail route for each tenant. This used local authentication and fixture data. The deployed managed-session and paired release checks remain open.

With targeted publication off, the canary enabled incremental inventory first. Its 110 host writes created inventory-trigger deltas without advancing the full evaluation revision. The peer used legacy revision scheduling and its existing CMDB deltas. Both tenants settled 110 applicable findings. After a worker restart with targeted publication enabled, a scoped advisory changed the applicability range. The canary used the committed route manifest and the peer used the legacy sweep. Both reconciled 100 component states on the first page and the final 10 on the next. A subsequent release paused after its first targeted page with one committed inventory delta still pending.

While the worker was stopped, incremental inventory was disabled for the canary. A new worker started with targeted publication off, cleared the targeted cursor and started a legacy scan. The next inventory write advanced the legacy revision without creating another incremental trigger job. The original delta completed on its first attempt, and both tenants returned to 110 applicable component states. The disposable feed watermark, in-progress GHSA checkpoint and committed record key matched their pre-switch values. The paired-browser checks passed again for both tenants after rollback.

## Performance follow-up

The saved PostgreSQL counters identify three separate paths. The figures below report cumulative statement execution time. Some publication counters include abandoned attempts. The measurements do not allocate the final restart's 23 minutes 7 seconds line by line.

| Path | What the evidence points to |
|---|---|
| Inventory normalization | 500,000 initial inventory-component inserts consumed 124.7 seconds on the database, including trigger work. Picking the next SCCM host consumed 33.5 seconds across 1,027 calls in the retained inventory run. Profile trigger cost and late-capture host selection first. The measured SCCM staging inserts consumed 8.4 seconds at full volume. |
| Finding freshness | 5,040 queue claims consumed 327.1 seconds and 5,001 lookups by `software_instances.inventory_component_id` consumed 180.3 seconds in the retained inventory run. The p95 finding clock should include collection and normalization as well as the queue wait. |
| Publication | Candidate keyset pages and per-record target and journal writes merit separate instrumentation during the release lock. Record the phase, rows, WAL and lock wait in a clean attempt. Early stale statistics and the superseded VEX delete inflated prior attempts. The remaining restart rebuilds the same reviewed release from the beginning. |

An isolated PostgreSQL probe copied 500,160 synthetic software-instance rows and 500,173 queue rows from the saved run, with RLS active under the restricted worker role. For 100 component IDs, an index on `inventory_component_id` changed a parallel scan to a bitmap index scan and the second execution fell from **22.214 ms to 0.089 ms**. With 1,000 ready work items in the copied queue, a partial index on `id` for pending rows removed the sort and the second 100-row claim fell from **0.487 ms to 0.073 ms**. The queue comparison covers a late-drain shape. A full fixture replay must measure other backlog sizes, additional index write cost, retries, and overlapping intake. Both indexes were trialed only on the disposable copies.

Publication timing sign-off stays open. If the measured lock or restart exceeds an agreed limit, qualify a sequence of smaller atomic releases on the same 400,000-CVE corpus. Record peak lock duration, pause/restart time, cross-generation reader correctness, and total time until the last generation is live, including BUILD and approval time.

## Acceptance and release status

The publication owner still needs to agree on the maximum release-lock hold, time to pause, full-attempt restart cost, and final-generation time if the catalog needs multiple atomic releases. Local load observations also need customer workload and environment assumptions for request rate, p95 route latency, storage retention, connection headroom and an AWS cost ceiling. JVM heap is one part of process memory, and local database and WAL samples do not represent RDS storage.

The Standard launch criteria remain a maximum 10-second correlation write transaction, p95 under five minutes to normalized inventory, and p95 under 15 minutes to updated findings. The proposed Standard AWS limits are a worker peak of 3.2 GiB and RDS used storage of 80 GiB, including agreed retention, staging, history, and WAL. Enforce these on the agreed customer shape. The local normalization p95 of 322 seconds exceeded the five-minute reference. The local delta p95 of 846 seconds used the queue timestamp as its starting point. The selected AWS shape still needs end-to-end freshness measurements under concurrent intake and UI traffic.

Open release gates include qualification on an authorized copy of the actual deployment, required PR CI, publication-timing agreement, customer workload and budget confirmation followed by AWS qualification, and explicit Ownership Release 2 clearance. ServiceNow batching, Static AI Grid, non-npm OSV, and scheduled NVD acquisition depend on agreed pilot scope.

## Reproduction

Start PostgreSQL 16 with `shared_preload_libraries=pg_stat_statements` on a disposable loopback port. Run from `prototype-app/backend` with the local Maven cache and Java 17.

```sh
mvn -Ppostgres-it verify \
  -Dit.test=FirstCustomerReadinessPostgresIntegrationTest,FirstCustomerInventoryPostgresIntegrationTest \
  -DfirstCustomerQualification=true \
  -Dpostgres.test.admin-url=jdbc:postgresql://127.0.0.1:55487/postgres \
  -Dpostgres.test.username=postgres
```

Both volume tests skip without explicit opt-in. The fresh fixture provisions its own named databases. After stopping its previous JVM, use `-DfirstCustomerResumeCatalog=true` with the catalog test alone to resume its existing disposable database before BUILD or retry its pending approved publication. The fixture validates the prior generation and staged checkpoint. `-DfirstCustomerRewriteBatches=true` enables the PgJDBC rewrite comparison for the inventory test.

Volume evidence is under `/tmp/sg-first-customer-volume.wOvykQ`. The earlier `cdce657d` Standard scorecard remains under `/tmp/sg-readiness-v79-governance/certification`. The supplemental local migrations, canary and paired-browser logs, and statement and trial-index measurements are under `/tmp/sg-first-customer-rehearsal.erKn8x`.
