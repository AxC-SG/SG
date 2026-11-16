# Ownership Release 2: qualification, enablement and runbooks

Scope: plan §16.5 exit ("ServiceNow directory, both cloud producers, BOM/CBOM, campaigns and tickets meet their
scorecards and rollback tests") and the Release 2 rows of the §18 scorecard. Release 2 is deployable but is not the
complete MVP (Release 3 adds Entra/Okta, AI Grid and the CVE workbench).

**How to read the status column.**

- **Automated** means a test in this repository exercises the gate and passed on the Release 2 branch stack.
- **Needs input** means the gate cannot be proven here and an external input or an environment is required.
- **Not built** means the capability is not in Release 2.

Automated results prove behaviour against mocks and a local PostgreSQL. They do not prove behaviour against a real
ServiceNow instance, AWS organization or customer data. Those need the inputs in §5.

## 1. Scorecard

| Gate | Evidence | Status |
|---|---|---|
| ServiceNow directory: paging, cursor advance, rate limit and Retry-After, permission denial | `ServiceNowDirectoryClientTest` (`MockRestServiceServer`) | Automated; real field shapes need R4 |
| Directory: linking rules, ambiguity review, non-destructive linking | `DirectoryLinkingPostgresIntegrationTest`, `OwnershipIdentitySourcePostgresIntegrationTest` | Automated |
| Directory: partial scan never deactivates, complete scan only for its own people, anomaly pause | `DirectorySyncPostgresIntegrationTest` | Automated |
| Group-to-team mapping and mapping-driven CMDB resolution | `OwnershipGroupMappingPostgresIntegrationTest` | Automated |
| Directory preview is audited and never cached | `OwnershipIdentitySourcePostgresIntegrationTest`, `IdentitySourceControllerTest` | Automated |
| AWS and GCP producers: create, re-observe, change, end, unmapped values, partial scope, anomaly pause per class, paused until CLOUD_BOM is canonical | `CloudOwnershipProducerPostgresIntegrationTest`, `CloudOwnershipProducerTest` | Automated; real tag values need R5 |
| AWS Organizations account owner | `AwsOrganizationsClientTest` | Automated (mocks); real organization needs R7 |
| Occurrence registration, retirement, parent edges, depth guard | `OccurrenceRegistrationPostgresIntegrationTest` | Automated; key normalization against real writers needs R2 |
| Finding adapters: dark report, switch idempotency, asset mismatch keeps v1, CRYPTO selection, never writes in DARK | `FindingSubjectAdapterPostgresIntegrationTest` | Automated |
| CLOUD_BOM switch: gates, evidence, go-decision hash, re-resolution of cloud claims, closed rollback window | `CloudBomCutoverPostgresIntegrationTest` | Automated |
| CORE switch (Release 1) still holds | `OwnershipCutoverPostgresIntegrationTest` | Automated |
| BOM and CBOM owner filters, per-occurrence assignment that never touches siblings | `CloudBomCutoverPostgresIntegrationTest` | Automated |
| Campaign membership: materialization, idempotency, create bound, reconciler, never removes, closed campaigns skipped | `CampaignLedgerPostgresIntegrationTest` | Automated; batch sizes at scale need R6 |
| Campaign owner-at-add is live, immutable and authority-gated; one writer | `CampaignLedgerPostgresIntegrationTest`, `CampaignLedgerWriterControlTest` | Automated |
| Outcome rules (Java and SQL agree for every status and closed reason) | `CampaignOutcomeClassifierTest`, `CampaignLedgerPostgresIntegrationTest` | Automated |
| Recipients: TEAM channel, encrypted CUSTOM recipients, role check and audit | `CampaignLedgerPostgresIntegrationTest` | Automated |
| Campaign and ticket endpoints authorized by role | `CampaignAuthorizationPostgresIntegrationTest`, `TicketAuthorizationPostgresIntegrationTest`, `OwnershipAuthorizationPostgresIntegrationTest` | Automated |
| Ticket routing: every row of the routing table, mixed-team batches, override audit, preview hash, legacy path, attempts on every path | `TicketRoutingPostgresIntegrationTest` | Automated |
| ServiceNow and Jira carry the routed group and never the legacy default on the routed path | `ServiceNowRoutedGroupTest`, `JiraTicketingProviderTest` | Automated |
| Ownership changes never move a ticket | `TicketRoutingPostgresIntegrationTest` (source check on the sync service) | Automated |
| CBOM campaigns, queue, SLA, portfolio and ticket note by owner team | `CbomOwnerTeamsPostgresIntegrationTest` | Automated |
| Consumer rollback: empty campaign and ticket waves restore legacy rendering and routing | `ReadWaveRollbackPostgresIntegrationTest` | Automated |
| Finding delete guard and tenant purge | `FindingDeleteGuardPostgresIntegrationTest` | Automated |
| Schema: V24 to V26 upgrade equals a fresh schema | `OwnershipReleaseTwoSchemaUpgradePostgresIntegrationTest`, `TenantSchemaParityPostgresIntegrationTest`, `MigrationCatalogTest` | Automated |
| Tenant isolation and RLS for new tables | existing tenant-isolation ITs; `OwnershipTenantStampPostgresIntegrationTest` | Automated |
| Campaign and ticket screens | vitest page and component tests (`features/campaigns`, `features/findings`, `CampaignsPage`) | Automated; no browser or visual run (see §5) |
| Performance at expected size and 3x | `backend/scripts/perf/ownership/run_benchmark.sh` against a disposable database | Needs input (R1) |
| Accessibility, keyboard and visual checks of the new workflows | none run | Needs input (§5) |
| Deployed KMS authentication and key wrapper | none (no KMS wrapper exists yet) | Needs input (§5) |
| Dashboards, alerts and runbooks verified | runbooks in §4; no dashboards or alerts exist | Needs input (§5) |
| Entra and Okta, AI Grid, CVE workbench, legacy removal | not Release 2 | Not built |

## 2. Enablement order

Everything is off or dark by default. Turn capabilities on in this order, per tenant, and run the qualification report
before each go decision (`GET /api/ownership/authority/{domain}/qualification`, then `POST /api/ownership/authority/{domain}`
with its `reportHash`).

1. **Tenant keys.** A production key wrapper must be configured (`APP_TENANT_KEY_WRAPPER`; the `local` wrapper is refused
   outside local/test). Every encrypted write needs it: directory data, team notification addresses, CUSTOM campaign
   recipients and the ticket routing hash.
2. **Directory.** Set `app.ownership.servicenow.directory-enabled=true`. In Ownership › Sources: configure the source,
   test it, preview (admin only, audited), then enable. The first complete run is the baseline load. Map groups to teams
   in Mappings before relying on mapping-driven resolution.
3. **CORE.** Move CORE LEGACY → DARK; the maintenance job links assets and findings; qualify; go. Set
   `app.ownership.read-waves.inventory` and `.findings` for the tenant.
4. **Cloud producers.** Set `app.ownership.cloud.producer-enabled=true` and the per-provider settings in Sources. Claims are
   written but own nothing until CLOUD_BOM is canonical.
5. **CLOUD_BOM.** LEGACY → DARK starts occurrence registration and the finding-adapter dark report. Qualify (CORE canonical,
   no unregistered occurrence, no adapter owner change; read the `evidence.*` lines) and go. The go decision re-queues
   every subject holding a cloud claim; the maintenance job then moves findings to their occurrences.
6. **Campaigns and tickets.** Set `app.ownership.read-waves.campaigns` and `.tickets`. Before that, set each team's
   `ticket_assignment_group` and notification address, and a default assignment group on the ServiceNow or Jira connector.
7. **Reconciler.** Always on worker nodes (`app.campaigns.reconciler.cron`, default every 15 minutes). Set the cron to `-`
   to stop it.

## 3. Rollback

| What | How | What is kept |
|---|---|---|
| Campaign display | Empty `app.ownership.read-waves.campaigns` | Members, snapshots, exceptions, notifications |
| Ticket routing | Empty `app.ownership.read-waves.tickets` | Attempts, tickets, owner snapshots |
| Inventory or findings display | Empty the matching read wave | All ownership data |
| A domain before its first canonical mutation | DARK → LEGACY (`POST /api/ownership/authority/{domain}`) | Dark data |
| A domain after CANONICAL | Not reversible through the API. Pause the sources, empty the read waves, then forward-fix | All ownership data |
| Directory source | Pause or disable the source; the `SERVICENOW` kill switch (`platform.ownership_kill_switches`, global or for one tenant) holds every sync | Imported people and groups |
| Cloud producers | Pause the provider in Sources, or switch an input off (ends only that input's claims) | Other claims |
| Campaign reconciler | Cron `-` | Membership is never removed by the reconciler |

Ownership changes never close, reopen or reassign a ticket, and never change its provider.

## 4. Runbooks

Each is symptom, check, action.

- **Directory credentials invalid or expired.** The source shows a failed test or failed runs. Re-enter the secret on the
  source (changing the URL, auth type or username needs the secret again, and a changed URL or filter returns the source
  to DISABLED), test, then resume.
- **ServiceNow throttling or pagination failure.** Runs end FAILED and the cursor advances only per committed page, so the
  next due run resumes. Check the run in Imports; a failed run changes no status. Pause the source if the instance needs
  relief.
- **Mass-deactivation anomaly.** A table that trips the anomaly rule writes nothing and pauses the source. Review the
  change, then Resume, which is the approval. Do not resume to "clear" an error you have not read.
- **Cloud ownership anomaly.** A `PRODUCER_ANOMALY` review item and a paused provider (the kill switch stops both claim
  classes). Review the item, fix the tags or mappings, then resume; the next run skips the gate once.
- **Resolver backlog.** The qualification check `queuedResolutions` and the maintenance job (every minute) show queue
  depth. A persistent backlog with errors in the maintenance log means poison work: find the subject in the log, fix its
  claim or team, and let the next pass retry.
- **Tenant key unavailable.** Directory writes, team and recipient addresses and `POST /api/tickets/preview` return 503
  while the key is not ready. Restore the key; nothing is lost. Tickets on the legacy route (read wave empty) do not need
  it.
- **Campaign not reconciling.** `GET /api/campaigns/{id}/reconciliation` shows `lastError` and
  `consecutiveFailures`; the third failure records `RECONCILE_FAILED` and increments `campaign.reconciliation.failures`.
  Fix the cause (usually a database or data error); the next run resumes from the stored watermark.
- **Campaign stuck MATERIALIZING.** The reconciler adds up to 1,000 members per campaign per run. Check the reconciliation
  endpoint; launch notifications go out when it completes.
- **Tickets going to the wrong group.** Compare `ticket-attempts` (owner team, group, routing source) with the team's
  `ticket_assignment_group` and the connector default. Fix the mapping; the next preview recomputes and a stale hash
  returns 409. Use an override with a reason for one-off cases.
- **Unexpected Unowned or Pending Migration.** Pending Migration means the domain or read wave is not canonical, not that
  nothing owns the item. Unowned means no eligible claim: check the subject's explanation
  (`GET /api/ownership/subjects/{type}/{id}`) and the unmapped-value review items.
- **Forward fix after a failed cutover.** After CANONICAL there is no automatic rollback. Pause the sources, empty the read
  waves, correct the data or mapping, and re-resolve (a team change or source resume queues the affected subjects).

## 5. Before release: what only you can do

These are not code. Each blocks enabling the named capability outside test tenants.

1. **A real ServiceNow instance (R4).** Read-only account with the `sys_user*` fields, custom `u_` fields and ACLs. Run the
   directory contract tests and a preview against it.
2. **A production tenant-key wrapper.** None exists yet (the KMS spike is open). Without it every encrypted write fails
   closed, and so does canonical ticket routing.
3. **A benchmark environment (R1)** sized for the expected occurrence counts, then the effective-owner benchmark and query
   plans. The owner filters, the 5,000/1,000 campaign bounds (R6) and occurrence registration depend on it.
4. **Real data samples:** package-key writers (R2), CBOM fingerprint stability (R3), cloud tag values (R5) and an AWS
   organization (R7). A customer Jira (R8) is a Release 3 input.
5. **A browser, accessibility and visual pass** of the new screens (`npm run build`, the pinned Playwright run, axe). The
   unit tests do not cover layout, keyboard or screen-reader behaviour.
6. **Operations.** Dashboards and alerts for the new metrics and queues, the kill-switch drill, and the on-call owner for
   each runbook above.
7. **A decision on the legacy columns.** `owner_group`, `support_group`, `ownership_rules` and the legacy ticket and campaign
   paths still exist because Release 3 screens and the AI Grid ownership step read them. Remove them only with Release 3.
8. **Merge the stack.** The Release 2 work is a stack of local branches (E1 to E17, plus the E4 fix). It needs review and a
   merge in order, with the migration integrity and tenant DDL CI checks (both pass locally).
