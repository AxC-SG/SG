# Ownership Phase 0B: Release 2 contracts

Status: §1–§4 approved November 14, 2026; §5 and §6 are working documents
Plan: [ownership-capability-mvp-plan.md](ownership-capability-mvp-plan.md) §16.3 (rolling contracts) and §16.5 (Release 2)
Built so far: [ownership-phase-0a-design.md](ownership-phase-0a-design.md) §8–§11

The plan requires four contracts before Release 2 begins. Each section states what is fixed, which existing schema and
code it builds on, and what stays **OPEN** until representative data or a person closes it. Open items are enforced in
code as disabled-by-default switches, as in Release 1.

| # | Contract | Section | Status |
|---|---|---|---|
| 1 | ServiceNow directory table/scope/identity-link | §1 | Approved (November 14, 2026) |
| 2 | AWS/GCP producer fields, TTL and authority | §2 | Approved (November 14, 2026) |
| 3 | BOM/CBOM occurrence identity and finding-adapter registry | §3 | Approved (November 14, 2026) |
| 4 | Campaign/ticket materialization, outcomes and routing | §4 | Approved (November 14, 2026) |
| 5 | Release 2 change ledger (plan §9.16) | §5 | Draft |
| 6 | Release 2 kickoff: requests, estimate and named leads (plan §16.1, §16.5) | §6 | Draft |

## 1. ServiceNow directory contract

Scope: plan §6.4 steps 1–5 and 7–10 for people, groups and memberships. CMDB ownership claims (step 6) already ship in
Release 1 (`ServiceNowOwnershipProducer`); this contract adds the directory side and the group-to-team mapping that
lets CMDB `support_group` values resolve by provider identity, not only by team name.

### 1.1 Source registration

- One `identity_source` row per ServiceNow instance, `kind = 'SERVICENOW'`. Several instances per tenant are allowed;
  each is a separate source.
- **Dedicated integration account** (plan §6.4 step 1). It is not the CMDB connector's account: the directory needs
  `sys_user*` read access the CMDB account should not have, and pausing one must not pause the other.
- Credentials (basic username/password or bearer token, the same two modes as `ServiceNowCmdbConfigService`) are stored
  in `identity_source.credentials_enc` through `TenantDataCipher` (`enc:t1:` envelope), never through the
  environment-key `CredentialEncryptionService`. They are write-only: no API returns them.
- The instance URL must pass `OutboundHostPolicy.validate("servicenow", …)`: HTTPS, allow-listed host, public address.
  It is re-checked on every run, not only at save.
- `scope_config` holds the approved tables, encoded-query filters and field list (§1.2). `mapping_config` holds the
  attribute mapping (§1.3). Changing either is audited and invalidates the last preview.
- Schedule: `identity_source.schedule` as an ISO-8601 duration, validated by
  `OwnershipSourcePolicy.requireValidInterval` (15 minutes to 7 days). Default `PT24H`.
- Lifecycle: `DISABLED` (default) → `ENABLED` only after a successful connection test and a preview; `PAUSED` by an
  admin or by an anomaly; `ERROR` after repeated failures. The platform kill switch
  (`platform.ownership_kill_switches`, `source_kind = 'SERVICENOW'`) stops every ServiceNow source at once.
- Authorization: configure, test, preview, enable and sync-now need `CONFIGURE_IDENTITY_SOURCE` (`TENANT_ADMIN` only,
  plan §5). Pause needs `PAUSE_SOURCE`. Group-to-team mapping needs `MAP_GROUPS`.

### 1.2 Tables, fields and permissions

| Table | Fields read | Used for |
|---|---|---|
| `sys_user` | `sys_id`, `user_name`, `email`, `first_name`, `last_name`, `name`, `active`, `locked_out`, `employee_number`, `manager`, `department`, `sys_updated_on` | `external_identity` and `directory_user` |
| `sys_user_group` | `sys_id`, `name`, `active`, `manager`, `parent`, `sys_updated_on` | `external_group` and `directory_group` |
| `sys_user_grmember` | `sys_id`, `user`, `group`, `sys_updated_on` | `directory_group_member` |

- Requests use `sysparm_fields` with exactly these fields, `sysparm_exclude_reference_link=true` and
  `sysparm_display_value=false`, so references arrive as `sys_id` values and no other columns are fetched.
- Minimum permission: read ACLs on these three tables and fields. The connection test reads one row from each table
  and reports which are denied; it never needs write, admin or `user_admin` roles.
- Admin filters are ServiceNow encoded queries per table (for example `companyINsys_id1,sys_id2`). They are appended
  with `^` to the system clauses below and cannot remove them. Filters are validated for length (≤ 2,000 characters)
  and must not contain `ORDERBY`, `^NQ` or `sysparm_` fragments.
- **OPEN (Phase 0A carry-over):** confirm the field list and ACLs against a representative instance; some customers use
  `u_`-prefixed fields for department or employee number.

### 1.3 Mapping to the directory

All PII goes through `TenantDataCipher`. A write first calls the tenant-key readiness check and fails with 503 when it
fails, as in Release 1.

- **Users.** Each `sys_user` row is one `external_identity` (`source_id`, `external_id_enc`/`external_id_index` = the
  `sys_id`). `email` fills `email_enc`/`email_index`, `user_name` fills `username_enc`. `active = false` or
  `locked_out = true` gives `status = 'INACTIVE'`. Display name, email and employee number are also written to the
  linked `directory_user` (§1.4) through `DirectoryService`, the single writer. `manager` (a `sys_user` reference)
  sets `directory_user.manager_user_id` once the manager's identity is linked; until then it stays unset and is
  retried on the next run.
- **Groups.** Each `sys_user_group` row is one `external_group` with its `name` as `display_name`. A `directory_group`
  is created for it on first sight and linked through `external_group.group_id`; renames in ServiceNow update the
  display name of that directory group only. `parent` is recorded as evidence only: group nesting does not create
  ownership inheritance in MVP.
- **Memberships.** Each `sys_user_grmember` row becomes one `directory_group_member` (`source_id` = this source)
  between the linked directory group and the linked directory user. A membership whose user or group is not linked
  yet is retried on the next run and counted as `rows_rejected`, not dropped.
- Every run is one `identity_import_run` with `kind = 'PROVIDER_SYNC'` and its counts; rows carry `last_seen_run_id`.

**DECISIONS (approved by the product owner, November 14, 2026):**

- Display name, email, employee number and manager are written only to people whose `created_source_id` is this
  source. People created manually, by CSV or by another source keep their values; their link is still recorded. An
  active identity reactivates an inactive person of this source.
- "Retried on the next run" means the next run that reads the row. Within one run, people are synced before
  memberships, and managers that appear later in `sys_user` are resolved at the end of that table. A reference that is
  still unresolved, for example to an `AMBIGUOUS` identity an admin has not resolved yet, is retried when ServiceNow
  changes the row or by the next complete scan (at least weekly, or on demand). No column holds pending references.
- `parent` is not stored: no V21 column holds it, and nesting creates no inheritance in MVP.

### 1.4 Identity linking (non-destructive)

Linking decides which `directory_user` an external identity belongs to. It never merges, deletes or relinks people
automatically (plan §6.5 step 8 and the duplicate-people risk in §20).

1. An identity already `LINKED` stays linked to the same user. A later email change in ServiceNow updates the
   identity's email fields but does not move the link.
2. A new identity whose email blind index matches **exactly one** ACTIVE `directory_user` is linked to it.
3. A new identity that matches **more than one** user is `AMBIGUOUS`: no link, plus one deduplicated
   `AMBIGUOUS_IDENTITY` review item. An admin resolves it by choosing the user or "create a new person".
4. A new identity that matches **no** user creates a `directory_user` with `created_source_id` = this source and
   links to it.
5. If a linked identity's email starts to match a *different* user, nothing changes automatically; an
   `AMBIGUOUS_IDENTITY` review item reports the drift.
6. `user_name` and employee number are evidence only; they never drive a link, because customers reuse and change them.

**DECISIONS (approved by the product owner, November 14, 2026):**

- A new identity whose email matches no ACTIVE person but at least one INACTIVE person is `AMBIGUOUS` with a review item
  (reason `ONLY_INACTIVE_MATCH`), not a new person. Rule 2 links only when the single match is ACTIVE. Any other set of
  matches, including one active and one inactive person, counts as rule 3.
- A new identity that is inactive or locked out is recorded `UNLINKED`: no person is created or linked. Rules 2–4
  apply when a later observation finds it active.
- An admin resolves an `AMBIGUOUS` identity with `POST /api/directory/external-identities/{id}/resolve`, guarded by
  `WRITE_DIRECTORY` (`TENANT_ADMIN` only), because linking decides who a person is. "Create a new person" keeps the
  identity's email even though another person has it. Resolving closes the open review item.

An email that is not a valid address is treated as absent. Review details carry the identity, source, reason and up to
10 candidate person IDs, never names or emails.

Directory people never gain Scoutgrid login, tenant membership or roles from a link (plan §3).

### 1.5 Paging, watermark and complete scans

- **Keyset paging, not offset.** The CMDB sync pages with `sysparm_offset`, which can skip or repeat rows when
  records change mid-run. The directory sync orders by `sys_updated_on` then `sys_id` and asks for rows after the last
  `(sys_updated_on, sys_id)` pair:
  `sys_updated_on>=T^sys_updated_on>T^ORsys_id>ID^ORDERBYsys_updated_on^ORDERBYsys_id`, that is
  `updated ≥ T AND (updated > T OR sys_id > ID)`. (Corrected November 14, 2026: ServiceNow applies `^OR` before `^`, so
  the earlier text `sys_updated_on>T^ORsys_updated_on=T^sys_id>ID` meant `(updated > T OR updated = T) AND sys_id > ID`
  and would have skipped later rows with a smaller `sys_id`. The intent is unchanged.) Admin filters are ANDed in
  front with `^`.
  Page size is 500, with the CMDB sync's fallback ladder (250, 100, 25) on timeouts.
- **Incremental runs** start from `identity_source.sync_cursor`, a JSON object with one `(updatedOn, sysId)` pair per
  table. The cursor for a table advances only after the page that produced it has committed. Incremental runs create
  and update; they never deactivate (plan §6.4 step 10).
- **Complete scans** read every row in scope from the beginning. Only a complete scan that finishes without a page
  error marks absent identities `INACTIVE`, absent groups `INACTIVE` and absent memberships `REMOVED`. A failed or
  partial scan changes no status. A complete scan runs on enable, then at least once every 7 days, and on demand.
- **Deactivating people.** A `directory_user` is deactivated by the sync only when its `created_source_id` is this
  source and every identity linked to it is inactive. People created manually, by CSV or by another source are never deactivated
  by a ServiceNow run.
- Rate limits: `OutboundHttpClient` with the `servicenow` provider policy, bounded retries and `Retry-After`. A run that
  exhausts its retries ends `FAILED`, keeps its cursor at the last committed page and sets `health = 'DEGRADED'`; three
  consecutive failures set `state = 'ERROR'`.

**Implementation (November 14, 2026):** `ServiceNowDirectorySync` runs on the five-minute UTC connector schedule and
needs `app.ownership.servicenow.directory-enabled`. The `identity_import_run` row is the durable job: enabling queues a
complete scan, resuming queues a run, and `POST /api/ownership/identity-sources/{id}/sync` with `{complete}` (sync-now,
`CONFIGURE_IDENTITY_SOURCE`, blocked by the switch and the kill switch) queues one or upgrades the queued one. Otherwise
a run is due when the last one is older than the source's schedule. One run per source holds a per-source advisory
lock; a `RUNNING` run older than the maximum run duration (default 4 hours) plus 30 minutes is ended `FAILED`. The run's
`cursor_start` JSON records whether it is complete, whether it is the baseline and which tables it may skip the anomaly
check for; `cursor_end` records the tables' cursors and any tables held by an anomaly. Rows apply one transaction each;
a row the directory refuses counts as `rows_rejected`. A complete scan moves the stored cursor only forward, and
changing the instance URL clears it. A run stops `CANCELLED` when the source leaves `ENABLED` or the kill switch is set.

### 1.6 Preview and first load

- Preview fetches counts per table and up to 10 sample rows per table, writes nothing and returns a preview token
  bound to the source version, the actor and the scope hash, valid for 30 minutes, like the CSV preview.
- **DECISION (approved by the product owner, November 14, 2026): samples show full names and emails.** Preview needs
  `CONFIGURE_IDENTITY_SOURCE` (`TENANT_ADMIN` only), so only tenant admins see them. Every preview records an audit
  event with the actor, the source and the number of sample rows, but not the values. Sample values exist only in the
  response: they are not stored, logged or cached, and the response carries `Cache-Control: no-store`.
- Enabling a source requires a preview token from the current scope. The first complete run is the **baseline load**.

### 1.7 Anomaly pause

`OwnershipSourcePolicy.anomalous(changes, creates, active, baselineLoad)` is applied per table to the changes a run
proposes, counting creates, updates, deactivations and membership removals against that table's active rows for this
source. A run that trips it writes nothing for that table, raises a `PRODUCER_ANOMALY` review item and pauses the source
until an admin approves. The first baseline load is exempt only from the percentage-based create check (plan §12.3):
its creates still count toward the absolute 10,000, and it is never exempt from validation failures or tenant quotas.
(Corrected November 14, 2026: this paragraph said creates count only after the baseline, which would have raised the
plan's threshold.)

**DECISIONS (approved by the product owner, November 14, 2026):** approval is the existing resume
(`CONFIGURE_IDENTITY_SOURCE`). The next run skips the check for the held tables only, is a complete scan when the held
run was one, and closes their review items once applied. A failed run carries the approval to the run after it. The
count is a read-only pass before the writes. Manager changes are not counted.

### 1.8 Group-to-team mapping and CMDB resolution

- An external group maps to a team only through an explicit `external_group_team_mapping` row: `provenance = 'MANUAL'`
  or `'CSV'`, state `ACTIVE`. At most one active mapping per external group (existing unique index).
- When an external group's name exactly equals a team name or alias (the shared normalized namespace), the sync may
  write a `SUGGESTED` mapping in state `PROPOSED`. It never activates it; an admin confirms with `MAP_GROUPS`.
- Mapping changes show the affected subjects and findings before confirmation, record an audit event and republish
  the affected claims (plan §6.7 steps 7–8).
- CMDB resolution order for a `support_group` value, after this contract: (1) the referenced `sys_user_group` `sys_id`
  through an active mapping for a ServiceNow source on the same instance, then (2) exact team name or alias, as today.
  No fuzzy matching and no team creation.
- **DECISION (approved by the product owner, November 14, 2026): the CMDB sync is fixed in Phase B**, as described
  below, so (1) is available in Release 2. Background: with the default connector fields, `support_group` comes only from the installed-software table's
  dot-walked `installed_on.support_group`, read with `sysparm_display_value=all`, and `CmdbInventoryIngestionRunner`
  stores the display value (the group name). The reference `sys_id` is not kept. `CmdbInventoryIngestionRunner` falls
  back to the raw field when no display value is present, so an admin-customised field list could store a `sys_id`
  instead. The fix: the CMDB sync stores the name and the reference `sys_id` in separate columns (tenant V24), with
  tests for both field shapes.

**Implementation (November 14, 2026), before tenant V24 (E3):** `GroupTeamMappingService` is the single writer of
`external_group_team_mapping`; `GroupMappingResolver` is its read side. Until V24, step (1) applies when the stored
`support_group` value is itself a 32-hex `sys_id`, which happens only when an admin's field list leaves out the display
value. Names still resolve by step (2). E3 only has to pass the new column's value to the same resolver.

**Implementation (E3, November 15, 2026):** the CMDB sync stores the display name in `cis.support_group` and the
reference `sys_id`, lower case, in `cis.support_group_sys_id` (tenant V24). With `sysparm_display_value=all` the
`sys_id` comes from the field's `value`; with raw values it is the field itself when that is a `sys_id`; a display name
is never taken for one. The CI-table lookups in `CiResolutionService` keep it the same way. Step (1) passes
`support_group_sys_id` to `GroupMappingResolver`; step (2) uses the name only. A CI with a reference and no display name
still maps through step (1). The mapping preview counts CIs by `support_group_sys_id`. The 32-hex-name workaround is
removed. No index is added on `support_group_sys_id`; the preview scans `cis` until a query plan shows it needs one.

**DECISIONS (architect, November 14, 2026; review with the product owner):**

- "Same instance" compares the identity source's stored `instanceUrl` with the CMDB connector's `base_url`, both as
  `https://host` in lower case. If sources on the same instance map one group to different teams, step (1) yields
  nothing and step (2) applies.
- Confirming a suggestion inserts a new MANUAL row and retires the proposal, which keeps its history. A dismissed
  suggestion is not proposed again for the same team.
- Activating or retiring needs a preview token (30 minutes; bound to the group, the target team, the mapping it
  replaces and the admin; the same signed format as the identity-source preview). The preview counts the CMDB CIs whose
  `support_group` is the group's `sys_id`, their subjects (up to 20 IDs returned) and their open findings.
- After a change the affected CIs are republished at once (when `app.ownership.servicenow.producer-enabled`); the
  confirmed impact stands in for the anomaly gate. Above 10,000 CIs the change needs `confirmLarge` and is applied by
  the next CMDB sync, which re-evaluates every CI. Retiring a mapping ends no claim: as with any unmapped value, the last
  claim stays until the value maps, expires or is cleared.
- Reads need `VIEW_OWNERSHIP`; preview, activate, retire and dismiss need `MAP_GROUPS`. CSV mapping import is not built.

### 1.9 Schema and code impact

- **Directory: no migration is expected.** The CMDB support-group `sys_id` column (§1.8, decided) goes in tenant
  V24. Tenant V21 already has `identity_source` (`SERVICENOW` kind, encrypted credentials,
  `scope_config`, `mapping_config`, `sync_cursor`, `schedule`, state and health), `external_identity`,
  `external_group`, `directory_group_member` with `source_id`, `external_group_team_mapping` with `SUGGESTED`/`PROPOSED`
  and `identity_import_run` with `PROVIDER_SYNC`. Tenant V22 has the `AMBIGUOUS_IDENTITY` and `PRODUCER_ANOMALY` review
  types. Platform V16 has the `SERVICENOW` kill switch. If implementation finds a gap, it is tenant V24.
- New code (Phase B): an identity-source service (configure, test, preview, enable, pause), a ServiceNow directory
  client with keyset paging, a durable sync job on the existing worker schedule, linking rules in `DirectoryService`,
  and the hub's **Sources** and **Mappings** views.
- Tests (Phase B): `MockRestServiceServer` contract tests for paging, cursor advance, rate limits and permission
  denial; Postgres ITs for linking rules 1–6, complete-scan deactivation, partial-scan no-op, anomaly pause and the
  mapping-driven CMDB resolution; authorization matrix rows for every new endpoint.

### 1.10 Open items

| Item | Owner | Blocks |
|---|---|---|
| Representative `sys_user*` fields and ACLs (custom `u_` fields) | Connector lead + a customer instance | Enabling outside test tenants |
| ~~CMDB `support_group` reference `sys_id` retained by the CMDB sync~~ Decided: fixed in Phase B (§1.8) | Connector lead | — |
| ~~Masking rule for preview samples~~ Decided: full values for tenant admins, audited, never stored (§1.6) | — | — |

## 2. AWS/GCP producer contract

Scope: plan §6.8 (AWS and GCP rows), §6.9 priorities 3 and 5, §12.1 TTL and §15.3 (cloud producers switch with the
`CLOUD_BOM` domain in Release 2). Azure resource ownership stays deferred (plan §21.8).

### 2.1 Producer shape and registration

- Each cloud producer follows the Release 1 ServiceNow pattern: it runs after a successful discovery sync and reads
  the assets that sync just wrote. It never holds its own cloud credentials and never calls a cloud API, with one
  exception: GCP project labels (§2.2).
- One producer per provider per tenant (`source_kind = 'AWS'` or `'GCP'`). Claims carry `source_id = NULL`, as
  ServiceNow CMDB claims do. `identity_source` is for people and groups (its kind check excludes AWS and GCP), and the
  plan keeps ownership producers on a separate source type (§8.2).
- **Enablement has three gates.** All must be on before a claim is written:
  1. the deployment flag `app.ownership.cloud.producer-enabled` (default `false`, like the ServiceNow producer flag);
  2. the tenant's `CLOUD_BOM` domain has left `LEGACY` (`OwnershipAuthorityService.producersMayPublish`);
  3. no `PAUSED` kill switch for `AWS`/`GCP`, either for the platform or for the tenant.
- Pause and resume use the existing tenant-scoped kill-switch row and need `PAUSE_SOURCE` (`TENANT_ADMIN`,
  `INVENTORY_ADMIN`). Producer settings (§2.2) need `CONFIGURE_OWNERSHIP_PRODUCER` (same roles, plan §5). Both
  actions are already in `OwnershipAuthorization`.
- **Schedule and TTL input.** The producer uses its connector's `interval_minutes`, and enabling it requires that
  interval to pass `OwnershipSourcePolicy.requireValidInterval` (15 minutes to 7 days). Today the AWS connector accepts
  intervals down to 5 minutes, and neither connector has an upper bound. While a producer is enabled, saving a
  connector interval outside the range is rejected with 400.

### 2.2 Approved inputs

| Provider | Subject | Input | Priority class | How it is read |
|---|---|---|---|---|
| AWS | EC2 instance (`HOST` asset) | Resource tags `owner`, `team` | `CLOUD_TAG` (5) | `assets.cloud_tags_json`, already written by `AwsResourceIngestionService` from `DescribeInstances` |
| AWS | Account (`CLOUD_ACCOUNT` subject) | Account tags `owner`, `team` | `CLOUD_STRUCTURED` (3) | AWS Organizations `ListTagsForResource`, callable only from the management or a delegated-admin account. Built in Release 2 (§2.2.1) |
| GCP | Compute Engine VM (`HOST`) and other resources (`CLOUD_RESOURCE`) | Labels `owner`, `team` | `CLOUD_TAG` (5) | `assets.cloud_tags_json`, already written by `GcpResourceIngestionService` |
| GCP | Project (`CLOUD_ACCOUNT` subject) | Project labels `owner`, `team` | `CLOUD_STRUCTURED` (3) | Resource Manager `projects.get` during the discovery run; `resourcemanager.projects.get` is in `roles/browser`, already required, and `cloudresourcemanager.googleapis.com` is already allow-listed for `gcp` |

- **Keys.** Only `owner` and `team` are read. AWS tag keys are matched case-insensitively after trimming; GCP labels
  are lowercase by definition. Every other tag or label is ignored for ownership and stays inventory evidence only.
  If a resource carries both keys, each is its own claim. When they map to different teams, the resolver reports
  `CONFLICT`, as plan §6.9 requires.
- Admin settings (`CONFIGURE_OWNERSHIP_PRODUCER`) can switch off a key or the account-level input per provider.
  **DECISION (approved by the product owner, November 14, 2026): they are stored per tenant** in tenant V24 columns
  on `aws_discovery_configs` and `gcp_discovery_configs` (`ownership_owner_key_enabled`,
  `ownership_team_key_enabled`, `ownership_account_input_enabled`, all default `true`). Changing them is audited and
  re-resolves the affected subjects through the §2.6 enqueue. A per-tenant custom key list is **not** in MVP.
- Reading project labels adds one `projects.get` per configured project per run, through `OutboundHttpClient`
  (provider `gcp`). A failed call leaves that project's account claims untouched for the run (§2.5).

#### 2.2.1 AWS account tags (decided: built in Release 2)

**DECISION (approved by the product owner, November 14, 2026):** AWS account-level claims are built in Release 2,
not deferred.

- **Role.** A separate, optional `organizations_role_arn` and external ID on `aws_discovery_configs` (tenant V24).
  The role is in the management account or a delegated-admin account and grants only
  `organizations:ListTagsForResource` (and `organizations:DescribeAccount` for the connection test). It is assumed
  with the connector's existing STS path. It is never a target role, and it is never used for discovery.
- **Reads.** Once per run, after discovery commits, one `ListTagsForResource` per observed account ID, through
  `OutboundHttpClient` with the `aws` provider policy, bounded retries and `Retry-After`. A failed or denied read
  changes nothing for that account (§2.5).
- **Without the role** AWS resource tags still work, and account claims are not written. The Sources view says
  account tags are not configured.
- **Qualification.** Tests run against mocks (`MockRestServiceServer`: success, `AccessDenied`,
  `AWSOrganizationsNotInUseException`, throttling, timeout). Enabling the account input outside test tenants still
  needs a customer organization (§2.11).

- **Implementation (E6, November 15, 2026, branch `feat/e6-aws-organizations`, not merged).** `AwsOrganizationsClient`
  sends AWS JSON 1.1 requests signed with SigV4 (`AwsV4HttpSigner`) through `OutboundHttpClient` under a new `aws`
  provider entry in the outbound allowlist (`organizations.us-east-1.amazonaws.com`), so the calls get the provider's
  bounded retries and `Retry-After`. AWS returns throttling as HTTP 400, so the error type decides retries:
  throttling and service errors retry; `AccessDeniedException`, `AWSOrganizationsNotInUseException` and
  `AccountNotFoundException` are final. `AwsCredentialProvider.forOrganizations` assumes the role with the
  connector's base identity through the existing STS path. The role ARN and external ID are set at
  `/api/ownership/cloud-sources/aws/organizations-role` (`CONFIGURE_OWNERSHIP_PRODUCER`); the external ID is tenant
  ciphertext (`TenantDataCipher`, 503 when tenant encryption is not ready), never returned, and a new ARN needs it
  again. The test endpoint describes the connector's account (or a named one) with no transaction open. After each
  AWS run, `AwsAccountTagReader` reads the tags of every account a successful target observed, only while the
  producer is enabled, the account input is on and a role is set; a failed read passes no values. The Sources view
  sets and tests the role.

### 2.3 Subjects and topology

- **Resource subjects** come from `InventorySubjectAdapter.subjectForAsset`, unchanged: EC2 and GCE VMs are `HOST`,
  other GCP resources are `CLOUD_RESOURCE`.
- **Account subjects.** The producer registers one `CLOUD_ACCOUNT` subject per AWS account or GCP project it observes,
  with `source_object_id` `aws:<accountId>` or `gcp:<projectId>` (from `assets.cloud_account_id`). It never creates an
  asset for an account.
- **Parent edges.** Each resource subject gets an `OWNERSHIP_PARENT` edge to its account subject through
  `OwnershipSubjectService.setParent`, but only when the resource has no active parent or its current parent is a
  `CLOUD_ACCOUNT` the producer set (`created_by = 'cloud-producer'`). A parent set by an admin or by another adapter
  is never replaced. A conflicting parent raises an `INHERITANCE_ERROR` review item instead. If the asset moves to a
  different account, the producer moves the edge.
- Account → application edges are not created by this contract. An admin can set them manually.

### 2.4 Value mapping and claims

- A value maps only through `TeamNamespaceService.resolve`: exact normalized team name or alias, no fuzzy matching and
  no team creation (plan §6.7). Admins add aliases for expected tag values (source kind `AWS`/`GCP` is provenance
  only).
- **Unmapped values** become `UNMAPPED_VALUE` review items through the Release 1 path, with the value encrypted by
  `TenantDataCipher` and deduplicated by blind index. Cloud tag values often hold emails, so they are treated as PII.
  An existing claim from the same key stays until the value maps, is cleared or expires, so a typo cannot silently
  remove an owner.
- Values are never resolved through a person: an email tag does not look up a directory user's team. Person
  evidence (`principal_user_id`) stays unset for cloud claims in MVP.
- Values longer than 256 characters, or containing control characters, are rejected as unmapped and never stored in
  clear text.
- `source_ref`: `aws:asset:<assetId>:tag:<key>`, `gcp:asset:<assetId>:label:<key>`,
  `aws:account:<accountId>:tag:<key>` and `gcp:project:<projectId>:label:<key>`. Asset IDs keep refs inside the
  512-character column for long GCP resource names.
- Idempotency key: the existing `OwnershipClaimService.idempotencyKey` (tenant, source kind, subject, role,
  `source_ref`, observation version `<teamId>@<observedAtMillis>`). An unchanged value re-observes the claim
  (timestamps only), which keeps the assignment watermark unchanged.
- `producer_version`: `aws-ownership-1` and `gcp-ownership-1`.

### 2.5 TTL, completeness and ending claims

- `observed_at` is the run's commit time. `stale_after` and `expires_at` come from `OwnershipSourcePolicy` with the
  connector interval (§2.1): stale after `max(2 × interval, 24h)` and expired after `max(3 × interval, 72h)`, capped
  at 30 days. No stricter cloud-specific TTL is proposed.
- **Observed resource, key cleared.** If a resource is present in this run and the key is gone or empty, the claim
  ends through `OwnershipClaimService.endAbsent` (`REVOKED`, `ended_by = 'cloud-producer'`), as Release 1 does. The provider reported the resource, so this is an authoritative
  observation, not a deactivation from absence (plan §12.1).
- **Absent resources.** Claims of resources missing from the run end only inside scopes the run listed completely,
  using the same rule the connectors already use to mark assets inactive: AWS by (resource type, region) in
  `observedScopes`, GCP by resource type listed completely and non-empty. A failed region, type or target ends
  nothing. Those claims age to stale and then expire.
- **Account claims** end only when that account's tag or label read succeeded and the key was absent. A failed read
  re-observes nothing and ends nothing.
- A run that fails or is cancelled before commit writes no claims.

### 2.6 Authority and domain

Every cloud claim belongs to the `CLOUD_BOM` domain, whatever subject it targets. This matters because EC2 and GCE VMs
are `HOST` subjects in the `CORE` domain, which Release 1 can already have switched to `CANONICAL`. Without a rule, an
AWS tag claim would change a canonical host's owner before cloud ownership passes dark qualification.

- **Rule.** An `AWS` or `GCP` claim is eligible for resolution only while the tenant's `CLOUD_BOM` domain is
  `CANONICAL`. In `DARK` the producer writes claims, but the resolver treats them like claims from a paused source:
  they are evidence and appear in the dark comparison report, but they do not affect assignments.
- **Implementation.** `OwnershipResolutionService` loads claims with a `source_paused` flag. That flag also becomes
  true for `AWS`/`GCP` claims when `CLOUD_BOM` is not `CANONICAL`. `OwnershipResolver` stays pure and unchanged
  (`RESOLVER_VERSION` stays 1, because the eligible set and the watermark already change).
- **Switch.** At the `CLOUD_BOM` go decision (plan §15.3 step 5), every subject with an active `AWS`/`GCP` claim is
  enqueued on `ownership_resolution_queue` with reason `SOURCE_STATE_CHANGED`, in bounded batches. A kill-switch
  pause or resume does the same for that provider's subjects.
- **Dark comparison** reports, per tenant: hosts whose CORE owner would change, `CLOUD_RESOURCE` subjects that would
  go from `UNOWNED` to owned, new conflicts, and unmapped values by key.
- **AI Grid subjects** (`AI_SYSTEM`, `AI_ARTIFACT`) never receive cloud claims in Release 2. Plan §15.3 keeps them
  legacy until the Release 3 switch.

### 2.7 Precedence between account and resource values

Plan §6.8 says "account structured value above resource tag", and §6.9 ranks `CLOUD_STRUCTURED` (3) above `CLOUD_TAG`
(5). But §6.9 step 3 also says any eligible direct claim beats an inherited one. In this contract, account values sit
on the account subject and tags sit on the resource, so the two never compete on one subject: **a resource tag wins
over its account's owner**, and the account owner applies only to resources with no direct claim.

- **DECISION (approved by the product owner, November 14, 2026):** keep this reading; a resource's own tag wins. The
  alternative is to copy each account's value onto every
  resource in it as a direct `CLOUD_STRUCTURED` claim. That would honour §6.8 literally, but it would fan out one claim
  per resource on every account change. It would also make a manual assignment on the account lose to the copied
  claims on each resource, so an admin could not override a whole account.
- Within one subject the priorities apply as written. Example: a GCP project with both a `CLOUD_STRUCTURED` project
  label and a manual claim resolves to the manual claim.

### 2.8 Anomaly pause

- `OwnershipSourcePolicy.anomalous(changes, active)` is applied per provider and per priority class (`CLOUD_TAG` and
  `CLOUD_STRUCTURED` separately). `changes` counts changes and ends; `active` is that class's active claims. The
  plan counts creates only after the baseline.
- A tripped run writes nothing for that class, raises a `PRODUCER_ANOMALY` review item (dedupe key
  `PRODUCER_ANOMALY|<kind>|<class>`) and pauses the tenant's producer through the kill switch until an admin approves.
  It never fails the discovery sync. The first complete run per provider is the baseline, exempt only from the
  percentage-based create check (plan §12.3).
- One retag of an account's resources by a cloud team can trip the threshold. That is intended: the admin sees the
  impact before it takes effect.

### 2.9 Schema and code impact

- **Claims and subjects: no migration is expected.** Tenant V22 already allows `AWS`/`GCP` claims with `CLOUD_STRUCTURED`/`CLOUD_TAG`
  priority classes, `CLOUD_ACCOUNT` subjects, `OWNERSHIP_PARENT` edges, and the `UNMAPPED_VALUE`,
  `INHERITANCE_ERROR` and `PRODUCER_ANOMALY` review types. Tenant V21 allows `AWS`/`GCP` alias provenance. Platform
  V16 has `CLOUD_BOM` authority and `AWS`/`GCP` kill switches.
- **Tenant V24 additions (decided):** the per-tenant key and account toggles (§2.2) on `aws_discovery_configs` and
  `gcp_discovery_configs`, and the AWS Organizations role ARN and external ID (§2.2.1) on `aws_discovery_configs`.
- New code (Phase B): `CloudOwnershipProducer` (one class, provider strategy for AWS/GCP) called from
  `AwsDiscoverySyncService` and `GcpDiscoverySyncService` after commit, never failing the sync; scan-completeness
  output from both ingestion services; GCP `projects.get` label read; the `CLOUD_BOM` eligibility flag in
  `OwnershipResolutionService`; the switch-time re-resolution enqueue; connector interval validation; and the hub's
  Sources view rows for AWS/GCP.
- **Implementation (E5, November 15, 2026, branch `feat/e5-cloud-ownership-producer`, not merged).**
  `CloudOwnershipProducer` (one class, `Provider` AWS/GCP) is called by `AwsDiscoverySyncService` and
  `GcpDiscoverySyncService` after the run completes and never fails the sync. Each sync passes the scopes it listed
  completely, by the same rule it uses to mark assets inactive (AWS: account, `EC2`, a region that returned records;
  GCP: project and a type listed completely and non-empty). The GCP sync reads `projects.get` labels only while the
  producer is enabled; a failed read passes no values. AWS account tags are passed by E6. `CloudOwnershipSourceService`
  owns the settings, the tenant kill switch (`platform.ownership_kill_switches`, pause/resume with re-resolution
  enqueue), anomaly approval (resuming after an anomaly pause lets the next run skip the gate once) and the Sources
  status; `/api/ownership/cloud-sources` exposes them. Switching a key or the account input off ends that input's
  active claims through `OwnershipClaimService.endBySourceRef`, which queues the subjects. `OwnershipResolutionService`
  treats `AWS`/`GCP` claims as paused until `CLOUD_BOM` is `CANONICAL`. A tripped anomaly gate in either class writes
  nothing for the run, because the kill switch it sets stops both classes. The `CLOUD_BOM` switch, its re-resolution
  enqueue and the dark comparison report are E15. **Tenant V25** widens `assets.cloud_tags_json` from 255 characters to
  `text`: the V1 baseline size made an instance with a few tags fail to save. An R1 index-only fix therefore becomes V26.
- Tests (Phase B): unit tests for key matching and `source_ref`; Postgres ITs for create/re-observe/change/end,
  unmapped values, partial-scope no-op, the account edge rules, `DARK` ineligibility on a `CANONICAL` CORE host,
  switch re-resolution, anomaly pause per class, and the §2.7 precedence; a `MockRestServiceServer` contract test for
  `projects.get` (success, 403, timeout); authorization matrix rows for any new endpoint.

### 2.10 Observations from the code

- `AwsResourceIngestionService` and `GcpResourceIngestionService` write `cis` rows for VMs (`sys_id` = ARN or GCP
  resource name, `last_cmdb_sync_at` = now). `ServiceNowOwnershipProducer` scans `cis` by `last_cmdb_sync_at` with no
  source filter, so a cloud sync that runs during a CMDB sync window adds cloud CIs to the ServiceNow scan. Those rows
  have no `support_group`, so no claim is written today, but the scan counts and the anomaly denominator are wrong.
  The ServiceNow producer should read ServiceNow-originated CIs only. Fix with Phase B, with a regression test.
  **Fixed (E4, November 14, 2026, branch `fix/servicenow-producer-cis-source`, not merged):** `cis` has no source
  column, so the scan reads only rows whose `sys_id` has ServiceNow's 32-hex format. AWS/GCP/Azure (ARNs, resource
  names), SCCM (numeric `ResourceID`) and patch (`patch-device:…`) rows are excluded. Regression:
  `ServiceNowOwnershipProducerPostgresIntegrationTest.cloudSccmAndPatchCisSyncedInTheSameWindowAreNotScanned`.
- When a ServiceNow row arrives without a `sys_id`, `CiResolutionService` stores a fallback `servicenow:<host>`.
  Before E4 such a CI produced a claim whose `source_ref` split at the wrong `:`, so the next complete scan ended it.
  After E4 these CIs produce no claim. Rows without a `sys_id` are not expected from the Table API.

### 2.11 Open items

| Item | Owner | Blocks |
|---|---|---|
| AWS account owner: built in Release 2 against mocks (§2.2.1, decided). Still needed: a customer org to test the Organizations role against | Connector lead + a customer org | Enabling the AWS account input outside test tenants (AWS resource tags are unaffected) |
| Representative tag/label values: share of emails vs team names, and alias coverage after preview | Connector lead + a customer tenant | Enabling outside test tenants |
| ~~ServiceNow producer `cis` source filter (§2.10)~~ Fixed by E4, pending merge | Ownership lead | — |

## 3. BOM/CBOM occurrence identity and finding-adapter registry

Scope: plan §6.11 (finding adapters, vulnerability adapter v2), §6.12 (BOM component occurrences), §7.2 subject rules
and §15.3 (occurrences switch with the `CLOUD_BOM` domain in Release 2). AI-BOM models, datasets and knowledge
sources are AI artifacts in the `AI_GRID` domain and stay in Release 3.

### 3.1 What an occurrence is

An occurrence is one component inside one inventory context. It is never the tenant-wide software identity, PURL or
CPE (plan §6.11 rule 1, §6.12).

| Inventory row | Context | Occurrence key |
|---|---|---|
| `inventory_components` (SBOM upload, GitHub/GHCR SBOM, BOM orchestrator, CMDB/SCCM/SSM/VM Manager host inventory) | `assets.id` of the row's asset: `HOST`, `APPLICATION`, `CONTAINER_IMAGE` or `CLOUD_RESOURCE` | `ecosystem`, `package_name`, `version`, `purl` after the writers' existing normalization |
| `cbom_components` | `assets.id` when `asset_id` is set; otherwise the `bom_sources.id` of the source BOM | `component_fingerprint` |

Software identities, `bom_components` (document rows) and `software_instances` are never ownership subjects. They
remain evidence and aggregation keys.

### 3.2 Subject identity

- `subject_type = 'COMPONENT_OCCURRENCE'` for both families.
- `source_object_id`: `pkg:<sha256 hex of ecosystem|package_name|version|purl>` for software and
  `crypto:<component_fingerprint>` for CBOM. `context_key`: `asset:<assetId>` or `bom-source:<sourceId>`. Together
  with `generation`, this is the plan's "tenant, parent inventory context, immutable component identity and
  generation" (§7.2).
- **Why not row IDs.**
  - `inventory_components` rows are reused across uploads today: `SbomContentIngestionService` matches on asset plus
    this key, marks rows `RETIRED` and revives them. But no database constraint enforces the key, and
    `BomIngestionOrchestrator` matches on name and version instead. A semantic key gives two rows with the same key on
    one asset the same subject, instead of splitting ownership.
  - `cbom_components` rows are unique per `(source_bom_id, component_fingerprint)`, so every CBOM revision creates new
    rows. A row-ID subject would lose its direct claims on every upload.
- **Containers.** An occurrence under a `CONTAINER_IMAGE` asset is registered only when `assets.image_digest` is set.
  GHCR assets are already keyed `repository@digest`. A tag-only image asset gets no occurrence subject; its findings
  stay on the asset subject (plan §6.12: a mutable tag is not a stable ownership key).
- **Same object.** The same key on the same asset is treated as the same occurrence, including a component that is
  retired and later reappears, so its direct claims apply again. A different version is a different key and a new
  occurrence. That is intended: ownership of an upgraded package inherits from the asset unless reassigned.
- **Retirement.** An occurrence subject is retired only when its component has been `RETIRED` (software) or absent
  from its source's current BOM (CBOM) for 90 days, it has no active direct claim and no open finding references it.
  A later reappearance registers generation 2. Retirement runs in the ownership maintenance job in bounded batches.

### 3.3 Parent edges

- Each occurrence gets one `OWNERSHIP_PARENT` edge to its context asset's subject (from
  `InventorySubjectAdapter.subjectForAsset`), `created_by = 'bom-occurrence-adapter'`. A parent set by an admin is
  never replaced.
- A `bom-source:` CBOM occurrence has no parent edge. Without a direct claim it is `UNOWNED`, and the explanation says
  the CBOM names no asset.
- **Not in Release 2:** CBOM crypto → containing software component edges (no link between CBOM and SBOM rows
  exists today), and image → host edges. Inheritance therefore goes occurrence → asset → (cloud account, §2.3) →
  any admin-set parent. That is at most three hops from an occurrence to a cloud account, inside the six-hop limit.
- **Bulk registration.** `OwnershipSubjectService.setParent` takes the tenant advisory lock on every call, which is
  too slow for millions of occurrences. Phase B adds a set-based `registerOccurrences(limit)` to the same single
  writer. It inserts subjects and edges for unregistered rows and skips any whose asset subject already has five
  ancestors. Occurrences are leaves, so no cycle can form.

### 3.4 Registration and links

- Registration starts only once the tenant's `CLOUD_BOM` domain leaves `LEGACY`. Backfill runs in the ownership
  maintenance job in batches of at most 10,000, then ingestion keeps it current: each writer of `inventory_components`
  and `cbom_components` registers occurrences for the rows it touched, after commit, without failing the ingest.
- Link columns: `inventory_components.ownership_subject_id` and `cbom_components.ownership_subject_id` (tenant V24,
  §3.8), as V23 did for `assets` and `findings`. BOM lists join owner state through them, never through
  `source_object_id`.
- Direct claims on occurrences come only from manual assignment in Release 2, and only once `CLOUD_BOM` is
  `CANONICAL` (`requireCanonicalWrites`). No producer targets occurrences.

**Implementation (E7, November 16, 2026, branch `feat/e7-occurrence-key`, not merged).**

- **R2 check (code review of every `inventory_components` writer; the sample confirmation stays with R2).** The writers
  do **not** normalize the key fields the same way. `SbomContentIngestionService` (direct uploads, GitHub/GHCR SBOMs
  and `BomIngestionOrchestrator`, which delegates to it) lower-cases `ecosystem` and `package_name` and stores
  `version` and `purl` as parsed. `CmdbHostInventorySupportService` (ServiceNow CMDB, SCCM, AWS SSM and GCP VM Manager
  host inventory) stores the normalized publisher in `ecosystem` and the normalized product in `package_name`.
  `CustomerDemoDatasetService` inserts seed values as given. So the R2 assumption does not hold as stated.
- **Consequence handled in E7.** `OccurrenceKey` normalizes for itself (ecosystem, package name and PURL trimmed and
  lower-cased; version trimmed; missing values empty), in Java and in an identical SQL expression, so case and spacing
  differences between writers do not split an occurrence. **Residual:** an SBOM row (`ecosystem = npm`) and a host
  inventory row (`ecosystem = <publisher>`) for the same software on the same host remain two occurrences, because the
  writers mean different things by `ecosystem`. Both inherit the host's owner, so ownership is unchanged unless an admin
  assigns one of them directly. Occurrence registration stays limited to test tenants until R2's samples confirm this
  is acceptable or the host writers adopt the SBOM ecosystem.
- `OwnershipSubjectService.registerOccurrences(limit)` is the set-based registration: it inserts subjects, links
  `inventory_components.ownership_subject_id`, adds parent edges (`created_by = 'bom-occurrence-adapter'`) where the
  occurrence has none and the asset subject has at most four ancestors, and records one `OCCURRENCES_REGISTERED`
  event per batch. Only `ACTIVE` rows register; a revived row links to its live subject again.
- **Registration runs in the ownership maintenance job only** (batches of at most 10,000, once `CLOUD_BOM` leaves
  `LEGACY`; asset subjects are linked first by `InventorySubjectAdapter.linkAssets`). Writers do not register after
  commit: an after-commit hook inside the ingest transactions would need a nested transaction, which the
  context-before-transaction rule forbids. New rows therefore get their subject within one maintenance cycle (one
  minute by default).

### 3.5 Finding-adapter registry

One registry, in code, maps each finding kind to one adapter version and its domain. The adapter selects the finding's
canonical subject and writes it to `findings.ownership_subject_id`. Nothing else writes that column.

| Finding kind | Adapter | Domain | Selects | Release |
|---|---|---|---|---|
| `VULNERABILITY` | v1 | `CORE` | Affected asset subject | Release 1 (shipped) |
| `VULNERABILITY` | v2 | `CORE` + `CLOUD_BOM` | Occurrence subject of `findings.component_id` when registered and active; otherwise v1 | Release 2 |
| `CRYPTO` | v1 | `CLOUD_BOM` | Occurrence subject of the CBOM finding's component (`cbom_risk_findings.cbom_component_id`) | Release 2 |
| `AI_POSTURE`, `AI_EXPOSURE` | — | `AI_GRID` | Not registered; legacy ownership | Release 3 |
| `AI_RUNTIME` | — | — | No adapter (out of scope, `AiRuntimeScope`) | — |

- **Result.** Each adapter returns `CANONICAL_SUBJECT(id)`, `OWNERSHIP_CONFLICT` or `UNOWNED`. In Release 2 every
  registered finding has exactly one primary subject (one asset and at most one component), so adapters never return
  `OWNERSHIP_CONFLICT`. Conflicts appear only from resolution of that subject. Plan §6.11 rules 3–4 (several primary
  occurrences) apply first to AI findings in Release 3, which will need a storage decision then.
- **Selection rules.**
  - v2 selects the occurrence only when the component's asset equals `findings.asset_id`. A mismatch keeps v1 and is
    counted in the dark report.
  - A `CRYPTO` finding whose component has no occurrence subject (a tag-only image context, or registration pending)
    is `UNOWNED` with reason `SUBJECT_PENDING`. It never falls back to a package or software identity.
  - A retired subject gives `UNOWNED` with a subject-removed explanation until the adapter selects a valid
    replacement (plan §6.11 rule 6).
- **Never in LEGACY/DARK.** An adapter never writes an occurrence subject while `CLOUD_BOM` is not `CANONICAL` (plan
  §6.11). In `DARK` it computes the selection for the comparison report only.
- Adapter selection is deterministic, so re-running it is idempotent. No adapter-version column is stored.

### 3.6 Vulnerability adapter v2 rollout

1. **Dark.** With `CLOUD_BOM` in `DARK`, occurrences are registered and v2 runs in compare-only mode. The report
   lists, per tenant: findings that would move to an occurrence, findings staying on the asset (with reason), and
   findings whose **effective owner team would change**.
2. **Expected result: no owner changes.** Before the switch no occurrence can have a direct claim (manual assignment
   needs `CANONICAL`, and no producer targets occurrences), and every occurrence inherits from the same asset subject
   v1 uses. A non-zero owner-change count means a registration or edge defect, and it blocks the switch.
3. **Switch.** At the `CLOUD_BOM` go decision (plan §15.3 step 5), with `CORE` already `CANONICAL`, findings move to
   v2 in bounded batches, keyed by finding ID, through an idempotent update guarded by the current value. One
   `ownership_event` is recorded per batch, not per finding. No finding is created, closed or duplicated.
4. **Rollback** before the go decision is a no-op, because nothing was written. After it, recovery is consumer rollback
   through the compatibility adapter (plan §15.3). Re-running v1 selection is also safe, because it is deterministic.
5. `CRYPTO` findings get their first canonical subject at the same switch. Before it they read
   `LEGACY_PENDING_MIGRATION`.

**Implementation (E8, November 16, 2026, branch `feat/e8-finding-adapter-registry`, not merged).**
`FindingSubjectAdapterRegistry` is the only writer of `findings.ownership_subject_id` (`OwnershipWriterControlTest`
checks SQL updates and JPA setters); `InventorySubjectAdapter` now links assets only. `select` is read-only,
`subjectForFinding` links on first use (VULNERABILITY v1 in DARK, v2 once `CLOUD_BOM` is CANONICAL; CRYPTO only once
CANONICAL), `linkBatch` is the CORE populate step, and `switchBatch` moves findings to their v2/CRYPTO target guarded
by the current value, with one `FINDING_SUBJECTS_SWITCHED` event per batch. The maintenance job runs `switchBatch`
every cycle, so it is the §3.6 switch at the go decision and afterwards keeps findings current when an occurrence is
registered or retires. A CRYPTO finding finds its CBOM component through `evidence ->> 'cbomComponentId'`, which
`CbomFindingMirrorService` writes. The dark report is `GET /api/ownership/finding-adapters/report`
(`MANAGE_AUTHORITY`); `passed` is false when any effective owner would change, and E15 adds it to the `CLOUD_BOM`
qualification gates. `OwnershipSubjectService.retireOccurrences` applies the §3.2 rule to software occurrences (90
days `RETIRED`, no active claim, no open finding, subject older than 90 days), retires the edge and unlinks the rows,
so a reappearance registers generation 2. `switchBatch` and the dark report scan `findings`; their plans belong in the
R1 benchmark.

### 3.7 Aggregates and reads

- Software identity and global package views show owner-team coverage across occurrences (`1 team`, `3 teams`,
  `Unowned occurrences`), counted by stable team ID. An aggregate with several teams displays `MULTIPLE_TEAMS`, which
  is presentation only and never stored (plan §6.12, §9.6).
- Owner filters on BOM and CBOM lists use `ownerTeamId` on occurrences, through the link columns and the effective
  view, under the same domain gate as Release 1 reads.
- Assign owner on an occurrence previews its affected findings and never applies to every occurrence of a package.

**Implementation (E9, November 16, 2026, branch `feat/e9-cbom-occurrences`, not merged).**
`OwnershipSubjectService.registerCbomOccurrences` registers `crypto:<component_fingerprint>` occurrences for rows of
each source's current revision (`status = 'ACTIVE'`, `superseded_by IS NULL`), in `asset:` context when the CBOM
names an asset (parent edge to it) and `bom-source:` context otherwise (no parent edge). It shares the linking code
with software occurrences, and later revisions with the same fingerprint link to the same subject. A tag-only image
asset gets none. Retirement covers CBOM occurrences that are absent from the current revision and were last seen in
a revision ingested more than 90 days ago. Reads: `OwnershipReadAdapter.forOccurrences` gives BOM (`/api/inventory/
components`) and CBOM component rows an `ownership` envelope, and `identityCoverage` gives the software identity
detail an `ownershipCoverage` (distinct owning team IDs, owned/unowned/conflict occurrences, never stored). Both are
null, with no ownership query, unless `app.ownership.read-waves.inventory` includes the tenant and `CLOUD_BOM` is
CANONICAL. The BOM components table, the CBOM component tables and the software identity page show an Owner column
or "Owner teams" row only then. Owner filters on BOM/CBOM lists and the assign-owner action with finding preview on an
occurrence (§3.7) are not built yet; they follow with the E15 read-wave work. R3 (CBOM fingerprint stability) still
gates CBOM occurrences outside test tenants.

**Implementation (E13, November 16, 2026, branch `feat/e13-cbom-owner-teams`, not merged).**

- **PQC progress** (`GET /api/bom/cbom/pqc/progress`) reads `CampaignLedger.progressByCampaign`, so it uses the same §4.8
  outcome rules and §4.5 owner buckets as campaigns. `open`/`resolved` become `active` (OPEN + REOPENED) and
  `remediated` (REMEDIATED only; accepted risk, suppressed and retired-asset closes no longer count), and each wave also
  returns `outcomes`. `owners` is a list of buckets (team ID and name, Unowned, Conflict, Pending Migration) instead of
  `coalesce(assigned_to, owner_group)`. The campaigns read wave is still off by default, so owners show as one Pending
  Migration bucket until E15 enables it; nothing falls back to a free-text owner.
- **Remediation queue and SLA** (`GET /api/bom/cbom/remediation/queue`). Each item carries the owner envelope from the
  findings read wave (`ownership`, replacing `ownerGroup`) beside the workflow `assignedTo`. SLA rows split
  `unassigned` (no workflow assignee) from `unowned` (no owner team, Conflict included). `unowned` is null while CLOUD_BOM
  findings are not canonical, because legacy labels cannot be counted as owners.
- **Ticket note** (`CryptoRemediationService.template`). The "ScoutGrid owner" line is now "ScoutGrid assignee" and "ScoutGrid
  owner team". The team is read live under the tickets read wave (Unowned or Ownership conflict when not owned) and is
  the legacy `owner_group` label only while the wave is off. `GET /api/findings/{id}/ticket-attempts` already returns the
  E11 routing fields.
- **Portfolio** (`GET /api/bom/cbom/portfolio?groupBy=ownerTeam`). Groups by the asset's current owner team ID through the
  effective view, adds `teamId` and `ownerBucket` (TEAM, UNOWNED, CONFLICT, PENDING_MIGRATION), and relabels a renamed
  team without splitting it. An asset whose type's domain is not canonical for inventory reads keeps its legacy
  `assets.owner_team` label as a PENDING_MIGRATION group. The `supportGroup` grouping is unchanged and offered in the UI
  as "CMDB support group (evidence, not ownership)".
- **Frontend.** The three CBOM rows of the §5.2 ledger are done here, so E14 does not revisit them:
  `CryptoRemediationPanel` (assignee and owner team in separate columns, an Unowned SLA column), `CbomPortfolioPanel`
  (owner buckets, remediated progress, pending-migration labelling) and `features/cbom/types.ts`. Shared helpers
  `ownerBucketLabel` and `campaignOwnerLabel` live in `features/campaigns/ownership.ts`.
- **Tests.** `CbomOwnerTeamsPostgresIntegrationTest` covers each read with CLOUD_BOM canonical and dark, including
  progress that counts only remediated findings, owner buckets by team ID, queue and SLA owners, a team rename and the
  legacy portfolio rows. The PQC and crypto remediation controller ITs and the three CBOM panel tests are updated.

### 3.8 Schema and code impact

- **Tenant V24 is needed.** It adds nullable `ownership_subject_id` columns, each with a tenant-inclusive foreign key
  to `ownership_subject` and a partial index, on `inventory_components` and `cbom_components`. The same V24 carries
  the §1.8 CMDB support-group `sys_id` column, the §2.9 producer settings and the §4.11 campaign and ticket changes. `MigrationCatalogTest` and `TenantSchemaCompatibility`
  move to V24.
- Everything else already exists: `COMPONENT_OCCURRENCE` and `context_key` on `ownership_subject` (V22), the
  `CLOUD_BOM` domain, `findings.ownership_subject_id` (V23) and the `CRYPTO` finding kind (V10).
- New code (Phase B): an occurrence-key helper shared by every `inventory_components` writer;
  `OwnershipSubjectService.registerOccurrences`; a `FindingSubjectAdapterRegistry` replacing the VULNERABILITY-only
  branch in `InventorySubjectAdapter.subjectForFinding`; the dark v2 comparison report; the switch batch; occurrence
  retirement in `OwnershipMaintenanceJob`; and owner columns on BOM, CBOM and software identity screens.
- Tests (Phase B):
  - unit tests for the occurrence key (normalization, digest gating) and for adapter selection;
  - Postgres ITs for: the same key on one asset across two rows and across CBOM revisions; retire and revive;
    90-day retirement; parent edges and the depth guard; `bom-source` occurrences unowned; v2 dark report with zero
    owner changes; switch idempotency; asset mismatch keeps v1; CRYPTO subject selection; never writing in
    `DARK`;
  - a writer-control test that only the registry writes `findings.ownership_subject_id`.

### 3.9 Open items

| Item | Owner | Blocks |
|---|---|---|
| Full-size effective-owner benchmark with 5M/15M occurrences (Release 1 open item; occurrences now exist for real). V24 assumes the §3.8 index design; a wrong design is fixed by an index-only V25 (§6, November 15, 2026) | Ownership lead | Enabling occurrence registration outside test tenants |
| Do all `inventory_components` writers normalize `ecosystem`, `package_name`, `version` and `purl` the same way? Confirm against SBOM, BOM orchestrator and CMDB host inventory samples. V24 assumes yes; E7 checks it (§6, November 15, 2026) | Inventory lead | Occurrence key sign-off; enabling occurrence registration outside test tenants |
| Is `component_fingerprint` stable across CBOM re-exports of an unchanged crypto asset? | CBOM lead | CBOM occurrence identity sign-off |
| ~~CBOM crypto → containing software component edges~~ Decided November 14, 2026: not in Release 2; crypto inherits from the asset (§3.3) | — | — |

## 4. Campaign/ticket materialization, outcomes and routing

Scope: plan §6.13, §6.14 (campaign and ticket behaviour), §7.4, §8.7, §9.11, §9.13, the campaign rows of §12.4 and
§16.5 (campaign materialization, outcome classifier, ticket mapping, preview and mixed-team routing, and the
campaign/ticket read waves). The CVE investigation workbench (§6.15, §9.12: lead principal, coordinating team,
ownership coverage card, notification export) stays in Release 3. This contract only fixes the backend routing and
campaign launch that the workbench will call.

### 4.1 What exists today

| Area | Current behaviour | Gap against the plan |
|---|---|---|
| CVE campaigns (`POST /api/campaigns`) | `CampaignService.createInCurrentTenantSchema` stores `campaign_vulnerabilities` only. Every read (`toSummary`, `toFindingRows`, `toAssetRows`, `toEvidenceRows`) runs `loadFindingsForCampaign`, which loads **every** tenant finding for those CVEs at read time | Membership is a dynamic query, not a ledger (§6.13, §9.11) |
| Finding campaigns (`POST /api/campaigns/from-findings` → `CryptoRemediationService.createCampaign` → `createFromFindings`) | Inserts into `campaign_findings` (tenant V17), capped at `MAX_CAMPAIGN_FINDINGS = 500`, `ON CONFLICT DO NOTHING` | No ownership snapshot; summary and detail ignore these rows (§4.12) |
| `campaign_findings` | PK `(campaign_id, finding_id)`, `added_by`, `added_at`; `finding_id` references `findings(id)` with `ON DELETE CASCADE` | No owner-at-add columns, FK is not tenant-inclusive |
| Progress | `isResolvedFinding` counts `RESOLVED`, `SUPPRESSED` and `AUTO_CLOSED` as resolved | Suppressed and accepted-risk findings count as remediated (§6.13) |
| Owner display | Finding rows return `findings.owner_group`; asset rows return `assets.support_group` | Free text used as ownership (§9.11) |
| Exceptions | `campaign_exceptions` keyed by free-text `finding_display_id`, `asset_name`, `package_name`; never mutates the finding | No stable `finding_id`, no owner snapshot |
| Notify groups | `campaign_notify_groups.group_name`/`group_email` free text, plaintext email | No `team_id`, no recipient type (§7.4) |
| Ticket routing | Single-finding ServiceNow tickets take `findings.owner_group` (`ServiceNowIncidentService.createFindingIncidentRemote`) and ignore the request's `assignmentGroup`. `TicketingService.createTicketsForCve` groups by the caller-supplied `TicketAsset.assignmentGroup` (the CMDB support group from the browser), then by package. Both fall back to the hard-coded `App-Sec Manager`. Jira renders the group as text in the summary and description | Raw CMDB group copied into tickets, implicit default, no conflict handling (§9.13) |
| Ticket attempts | `finding_ticket_attempts` (V17) is written by `CryptoRemediationService.createTicket`, which `FindingTicketController` uses for single-finding tickets. CVE tickets and AI Grid tickets write no attempt | No routing audit |
| Ticket sync | `FindingIncidentSyncService` pushes finding status to the ticket and resolves the finding when the ticket resolves. It never reads ownership | Already correct for "ownership changes do not close tickets" |
| Read waves | `OwnershipReadAdapter.Consumer` has `CAMPAIGNS` and `TICKETS`, but only `read-waves.inventory` and `read-waves.findings` are wired | Campaign and ticket consumers cannot be switched on |

### 4.2 Membership ledger

`campaign_findings` becomes the only source of membership for every campaign. `campaign_vulnerabilities` stays as the
CVE scope definition. No read path calls `loadFindingsForCampaign` after this contract.

- **Scope kind.** `campaigns.scope_kind` is `CVE` (created from CVE IDs) or `FINDINGS` (created from finding IDs). A
  `FINDINGS` campaign never gains members automatically.
- **Create, CVE scope.** One set-based `INSERT … SELECT` in the create transaction adds every finding whose
  vulnerability is in scope and whose status is `OPEN`. Suppressed, accepted-risk and false-positive findings are
  added only when the request sets `includeExcepted = true` (§6.14). Findings already `RESOLVED` or `AUTO_CLOSED` are
  not added: a new campaign does not start with remediation it did not drive.
- **Create, finding scope.** As today, with stable `findingIds`. The 500-member cap stays for this path.
- **Size bound (decided, §4.13).** The create transaction materializes at most 5,000 members. A larger CVE scope creates the
  campaign with `membership_state = 'MATERIALIZING'`, and the reconciler (§4.3) adds the rest in batches. Detail shows
  the partial count and the state; launch notifications wait until the state is `COMPLETE`.
- **Idempotent key.** The existing primary key `(campaign_id, finding_id)` is the membership key. Every insert uses
  `ON CONFLICT DO NOTHING`, so a retried create or reconcile never duplicates a member or overwrites its snapshot.
- **Never delete history.** No API or job deletes a `campaign_findings` row. A member whose finding later closes,
  is suppressed or changes owner stays a member. `add_source` records how it arrived: `CREATE`, `RECONCILER`,
  `MANUAL` (add-findings action) or `BACKFILL` (§4.10).
- **Request contract (plan §8.7).** `POST /api/campaigns` accepts `cveIds` or `findingIds` (one of the two), optional
  `assigneePrincipalId`, optional `coordinatingTeamId`, `includeExcepted`, and the existing notes, notify and
  watchlist fields. A body that names `ownerGroup` or `supportGroup` is rejected with 400. The same applies to
  `POST /api/campaigns/from-findings` and the PQC campaign request, whose `ownerGroup` fields are removed (§4.12). The assignee must be an
  active member of the tenant (the same check as `findings.assignee_principal_id`); the coordinating team must be
  `ACTIVE`. Neither changes subject or finding ownership.
- **Preview.** `POST /api/campaigns/preview` takes the same body and writes nothing. It returns the member count, the
  distribution by current owner team ID, Unowned, Conflict and Pending Migration counts, excluded counts by exception
  state, and the teams that have no notification channel (§4.6).

### 4.3 Reconciler

- `CampaignMembershipReconciler` runs every 15 minutes on worker nodes. It iterates
  `tenantService.listActiveTenants()` and works inside `tenantSchemaExecutionService.run(tenant, …)` with the
  transaction opened inside, following the context-before-transaction rule.
- It processes `CVE` campaigns in `ACTIVE`, `PAUSED`, `BLOCKED` or `IN_REVIEW`, and every campaign in
  `MATERIALIZING`. It never touches `CLOSED` or `CANCELLED` campaigns.
- **Watermark.** Per campaign, a keyset over `(findings.updated_at, findings.id)` for findings in scope, stored in
  `campaigns.reconcile_watermark`. A finding created after launch, or a non-member finding that reopens, matches and
  is added with `add_source = 'RECONCILER'`. A reopened member is already present and is not touched.
- **Bounds.** At most 1,000 members per campaign and 20 campaigns per tenant per run. The watermark advances only
  after its batch commits.
- **Observability (plan §8.7).** `GET /api/campaigns/{id}/reconciliation` returns `scopeKind`, `membershipState`,
  `reconciledAt`, the watermark, the members added in the last run and the last error. Three consecutive failures
  record a `RECONCILE_FAILED` campaign activity and raise the campaign-reconciliation metric. No ownership review item
  is raised: membership is campaign workflow, not ownership.

### 4.4 Owner-at-add snapshot

Each member records `owner_team_id_at_add`, `ownership_assignment_id_at_add` and `ownership_status_at_add`.

- **Resolved live.** The snapshot is read in the insert transaction from the `ownership_effective_assignment` view
  through `findings.ownership_subject_id`, never from `ownership_effective_cache` (plan §7.5: campaign owner-at-add is
  correctness-sensitive). The set-based insert joins the view directly.
- **Gated by authority, not by read wave.** A member whose finding kind's domain (`OwnershipReadAdapter.domainForFindingKind`)
  is `CANONICAL` gets the resolved status (`OWNED`, `UNOWNED` or `CONFLICT`); an unlinked finding in a canonical domain
  is `UNOWNED`. A member whose domain is `LEGACY` or `DARK` gets `LEGACY_PENDING_MIGRATION` with no team or
  assignment. It never receives a fabricated team (plan §9.11). The read wave only controls display, so switching it
  on later shows snapshots that were already correct.
- **Immutable.** Nothing updates these three columns after insert. A writer-control test enforces this. No trigger
  is used, because schema reset does not clone triggers (Release 1 known limitation).
- A stale effective row is recorded as resolved; staleness is not stored.

### 4.5 Current ownership, buckets and reads

- **Member reads.** `GET /api/campaigns/{id}/members` replaces the unpaged `GET /api/campaigns/{campaignId}/findings`
  and is cursor-paged (page size ≤ 200, matching
  `OwnershipReadAdapter.MAX_IDS`). Each row returns `ownerAtAdd` (team ID, team name joined at read time, status,
  assignment ID), `currentOwnership` from `OwnershipReadAdapter.forFindings` under `Consumer.CAMPAIGNS`,
  `ownershipChanged`, the finding status and exception state, and the campaign-exception state (plan §8.7).
- `ownershipChanged` is true only when both values are canonical and the team ID or status differs. A member that was
  `LEGACY_PENDING_MIGRATION` at add and is canonical now shows "owner assigned since launch", not a change.
- **Buckets.** Grouping, filters, counts and exports use stable team ID with four other buckets: `UNOWNED`,
  `CONFLICT`, `PENDING_MIGRATION` (domain still legacy) and, for owner-at-add grouping only, `NOT_RECORDED` (backfilled
  members, §4.10). Grouping defaults to current owner; owner-at-add is a selectable alternative. A team rename changes
  only the label.
- **Mixed domains.** A campaign can hold `VULNERABILITY` (CORE) and `CRYPTO` (CLOUD_BOM) members. Each member is
  canonical only when its own domain is, as `forFindings` already does. CRYPTO members read Pending Migration until the
  `CLOUD_BOM` switch (§3.6).
- **Read wave off.** With `app.ownership.read-waves.campaigns` empty, members render the legacy `owner_group` label
  under `LEGACY_PENDING_MIGRATION` and no ownership query runs, as in Release 1.
- **Counts.** Bucket counts are computed in SQL over `campaign_findings` joined to the view, not by loading members
  into Java. The asset rows group by asset ID and no longer return `assets.support_group`.
- **Exports** carry team ID, team name, status, source kind and resolved time for both current owner and owner at
  add (plan §9.11).

### 4.6 Notify groups and recipients

- `campaign_notify_groups` gains `recipient_type` (`TEAM` or `CUSTOM`) and nullable tenant-inclusive `team_id`.
- **TEAM.** The address is the team's notification channel: one email address per team (decided, §4.13), stored in a
  new `team.notification_email_enc` (encrypted through `TenantDataCipher`, set with `WRITE_TEAMS`). Directory groups
  are not a channel. The label is the team name, joined at read time. A team with no
  channel produces a `SKIPPED` delivery attempt with "Team has no notification channel", and the create preview lists
  it.
- **CUSTOM.** Free-text label and an address stored as `group_email_enc`. Creating or editing one needs
  `TENANT_ADMIN` or `SECURITY_ANALYST` (decided, §4.13), always records a `CUSTOM_RECIPIENT_ADDED` or
  `CUSTOM_RECIPIENT_UPDATED` campaign activity with the actor, and is shown as "not an owner recipient". The separate
  authorization the plan requires (§6.13) is this explicit check and audit, not a narrower role. A custom recipient is never ownership evidence.
- A TEAM recipient's membership in the campaign's current owner buckets is shown but not required: a coordinating
  team can be notified without owning any member.
- Launch notifications are sent for both scope kinds once `membership_state` is `COMPLETE`. Today
  `createFromFindings` sends none.
- The watchlist (`campaign_watchlist_entries`) is unchanged. It names people who follow the campaign, not owners.

### 4.7 Campaign exceptions

- `campaign_exceptions` gains tenant-inclusive `finding_id`, `owner_team_id_at_request` and
  `ownership_assignment_id_at_request`. The snapshot is taken live in the request transaction, as in §4.4.
- New exceptions require `findingId`, and the finding must be a member (409 otherwise). `findingDisplayId` is still
  accepted and resolved to the ID server-side. `asset_name` and `package_name` become display fields copied from the
  finding.
- Existing rows without `finding_id` are shown as unlinked legacy exceptions and count in no outcome bucket.
- A campaign exception stays campaign-local: it never suppresses, closes or changes the finding (true today). The UI
  labels it as campaign-only and links to the finding-exception action, which has its own authorization.

### 4.8 Outcome classifier

`CampaignOutcomeClassifier` replaces `isResolvedFinding`. It is a pure function of the finding's `status`,
`closed_reason`, finding events after the member's `added_at`, and the member's approved campaign exception. Rules are
applied in order; the first match wins.

| # | Condition | Outcome |
|---|---|---|
| 1 | `status = SUPPRESSED`, or `closed_reason = AUTO_SUPPRESSED_BY_RULE` | `SUPPRESSED` |
| 2 | `closed_reason = MANUAL_FALSE_POSITIVE` | `FALSE_POSITIVE` |
| 3 | `closed_reason = MANUAL_ACCEPTED_RISK` (today the manual `AUTO_CLOSED` transition in `FindingWorkflowService`) | `ACCEPTED_RISK` |
| 4 | `closed_reason` in `MANUAL_FIXED`, `VERIFIED_REMEDIATION`, `AUTO_NOT_OBSERVED`, `AUTO_COMPONENT_REMOVED`, `SUPERSEDED_BY_REPLACEMENT` | `REMEDIATED` |
| 5 | Any other closed reason (`AUTO_ASSET_RETIRED`, `AUTO_DUPLICATE`, `AUTO_SOURCE_DISABLED`, the `AUTO_POLICY_*` reasons, `AUTO_RECLASSIFIED_NOT_SOFTWARE`), or closed with no reason | `CLOSED_OTHER` (decided, §4.13) |
| 6 | Open, and an approved, unexpired campaign exception names this finding | `CAMPAIGN_EXCEPTED` |
| 7 | Open, and the finding was closed or suppressed at any time after `added_at` (a `REOPEN*` event or a `STATUS_CHANGED` event to `OPEN` from a closed state) | `REOPENED` |
| 8 | Otherwise | `OPEN` |

- `CLOSED_OTHER` is never remediated and never active work. The campaign shows it as "closed, not fixed".
- `FALSE_POSITIVE` reads 0 in Release 2, because no code writes `MANUAL_FALSE_POSITIVE` (§4.12). The finding-level
  false-positive decision arrives with the Release 3 exception UI (decided, §4.13). The bucket and rule 2 ship now, so
  nothing changes when it does.
- A finding resolved through ticket sync (`FindingIncidentSyncService.resolveFromTicket` → `MANUAL_FIXED`) is
  `REMEDIATED`, as today.
- **Metrics.** `remediatedCount` counts `REMEDIATED` only, and `completionPercent` is `REMEDIATED / members`.
  `activeRemainingCount` is `OPEN + REOPENED`. Every bucket is returned as `outcomes` on the summary and detail.
  Overdue counts only `OPEN` and `REOPENED` members. The existing `resolvedFindings` field becomes `remediatedCount`
  (plan §6.13 replaces the boolean test; there are no customers to keep the old meaning for).
- Members in suppressed, false-positive and accepted-risk buckets are hidden from active-remediation views by default
  and available through explicit filters with their exception type and expiry (plan §9.11).
- Reopen detection reads `finding_events` by `(finding_id, created_at)` only for members, in the same SQL as the
  counts.

**Implementation (E10, November 16, 2026, branch `feat/e10-campaign-ledger`, not merged).**

- **Ledger.** `CampaignLedger` is the only writer of `campaign_findings` and only inserts (`CampaignLedgerWriterControlTest`
  rejects any update or delete, and any `SET` of an at-add column, anywhere in `src/main`). Every insert is one
  set-based `INSERT … SELECT … ON CONFLICT DO NOTHING` with `tenant_id` from the session. The snapshot joins
  `ownership_effective_assignment` in the same statement, gated per finding kind by domain authority
  (`CANONICAL` → resolved status, unlinked → `UNOWNED`; otherwise `LEGACY_PENDING_MIGRATION`, no team), never by read
  wave and never from the cache. Every read path (summary, detail rows, asset rows, members, buckets) is SQL over
  `campaign_findings`; `loadFindingsForCampaign` and `isResolvedFinding` are gone.
- **Create.** `POST /api/campaigns` takes `cveIds` or `findingIds` (exactly one), `assigneePrincipalId` (an ACTIVE user
  with an ACTIVE membership of the tenant), `coordinatingTeamId` (ACTIVE team) and `includeExcepted`; a body that names
  `ownerGroup` or `supportGroup` (even as `null`) is 400. CVE scope materializes at most 5,000 members ordered by
  `(updated_at, id)`; when more are eligible the campaign is `MATERIALIZING` and its reconciler watermark starts after
  the last materialized member. Tenant **V26** adds `campaigns.include_excepted`, so the reconciler applies the same
  filter. `POST /api/campaigns/preview` returns the count, the distribution by owner as the snapshot would record it,
  excluded counts (`CLOSED`, `SUPPRESSED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`), `exceedsCreateBound` and the teams
  (owners and TEAM recipients) without a notification channel.
- **Finding scope.** `POST /api/campaigns/from-findings` and the PQC request reject `ownerGroup` and the free-text
  `assignedTo` with 400 and take `assigneePrincipalId`. `CryptoRemediationService.createCampaign` no longer bulk-writes
  `findings.assigned_to`, `owner_group` or `due_at`: the assignee is stored on the campaign only, because nothing writes
  `findings.assignee_principal_id` yet and a campaign must not change finding workflow. Finding-scope campaigns now show
  their members, progress and launch notifications. The PQC "owners" list stays empty until E13 moves it to team buckets.
- **Add-findings.** `POST /api/campaigns/{id}/members` (≤ 500 IDs, `add_source = 'MANUAL'`, 409 on a closed or cancelled
  campaign) is the backend for the §4.12 action; the dialog is E14.
- **Reconciler.** `CampaignMembershipReconciler` (every 15 minutes, `app.campaigns.reconciler.cron`, worker nodes) picks at
  most 20 campaigns per tenant, least recently reconciled first, locks each row `FOR UPDATE SKIP LOCKED` and runs one
  1,000-row keyset batch in its own transaction inside `run(tenant, …)`. Findings updated in the last minute are left
  for the next run so a transaction still in flight is not skipped; the watermark therefore lags by one minute. A
  `MATERIALIZING` campaign whose batch comes back short becomes `COMPLETE`, records `MATERIALIZED` and sends its launch
  notifications. Failures increment `reconcile_failures`; the third consecutive one records `RECONCILE_FAILED` and
  increments `campaign.reconciliation.failures`. `GET /api/campaigns/{id}/reconciliation` reports the state.
- **Outcomes.** `CampaignOutcomeClassifier` holds the §4.8 rules once, as Java and as the SQL `CASE` the ledger uses
  for counts, buckets and filters; a Postgres IT checks both agree for every status, closed reason and flag. An OPEN
  finding is never classified by a stale closed reason. Reopen detection is a `finding_events` row after `added_at` whose
  type contains `REOPEN`, or a `STATUS_CHANGED` event to `OPEN` from another status. The summary returns
  `remediatedCount`, `activeRemainingCount` and `outcomes`; `resolvedFindings`/`openFindings` are removed.
- **Reads.** `GET /api/campaigns/{id}/members` is cursor-paged on `(added_at, finding_id)` (≤ 200), hides suppressed,
  false-positive and accepted-risk members unless `outcome` names them or `includeHidden=true`, and filters by
  `groupBy`/`bucket`/`teamId`. `currentOwnership` comes from `OwnershipReadAdapter.forFindings(Consumer.CAMPAIGNS, …)`;
  `GET /api/campaigns/{id}/owner-buckets?groupBy=current|atAdd` returns the §4.5 buckets with outcome counts. The
  `CAMPAIGNS` read-wave property itself is wired in E15, so until then current ownership is always the legacy envelope
  and current grouping is `PENDING_MIGRATION` with no ownership query; owner-at-add buckets work now. The unpaged
  `GET /api/campaigns/{id}/findings` is removed. Detail asset rows group by asset ID without `support_group`.
- **Recipients.** TEAM recipients name a team and use `team.notification_email_enc`, set (or cleared with a blank) through
  the write-only `notificationEmail` field of `PATCH /api/ownership/teams/{id}` (`WRITE_TEAMS`, `TeamNamespaceService`,
  tenant ciphertext, 503 when the key is not ready); a team without one gets a `SKIPPED` "Team has no notification
  channel" attempt. CUSTOM recipients store only `group_email_enc` (purpose `campaign.recipient.email`), need
  `TENANT_ADMIN` or `SECURITY_ANALYST` (403 otherwise, including a platform owner without either role), record
  `CUSTOM_RECIPIENT_ADDED`/`UPDATED` and return `ownerRecipient = false`. **V26** drops the plaintext `group_email`;
  with no customer data nothing is re-encrypted.
- **Exceptions.** New exceptions need `findingId` (or a resolvable `findingDisplayId`) of a member (409 otherwise, 404
  for an unknown finding); asset and package names are copied from the finding and the owner is snapshot at request.
  Only `APPROVED` counts for `CAMPAIGN_EXCEPTED` (there is no separate expiry column).
- **Backfill (§4.10 step 1) is not built**: there are no customer campaigns, so `BACKFILL` and `NOT_RECORDED` remain only
  for rows written before the ledger.
- Frontend changes in E10 are limited to keeping the existing campaign and CBOM screens working against the new DTOs
  (outcome-based progress, owner labels from the read envelope, no owner or assignee inputs on the crypto and PQC
  dialogs); the §5.2 campaign UI is E14.

### 4.9 Ticket routing

Routing is server-derived on the canonical path. The browser no longer supplies the assignment group.

- **When canonical.** A finding routes canonically when its domain is `CANONICAL` and
  `app.ownership.read-waves.tickets` includes the tenant. Otherwise today's behaviour is kept unchanged, including the
  `App-Sec Manager` fallback, until the switch.
- **Live owner.** Routing reads the current owner from `ownership_effective_assignment` in the ticket transaction,
  never from the cache (plan §7.5).

| Current ownership | Assignment group | `routing_source` |
|---|---|---|
| `OWNED`, team has `ticket_assignment_group` | The team's group | `TEAM_MAPPING` |
| `OWNED`, team has no mapping | The tenant's configured default group, if set; otherwise the user must select one | `TENANT_DEFAULT` or `USER_SELECTED` |
| `UNOWNED` | Same as the row above | `TENANT_DEFAULT` or `USER_SELECTED` |
| `CONFLICT` | Never routed automatically. The user resolves ownership or selects a group with a reason | `OVERRIDE` |

- **No implicit values.** The hard-coded `DEFAULT_ASSIGNMENT_GROUP` is not used on the canonical path. The tenant
  default is an explicit setting on the ticketing connector configuration (§4.11). The team display name is never sent
  as a group. `TicketAsset.assignmentGroup` from the request (the raw CMDB support group) is ignored on the canonical
  path (plan §9.13).
- **Override.** Any batch may set `assignmentGroupOverride` with a required `overrideReason` (≤ 500 characters). The
  override and reason are recorded in the ticket attempt and as a `TICKET_ROUTING_OVERRIDE` finding event carrying the
  V23 `owner_team_id`/`ownership_assignment_id` snapshot. It needs the same roles as creating a ticket.
- **Mixed-team CVE tickets (plan §6.15 step 8).** `createTicketsForCve` partitions the selected findings into one
  batch per current owner team, plus one batch each for Unowned and Conflict. Each batch becomes one ticket, also when
  two teams map to the same assignment group (decided, §4.13), so every ticket has exactly one owner team. There is
  no first-group fallback. A coordinator override sends every batch as one ticket to one chosen group, with a reason.
  Package grouping remains only inside the legacy path.
- **Preview.** `POST /api/tickets/preview` takes finding IDs, or a CVE plus component IDs, and returns the batches
  (team ID and name, assignment group, `routing_source`, finding count), the unroutable findings (Conflict, unmapped
  without a default), and the excluded ones (closed or already ticketed). It also returns a `routingHash` over the
  batches and the assignment IDs used. Create must send the hash. If ownership or mappings changed since the preview,
  create returns 409 with a fresh preview. The hash is valid for 10 minutes.
- **Audit.** Every ticket path (single finding, CVE, AI Grid, crypto) writes one `finding_ticket_attempts` row per
  linked finding through `TicketingService`, not only the crypto path. Each row records `owner_team_id`,
  `ownership_assignment_id`, the `assignment_group` sent, `routing_source`, `override_reason` and a `batch_id`
  shared by the findings of one ticket.
- **Lifecycle.** Ownership changes never close, reopen or reassign a ticket, and never change `incident_provider`.
  `FindingIncidentSyncService` is unchanged. Finding detail shows "owner changed since ticket" by comparing the
  latest successful attempt's `owner_team_id` with the current owner. Suppression keeps the existing comment push.
- **Jira.** Jira has no assignment-group field. In Release 2 the mapped group is written as text in the summary and
  description, as today (decided, §4.13). Mapping it to a Jira component, label or team field waits for a customer
  Jira to test against.
- **CVE ticket authorization.** See §4.12.

**Implementation (E11, November 16, 2026, branch `feat/e11-ticket-routing`, not merged).**

- **`TicketRoutingService`** computes the plan for a set of findings in the caller's transaction, reading the live
  owner from `ownership_effective_assignment` and the team's `ticket_assignment_group`. It applies every row of the
  routing table: an unlinked finding counts as `UNOWNED`, a selection is used only when the tenant has no default, and
  Conflict findings are listed as unroutable. There are no implicit values on this path, and the team name is never sent
  as a group. Canonical means every finding's domain is `CANONICAL` and the tenant is in
  `app.ownership.read-waves.tickets`. E11 wires that property and `app.ownership.read-waves.campaigns` in
  `OwnershipReadAdapter` (both empty by default), because routing cannot be tested without them. E15 keeps the
  enablement, qualification and rollback work.
- **Batches.** There is one batch per owner team and one for Unowned; Conflict gets no batch. Two teams on one group
  still get two tickets. An override (`assignmentGroupOverride` plus a required `overrideReason` of at most 500
  characters, 400 otherwise) sends every eligible finding as one ticket. In this version the override applies to the
  whole request, not to a single batch. Closed and already-ticketed findings are listed as excluded.
- **Preview and hash.** `POST /api/tickets/preview` takes finding IDs, or a CVE plus component IDs, and returns batches,
  unroutable and excluded findings, the tenant default, and a `routingHash`. The hash is a SHA-256 digest of the batches,
  the per-finding assignment IDs and statuses, the excluded findings and the choice. It is HMAC-signed under the tenant
  key (`ticket.routing.preview`), carries its own 10-minute expiry, and fails with 503 when the key is not ready. Every
  canonical create recomputes the plan. A missing, tampered, expired or stale hash returns 409 `TICKET_ROUTING_CHANGED`,
  with the fresh preview in the body (`ApiExceptionHandler`). Previews are read-only.
- **Create.** `POST /api/findings/{id}/ticket` and the CVE endpoints accept `routingHash`, `selectedAssignmentGroup`,
  `assignmentGroupOverride` and `overrideReason`. On the canonical path the routed group replaces the request's
  `assignmentGroup`. On CVE tickets the per-asset CMDB group is stripped, and each ticket carries only its batch's
  assets and links only its batch's findings. With the wave off, or for non-canonical kinds (CRYPTO before the
  `CLOUD_BOM` switch, AI Grid), today's behaviour is unchanged.
- **Tenant default.** `default_assignment_group` is now read and written through the ServiceNow CMDB and Jira connector
  config APIs. Null keeps the stored value and blank clears it. The active provider's config supplies the default.
- **Audit.** `TicketingService` writes one `finding_ticket_attempts` row per linked finding on every path (single,
  CVE, AI Grid, crypto). Each row records `owner_team_id`, `ownership_assignment_id`, the group sent, `routing_source`,
  `override_reason` and a `batch_id` shared by one ticket's findings. Failures are written in their own transaction, and
  only for findings that exist. `CryptoRemediationService` no longer records attempts itself, and `GET
  /api/findings/{id}/ticket-attempts` returns the new fields. An override also writes a `TICKET_ROUTING_OVERRIDE` finding
  event with the V23 owner snapshot. On the legacy path `assignment_group` is the caller-supplied group, because the
  provider still chooses its own fallback.
- **Roles (§4.12).** The CVE ticket endpoints (`/ticket`, `/servicenow-incident`) and the preview now require
  `PLATFORM_OWNER`, `TENANT_ADMIN` or `SECURITY_ANALYST`. `TicketAuthorizationPostgresIntegrationTest` covers them and
  fails without the check.
- **Provider payloads** are E12 (below). `FindingIncidentSyncService` is unchanged, and a source check asserts that it
  never reads ownership.

**Implementation (E12, November 16, 2026, branch `feat/e12-provider-routed-group`, not merged).**

- **Routed marker.** `TicketRequest.routedAssignmentGroup` and `CveTicketRequest.routed` are set only by
  `TicketingService` on the canonical path. A routed finding request replaces any caller `assignmentGroup`; a routed CVE
  request carries the batch's group. Callers cannot set either field: `FindingTicketController` and the AI Grid and crypto
  paths build requests through the old constructors. A request without the marker keeps today's behaviour exactly.
- **ServiceNow.** A routed single-finding incident sends `assignment_group` = the routed group, never the finding's
  `owner_group` and never `App-Sec Manager` (`ServiceNowIncidentService.createFindingIncidentRemote` has a routed-group
  overload; the old signature delegates with null). A routed CVE ticket sends its batch group; a routed ticket without a
  group is refused (`IllegalStateException`) instead of defaulting. The legacy path still falls back to `owner_group`
  and then `App-Sec Manager` for single findings, and to `App-Sec Manager` for CVE tickets, until the wave is on.
- **Jira.** A routed finding ticket appends ` — <group>` to the summary and writes `Assignment group: <group>` in the
  description, and no longer shows the finding's free-text `owner_group`. This matches the CVE ticket, which already
  named its group in both places. Mapping to a Jira component, label or team field still waits for a customer Jira (R8).
- **Tests.** `ServiceNowRoutedGroupTest` (`MockRestServiceServer` over a real `OutboundHttpClient`) checks the
  ServiceNow payload on routed and legacy paths for single findings and CVEs, including that `App-Sec Manager`,
  `owner_group` and a caller group never appear on a routed ticket. `JiraTicketingProviderTest` covers the routed and
  legacy text, and `TicketRoutingPostgresIntegrationTest` checks that the service marks canonical requests as routed
  and legacy requests as not routed.

### 4.10 Rollout and rollback

1. **Schema and backfill (dark).** V24 ships (§4.11). A one-time job materializes every existing CVE campaign's
   current matches, all statuses, with `add_source = 'BACKFILL'`. Backfilled members get
   `ownership_status_at_add = NULL` (shown as `NOT_RECORDED`) because their real add time and owner are unknown. The
   job encrypts existing `group_email` values into `group_email_enc`, marks those notify groups `CUSTOM` and links
   exceptions to `finding_id` where `finding_display_id` resolves.
2. **Ledger reads.** Campaign reads switch to `campaign_findings` and the outcome classifier. These do not depend on
   ownership and are not flagged; there are no customers whose numbers would change.
3. **Snapshots.** Members added from now on carry snapshots under §4.4, whatever the read wave.
4. **Read waves.** `app.ownership.read-waves.campaigns` and `app.ownership.read-waves.tickets` are wired in
   `OwnershipReadAdapter`, empty by default, enabled per tenant after CORE is `CANONICAL`.
5. **Rollback.** Emptying a read wave returns campaigns to legacy labels and tickets to the legacy routing path.
   Snapshots, attempts and members are kept. They are history and are never rewritten.

### 4.11 Schema and code impact

- **Tenant V24 (shared with §3.8).**
  - `campaigns`: `scope_kind` (`CVE`, `FINDINGS`), `membership_state` (`MATERIALIZING`, `COMPLETE`),
    `assignee_principal_id` (FK `platform.app_users`), `coordinating_team_id` (tenant-inclusive FK `team`),
    `reconcile_watermark` (jsonb), `reconciled_at`, `last_reconcile_added`, `last_reconcile_error`,
    `reconcile_failures`.
  - `campaign_findings`: `owner_team_id_at_add`, `ownership_assignment_id_at_add`, `ownership_status_at_add` (check
    `OWNED`, `UNOWNED`, `CONFLICT`, `LEGACY_PENDING_MIGRATION`, nullable for backfill), `add_source`; tenant-inclusive
    FKs to `team`, `ownership_assignment` and `findings (tenant_id, id)`, the last replacing the V17 `findings(id)` FK
    with `ON DELETE RESTRICT` (decided, §4.13); index `(campaign_id, owner_team_id_at_add)`.
  - `campaign_exceptions`: `finding_id` (tenant-inclusive FK), `owner_team_id_at_request`,
    `ownership_assignment_id_at_request`.
  - `campaign_notify_groups`: `recipient_type`, `team_id` (tenant-inclusive FK), `group_email_enc`; check that `TEAM`
    rows have `team_id` and `CUSTOM` rows do not. `group_email` is dropped at contract cleanup.
  - `team`: `notification_email_enc`.
  - `finding_ticket_attempts`: `owner_team_id`, `ownership_assignment_id` (tenant-inclusive FKs), `assignment_group`,
    `routing_source` (check `TEAM_MAPPING`, `TENANT_DEFAULT`, `USER_SELECTED`, `OVERRIDE`, `LEGACY`),
    `override_reason`, `batch_id`.
  - Ticketing connector configuration: a nullable default assignment group on the ServiceNow and Jira ticketing
    configs.
  - `MigrationCatalogTest` and `TenantSchemaCompatibility` move to V24, once for all of §3 and §4.
- **Code (Phase B).** `CampaignService` reads only `campaign_findings`; set-based materialization with live snapshot;
  `CampaignMembershipReconciler`; `CampaignOutcomeClassifier`; members, preview and reconciliation endpoints; notify
  recipient types and team channel; exception `finding_id`; `TicketRoutingService` (live owner, mapping, default,
  override, preview hash) called by `TicketingService`; attempt recording moved into `TicketingService`; read-wave
  wiring for `CAMPAIGNS` and `TICKETS`; campaign list/detail/create UI with team buckets, `OwnerChangeIndicator`,
  outcome buckets; ticket dialogs showing owner team and external group separately (plan §9.13).
- **Tests (Phase B).**
  - unit tests for the classifier (every `FindingCloseReason`, rule order, reopen detection) and for routing (every
    row of the §4.9 table, override, no implicit default);
  - Postgres ITs: CVE create materializes open members only; `includeExcepted`; 5,000-member bound and
    `MATERIALIZING` completion; deleting a finding that has campaign membership fails; reconciler adds new and reopened non-member findings, never removes, is idempotent
    under retry and skips closed campaigns; snapshot from the live view with the cache disabled and with a stale cache
    row; `LEGACY_PENDING_MIGRATION` while CORE is `DARK`; snapshot unchanged after an owner change; team rename keeps
    one bucket; mixed CORE/CLOUD_BOM members; exception requires a member; campaign exception leaves the finding
    unchanged; mixed-team CVE tickets produce one ticket per team and none for Conflict without override; preview hash
    409 after a mapping change; attempts written for every path; an ownership change does not alter ticket or finding
    status through `FindingIncidentSyncService`;
  - a writer-control test that nothing updates the at-add columns;
  - authorization matrix rows for every new endpoint, CUSTOM recipients and the CVE ticket endpoints (§4.12);
  - `MockRestServiceServer` tests that the ServiceNow payload carries the mapped group and never `App-Sec Manager` on
    the canonical path;
  - read-wave rollback: emptying each wave returns legacy rendering and legacy routing with no ownership query.

### 4.12 Observations from the code

- **Finding-scope campaigns show no progress.** `createFromFindings` writes `campaign_findings`, but `toSummary`,
  `toFindingRows`, `toAssetRows` and `toEvidenceRows` read only `campaign_vulnerabilities`. A crypto campaign has no
  CVEs, so its list and detail show 0 findings and 0% complete; only `GET /api/campaigns/{campaignId}/findings`
  (`CryptoRemediationController` → `CampaignService.findings`) lists its members. §4.2 fixes this.
- **CVE ticket endpoints have no role check.** `ServiceNowIncidentController` (`POST /api/cve-detail/{cveId}/ticket`
  and `/servicenow-incident`) has no `@PreAuthorize`, and `SecurityConfig` admits every tenant role on `/api/**`.
  `READ_ONLY_AUDITOR` and `INVENTORY_ADMIN` therefore appear able to create tickets, while the single-finding endpoint
  is limited to `PLATFORM_OWNER`, `TENANT_ADMIN` and `SECURITY_ANALYST`. **Decided (November 14, 2026):** the CVE
  ticket endpoints and the new ticket preview get the same three roles. Phase B adds the check and an authorization IT
  that fails before the fix.
- **No false-positive writer.** `FindingCloseReason.MANUAL_FALSE_POSITIVE` exists, but no code sets it. The manual
  `AUTO_CLOSED` transition records `MANUAL_ACCEPTED_RISK`. The `FALSE_POSITIVE` bucket will therefore stay empty until
  a false-positive decision path exists (§4.13).
- **Campaign launch writes free-text owners onto findings.** `CryptoRemediationService.createCampaign` (used by
  `POST /api/campaigns/from-findings` and `CbomEnterpriseService` PQC campaigns) bulk-updates every member's
  `findings.owner_group` from the request's `ownerGroup` through `updateWorkflowBulkByIds`. `CryptoCampaignDialog`
  offers it as "Owner group (optional)". Plan §6.13 forbids this: launch may set an assignee principal, not an owner.
  The assignee part stays and moves to `assignee_principal_id`; the owner part is removed.
- **PQC progress has its own "resolved" rule.** `CbomEnterpriseService` counts `RESOLVED` and `AUTO_CLOSED` as
  resolved and lists owners as `coalesce(assigned_to, owner_group)`. It must use the §4.8 classifier and §4.5 buckets.
  `CampaignDetailPage` also computes per-severity progress in the browser from `status === 'RESOLVED'`; it must read
  the server's `outcomes`.
- **Add assets is not saved.** `CampaignDetailPage`'s Add assets dialog searches raw `asset.ownerTeam`, then adds rows
  to local state only (`setScopeEditedLocally`); no API call persists them. Release 2 replaces it with an add-findings
  action that writes `campaign_findings` (`add_source = 'MANUAL'`) and searches by current owner team ID (plan §9.11).
- **History can cascade away.** `campaign_findings.finding_id` uses `ON DELETE CASCADE`, so deleting a finding removes
  its membership history. Findings are not deleted in normal workflow. V24 replaces the FK with `RESTRICT` (§4.13), so
  any path that deletes findings must remove campaign rows first. **Decided (November 14, 2026):** tenant purge
  deletes `campaign_findings` (and the campaign tables) before findings; nothing is archived.

### 4.13 Decisions and open items

**DECISIONS (approved by the product owner, November 14, 2026):**

| Question | Decision | Where applied |
|---|---|---|
| How to count non-remediation closes (`AUTO_ASSET_RETIRED`, `AUTO_DUPLICATE`, `AUTO_SOURCE_DISABLED`, `AUTO_POLICY_*`, `AUTO_RECLASSIFIED_NOT_SOFTWARE`) | Separate `CLOSED_OTHER` bucket, never remediated | §4.8 rule 5 |
| False-positive decision in Release 2 | Not added. The bucket ships and reads 0 until the Release 3 exception UI | §4.8 |
| Jira mapping of the team ticket group | Text in summary and description, as today | §4.9 |
| Team notification channel | One encrypted email address per team | §4.6 |
| Who may add CUSTOM recipients | `TENANT_ADMIN` and `SECURITY_ANALYST`, always audited | §4.6 |
| Two teams sharing one assignment group on a CVE ticket | One ticket per team | §4.9 |
| `campaign_findings` FK on finding delete | `RESTRICT` | §4.11, §4.12 |
| Members materialized at create | 5,000; the rest by the reconciler in batches of 1,000 | §4.2, §4.3 |
| Tenant purge with `RESTRICT` | Delete campaign rows before findings; no archive | §4.12 |
| Roles for CVE ticket endpoints and ticket preview | `PLATFORM_OWNER`, `TENANT_ADMIN`, `SECURITY_ANALYST` | §4.12 |

**Still open:**

| Item | Owner | Blocks |
|---|---|---|
| Confirm the 5,000 create bound and the 1,000 reconciler batch against the expected-size benchmark | Ownership lead | Enabling CVE campaigns outside test tenants |
| Jira component, label or team-field mapping, tested against a customer Jira | Connector lead + a customer Jira | Jira routing beyond text (not Release 2) |

## 5. Release 2 change ledger

Plan §9.16 requires the initial change inventory to be replaced by a mechanical, owner-assigned ledger before each
owning release. This is the Release 2 ledger. It was built on November 14, 2026 by searching `backend/src/main` and
`frontend/src` (tests excluded) for `owner_group`, `ownerGroup`, `support_group`, `supportGroup`, `assignmentGroup`,
`assignment_group`, `ownerTeam`, `owner_team`, `groupName` and `groupEmail`, then reading each hit in the Release 2
areas: campaigns, tickets, BOM/CBOM, cloud and the ServiceNow connector. Release 1 areas (inventory and findings read
paths) and Release 3 areas are listed only where a Release 2 change touches them.

Re-run the search before Release 2 starts. A new hit in these areas is added here with an owner before it merges.

**Re-run (November 14, 2026, kickoff prep).** Same terms and paths, tests excluded: 103 files. No code under
`backend/src/main` or `frontend/src` changed since the first pass, so the new rows are hits that pass did not list.
They are marked *(re-run)* in §5.1–§5.3. Hits outside the Release 2 areas were left out as before: Release 1
inventory and findings read paths, the ownership services and their canonical `ownerTeamId` fields, AI Grid (Release 3
ledger), and migration files. `service/LegacyGithubSyncRunBackfillService.java` is not ownership: its `ownerGroup` is
the GitHub repository owner used to group sync runs.

Kinds: **W** writes free text as ownership, **R** reads free text as ownership or routing, **E** evidence or metadata
that must be proven not to be read as ownership, **B** behaviour change with no ownership field.

### 5.1 Backend

| File | Use today | Kind | Release 2 change | Contract | Owner |
|---|---|---|---|---|---|
| `service/CampaignService.java` | `loadFindingsForCampaign` dynamic membership; `isResolvedFinding`; finding rows return `owner_group`, asset rows `support_group` | R, B | Ledger reads, snapshots, buckets, classifier | §4.2–§4.5, §4.8 | Workflow lead |
| `dto/CampaignDtos.java` | `CampaignFromFindingsRequest.ownerGroup`; row DTOs carry `ownerGroup`/`supportGroup`; notify group `groupName`/`groupEmail` | W, R | Remove `ownerGroup`; add `ownerAtAdd`, `currentOwnership`, `outcomes`, `recipientType`, `teamId` | §4.2, §4.5, §4.6 | Workflow lead |
| `domain/CampaignNotifyGroup.java` | Free-text `group_name`, plaintext `group_email` | R | `recipient_type`, `team_id`, `group_email_enc` | §4.6 | Workflow lead |
| `domain/CampaignException.java` | Free-text `finding_display_id` | B | `finding_id` and owner snapshot | §4.7 | Workflow lead |
| `service/CampaignAiService.java` | Groups findings by `ownerGroup`, "Unassigned" | R | Group by current owner team ID with Unowned/Conflict; names joined at read time | §4.5 | Workflow lead |
| `service/cbom/CryptoRemediationService.java` | `createCampaign` bulk-writes `findings.owner_group`; queue and SLA use `owner_group`; ticket notes "ScoutGrid owner" from `owner_group`; records ticket attempts | W, R | Drop owner write; assignee principal only; owner from the effective view; attempt recording moves to `TicketingService` | §4.9, §4.12 | CBOM lead |
| `service/cbom/CbomEnterpriseService.java` | `PqcCampaignRequest.ownerGroup`; PQC progress counts `AUTO_CLOSED` as resolved, owners from `coalesce(assigned_to, owner_group)`; portfolio groups by `a.owner_team` and `a.support_group` | W, R | Remove `ownerGroup`; classifier and team buckets; portfolio "owner team" groups by current owner team ID; `supportGroup` grouping stays, labelled as CMDB evidence | §3.7, §4.8, §4.12 | CBOM lead |
| `ticketing/TicketingService.java` | Groups CVE tickets by caller `assignmentGroup`, then package | R | Canonical routing, mixed-team batches, preview hash, attempts | §4.9 | Workflow lead |
| `ticketing/TicketRequest.java`, `CveTicketRequest.java`, `TicketAsset.java` | Caller-supplied `assignmentGroup` | R | Add `assignmentGroupOverride`/`overrideReason`; ignore `TicketAsset.assignmentGroup` on the canonical path | §4.9 | Workflow lead |
| `ticketing/ServiceNowTicketingProvider.java` | Hard-coded `App-Sec Manager` fallback | R | Use the routed group only; no fallback on the canonical path | §4.9 | Connector lead |
| `service/ServiceNowIncidentService.java` | Single-finding incident uses `finding.getOwnerGroup()` then `App-Sec Manager` | R | Take the routed group from `TicketRoutingService` | §4.9 | Connector lead |
| `ticketing/JiraTicketingProvider.java` | Group as text in summary/description | E | Text from the routed group (decided) | §4.9 | Connector lead |
| `controller/ServiceNowIncidentController.java`, `dto/CreateServiceNowIncidentRequest.java` | Per-asset `assignmentGroup` from the browser; no `@PreAuthorize` on ticket POSTs | R, B | Ignore per-asset group on the canonical path; add role check | §4.9, §4.12 | Workflow lead |
| `controller/FindingTicketController.java`, `dto/CreateFindingTicketRequest.java` | Request `assignmentGroup` (ignored by ServiceNow today) | R | Override with reason; preview | §4.9 | Workflow lead |
| `service/FindingIncidentSyncService.java` | Status sync, no ownership | B | None; regression test that ownership changes do not move tickets | §4.9 | Workflow lead |
| `service/ownership/OwnershipReadAdapter.java` | Read waves wired for `INVENTORY` and `FINDINGS` only | B | Wire `CAMPAIGNS` and `TICKETS`; CLOUD_BOM eligibility | §2.6, §4.10 | Ownership lead |
| `service/ownership/ServiceNowOwnershipProducer.java` | Scans every `cis` row by sync time | B | ServiceNow-originated CIs only (E4 done on branch, pending merge) | §2.10 | Ownership lead |
| `service/ServiceNowCmdbConfigService.java` | Reads `installed_on.support_group` display value | E | Keep name and reference `sys_id` in separate columns | §1.8 | Connector lead |
| `service/ownership/InventorySubjectAdapter.java` | VULNERABILITY-only finding subject | B | `FindingSubjectAdapterRegistry` | §3.5 | Ownership lead |
| `service/SoftwareIdentityMetadataService.java`, `dto/SoftwareIdentityMetadata*.java` | Stores and returns `support_group` on software identity metadata; no other reader | E | Keep as reference metadata; never read as ownership; the identity's owner coverage comes from occurrences | §3.7 | Inventory lead |
| `inventory_components` writers (SBOM, BOM orchestrator, CMDB/SCCM/SSM/VM Manager host inventory) | No ownership field | B | Shared occurrence key and post-commit registration | §3.2, §3.4 | Inventory lead |
| `service/AwsDiscoveryConfigService.java`, `service/GcpDiscoveryConfigService.java` | AWS accepts 5-minute intervals; no upper bound | B | Interval validation while a producer is enabled; per-tenant producer toggles; AWS Organizations role and connection test | §2.1, §2.2, §2.2.1 | Connector lead |
| AWS client (new Organizations reader) | None | B | `ListTagsForResource` per observed account through `OutboundHttpClient` | §2.2.1 | Connector lead |
| Tenant purge | Deletes findings; `campaign_findings` cascades today | B | Delete campaign tables before findings under `RESTRICT` | §4.12 | Ownership lead |
| Directory preview (new) | None | B | Full sample values for tenant admins, audit event, `no-store` | §1.6 | Ownership lead |
| `service/CiResolutionService.java`, `domain/Ci.java` *(re-run)* | Requests `support_group` (with `owned_by`, `managed_by`, `assigned_to`, `department`) when resolving CIs; copies the display value to `cis.support_group` and `assets.support_group` | E | Same as `ServiceNowCmdbConfigService`: name and reference `sys_id` kept separately; never read as ownership | §1.8 | Connector lead |
| `service/cmdbingestion/CmdbInventoryIngestionRunner.java` *(re-run)* | Reads `installed_on.support_group` display value from CMDB rows | E | Same as above | §1.8 | Connector lead |
| `domain/BomComponent.java`, `service/BomIngestionOrchestrator.java` *(re-run)* | `groupName` is the CycloneDX component `group`, else the supplier name; not ownership | E | None for ownership. Request R2 (§6.1) confirms whether it affects `package_name` in the occurrence key | §3.2 | Inventory lead |

### 5.2 Frontend

| File | Use today | Kind | Release 2 change | Contract | Owner |
|---|---|---|---|---|---|
| `features/campaigns/CampaignDetailPage.tsx` | Groups findings by `ownerGroup`; Add assets searches `asset.ownerTeam`, maps it to `supportGroup` and never saves; notify owner by `groupName`; severity progress from `status === 'RESOLVED'` | R, B | Team ID buckets with Unowned/Conflict/Pending Migration; `OwnerChangeIndicator`; saved add-findings action; TEAM/CUSTOM recipients; server `outcomes` | §4.5, §4.6, §4.8, §4.12 | Workflow lead |
| `features/campaigns/CampaignLinkedFindings.tsx` | Shows `assignedTo ?? ownerGroup` | R | Assignee and owner team in separate columns | §4.5 | Workflow lead |
| `pages/CampaignsPage.tsx` | Launch wizard sends free-text notify `groupName` | R | Canonical team picker for TEAM recipients; CUSTOM visibly non-owner; launch preview | §4.2, §4.6 | Workflow lead |
| `features/campaigns/types.ts` | `ownerGroup`, `supportGroup`, `groupName` types | R | Match §4 DTOs | §4 | Workflow lead |
| `features/cbom/CryptoCampaignDialog.tsx` | "Owner group (optional)" free-text input | W | Remove; `ApplicationPrincipalPicker` for assignee | §4.12 | CBOM lead |
| `features/cbom/CryptoRemediationPanel.tsx` | Shows `assignedTo ?? ownerGroup` | R | Assignee and owner team separately | §4.5 | CBOM lead |
| `features/cbom/CbomPortfolioPanel.tsx`, `features/cbom/types.ts` | "Owner team" grouping from `a.owner_team` | R | Group by current owner team ID | §3.7 | CBOM lead |
| `pages/FindingDetailPage.tsx` | Ticket dialog defaults the group from `finding.ownerGroup` | R | Show owner team and external group separately; routing preview; override with reason | §4.9 | Workflow lead |
| `pages/SoftwareIdentityDetailPage.tsx`, `features/software-identities/types.ts` | Editable `supportGroup` metadata | E | Label as reference metadata; add occurrence owner coverage | §3.7 | Inventory lead |
| `api/client.ts` campaign-from-findings payload *(re-run)* | Sends `ownerGroup` to `/campaigns/from-findings` | W | Remove with the DTO field | §4.2 | Workflow lead |
| `api/client.ts` `createCbomPqcCampaign` *(re-run)* | Sends `ownerGroup` to the PQC campaign endpoint | W | Remove with `PqcCampaignRequest.ownerGroup` | §4.12 | CBOM lead |
| `features/connect/types.ts` `CreateFindingTicketRequest` *(re-run)* | Caller `assignmentGroup` | R | Override with reason, matching the backend DTO | §4.9 | Workflow lead |

### 5.3 Not in Release 2

These hits were found, but their owning release is not Release 2. They must keep working through the Release 2
legacy ticket path (§4.9) until then.

| File | Use today | Owning release |
|---|---|---|
| `features/cve-workbench/components/WorkbenchMain.tsx`, `FindingsTab.tsx`, `CveOverviewTab.tsx`, `InvestigationCanvas.tsx`, `NotifyGroupsPanel.tsx` | Free-text assignment group, CMDB support group per asset, notify groups | Release 3 (plan §6.15, §9.12) |
| `pages/FindingDetailPage.tsx` owner-group edit (`updateWorkflow({ ownerGroup })`) and `pages/FindingsPage.tsx` Owner Group / Support Group columns | Legacy finding owner field | Findings consumer wave (Release 1), removed at cleanup (plan §15.5) |
| `features/findings/types.ts` | `ownerGroup` type | Cleanup |
| `pages/VulnRepoCveAssetsPage.tsx` *(re-run)* | "Assign by support group" sends a per-asset `assignmentGroup` on CVE tickets; support group and owner columns. The canonical ticket path ignores the per-asset group (§4.9) | Release 3 (plan §6.15) |
| `controller/CveDetailController.java`, `service/CveDetailQueryFacade.java`, `features/cve-workbench/asset-report.ts`, `investigation-context.ts`, `source-helpers.ts`, `vendor-helpers.ts`, `types.ts` *(re-run)* | CMDB support group per asset in workbench reads and ticket assets | Release 3 (plan §6.15, §9.12) |
| `service/FindingQueueResolutionService.java`, `service/PersonalFindingQueueService.java` *(re-run)* | `ownerGroup`/`supportGroup` queue filters beside `ownerTeamId` | Findings consumer wave (Release 1), removed at cleanup |
| `dto/CmdbAssetRecordRequest.java`, `service/AssetLifecycleService.java`, `features/connect/types.ts` `CmdbAssetRecord` *(re-run)* | `POST /api/assets/cmdb-sync` writes caller `ownerTeam` to `assets.owner_team`. Its only Release 2 reader is the CBOM portfolio (§5.1, CBOM lead) | Cleanup (decided November 14, 2026) |
| `service/CustomerDemoDatasetService.java` *(re-run)* | Seeds `owner_group`, `owner_team` and `support_group` in demo tenants | Cleanup |

### 5.4 Ledger rules

- **Done.** An entry is done when its change merges with the test named in its contract and a re-run of the search
  shows no remaining **W** or **R** use in that file outside the legacy path behind a read wave.
- **E entries** close with a test or reader scan proving the field is not read as ownership, not by removing the
  field.
- Owners are roles (plan §16.1 workstreams). Release 2 staffing names a person for each role before work starts
  (plan §16.3).

## 6. Release 2 kickoff preparation

Scope: plan §16.1 (dependency-based estimate, named staffing, environments, provider access dates, critical path),
§16.3 and §16.5. Release 1 is built but off by default and not release-qualified; its KMS spike, benchmarks and real
CMDB sample stay open and are tracked in the Phase 0A design (§10), not here.

**DECISION (product owner, November 15, 2026): the V24 hold is lifted.** Tenant V24 (E1) is built now and does not
wait for R1 (due December 4) or R2 (due November 27). In place of their results:

- **R2 assumption.** Every `inventory_components` writer normalizes `ecosystem`, `package_name`, `version` and `purl`
  the same way. E7 must confirm this before occurrence registration is enabled outside test tenants. **E7 result
  (November 16, 2026):** they do not; the occurrence key now normalizes for itself, with one residual recorded in §3.4.
- **R1 assumption.** V24 uses the §3.8 index design as written. If R1 shows it is wrong, the fix is an additive,
  index-only migration (now V26, since E5 used V25). No V24 column or constraint depends on R1.

There are no customer tenants, so V24 takes the final column shape (NOT NULL and checks) without a separate backfill
phase; existing development rows are filled by the migration itself.

**Kickoff (K) was November 14, 2026 (decided).** Work starts Monday, November 16, 2026; the dates below count from
there.

### 6.1 Requests

Each open item from §1.10, §2.11, §3.9 and §4.13 as a request. "Needed by" is the latest date that does not delay
what it blocks.

| # | Request | Owner | Provided by | Needed by | Blocks | Contract |
|---|---|---|---|---|---|---|
| R1 | Benchmark environment sized for 5M and 15M occurrences, then the effective-owner benchmark and query plan | Ownership lead | SRE (environment) | Environment: Mon Nov 23, 2026 (K+1 wk). Result: Fri Dec 4, 2026 | §3.8 index design, so V24; enabling occurrence registration outside test tenants; R6 | §3.8, §3.9 |
| R2 | Package-key normalization: do all `inventory_components` writers normalize `ecosystem`, `package_name`, `version` and `purl` the same way? Samples from SBOM, BOM orchestrator and CMDB host inventory; include whether CycloneDX `group` reaches `package_name` (§5.1; in scope, decided November 14, 2026) | Inventory lead | Inventory writer owners; sample tenants | Fri Nov 27, 2026 | Occurrence key sign-off; §3.8 index design, so V24 | §3.2, §3.9 |
| R3 | CBOM fingerprint stability: two re-exports of an unchanged crypto asset produce the same `component_fingerprint` | CBOM lead | CBOM sample sources | Fri Dec 4, 2026 | CBOM occurrence identity sign-off | §3.2, §3.9 |
| R4 | Representative ServiceNow instance: `sys_user*` fields (including custom `u_` fields) and ACLs, read-only account | Connector lead | A customer ServiceNow admin | Fri Dec 4, 2026 | Mapping and contract tests on real field shapes; enabling outside test tenants | §1.2, §1.10 |
| R5 | Representative cloud tag and label values for `owner` and `team`: share of emails versus team names, alias coverage after preview | Connector lead | A customer AWS and GCP tenant | Fri Dec 11, 2026 | Enabling cloud producers outside test tenants | §2.4, §2.11 |
| R6 | Campaign batch sizes: confirm the 5,000 create bound and the 1,000 reconciler batch on the R1 environment | Ownership lead | — (needs R1) | Mon Jan 4, 2027 | Enabling CVE campaigns outside test tenants | §4.2, §4.3, §4.13 |
| R7 | A customer AWS organization to test the Organizations role (management or delegated-admin account) | Connector lead | A customer AWS org | Fri Jan 8, 2027 | Enabling the AWS account input outside test tenants (resource tags are unaffected) | §2.2.1, §2.11 |
| R8 | A customer Jira for component, label or team-field mapping | Connector lead | A customer Jira | Fri Jan 22, 2027 | Jira routing beyond text. **Not a Release 2 blocker**; Release 3 input | §4.9, §4.13 |

Track each row with the date requested and the date received. A request not received by its date is raised at the
next lead review with the re-estimate it causes (plan §16.1).

### 6.2 Named leads

Release 2 work does not start until every role has a person (§5.4, plan §16.3). **Decided (November 14, 2026):** Scout
holds all five roles, so work runs one item at a time unless more people join.

| Role | Workstream (plan §16.1) | Person | §5 ledger rows | §6.1 requests | Confirmed on |
|---|---|---|---:|---|---|
| Ownership lead | Ownership/platform/backend | Scout | 5 | R1, R6 | November 14, 2026 |
| Connector lead | Connectors/data ingestion | Scout | 8 | R4, R5, R7, R8 | November 14, 2026 |
| Inventory lead | Connectors/data ingestion | Scout | 4 | R2 | November 14, 2026 |
| Workflow lead | Consumer APIs/frontend/workflows | Scout | 17 | — | November 14, 2026 |
| CBOM lead | Consumer APIs/frontend/workflows | Scout | 6 | R3 | November 14, 2026 |

### 6.3 Estimate template

**Decided (November 14, 2026):** Release 2 starts without the plan §16.1 estimate. The table below is kept as the
work breakdown and dependency order; the estimate columns are optional. Leads fill in estimate, staff and dates. Estimates are in engineer-weeks as a low–high range. "Depends on" lists
what must finish first; a request dependency (R*n*) only gates enablement outside test tenants unless the row says
otherwise.

| ID | Work item | Contract | Owner | Depends on | Estimate (eng-wk) | Staff | Start | Finish |
|---|---|---|---|---|---|---|---|---|
| E1 | Tenant V24: §1.8 `sys_id`, §2.9 settings, §3.8 occurrence columns and index, §4.11 campaign and ticket changes; `MigrationCatalogTest` and `TenantSchemaCompatibility` | §3.8, §4.11 | Ownership lead | — (hold lifted November 15, 2026; R1, R2 assumed, §6) | | | | |
| E2 | ServiceNow directory: identity-source service, directory client, sync job, linking rules, Sources and Mappings views | §1.1–§1.9 | Connector lead | — (V21); R4 | | | | |
| E3 | CMDB support-group `sys_id` kept with the name | §1.8 | Connector lead | E1 | | | | |
| E4 | ServiceNow producer reads ServiceNow-originated CIs only | §2.10 | Ownership lead | — | | | | |
| E5 | Cloud producer: `CloudOwnershipProducer`, scan completeness, GCP `projects.get`, per-tenant settings, interval validation | §2.1–§2.9 | Connector lead | E1; R5 | | | | |
| E6 | AWS Organizations reader and connection test | §2.2.1 | Connector lead | E1; R7 | | | | |
| E7 | Shared occurrence key across `inventory_components` writers; `registerOccurrences` | §3.2–§3.4 | Inventory lead | R2 (gating), E1 | | | | |
| E8 | `FindingSubjectAdapterRegistry`, v2 dark report, switch batch, occurrence retirement | §3.5, §3.6 | Ownership lead | E7 | | | | |
| E9 | CBOM occurrences and owner columns on BOM, CBOM and software identity screens | §3.2, §3.7 | CBOM lead | R3 (gating), E1, E8 | | | | |
| E10 | Campaign ledger: materialization, reconciler, snapshots, classifier, recipients, exceptions, backfill | §4.2–§4.8, §4.10 | Workflow lead | E1; R6 | | | | |
| E11 | Ticket routing: `TicketRoutingService`, attempts in `TicketingService`, override, preview hash | §4.9 | Workflow lead | E1 | | | | |
| E12 | ServiceNow and Jira provider changes on the routed group | §4.9 | Connector lead | E11 | | | | |
| E13 | CBOM campaigns, remediation queue and portfolio by owner team ID | §3.7, §4.12 | CBOM lead | E10 | | | | |
| E14 | Campaign and ticket frontend (§5.2 Workflow rows) | §4.5, §4.6, §4.9 | Workflow lead | E10, E11 | | | | |
| E15 | Read waves `CAMPAIGNS` and `TICKETS`; `CLOUD_BOM` eligibility | §2.6, §4.10 | Ownership lead | E5, E10, E11 | | | | |
| E16 | Tenant purge order under `RESTRICT`; directory preview audit | §1.6, §4.12 | Ownership lead | E1 | | | | |
| E17 | Release 2 qualification: provider failure, pagination, rate limit, anomaly, reconciliation, scorecards and rollback tests | plan §16.5 | Ownership lead | E2–E16; R4–R7 | | | | |

**Critical path (skeleton).** Leads confirm or replace it once E1–E17 have estimates:

1. **E1 V24** starts November 15, 2026 (hold lifted, §6). R1 (Dec 4) can only add an index-only V25; R2 (Nov 27)
   is checked by E7.
2. E1 → E7 → E8 → E9 (occurrences and CBOM).
3. E1 → E10 and E11 → E14 → E15 (campaigns and tickets).
4. Both paths → E17. Requests R4–R7 must arrive before E17 to enable anything outside test tenants.

E2 and E4 do not wait for V24 and can start at K.
