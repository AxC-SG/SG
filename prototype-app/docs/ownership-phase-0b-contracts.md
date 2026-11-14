# Ownership Phase 0B: Release 2 contracts

Status: draft for approval
Plan: [ownership-capability-mvp-plan.md](ownership-capability-mvp-plan.md) §16.3 (rolling contracts) and §16.5 (Release 2)
Built so far: [ownership-phase-0a-design.md](ownership-phase-0a-design.md) §8–§11

The plan requires four contracts before Release 2 begins. Each section states what is fixed, which existing schema and
code it builds on, and what stays **OPEN** until representative data or a person closes it. Open items are enforced in
code as disabled-by-default switches, as in Release 1.

| # | Contract | Section | Status |
|---|---|---|---|
| 1 | ServiceNow directory table/scope/identity-link | §1 | Draft |
| 2 | AWS/GCP producer fields, TTL and authority | §2 | Draft |
| 3 | BOM/CBOM occurrence identity and finding-adapter registry | §3 | Draft |
| 4 | Campaign/ticket materialization, outcomes and routing | §4 | Not started |

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

Directory people never gain Scoutgrid login, tenant membership or roles from a link (plan §3).

### 1.5 Paging, watermark and complete scans

- **Keyset paging, not offset.** The CMDB sync pages with `sysparm_offset`, which can skip or repeat rows when
  records change mid-run. The directory sync orders by `sys_updated_on` then `sys_id` and asks for rows after the last
  `(sys_updated_on, sys_id)` pair:
  `sys_updated_on>T^ORsys_updated_on=T^sys_id>ID^ORDERBYsys_updated_on^ORDERBYsys_id`.
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

### 1.6 Preview and first load

- Preview fetches counts per table and up to 10 sample rows per table with names and emails masked (first character
  plus domain), writes nothing and returns a preview token bound to the source version, the actor and the scope hash,
  valid for 30 minutes, like the CSV preview.
- Enabling a source requires a preview token from the current scope. The first complete run is the **baseline load**.

### 1.7 Anomaly pause

`OwnershipSourcePolicy.anomalous(changes, active)` is applied per table to the changes a run proposes, counting
updates, deactivations and membership removals; creates count only after the baseline. A run that trips it writes
nothing for that table, raises a `PRODUCER_ANOMALY` review item and pauses the source until an admin approves. The
first baseline load is exempt only from the percentage-based create check (plan §12.3), never from validation failures
or tenant quotas.

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
- **OPEN:** with the default connector fields, `support_group` comes only from the installed-software table's
  dot-walked `installed_on.support_group`, read with `sysparm_display_value=all`, and `CmdbInventoryIngestionRunner`
  stores the display value (the group name). The reference `sys_id` is not kept. `CmdbInventoryIngestionRunner` falls
  back to the raw field when no display value is present, so an admin-customised field list could store a `sys_id`
  instead. Using (1) needs the CMDB sync to store the name and the reference `sys_id` in separate columns; that is a
  CMDB connector change, scheduled with Phase B, with tests for both shapes.

### 1.9 Schema and code impact

- **No migration is expected.** Tenant V21 already has `identity_source` (`SERVICENOW` kind, encrypted credentials,
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
| CMDB `support_group` reference `sys_id` retained by the CMDB sync | Connector lead | Mapping-driven CMDB resolution (§1.8) |
| Masking rule for preview samples | Security review | Preview UI sign-off |

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
| AWS | Account (`CLOUD_ACCOUNT` subject) | Account tags `owner`, `team` | `CLOUD_STRUCTURED` (3) | **OPEN**: AWS Organizations `ListTagsForResource`, callable only from the management or a delegated-admin account (§2.11) |
| GCP | Compute Engine VM (`HOST`) and other resources (`CLOUD_RESOURCE`) | Labels `owner`, `team` | `CLOUD_TAG` (5) | `assets.cloud_tags_json`, already written by `GcpResourceIngestionService` |
| GCP | Project (`CLOUD_ACCOUNT` subject) | Project labels `owner`, `team` | `CLOUD_STRUCTURED` (3) | Resource Manager `projects.get` during the discovery run; `resourcemanager.projects.get` is in `roles/browser`, already required, and `cloudresourcemanager.googleapis.com` is already allow-listed for `gcp` |

- **Keys.** Only `owner` and `team` are read. AWS tag keys are matched case-insensitively after trimming; GCP labels
  are lowercase by definition. Every other tag or label is ignored for ownership and stays inventory evidence only.
  If a resource carries both keys, each is its own claim. When they map to different teams, the resolver reports
  `CONFLICT`, as plan §6.9 requires.
- Admin settings (`CONFIGURE_OWNERSHIP_PRODUCER`) can switch off a key or the account-level input per provider. A
  per-tenant custom key list is **not** in MVP.
- Reading project labels adds one `projects.get` per configured project per run, through `OutboundHttpClient`
  (provider `gcp`). A failed call leaves that project's account claims untouched for the run (§2.5).

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

- **No migration is expected.** Tenant V22 already allows `AWS`/`GCP` claims with `CLOUD_STRUCTURED`/`CLOUD_TAG`
  priority classes, `CLOUD_ACCOUNT` subjects, `OWNERSHIP_PARENT` edges, and the `UNMAPPED_VALUE`,
  `INHERITANCE_ERROR` and `PRODUCER_ANOMALY` review types. Tenant V21 allows `AWS`/`GCP` alias provenance. Platform
  V16 has `CLOUD_BOM` authority and `AWS`/`GCP` kill switches. The per-provider key and account toggles (§2.2) fit an
  application setting. If they must be stored per tenant, that needs tenant V24 columns on
  `aws_discovery_configs`/`gcp_discovery_configs`.
- New code (Phase B): `CloudOwnershipProducer` (one class, provider strategy for AWS/GCP) called from
  `AwsDiscoverySyncService` and `GcpDiscoverySyncService` after commit, never failing the sync; scan-completeness
  output from both ingestion services; GCP `projects.get` label read; the `CLOUD_BOM` eligibility flag in
  `OwnershipResolutionService`; the switch-time re-resolution enqueue; connector interval validation; and the hub's
  Sources view rows for AWS/GCP.
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

### 2.11 Open items

| Item | Owner | Blocks |
|---|---|---|
| AWS account owner: Organizations read role (management or delegated admin), `organizations:ListTagsForResource`, and a customer org to test against | Connector lead + a customer org | AWS `CLOUD_STRUCTURED` claims (off until closed; AWS resource tags are unaffected) |
| Representative tag/label values: share of emails vs team names, and alias coverage after preview | Connector lead + a customer tenant | Enabling outside test tenants |
| ServiceNow producer `cis` source filter (§2.10) | Ownership lead | None (fix with Phase B) |

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

### 3.7 Aggregates and reads

- Software identity and global package views show owner-team coverage across occurrences (`1 team`, `3 teams`,
  `Unowned occurrences`), counted by stable team ID. An aggregate with several teams displays `MULTIPLE_TEAMS`, which
  is presentation only and never stored (plan §6.12, §9.6).
- Owner filters on BOM and CBOM lists use `ownerTeamId` on occurrences, through the link columns and the effective
  view, under the same domain gate as Release 1 reads.
- Assign owner on an occurrence previews its affected findings and never applies to every occurrence of a package.

### 3.8 Schema and code impact

- **Tenant V24 is needed.** It adds nullable `ownership_subject_id` columns, each with a tenant-inclusive foreign key
  to `ownership_subject` and a partial index, on `inventory_components` and `cbom_components`. If the §2.9 per-tenant
  producer settings are approved, they go in the same V24. `MigrationCatalogTest` and `TenantSchemaCompatibility`
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
| Full-size effective-owner benchmark with 5M/15M occurrences (Release 1 open item; occurrences now exist for real) | Ownership lead | Enabling occurrence registration outside test tenants |
| Do all `inventory_components` writers normalize `ecosystem`, `package_name`, `version` and `purl` the same way? Confirm against SBOM, BOM orchestrator and CMDB host inventory samples | Inventory lead | Occurrence key sign-off |
| Is `component_fingerprint` stable across CBOM re-exports of an unchanged crypto asset? | CBOM lead | CBOM occurrence identity sign-off |
| CBOM crypto → containing software component edges | Product owner | Nothing in Release 2 (crypto inherits from the asset) |
