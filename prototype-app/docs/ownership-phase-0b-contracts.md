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
| 2 | AWS/GCP producer fields, TTL and authority | §2 | Not started |
| 3 | BOM/CBOM occurrence identity and finding-adapter registry | §3 | Not started |
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
