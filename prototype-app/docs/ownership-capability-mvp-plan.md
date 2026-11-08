# Scoutgrid Identity and Ownership MVP Execution Plan

Status: implementation planning baseline  
Audience: product, architecture, backend, frontend, security, SRE, QA and connector teams  
Related target-state plan: `docs/ownership-capability-final-plan.md`

## 1. Executive decision

Scoutgrid will deliver an identity-aware ownership MVP that imports people and groups, resolves asset ownership from enterprise and cloud sources, and projects the resolved owner onto findings, campaigns and tickets.

The MVP is a clean replacement of the current free-text ownership implementation. There are no customers whose ownership rules, `owner_group` values, saved owner filters or AI Grid owner history must be preserved. Expand/contract deployment steps and temporary compatibility readers are retained only for release safety; they are not a data-migration or legacy-product commitment.

The MVP includes:

- Canonical directory users, external groups, group memberships and Scoutgrid ownership teams.
- Manual creation and CSV import of users, groups and memberships.
- ServiceNow user, group and membership synchronization plus CMDB ownership evidence.
- Microsoft Entra ID and Okta directory synchronization.
- Multiple ownership producers: ServiceNow CMDB, AWS, GCP and AI Grid.
- Canonical group-to-team and alias-to-team mappings.
- Ownership claims, deterministic fixed-precedence resolution and explanations.
- Manual subject ownership overrides with reason and optional expiry.
- Ownership review for unmapped values, identity ambiguity, conflicts and inactive owners.
- Resolved ownership in inventory, findings, saved queues, campaigns and ticket creation.
- Multi-team ownership coverage in CVE investigations, with lead/coordinator kept separate from affected owner teams.
- Occurrence-scoped ownership for SBOM/container/application components and CBOM cryptographic components.
- Common ownership for AI systems, AI artifacts, AI-BOM resources and AI posture/exposure findings. AI runtime findings remain explicitly out of scope.
- Preservation and ownership integration of exception requests, false-positive decisions, accepted risk, direct suppression, suppression rules, expiry and reopening.
- Mandatory tenant isolation, PII encryption, connector security, auditing and operational controls.

The MVP does not include tenant-authored policy language, complex approval workflows, arbitrary topology, SLA/escalation workflows or extended directory providers. Section 21 records all deferred capabilities, their prerequisites and the signal for starting them.

## 2. MVP outcome and success definition

The MVP proves this complete user outcome:

> A tenant administrator imports people and groups from manual entry, CSV, ServiceNow, Entra or Okta; maps external groups and source values to canonical Scoutgrid teams; enables ServiceNow and cloud ownership producers; and sees one explainable owner team consistently on an inventory subject, its findings, campaign items and tickets.

The MVP is complete only when all of the following are true:

1. A user, group and membership can be created manually and imported through CSV.
2. ServiceNow imports users, groups and memberships from approved tables and emits CMDB ownership claims.
3. Entra and Okta synchronize users, groups and memberships from authorized test tenants.
4. AWS and GCP emit ownership claims from approved account/project fields and reviewed tags or labels.
5. Existing AI Grid owner signals emit common ownership claims rather than using an independent owner store.
6. External groups and textual source values resolve only through reviewed mappings to stable team IDs.
7. Fixed precedence deterministically produces `OWNED`, `UNOWNED` or `CONFLICT`.
8. Inventory displays resolved ownership separately from raw source evidence.
9. Findings derive ownership from a canonical subject and never use free-text `owner_group` as authority.
10. BOM component ownership is scoped to an occurrence and never fabricates one owner for a global package identity.
11. AI inventory and AI findings use the common ownership model with no independent AI owner authority.
12. Suppression, false-positive and accepted-risk workflows remain independent of ownership while retaining an owner-team snapshot for audit.
13. Every campaign type materializes stable finding membership and keeps owner-at-add separate from current ownership.
14. CVE investigations show all affected owner teams, Unowned and Conflict without assigning one owner to the CVE.
15. Saved queues and tickets use stable team IDs; mixed-team ticket routing is explicit.
16. Failed or partial source synchronization cannot mass-deactivate identities, memberships, subjects or claims.
17. Cross-tenant access, cross-tenant foreign keys and tenantless background work are rejected.
18. PII and connector secrets are encrypted before the first identity source is enabled.
19. Imports, mappings, manual assignments, unmasked reads and connector configuration changes are audited.
20. Section 13 SLO/product-quality targets and section 18 release gates pass at expected and three-times-expected tenant size.

## 3. Product and architecture boundaries

### 3.1 Concepts that must remain separate

| Concept | Purpose | Must not imply |
|---|---|---|
| Directory user | A person observed manually, by CSV or from a directory provider | Scoutgrid login access or product role |
| External group | A provider-scoped collection of directory users | A canonical ownership team |
| Ownership team | Stable Scoutgrid unit used for ownership, filtering, routing and ticket mapping | Directory membership or product authorization |
| Scoutgrid application user | A principal authorized to sign in and perform product actions | Directory ownership merely because identities match |
| Ownership claim | Source observation asserting a team or person owns a subject | Current resolved assignment |
| Ownership assignment | Persisted deterministic result of direct claims for a subject and role | Copied rows on every inheriting descendant or finding |
| Effective ownership | Direct assignment when present, otherwise bounded fallback through one parent chain | A separate writable authority |
| Finding assignee | Person actively working a finding | Accountable owner team |

Directory users and external groups never grant Scoutgrid login, tenant membership or roles. Application authorization continues through the existing Scoutgrid identity and tenant-membership model.

### 3.2 Canonical ownership flow

```text
Manual / CSV / ServiceNow / Entra / Okta
                    |
                    v
       Users, groups and memberships
                    |
                    v
       External group -> team mappings

ServiceNow CMDB / AWS / GCP / AI Grid / manual override
                    |
                    v
             Ownership claims
                    |
                    v
       Fixed deterministic resolver
                    |
                    v
        Subject ownership assignment
                    |
        +-----------+------------+-------------+
        |           |            |             |
     Inventory   Findings    CVE coverage  Campaigns/tickets
```

### 3.3 MVP ownership role

The schema supports a role discriminator, but the MVP UI and resolver expose only:

```text
TECHNICAL_OWNER
```

Business owner, data owner, model owner and security owner are deferred until customers validate the need for independent roles.

## 4. Required scope and explicit exclusions

### 4.1 Required MVP capabilities

| Area | Required capability |
|---|---|
| People | Create, update, deactivate, reactivate, search and view provenance |
| Groups | Create, update, deactivate, reactivate, search and view provenance |
| Memberships | Add/remove manually and synchronize from providers |
| CSV | Templates, dry run, validation, idempotent import and error download |
| ServiceNow directory | Users, groups and memberships |
| ServiceNow CMDB | Support group, owner team and approved person/group fields as claims |
| Entra | Microsoft Graph users, groups, memberships and delta synchronization |
| Okta | Users, groups, memberships, pagination and incremental synchronization |
| Teams | Canonical team administration and source aliases |
| Mappings | External group to team and textual alias to team |
| Cloud producers | AWS and GCP ownership claims; AI Grid common claims |
| Resolution | Fixed precedence, expiry, conflict and unowned behavior |
| Manual ownership | Team assignment to subject with reason and optional expiry |
| Review | Unmapped value, ambiguous identity, conflict and inactive owner |
| Inventory | Resolved owner, evidence, filters, coverage and assignment action |
| BOM/CBOM | Occurrence-scoped ownership, inheritance, coverage and finding derivation |
| AI inventory/AI-BOM | Common assignments for AI systems, artifacts, models, data/knowledge and MCP resources |
| AI findings | Canonical target ownership for posture and exposure findings; runtime remains excluded by repository scope |
| Findings | Subject-derived owner, owner filters and explanation |
| Exception management | Preserve direct/requested suppression, false positive, accepted risk, expiry, reopening and CBOM governance |
| Suppression rules | Preserve existing rule lifecycle while prohibiting ownership-dependent predicates in MVP |
| Campaigns | Stable owner team display, grouping and unowned/conflict buckets |
| Tickets | Team-to-ticket-assignment-group mapping |
| Security | Tenant isolation, KMS, masking, auditing, SSRF and upload safety |
| Operations | Health, cursors, retries, reconciliation, anomaly pause and kill switches |

People and memberships remain required because they are an explicit product requirement for manual/CSV/ServiceNow/Entra/Okta administration and provide assignee/profile evidence. They do not automatically grant application access, create teams or participate in ownership precedence. Workflow assignees/leads are active Scoutgrid application principals, optionally linked to directory people for display.

### 4.2 Not part of MVP

- Conversion or preservation of existing ownership rules and free-text owner values.
- Tenant-defined ownership policy language.
- Permanent per-finding ownership independent of the finding's subject.
- Multiple ownership roles in the UI.
- Multi-parent tenant-authored topology.
- Second-admin approval for normal changes.
- Automatic SLA clocks, accept/reject workflow and escalation hierarchy.
- LDAP/AD, Ping, Google Workspace, OneLogin and JumpCloud.
- Azure Resource Graph ownership producer unless separately approved; Entra is an identity provider, not an Azure resource inventory provider.
- CODEOWNERS and repository ownership.
- Tenant-configurable audit retention.

## 5. Personas and authorization

| Action | `TENANT_ADMIN` | `INVENTORY_ADMIN` | `SECURITY_ANALYST` | Read-only tenant role | `SERVICE_ACCOUNT` |
|---|---:|---:|---:|---:|---:|
| View resolved team ownership | Yes | Yes | Yes | Yes | No interactive access |
| View masked directory identity | Yes | Yes | Yes | If product policy permits | No |
| Create/update users and groups | Yes | No | No | No | Bound import only |
| Run CSV identity import | Yes | No | No | No | No |
| Configure ServiceNow/Entra/Okta | Yes | No | No | No | No |
| Configure cloud ownership producer | Yes | Yes | No | No | No |
| Create/update teams and aliases | Yes | Yes | No | No | No |
| Map external group to team | Yes | Yes | No | No | No |
| Create manual subject assignment | Yes | Yes | Only for assigned workflow scope; mandatory reason and alert | No | No |
| Set campaign/CVE lead or coordinator | Yes | No | Yes within workflow scope | No | No |
| Export owner-team notification drafts | Yes | No | Yes within workflow scope | No | No |
| Override external ticket routing | Yes | Yes | Yes with reason | No | No |
| Resolve/dismiss review item | Yes | Yes | Acknowledge only | No | No |
| Unmask PII | Restricted tenant admin action, audited | No | No | No | No |
| Ingest claims | No | No | No | No | Bound producer only |
| Disable a source or kill switch | Yes | Yes for inventory sources | No | No | No |

Every new controller method requires explicit method authorization and an authorization-matrix integration test. Wrong-tenant identifiers return 404 rather than revealing existence.

For MVP, `SECURITY_ANALYST` **assigned workflow scope** permits one subject per request, chosen from either (a) the canonical subject of a finding currently assigned to that application principal or (b) the current affected-subject set of a CVE investigation for which that principal is the active lead. The server derives and validates this relationship; a client-supplied subject ID is insufficient. Analyst-created manual claims require a reason, expire within 30 days, cannot be bulk operations and emit the alert in section 6.10. They are allowed only when impact preview reports at most 100 effective descendants and 1,000 affected findings; larger/high-level assignments require `TENANT_ADMIN` or `INVENTORY_ADMIN`. These are platform maximums for analysts and tenants may configure lower values.

## 6. Functional workflows

### 6.1 Tenant onboarding

1. Tenant admin opens **Ownership & Directory**.
2. The product blocks identity-source enablement until KMS, tenant key and PII readiness checks pass.
3. Admin creates or imports canonical teams.
4. Admin creates aliases for expected ServiceNow and cloud values.
5. Admin creates people/groups manually or imports CSV.
6. Admin connects ServiceNow, Entra and Okta and runs preview synchronization.
7. Admin reviews counts, field mappings, ambiguities and rejected records.
8. Admin enables approved identity sources.
9. Admin connects ownership producers and previews claim coverage.
10. Admin resolves unmapped values and group-to-team mappings.
11. Admin enables ownership publication.
12. The resolver publishes assignments and projects them to inventory and findings.

### 6.2 Manual people and group administration

1. Admin opens **People** or **Groups**.
2. Admin creates a record with stable Scoutgrid ID and required display fields.
3. The service checks tenant-scoped identifiers across manual and provider-linked identities.
4. Admin adds or removes memberships.
5. The service audits before/after references without writing sensitive values into audit payloads.
6. Deactivation makes person-target claims ineligible; it never deletes historical references.
7. Reactivation is allowed only for the same canonical identity.
8. Merge and destructive identity consolidation are not automated in MVP; ambiguity becomes a review item.

### 6.3 CSV import

Supported templates:

- `users.csv`: `external_id`, `display_name`, `email`, `manager_external_id`, `status`.
- `groups.csv`: `external_id`, `display_name`, `status`.
- `memberships.csv`: `group_external_id`, `user_external_id`, `operation`.
- `teams.csv`: `name`, `parent_team`, `ticket_assignment_group`.
- `team_aliases.csv`: `source_kind`, `alias`, `team_name`.

Workflow:

1. Admin downloads the current versioned template.
2. Admin uploads a bounded UTF-8 CSV file.
3. Backend scans file type, size, encoding, headers, formula prefixes and row limits.
4. A dry run produces valid, warning, duplicate, ambiguous and rejected counts.
5. No data changes during dry run.
6. Admin confirms a dry-run token bound to file hash, tenant, importer and expiry.
7. Durable work imports valid rows idempotently in bounded batches.
8. UI displays progress and allows download of row-level errors.
9. A failed batch retries safely; replay does not duplicate records or memberships.
10. MVP supports compensating deactivation of records created by an import, not arbitrary historical rollback of provider-owned records.

CSV values beginning with `=`, `+`, `-` or `@` are escaped in exports and never evaluated. Zip files, macros and embedded formulas are not accepted.

### 6.4 ServiceNow identity and CMDB workflow

Phase 0A must validate representative ServiceNow-specific fields. Initial contract:

| Data | Initial source |
|---|---|
| Users | `sys_user` |
| Groups | `sys_user_group` |
| Memberships | `sys_user_grmember` |
| Asset technical owner | CMDB `support_group` |
| Asset owner team | Approved CMDB `owner_team`/department field |
| Person evidence | Approved `managed_by`/`owner_email` field |

Workflow:

1. Admin configures a dedicated ServiceNow integration account and instance host.
2. Connection validation checks TLS, host allow-list, credentials and minimum table permissions.
3. Admin chooses approved tables, filters and attribute mappings.
4. Preview fetches counts and samples with PII masked.
5. Initial sync imports users, groups and memberships with provider external IDs.
6. CMDB ingestion emits ownership claims from approved fields.
7. Group/person values resolve only through exact provider identity, team name or source alias.
8. Unmatched values create deduplicated review items; they never create teams automatically.
9. Incremental sync uses an approved watermark such as `sys_updated_on` plus stable tie-breaker.
10. Deactivation or absence is applied only after a complete authoritative scan; partial/failed scans never deactivate.

### 6.5 Entra workflow

1. Tenant admin authorizes or configures a tenant-scoped Microsoft Graph application.
2. Connection validation checks tenant, client, granted scopes and Graph host.
3. Admin selects permitted users/groups and allow-listed attributes.
4. Preview shows counts and expected changes.
5. Initial sync imports users, groups and memberships.
6. Subsequent sync uses Graph delta tokens.
7. Expired delta tokens trigger a controlled full resync without mass deactivation until completion.
8. Ambiguous identity links create review items; mutable identifiers never cause destructive automatic merges.
9. Provider throttling honors retry headers and bounded backoff.

### 6.6 Okta workflow

1. Tenant admin configures an Okta organization and scoped API credential/OAuth application.
2. Host, TLS and permissions are validated.
3. Admin selects group/user scope and allow-listed attributes.
4. Preview shows counts and changes.
5. Initial sync follows pagination links only for the validated Okta host.
6. Incremental synchronization uses supported provider watermarks/events with scheduled reconciliation.
7. Membership removal and deactivation are applied only from complete authoritative results.
8. Rate limits, retry and cursor state are visible in source health.

### 6.7 Team and mapping workflow

1. Admin creates a canonical team or imports teams.
2. Team name and every alias share one tenant-wide normalized namespace, regardless of alias source. Source kind is provenance, not a uniqueness scope.
3. All team-name and alias writes use one transactional service, tenant-scoped advisory lock and cross-table recheck.
4. External groups are mapped to teams explicitly.
5. Text values from CMDB/cloud sources map through exact normalized team name or alias.
6. No fuzzy matching and no automatic team creation.
7. Reassigning an alias or group mapping republishes affected claims and assignments.
8. Mapping change shows affected subjects/findings before confirmation and records an audit event.

### 6.8 Ownership producers

| Producer | MVP inputs | Authority |
|---|---|---|
| Manual | Explicit subject-to-team assignment | Highest |
| ServiceNow CMDB | Approved support group/owner team fields | Authoritative enterprise source |
| AWS | Account owner field; reviewed `owner`/`team` resource tags | Account structured value above resource tag |
| GCP | Project owner field; reviewed `owner`/`team` labels | Project structured value above resource label |
| AI Grid | Existing verified AI ownership observations | Common claim, not separate owner state |
| Entra/Okta | Explicitly configured ownership attribute/group only | Optional enrichment below CMDB/cloud structured fields |

Each producer:

- Is bound to one tenant and registered source.
- Uses an idempotency key containing tenant, producer, subject, role, source reference and observation version.
- Emits mapped claims only; unresolved values live in review items.
- Publishes in bounded batches.
- Has source-specific anomaly limits and a kill switch.
- Cannot write assignments or finding projections directly.

### 6.9 Fixed MVP resolution

The MVP uses fixed precedence rather than tenant-authored rules:

| Priority | Eligible claim |
|---:|---|
| 1 | Active manual subject assignment |
| 2 | ServiceNow authoritative group/team field |
| 3 | Cloud account/project structured owner |
| 4 | AI Grid verified authoritative AI system/artifact owner observation |
| 5 | Reviewed cloud resource tag/label |
| 6 | Explicitly configured Entra/Okta ownership attribute |

Resolution algorithm:

1. Load current **direct** claims for `(tenant, subject, TECHNICAL_OWNER)`.
2. Exclude expired, superseded, unmapped, inactive-target and disabled-source claims.
3. If any eligible direct claims remain, select the highest direct priority. Direct subject specificity wins before considering any ancestor: for example, a reviewed cloud tag directly on an occurrence wins over a manual claim inherited from its application parent.
4. If all winning direct claims map to one team, return `OWNED`; if they map to different teams, return `CONFLICT` and do not route automatically.
5. If no eligible direct claim remains, follow the single `OWNERSHIP_PARENT` edge and evaluate that parent's effective result. Continue for at most six parent hops, covering the current longest expected occurrence → image → host → cloud resource → account → application chain with one reserved hop; cycle, missing-parent or depth overflow returns `CONFLICT`/review rather than guessing.
6. An inherited `OWNED` or `CONFLICT` result retains the originating subject, assignment and inheritance path in the explanation. If no ancestor has an eligible direct result, return `UNOWNED`.
7. Persist `ownership_assignment` only for subjects with direct claim inputs. Effective inherited ownership is resolved through the bounded parent join/view and is not materialized onto every descendant.
8. Save the direct winning claim/team/status, resolver version, input watermark, reason and resolved time.
9. Emit an ownership event only when the direct result or explanation-relevant inputs change. Do not enqueue descendant-wide assignment rewrites. If the optional effective cache is selected, bounded ID-only cache invalidation/refresh is permitted under section 7.5 and is not an assignment or display-name rewrite.
10. Idempotent replay of unchanged inputs produces zero assignment writes.

Within one priority, newest observation does not silently defeat a contradictory current claim. Contradictions at the winning priority are visible conflicts. Inheritance is fallback-only: an eligible direct claim of any priority is more specific than an inherited claim of any priority.

### 6.10 Manual subject assignment

1. Authorized user opens an asset or subject detail page.
2. User selects **Assign owner**.
3. Team picker returns canonical teams by stable ID.
4. User enters mandatory reason and optional expiry.
5. System previews directly affected findings and counts only descendants whose effective result would actually change because they have no eligible direct claim before reaching this parent. It does not materialize descendant assignments.
6. User confirms; no second-admin approval is required in MVP.
7. Service creates a manual ownership claim and audit event.
8. A `SECURITY_ANALYST` assignment emits a security/audit alert with actor, subject, previous team, new team, reason and expiry; tenant/inventory admins may review or revoke it. Analysts cannot bulk-assign or change topology/mappings.
9. For an analyst, the service rejects the mutation if the server-derived scope check fails or the preview exceeds 100 effective descendants or 1,000 affected findings. Admins use the separately authorized high-impact path.
10. Resolver updates the direct assignment, invalidates bounded caches and lets effective-owner joins expose the change immediately.
11. Expiry or revocation triggers re-resolution to the next eligible claim or `UNOWNED`.

MVP parent assignment is fallback ownership, not a forced subtree override. A child with any eligible direct claim—including a stale-but-not-expired claim—keeps that direct result. Forced subtree override is not supported; the preview must say so and separate `would change`, `blocked by direct claim`, `conflict` and `already effective` counts.

### 6.11 Finding ownership

Each finding adapter returns exactly one of:

- `CANONICAL_SUBJECT(subject_id)`.
- `OWNERSHIP_CONFLICT` when primary subjects resolve to different teams.
- `UNOWNED` when no valid subject/assignment exists.

Initial adapters:

| Finding kind | Canonical subject |
|---|---|
| `VULNERABILITY` | Release 1: affected asset. Release 2 after occurrence-domain cutover: contextual BOM/CBOM component occurrence when eligible, otherwise affected asset |
| `AI_POSTURE` | Evaluated AI system or canonical AI artifact such as model, endpoint, agent, dataset or knowledge base |
| `AI_EXPOSURE` | Exposure-target AI system/artifact; intermediate path nodes are explanation evidence only |

`AI_RUNTIME` has no MVP adapter and is not a release gate. The repository's `AiRuntimeScope` continues to reject runtime ingestion/read paths with `RUNTIME_OUT_OF_SCOPE`; enabling runtime remains a startup failure. Static endpoint/deployment artifacts can still be ownership subjects without implying runtime telemetry or runtime findings.

Versioned vulnerability-adapter rollout:

- Release 1 adapter v1 selects the affected asset subject only, even when component-occurrence data exists, because the occurrence domain is not canonical yet.
- Release 2 adapter v2 may select the contextual BOM/CBOM occurrence only after that subject family/domain is `CANONICAL` and its occurrence identity contract passes.
- The v2 rollout runs dark comparison and impact preview, then updates each finding's canonical subject idempotently. It never returns an occurrence from a `LEGACY`/`DARK` domain and never creates duplicate findings.

Adapter rules:

1. A finding must not use a global package/software identity as its owner merely because the package name or PURL matches.
2. A component subject means an occurrence inside a host, image, application or other deployment context.
3. Several occurrences with the same resolved team produce that team.
4. Several primary occurrences/targets with different resolved teams produce `OWNERSHIP_CONFLICT`.
5. Secondary assets, exposure-path nodes and supporting AI artifacts appear in the explanation but do not silently change the canonical subject.
6. A tombstoned/removed canonical subject produces `UNOWNED` with a subject-removed explanation until correlation selects a valid replacement.

The finding read path joins the selected subject to its effective direct-or-inherited assignment. The finding projection stores the canonical subject ID and exception/workflow facts, not a copied owner name. It does not independently execute ownership rules or scan provider data. Permanent ownership is changed on the subject, not on each finding. A temporary finding-only override is deferred.

### 6.12 BOM component and AI inventory ownership

#### BOM component occurrences

Ownership attaches to a component occurrence, not to the source-neutral software identity shared across the tenant.

```text
Application / repository / cloud account
                    |
                    v
        Host / container image / asset
                    |
                    v
          BOM component occurrence
                    |
                    v
     Vulnerability or cryptographic finding
```

MVP rules:

- Each component occurrence has exactly one ownership parent for a given inventory context.
- If the same package appears in three assets, Scoutgrid creates or identifies three contextual occurrences even when all reference one normalized software identity.
- Container occurrences are scoped to immutable image digest; a mutable tag alone is not a stable ownership key.
- A direct manual claim on the occurrence wins according to normal precedence.
- Without a direct eligible claim, the occurrence inherits the resolved assignment from its one ownership parent.
- SBOM components normally inherit from image, host or application.
- CBOM cryptographic components normally inherit from the containing component, host or application unless directly assigned.
- A global software identity page aggregates occurrences and may show several owner teams; it must not manufacture one global owner.
- An aggregate with several teams displays `MULTIPLE_TEAMS` for presentation, while each occurrence remains deterministically `OWNED`, `UNOWNED` or `CONFLICT`.

Initial BOM subject mapping:

| Inventory object | Ownership subject behavior |
|---|---|
| Normalized software identity/PURL/CPE | Reference identity only; not an authoritative ownership target in MVP |
| Host-installed component | Occurrence subject; inherits from host/application |
| Container component | Occurrence subject keyed by image digest plus component identity |
| Application SBOM component | Occurrence subject; inherits from application |
| CBOM cryptographic component | Occurrence subject; inherits from containing component/asset/application |
| AI-BOM model | Canonical AI model artifact subject |
| AI-BOM dataset/knowledge source | Canonical AI data/knowledge artifact subject |
| AI-BOM dependency | Inherits from owning AI system/artifact unless registered as a directly ownable artifact |

#### AI inventory

All AI inventory types use the common subject, claim and assignment model:

| AI inventory type | MVP ownership behavior |
|---|---|
| AI system/application | Direct claim or simple parent application/team inheritance |
| Model | Direct claim or inherit from containing AI system |
| Agent | Direct claim or inherit from containing AI system/application |
| Endpoint/deployment | Direct claim or inherit from AI system/cloud account/asset |
| Knowledge base | Direct claim or inherit from AI system |
| Dataset/data source/data store/search index | Direct claim or inherit from owning AI system |
| MCP server/gateway/target | Direct claim or inherit from AI system/application |
| Provider account/subscription/project | Structured account/project ownership claim |

AI Grid becomes a producer and consumer of the common ownership model. It must not maintain a second authoritative owner state. Qualified current verified signals are republished as new AI Grid source claims. Legacy owner-confirmation/history rows are not converted or preserved, and no legacy row is automatically elevated to a manual claim. AI inventory lists/details read common effective assignments.

### 6.13 Campaign and ticket workflow

- `campaign_findings` is the canonical membership ledger for every campaign type, including campaigns created from CVE scope. `campaign_vulnerabilities` remains a scope definition, not a substitute for materialized finding membership.
- Campaign creation materializes the currently matching findings into `campaign_findings`. A bounded, idempotent reconciler may add findings discovered later for a continuing CVE scope; it must never silently remove historical members.
- Every campaign member records the finding ID plus `owner_team_id_at_add`, `ownership_assignment_id_at_add` and `ownership_status_at_add`. Current ownership is read from the finding projection and is never copied over the historical snapshot.
- Campaign grouping, search, filters, counts and exports use stable team ID, not team display name. A team rename cannot split one campaign bucket into two.
- `UNOWNED` and `CONFLICT` are first-class campaign buckets.
- Campaign launch does not accept free-text owner group.
- A campaign may select a canonical campaign assignee principal or coordinating team, but neither changes subject/finding ownership.
- Campaign notify groups reference canonical `team_id` and the team's configured notification/ticket channel. Any custom recipient is explicitly typed `CUSTOM`, separately authorized and never treated as ownership evidence.
- Campaign exceptions reference stable `finding_id`. A campaign exception is campaign-local workflow state and does not suppress or change the canonical finding unless the user invokes the separately authorized finding-exception action.
- Campaign progress distinguishes remediated, suppressed, false positive, accepted risk, campaign-excepted, reopened and open. Suppressed/false-positive/accepted-risk findings are terminal for active-remediation work only under the documented metric, not relabeled as remediated.
- Replace the current boolean resolved test with an explicit outcome classifier; `SUPPRESSED` and `AUTO_CLOSED` caused by an exception must not increment the remediated count.
- Ticket creation reads the current canonical owner team and maps it to `team.ticket_assignment_group`.
- If the team lacks a ticket mapping, the UI requires an explicit configured default or user selection; it never sends the Scoutgrid display name as an assumed ServiceNow group.
- Conflict findings are not auto-routed. The user must resolve ownership or explicitly choose a ticket group with an audit reason.

### 6.14 Exception, false-positive and suppression integration

Ownership answers who is accountable. Exception management answers why remediation is not currently required. They are independent state machines.

MVP preserves:

- Direct finding suppression where existing role/severity policy permits it.
- Suppression requests and approval/rejection workflows.
- False-positive decisions with mandatory justification.
- Accepted-risk decisions with business justification, compensating controls and expiry where required.
- Under-investigation and reopen actions.
- Automated suppression rules, rule reversal and expiration reopening.
- Organization-wide CVE suppression as a separate explicit action.
- Existing CBOM/cryptographic-finding exception controls, including stricter critical/unknown-severity behavior.

Interaction rules:

1. Suppression, false positive or accepted risk never clears ownership claims or assignments.
2. Ownership changes never suppress, reopen, close or change the decision state of a finding.
3. Suppressed findings continue to resolve current ownership through their canonical subject/effective-assignment join.
4. Expiration/reopening reads the current assignment; it does not restore historical owner text.
5. A removed canonical subject changes ownership to `UNOWNED` while preserving exception history.
6. Ownership conflict/unowned does not invalidate an authorized exception request, but it prevents automatic owner-based routing and raises/retains ownership review.
7. Exception events record `owner_team_id` and `ownership_assignment_id` effective at request/decision time for non-PII audit context.
8. Current ownership and the historical owner snapshot are displayed separately.
9. AI, vulnerability, SBOM/CBOM and AI-BOM findings use the same canonical exception lifecycle unless a documented severity/type policy is stricter.
10. AI-BOM reconciliation and ownership projection never mutate finding suppression or decision state.

Automated suppression-rule boundary for MVP:

- Preserve the existing suppression-rule engine, lifecycle, condition builder, expiry/reopen and reversal behavior.
- Remove only the legacy ownership-rule engine and Ownership Rules UI; do not delete shared condition-matching code required by suppression.
- Suppression predicates may use the existing approved non-ownership finding/risk fields.
- Suppression predicates must not use `ownerGroup`, `ownerTeamId`, `ownershipStatus`, raw `supportGroup` or assignee identity during MVP.
- Existing/demo suppression rules using ownership text may be deleted and reseeded because there are no customers.
- Since ownership is not a suppression predicate, assignment changes do not trigger suppression-rule reevaluation in MVP.
- Owner-aware automated suppression is deferred until targeted reevaluation, impact preview and rollback are implemented.

Campaign and ticket behavior:

- New active-remediation campaigns exclude suppressed/false-positive/accepted-risk findings by default unless the creator explicitly includes them.
- A campaign item later suppressed remains for history and is labeled with exception type and expiry.
- Campaign outcome counts separate remediated, suppressed, false positive, accepted risk, reopened and still open.
- Ticket lifecycle remains governed by its existing integration policy; ownership changes alone do not close tickets, and suppression does not change owner assignments.

### 6.15 CVE investigation ownership workflow

A CVE is threat intelligence, not a single ownable tenant subject. One CVE can affect many component occurrences, assets and owner teams. The workbench must not choose the first matched asset, software identity or support-group string as the CVE owner.

Required workflow:

1. The analyst opens a CVE. The workbench resolves each matched occurrence/finding through its registered canonical subject and displays current `OWNED`, `UNOWNED` or `CONFLICT` state.
2. The header shows a lead analyst (`lead_principal_id`) and, when needed, an optional coordinating team (`coordinating_team_id`). These coordinate the investigation and do not replace affected-subject ownership.
3. The impact view groups affected occurrences and findings by stable owner-team ID, with separate Unowned and Conflict buckets. Counts include assets, component occurrences, open findings and exception states.
4. Finding creation always derives ownership from each new finding's canonical primary subject. The create-finding dialog may select an assignee principal, but it cannot stamp a free-text assignment group or make a CVE-wide team the owner of every finding.
5. If an analyst needs to correct ownership, the workbench opens the common manual **subject assignment** flow with impact preview and reason. It never writes ownership directly on the finding.
6. Notification recipients are canonical affected teams, keyed by team ID. Preview shows excluded Unowned/Conflict items and teams with no configured channel. A custom recipient is separately labeled and audited.
7. Creating a campaign from the investigation passes stable finding IDs and the CVE scope; the campaign service materializes members and ownership snapshots under section 6.13. It does not pass `ownerGroup`.
8. Ticket creation partitions selected findings by current owner team and external assignment-group mapping. Mixed-team selections create separate routing batches or require an explicit, audited coordinator override; they never use an arbitrary first group.
9. Applicability, VEX evidence, false-positive decisions, accepted risk and suppression remain independent of ownership. Their immutable events snapshot the effective owner team/assignment at decision time.
10. Owner changes refresh current team buckets and notification previews while preserving investigation activities, previously exported notifications, campaign membership snapshots and exception-decision snapshots.

VEX/advisory false-positive analysis is evidence, not by itself a canonical false-positive decision. An authorized analyst must commit the decision through the existing finding exception workflow with justification; the evidence and decision remain attributable to the affected occurrence/finding and never alter ownership.

The investigation summary and AI-generated action text may recommend an accountable role, but it must use resolved team facts supplied in the prompt/context and must not emit a fabricated free-text owner as authoritative data.

## 7. Data model

Ownership/directory operational tables live in the repository's per-tenant schemas and retain non-null `tenant_id` plus forced RLS as defense in depth. Tenant-inclusive candidate keys/FKs are used for cross-row references; ordinary high-cardinality indexes follow actual predicates rather than mechanically leading with the schema-constant tenant ID. No cross-tenant cascade path is permitted.

### 7.1 Identity and teams

| Table | Key fields and rules |
|---|---|
| `directory_user` | `id`, `tenant_id`, encrypted display/email/employee fields, manager ID, status, created source; not an application user |
| `directory_group` | `id`, `tenant_id`, display name, status, source-neutral canonical reference if linked |
| `external_identity` | Provider/source, immutable external ID, canonical user ID, encrypted identifiers, link status; unique per tenant/source/external ID |
| `external_group` | Provider/source, immutable external ID, encrypted/display fields, status; unique per tenant/source/external ID |
| `directory_group_member` | External/canonical group and user references, source, observed time and status; idempotent unique membership |
| `identity_source` | Provider, encrypted credentials, scope, mappings, cursor, schedule, state and health |
| `identity_import_run` | Source, file/hash or provider run, state, counts, cursor/watermark, errors and actor |
| `team` | Stable canonical accountable unit, name key, optional parent for organizational display/navigation only, ticket group and active status; `team.parent` does not participate in subject ownership inheritance |
| `team_alias` | Normalized alias to team with source provenance; one tenant-wide namespace shared with every team name and alias |
| `external_group_team_mapping` | External group to team, provenance, state, effective window and actor |
| `team_member` | Optional canonical person-to-team relationship for display/routing evidence; never grants application access |

PII-bearing columns use purpose-bound tenant encryption. Hash/search columns use tenant-keyed normalized hashes where exact lookup is required without plaintext indexing.

### 7.2 Ownership

| Table | Key fields and rules |
|---|---|
| `ownership_subject` | Tenant, subject type, source object ID, contextual parent key when required, generation, lifecycle status and timestamps |
| `ownership_subject_edge` | Minimal typed application/account/asset/component/AI-system relationships used by MVP inheritance |
| `ownership_claim` | Subject, role, team/principal target, source kind/ref, priority class, observed/expiry, producer version, status and idempotency key |
| `ownership_assignment` | Direct-result row only, unique `(tenant_id, subject_id, role)`, winner, team, status, reason, resolver version, watermark and resolved time; inherited descendants do not receive copied rows |
| `ownership_effective_assignment` | Read view/query, not a writable table: direct assignment or first bounded parent direct assignment, including origin subject, path/depth, stale state and conflict/unowned result |
| `ownership_effective_cache` | Conditional Phase-0A performance fallback only; stable IDs/status/origin assignment version/per-subject-or-subtree path versions and freshness, no display names, no tenant-wide epoch, not authoritative and never used stale for correctness-sensitive writes |
| `ownership_review_item` | Type, dedupe key, subject/source, encrypted unresolved value when allowed, state, count and timestamps |
| `ownership_event` | Append-only non-sensitive event references and action metadata |

Claims never store unresolved group/person values as valid targets. Unresolved values exist only in review items or protected source observations.

Subject rules:

- Subject types include application, host, container image, cloud account/project, cloud resource, component occurrence, AI system and AI artifact.
- A normalized software identity is not automatically an ownership subject.
- Component occurrence uniqueness includes tenant, parent inventory context, immutable component identity and generation.
- AI artifacts retain their taxonomy type while participating in the common ownership-subject registry.
- MVP inheritance edges identify at most one `OWNERSHIP_PARENT` for a contextual occurrence/artifact. Effective resolution follows at most six hops, detects cycles and uses inheritance only when the child has no eligible direct claim. `team.parent` never creates an `OWNERSHIP_PARENT` edge. Multiple-parent policy is deferred.
- Reused asset, image, component or AI artifact identifiers create a new generation unless the adapter proves the same underlying object.

### 7.3 Exception integration

Existing finding status, decision, suppression-rule and exception-request storage remains canonical. The ownership MVP does not create a competing exception table or rewrite the canonical suppression mutation service.

Required additive references where absent:

```text
owner_team_id_at_request UUID
ownership_assignment_id_at_request UUID
owner_team_id_at_decision UUID
ownership_assignment_id_at_decision UUID
```

These references belong on the canonical suppression request/decision or immutable exception event, not on `ownership_claim`. Display-name snapshots may be retained for historical readability but stable IDs remain authoritative references. The references are tenant-inclusive and may be null for historical/system events with no resolved owner.

Exception reasons and compensating controls are tenant-sensitive data. They are not ownership evidence and never participate in ownership resolution.

### 7.4 Campaign and investigation workflow storage

Required campaign changes:

| Storage | Required contract |
|---|---|
| `campaign_findings` | Canonical membership for every campaign; tenant-inclusive `finding_id`, owner team/assignment/status snapshots at add time, `added_at`, `added_by` and idempotent membership key |
| `campaign_vulnerabilities` | CVE scope definition only; a reconciler materializes newly matching findings into `campaign_findings` |
| `campaign_exceptions` | Add tenant-inclusive stable `finding_id`; retain campaign-local reason/status/decision history and ownership snapshot without mutating canonical finding exception state |
| `campaign_notify_groups` | Replace ownership-like free-text group authority with nullable canonical `team_id`; custom recipients use an explicit recipient type and protected address |

Current campaign ownership is joined from the finding's canonical subject through the effective-assignment view. At-add fields are immutable audit attribution. Historical membership is not deleted when scope, ownership or finding exception state changes.

Required CVE investigation changes:

| Storage | Required contract |
|---|---|
| `investigations` | Replace free-text `assigned_to` with tenant-inclusive `lead_principal_id`; add optional tenant-inclusive `coordinating_team_id` |
| Investigation activity/action evidence | Store stable affected team, subject/finding and assignment references for exported notifications, campaign launch, ticket routing and exception decisions where attribution is required |
| Investigation summaries | Owner labels in generated prose are derived display values only; structured team facts are stable IDs and current ownership states |

Do not add an `owner_team_id` to the CVE/vulnerability record. Owner-team coverage is a tenant-scoped aggregation across affected canonical subjects/findings and can legitimately contain many teams, Unowned and Conflict at once.

### 7.5 Read projections

Inventory and finding projections store the canonical ownership subject and lightweight state needed for workflow:

```text
ownership_subject_id UUID
assignee_principal_id UUID          -- finding workflow only
exception_type VARCHAR              -- finding workflow only
exception_expires_at TIMESTAMPTZ    -- finding workflow only
exception_state VARCHAR             -- finding workflow only
```

Owner-facing queries join `ownership_subject_id` to a bounded effective-assignment view/query and then join `team` for the current display name:

```text
owner_team_id UUID
ownership_status VARCHAR
ownership_origin_subject_id UUID
ownership_assignment_id UUID
ownership_source_kind VARCHAR
ownership_resolved_at TIMESTAMPTZ
ownership_stale BOOLEAN
inheritance_depth SMALLINT
```

During staged domain migration, read DTOs additionally carry transition-only `authorityDomain` and `authorityState` (`LEGACY_PENDING_MIGRATION` or `CANONICAL`) plus an optional `legacyOwnerLabel`; `DARK` is exposed only in authorized shadow-comparison diagnostics. These are derived by the domain-aware adapter, are not persisted as ownership, and are removed at contract cleanup.

`owner_team_name` and assignee display names are never denormalized into asset/finding ownership projections. They are display attributes joined from canonical team/application-principal records. Filters, joins, campaign attribution and routing use stable IDs. This prevents team rename and person rename fan-out.

Effective-owner performance decision:

- Phase 0A must benchmark the bounded effective-assignment join for owner-team/status filtering over 1M expected and 3M qualification findings plus representative 5M/15M occurrence topology. Release 1 cannot start implementation of the read path without an approved `EXPLAIN (ANALYZE, BUFFERS)` result and p95 evidence against section 13.
- If the direct/parent join misses the gate, the mandatory fallback is an indexed `ownership_effective_cache` keyed by `(subject_id, role)`. It stores only stable team/status/origin assignment/path-version IDs and timestamps—never team/person names.
- Cache versions are granular, never tenant-wide: every directly assigned subject has an assignment version and every ownership edge/subtree root has a topology version. A cache row records the at-most-six-hop path's subject/edge versions (or their deterministic hash) plus origin assignment version.
- Cache refresh is lazy plus bounded durable work in chunks no larger than 10,000 subjects. A direct assignment/edge change increments only the affected subject/subtree versions, marks/enqueues descendant cache IDs in bounded pages and leaves unrelated subtrees hot. List/filter reads may show the explicit stale state during the propagation SLO.
- Correctness-sensitive actions—ticket routing, manual-assignment impact confirmation, exception owner snapshot and campaign owner-at-add—always resolve/validate live in the transaction and never trust an expired/stale cache row.
- Team rename never refreshes effective cache because names are joined at read time. Cache fallback is a performance optimization, not another ownership authority.

### 7.6 Constraints and indexes

- Unique team name key per tenant.
- One shared normalized namespace across team names and aliases per tenant, enforced by the transactional namespace service/advisory lock; per-table uniqueness remains only a backstop.
- Tenant-inclusive foreign keys for every team, user, group, subject, claim and assignment reference.
- Unique external identity/group per `(tenant_id, source_id, external_id)`.
- Unique current assignment per `(tenant_id, subject_id, role)`.
- Confidence is not used for MVP precedence; any retained confidence field must be informational only.
- Claim expiry must be later than observation time.
- Partial indexes support active claims and open review items.
- Effective-assignment query indexes cover direct `(subject_id, role)` lookup, parent traversal and team/status filtering without storing owner display names.
- Membership indexes support group members and user groups.
- Direct SQL writes to team, alias, claims, assignments and projections are blocked by architecture/writer-control tests except named migration/maintenance paths.
- Exception owner/assignment snapshot references must belong to the same tenant as the finding and request/event.
- Campaign finding, owner-at-add, exception and notify-team references must be tenant-inclusive. Uniqueness prevents the same finding from being materialized twice in one campaign.
- Investigation lead/coordinator and action-snapshot references must be tenant-inclusive; a CVE identifier alone is never sufficient authorization to read tenant investigation ownership.

## 8. API surface

Exact URI conventions follow existing API standards. Required logical endpoints:

### 8.1 Directory and imports

```text
GET/POST/PATCH  /api/directory/users
GET/POST/PATCH  /api/directory/groups
GET/POST/DELETE /api/directory/groups/{id}/members
POST            /api/directory/imports/preview
POST            /api/directory/imports/{previewToken}/commit
GET             /api/directory/imports/{id}
GET             /api/directory/imports/{id}/errors
```

### 8.2 Sources

```text
GET/POST/PATCH  /api/identity-sources
POST            /api/identity-sources/{id}/validate
POST            /api/identity-sources/{id}/preview
POST            /api/identity-sources/{id}/enable
POST            /api/identity-sources/{id}/pause
POST            /api/identity-sources/{id}/sync
GET             /api/identity-sources/{id}/runs
```

Ownership producers use a separate source type/configuration but share health conventions and kill-switch behavior.

### 8.3 Teams, mappings and review

```text
GET/POST/PATCH  /api/ownership/teams
GET/POST/DELETE /api/ownership/teams/{id}/aliases
GET/POST/PATCH  /api/ownership/group-mappings
GET/PATCH       /api/ownership/review-items
GET             /api/ownership/coverage
```

### 8.4 Assignments and explanations

```text
GET  /api/ownership/subjects/{type}/{id}
POST /api/ownership/subjects/{type}/{id}/manual-assignment
POST /api/ownership/subjects/{type}/{id}/manual-assignment/revoke
GET  /api/ownership/subjects/{type}/{id}/explanation
```

All mutations accept an idempotency key where replay is possible. Collection endpoints use bounded pagination; no tenant-wide unbounded list endpoint is allowed.

During staged migration, all ownership summaries use the domain-aware read envelope from section 7.5. Mutation APIs validate the subject's active authority domain and return a conflict/error for canonical writes against `LEGACY_PENDING_MIGRATION` subjects rather than fabricating an Unowned canonical assignment.

### 8.5 Exception API compatibility

- Preserve existing direct suppression, suppression-request, approval/rejection, reopen, false-positive, accepted-risk and suppression-rule endpoints unless the Release-3 Phase 0B contract identifies a correctness defect.
- Add current ownership plus request/decision owner snapshots to exception read responses where required by UI.
- Do not accept owner-team text through exception mutations.
- Keep exception authorization and severity gates independent from ownership administration roles.
- Reject ownership fields in new/updated MVP suppression-rule conditions with a clear validation error.
- Keep organization-wide CVE suppression explicitly separate from occurrence/finding suppression.

### 8.6 Breaking API changes

- At final contract cleanup, remove `/api/ownership-rules` and its apply endpoints. During migration they remain route-gated to `LEGACY` authority domains, absent from the new UI and unavailable once that domain accepts canonical mutations.
- Remove `ownerGroup` from finding workflow and bulk requests.
- Replace finding/inventory owner-name filters with `ownerTeamId`.
- Replace free-text person assignment with `assigneePrincipalId`.
- Replace AI Grid owner-confirmation endpoint with common manual subject assignment.
- Update campaign DTOs from `ownerGroup`/`supportGroup` authority to `ownerTeamId`, display name and ownership status.
- Replace CVE investigation `assignedTo` text with `leadPrincipalId`; return optional `coordinatingTeamId` separately.
- Remove the CVE workbench's direct ServiceNow assignment-group list as an ownership source. Team selection uses the canonical team API; external assignment groups are exposed only as ticket mappings.
- Replace the CVE workbench's free-text `/assets/assigned-to` lookup with the authorized canonical application-principal picker.
- Do not remove suppression APIs, suppression-rule DTOs, canonical suppression mutations or exception history while removing legacy ownership code.

### 8.7 Campaign and CVE investigation contracts

- Campaign create/read APIs use stable `findingIds`, optional `vulnerabilityIds`, `assigneePrincipalId` and optional `coordinatingTeamId`; they reject `ownerGroup` as an ownership mutation.
- Campaign member responses return both `ownerAtAdd` and `currentOwnership`, plus `ownershipChanged`, exception state and campaign-exception state.
- Campaign reconciliation is bounded, idempotent and observable; its watermark and last result are available to authorized users.
- CVE detail returns an `ownershipCoverage` aggregate keyed by team ID with Unowned/Conflict buckets and counts by subject, finding and exception state.
- CVE investigation mutations accept `leadPrincipalId` and optional `coordinatingTeamId`, using canonical pickers and tenant authorization.
- Finding creation from the CVE workbench accepts subject/component decisions and optional assignee principal; owner team is server-derived after the canonical finding adapter selects its subject.
- Notify preview/export and ticket preview APIs accept stable team/finding selections, return excluded/unroutable counts and audit the effective ownership assignment IDs.

## 9. Required UI changes

### 9.1 Configurations: replace the existing Ownership Rules screen

Remove the current name/condition/free-text-user-group rule editor and **Execute Now** action. Replace the Ownership section with an **Ownership & Directory** hub.

Required tabs:

| Tab | Required content/actions |
|---|---|
| Overview | Owned/unowned/conflict/stale counts, source coverage, last syncs and blocked work |
| People | Search, status, source identities, manager, groups, create/edit/deactivate |
| Groups | Search, provider, status, members, mapped team and create/edit/deactivate |
| Teams | Canonical teams, aliases, ticket group, create/edit/deactivate |
| Mappings | External group-to-team and source alias-to-team mapping |
| Sources | ServiceNow, Entra, Okta, AWS, GCP and AI Grid state/health/actions |
| Imports | Template download, dry run, progress, history and error file |
| Review | Unmapped values, conflicts, ambiguous identities and inactive owners |

The MVP does not expose a tenant policy/rule editor.

The existing **Suppression Rules** configuration remains. Its condition field allow-list must reject ownership fields for MVP. Ownership-screen removal must not remove shared matcher/editor code used by suppression.

### 9.2 Connect/source setup

Existing connector setup must add an ownership/identity step:

1. Credential and host validation.
2. Scope and attribute mapping.
3. Preview counts and sample masked records.
4. Ownership-field selection.
5. Publication toggle initially off.
6. Health, last cursor, last success and kill switch.

The page must distinguish **identity synchronization** from **ownership evidence production** even when ServiceNow supplies both.

### 9.3 Inventory overview and lists

Stop calculating owner from raw `ownerEmail`, `ownerTeam` and `supportGroup` fallbacks.

Default columns:

- Resource.
- Type.
- Environment/account/project.
- Owner Team.
- Ownership Status.
- Ownership Source.
- Open Findings.
- Criticality.
- Source System.
- Last Seen.

Required filters/grouping:

- Canonical `ownerTeamId`.
- Ownership status: owned, unowned, conflict, stale and transition-only Pending Migration. Pending Migration is never counted as Unowned.
- Ownership source.
- Accountable person where authorized.
- Unmapped ownership value.
- Cloud provider/account/project.
- Existing inventory/risk filters.

Summary cards use resolver status, not empty display strings: Owned, Unowned, Conflict, Unmapped and Stale.

### 9.4 Asset/host/application/cloud detail

Replace the current mixed Ownership panel with:

**Resolved Ownership**

- Status.
- Canonical owner team.
- Accountable person where available and permitted.
- Direct or inherited assignment.
- Winning source and reason.
- Observed and resolved times.
- Freshness.
- Affected finding count.
- Actions: Assign owner, revoke override, view explanation, resolve conflict, map value.

**Observed Ownership Evidence**

- Provider/source.
- Field/tag/label.
- Masked value.
- Mapping status.
- Observation time and expiry.

Raw CMDB fields remain source evidence and are not labeled as the resolved owner.

### 9.5 AI inventory detail

- Remove free-text **Team or owner** confirmation.
- Use the common canonical team picker and manual subject assignment endpoint.
- Replace AI-specific owner state/history with common `OwnershipSummary` and events.
- Display AI signals in Observed Ownership Evidence.
- Apply the same Owner Team, Ownership Status and Ownership Source columns/filters to AI inventory lists.
- Apply the common ownership card to AI systems, models, agents, endpoints, deployments, knowledge bases, datasets/data stores/search indexes and MCP server/gateway/target details.
- Show direct versus inherited ownership and link to the containing AI system or cloud/host parent.
- For AI-BOM resources, link ownership to the canonical model/data/knowledge artifact rather than copying owner text into BOM rows.
- Remove or rewrite AI owner confirmation/history screens that read independent AI Grid owner columns.

### 9.6 BOM, software identity, CBOM and AI-BOM screens

Required list behavior:

- BOM component rows show occurrence context, Owner Team, Ownership Status, assignment type and Ownership Source.
- Owner filters use stable `ownerTeamId` and apply to occurrences, not global package names.
- Software identity/global package lists display owner-team coverage such as `1 team`, `3 teams` or `Unowned occurrences`; they do not display an invented global owner.
- CBOM lists use the containing occurrence/asset assignment and expose cryptographic ownership gaps.
- AI-BOM lists resolve models, datasets and knowledge resources through canonical AI artifact subjects.

Required detail behavior:

- BOM component detail shows the component occurrence, immutable context, ownership parent and resolved assignment.
- Software identity detail lists occurrences grouped by owner team and provides links to the owning assets/applications.
- Container component detail identifies the immutable image digest; mutable tag is display-only context.
- CBOM component detail shows resolved owner, inheritance path and affected cryptographic findings.
- AI-BOM detail links to the canonical AI model/data/knowledge artifact and shared ownership explanation.
- **Assign owner** operates on the selected occurrence or canonical AI artifact and previews affected findings; it never changes every occurrence of a global package by default.

Required affected screens/components include BOM inventory, BOM component detail, Software Identity Detail, CBOM inventory/detail panels, AI-BOM resources and any CVE workbench tables that currently display raw support group/owner text.

### 9.7 Findings list

Replace columns and filters:

| Existing | MVP |
|---|---|
| Owner Group | Owner Team using stable ID |
| Owner/raw support group | Ownership Source or optional observed evidence |
| Assigned To free text | Authorized Scoutgrid application principal |
| Empty owner | Explicit Ownership Status |

Default ownership columns: Owner Team, Ownership Status, Assignee and optional Ownership Source. Saved queues store `ownerTeamId`; incompatible existing saved owner filters may be deleted because there are no customers.

During domain migration, findings from later domains show a **Pending Migration** badge and their legacy owner label. Exact reviewed mappings may participate in `ownerTeamId` filtering; unmapped legacy labels appear only in the Pending Migration bucket and cannot be auto-routed.

### 9.8 Finding detail

- Remove editable free-text Assignment Group.
- Replace free-text Assigned To with an authorized Scoutgrid application-principal selector. A linked directory identity may supply masked display/profile data but never grants tenant access or workflow authority.
- Add one Ownership card showing status, team, canonical subject, source, reason, freshness and affected subject link.
- Move raw asset/CMDB ownership fields into expandable evidence.
- **Change subject ownership** opens the subject assignment dialog and shows how many findings will change.
- Conflict/unowned states link to the review workflow.
- Do not provide permanent one-finding owner editing in MVP.
- For vulnerability/CBOM findings, show the selected component occurrence and its ownership parent.
- For AI posture/exposure findings, show the canonical AI target; secondary artifacts/path nodes remain explanation evidence. Runtime finding UI remains absent/out of scope.

### 9.9 Exception, false-positive and suppression UI

Finding Detail retains and integrates existing actions:

- Suppress or Request Exception.
- Mark False Positive with mandatory justification.
- Accept Risk with justification, compensating control and expiry according to existing policy.
- Mark Under Investigation.
- Reopen, including clearing applicable deferral/suppression state through the canonical mutation service.

The exception panel displays:

- Current Owner Team and current Ownership Status.
- Owner Team at request time and at decision time.
- Requester, approver and timestamps.
- Exception type, reason, justification and compensating control.
- Suppression rule when automated.
- Expiration and reopening status.
- Type-specific restrictions such as CBOM critical/unknown-severity controls.

Finding list filters add Exception Type, Exception State, Suppression Rule, Expiration/Expiring Soon, False Positive and Accepted Risk. These combine with Owner Team and Ownership Status filters without changing either lifecycle.

Inventory/asset detail shows aggregate Open, Suppressed, False Positive and Accepted Risk finding counts. Changing asset ownership does not alter these counts except through ordinary finding queries.

AI posture/exposure and BOM/CBOM finding details use the same exception component, with their canonical AI target or component occurrence visible beside the exception.

### 9.10 Findings bulk actions

- Retain bulk assignee changes using canonical principal IDs.
- Remove bulk free-text owner-group changes.
- Optional bounded bulk subject assignment may be included only if it previews unique subjects and affected findings, requires a reason and uses the common manual-claim service.
- Mixed/conflict ownership selections display counts rather than selecting an arbitrary value.

### 9.11 Campaigns

Campaign list/detail/create flows must change as follows:

- Replace `ownerGroup` and `supportGroup` authority with `ownerTeamId`, `ownerTeamName` and `ownershipStatus`.
- Group campaign findings/assets by stable team ID.
- Add explicit Unowned and Conflict groups.
- During staged migration, add a separate Pending Migration group for members whose subject domain is still legacy; do not merge it into Unowned or snapshot a fabricated canonical team.
- Materialize all campaign finding membership, including CVE-based campaigns, in `campaign_findings`; do not render an untracked dynamic query as campaign membership.
- Campaign item records owner team/assignment/status at add time for attribution and shows current owner with a changed/stale indicator.
- Add-assets search uses current resolved owner team, not raw asset `ownerTeam`.
- Campaign launch cannot accept a free-text owner group.
- Canonical assignee selection remains distinct from owner team.
- Notify recipients select canonical team IDs and show the configured channel; custom recipients are visibly non-owner recipients.
- Campaign exceptions are visibly campaign-local. A separate authorized action is required to suppress, mark false positive or accept risk on the finding itself.
- Campaign exports include team ID, display name, status, source and resolved time.
- Suppressed, false-positive and accepted-risk items are excluded from active remediation by default and remain available through explicit filters.
- Existing campaign items retain historical rows when an exception is applied and display exception type/expiry.
- Campaign outcome metrics separate remediated, suppressed, false positive, accepted risk, reopened and open.

### 9.12 CVE investigation workbench

- Replace free-text lead analyst with `ApplicationPrincipalPicker` backed by active tenant memberships; show the optional coordinating team separately.
- Add an ownership coverage card with affected-team count, Unowned, Conflict and Stale counts.
- Findings and matched-software tables use `OwnershipSummaryCard` data from canonical subjects. Remove fallback from canonical ownership to raw `supportGroup` for authoritative display/filtering.
- Group affected assets/component occurrences by stable team ID. Preserve occurrence context; a global package/software identity does not receive one fabricated owner.
- Replace **Assignment / Ownership Logic** with separate controls: server-derived **Subject owner** (read-only/default), optional finding assignee and ticket routing preview. Ownership corrections launch `ManualAssignmentDialog` for the subject.
- Replace the direct ServiceNow assignment-group datalist with canonical team selection and a separately labeled external ticket-group mapping/override.
- Notification recipients are canonical impacted teams. Show asset/finding counts, configured channel, Unowned/Conflict exclusions and custom-recipient status before export/send.
- Campaign launch preview shows materialized finding count, team distribution, Unowned/Conflict count and excluded exception states.
- Mixed-team ticket creation previews one routing batch per team; no first-group fallback is permitted.
- Applicability, false-positive, risk-acceptance and suppression panels show current owner plus owner-at-decision without allowing those decisions to mutate ownership.
- Investigation summary/AI action cards distinguish suggested role text from resolved canonical team facts.

### 9.13 Tickets and ServiceNow incident dialogs

- Default assignment group from `team.ticket_assignment_group`.
- Display the Scoutgrid owner team and external ticket group separately.
- Require explicit selection/configured fallback when no ticket mapping exists.
- Prevent automatic routing for Conflict.
- Audit manual ticket-group override with reason.
- Do not copy raw CMDB support group into the ticket merely because it is present.
- Ownership changes do not close tickets; suppression/exception ticket behavior continues under the existing ticket policy.

### 9.14 Dashboards, search and exports

- Missing-owner widgets use `UNOWNED`, not null/free-text checks.
- Add ownership coverage and conflict counts.
- Global search may find teams and masked people/groups within authorization.
- Exports are role-gated, tenant-scoped, reason-bound when PII is included, watermarked and audited.
- Existing reports and AI recommendations that read `owner_group` must use current assignments/projections.
- Ownership coverage can be segmented by host/application/cloud resource, BOM occurrence, AI system/artifact and finding kind.
- Exception dashboards can be segmented by current owner team without treating exception status as ownership status.
- Export current owner and owner-at-decision as separate stable-ID/display fields.

### 9.15 Shared frontend components

Create reusable components rather than reimplementing ownership by inventory type:

```text
OwnershipSummaryCard
OwnershipStatusBadge
CanonicalTeamPicker
DirectoryPersonPicker
ApplicationPrincipalPicker
OwnershipEvidenceTable
OwnershipExplanationDrawer
ManualAssignmentDialog
OwnershipConflictPanel
SourceHealthCard
CsvImportWizard
ExceptionSummaryPanel
ExceptionStatusBadge
OwnershipCoverageCard
OwnerChangeIndicator
```

`DirectoryPersonPicker` is limited to directory administration/evidence relationships. Finding assignee, campaign assignee and investigation lead controls always use `ApplicationPrincipalPicker` and active tenant membership authorization.

All new components require keyboard navigation, screen-reader labels, loading/error/empty states and visual regression coverage.

### 9.16 Initial repository change inventory

The rolling Phase 0B contract work must replace this initial list with a mechanical, owner-assigned ledger before each owning release. Known high-impact areas are:

| Layer | Existing areas requiring change |
|---|---|
| Legacy ownership backend | `OwnershipRule`, `OwnershipRuleRepository`, `OwnershipRuleService`, `OwnershipRuleController` and ownership rule DTOs |
| Exception/suppression preservation | `SuppressionRuleService`, canonical suppression mutations, finding suppression requests, reopen/expiry workers and shared condition matcher must remain valid |
| Finding domain/API | `Finding.ownerGroup`, workflow/bulk requests, responses, filters and queue resolution |
| Finding projections | Projection refresh/query/list services, owner-name index and saved queue contracts |
| Inventory backend | `Asset.ownerTeam`, `ownerEmail`, `managedBy`, `supportGroup`, `assignedTo` interpretation and asset/host DTOs |
| AI Grid | Independent owner resolver, owner columns/history, confirmation API and every downstream reader |
| Campaigns | `CampaignDtos`, `CampaignService`, dynamic CVE membership, `isResolvedFinding`, `campaign_findings`, `campaign_exceptions`, notify groups and item/grouping logic using `ownerGroup` or `supportGroup` |
| CVE investigation backend | `Investigation.assignedTo`, CVE detail/workflow DTOs, manual finding creation, notification/ticket request builders and investigation summary ownership text |
| Tickets | ServiceNow/Jira request builders that infer assignment group from free text |
| Configuration UI | `ConfigurationsPage` ownership-rule editor and related API/types/tests |
| Finding UI | `FindingsPage`, `FindingDetailPage`, finding types, filters and bulk actions |
| Inventory UI | `InventoryPage`, `HostAssetDetailPage`, `AiAssetDetailPage`, application/cloud detail and shared inventory types |
| BOM/AI-BOM UI | BOM inventory/component detail, Software Identity Detail, CBOM panels, AI inventory/knowledge/MCP pages and CVE workbench ownership cells |
| Campaign UI | Campaign list/detail/create, linked findings and exports |
| CVE investigation UI | `WorkbenchMain`, `FindingsTab`, `CveOverviewTab`, `NotifyGroupsPanel`, ownership helpers/types and direct ServiceNow group lookup |
| Cross-cutting | API client, demo seeding, fixtures, docs, metrics, reports, saved views and accessibility tests |

Raw asset fields may remain when other inventory features need them, but the ledger must prove they are no longer consumed as resolved ownership.

## 10. Security and privacy requirements

Security is a release prerequisite, not a later hardening phase.

### 10.1 PII and keys

- One environment KMS key-encryption key wraps versioned per-tenant data-encryption keys.
- Encryption context includes tenant ID and key version.
- AES-256-GCM AAD includes tenant ID and column purpose.
- Local keys are allowed only in development/test and rejected in deployed profiles.
- Plaintext tenant keys are cached briefly by tenant and version.
- KMS outage fails closed for PII/credential writes; non-PII reads and resolution continue where decryption is not required.
- Key rotation is resumable; old versions remain decrypt-only until unreferenced.
- Tenant purge destroys wrapped keys only at the approved irreversible stage.
- The repository currently encrypts connector secrets with environment-key `CredentialEncryptionService` envelopes and migrates them in bounded batches with `ProviderCredentialMigrator`; it has no KMS client. The Render/KMS spike is therefore new platform work, not assumed reuse.
- The target introduces one versioned sensitive-value encryption interface backed by `TenantKeyProvider`. New PII and connector-secret writes use a tenant-bound KMS-wrapped DEK envelope. `CredentialEncryptionService` remains a transitional reader/adapter for existing `enc:v1`/`enc:v2` values only.
- Extend/reuse the bounded, rollback-on-batch-failure `ProviderCredentialMigrator` inventory and process to re-envelope existing connector credentials into the new tenant-key envelope. Do not create a second unrelated credential migration path or leave two write formats active.

PII includes names, emails, employee identifiers, external identifiers, manager chains and memberships. Team names are business data unless customer policy classifies them otherwise.

PII search contract:

- Directory display names and emails remain tenant-encrypted; they are not indexed as plaintext.
- Exact email/employee-ID lookup uses a purpose-bound tenant-keyed HMAC.
- Display-name search is prefix-only in MVP, with a minimum three-character normalized prefix. A separate `directory_user_search_token` table stores tenant-keyed HMAC tokens for bounded prefixes, never plaintext n-grams.
- Arbitrary substring/contains search over encrypted people data is not supported in MVP. Team names remain normally searchable business data.
- Search-token generation is versioned with the tenant key, rate-limited and rebuilt resumably during key rotation. Results decrypt only the authorized bounded result page.
- Release 1 qualification must prove the section 13 search SLO at 100,000 and 300,000 directory users and document the frequency-leakage/security review of prefix tokens.

### 10.2 Masking and audit

- PII is masked by default outside authorized administrative views.
- Unmask is a sensitive action, rate-limited and audited once per request with record count and references, never plaintext values.
- Audit payloads do not contain secrets, tokens, raw emails or unresolved personal values.
- Campaign/CVE notification recipient addresses and custom recipients are masked/protected tenant data; audit stores recipient/team references and counts, not raw addresses.
- Exception justification and compensating-control text are treated as tenant-sensitive data and excluded from metrics/log payloads.
- Support access is time-boxed, tenant-scoped, masked by default and audited.

### 10.3 Connector security

- Credentials are stored only as tenant-encrypted secrets.
- Provider type determines allowed host pattern; tenants cannot configure arbitrary egress URLs.
- DNS/IP validation blocks private, loopback, link-local and cloud metadata destinations unless a separately approved private-connector architecture exists.
- Redirects are disabled or revalidated hop by hop.
- TLS verification is mandatory.
- OAuth scopes/API permissions follow least privilege and are shown in setup documentation.
- Logs and metrics redact credentials, authorization headers and PII.

### 10.4 CSV and export security

- Enforce file size, row count, content type, encoding and parsing limits.
- Reject archives, macros and malformed quoting beyond parser limits.
- Protect spreadsheet exports from formula injection.
- Store uploads only for the minimum processing window; remove them after import/error-retention expiry.
- Export endpoints require authorization, tenant context, bounded size and audit.

### 10.5 Application security

- Method authorization on every endpoint.
- Rate limiting for sensitive writes, validation and imports.
- CSRF protection follows existing browser/API architecture.
- Parameterized SQL and strict allow-lists for provider fields.
- No arbitrary expression execution in MVP.
- STRIDE review covers identity linking, source admission, mapping, manual assignment, exports and tenant keys.
- STRIDE review also covers campaign materialization/reconciliation, CVE multi-team aggregation, notification recipient selection and ticket-routing override.
- Penetration test focuses on cross-tenant access, SSRF, IDOR, CSV injection, secret exposure and PII unmask.

## 11. Tenant isolation requirements

Scoutgrid retains the repository's schema-per-tenant architecture:

- `platform` holds global application users, tenant memberships/support grants, tenant registry/schema versions, wrapped tenant-key metadata and the minimum pre-tenant routing/control-plane data.
- Each tenant schema holds directory users/groups/memberships, sources, teams, mappings, ownership subjects/edges/claims/assignments/review/events, projections, campaigns and investigations.
- No ownership or tenant directory row is stored in a new shared operational table.

Defense-in-depth rules:

- Every row in a tenant schema still contains the schema tenant's non-null `tenant_id`, and forced RLS is pinned to `app.current_tenant_id`.
- Foreign keys between tenant operational tables include tenant ID where the referenced candidate key permits it; references to application principals validate an active `(tenant_id, app_user_id)` platform tenant membership.
- Shared `platform` tables use explicit tenant IDs, tenant-scoped keys/indexes and RLS where tenant-facing access is allowed.
- Because a tenant schema physically contains one tenant, high-cardinality tenant-table indexes are ordered for actual query predicates; they do not mechanically lead with low-selectivity `tenant_id` unless required by a composite FK/unique contract.
- Tenant schema provisioning/migration is performed by the existing tenant schema control plane; the long-running API performs no DDL.
- Forced RLS and search-path/reset behavior are validated for runtime, migration, maintenance and test roles.
- Jobs fail closed without explicit tenant context.
- Queue messages include tenant ID plus immutable object ID; workers re-establish and validate tenant context.
- Caches, cursor keys, idempotency keys, advisory locks, metrics labels and dedupe keys are tenant-partitioned.
- Provider external IDs are unique only inside tenant and source, never globally trusted.
- Wrong-tenant IDs return 404.
- Platform operators see aggregate health only unless they hold an active scoped support grant.
- Cross-tenant decrypt attempts fail because AAD and wrapped-key context bind data to tenant.
- Tenant purge first disables access/work, removes platform references and wrapped key material in the approved order, then drops/purges the tenant schema containing identity, memberships, sources, credentials, claims, assignments, review items, projections, campaign membership/snapshots, investigation workflow evidence and events.

Mandatory tenant tests:

1. CRUD isolation for every new table/controller.
2. Cross-tenant foreign-key rejection.
3. Cross-tenant IDOR rejection.
4. Worker execution without tenant context fails.
5. Cache/idempotency collision across tenants does not leak or suppress work.
6. Cross-tenant ciphertext cannot decrypt.
7. Support grant expiry immediately removes access.
8. Provider callback/cursor cannot be replayed into another tenant.
9. Exception request/decision owner snapshots cannot reference another tenant's team or assignment.
10. Suppression expiry/reopen workers fail closed without explicit tenant context.
11. Campaign membership/reconciliation cannot attach a finding, team or assignment from another tenant.
12. CVE ownership coverage, lead/coordinator selection, notification preview and ticket batching cannot discover another tenant's principals, teams or findings.

## 12. Reliability, synchronization and reconciliation

### 12.1 Source state

```text
DRAFT -> VALIDATED -> ENABLED
ENABLED -> PAUSED
ENABLED -> FAILING
FAILING -> ENABLED
ANY -> DISABLED
```

Enablement requires successful credential validation and preview. Disabling retains evidence and history but stops new ingestion.

Freshness and claim eligibility defaults:

- Manual claims do not expire unless the actor supplies an expiry; revoked manual claims become immediately ineligible.
- Provider claims carry `observed_at`, source schedule and `expires_at`. MVP source schedules must be between 15 minutes and seven days. Unless a stricter producer contract is approved, a source becomes stale after `max(2 × configured interval, 24 hours)` without a complete successful observation, and its claims expire after `max(3 × configured interval, 72 hours)`, capped at 30 days. For every allowed interval, expiry is later than the stale threshold.
- An authoritative provider deletion/supersession event makes the affected claim ineligible immediately after idempotent processing; it does not wait for TTL.
- `ownership_stale` means the effective winning claim's source crossed its stale threshold but the claim has not yet expired. Expiry triggers effective re-resolution/inheritance fallback or `UNOWNED`.
- The UI shows the exact stale/expiry time and source health. Stale claims remain visible evidence even after they are no longer eligible.

### 12.2 Durable work

All imports, provider syncs, claim publications, resolution and projections use durable, bounded, retryable work with:

- At-least-once delivery.
- Idempotency keys.
- Lease/fence tokens.
- Exponential backoff with provider-aware retry.
- Poison-work state and review/alert.
- Coalescing of repeated subject updates.
- Per-tenant and per-source concurrency limits.
- Kill switches.

### 12.3 Safety against destructive synchronization

- Partial/failed scans never deactivate or delete.
- Deactivation requires a complete authoritative scan or explicit provider deletion event followed by reconciliation.
- Mass change thresholds pause publication before changes become effective.
- Default anomaly pause is triggered when one run proposes at least 100 changes and at least 10% of the source's active identities/claims, or at least 10,000 changes regardless of percentage. A source contract may only lower these defaults without explicit security/SRE approval.
- A source's first complete baseline load is exempt only from percentage-based **create** anomaly checks after an authorized preview/confirmation. Absolute ingestion/capacity limits, validation failures, unexpected updates/deactivations and tenant quotas still pause or reject the run. The source becomes baseline-qualified only after the complete run commits successfully.
- A manual mapping/alias change affecting more than 10,000 subjects requires a second impact confirmation and executes as bounded durable work, even though second-admin approval remains deferred.
- Preview compares expected creates, updates, deactivations, membership removals and claim changes.
- A paused source retains accurate last-success and staleness indicators.

### 12.4 Reconciliation jobs

| Job | Comparison | Automatic repair | Escalation |
|---|---|---|---|
| Identity source | Provider watermark vs imported identities | Retry missing pages/runs | Source review item |
| Membership | Provider snapshot/delta vs active memberships | Repair idempotently after complete source run | Anomaly pause |
| Group mapping | External group/team references | None for semantic mismatch | Review item |
| Claims | Source observation watermark vs claims | Republish missing mapped claims | Producer alert |
| Assignments | Eligible claims vs stored assignment | Re-resolve subject | Resolver alert above threshold |
| Effective-owner cache, if selected | Direct assignments/per-subject or subtree path versions vs cached stable-ID result | Bounded lazy/durable refresh | Stale-cache/propagation alert |
| Inventory ownership link | Inventory object vs canonical ownership subject reference | Targeted link repair | Projection alert |
| Finding ownership link | Finding adapter result vs canonical subject reference | Targeted upsert/delete | Projection alert |
| Campaign membership | CVE campaign scope/current matches vs materialized finding members | Idempotently add missing members with owner-at-add snapshot; never delete history | Campaign reconciliation alert/review |
| Campaign ownership view | Member owner-at-add vs current finding effective assignment | Refresh bounded cache only if used | Projection alert |
| Investigation ownership coverage | Affected subjects/findings vs current team buckets | Recompute cache/projection from canonical assignments | Investigation coverage alert |
| Namespace | Team names/aliases | No semantic auto-repair | Admin review |
| RLS/grants | Expected policies/grants vs catalog | No runtime repair | Release/operations alert |

### 12.5 Backup, recovery and retention

Provisional MVP objectives, confirmed against platform capabilities in Phase 0A and updated per release:

| Control | Initial target |
|---|---|
| Database recovery point objective | 15 minutes or better |
| Database recovery time objective | 4 hours or better |
| Restore exercise | Before release and at least quarterly |
| Uploaded CSV retention | Delete within 24 hours after terminal import state |
| Downloadable row-error file | 7 days, tenant-authorized access only |
| Import-run metadata | 90 days minimum |
| Ownership/audit event retention | Platform default of 400 days unless legal/security policy changes it |
| Provider cursor and health history | 90 days minimum |

- Backups include tenant schemas and platform tenant-key metadata, but not plaintext keys or secrets.
- Restore procedures prove encrypted values remain decryptable with authorized key versions.
- Tenant purge and legal erasure are not undone by ordinary application restore; restoration requires the platform's approved deleted-tenant policy.
- Regional backup/data-residency obligations are approved before storing production PII.
- Recovery tests include rebuilding assignments and projections from retained claims without invoking tenant-wide rebuild per item.

## 13. Performance and capacity assumptions

Phase 0A validates the Release-1 assumptions; Phase 0B validates later-release additions against these provisional qualification sizes:

| Measure | Expected tenant | Qualification size |
|---|---:|---:|
| Directory users | 100,000 | 300,000 |
| Directory/external groups | 20,000 | 60,000 |
| Memberships | 2,000,000 | 6,000,000 |
| Inventory subjects | 500,000 | 1,500,000 |
| BOM component occurrences | 5,000,000 | 15,000,000 |
| AI systems/artifacts | 250,000 | 750,000 |
| Open findings | 1,000,000 | 3,000,000 |
| Historical findings | 5,000,000 | Representative partition/sample |
| Active claims | 2,000,000 | 6,000,000 |
| Findings in one campaign | 100,000 | 300,000 |
| Affected occurrences in one CVE investigation | 100,000 | 300,000 |
| CSV rows per file | 100,000 | Limit test plus rejection test |

Initial SLO targets:

| Operation | Target |
|---|---|
| User/group search | p95 under 500 ms |
| Inventory/finding owner filter | p95 under 750 ms at expected size |
| Manual assignment API | p95 under 500 ms excluding async propagation |
| Ownership propagation | 95% visible within 60 seconds |
| Single-subject resolution | p95 under 250 ms worker time |
| Provider preview | Progress visible within 10 seconds |
| Incremental identity freshness | 95% within configured schedule plus 15 minutes |
| Campaign member page/team grouping | p95 under 1 second at expected per-campaign size |
| CVE ownership coverage summary | p95 under 1 second cached/projected; refresh completes within 60 seconds of ownership propagation |
| Idempotent replay | Zero duplicate records and zero extra effective assignment writes |
| Interactive availability | 99.9% monthly target excluding approved maintenance |

Full initial provider synchronization is asynchronous and must not block normal product reads.

Initial product-quality targets on the approved representative qualification tenant:

| Measure | Blocking MVP target |
|---|---:|
| Active inventory subjects with `OWNED` effective status | At least 90% |
| Open findings with a valid canonical subject | At least 98% |
| Open findings with `OWNED` effective status | At least 90% |
| Effective ownership conflicts | At most 2% |
| Unmapped source values after qualification mapping | At most 5% |
| Open review items acknowledged or resolved | 95% within two business days |
| Stale effective assignments under normal source health | At most 2% |

Targets are release gates for the qualification dataset, not claims about future customer data. A miss requires an accountable owner, root cause and approved time-bound exception; it cannot be hidden by converting Unowned/Conflict to a default team.

## 14. Observability

Required per-tenant/source metrics and UI status:

- Last attempt, last success and duration.
- Cursor/watermark age.
- Records fetched, created, updated, deactivated and rejected.
- Membership changes.
- Claims created, superseded, expired and rejected.
- Assignments changed, unowned and conflict.
- Unmapped value count and top sources.
- Queue depth, oldest work age, retry and poison counts.
- Provider throttle count and retry-after duration.
- KMS failures and decrypt failures without PII labels.
- Projection lag and mismatch counts.
- Kill-switch and anomaly-pause status.

Alerts:

- Repeated provider failure.
- Cursor age above freshness SLO.
- Unexpected mass deactivation/removal.
- Ownership change volume/rate anomaly.
- Resolver/projection backlog above SLO.
- Effective-owner cache stale count/age and live-resolution fallback rate when the Phase-0A cache option is selected.
- Cross-tenant/RLS test or runtime invariant failure.
- KMS/credential-decryption failure.
- Missing event partitions if partitioning is selected for the MVP migration.

## 15. Migration and cutover strategy

Migration versions must be reconfirmed against the repository in Phase 0A and before each later release. Use the next available platform and tenant versions.

### 15.1 Expand

- Add tenant key infrastructure before any PII write.
- Add identity, team, source, claim, assignment, review and event tables.
- Add canonical ownership-subject and assignee-principal references to asset/finding read projections plus the effective-assignment view/query.
- Add RLS, grants, composite FKs, indexes and purge coverage.
- Deploy new code behind disabled source/publication switches and independent per-consumer read flags.
- Keep legacy endpoints, rules and columns operational but hidden from new UI until all consumer waves are qualified.

For each migration domain, the old implementation remains the sole temporary authority until that domain's explicit authority switch. There is no dual authority for the same domain/source/subject and no conversion of old ownership history.

### 15.2 Populate and qualify

- Reseed demo data using new identity/team/claim APIs.
- Configure authorized test provider tenants.
- Import teams, identities and mappings.
- Run providers with publication disabled.
- Validate counts, mappings, direct assignments, inherited effective results and consumer query plans.
- Run subject/projection rebuild only as a qualification/repair operation.
- Exercise every consumer flag in test/preproduction while comparing new results with approved expected outcomes; legacy/new differences are not automatically treated as defects because the old model is being replaced.

### 15.3 Per-domain authority switch and compatibility adapter

Authority state is tracked per migration domain, not by one global switch:

| Domain | Canonical switch |
|---|---|
| Core inventory/findings: manual, CSV mappings and ServiceNow CMDB | Release 1 |
| Cloud and BOM/CBOM: AWS, GCP and occurrence adapters | Release 2 |
| AI Grid/AI-BOM ownership producers and consumers | Release 3 |

Every subject family is assigned to exactly one migration domain. AI systems/artifacts and AI findings remain in the AI Grid domain regardless of whether a future AWS/GCP observation can reference them; any canonical cross-producer claim targeting that family stays `DARK`/ineligible until the Release-3 domain switch. State is recorded per tenant and domain, and each moves `LEGACY -> DARK -> CANONICAL`. A database constraint/service guard prevents legacy and canonical writers from being eligible for the same tenant/domain/subject. AI Grid therefore remains solely legacy through Releases 1–2 and switches only in Release 3; Release 1 does not claim to switch it.

Before any domain's first tenant switch, dark qualification uses representative authorized data and a dedicated internal canary tenant executes the complete switch/read-wave/recovery rehearsal. The canary must satisfy correctness, query, error and queue gates for at least 24 hours before batched tenant rollout.

For each domain switch:

1. Pause that tenant/domain's ownership mutations and source publication for a bounded window.
2. Reconcile dark claims/results and publish an impact report.
3. Select canonical resolution in read-only switch mode, stop the legacy writer/rule path and keep canonical mutations/publication blocked.
4. Freeze the domain's legacy owner columns, enable the **read-only compatibility adapter/view**, and run schema, RLS, inheritance, route, source and representative ownership smoke tests. The adapter returns DTO fields such as `ownerGroup` from the live effective-assignment/team join, never persists team text or descendant ownership, and therefore does not reintroduce rename/parent fan-out.
5. Make an explicit go/no-go decision. On no-go, return to `LEGACY` while no canonical mutation has been accepted. On go, record the authority acceptance event, enter `CANONICAL`, and only then resume canonical mutations/publication.

The automatic authority-rollback window is deliberately limited to steps 1–4 and closes at the step-5 go decision. DARK comparison, canary evidence and paused smoke tests carry the authority-switch risk. After canonical publication resumes, claims/mutations are retained and never silently discarded or hidden by an automatic return to `LEGACY`; recovery uses source pause, consumer rollback through the compatibility adapter and a forward fix. Any exceptional reverse migration requires a separately approved impact/export/reconciliation plan.

### 15.4 Per-consumer read waves

Consumer pages may contain rows from several authority domains. All list/detail/campaign/ticket readers therefore call one domain-aware ownership read adapter per row/subject:

- `CANONICAL`: return the live canonical effective assignment and stable team ID.
- `LEGACY` or production `DARK`: return the current legacy owner value through the same response envelope, with `authorityState=LEGACY_PENDING_MIGRATION`; exact reviewed team/alias mapping may supply a display/filter `ownerTeamId`, but this does not create a claim or make canonical ownership authoritative.
- A legacy-domain row is never reported as `UNOWNED` merely because its canonical domain has not switched. Unmapped legacy values remain visibly `LEGACY_PENDING_MIGRATION` and cannot auto-route through canonical team mapping.
- Any `ownerTeamId` supplied by this transitional legacy mapping is display/filter metadata only: it cannot drive routing, team-to-ticket assignment-group mapping, ticket defaults or campaign owner-at-add stable-ID snapshots; those operations must use the subject's active authority, and campaign stable ownership references remain null until canonical attribution exists.
- Correctness-sensitive mutations dispatch only to the subject's active authority. Canonical mutation endpoints reject legacy/dark subjects; transitional legacy actions remain route-gated until that domain switch.
- Mixed lists, counts, filters, exports and campaign membership include an authority-state bucket so users can distinguish Owned/Unowned/Conflict from Pending Migration. After all domains are canonical, the transition field/bucket is removed at cleanup.

This contract lets the Release-1 findings wave show host/asset legacy/canonical ownership alongside Release-2 occurrence and Release-3 AI rows without rendering later-domain findings as Unowned.

After at least one domain is canonical, flip consumers independently using server-side flags with an immediately reversible previous response/UI shape:

1. Inventory lists/details and ownership coverage.
2. Finding lists/details, saved queues and exception ownership snapshots.
3. Campaigns and CVE investigation.
4. Ticket creation/routing.
5. AI Grid/AI inventory and AI-BOM consumers.

Each wave requires consumer-specific contract tests, query/SLO evidence, error and mismatch telemetry, and an accountable go/no-go decision. Production waves observe at least 24 hours of healthy telemetry before the next wave unless the release authority documents why a longer window is required. Rollback flips only the affected consumer to the compatibility response/UI shape backed by live canonical data; it does not reactivate the legacy resolver, discard claims or require text mirroring. Source kill switches are not used as reader rollback.

### 15.5 Contract cleanup

After every consumer has remained on the canonical path for the approved stability window and repository scans/telemetry prove no legacy reader or writer remains:

- Drop `ownership_rules`.
- Drop `findings.owner_group` and old projection column/index.
- Drop obsolete AI Grid owner columns/history.
- Remove entity, repository, service, DTO, frontend types, fixtures and tests for legacy ownership.
- Remove free-text campaign/ticket owner fields that no longer have a historical contract.
- Remove the compatibility adapter and all consumer/domain-transition flags.

Database DDL is forward-only; no destructive schema downgrade is promised. Before contract cleanup, consumer response/UI behavior can roll back through per-consumer flags; canonical claims are retained. After cleanup, correct failures with source/publication kill switches and forward fixes. Database backup is for diagnosis and disaster recovery, not legacy product restoration.

## 16. Execution phases and deliverables

The requested scope remains one MVP program, delivered as three independently releasable increments plus cleanup. Entra, Okta, AWS, GCP, AI Grid, users/memberships, campaigns, CVE investigation and exception integration remain required for MVP completion; sequencing them later is not deferral.

### 16.1 Planning assumption and estimate gate

Initial rough-order planning floor, to be replaced by team-owned estimates:

| Workstream | Suggested dedicated capacity |
|---|---:|
| Ownership/platform/backend | 4–5 engineers |
| Connectors/data ingestion | 3–4 engineers |
| Consumer APIs/frontend/workflows | 3–4 engineers |
| Shared QA/SRE/security/product/architecture | 3–4 contributors |

With three parallel workstreams, the revised non-binding ROM is 26–36 calendar weeks after Phase 0A approval: Release 1 in 10–12 weeks, Release 2 in 7–10 weeks, Release 3 in 8–12 weeks and cleanup in 2–3 weeks, with overlap only after shared contracts stabilize. This is not a delivery commitment. Before implementation starts, accountable leads must publish a dependency-based estimate, named staffing, environments, external-provider access dates and critical path. Materially lower staffing requires scope/calendar re-estimation rather than silently compressing qualification.

### 16.2 Phase 0A: release-1 architecture gate

Use ten working days as the first Phase-0A decision checkpoint, not permission to waive unfinished evidence. The KMS spike is the first five-working-day critical path; a failed or incomplete spike/benchmark keeps Release 1 blocked and triggers re-estimation.

Release 1 may start only when these are approved:

1. Repository-aligned platform-versus-tenant-schema storage map, migration versions, RLS/grant and purge plan.
2. Deployed Render-to-KMS greenfield spike proving authentication, wrap/unwrap, encryption context, key cache, rotation, outage behavior and secret-redacted observability. It must decide and prototype the versioned encryption interface plus extension of `CredentialEncryptionService`/`ProviderCredentialMigrator` for tenant-key re-enveloping. No production PII or new connector-secret write is allowed if this fails.
3. Identity canonical key and encrypted exact/prefix-search contract with 100k/300k query plan.
4. Release-1 authorization matrix, including analyst manual-assignment alert/revocation.
5. Fixed precedence/inheritance contract, source TTL/staleness and anomaly thresholds.
6. ServiceNow CMDB field/permission/watermark contract from representative data.
7. Effective-owner join benchmark with approved query plan and a recorded decision on the `ownership_effective_cache` fallback.
8. Per-domain authority/read-flag, read-only compatibility-adapter and recovery test plan.
9. Named accountable leads, staffing/ROM plan and Release-1 acceptance evidence owners.

Exit: all nine Release-1 prerequisites pass. Later-provider/UI contracts do not block Release 1.

### 16.3 Phase 0B: rolling contracts

Complete each contract before its owning release begins:

| Contract | Required before |
|---|---|
| ServiceNow directory table/scope/identity-link contract | Release 2 |
| AWS/GCP producer fields, TTL and authority | Release 2 |
| BOM/CBOM occurrence identity and finding-adapter registry | Release 2 |
| Campaign/ticket materialization, outcomes and routing | Release 2 |
| Entra Graph and Okta scope/delta/incremental contracts | Release 3 |
| AI Grid/AI-BOM producer, consumer and legacy-removal ledger | Release 3 |
| CVE investigation multi-team/notification/campaign/ticket contract | Release 3 |
| Exception/suppression compatibility and UI contract | Release 3 |
| Full writer/consumer removal ledger and contract-cleanup migration | Cleanup |

Capacity assumptions, UI acceptance maps, PII inventory, accessibility criteria, test evidence and accountable people are updated per release rather than approved speculatively at program start.

### 16.4 Release 1: thin ownership vertical slice

- Tenant-key/KMS foundation and tenant-schema ownership migrations.
- Manual and CSV users, groups and memberships, encrypted prefix search, teams and shared alias namespace.
- ServiceNow CMDB claim producer, mappings, TTL/staleness and review items.
- Subject/edge/claim/direct-assignment model and bounded fallback inheritance.
- Manual subject assignment with mandatory reason, analyst alert and optional expiry.
- Inventory and finding domain-aware read paths, explanations and filters; canonical rows show effective ownership while later-domain rows retain legacy Pending Migration ownership.
- Vulnerability adapter v1 selects the affected asset only.
- Dark qualification, Release-1 domain authority switch, read-only compatibility adapter, then inventory and findings consumer waves.

Exit: manual/CSV and ServiceNow-CMDB-to-inventory/finding journeys pass isolation, encryption, inheritance, rollback, SLO and initial product-quality gates. Release 1 is deployable but is not the complete MVP.

### 16.5 Release 2: enterprise and remediation expansion

- ServiceNow directory users/groups/memberships and non-destructive linking.
- AWS and GCP ownership producers.
- BOM/SBOM/container/application occurrence and CBOM ownership adapters/UI.
- Vulnerability adapter v2 dark comparison, impact preview and idempotent asset-to-occurrence subject migration after the occurrence domain becomes canonical.
- Campaign materialization, owner-at-add/current-owner behavior and outcome classifier.
- Ticket mapping, preview and mixed-team routing.
- Campaign/ticket consumer read waves and exception owner-snapshot backend compatibility.
- Provider failure, pagination, rate-limit, anomaly and reconciliation qualification.

Exit: ServiceNow directory, both cloud producers, BOM/CBOM, campaigns and tickets meet their scorecards and rollback tests. Release 2 is deployable but is not the complete MVP.

### 16.6 Release 3: identity breadth, AI and investigation completion

- Entra initial/delta synchronization and Okta initial/incremental synchronization.
- AI Grid producer/consumer migration, AI systems/artifacts, AI-BOM and AI finding adapters.
- CVE workbench ownership coverage, application-principal/team selection, finding creation, notifications, campaign launch and mixed-team ticket batching.
- Exception/suppression UI integration across vulnerability, AI, BOM/CBOM and campaign contexts.
- AI Grid final consumer wave plus all remaining dashboards, exports, accessibility and visual regression.
- Real authorized provider-tenant qualification plus mocked failure suites.

Exit: all required MVP capabilities and section 18 gates pass; every ownership display traces to a direct or inherited effective assignment and no active consumer treats free text as authority.

### 16.7 Cleanup and general availability

- Complete expected and 3x scale, penetration, restore, provider outage, cursor reset and reconciliation exercises.
- Observe every canonical consumer for the approved stability window.
- Run the full repository writer/reader scan and contract migration from section 15.5.
- Remove legacy endpoints/rules/UI/storage, compatibility adapter and transition/read flags only after evidence approval.
- Finalize operational runbooks, dashboards, on-call ownership and release evidence.

Exit: section 18 scorecard passes, cleanup is irreversible only after sign-off, and accountable product/architecture/security/SRE/QA owners approve general availability.

## 17. Testing strategy

### 17.1 Unit and contract tests

- Identifier normalization and exact matching.
- Team/alias cross-table namespace, including concurrency.
- Identity-link ambiguity and mutable identifier handling.
- CSV parsing, limits, formula protection and dry-run token binding.
- Provider mapping and cursor behavior.
- Claim admission and idempotency.
- Resolver precedence, expiry, conflict and inactive target.
- Direct child claim versus higher-priority inherited parent claim, bounded six-hop inheritance, cycle detection and depth overflow.
- Release-1 vulnerability adapter selects asset; Release-2 version selects occurrence only after the occurrence domain is canonical.
- Source stale/expiry thresholds and immediate provider deletion/supersession.
- Encrypted exact/prefix search-token generation, key-version rotation and minimum-prefix enforcement.
- Finding adapter outcomes.
- BOM occurrence identity and single-parent inheritance.
- Global software identity aggregation without fabricated owner.
- AI posture/exposure canonical-target selection and guard tests proving runtime remains out of scope.
- Ownership and exception state-machine independence.
- Reopening after expiry uses the current assignment.
- MVP suppression-rule validation rejects ownership-dependent predicates.
- Ownership explanation stability.
- Masking and encryption round-trip.

### 17.2 Integration tests

- RLS and tenant-inclusive FK behavior for every table.
- Controller authorization matrix.
- KMS context and cross-tenant decrypt rejection.
- Deployed Render/KMS authentication, outage and rotation behavior.
- Durable retry/fence/idempotency behavior.
- Provider pagination, throttle and partial failure.
- Complete-scan deactivation versus failed-scan safety.
- Inventory/finding canonical-subject links expose assignment changes through effective joins without copied owner-name writes.
- Parent assignment changes affect BOM occurrences and AI artifacts through bounded inheritance joins without descendant assignment fan-out.
- If selected, effective-cache per-subject or subtree version invalidation, bounded refresh, stale display behavior and live validation for ticket/exception/campaign writes.
- Effective cache uses per-subject/subtree versions, never a tenant-wide churn epoch, and refresh payloads contain no display names.
- Campaign/ticket stable team behavior.
- Campaign materialization/reconciliation, immutable owner-at-add snapshots, current-owner change indicators and team-rename stability.
- CVE investigation multi-team aggregation, coordinator separation, canonical notification recipients and no first-owner fallback.
- Legacy writer-control scan.
- Per-domain writer exclusion, read-only compatibility adapter and independent inventory/findings/campaign/ticket/AI Grid consumer rollback.
- Mixed-domain finding/campaign reads return canonical ownership for canonical rows and legacy Pending Migration values for later-domain rows without false Unowned results.
- Analyst single-subject workflow-scope validation and 100-descendant/1,000-finding impact-limit rejection.
- Canary and paused switch steps 1–4 can return to legacy; after step-5 acceptance, authority rollback is rejected and consumer recovery remains available.
- Shared suppression matcher and canonical mutation service remain valid after ownership-rule removal.
- Exception snapshot tenant FKs/RLS and expiry worker tenant context.

### 17.3 End-to-end user journeys

1. Manual user/group/team creation through finding display.
2. CSV dry run through imported membership and mapping.
3. ServiceNow directory plus CMDB claim through resolved asset/finding.
4. Entra and Okta sync with one canonical person and multiple external identities.
5. AWS/GCP source conflict and review resolution.
6. Manual assignment, expiry and fallback.
7. Campaign materialization, stable grouping, owner-at-add/current-owner display and ticket assignment-group mapping.
8. Unowned/conflict/stale UI states.
9. Source failure, pause, recovery and reconciliation.
10. Tenant A cannot discover, read, mutate or decrypt Tenant B data.
11. One software identity in differently owned assets preserves separate occurrence owners.
12. Container component ownership remains bound to immutable image digest across tag movement.
13. CBOM finding derives through its contextual cryptographic component/asset.
14. AI posture and exposure findings resolve the intended AI target and conflict on differently owned primary targets; runtime APIs remain HTTP 410/out of scope.
15. Direct/requested suppression, false positive and accepted risk retain ownership and owner-at-decision audit snapshots.
16. Suppression expiry/reversal reopens a finding with its current owner assignment.
17. Ownership changes while suppressed change the effective owner read without changing exception state.
18. AI and BOM/CBOM exception workflows preserve their canonical targets and type-specific gates.
19. One CVE affecting several teams displays all team buckets plus Unowned/Conflict without assigning an owner to the CVE.
20. CVE finding creation derives each owner from its canonical subject; lead analyst and coordinator do not overwrite it.
21. CVE notification, campaign launch and mixed-team ticket previews use stable team/finding IDs and preserve exception decisions.
22. Each domain switch prevents overlapping writers; every consumer wave can roll back its response/UI shape without discarding canonical claims.
23. A Release-1 findings page containing host, occurrence and AI findings shows later-domain legacy ownership as Pending Migration, not Unowned.
24. Release-2 adapter migration changes eligible vulnerability findings from asset to occurrence idempotently after impact preview.

### 17.4 Non-functional tests

- Expected and 3x capacity.
- Concurrent provider syncs and user writes.
- Large membership group search.
- Claim burst and projection backlog.
- Effective-owner joins across 5M expected and 15M qualification component occurrences, including a parent owner change with zero descendant assignment/name rewrites.
- Encrypted prefix search at 100k and 300k users, including key rotation rebuild under concurrent reads.
- KMS outage.
- Provider timeout/rate limit/cursor invalidation.
- CSV maximum and rejection limits.
- Accessibility WCAG checks and keyboard-only workflows.
- Visual regression for all ownership states.

## 18. Release scorecard

All measures are blocking unless an explicitly named release authority accepts a time-bound exception.

| Category | Gate |
|---|---|
| Legacy removal | No active endpoint, writer, reader, DTO, filter or UI mutation uses legacy ownership authority |
| Identity | Manual, CSV, ServiceNow, Entra and Okta journeys pass |
| Producers | ServiceNow CMDB, AWS, GCP and AI Grid claims pass contract tests |
| Resolution | Deterministic direct precedence, fallback-only bounded inheritance, cycle/depth handling and zero-write unchanged replay |
| Findings | All finding kinds return owned, conflict or unowned through registered adapters |
| Inventory | Raw evidence and resolved assignment are visually distinct |
| BOM components | Occurrence-scoped ownership works for SBOM, container, host/application and CBOM; global identities do not fabricate one owner |
| AI inventory | Every AI inventory type reads the common assignment model; no independent AI owner authority remains |
| AI findings | Posture and exposure findings select the registered AI target and expose multi-target conflict; no runtime adapter/UI/gate is enabled |
| Exceptions | Direct/requested suppression, false positive, accepted risk, expiry/reopen and CBOM gates pass without changing ownership state |
| Suppression rules | Existing non-ownership rule lifecycle works; ownership predicates are rejected; shared matcher survives legacy ownership removal |
| Campaign | All campaign types have materialized, idempotent finding membership; stable team IDs drive grouping; owner-at-add and current owner remain distinct |
| CVE investigation | Lead/coordinator are distinct from all affected owners; multi-team, Unowned and Conflict flows never choose a first-owner fallback |
| Ticket | Stable owner-team IDs drive external assignment-group mapping and mixed-team batching |
| Isolation | Cross-tenant CRUD, IDOR, FK, job, cache and decrypt suites pass |
| Security | Deployed Render/KMS authentication plus KMS, SSRF, secret redaction, upload and export suites pass |
| PII | Encrypted, masked, audited and purge-covered; zero plaintext PII columns/logs; exact/prefix search meets its leakage review and SLO |
| Reliability | Partial sync cannot deactivate; retries and reconciliation converge |
| Cutover | Per-domain writers never overlap; mixed-domain reads preserve later-domain legacy values as Pending Migration; AI Grid remains legacy until Release 3; compatibility adapter persists no owner text; canary and each consumer rollback are exercised before cleanup |
| Performance | Section 13 SLOs pass at expected size; 3x completes without blocking reads |
| Product quality | Section 13 coverage, conflict, unmapped, stale and review-time targets pass or have an approved time-bound exception |
| Accessibility | New workflows pass keyboard, screen-reader and visual checks |
| Operations | Dashboards, alerts, kill switches and runbooks verified |

## 19. Operational runbooks

Required before release:

- Provider credentials invalid/expired.
- Entra delta token invalid.
- Okta/ServiceNow throttling or pagination failure.
- Mass-deactivation anomaly pause.
- Ownership-change anomaly pause.
- Resolver/projection backlog.
- Poison work and targeted replay.
- KMS unavailable or key-version mismatch.
- Cross-tenant/RLS invariant alert.
- Manual reconciliation and tenant projection rebuild.
- Tenant purge and key destruction.
- Forward fix after migration/cutover failure.
- Domain-switch rollback before the first canonical mutation, plus post-canonical source-pause/consumer-rollback/forward-fix recovery.
- Individual inventory/findings/campaign/ticket/AI Grid consumer rollback.
- Mixed-domain compatibility-adapter mismatch or false-Unowned detection.
- Canary failure during paused authority-switch steps 1–4.
- Prefix-search token rebuild/key rotation failure.
- Source stale threshold, claim expiry and unexpected ownership fallback.

## 20. Risks and mitigations

| Risk | Mitigation |
|---|---|
| MVP spans too many providers | Shared connector/source framework, provider contract gates and staged enablement |
| Program scope exceeds available team/calendar | Three releasable increments, planning floor/ROM gate, named staffing and dependency estimate before commitment |
| Duplicate people across sources | External identity links, exact identifiers, ambiguity review, no destructive auto-merge |
| Directory groups confused with teams | Separate models and explicit reviewed mapping |
| Raw CMDB/cloud data shown as authority | Common ownership summary and evidence separation |
| Failed sync removes valid identities | Complete-scan rule, anomaly pause and reconciliation |
| Source conflict routes to wrong team | Explicit `CONFLICT`, no auto-routing |
| Free-text fields survive in hidden consumers | Mechanical writer/consumer ledger and CI architecture tests |
| PII introduced before keys | Phase 0A deployed KMS spike, Release-1 key gate and deployed-profile rejection |
| Cloud tags create team sprawl | Exact reviewed aliases; never auto-create teams |
| Campaign/ticket semantics drift | Stable team ID contract and explicit external ticket mapping |
| CVE investigation assigns every occurrence to one group | Treat CVE as non-ownable intelligence; aggregate owners per canonical affected subject and separate coordinator/lead |
| Dynamic CVE campaign membership loses attribution | Materialize idempotent `campaign_findings`, preserve owner-at-add and reconcile additions without deleting history |
| Provider-specific UI fragments | Shared source and ownership components |
| Ownership fan-out overload | Direct assignments only plus bounded parent joins; no descendant assignment/name rewrites; optional cache permits only bounded stable-ID refresh using per-subtree/per-subject versions |
| Ownership cutover breaks suppression | Preserve canonical suppression services/APIs, prohibit owner predicates in MVP and run cross-lifecycle regression suites |

## 21. Deferred capabilities for future execution

Deferred items are intentionally excluded from MVP, not forgotten. Each requires a separate approval and implementation increment.

### 21.1 Tenant-defined policy language

Future capability:

- Versioned draft/review/activate lifecycle.
- Constrained rule builder, not arbitrary code.
- Scope by asset type, environment, provider, account and criticality.
- Per-scope precedence, exclusions, inheritance and fallback.
- Dry-run simulation, impact preview, snapshot and rollback.
- Complexity/execution limits and stale-simulation invalidation.

Start when at least two validated tenants require different precedence that fixed configuration cannot express.

### 21.2 Multiple ownership roles

Add business, security, data, application/model and escalation owner roles. Start when workflows demonstrate that one technical owner cannot represent accountability without overloading team mappings.

### 21.3 Complex topology and inheritance

Add tenant-editable multi-parent typed graphs, deep inheritance, topology approvals and high-fan-out impact controls. Start after simple application/account/asset/component relationships are qualified and a real tenant requires more.

### 21.4 Governance and approvals

Add second-admin approval for high-impact assignments, topology changes, mappings, bulk changes and policy activation. Include single-admin tenant limitations and approval SLAs. Start for enterprise governance/compliance requirements.

### 21.5 Advanced routing workflow

Add automatic team queues, SLA clocks, escalation, accept/reject, notifications and reassignment workflow. Start after ownership accuracy and team/ticket mappings meet agreed coverage.

### 21.6 Temporary finding overrides

Add reason-bound, expiring finding-only overrides for exceptional incident coordination. Default remains subject ownership. Start only when customers demonstrate legitimate cases that cannot be represented on the canonical subject.

### 21.7 Extended identity providers

Add LDAP/AD, Ping, Google Workspace, OneLogin and JumpCloud through the qualified source framework. Each requires provider-specific permissions, cursor, deletion, SSRF and real-tenant qualification.

### 21.8 Azure resource ownership

Add Azure Resource Graph/ARM producer for subscriptions, resource groups, resources and tags. Entra identity support does not satisfy this capability. Start when Azure resource inventory ownership is an approved product requirement.

### 21.9 Repository and code ownership

Add CODEOWNERS and repository-provider claims with reviewed repository-to-application/asset relationships. Start when repository subjects and source permissions are stable.

### 21.10 Advanced bulk governance

Add governed bulk assignment/mapping, resumable rollback and large-impact approval. MVP bulk operations remain bounded and administrative.

### 21.11 Advanced privacy administration

Add tenant-configurable anonymization, retention, residency reporting, legal hold and export policies. MVP uses approved platform defaults and documented erasure/purge procedures.

### 21.12 Event partitioning and tenant retention controls

If measured event volume justifies it, partition events monthly from the first production migration; otherwise begin with an indexed append-only table and a platform retention job. Tenant-configurable retention/reporting remains deferred.

### 21.13 Confidence scoring and ML-assisted mapping

Do not use opaque confidence to choose MVP owners. Future assisted suggestions may rank mappings, but a human must review identity/group/team links and the deterministic resolver must remain explainable.

### 21.14 Advanced campaign and workflow analytics

Add mean-time-to-own, reassignment churn, campaign scope-drift trends, CVE ownership-concentration/coverage history, SLA by owner team, acceptance latency and escalations after ownership and routing workflows have sufficient production data.

### 21.15 Owner-aware automated suppression

Allow stable `ownerTeamId`/`ownershipStatus` predicates only after targeted suppression reevaluation on assignment change, impact preview, bounded execution, rule-version evidence and reversal/rollback are implemented. Free-text owner/support-group predicates remain prohibited.

## 22. Final implementation rule

The MVP must preserve one invariant across every backend service and UI surface:

> Source systems produce evidence, the ownership resolver produces one canonical subject assignment, and inventory, findings, CVE investigations, campaigns and tickets consume or aggregate that assignment by stable ID.

No screen or service may independently infer an authoritative owner from free text, raw CMDB fields, cloud tags or directory membership.

Exception management remains orthogonal: suppression and decision workflows may snapshot and display ownership, but they never create, clear or resolve ownership assignments.
