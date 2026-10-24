# Platform Owner and SG Internal Tenant — MVP Implementation Plan

## 1. Outcome and architectural approach

Implement the agreed flow within the existing Spring Boot, React, and PostgreSQL application. Reuse its authentication, invitation delivery, tenant provisioning, and durable job infrastructure.

The operating flow becomes:

**Bootstrap both identities and SG Internal → Activate accounts independently → Ingest central intelligence into staging → Deduplicate and review selected feed runs → Approve and publish → Automatically correlate eligible tenants → Create or update findings.**

Keep all activity documentation in [PO & SG Internal Tenant Flow](</Users/karthik/Desktop/SG/Working Knowledge/PO & SG Internal Tenant Flow>). During implementation, update the existing flow document and add `implementation-plan.md` and `implementation-evidence.md` there.

The latest decisions supersede the earlier flow document:

- This is the first release; there are no active integrations requiring a legacy-data transition.
- MFA is outside scope and is not an activation dependency for this MVP.
- One bootstrap operation provisions both accounts and SG Internal.
- Two distinct email aliases reaching the platform owner receive separate activation emails.
- The owner selects completed feed runs for publication.
- Manual advisories obey tenant source settings.
- Disabling a source makes findings supported only by that source inactive, retaining history.
- EOL remains platform-owned but outside the vulnerability/advisory approval gate.
- One platform owner can review and publish; no second approver or mandatory SG validation gate.

## 2. Architecture and interface changes

### Separate staging from approved intelligence

Keep the existing central vulnerability tables as the **approved runtime projection** consumed by tenant queries and correlation. Introduce staging and immutable release records alongside them.

This avoids adding a second runtime, message broker, or per-tenant vulnerability database.

Add these platform records:

| Record | Purpose |
|---|---|
| Staged intelligence records | Run-scoped normalized observations, affected-product rules, version ranges, configuration expressions, GHSA package data, VEX assertions, and validation results |
| Review candidates and candidate records | Selected run checkpoints, base release, immutable proposed changes, quality report, exclusions, and content digest |
| Releases | Published candidate, predecessor, approved content changes, previous values, digest, actor, and timestamps |
| Active intelligence state | Singleton holding the current release and generation |
| Publication outbox | Durable publication/fan-out work with retry and progress state |
| Verified identifier aliases | Resolve source identifiers to stable canonical vulnerability identities |

Retain existing approved UUIDs wherever possible. Published releases and their evidence remain immutable; corrections create another release.

All intelligence writers must cross this boundary, including single-CVE refresh, manual imports, GHSA-specific storage, VEX repair/backfill, and existing EPSS enrichment. Updating only the main ingestion method would leave bypasses.

### Publication transaction

Build candidates before publication. On approval, use the existing job infrastructure to perform publication asynchronously:

1. Validate the candidate digest and unchanged base release.
2. Acquire the publication lock.
3. Apply prepared changes to approved observations and all matching artefacts.
4. Update canonical summaries and the active release generation.
5. Commit the release, audit event, and durable fan-out intent together.

A failed transaction leaves the previous approved state intact. Tenant processing begins only after commit.

Multi-query reads and correlation use consistent database snapshots; PostgreSQL’s default isolation permits successive queries to see different committed states, so transaction boundaries must be explicit. [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)

### Public interfaces

Add owner-only endpoints under `/api/platform/intelligence`:

| Endpoint | Behaviour |
|---|---|
| `POST /candidates` | Accept selected successful `syncRunIds`; return candidate ID and build status |
| `GET /candidates/{id}` | Return digest, base release, counts, exclusions, quality report, and status |
| `GET /candidates/{id}/records` | Paginated canonical changes and supporting source evidence |
| `POST /candidates/{id}/publish` | Require reviewed digest, base release, and idempotency key; return asynchronous publication status |
| `POST /candidates/{id}/reject` | Record rejection reason without changing approved intelligence |
| `GET /releases` | Publication history |
| `GET /releases/{id}/processing` | Paginated tenant processing status |
| `POST /releases/{id}/withdraw` | Withdraw the active release and restore its predecessor through an audited corrective publication |

For MVP, withdrawal applies only to the active release. Older errors require a corrective candidate. Withdrawing the first release restores empty approved intelligence.

Extend existing tenant source settings and finding responses rather than introducing parallel configuration APIs. Add tenant processing status showing current release, last completed evaluation, pending work, and failures.

## 3. Ordered implementation work packages

### Phase 1 — Reserve SG Internal and separate identities

**Deliverable:** Repeatable installation bootstrap with two independently activated accounts.

- Add protected tenant classification: `INTERNAL` or `CUSTOMER`.
- Bind the reserved internal tenant to `tenant_default`; preserve an existing valid tenant ID rather than replacing it.
- Replace name-based default-tenant discovery and “first usable tenant” fallback with explicit reserved identity resolution.
- Display the tenant as **SG Internal**, retaining the existing slug for compatibility.
- Prevent customer provisioning from choosing the reserved identity, schema, or classification.
- Exclude SG Internal from demo expiry, automatic cleanup, and ordinary deletion.
- Provision Enterprise entitlements and sufficient quotas for every supported tenant capability through normal authorization paths.
- Remove playground bootstrap membership grants to platform-owner identities. Retain explicit audited support access.
- Keep missing tenant context denied.

Extend the privileged bootstrap CLI to require distinct owner and internal-admin email aliases. After schema readiness, create both passwordless identities and commit their setup authority and delivery intent in one operation.

The owner receives platform authority only. The internal administrator receives `TENANT_ADMIN` membership only. Both can activate independently; neither waits for the other.

Bootstrap reruns verify state without resetting credentials or reissuing invitations. Conflicting existing identities or schema mappings stop the operation with a clear diagnostic.

### Phase 2 — Reuse activation and email delivery

**Deliverable:** Two safe, independently recoverable setup invitations.

- Reuse existing token digests, fragment-link exchange, setup cookies, CSRF checks, and password establishment.
- Extend the encrypted invitation outbox with an explicit platform-owner setup delivery type.
- Allow tenant-free outbox records only for platform setup; retain mandatory tenant binding for tenant invitations.
- Refactor the CLI setup-link issuer to enqueue delivery after committing authority, replacing its direct provider call inside the database transaction.
- Share the existing encryption and payload format between bootstrap and runtime delivery without starting the application with migration credentials.
- Use a configurable 30-minute default activation lifetime for both initial accounts.
- Preserve existing bounded retries, provider idempotency, and uncertain-delivery reconciliation.
- Require explicit reissue after expiry; normal deployment never rotates an active setup link.

Use the neutral email template already agreed, with an absolute expiry timestamp to remain accurate after delivery delays:

> **Subject:** Complete your SG account setup  
>
> Hello,  
>
> You have been invited to set up an SG account.  
>
> **[Complete account setup]**  
>
> This link expires at {expiry_with_timezone} and can be used once. Do not forward this email or share the link.  
>
> If you were not expecting this invitation, leave the link unused and contact your administrator through your usual channel.  
>
> SG

Keep roles, workspace names, schema names, internal identifiers, and deployment information out of subjects, bodies, URLs, and provider tags. Use opaque delivery identifiers, disable click tracking, and exclude activation secrets from logs and analytics.

Single-use, expiring, securely stored tokens follow [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

### Phase 3 — Stage ingestion and deduplicate before review

**Deliverable:** Successful synchronization produces reviewable data without affecting tenants.

- Introduce one staging interface used by every vulnerability/advisory ingestion path.
- Stage complete matching evidence, not only titles and severity.
- Remove direct tenant recomputation and approved-table writes from fetch/normalization paths.
- Freeze staged records when a run completes. Failed or incomplete runs are not publication candidates.
- Separate fetched continuity checkpoints from published checkpoints.
- When selecting an incremental run, include its required successful unpublished predecessors. Show the expanded selection before review.
- Apply explicit withdrawals; absence from an incremental response does not imply withdrawal.
- Deduplicate by authoritative identifiers and verified structured aliases. Never merge solely from description similarity or incidental CVE mentions.
- Preserve one-to-many advisory relationships and source observations.
- Quarantine ambiguous aliases and invalid records. Review explicitly identifies excluded records.
- Reuse existing deterministic source precedence and scoring rules, applying them only to eligible source evidence.
- Include the normalization-policy version in the candidate digest.

Later alias discoveries must preserve canonical redirects and finding history while consolidating duplicate exposure identities.

### Phase 4 — Add review, publication, and scope-specific connectors

**Deliverable:** The owner can manage central sources and publish an exact reviewed candidate.

Platform navigation exposes central feed configuration, triggers, schedules, ingestion history, candidate review, releases, and processing health. Remove inventory/BOM connectors and their configuration queries from platform scope.

Tenant navigation retains inventory integrations and source enablement settings. Inventory connectors remain tenant capabilities, including in SG Internal.

The review screen shows canonical additions, changes, withdrawals, rejected records, merge counts, source freshness, affected-version quality, and volume changes.

Use **Approve and publish** as the single release action. Additional ingestion cannot change a candidate under review. A stale base release requires rebuilding and reviewing the candidate.

Tighten existing central ingestion endpoints to platform-owner authority. Preserve existing URLs where practical, but remove tenant-admin permission to trigger shared feeds. Enforce this in services and background execution as well as controllers.

### Phase 5 — Automatic tenant processing and finding lifecycle

**Deliverable:** Publication creates findings automatically for enabled sources.

- Reuse existing PostgreSQL queues and workers.
- Fan out committed publication intent in bounded, resumable tenant batches.
- Schedule processing on publication, source enablement, inventory changes, tenant activation/resumption, and approved corrections or withdrawals.
- Recheck tenant readiness and source settings at execution.
- Use one source registry to align connector IDs, normalized evidence sources, and tenant settings. Include manual advisories as configurable.
- Default supported sources to enabled, preserving current behaviour; persist settings explicitly for new tenants.
- Treat enrichment-only evidence as enrichment, never sufficient applicability evidence by itself.
- Resolve applicability, VEX, severity, KEV, and risk inputs using enabled approved evidence. Disabled-source values cannot influence correlation or scoring.
- Reconcile GHSA-specific integration controls with the same source setting rather than maintaining conflicting switches.

Add a tenant processing revision record and release/revision metadata to jobs and evaluated findings. Fence bounded worker transactions against changed release, source-setting, or inventory revisions. Superseded work evaluates the latest required state; completion cannot overwrite newer results.

Add finding intelligence eligibility separately from workflow status:

- `ELIGIBLE`
- `SOURCE_DISABLED`
- `INTELLIGENCE_WITHDRAWN`

Source-disabled findings leave actionable lists and counts while retaining evidence, analyst decisions, and incident references. Re-enabling the source reevaluates the same finding identity without erasing manual suppression or resolution.

Apply the same eligibility rule across dashboards, exports, notifications, and downstream workflows. Deduplicate finding writes and workflow side effects; never interpret source disablement as remediation.

## 4. Verification and release sequence

Append migrations after the current platform V6 and tenant V5 heads; recheck allocation before implementation. Update migration catalog tests, compatibility checks, runtime grants, and tenant isolation policies. Do not rewrite applied migrations or reset shared databases.

Required acceptance scenarios:

1. **Bootstrap:** Empty installation creates exactly one internal tenant and two separate accounts; reruns preserve data, credentials, and invitation state.
2. **Authorization:** Owner credentials cannot perform ordinary tenant inventory operations; internal-admin credentials cannot invoke platform APIs. Customer requests cannot claim SG Internal.
3. **Activation:** Both invitations work independently; expiry, reissue, replay, scanner GETs, duplicate delivery, and provider uncertainty preserve account authority.
4. **Staging isolation:** Every ingestion path—including EPSS, GHSA, VEX maintenance, and single-record refresh—leaves tenant reads, matching, and findings unchanged before publication.
5. **Deduplication:** Repeated ingestion and verified aliases yield one canonical vulnerability; multi-CVE advisories remain distinct; ambiguous relationships are quarantined.
6. **Publication:** Concurrent approval, changed digests, stale candidates, crashes, and duplicate requests cannot expose partial intelligence or lose processing intent.
7. **Tenant behaviour:** Enabled sources process automatically; disabled sources do not influence matching or scores. New inventory and source enablement trigger evaluation without tenant approval.
8. **Finding history:** Disable/re-enable, withdrawal, retries, and alias consolidation preserve identity and analyst decisions without duplicate findings or external side effects.
9. **Isolation and recovery:** One failed tenant does not block others; restart, tenant suspension/resumption, and stale workers converge to the correct approved state.
10. **Usability:** Browser journeys cover both activations, platform-only connectors, candidate review/publication, and automatic SG Internal findings.

Run targeted tests during each phase, then backend `mvn -Ppostgres-it verify` and frontend type checking, unit tests, lint, and production build. Exercise a representative full-feed dataset to verify transaction duration, queue recovery, and bounded memory use.

Deploy through the existing migration control plane with feed schedules disabled. Verify bootstrap, activations, and schema grants; ingest and publish the first reviewed candidate; confirm automatic tenant findings; then enable configured schedules.

Monitor ingestion failures, candidate age, publication failures, queue age, tenant processing failures, and invitation delivery state. Record release evidence and operational recovery instructions in the activity folder.

## 5. Explicit MVP boundaries

- No MFA, external identity-provider migration, new broker, microservices, or duplicate per-tenant intelligence databases.
- No historical-data migration or automatic approval of seed/demo intelligence.
- No customer acceptance, import, or adoption step.
- No mandatory internal canary or second-person approval.
- No general draft-data preview environment or arbitrary historical rollback UI.
- EOL continues its existing platform-owned lifecycle processing.
- “All tenant capabilities” means all currently supported capabilities; globally unavailable functionality stays unavailable.
- Live credentials, email delivery, migrations, and deployment are implementation operations; this plan does not execute them.
