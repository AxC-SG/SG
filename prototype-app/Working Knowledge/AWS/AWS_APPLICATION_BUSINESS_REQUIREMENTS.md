# ScoutGrid application repair: business requirements

**Prepared:** October 18, 2026. **Status:** requirements with local Phase 1/2 implementation recorded in the technical plan; release acceptance remains pending.

**Source:** [Application prerequisites and remediation plan](AWS_APPLICATION_PREREQUISITES.md), scope revised October 18, 2026.

This document translates the plan's 36 definitions of done into business requirements and observable acceptance criteria for nontechnical stakeholders. Each **BR-Pxx** maps to the same **Pxx** in the technical plan. The technical plan retains implementation details, assigned teams, severity, delivery priority and estimates. This translation does not mark any repair complete or authorize changes to a live environment.

Local progress on October 20: Phase 2 adds protection for customer credentials and invitations, immediate access removal, safe connection cleanup, public request limits and browser error reporting. Customer deletion, live SCCM, synthetic recommendations and unfinished customer OSV correlation remain unavailable. Existing invitations may need reissue and old AWS connections need reconnection after an authorized release. The technical plan records verification and remaining operator actions; the application has not been deployed by this work.

## Scope and terms

The goal is to correct security, data accuracy, access, processing and recovery problems in the existing ScoutGrid application. A **customer workspace** is one customer's separate area, called a *tenant* in the technical plan. A **platform owner** administers the overall service. A **connector** brings information from an external customer data source into ScoutGrid. A **software inventory** lists software components and is called a BOM or SBOM in the technical plan.

**Generative AI assistance** produces text through an external AI service; the existing rule-based assessments do not require it. **Direct requests** reach the application without using its screens, so hiding a screen alone cannot enforce a restriction. **CSV** is the spreadsheet-compatible export format; **JSON** is the existing format for exchanging structured records with other tools.

Although these documents sit in the AWS folder, this program covers the current application on Render and Vercel. Moving to AWS, building new capabilities, changing identity or email providers, and making new availability, recovery, retention or compliance commitments remain separate work.

## Delivery and pilot boundaries

| Milestone | Requirements | Business outcome |
| --- | --- | --- |
| M1 — Immediate protection | BR-P01–BR-P09, BR-P15, BR-P22, BR-P25, BR-P30, BR-P33 | Prevent unauthorized access and customer data exposure; protect existing data; block unsafe exposed operations. |
| M2 — Consistent operation and recovery | BR-P10–BR-P14, BR-P16–BR-P21, BR-P23–BR-P24, BR-P26–BR-P29, BR-P31–BR-P32, BR-P34–BR-P35 | Accepted work, customer setup, sign-in, cleanup and status reporting behave consistently and recover safely. |
| M3 — Release evidence | BR-P36 | Demonstrate that the agreed repairs and feature restrictions work together in the current application. |

Requirement numbers provide traceability, not an implementation sequence. Release the limited BR-P01 permission fix first, with the urgent BR-P02 protection against previously issued excessive access addressed alongside it. The full BR-P02 repair remains separately tracked. BR-P03 and BR-P25 can also be delivered independently.

The source plan calls for immediate checks or restrictions on API-key sign-in, new demo approvals, workspace deletion, optional generative AI and general Azure discovery. Record any operational pause separately from a system-enforced block. Review existing access, outstanding invitations, and queued or running work separately; stopping new requests alone does not resolve them. Live actions require the authorization applicable to that environment.

| Pilot decision | Required business behavior |
| --- | --- |
| Live SCCM connections, the Microsoft device inventory integration | Unavailable through every existing access route, including saved and queued work. Sample data must not stand in for a customer's live inventory. |
| General Azure resource discovery | Disabled while existing assets are preserved. The separate supported AI asset inventory capability is assessed independently. |
| Moving content to the local archive | Disabled. Keep available descriptions and source content in the application database; identify inaccessible historical archive content honestly. |
| Optional generative AI assistance | Disabled. Existing rule-based assessments, findings, summaries and progress reporting continue. |
| Customer plan restrictions | Enforced for an explicitly named pilot group after its agreed feature-access rules are verified. Observation-only mode does not satisfy enforcement. |
| Unfinished capabilities | Unavailable, with no sample or invented output represented as customer evidence. |
| Audit export | Retain authorized spreadsheet export with safe text handling. A temporary restriction is acceptable only as recorded containment, while authorized JSON export remains available. |

## Business requirements

### BR-P01 — Keep workspace administration separate from platform ownership · [P01](AWS_APPLICATION_PREREQUISITES.md#p01)

**Requirement:** Customer workspace administrators must manage only permitted workspace roles and must never gain platform-wide ownership through membership changes.

**Accepted when:**

- Creating, changing, inviting or activating a member accepts only permitted workspace roles. Every platform-wide, system or unrecognized role is rejected, including when using stored roles or issuing access credentials.
- Normal workspace access and legitimate platform-owner access continue to work, including when an owner selects a customer workspace.
- Unexpected existing roles and ownership grants are reviewed while preserving evidence.
- This focused repair can be released independently; existing elevated sign-in/access credentials and grants are separately contained under BR-P02 before the overall privilege boundary is considered safe.

### BR-P02 — Make access removal take effect on the next action · [P02](AWS_APPLICATION_PREREQUISITES.md#p02)

**Requirement:** A person's current approved access and active status must determine what they can do, including when they use existing sign-in/access credentials.

**Accepted when:**

- Removing platform ownership, reducing administrator privileges, disabling a user, or revoking workspace or support access denies the next prohibited action.
- Existing and newly issued credentials cannot restore removed roles or recreate unauthorized ownership.
- Previously elevated credentials and all existing ownership records, including the older owner setting, are reviewed and contained while legitimate current owners retain access.
- The urgent ownership repair can ship alongside BR-P01; remaining access-removal requirements stay open until verified across the existing sign-in methods.

### BR-P03 — Keep each customer's connector activity independent · [P03](AWS_APPLICATION_PREREQUISITES.md#p03)

**Requirement:** Each customer workspace must independently start, schedule and view its own existing inventory connections without interference or information exposure from other customers.

**Accepted when:**

- Two customer workspaces can independently start and schedule supported, enabled AWS, Azure and inventory-management connections; pilot-disabled connections stay disabled.
- Neither customer receives the other's run reference, progress, history or related information through status views or scheduling decisions.
- Simultaneous requests for the same workspace and connection configuration produce one effective run; separate supported configurations remain distinct.
- These checks cover manual requests, status views and scheduled activity while intentionally shared threat-intelligence feeds continue to operate as shared services.

### BR-P04 — Prevent operation with unsafe production settings · [P04](AWS_APPLICATION_PREREQUISITES.md#p04)

**Requirement:** The application must start only with approved settings that identify its operating environment and what each service is allowed to do, while preserving production access protections.

**Accepted when:**

- Approved current operating configurations start successfully; missing or unrecognized service duties and unsafe production combinations prevent startup.
- Production cannot enable the existing API-key route that can grant platform-owner access; the effective deployed settings are verified.
- Inappropriate demonstration personas, mock data, initial setup shortcuts and customer-workspace selection through request headers are rejected in production.
- Security keys meet the requirements of their actual use and format, including encryption keys, rather than passing solely because their text is long enough.

### BR-P05 — Protect connection secrets and invitation access · [P05](AWS_APPLICATION_PREREQUISITES.md#p05)

**Requirement:** Stored customer connection credentials and invitation/setup codes must remain protected throughout use, replacement and recovery.

**Accepted when:**

- New provider credentials are encrypted; customer and demo invitation records allow code validation without keeping readable codes. Existing readable values are removed through a controlled transition.
- Invitations expire, work once even under simultaneous acceptance, and remain consistent when reissued; legacy links expire, are reissued or have a defined transition limit.
- New invitation/setup requests and monitoring records do not expose codes in request addresses, logs or diagnostics.
- Encryption-key replacement and backup recovery preserve authorized access; previously identified potentially exposed credential material is checked and revoked or replaced if active.

### BR-P06 — Protect public access without blocking legitimate sign-ins · [P06](AWS_APPLICATION_PREREQUISITES.md#p06)

**Requirement:** Public-request protections must identify callers through trusted hosting routes and keep registration abuse from consuming legitimate sign-in allowances.

**Accepted when:**

- Forged caller-address claims and untrusted direct access cannot bypass controls; the current hosting configuration is recorded.
- Exhausting registration's allowance leaves a fresh trusted sign-in address its existing 30 checks across different emails per 15 minutes; check 31 is denied. Each email address retains 10 checks per 15 minutes across caller addresses; check 11 is denied, unless approved settings intentionally change.
- Existing email and access-code protections remain effective.
- Documentation and checks accurately explain that counters apply to each running application process, including restarts and multiple processes.

### BR-P07 — Verify the customer identity used by AWS connections · [P07](AWS_APPLICATION_PREREQUISITES.md#p07)

**Requirement:** Existing AWS connections must access only the customer workspace, account and approved access role to which they are bound.

**Accepted when:**

- Each connection has a unique application-issued verification identifier that customers cannot arbitrarily replace; the account and role details agree.
- Saving, starting and executing a connection verify its authorization; execution confirms the effective customer account before collecting information, even if the separate connection test was skipped.
- Missing roles, incorrect customer/account bindings and invalid verification identifiers are rejected before collection; customer connections cannot silently use platform credentials.
- Controlled simulations demonstrate valid and invalid bindings. This requirement does not create AWS resources or treat possession of another identifier as proof of account access.

### BR-P08 — Keep connection credentials separate and pause live SCCM access · [P08](AWS_APPLICATION_PREREQUISITES.md#p08)

**Requirement:** Customer connections must use their own authorized credentials, and live SCCM database access must remain disabled for the assisted pilot.

**Accepted when:**

- Saved, standalone, manual and scheduled GitHub and GitHub Container Registry collection never inherits another customer's or the platform's credentials; consecutive jobs do not leak credentials.
- Supported public repositories still allow deliberate anonymous collection; GitHub Container Registry clearly rejects missing credentials. Shared feed credentials remain separately scoped.
- SCCM configuration, testing, synchronization and already queued work make no live database connections and return no substitute sample results.
- SCCM is recorded as contained and disabled, with checks of permitted database destinations and connection methods deferred until explicit re-enablement; the remaining credential repairs are tracked independently.

### BR-P09 — Restrict external connections and report retrieval failures honestly · [P09](AWS_APPLICATION_PREREQUISITES.md#p09)

**Requirement:** Existing external-data retrieval must connect only to approved destinations, stop within configured limits and never present unavailable evidence as a clean result.

**Accepted when:**

- Private, internal and special-purpose destinations are rejected across supported address formats, including when an approved hostname changes its destination.
- Follow-on requests for supported data retrieval remain within approved destinations and configured time, page and data-size limits; pilot-disabled connectors stay disabled.
- Required provider destinations are configured correctly; failed or partial advisory retrieval is visibly unavailable or incomplete rather than evidence that no issue exists.
- Controlled address and retrieval simulations demonstrate these protections while preserving stronger existing AI Azure controls and destination restrictions; no live cloud account is required.

### BR-P10 — Preserve accepted assessments and show accurate progress · [P10](AWS_APPLICATION_PREREQUISITES.md#p10)

**Requirement:** Existing services must perform only their configured duties, and accepted background assessments must continue reliably with truthful progress visible to users.

**Accepted when:**

- Request-handling and background services respect their approved duties, including during startup and recovery; unrecognized duties are rejected.
- Accepted work remains recoverable if the local handoff to background processing fails, without changing existing request/response behavior.
- A policy rollout waits for its accepted assessment, including an assessment shared with another request or delayed during recovery, and rechecks its intended release before completion.
- Manual execution shows data collection and assessment progress separately, keeps checking pending assessments, and preserves pending, running, partial, failed and complete states. Existing rule-based security assessments work when generative assistance is off.

### BR-P11 — Keep saved changes and their required follow-up work together · [P11](AWS_APPLICATION_PREREQUISITES.md#p11)

**Requirement:** Accepted changes must be saved together with recoverable instructions for their required follow-up processing, so neither can be lost or act on unconfirmed data.

**Accepted when:**

- Follow-up work cannot become visible before its source changes are confirmed; failed changes leave previous data intact and create no follow-up event.
- Successful source changes lead to their required recalculation, and accepted connector work survives the request-handling process stopping.
- GitHub source updates, run status, capacity approval and job creation succeed together; capacity denial leaves the source eligible to retry.
- Evidence demonstrates this behavior using the actual database, including failures before confirmation and process loss after acceptance.

### BR-P12 — Recover interrupted work without disrupting healthy jobs · [P12](AWS_APPLICATION_PREREQUISITES.md#p12)

**Requirement:** Interrupted existing background work must recover safely while healthy executions continue and outdated attempts cannot overwrite current results.

**Accepted when:**

- Starting another background service leaves healthy work unchanged; each service claims only work it supports and preserves accepted waiting jobs.
- Interrupted or expired attempts recover within the configured retry limits, including failures before execution or rejection of the local handoff.
- Once an attempt loses ownership, it cannot make late data changes or overwrite a replacement attempt's result.
- Checks cover overlapping services and single-service restarts across retained ingestion, vulnerability, governance, demo and source workflows; disabled capabilities require no new processing system.

### BR-P13 — Run scheduled work once while allowing independent work · [P13](AWS_APPLICATION_PREREQUISITES.md#p13)

**Requirement:** Existing recurring tasks must avoid duplicate business effects while allowing different sources and customer workspaces to progress independently.

**Accepted when:**

- A documented inventory covers every retained schedule: purpose, enablement evidence, permitted duties, customer or shared scope, timing/time zone, overlap protection, restart behavior and a decision to retain unchanged, repair or disable it.
- Simultaneous scheduled attempts for the same source and occurrence produce one effective result; independent sources and workspaces both progress.
- After a restart, pending work can recover or a missed run is reported explicitly.
- Evidence records the actual hosting services, their duties, scheduling settings, number of running copies, release and verification date, and agrees with the inventory.

### BR-P14 — Keep completed work successful through reporting failures · [P14](AWS_APPLICATION_PREREQUISITES.md#p14)

**Requirement:** Work that has successfully saved its business changes must remain successful, even if later reporting fails or the application stops.

**Accepted when:**

- A failure while recording completion history or metrics leaves completed work successful and shows the reporting failure or retry separately.
- Failures before work starts do not leave it permanently shown as running.
- Planned shutdown stops new work from starting and safely finishes or preserves accepted work for recovery, including interruptions at the start, during processing or when saving results.
- Recovery avoids duplicate effective business changes, and an expired worker cannot make late changes. Existing shutdown behavior is verified; email delivery is covered separately by P32.

### BR-P15 — Keep customer workspaces isolated after errors · [P15](AWS_APPLICATION_PREREQUISITES.md#p15)

**Requirement:** An operation must use the correct customer workspace throughout, and failures must never carry one workspace's access context into subsequent work.

**Accepted when:**

- Alternating operations for different workspaces remain isolated, including after processing errors and failed database operations.
- Related operations within the same workspace continue to work; attempts to switch workspaces during an operation are rejected before unsafe access occurs.
- If the application cannot safely clear a workspace's access context, it retires the affected database connection. Later customer and platform operations inherit no previous workspace settings.
- Invalid isolation settings fail explicitly, and existing workspace access restrictions remain enforced.

### BR-P16 — Recover missing vulnerability information and risk scores · [P16](AWS_APPLICATION_PREREQUISITES.md#p16)

**Requirement:** Existing vulnerability updates and risk-score refreshes must recover missed information and report incomplete coverage accurately.

**Accepted when:**

- The public vulnerability feed (NVD) resumes from its last fully completed period after downtime, using manageable overlapping periods without duplicating records; progress advances only after a period succeeds.
- Risk-score refreshes (EPSS) cover every eligible record across multiple result pages, even as earlier records are updated. Missing scores and failed requests receive a finite, recorded attempt outcome.
- Failures partway through processing and repeated runs recover eligible records and update existing findings and derived views.
- Status distinguishes incomplete or unavailable coverage from a successful update that found no results.

### BR-P17 — Disable pilot Azure collection and reject incomplete inventories · [P17](AWS_APPLICATION_PREREQUISITES.md#p17)

**Requirement:** Generic Azure discovery must remain disabled for the assisted pilot, and supported software inventories must never silently omit components.

**Accepted when:**

- Application controls block configuration changes, connection checks, all manual and targeted scans, schedules and waiting work. Blocked and waiting work make no Azure requests and cannot change existing assets' activity status; treatment of already running work is recorded.
- Supported software inventory uploads exceeding their component limit are rejected explicitly, with separate completion evidence under P25.
- Generic Azure is recorded as contained through disablement, with an owner and review conditions. Re-enablement requires an explicit decision; the independently implemented AI Azure capability is outside this restriction.
- Before any future re-enablement, checks cover a scan that fails after an initial successful page, empty scans and entirely failed scans. Unseen assets remain unchanged until a complete authoritative scan confirms their absence, across separate subscriptions, resource types and regions.

### BR-P18 — Apply existing work limits fairly under simultaneous demand · [P18](AWS_APPLICATION_PREREQUISITES.md#p18)

**Requirement:** Simultaneous requests must respect each customer workspace's configured work limits, avoid duplicate jobs and allow other customers to continue.

**Accepted when:**

- Concurrent submissions and workers cannot exceed existing configured limits. Existing provider allowances apply across the operations using them, and combined database usage is checked against the actual number of running application copies.
- Identical simultaneous requests return the same logical job without creating duplicates or an avoidable server error.
- A scheduled source denied capacity remains eligible for a later attempt, records its deferral and does not block independent sources or workspaces.
- The source, its recorded run and its accepted job remain consistent. Evidence exercises genuine simultaneous requests and database conflicts.

### BR-P19 — Use limited database access and verified secure connections · [P19](AWS_APPLICATION_PREREQUISITES.md#p19)

**Requirement:** Retained application features must work with appropriately limited database access and securely verified connections to the current database service.

**Accepted when:**

- Retained shared advisory and workspace features work with ordinary application permissions; any unsupported legacy advisory routes are explicitly disabled.
- Checks confirm that one workspace cannot access another's data and that ordinary application access cannot change database structure.
- Existing database connection security options and bounded timeouts survive maintenance tooling unchanged; controlled checks reject an untrusted server certificate or incorrect server identity.
- Current hosting evidence confirms the database's certificate trust and identity checks without exposing credentials. This requirement covers the current database rather than future AWS infrastructure.

### BR-P20 — Make setup and inspection results trustworthy · [P20](AWS_APPLICATION_PREREQUISITES.md#p20)

**Requirement:** Existing database setup and inspection tools must accurately report what happened and preserve customer data.

**Accepted when:**

- One-time setup and ongoing maintenance are clearly distinguished; success, failure and cancellation are reported accurately without exposing secrets.
- Initial setup, repeat execution, failure and cancellation are verified using disposable databases. Inspection advertised as read-only attempts no operation that changes database structure.
- Verification uses the application's actual packaged database versions and intended target, removing obsolete version expectations.
- Existing applied database changes remain intact; repairs add subsequent changes. Permanent application and background-job access does not use database-owner credentials, and no reset or destructive verification is performed on the existing hosted database.

### BR-P21 — Open customer workspaces only when setup is complete · [P21](AWS_APPLICATION_PREREQUISITES.md#p21)

**Requirement:** A new customer workspace must become active only after its required database setup, compatibility and ordinary application access have been verified.

**Accepted when:**

- Setup verifies the workspace's required structure, expected version and integrity checks, and access permissions before activation.
- A failure at any setup stage leaves the workspace inaccessible with an accurate state that supports recovery.
- Failure while setting up a later workspace does not leave an earlier workspace active without the permissions it needs.
- Retrying setup is safe, and an activated workspace passes an ordinary-use check without database-owner access. The existing operator-run setup process is sufficient; automatic provisioning is outside this repair.

### BR-P22 — Delete one workspace without harming shared users · [P22](AWS_APPLICATION_PREREQUISITES.md#p22)

**Requirement:** Administrative workspace deletion must preserve access to other workspaces and report success only after required cleanup is complete.

**Accepted when:**

- The unsafe deletion route remains restricted or disabled until repaired; a controlled privileged operator procedure may provide the supported deletion path.
- Deleting workspace A preserves a shared user's login credentials, membership and privileges in workspace B.
- Empty and populated workspaces, insufficient permissions and cleanup failures produce accurate results. Required cleanup cannot be silently skipped, and partly deleted workspaces remain inaccessible.
- Retrying cleanup completes safely, preserves required audit records and holds, and records success only after verified completion. Normal application database permissions are not broadened to perform deletion.

### BR-P23 — Keep healthy workspaces available during another's setup failure · [P23](AWS_APPLICATION_PREREQUISITES.md#p23)

**Requirement:** The application's availability checks and workspace access rules must consistently distinguish a platform outage from an individual workspace problem.

**Accepted when:**

- One documented compatibility policy governs application startup, readiness to serve and workspace access, including the supported range for returning to a prior application release.
- Compatible active workspaces remain usable while another workspace is being set up, has failed setup or has incompatible database changes. The affected workspace receives an explicit access failure.
- Missing required shared platform dependencies stop the affected application instance from serving; basic process-alive checks remain distinct from readiness.
- Database access protections remain enforced. Verification covers additive database changes and supported prior application behavior against the same disposable database.

### BR-P24 — Keep archive migration disabled and preserve available content · [P24](AWS_APPLICATION_PREREQUISITES.md#p24)

**Requirement:** Local archive migration must remain disabled for the assisted pilot while available vulnerability descriptions and source content remain accessible.

**Accepted when:**

- Operator migration is paused, application controls block archive writes and migration, and no hidden background task can resume them. Disabled attempts create no archive files or references and cannot remove database content.
- Existing ingestion and supported reads retain available original descriptions and source content in the database; disablement removes no existing source content, archive references or files.
- Historical content available only in an inaccessible archive is clearly reported as unavailable, rather than as a successful empty result. Screens and operator guidance agree.
- Disablement has an owner and re-enablement criteria. Storage accessibility and durability qualification require a later explicit archive-retention decision.

### BR-P25 — Rejected inventory uploads leave existing information intact · [P25](AWS_APPLICATION_PREREQUISITES.md#p25)

**Requirement:** Accept supported software inventory uploads safely, without changing customer information when an upload is rejected.

**Accepted when:**

- Invalid, unrecognized or empty replacement files leave the previous inventory, components, supporting evidence and active version unchanged; rejected new uploads leave no unintended asset.
- Every supported format is checked at its actual size and component limits, including just above each limit. Oversized downloads are stopped while being read, even when their reported size is missing or wrong; incomplete inventories are rejected rather than silently shortened.
- Difficult files finish or fail within controlled processing bounds. Existing upload behavior and verified limits are documented; new limits or a different upload process require a separate decision.

### BR-P26 — Cleanup follows approved policies and protects required evidence · [P26](AWS_APPLICATION_PREREQUISITES.md#p26)

**Requirement:** Remove eligible information in controlled amounts while preserving evidence that must remain available.

**Accepted when:**

- Every stored category has a documented cleanup policy, owner, schedule, processing bounds, protection checks, audit record and handling for interruptions or overlapping runs; verified problems and unreviewed areas are distinguished.
- Demonstrations spanning more than two cleanup batches, including interruption and restart, show steady progress without duplicate audit records or missed eligible information. Actual processing bounds are recorded, and disabled, failed or overdue cleanup is visible.
- Evidence under a hold, still referenced, unexpired or protected for reprocessing survives simultaneous cleanup. Existing approved policies remain authoritative; this work establishes no new retention periods, storage allowances or deletion commitments.

### BR-P27 — Sign-in and workspace switching work consistently · [P27](AWS_APPLICATION_PREREQUISITES.md#p27)

**Requirement:** Existing sign-in, setup and workspace-switching journeys work reliably within users' current permissions.

**Accepted when:**

- Valid access credentials created by these journeys work under the selected configuration; incompatible sign-in settings are rejected.
- Credentials from an unexpected sign-in service, for the wrong application or purpose, with failed security checks or with revoked access are rejected. Current membership and support permission are checked; invalid sign-in credentials cannot gain access through an alternative API key.
- Browser journeys work without development-only shortcuts. Setup remains protected against unauthorized browser-initiated actions, using the existing sign-in system.

### BR-P28 — Support staff and automated accounts stay within their permissions · [P28](AWS_APPLICATION_PREREQUISITES.md#p28)

**Requirement:** Support staff and automated accounts can act only within currently approved permissions for the correct customer workspace.

**Accepted when:**

- Support access is restricted to the named person, workspace, expiry and read/write permission; expired, revoked or read-only grants cannot perform prohibited actions, and activity identifies who acted.
- Support cannot manage membership without separate direct authorization. Published scope is workspace-wide unless narrower restrictions are enforced.
- Automated accounts have permitted roles and verified credentials; deleted, disabled or wrong-workspace accounts cannot act. Unsupported sign-in methods are disabled; an account or key identifier alone never grants access.

### BR-P29 — Pilot customers receive exactly their approved capabilities · [P29](AWS_APPLICATION_PREREQUISITES.md#p29)

**Requirement:** Apply the agreed capability restrictions to an explicitly named pilot group, consistently across screens and direct requests.

**Accepted when:**

- Evidence records the effective enforcement setting, named pilot workspaces and approved capability matrix without secrets. Observation-only settings are used only for prior assessment, and the pilot group is deliberately selected.
- Enabled and disabled plans, expired exceptions, unknown capabilities, and customers inside and outside the pilot group behave as agreed in both the application and its screens.
- Disabled general Azure discovery, live SCCM database connections and generative assistance stay blocked regardless of plan access. User permissions and resource limits remain independent of commercial plans; no billing project or mandatory observation period is introduced.

### BR-P30 — Customers see only supported capabilities and genuine results · [P30](AWS_APPLICATION_PREREQUISITES.md#p30)

**Requirement:** Present the application's current supported capabilities honestly and prevent unfinished features from producing customer evidence.

**Accepted when:**

- Unfinished OSV matching of vulnerabilities to customer inventories, simulated Fix Intelligence results and excluded runtime monitoring remain unavailable through direct requests, manual actions, scheduled work and ordinary configuration.
- Screens and documentation match these restrictions; hiding a screen alone does not count as disabling a capability. No simulated result is presented as a customer finding.
- Supported inventory, static AI analysis, rule-based assessments and the protected demo-request form continue working where applicable. Disabling optional assistance preserves existing rule-based results without replacement features.

### BR-P31 — Optional generative assistance stays off and guidance remains trustworthy · [P31](AWS_APPLICATION_PREREQUISITES.md#p31)

**Requirement:** Keep generative assistance disabled for the pilot while preserving useful, evidence-based assessment and guidance.

**Accepted when:**

- Disabled or unauthorized requests send nothing to a generative provider, including investigation summaries and every configured credential route. Until the control is repaired, affected access is restricted or provider credentials are removed through a separately authorized operation.
- With assistance disabled or unavailable, existing summaries, findings, security results and assessment updates remain usable. Guidance invents neither vendor attribution nor verified upgrade versions; timestamps alone are not presented as newly completed analysis, and failures to retrieve security advisories remain visible.
- Re-enabling assistance requires a separate explicit decision covering authorization, budget and information sent; passing these checks does not enable it automatically.

### BR-P32 — Invitations and campaign emails remain recoverable after failures · [P32](AWS_APPLICATION_PREREQUISITES.md#p32)

**Requirement:** Send emails only for saved actions, with reliable retry and recovery that preserve the correct invitation or campaign message.

**Accepted when:**

- Cancelled or failed saves send no uncommitted invitation. Saved delivery instructions survive restarts; retries preserve the same message and invitation version. Access codes stored for retry are encrypted; invitation records retain only values that allow validation without recovering the original code.
- Restart and uncertain-response scenarios reuse the same delivery identity within the provider's duplicate-prevention guarantees. Reissued invitations and separate campaign events receive distinct identities; uncertain acceptance outside those guarantees is reconciled before resending.
- Retries stay within configured limits; exhausted retries, uncertain acceptance and controlled resend are visible and recoverable. An invitation cannot become permanently unusable because delivery instructions were lost. Status distinguishes provider acceptance from confirmed inbox delivery.

### BR-P33 — Browser software and error reporting do not expose credentials · [P33](AWS_APPLICATION_PREREQUISITES.md#p33)

**Requirement:** Keep access secrets out of released browser files, and keep credentials and sensitive personal information out of diagnostic data.

**Accepted when:**

- Production releases reject or exclude planted sign-in tokens and arbitrary secret keys; development-only shortcuts cannot embed credentials in released browser files.
- Diagnostic and error records collected during controlled invitation and setup journeys contain no planted secrets in recorded page addresses, address fragments, referring addresses, request details or activity trails. Existing monitoring removes personal information, including automatically collected data.
- Checks use artificial values without exposing real secrets. Browser sign-in still works; monitoring configured off stays off.

### BR-P34 — Authorized audit exports are safe to open · [P34](AWS_APPLICATION_PREREQUISITES.md#p34)

**Requirement:** Authorized customers can use audit records without exported content executing spreadsheet formulas or bypassing access controls.

**Accepted when:**

- CSV exports treat potentially executable formulas and control characters as text, while preserving ordinary quotes and line breaks; customer-controlled tracking fields are validated.
- Customers cannot export another workspace's records or alter audit history without authorization. Approved recording and cleanup continue under existing permissions and policies.
- If safe CSV handling cannot ship, temporarily disable CSV and record containment; keep authorized JSON export. Disablement is not a completed safety repair; no new retention policy or external audit storage is introduced.

### BR-P35 — Operational figures show their freshness, coverage and limitations · [P35](AWS_APPLICATION_PREREQUISITES.md#p35)

**Requirement:** Help operators distinguish current, valid measurements from incomplete, stale or unavailable information.

**Accepted when:**

- Known waiting work and processing delays produce correct figures. Each measurement identifies its actual operating role and scope, including when it reflects only one running instance's recent activity.
- Refresh time, validity and errors are visible. Eligible workspaces are deliberately selected; one workspace's failure does not hide others, and partial refresh is visibly incomplete or stale.
- Startup, failure and recovery demonstrations show default or old values never imply verified overall health. Monitoring categories remain controlled, with no secrets or customer source content; existing monitoring facilities are used.

### BR-P36 — Release evidence proves the agreed application repairs · [P36](AWS_APPLICATION_PREREQUISITES.md#p36)

**Requirement:** Approve the repaired application against recorded evidence and accurate operating guidance, with remaining limitations explicit.

**Accepted when:**

- The identified source version passes applicable browser, backend, database, migration and script checks, including checks that released browser files contain no embedded credentials, without weakened coverage requirements.
- Evidence covers restricted database permissions, workspace setup and lifecycle, access controls, rejected-operation rollback, simultaneous work, failures and disabled features relevant to each repair. Destructive cleanup is demonstrated using disposable test databases and data.
- Results record configuration assumptions, exclusions, outputs and reviewer. Guidance reflects the separate current platform and workspace database histories, preserves existing corrections, and requires future changes to preserve migration history; historical development resets do not authorize shared-database resets.
- Outstanding live Render configuration checks are listed. Passing application checks is not presented as AWS qualification or production readiness; cloud deployment, production-scale capacity, recovery commitments and customer migration remain separate.

## Acceptance and sign-off

All requirements begin **Open / Pending**. Use the following outcomes consistently:

| Outcome | Evidence required |
| --- | --- |
| Verified | The applicable acceptance criteria pass for an identified application release and environment. Record the requirement ID, responsible owner, demonstration or test results, configuration assumptions, date and reviewer. |
| Contained—disabled | The affected capability is blocked by the application, its screens and guidance describe that restriction, and evidence covers direct requests plus queued and scheduled work where applicable. Record the owner, remaining exposure and conditions for reconsidering enablement. The underlying full repair remains tracked. |
| Open / Pending | Evidence is missing, the work is partial, or an applicable acceptance criterion fails. A planned fix or operator pause alone is insufficient for verification. |

Re-enabling a pilot-disabled capability requires a separate explicit decision after its relevant safety checks pass. Preserve current configured limits and approved data-retention protections. This document introduces no new delivery dates, customer quotas, retention periods or service guarantees.

Release evidence must distinguish controlled demonstrations from checks of the live environment. List outstanding live configuration checks and deferred repairs. Acceptance of this repair program establishes only the agreed current-application outcomes; broader platform and launch obligations remain separately tracked in the [technical plan](AWS_APPLICATION_PREREQUISITES.md#deferred-platform-work-and-closure-rules).
