# Implementation evidence

Date: 22 October 2026. Scope: the supplied MVP implementation plan.

## Source and migration changes

- Initial allocation was platform V6 / tenant V5. New migrations are platform V7–V8 and tenant V6; applied migrations were not rewritten. Required tenant compatibility is V6–V6. Runtime grants and readiness use the new structures. Publication alias-map changes are included in the immutable release journal and restored on withdrawal.
- SG Internal uses protected `tenant_default` identity, retained UUID/slug, Enterprise capabilities and normal entitlements. Owner membership is no longer granted implicitly.
- Bootstrap atomically provisions the two distinct initial identities, setup digests and encrypted delivery intents. The CLI performs no provider call inside that transaction. Runtime delivery, setup exchange and independent recovery share the existing delivery/auth infrastructure.
- Every normalized vulnerability/advisory producer stages full evidence. Approved observations, matching artifacts and summaries change only inside reviewed publication. SQL guards protect the runtime projection and immutable evidence.
- Candidate approval binds digest, policy, expanded checkpoints and base release. Publication and corrective withdrawal atomically commit immutable release history, active generation, audit and durable fan-out.
- Tenant evaluation is automatic, bounded and fenced by generation/input revisions. Manual advisories obey tenant preferences. Source-specific eligible evidence supplies matching, VEX, severity and scoring inputs. Intelligence eligibility is separate from workflow status.
- Owner UI includes review/releases/processing (including completed staging repairs), persisted feed schedules and central triggers; tenant UI includes inventory integrations and source preferences. EPSS/OSV and EOL scheduling are exposed through the same central controls.
- Compatibility GHSA triggers use the durable GHSA queue, and compatibility advisory reads use approved observations and targets. Demo generation requires explicitly approved demo CVEs.

Existing unrelated local edits to CI, moved documents, frontend dependencies, API client, configuration page and platform console were preserved. No commit or push was created.

## Verification

Final frozen-source backend and frontend checks passed. Machine-readable counts and migration fingerprints are in [verification-results.json](verification-results.json).

| Check | Result |
| --- | --- |
| Full backend `mvn -Ppostgres-it verify` | PASS: 1,308 unit tests and 494 PostgreSQL integration tests, zero failures/errors/skips |
| Frontend `npm run typecheck` | PASS |
| Frontend `npm run lint` | PASS: zero errors; three existing warnings |
| Frontend `npm run test:coverage` | PASS: 674 tests in 75 files; configured coverage thresholds passed |
| Frontend `npm run build` | PASS, including production authentication-input/bundle checks |
| `git diff --check` | PASS |
| Final central-control additions | PASS: EPSS/OSV trigger replay and owner scope verified against API-only runtime; EPSS and EOL intervals persisted with schedules disabled |

All database work used a disposable PostgreSQL instance on loopback port 55467 and isolated test databases. No shared database was reset. An earlier run crossed a prolonged host suspension and failed real-time shutdown/lease deadlines; the awake full rerun passed without relaxing timeouts or behavior.

Specific acceptance evidence:

- `InternalInstallationActivationPostgresIntegrationTest`: distinct aliases, independent activation, owner has no tenant membership, internal admin has no global owner role, setup replay fails, cross-scope APIs return 403.
- Bootstrap/setup issuer tests: schema readiness, identity preservation, encrypted enqueue, no direct provider delivery, rerun/reissue behavior. Existing invitation suites cover hashed tokens, concurrency, expiry, provider uncertainty and reconciliation.
- `IntelligencePublicationPostgresIntegrationTest`: staging invisibility, exact digest, immutable evidence, publication/fan-out, automatic tenant evaluation, failed-peer isolation/retry, disabled/re-enabled source preserving suppression and finding UUID, withdrawal retaining history. Actual NOSUPERUSER/NOBYPASSRLS role checks actionable/history visibility and cross-tenant isolation.
- `IntelligencePublicationRecoveryPostgresIntegrationTest`: 1,000 synthetic full-feed-shaped observations with product/version rules; concurrent same-key approval, stale candidate denial, injected artifact failure with zero partial approved rows/releases/fan-out, durable retry, exactly one release and fan-out. Successful publication measured approximately 2.5–6.1 seconds locally across runs. Artifact processing uses bounded 100-row pages and clears the persistence context. This is an offline representative workload, not a production-scale NVD benchmark.
- `IntelligenceAliasPostgresIntegrationTest`: GHSA-only identity later resolves to a verified CVE, redirect and canonical UUID reuse; multi-CVE advisories remain distinct; conflicting aliases are quarantined. The regression fixture includes real-world lower-case GHSA suffixes; aliases and feed source-record identity normalize consistently. Withdrawal restores the predecessor alias ledger and redirects, and a fresh reviewed run can consolidate it again.
- EPSS, NVD continuity, feed-effect and durable-work tests assert staging without premature tenant fan-out. The optional NVD target repair explicitly opens a normalization run and stages prepared targets instead of modifying approved matching data. API goldens now reflect asynchronous publication/finding behavior and advisory run history; fixture ingestion explicitly reviews and publishes intelligence.

## Browser, API and database journey

The local QA app used a separately bootstrapped database and the restricted runtime role. Real email delivery and OpenAI were disabled; no production environment/secrets file was loaded.

1. Both initial fragment links independently exchanged into the neutral account setup form. Password establishment used the HTTP setup endpoints with synthetic test credentials; subsequent separate account sign-ins were exercised in the browser.
2. Owner connector navigation resolved to central feeds, with inventory/BOM connectors absent. Tenant sign-in displayed SG Internal and normal tenant navigation.
3. An offline advisory and a one-component CycloneDX inventory were submitted through their authorized APIs. Before publication, tenant finding count was zero.
4. In the browser, selecting the latest completed advisory run expanded review to both unpublished checkpoints. Prepared exact-version evidence and the digest were inspected; **Approve and publish** queued and then published the immutable candidate.
5. Release processing completed at generation 1 and input revision 13. SG Internal displayed one automatic HIGH finding for the test package. Health showed zero ingestion/publication/tenant-processing failures and no uncertain deliveries.
6. Disabling manual advisories scheduled a new revision and reduced actionable findings to zero. Authorized inactive history returned `SOURCE_DISABLED`. Re-enabling restored eligibility for the same finding identity.
7. Real runtime requests confirmed owner ordinary inventory access and internal-admin platform access both return 403.
8. EPSS/OSV owner triggers returned durable 202 responses; repeated requests reused each active run and internal-admin calls returned 403. EPSS and EOL full/date-sweep schedules persisted selected intervals while disabled. The API-only runtime prevented external provider execution.

A focused real-service check also verified that disabled NVD/KEV/EPSS evidence cannot leak severity, CVSS, exploitation probability, KEV membership, derived CVSS risk metrics or score contributions into a tenant result; tenant resolution leaves the central canonical entity unchanged.

Screenshots: [publication and processing](qa-publication.png), [automatic SG Internal finding](qa-automatic-finding.png). They contain synthetic data and no activation credentials.

## Operator release and recovery

These are prepared operational instructions; this implementation did not deploy or send live email.

- Inspect actual deployed migration history and backups before the authorized control-plane run. Apply platform V7–V8 and tenant V6 with the existing migrator. Supply distinct `PLATFORM_OWNER_SETUP_EMAIL` (or its existing bootstrap email fallback) and `SG_INTERNAL_ADMIN_EMAIL`, plus the same encryption key/key ID used by runtime delivery. Default initial activation lifetime is 30 minutes.
- Keep feed schedules disabled until both setup paths, schema readiness, runtime grants, the first reviewed release and automatic tenant findings are verified. Runtime API processes do not migrate schemas. EOL is outside the vulnerability approval gate.
- An ordinary bootstrap rerun does not reset passwords or rotate even an expired invitation. Explicit CLI recovery flags are `PLATFORM_OWNER_SETUP_ALLOW_REISSUE` and `SG_INTERNAL_ADMIN_SETUP_ALLOW_REISSUE`; select only the account being recovered. Reset those flags after the authorized recovery run.
- An authenticated owner can inspect `GET /api/platform/setup-deliveries`, reissue via `POST /users/{userId}/reissue` with a reason, or reconcile `POST /{deliveryId}/reconcile` using an `ACCEPTED` or `FAILED` outcome, provider message ID where applicable, and a note. UNKNOWN deliveries require reconciliation rather than blind resend; provider acceptance is not inbox-delivery proof.
- Publication jobs retry transaction failures up to three attempts. A process crash rolls back the job acknowledgement with its writes. Inspect candidate error, source evidence and `/api/platform/intelligence/health`; build/review a corrected candidate if a job exhausts retries. Do not edit frozen evidence or manually mark a release published.
- Stale candidates require rebuilding against the current release. Duplicate request retries reuse the same approval idempotency key. Withdrawal is limited to the active release and creates a corrective release; older errors use a corrective candidate.
- Tenant failures retry independently after 30 seconds; progress resumes from bounded cursors. Restore tenant/schema readiness before retrying. Source/inventory revisions supersede older work automatically. Findings remain in authorized history while ineligible.
- `/api/platform/intelligence/health` and `intelligence.*` gauges cover recent ingestion failures, candidate age, publication failures, pending queue age, tenant-processing failures and uncertain setup delivery. Tenant processing endpoints expose release/generation/revision progress.

## Operational boundaries

No live credentials were read, no real activation email was sent, no production/shared migration or deployment was run, and no production-scale feed load was attempted. The first real release still requires the existing authorized deployment/control-plane process and configured delivery provider. MFA, external identity migration, a second approver, a mandatory internal canary, preview environments and arbitrary historical rollback remain outside the agreed MVP.

Final cleanup: temporary browser-QA API/frontend processes were stopped and synthetic activation/session files removed. The disposable PostgreSQL instance was stopped after verification; diagnostic files remain only under `/private/tmp`.
