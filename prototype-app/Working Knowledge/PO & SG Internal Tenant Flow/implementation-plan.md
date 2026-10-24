# Implementation work log

Implementation: 22 October 2026. Scope is the supplied MVP plan. Existing unrelated local changes were preserved. Activity files use this existing directory; the shorter activity path written inside the source plan does not exist in this checkout.

| Work package | Result |
| --- | --- |
| Reserve SG Internal and separate identities | Implemented protected classification/schema identity, normal Enterprise entitlements and removal of implicit owner membership |
| Atomic installation and setup delivery | Implemented distinct passwordless accounts, encrypted outbox, neutral links, independent activation and explicit recovery |
| Staging, review and publication | Implemented shared normalization sink, immutable evidence/candidates/releases, exact approval, transactional publication and withdrawal |
| Platform and tenant connectors | Implemented owner feed controls, persisted schedules, review/releases/processing UI; tenant inventory connectors and source settings remain scoped |
| Automatic tenant lifecycle | Implemented bounded fan-out/evaluation, revisions/fences, source-filtered evidence and independent finding eligibility |
| Verification and documentation | Backend and frontend full suites passed; isolated browser/API/database journey verified; evidence and recovery instructions recorded |

Important implementation corrections found during verification: incomplete GHSA pagination fails its checkpoint; EPSS recognizes existing approved CVEs; central feed audit events use platform storage; compatibility GHSA views share the approved projection. Demo generation requires already approved intelligence and cannot silently publish fixtures.

The final source includes owner controls for EPSS/OSV and EOL scheduling, case-normalized GHSA aliases, exact alias restoration on withdrawal and explicit staging for optional NVD target repair. Focused restoration/repair regressions passed. The final frozen-source check passed: 1,308 unit tests, 494 PostgreSQL integration tests and 674 frontend tests, plus type checking, lint and production build. Results are maintained in [implementation-evidence.md](implementation-evidence.md).

No live database migration, external email delivery, production deployment, commit or push was performed. Only named disposable local PostgreSQL databases and test identities were used.
