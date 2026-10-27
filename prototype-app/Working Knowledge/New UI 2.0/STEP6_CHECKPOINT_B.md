# Step 6 checkpoint B — verified before final slice

The family slices and public extraction are complete locally. Checkpoint B is verified with the intended Intelligence geometry differences below. The required stop was honored. The user authorized the final slice on 2026-10-27; its separate evidence is in STEP6_FINAL_MAP.md. Results below qualify checkpoint B only. Step 8 must qualify the final tip.

## Results

| Check | Fresh result |
|---|---|
| Lint / typecheck | 0 lint errors, 2 existing warnings; typecheck passed |
| Unit fast gate | 788 passed / 0 failed / 0 skipped; 84 files, 32 scope tests |
| Host coverage | 788 passed / 0 failed / 0 skipped; unchanged floors met |
| UI2 production build / artifact build | Passed, bundle/security check passed; data-ui boundary 15/15 |
| Fixture journeys | 737 passed / 0 failed / 0 skipped |
| Strict container visual | 140 passed / 0 failed / 0 skipped |
| Affected routes since 68a4a3bc | All 35 routes, 140 passed / 0 failed / 0 skipped |
| Affected axe | 883 current = 883 baseline; 0 new, 0 resolved |
| Full axe audit from update runner, independently compared to untouched tracked baseline | 939 current = 939 baseline; 0 new, 0 resolved |
| Live journeys | 250 passed / 0 failed / 2 skipped; all original 250 required case names reached |
| Cold/navigation/Back probe | 240 comparisons, 0 differences |
| Public boundary probe | 120 sequences, 0 bad |
| Probe against original starting baseline | 380 snapshots, 12 intended height-only differences |
| Modal/sub-navigation state | Identical to original starting baseline |

Fixture breakdown: Findings 67, CVE 80, Inventory 106, Governance 166, Connect 116, Experience 202. Coverage: lines 7937/15211 (52.17%), statements 8916/18010 (49.5%), functions 2573/6208 (41.44%), branches 7868/19521 (40.3%). No floors, assertions or visual tolerances lowered.

The 12 baseline probe differences are only `.content`/`.panel` heights on `/vuln-repo/vulnerabilities`, at both themes and widths across cold/navigation/Back. Shared Findings controls now load eagerly, eliminating the old route-order dependency. All 240 within-candidate comparisons agree. The original baseline remains unchanged; these differences were classified, not hidden by replacing it.

## Exact tested sources

- Host full gate: `f0bb95d494ca210871a6c294a4e44c07b221d9c0`.
- Strict container: `7b3f30b3eeeade80e10d2f8a30107fdd831cfc59`, native `aarch64`, `mcr.microsoft.com/playwright:v1.63.0-noble`.
- Latest fast and complete live gates: `130729c7a1e57a1c9a221f79dfe0e0048bede239`; frontend tree `0601bb987ac9ab213d1b37ae166438d7aab286d8`.
- All three have the same application `frontend/src` tree: `384efe6623ec412a93659587009892a27889f53e`. Container and current PNG trees also match. Changes after the host gate are eight PNGs and bounded live-harness readiness checks. Changes after the container gate are only those additional live readiness checks and ledger evidence. The final evidence amendment changes documentation only.

Scratch evidence lives under `/private/tmp/sg-ui2-step6.QsSmLw/`: `gate-checkpoint-b-final/`, `gate-checkpoint-b-final-ctr/`, `gate-snapshot-qualification/`, `gate-snapshot-update/`. `source-equivalence.json`, live case-name comparison and bundle comparison are in the corrected host evidence folder. Probes, state files, reports and credentials are never committed.

## Visual updates and diagnosed attempts

Only eight UI2 PNGs changed: Intelligence and AI Inventory, both themes and widths. Generated through `npm run e2e:update` inside the pinned native-arm64 container. Selected-route compare was 4 passed / 8 failed / 0 skipped; update was 12 passed / 0 failed / 0 skipped and the full runner passed 9/9 steps. Seven new files exactly match the inspected actuals; the remaining dark Intelligence/390 image differs by six search-border pixels and was inspected side by side. No masks or tolerances changed. Hosts PNGs, UI1 baselines, tracked journey baselines and tracked axe baselines are unchanged.

Earlier attempts remain available:

- `gate-checkpoint-b-attempt-1/`: missing font-import semicolon after public extraction, diagnosed and corrected in the public slice; sandbox socket denial rerun with local-server permission.
- `gate-checkpoint-b/` and `gate-checkpoint-b-ctr/`: initial container 130 passed / 10 failed / 0 skipped. All diffs inspected. Inventory semantic bar colours were a real priority regression, restored with combined variant/fill selectors. Corrected focused Hosts and AI Inventory controls match starting UI2 navigation exactly. CVE consistently retains its existing owned toolbar properties instead of a lazy Findings override.
- Initial host probe sampled preceding React routes after history changes. It now waits for committed target identity and settled requests, retaining every comparison/property/boundary assertion. Full corrected probe passed.
- `gate-checkpoint-b-final/live/`: 245 passed / 1 failed / 2 skipped. Assessment saved, but the harness checked Findings creation before navigation finished. Added bounded enabled/visible transition waits.
- `gate-checkpoint-b-final/live-after-waits/`: 248 passed / 0 failed / 2 skipped. Case-name audit caught two silently omitted light Inventory checks while details still showed Loading. Added visible waits plus explicit failure branches. The final full live run reaches all original 250 cases, including both restored checks, with 0 failures.

## Live backend and limits

Before the final live run, verified backend PID 94226 cwd `prototype-app/backend`, unchanged backend tree `2d25898ef3da9b73125b009810f097df51906cba`, JDBC connections to disposable `scout_ui2_qual`, platform Flyway V8, and ACTIVE `ui2-qual-2` at tenant schema V6. Credentials were not printed. The two provider skips cover successful outbound ServiceNow delivery without an approved external endpoint. No customer data, database resets, API/auth/tenant/schema changes or external delivery occurred.

Existing accessibility defects remain in the baseline; zero new axe violations is not a completed accessibility review. That review stays open. Staging and human reviews are waived. Logged unrelated keyboard, overflow and API defects remain open.

## Bundle and preserved baseline

Current CSS: **752338 raw / 96964 gzip bytes**, 4 files. Step 0: 645010 / 95396, a change of +107328 raw (+16.64%) / +1568 gzip (+1.64%). Qualified Step 5 (`c29515d8`, same frontend tree as Step 6 start): 645602 / 95535, a change of +106736 raw (+16.53%) / +1429 gzip (+1.50%). Repeated zero-specificity app-boundary scopes increase raw CSS. This is an increase, not a size reduction. The earlier Step 5 pre-focus measurement 645193 / 95440 is retained as history, not used as the final qualified reference.

The original baseline at `68a4a3bc78f3688a095e8e89291cd671dd9891d6` remains `/private/tmp/sg-ui2-step6.QsSmLw/baseline`, with all three hashes verified against `source.json`. Frozen UI1 archive SHA256 remains `f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707`; never rebuilt. No push, remote merge or deploy performed. User deletion and two untracked documents remain untouched.
