# CI reliability rollout

## Change sequence and invariants

Four implementation stages cover certification correctness, stable merge gates, build/test de-duplication, and CI maintenance. The inspected accessibility baseline expansion is a separate fifth commit. Security thresholds, coverage floors, screenshot tolerance, all six journeys and existing assertions stay intact. No deployment or live customer operation is part of this change.

Local verification passed: full backend verify (unit tests, 25% coverage floor, SpotBugs), both migration test classes, frontend lint/typecheck/build/coverage on Node 24, strict-certification regressions, CI gate contracts, Maven report validation, journey worker-pool tests, actionlint and a redacted secret scan. Frontend coverage: lines 52.18%, statements 49.51%, branches 40.31%, functions 41.44%; floors are unchanged. Lint retains two pre-existing warnings.

## Required repository settings

Apply `.github/required-main-ruleset.json` to repository ruleset 25546722 only after the final candidate passes all listed checks. It explicitly targets refs/heads/main, requires current-branch checks and PRs with zero approvals, blocks force pushes/deletion and defines no bypass. No merge queue is introduced. The five named checks are bound to GitHub Actions (integration 15368). CodeQL uses a separate code_scanning rule requiring completed CodeQL results, with errors / high_or_higher thresholds. Default setup is managed in repository settings and analyzes Actions, Java/Kotlin, JavaScript/TypeScript and Python. Generated Analyze job names are diagnostic evidence, not required status-check contracts.

An administrator can apply the reviewed payload with:

```sh
gh api --method PUT repos/AxG-SG/SG/rulesets/25546722 --input .github/required-main-ruleset.json
```

Then verify the applied conditions/check names and demonstrate that a failing or incomplete candidate cannot merge. Final successful-check qualification is a prerequisite; do not apply the payload early. The connector cannot administer rules, but read-only inspection confirmed the signed-in browser can edit the existing ruleset. At initial inspection it warned that no branches were targeted. Consult the PR qualification record for the verified applied state; workflow changes alone never establish enforcement.

## Runtime and qualification evidence

Baseline main Quality run 40619327452: 24.5 minutes elapsed, 46.2 aggregate job minutes; PostgreSQL 21.0 minutes, frontend E2E 14.3 minutes, late image rebuild 3.4 minutes. Baseline PR Quality run 40614179626: 22.9 minutes elapsed; PostgreSQL 19.2 minutes, E2E 18.7 minutes, late image rebuild 3.7 minutes.

Qualification run 40631937235 verified all 110 PostgreSQL test classes without skips in 11.6 minutes; ordinary unit tests and both migration classes also passed. This early run failed only the synthetic-fixture history scan and is not counted as a successful candidate. The fixture layout was corrected without adding a suppression, and clean history was verified locally and in run 40632813693.

The bounded journey run in 40632813693 passed in 9.7 minutes (409 seconds for journeys, 95 seconds for the unchanged visual suite), versus 14.3 minutes in the baseline main run. Browser artifact verification exposed an existing hidden-directory upload issue; uploads now explicitly include hidden files and fail if evidence is absent.

Documentation-only qualification PR #28 was closed without merging after Quality run 40633212458 and Performance run 40633212453 passed: all application suites and certification explicitly skipped; guards, contracts, secrets and stable gates reported success. Semgrep also passed, while Trivy continued independently.

Record three completed representative application PR candidates with head SHA, run URL, elapsed minutes, aggregate runner-job minutes, expected test counts and conclusions. Report failed qualification runs separately; do not advertise them as improvements or fabricate timings. Full browser-tooling qualification is more expensive than ordinary application PR verification because it deliberately requests the four-width fallback.

Node 24 is declared in .nvmrc and frontend package engines, including the lockfile, and used by CI and the CI Docker builder. The package engine constrains Vercel build runtime; the connected Scout Vercel team currently lists no projects, so deployed-project runtime alignment cannot yet be verified through that connection.

## Accessibility debt by shared cause

These are accepted baseline entries repeated across routes, themes and widths, not distinct defects. A passing comparison means no new entries. Remediation remains a separate backlog, owned by the existing frontend maintainers; this change must not expand existing-width suppressions.

| Rule | Existing entries | Remediation area | Status |
| --- | ---: | --- | --- |
| aria-prohibited-attr | 4 | Shared UI controls | Open |
| aria-required-children | 16 | Shared UI controls | Open |
| color-contrast | 197 | UI foundations and page owners | Open |
| empty-table-header | 16 | UI foundations and page owners | Open |
| heading-order | 64 | UI foundations and page owners | Open |
| label | 44 | Shared UI controls | Open |
| landmark-complementary-is-top-level | 4 | UI foundations and page owners | Open |
| nested-interactive | 568 | Shared UI controls | Open |
| scrollable-region-focusable | 14 | Shared UI controls | Open |
| select-name | 12 | Shared UI controls | Open |

For the newly audited 768/1440 widths, retain raw axe artifacts and inspect rule, target, route, severity and contrast details before adding only new-width entries. Preserve the existing 390/1280 baseline and report new versus accepted entries separately. Do not automatically regenerate all baselines.

## Remaining release qualification

Live browser-to-backend-to-database persistence and accessibility defect remediation are separate follow-ups. Fixture browser CI does not certify deployed ingress, production data or connector credentials.


## Feedback incorporated into the implementation plan

See [the revised implementation plan](ci-reliability-plan.md). Required gate names are locked against the ruleset by CI contracts. Only main is a push target; unused merge-group triggers were removed because no merge queue is planned. Strict up-to-date checks deliberately trade additional re-runs after main advances for verification before merge; post-merge checks remain an additional safeguard.

Both workflow selectors use the same script, introduced before gate activation. Markdown-only changes skip performance intentionally: runtime certification inputs are backend code/configuration and files under scripts, while migration/policy guards continue to run. Job-level selection is distinct from event-conditioned steps; advisory docs-check is not required.

Journey processes share only an immutable artifact HTTP server. Each process owns its browser, isolated contexts and fixture state; each journey has a distinct output directory. Baseline-update commands remain serial. Preserve all journey source assertions when tuning concurrency and repeat actual runs to monitor intermittent failures.

Current timeouts are conservative per-job caps, not estimated p95 values. Record at least 20 comparable observations before revisiting p95-based budgets. Label each measurement with workflow/head, relevant change scope, runner OS/architecture, Node/JDK versions, Docker and Maven cache-hit state, and warm/cold/unknown classification. Three runs support an initial comparison, not statistical tail-latency claims. Do not compare the full harness-qualification sweep to an ordinary application run as equivalent workloads.

CI certification uses synthetic local credentials and a disposable PostgreSQL service, so it needs no repository secret on fork PRs. CERTIFICATION_STRICT remains true when authentication fails: errors and auth skips fail validation rather than changing mode. Real-environment authentication and release qualification remain outside this change.

### Recovery if a required gate misfires

Never automatically disable merge protection on a test failure. First fix the gate or restore the last verified ruleset payload through an administrator. Save a pre-change ruleset export for recovery and verify its branch scope and security properties before restoring it. For an explicitly approved emergency when no verified payload is viable, an administrator may temporarily set this ruleset to Disabled, manually verify every gate for the exact candidate, repair the contract and restore Active immediately. Evaluate mode is not assumed available on the current plan. The bypass list remains empty; zero approvals does not grant bypass.

The separate [accessibility baseline review](ci-accessibility-baseline-review.md) records new-width evidence and preserves existing entries. Latest qualification results and applied repository settings are recorded in PR #27 so documenting a completed run does not itself change the candidate SHA and trigger another qualification run.
