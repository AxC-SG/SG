# CI reliability rollout

## Change sequence and invariants

Four implementation commits cover certification correctness, stable merge gates, build/test de-duplication, and CI maintenance. Security thresholds, coverage floors, screenshot tolerance, all six journeys and existing assertions stay intact. No deployment or live customer operation is part of this change.

Local verification passed: full backend verify (unit tests, 25% coverage floor, SpotBugs), both migration test classes, frontend lint/typecheck/build/coverage on Node 24, strict-certification regressions, CI gate contracts, Maven report validation, journey worker-pool tests, actionlint and a redacted secret scan. Frontend coverage: lines 52.18%, statements 49.51%, branches 40.31%, functions 41.44%; floors are unchanged. Lint retains two pre-existing warnings.

## Required repository settings

Apply `.github/required-main-ruleset.json` to repository ruleset 25546722 only after the final candidate passes all listed checks. It explicitly targets refs/heads/main, requires current-branch checks and PRs with zero approvals, blocks force pushes/deletion and defines no bypass. No merge queue is introduced. The four Analyze checks use the verified GitHub Actions source (integration 15368); the separate CodeQL dashboard check uses a different app and is not substituted for language execution evidence.

An administrator can apply the reviewed payload with:

```sh
gh api --method PUT repos/AxG-SG/SG/rulesets/25546722 --input .github/required-main-ruleset.json
```

Then verify the applied conditions/check names and demonstrate that a failing or incomplete candidate cannot merge. Administrator access and final successful-check qualification are prerequisites; do not apply the payload early.

## Runtime and qualification evidence

Baseline main Quality run 40619327452: 24.5 minutes elapsed, 46.2 aggregate job minutes; PostgreSQL 21.0 minutes, frontend E2E 14.3 minutes, late image rebuild 3.4 minutes. Baseline PR Quality run 40614179626: 22.9 minutes elapsed; PostgreSQL 19.2 minutes, E2E 18.7 minutes, late image rebuild 3.7 minutes.

Record three completed representative application PR candidates with head SHA, run URL, elapsed minutes, aggregate runner-job minutes, expected test counts and conclusions. Report failed qualification runs separately; do not advertise them as improvements or fabricate timings. Full browser-tooling qualification is more expensive than ordinary application PR verification because it deliberately requests the four-width fallback.

Node 24 is declared in .nvmrc and frontend package engines, including the lockfile, and used by CI and the CI Docker builder. The package engine constrains Vercel build runtime; independently confirm the connected project's configured runtime before declaring hosting alignment verified.

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
