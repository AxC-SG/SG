<!--
This template is required for every PR (human or agent). Fill it in completely.
Reviewers: reject PRs that leave sections blank.
-->

## Scope

<!-- What does this PR change? One or two sentences. Include the user-visible
behavior change, not just the code change. If this is a refactor, say so. -->

## Why

<!-- Link the bug report, ticket, or design doc that justifies this work.
"Improvement" is not a reason — there must be a concrete trigger.
If this is an agent-driven fix, link the originating bug record. -->

- Linked issue / bug:

## Repro / Manual Test

<!-- Steps to reproduce the original problem and verify the fix.
For UI changes: include a before/after screenshot or recording. -->

## Test added or changed

<!-- Every PR that changes behavior must add or change a test.
If you didn't add one, justify why (e.g., pure refactor with existing
coverage, infra-only change). "Hard to test" is not a justification — flag
the testability gap as a follow-up issue if it exists. -->

- [ ] Test added / changed
- [ ] Justification for not adding a test:

## Risk and Rollback

<!-- What's the worst case if this is wrong in prod? How do we revert? -->

- Blast radius:
- Rollback plan:

## Documentation

<!-- Check "No docs impact" if this PR changes no user-visible behavior, APIs, or architecture.
Otherwise check every doc you updated. -->

- [ ] No docs impact
- [ ] `docs/architecture.md` — structural or cross-cutting changes
- [ ] `docs/backend.md` — new or changed API endpoints / services
- [ ] `docs/frontend.md` — new components, routes, or pages
- [ ] `docs/database.md` — schema or migration changes
- [ ] `docs/business-logic-guide.md` — business logic changes

## Pre-merge checklist

- [ ] `mvn -Ppostgres-it verify` passes locally (backend changes)
- [ ] `npm run build && npm run test:unit` passes locally (frontend changes)
- [ ] No new Flyway migration edits an already-applied file
- [ ] No new secret committed (`backend/secrets/`, `.env`, credentials)
- [ ] CLAUDE.md updated if conventions, watermarks, or architecture changed
